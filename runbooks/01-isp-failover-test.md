# Runbook 01 — ISP failover test (PCC dual-WAN)

> Scope: validate that traffic continues to flow when one of the two PPPoE
> uplinks goes down. Run this once per quarter, after every RouterOS upgrade,
> and after any change to `/ip firewall mangle` PCC rules.

| | |
|---|---|
| **Target** | MikroTik RB5009UPr+S+ — RouterOS 7.18.2 |
| **Pre-reqs** | Console access (Winbox or SSH from MGMT VLAN), 2 active PPPoE clients (`pppoe-out1`, `pppoe-out2`), PCC mangle rules already in place |
| **Risk** | Low — both uplinks reconnect automatically when re-enabled |
| **Duration** | ~10 min |

---

## Why we test this

PCC (Per-Connection Classifier) is a per-flow load-balance mechanism, not an
HA mechanism in the traditional sense. RouterOS marks each new connection with
either `ISP1` or `ISP2` and pins it to that uplink for the lifetime of the
connection. If one uplink goes down, **existing connections on it die** — but
new connections must continue to be classifiable and routable on the surviving
uplink.

The two failure modes I care about:

1. **Connection-level failover** — new connections take the surviving link.
2. **Route-level failover** — the default route via the dead link is withdrawn
   so the surviving link's default route takes over for unmarked traffic.

Both must work. Both are tested here.

---

## Procedure

### 1. Baseline — confirm both uplinks are healthy

From the MikroTik:

```text
> /interface pppoe-client print where running=yes
Flags: X - disabled, R - running
 #    NAME            INTERFACE    USER          MTU PROFILE      STATUS
 0  R pppoe-out1      ether2       user1          1492 default     connected
 1  R pppoe-out2      ether4       user2          1492 default     connected

> /ip route print where dst-address=0.0.0.0/0
Flags: X - disabled, A - active, D - dynamic, S - static
 #     DST-ADDRESS    GATEWAY                 DISTANCE
 0  AS 0.0.0.0/0      pppoe-out1               1
 1  AS 0.0.0.0/0      pppoe-out2               1
```

Both routes active, both clients in `connected` state. Move on.

### 2. Generate traffic from each VLAN to confirm the baseline path

From the **Home** VLAN (192.168.20.x):

```bash
$ for i in 1 2 3 4 5; do curl -s https://api.ipify.org; echo; done
XX.XX.XX.X
XX.XX.XX.X
XX.XX.XX.X
XX.XX.XX.X
XX.XX.XX.X
```

You should see a mix of two distinct public IPs (one per ISP). If every
request comes back with the same IP, your PCC rules are not actually
splitting flows — stop here and review the mangle rules.

Tip: `curl` re-uses the same connection by default which defeats PCC; use
`-H "Connection: close"` or call a different host each iteration.

### 3. Failover test — kill ISP1

```text
> /interface pppoe-client disable pppoe-out1
```

Within 5 s, the default route via `pppoe-out1` should be withdrawn:

```text
> /ip route print where dst-address=0.0.0.0/0
Flags: X - disabled, A - active, D - dynamic, S - static
 #     DST-ADDRESS    GATEWAY                 DISTANCE
 1  AS 0.0.0.0/0      pppoe-out2               1
```

### 4. Re-test from the client side

Open a fresh terminal on the Home VLAN host (close any cached HTTPS sessions —
HTTP/2 connection reuse will keep using the dead path until the ISP-pinned
connection times out):

```bash
$ for i in 1 2 3 4 5; do curl -s -H "Connection: close" https://api.ipify.org; echo; done
XX.XX.XX.X
XX.XX.XX.X
XX.XX.XX.X
XX.XX.XX.X
XX.XX.XX.X
```

All five should return ISP2's public IP. If any return zero (timeout) or the
old ISP1 IP, the routing-mark cleanup is not happening — see "Common
failures" below.

### 5. Restore ISP1

```text
> /interface pppoe-client enable pppoe-out1
```

Wait for `pppoe-out1` to return to `connected`. Recheck:

```text
> /ip route print where dst-address=0.0.0.0/0
Flags: X - disabled, A - active, D - dynamic, S - static
 #     DST-ADDRESS    GATEWAY                 DISTANCE
 0  AS 0.0.0.0/0      pppoe-out1               1
 1  AS 0.0.0.0/0      pppoe-out2               1
```

### 6. Symmetric test — kill ISP2

Repeat step 3 with `pppoe-out2`. Expect ISP1's IP from clients.

### 7. Document

Record the result in `/runbooks/_log.md`:

```markdown
| Date       | RouterOS | Test | Result | Notes |
|------------|----------|------|--------|-------|
| 2026-04-30 | 7.18.2   | ISP1 down  | PASS | route withdrawn in 4 s |
| 2026-04-30 | 7.18.2   | ISP2 down  | PASS | route withdrawn in 4 s |
```

---

## Common failures

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Default route via dead link stays in routing table | `check-gateway=ping` not configured on PPPoE client | Set it: `/interface pppoe-client set [find name=pppoe-outX] check-gateway=ping` |
| All flows still leave via one ISP | PCC `per-connection-classifier` denominator wrong, or mangle rule disabled | Re-check `/ip firewall mangle print` |
| Existing connections survive but new ones time out | Routing marks pin new connections to the dead uplink (no failover) | Add fallback rules: `/ip route` with `routing-mark=ISP1` and `gateway=pppoe-out2` at higher distance |
| ICMP works, TCP times out | MSS clamp missing on PPPoE | `/ip firewall mangle add chain=forward action=change-mss new-mss=1452 protocol=tcp tcp-flags=syn` |
