# 2026-04-22 — MikroTik ISP1 PPPoE authentication loop

| | |
|---|---|
| **Component** | MikroTik RB5009UPr+S+ — `pppoe-out1` against ISP1 BRAS |
| **Severity** | High — ISP1 uplink completely down |
| **Detected by** | Cloudflare DDNS update failures (no public IPv4 to register) |
| **Time to detect** | ~3 min from session drop |
| **Time to resolve** | ~2 h (waiting on ISP-side fix on their BRAS) |
| **Status** | Resolved — ISP cleared a stale RADIUS session on their BRAS |

---

## Symptoms

- DDNS update agent on the MikroTik logged `update failed: no public IP` every
  60 s for `outside1.example.dyn`.
- `/interface pppoe-client print` showed `pppoe-out1` cycling between `connecting`
  → `disconnected` every 8–12 seconds.
- `/log print where topics~"pppoe"` filled with `LCP terminated`, `link down`,
  `dialing`, repeating in a tight loop.
- Calling the ISP support line: their L1 said "your modem looks fine from
  here" — the modem was online; what was failing was the **PPPoE session
  layer**, which their L1 cannot see directly.

## Detection

The first signal was the DDNS failure log. The MikroTik runs a 60 s cron that
pushes the current public IPv4 to Cloudflare for the `outside1.example.dyn`
A record. With no IPv4 to send, every push failed:

```text
2026-04-22 11:08:14 cron-ddns: update failed - public IP not learned
2026-04-22 11:09:14 cron-ddns: update failed - public IP not learned
2026-04-22 11:10:14 cron-ddns: update failed - public IP not learned
```

This is a much louder signal than the PPPoE log itself, because the cron
output is shipped to Wazuh as a host syslog stream, while raw PPPoE flap
messages would have been dropped by my decoder threshold.

## Investigation

### Step 1 — capture PADI/PADO/PADR/PADS at L2

I created a port mirror on the Aruba switch from the MikroTik WAN-facing
trunk port to a sniffer port, then ran a Suricata-side `tcpdump` filtering on
EtherType `0x8863` (PPPoE Discovery) and `0x8864` (PPPoE Session):

```bash
tcpdump -i mirror0 -nn -e 'pppoes or pppoed' -w /tmp/isp1-pppoe.pcap
```

15 minutes of capture, opened in Wireshark.

### Step 2 — read the discovery exchange

The MikroTik was sending **PADI** (PPPoE Active Discovery Initiation) — fine.
The ISP BRAS was replying with **PADO** (Offer) — also fine, this is
critical, it means the BRAS sees the modem and is willing to negotiate.

The MikroTik replied with **PADR** (Request) — fine. The BRAS then replied
with **PADS** (Session-confirmation) carrying a session ID.

So far, an entirely textbook discovery handshake.

The failure came in the next phase: **LCP** (Link Control Protocol), the
authentication step inside PPP. The MikroTik sent its credentials. The BRAS
replied with `LCP TermReq` (terminate request) within 200 ms — every single
time. No authentication NACK, no retry — just a straight terminate.

### Step 3 — eliminate the local side

Possibilities for "BRAS terminates after auth":

1. Bad credentials on my side — wrong username or password
2. Account suspended on the ISP side
3. RADIUS session limit reached (their BRAS thinks I am already online)
4. Modem hardware identifier blacklisted

I logged into the MikroTik with the credentials on a Windows PPPoE dialer,
direct to the modem on a separate cable (bypassing the MikroTik entirely):
**same behaviour**. PADI/PADO/PADR/PADS succeed, LCP terminates immediately
after auth.

That ruled out (1) — the credentials are valid, the BRAS just refuses to
accept them.

### Step 4 — second call to the ISP, with evidence

I called the ISP NOC line (not L1) with the PCAP open and quoted the exact
LCP TermReq timing. Their senior tech checked their AAA backend and found a
**stale RADIUS session** under my account on the BRAS — a previous session
had not been cleaned up on a backend reboot, and the BRAS was rejecting new
auths because the user appeared "already online".

Their tech force-cleared the session from their side. The next PPPoE retry
on the MikroTik came up immediately:

```text
2026-04-22 13:14:02 pppoe-out1: connecting
2026-04-22 13:14:04 pppoe-out1: connected
2026-04-22 13:14:04 pppoe-out1: assigned XX.XX.XX.X
```

## Root cause

Stale RADIUS session entry on the ISP1 BRAS for my account. New session
attempts were being rejected with `LCP TermReq` because the AAA backend
considered the account already online. The state was created during a
previous BRAS maintenance window earlier that day and was not cleaned up
on the way out.

This was confirmed by the ISP NOC.

## Fix

Resolved by the ISP NOC clearing the stale RADIUS session on their BRAS.
On my side: no config change required.

## Verification

```text
> /interface pppoe-client monitor pppoe-out1
       status: connected
       uptime: 4m12s
   local-address: XX.XX.XX.X
  remote-address: XX.XX.XX.X
              mtu: 1492
              mru: 1492

> /tool fetch url=https://api.ipify.org
status: finished
downloaded: 11 bytes
```

DDNS cron pushed the new IPv4 on the next 60 s tick. Cloudflare confirmed the
update via the API audit log.

## Lessons learned

1. **A clean four-way handshake followed by an immediate LCP terminate is a
   server-side state problem, almost never a client problem.** Knowing the
   PADI/PADO/PADR/PADS sequence and reading it in Wireshark turned a 4-hour
   "open a ticket and wait" into a focused 10-minute conversation with the
   ISP NOC.
2. **Always have a path that bypasses your gear.** Plugging a laptop directly
   into the modem and reproducing the failure was the proof I needed to
   eliminate myself as the cause.
3. **DDNS update logs are an excellent canary for WAN-side IPv4 health.**
   They fire faster and are more visible than the underlying PPPoE flap log.

## Detection rule used

`local_rules.xml` (Wazuh) — fires when DDNS reports "no public IP" three
times within 5 minutes:

```xml
<group name="ddns,wan,">
  <rule id="100221" level="9" frequency="3" timeframe="300">
    <decoded_as>cron-ddns</decoded_as>
    <match>update failed - public IP not learned</match>
    <description>DDNS cannot publish public IP — WAN PPP session likely down</description>
    <mitre><id>T1498</id></mitre>
  </rule>
</group>
```
