# Runbook 02 — Suricata rule tuning workflow

> Scope: triage Suricata alerts in the Wazuh dashboard, classify them as
> true / false / informational, and produce a sustainable noise-reduction
> change. Run weekly, or whenever the alert volume crosses 200/day.

| | |
|---|---|
| **Target** | Suricata 6.x sensor in AF_PACKET mode on Proxmox bridge `vmbr0` |
| **Ruleset** | ET Open (Emerging Threats Open) — currently 49,838 rules |
| **Output** | EVE JSON → Wazuh decoder → SIEM dashboard |
| **Pre-reqs** | SSH access to the Suricata LXC, Wazuh dashboard URL, ability to write `local.rules` and `disable.conf` |
| **Risk** | Medium — disabling a rule is a recorded decision, not a "make it go away" |

---

## Daily/weekly triage cycle

1. **Pull the top-N noisy SIDs from Wazuh.**

   In the Wazuh discover view, filter:
   ```
   rule.groups: "suricata" AND _exists_: data.alert.signature_id
   ```
   Group by `data.alert.signature_id` over the last 7 days.

2. **For each SID in the top 20, decide one of three outcomes:**

   - **Keep, accept the volume.** Rule is firing on real activity I want to
     see — for example, outbound DNS queries hitting a known bad domain. No
     change.
   - **Tune the rule.** Rule is correct but firing too broadly. Narrow it
     with a `flowbits`, threshold, or `target` modifier.
   - **Disable the rule.** Rule does not apply to my network at all (e.g.
     anti-virus signature for a Windows IIS exploit when I have no Windows
     servers). Add to `disable.conf` with a justification.

3. **Apply the change, reload, verify.**

---

## Procedure — disable a rule with justification

Edit `disable.conf`:

```bash
root@suricata:~# vi /etc/suricata/disable.conf
```

Add a new line. **Always include a comment with the reason and the date.**
This is the audit trail — it is the difference between defensible noise
reduction and "I disabled it because it was annoying".

```text
# 2026-04-29 — anti-virus sig for IIS .ASP upload — no Windows IIS in scope
2025840

# 2026-04-29 — broad DNS query log on outbound to common CDN — handled by AdGuard
2030001
```

Reload the ruleset:

```bash
root@suricata:~# suricata-update
root@suricata:~# kill -USR2 $(pgrep -f "suricata -c")
root@suricata:~# tail -f /var/log/suricata/suricata.log | grep -i 'rule reload'
```

Verify the rule is no longer loaded:

```bash
root@suricata:~# grep -c "^alert.*sid:2025840;" /var/lib/suricata/rules/suricata.rules
0
```

---

## Procedure — threshold a noisy rule

Some rules are correct but fire 50× on a single normal user action (web
browsing on a long-running tab). Threshold them in `/etc/suricata/threshold.config`:

```text
# 2026-04-29 — limit chatty rule to 5 hits / 60 s per source IP
threshold gen_id 1, sig_id 2010935, type both, track by_src, count 5, seconds 60
```

`type both` keeps the first N hits in a window and drops the rest, so you
keep the signal without flooding the SIEM.

---

## Procedure — write a local rule

Local rules go in `/etc/suricata/rules/local.rules` and are loaded last.
Use SID range `1000000–1099999` to avoid collision with ET ruleset.

Example — alert on any TCP connection from VLAN 30 (Wireless) to VLAN 60
(Server) on a non-allowed port. This duplicates the ASA ACL deny but gives
me a NIDS-side data point if the ACL is ever bypassed:

```text
alert tcp [192.168.30.0/24] any -> [192.168.60.0/24] ![22,8006,8443] (
    msg:"LOCAL: Wireless VLAN reaching Server VLAN on unexpected port";
    flow:to_server,established;
    classtype:policy-violation;
    sid:1000041;
    rev:1;
    metadata:created_at 2026-04-29;
)
```

Reload, then watch the dashboard for `signature_id=1000041`. The first hit on
this rule means **either** an ACL leak **or** a misconfigured client trying
to reach the wrong subnet.

---

## Procedure — verify rule order is correct

```bash
root@suricata:~# suricata --build-info | grep "Rule profiling"
root@suricata:~# suricata-update list-sources --enabled
Name: et/open
URL : https://rules.emergingthreats.net/open/suricata-6.0.0/emerging.rules.tar.gz
Local: /etc/suricata/rules/local.rules
```

Local rules must be in the load list. If `local.rules` does not appear,
re-add it:

```bash
root@suricata:~# echo "- local.rules" >> /etc/suricata/suricata.yaml.d/local-rules.yaml
```

(`include` order matters — check `suricata.yaml`.)

---

## Verification

- Wazuh dashboard: alert volume for the disabled SID drops to zero on the
  next polling window.
- Wazuh dashboard: `signature_id` for the new local rule appears under
  `rule.groups: "suricata"` after the next test event.
- `/var/log/suricata/suricata.log` shows `Engine started` with the new
  rule count, no errors.

---

## Anti-patterns (do not do)

- ❌ **Disable a rule without a comment.** A SID in `disable.conf` with no
  reason is unmaintainable — six months later you will not remember why.
- ❌ **Disable a rule because of one false positive without checking the
  pattern.** One false positive on the same source might hint at a subtle
  network misconfig that the rule is correctly catching.
- ❌ **Edit `/var/lib/suricata/rules/suricata.rules` directly.** That file
  is overwritten by `suricata-update`. Local rules go in `local.rules`,
  disables in `disable.conf`, modifications in `modify.conf`.
