# Sanitized device configs

These are **sanitized** exports of the configurations running on the lab's
network devices. They are intended to be readable by anyone reviewing the
lab — every secret is scrubbed, every public IP is replaced with the
placeholder `XX.XX.XX.X`, and every internal hostname / SSID is renamed to
a generic placeholder.

| File | Device | Notes |
|------|--------|-------|
| [`asa-5515.cfg.example`](asa-5515.cfg.example) | Cisco ASA 5515-X | L3 firewall, inter-VLAN policy, NAT |
| [`mikrotik.rsc.example`](mikrotik.rsc.example) | MikroTik RB5009UPr+S+ | Edge router, dual-PPPoE, PCC failover |
| [`aruba-2530.cfg.example`](aruba-2530.cfg.example) | HP Aruba 2530-24-PoE+ | L2 switch, MSTP, port mirror |

---

## What "sanitized" means here

For every config in this folder:

| Field | Treatment |
|-------|-----------|
| Public IPv4 addresses | Replaced with `XX.XX.XX.X` |
| Username / password | Replaced with `REDACTED` |
| SNMP communities | Replaced with `REDACTED` |
| RADIUS / AAA shared keys | Replaced with `REDACTED` |
| IPSec / VPN pre-shared keys | Replaced with `REDACTED` |
| Certificate blobs | Stripped entirely |
| Hostnames / SSIDs | Renamed to generic placeholders (e.g. `HOME-SSID`, `IOT-SSID`) |
| RFC 1918 internal IPs | Kept as-is — these are not secrets |
| ACL names, VLAN numbers, port numbers | Kept as-is — these document the design |

The redaction was performed by the procedure in
[`/runbooks/04-config-backup.md`](../runbooks/04-config-backup.md), which
is the same daily-backup pipeline that produces these files in operation.

## What these files are useful for

- **Verifying claims in the README and incident reports.** Every command
  referenced in `/incidents/` or `/runbooks/` should be visible in one of
  these files — that consistency is the point.
- **Reading reference configs.** They show what a hardened ASA / MikroTik /
  Aruba actually looks like end-to-end, not just snippets.
- **Diff-replay during a re-build.** If I ever have to re-image a device,
  these files plus the secrets vault are the recipe.

## What they are **not**

- They are **not** drop-in templates. The IP plan, VLAN numbers, and host
  identities are specific to this lab. Copy-pasting will not work; reading
  for patterns will.
- They are **not** complete. The redaction strips encrypted material;
  re-applying these configs on hardware would require regenerating SSH
  keys, certificates, and shared secrets.
