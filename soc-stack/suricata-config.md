# Suricata deployment notes

> AF_PACKET sensor on the Proxmox `vmbr0` bridge, fed by an L2 port mirror
> from the Aruba switch. Alerts ship as EVE JSON to Wazuh, which decodes
> them via the bundled Suricata rule set and surfaces them in the dashboard
> with `signature_id` preserved.

| | |
|---|---|
| **Sensor host** | Suricata LXC, Debian 12, 4 vCPU / 6 GB RAM |
| **Capture** | AF_PACKET on `span0` (raw NIC, port mirror destination) |
| **Ruleset** | ET Open — 49,838 rules at last `suricata-update` |
| **Output** | EVE JSON → Wazuh decoder |
| **Mode** | NIDS (read-only). Not inline. |

---

## Why NIDS, not IPS

See [`/runbooks/05-port-mirror-to-ids.md`](../runbooks/05-port-mirror-to-ids.md).
Short version: I want detection without the risk of dropping production
traffic on a false-positive. SPAN gives me visibility, alerts go to the SIEM,
no action on the live path.

---

## Install

```bash
root@suricata:~# apt update && apt install suricata jq
root@suricata:~# suricata --build-info | head -20
```

Pin the version:

```bash
root@suricata:~# apt-mark hold suricata
```

---

## AF_PACKET configuration

`/etc/suricata/suricata.yaml` (excerpt):

```yaml
af-packet:
  - interface: span0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 200000
    block-size: 1048576
    checksum-checks: no    # SPAN delivers re-stamped frames

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            metadata: yes
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - flow
        - stats:
            interval: 60
```

Restart and verify capture is live:

```bash
root@suricata:~# systemctl restart suricata
root@suricata:~# tail -f /var/log/suricata/suricata.log | grep -E 'engine started|threads'
```

---

## Ruleset management

`suricata-update` is configured to pull ET Open and merge with the local
rules in `/etc/suricata/rules/local.rules`:

```bash
root@suricata:~# suricata-update list-sources
root@suricata:~# suricata-update enable-source et/open
root@suricata:~# suricata-update
```

The result is written to `/var/lib/suricata/rules/suricata.rules`. The
running engine is reloaded without restart:

```bash
root@suricata:~# kill -USR2 $(pgrep -of "suricata -c")
root@suricata:~# tail -1 /var/log/suricata/suricata.log
```

The full tuning workflow lives in
[`/runbooks/02-suricata-rule-tuning.md`](../runbooks/02-suricata-rule-tuning.md).

---

## Wazuh integration

Wazuh ships a Suricata decoder out of the box; no custom decoder needed for
EVE JSON. Configure the agent on the Suricata LXC to tail `eve.json`:

```xml
<!-- /var/ossec/etc/ossec.conf on the Suricata LXC -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

After agent restart, alerts surface in the dashboard with:

- `rule.groups: ["suricata", "ids"]`
- `data.alert.signature_id`
- `data.alert.signature`
- `data.alert.category`
- `data.alert.severity`
- `data.src_ip`, `data.dest_ip`, `data.src_port`, `data.dest_port`
- `data.flow_id` (joinable with HTTP/DNS/TLS records of the same flow)

---

## Local rules in this lab

`/etc/suricata/rules/local.rules`:

```text
# 1000041 — Wireless VLAN reaching Server VLAN on a non-allowed port
alert tcp [192.168.30.0/24] any -> [192.168.60.0/24] ![22,8006,8443] (
    msg:"LOCAL: Wireless VLAN reaching Server VLAN on unexpected port";
    flow:to_server,established;
    classtype:policy-violation;
    sid:1000041; rev:1;
    metadata:created_at 2026-04-29;
)

# 1000042 — Kids VLAN attempting any non-DNS traffic
alert ip [192.168.40.0/24] any -> any any (
    msg:"LOCAL: Kids VLAN traffic outside DNS scope";
    flow:to_server;
    threshold: type both, track by_src, count 5, seconds 60;
    classtype:policy-violation;
    sid:1000042; rev:1;
)

# 1000043 — DNS query to a known-bad TLD from any client VLAN
alert dns any any -> any any (
    msg:"LOCAL: DNS query for known-suspect TLD";
    dns.query; content:".tk"; nocase; endswith;
    classtype:bad-unknown;
    sid:1000043; rev:1;
)
```

These complement the ASA ACLs — even if a misconfig opens a path on the L3,
Suricata still sees the L2 frame and alerts.

---

## Performance baseline

| Metric | Target | Current |
|--------|--------|---------|
| `kernel_drops` per 24h | 0 | 0 |
| Rule-match latency (p99) | < 5 ms | 1.2 ms |
| Rule reload time | < 30 s | 9 s |
| EVE JSON write rate | < 5 MB/min | ~1.4 MB/min |
| Disk usage `/var/log/suricata` | < 50 GB | 12 GB (rotation: daily, 14 days) |

Drop counter is the **only** number that, if non-zero, means we are missing
data. Everything else is operational comfort.
