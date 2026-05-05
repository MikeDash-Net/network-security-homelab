# Wazuh deployment notes

> Single-node Wazuh manager + indexer + dashboard, running as an LXC on the
> Server VLAN. Five agents enrolled (Proxmox host, three Linux LXCs,
> Windows admin PC), plus syslog ingestion from MikroTik, ASA, and Aruba.

| | |
|---|---|
| **Manager IP** | 192.168.60.20 |
| **Version** | 4.7.5 (pinned — see [`/runbooks/03-wazuh-agent-enrollment.md`](../runbooks/03-wazuh-agent-enrollment.md)) |
| **Components** | wazuh-manager, wazuh-indexer (single node), wazuh-dashboard |
| **OS** | Debian 12 LXC, 4 vCPU / 8 GB RAM / 60 GB ZFS dataset |

---

## Deployment

The single-node "all-in-one" install script handles manager + indexer +
dashboard on the same host. For a five-agent lab this is more than enough;
splitting into roles would be premature.

```bash
root@wazuh:~# curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
root@wazuh:~# bash ./wazuh-install.sh -a -i
```

Output prints the auto-generated `admin` password. **Capture this immediately
to a password vault** — it is shown once. Then `apt-mark hold` every Wazuh
package to prevent silent major-version upgrades:

```bash
root@wazuh:~# apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

Rotate the dashboard admin password before exposing the UI:

```bash
root@wazuh:~# /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p '<NEW_PASSWORD>'
```

---

## Agent fleet

| Host | Role | OS | Notes |
|------|------|----|-------|
| pve-host | Hypervisor | Proxmox VE | rootcheck + log_alerts only; container telemetry comes from per-LXC agents |
| npm | Reverse proxy | Debian 12 LXC | FIM on `/data/nginx/proxy_host`, custom decoder for NPM access logs |
| envisionite-app | Application backend | Alpine LXC | FIM on `/var/www`, syscheck every 12 h |
| mgmt-tools | Backup host | Debian 12 LXC | Custom decoder for the `config-backup` syslog tag |
| admin-pc | Workstation | Windows 11 | sysmon configured; events fed via the Wazuh agent collector |

Agents are enrolled with the procedure in
[`/runbooks/03-wazuh-agent-enrollment.md`](../runbooks/03-wazuh-agent-enrollment.md).

---

## Syslog ingestion (network devices)

Manager listens on UDP/514 by default. Add a remote listener:

```xml
<!-- /var/ossec/etc/ossec.conf (excerpt) -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.0.0.1</allowed-ips>          <!-- MikroTik -->
  <allowed-ips>192.168.20.1</allowed-ips>      <!-- ASA inside -->
  <allowed-ips>192.168.20.250</allowed-ips>    <!-- Aruba mgmt -->
</remote>
```

Restart the manager:

```bash
root@wazuh:~# systemctl restart wazuh-manager
root@wazuh:~# tail -f /var/ossec/logs/ossec.log | grep -i 'syslog'
```

Within minutes the dashboard's "Network" group should show events from
each device — the rule decoders for ASA, MikroTik, and ArubaOS are bundled
with Wazuh, so no custom decoder work was needed for the device side.

---

## Custom decoders

The two custom decoders that exist in this lab:

### 1. `cron-ddns` — MikroTik DDNS update logs

`/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="cron-ddns">
  <prematch>cron-ddns:</prematch>
</decoder>

<decoder name="cron-ddns-update">
  <parent>cron-ddns</parent>
  <regex>cron-ddns: (\S+)</regex>
  <order>action</order>
</decoder>
```

Used by rule 100221 in the MikroTik PPPoE incident
([`/incidents/2026-04-22-mikrotik-pppoe-auth-loop.md`](../incidents/2026-04-22-mikrotik-pppoe-auth-loop.md)).

### 2. `config-backup` — daily config-snapshot SHA-256

`/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="config-backup">
  <prematch>config-backup:</prematch>
</decoder>

<decoder name="config-backup-hash">
  <parent>config-backup</parent>
  <regex>config-backup: (\w+)\s+(\S+)</regex>
  <order>sha256,filename</order>
</decoder>
```

Used by rule 100330 in [`/runbooks/04-config-backup.md`](../runbooks/04-config-backup.md).

---

## Custom rules

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,wan,">
  <rule id="100210" level="7" frequency="5" timeframe="300">
    <if_sid>17000</if_sid>
    <field name="ifInOctets_delta">^0$</field>
    <field name="ifOperStatus">^1$</field>
    <description>WAN interface up but no inbound packets — possible RX failure</description>
    <mitre><id>T1499.004</id></mitre>
  </rule>

  <rule id="100221" level="9" frequency="3" timeframe="300">
    <decoded_as>cron-ddns</decoded_as>
    <match>update failed - public IP not learned</match>
    <description>DDNS cannot publish public IP — WAN PPP session likely down</description>
    <mitre><id>T1498</id></mitre>
  </rule>

  <rule id="100307" level="9" frequency="2" timeframe="60">
    <if_sid>31100</if_sid>
    <match>HTTP/2 5..</match>
    <description>External uptime check failing for 60s+</description>
  </rule>

  <rule id="100308" level="10" frequency="2" timeframe="600">
    <decoded_as>npm-upstream-poll</decoded_as>
    <field name="upstream_status">^(0|5..)$</field>
    <description>NPM upstream unreachable — backend service may have moved IP</description>
    <mitre><id>T1499.004</id></mitre>
  </rule>

  <rule id="100330" level="7">
    <decoded_as>config-backup</decoded_as>
    <description>Network device config snapshot generated</description>
  </rule>
</group>
```

The four rules above (100210, 100221, 100307, 100308) all came out of real
incidents in this lab. Each rule has a corresponding incident write-up in
[`/incidents/`](../incidents/).

---

## Operational notes

- Indexer disk usage: ~1.2 GB / week with current rule volume. ZFS dataset
  trimmed weekly via `zpool trim`.
- Dashboard auth: TOTP-MFA enabled for the `admin` user.
- API access: scoped read-only token used by Velociraptor for IOC enrichment.
