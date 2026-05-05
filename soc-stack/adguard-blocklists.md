# AdGuard Home — DNS filter

> Authoritative DNS for the LAN. Forwarded from the MikroTik for every
> client VLAN. Blocklists for malware C2, ad networks, and known phishing
> infrastructure. Per-client query log fed back into the SIEM.

| | |
|---|---|
| **Host** | 192.168.60.30 (LXC, Debian 12, 1 vCPU / 1 GB RAM) |
| **Listen ports** | tcp/53 + udp/53 (DNS), tcp/3000 (admin UI on Home only) |
| **Upstream resolvers** | 1.1.1.1, 9.9.9.9 (DoT, with fallback to plain) |
| **Admin auth** | TOTP-MFA |

---

## DNS path in this lab

```
client (any VLAN)
  → MikroTik 10.0.0.1 :53        (forwarder, ASA-permitted)
    → AdGuard 192.168.60.30 :53   (filter)
      → 1.1.1.1 :853 (DoT)
      → 9.9.9.9 :853 (DoT)
```

The MikroTik is the resolver every client points at via DHCP. The MikroTik
forwards to AdGuard. AdGuard does the filtering and forwards filtered
queries upstream over DoT.

This means:

- Every DNS query from every client is logged on AdGuard with the client's
  source IP.
- A client who manually overrides DNS to `8.8.8.8` is logged **and dropped**
  by ASA ACLs (no client VLAN has direct outbound DNS to the Internet).
- Blocklists apply uniformly across all VLANs — there is exactly one
  policy plane.

---

## Install

```bash
root@adguard:~# curl -sLO https://static.adguard.com/adguardhome/release/AdGuardHome_linux_amd64.tar.gz
root@adguard:~# tar xzf AdGuardHome_linux_amd64.tar.gz
root@adguard:~# ./AdGuardHome/AdGuardHome -s install
root@adguard:~# systemctl status AdGuardHome
```

Initial setup wizard runs on `:3000`. Set admin user, password, choose ports
(53 + 3000), set the upstream DNS servers.

---

## Blocklists in use

| List | Source | Purpose |
|------|--------|---------|
| AdGuard DNS filter | https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt | General ads + tracking |
| StevenBlack/hosts (unified) | https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | Ads + malware + fakenews |
| OISD basic | https://big.oisd.nl/ | Curated, well-maintained |
| Phishing Army | https://phishing.army/download/phishing_army_blocklist_extended.txt | Phishing-specific |
| URLhaus by abuse.ch | https://urlhaus.abuse.ch/downloads/hostfile/ | Active malware C2 |
| Malware-Filter (DigitalSide) | https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt | Recent observed threats |

Lists update every 4 hours by default. Check via:

```bash
root@adguard:~# tail -f /opt/AdGuardHome/data/AdGuardHome.log | grep -i 'updated'
```

---

## Per-client clients block

Each VLAN is registered as a "client" so the dashboard groups queries by
network segment instead of by IP:

```
Settings → Client settings → New client

  Name:   home-vlan-20
  IDs:    192.168.20.0/24
  Tags:   trusted

  Name:   wireless-vlan-30
  IDs:    192.168.30.0/24
  Tags:   wireless

  Name:   kids-vlan-40
  IDs:    192.168.40.0/24
  Tags:   kids, restricted
  Filter:  use_global_blocked_services + add: youtube.com (specific to Kids)

  Name:   guest-vlan-50
  IDs:    192.168.50.0/24
  Tags:   guest

  Name:   server-vlan-60
  IDs:    192.168.60.0/24
  Tags:   server, internal
  Filter: use_global_blocked_services (no extra restrictions)
```

The Kids client gets an additional rule that blocks YouTube during weekday
hours — this kind of policy is exactly what makes a client-grouping useful.

---

## SIEM integration

AdGuard's query log is JSON. Wazuh tails it via the agent on the AdGuard
LXC:

```xml
<!-- /var/ossec/etc/ossec.conf on adguard LXC -->
<localfile>
  <log_format>json</log_format>
  <location>/opt/AdGuardHome/data/querylog.json</location>
</localfile>
```

A custom decoder extracts `client`, `question`, `answer`, `result`:

```xml
<decoder name="adguard-querylog">
  <prematch>"QH":</prematch>
</decoder>

<decoder name="adguard-fields">
  <parent>adguard-querylog</parent>
  <regex>"QH":"([^"]+)".*"IP":"([^"]+)".*"Reason":"([^"]+)"</regex>
  <order>question,client_ip,reason</order>
</decoder>
```

Local rule fires when a client hits a blocked domain three times in 5 min:

```xml
<rule id="100410" level="8" frequency="3" timeframe="300">
  <decoded_as>adguard-querylog</decoded_as>
  <field name="reason">^(Blocked|FilteredBlackList)$</field>
  <description>Client repeatedly querying blocked domain — possible malware beaconing</description>
  <mitre><id>T1071.004</id></mitre>
</rule>
```

Three blocks of the same domain in 5 min is exactly the signature of a
beaconing implant trying to phone home, and worth a SIEM event even if no
data exfil happened (the block worked).

---

## Operational notes

- AdGuard's UI is exposed only on the Home VLAN, enforced by the ASA
  `home_access` ACL and again by AdGuard's own `bind_hosts: ['192.168.60.30']`
  + iptables rule on the LXC.
- DoT to upstream is **always** preferred. Plain UDP/53 to upstream falls
  back only on first-resolution boot, and only if DoT initialisation
  fails.
- Total query volume in this lab: ~30k queries / day, ~6% blocked. The
  block ratio is the leading indicator I watch — sudden jumps mean
  either a blocklist update went wrong or a client got infected.
