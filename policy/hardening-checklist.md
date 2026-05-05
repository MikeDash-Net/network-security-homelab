# Three-layer hardening checklist

> The exact commands and configuration items that turn each device from
> "reachable on the network" to "running with sane defaults". Organised by
> layer (Edge → L3 → L2) plus a cross-cutting practice section.

---

## Layer 1 — Edge: MikroTik RB5009UPr+S+

### 1.1 Drop everything on the WAN input chain

The default RouterOS firewall is permissive. Replace it with deny-by-default
on the input chain:

```text
/ip firewall filter
add chain=input action=accept connection-state=established,related comment="established/related"
add chain=input action=accept protocol=icmp limit=50,5:packet comment="ICMP rate-limited"
add chain=input action=accept in-interface-list=LAN comment="LAN trusted"
add chain=input action=drop in-interface-list=WAN comment="drop everything else from WAN"
```

### 1.2 MSS clamp to avoid PMTU blackholes

PPPoE encapsulation drops the effective MTU; without an MSS clamp, large
TCP transfers will black-hole on paths that drop ICMP-too-big.

```text
/ip firewall mangle
add chain=forward action=change-mss new-mss=1452 \
    protocol=tcp tcp-flags=syn passthrough=yes \
    comment="MSS clamp for PPPoE"
```

### 1.3 SSH on mgmt interface only, strong-crypto on

```text
/ip ssh set strong-crypto=yes \
    allow-none-crypto=no \
    forwarding-enabled=no
/ip service set ssh address=192.168.20.0/24
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes        ! HTTP off; use HTTPS only if needed
/ip service set api disabled=yes
/ip service set api-ssl disabled=yes
```

### 1.4 DDNS on a 5-minute cron, two zones

```text
/system scheduler
add name=ddns-update interval=5m on-event=ddns-script \
    start-time=startup
```

The script reads the current PPPoE address and pushes to Cloudflare for
both apex and a wildcard.

### 1.5 Honeypot DNATs to an isolated host

`tcp/4444` and `tcp/4445` are common attacker pivot ports. Forward them to
an isolated honeypot so I get visibility of the scan:

```text
/ip firewall nat
add chain=dstnat action=dst-nat protocol=tcp dst-port=4444,4445 \
    in-interface-list=WAN to-addresses=192.168.60.99 \
    comment="honeypot DNAT"
```

### Edge checklist

- [x] Input chain default deny on WAN
- [x] ICMP rate-limited (still useful for diagnostics)
- [x] MSS clamp on PPPoE forward chain
- [x] SSH restricted to mgmt subnet
- [x] Telnet, FTP, HTTP, API services disabled
- [x] DDNS automated, two zones
- [x] Honeypot DNAT to isolated host
- [x] PCC mangle rules for dual-WAN load-balance
- [x] All admin via SSH key, no passwords

---

## Layer 2 — L3: Cisco ASA 5515-X

### 2.1 SSH v2 only, modern KEX/cipher set

```text
ssh version 2
ssh key-exchange group dh-group14-sha1
ssh cipher encryption high
ssh cipher integrity high
crypto key generate rsa modulus 2048
no telnet outside
no http server enable    ! ASDM disabled — CLI-only
```

### 2.2 AAA local with explicit enable

```text
aaa authentication ssh console LOCAL
aaa authentication enable console LOCAL
username admin password REDACTED privilege 15
service password-encryption
no enable password
```

### 2.3 Login banner — legal notice, no version

```text
banner motd ^
**********************************************************
*  Authorized access only. All activity is logged.        *
*  Disconnect immediately if you are not authorised.      *
**********************************************************
^
```

### 2.4 ACLs — explicit deny on cross-VLAN

See [`inter-vlan-acl.md`](inter-vlan-acl.md) for the full `home_access` ACL.
Each non-Home VLAN gets a similar but tighter ACL:

- `wireless_access` — permit DNS to MikroTik, permit ip any (Internet), deny rest
- `kids_access` — permit DNS only, deny rest (effectively DNS-walled garden)
- `guests_access` — permit ip any (Internet), deny rest
- `server_access` — permit return + permit syslog out + deny rest

### 2.5 Threat-detection enabled

```text
threat-detection basic-threat
threat-detection statistics access-list
threat-detection statistics tcp-intercept rate-interval 30 burst-rate 400 average-rate 200
```

### 2.6 Logging buffered + remote syslog → Wazuh

```text
logging enable
logging buffered notifications
logging trap informational
logging host inside 192.168.60.20
logging timestamp
no logging asdm enable
```

### L3 checklist

- [x] SSH v2 only, telnet off, ASDM off
- [x] AAA local, enable disabled
- [x] Login banner — legal text, no version disclosure
- [x] Service password encryption
- [x] Explicit deny + log on every cross-VLAN
- [x] Threat-detection: basic + ACL + scanning + SYN
- [x] Remote syslog to Wazuh
- [x] No `permit ip any any` in any ACL

---

## Layer 3 — L2: HP Aruba 2530-24-PoE+

### 3.1 Disable everything except SSH

```text
no telnet-server
no web-management
no web-management plaintext
no snmp-server enable
ssh version 2
ssh server vrf default
ip ssh server cipher aes256-ctr aes256-cbc
```

### 3.2 SNMPv3 only, if SNMP is needed at all

```text
snmpv3 enable
snmpv3 user wazuh-mon auth sha REDACTED priv aes REDACTED
snmpv3 group readonly user wazuh-mon sec-model ver3
no snmp-server community public
no snmp-server community private
```

### 3.3 MSTP root, BPDU protection on edge ports

```text
spanning-tree mode mstp
spanning-tree priority 0 instance 0
interface 1-22
   spanning-tree bpdu-protection
   spanning-tree port-fast
exit
```

`spanning-tree bpdu-protection` is the single most important hardening on a
client-facing port. Any device that sends a BPDU on these ports gets the
port disabled — preventing rogue switches from poisoning the spanning tree.

### 3.4 Administratively shut unused ports

```text
interface 5-23
   disable
exit
```

19 unused ports off. A misplaced cable into a disabled port produces nothing.

### 3.5 Console idle timeout, banner

```text
console idle-timeout 600
banner motd "Authorized access only. All activity is logged."
```

### 3.6 Port mirror to IDS sensor

See [`/runbooks/05-port-mirror-to-ids.md`](../runbooks/05-port-mirror-to-ids.md).

### L2 checklist

- [x] Telnet, web-mgmt, plaintext-mgmt all off
- [x] SSH v2 only, restricted ciphers
- [x] SNMPv2c off; SNMPv3 with auth+priv if used
- [x] MSTP root with priority 0
- [x] BPDU protection on every edge port
- [x] Unused ports administratively shut
- [x] Console idle-timeout 10 min
- [x] Login banner
- [x] SPAN to IDS sensor

---

## Cross-cutting practices

### 4.1 Daily config snapshot

Every device exported nightly, redacted, hashed, shipped to Wazuh.
See [`/runbooks/04-config-backup.md`](../runbooks/04-config-backup.md).

### 4.2 Syslog consolidation

```text
ASA       → syslog 192.168.60.20 udp/514
MikroTik  → /system logging action add target=remote remote=192.168.60.20
Aruba     → logging 192.168.60.20
Proxmox   → rsyslog forward to 192.168.60.20
LXCs      → rsyslog forward to host
```

Single SIEM, one query language for every event.

### 4.3 NTP synced from Cloudflare time service

```text
MikroTik:  /system ntp client set enabled=yes servers=time.cloudflare.com
ASA:       ntp server time.cloudflare.com
Aruba:     timesync sntp; sntp unicast; sntp server priority 1 time.cloudflare.com
```

Without consistent time, log correlation across devices fails.

### 4.4 Admin source restricted to MGMT VLAN

Every device's SSH ACL allows only:

- `192.168.20.0/24` — Home (mgmt host)
- denies everything else, including the Server VLAN

If an attacker pivots into Server, they cannot SSH to the network gear from
there.

### 4.5 Change discipline

- Every change has a one-line ticket in `/runbooks/_log.md`.
- Every incident has a post-mortem in `/incidents/`.
- Every config snapshot lives in version control.

---

## Verification

```bash
# From the mgmt host
$ for h in 10.0.0.1 192.168.20.1 192.168.20.250; do
    nmap -sV -p 22,23,80,161,443 "$h" | grep -E '^(Nmap|22|23|80|161|443)'
done
```

Expected:

| Host | tcp/22 | tcp/23 | tcp/80 | udp/161 | tcp/443 |
|------|--------|--------|--------|---------|---------|
| MikroTik 10.0.0.1 | open | filtered | filtered | filtered | filtered |
| ASA 192.168.20.1 | open | filtered | filtered | filtered | filtered |
| Aruba 192.168.20.250 | open | filtered | filtered | filtered | filtered |

Only `tcp/22` (SSH) should be reachable from mgmt. Everything else
filtered.
