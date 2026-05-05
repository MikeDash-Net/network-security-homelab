# Inter-VLAN allow / deny matrix

> Quick-reference matrix of what each VLAN can reach. Authoritative
> ACLs live in [`/policy/inter-vlan-acl.md`](../policy/inter-vlan-acl.md);
> this is the human-readable summary.

## Matrix

Rows are the **source** VLAN. Columns are the **destination**. Cell value
indicates whether the ASA permits the indicated traffic.

| Source ↓ \\ Dest → | Home (20) | Wireless (30) | Kids (40) | Guests (50) | Server (60) | Internet |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Home (20)**     | self | ❌ | ❌ | ❌ | partial | ✅ |
| **Wireless (30)** | ❌ | self | ❌ | ❌ | ❌ | ✅ |
| **Kids (40)**     | ❌ | ❌ | self | ❌ | ❌ | ❌ (DNS only) |
| **Guests (50)**   | ❌ | ❌ | ❌ | self | ❌ | ✅ |
| **Server (60)**   | ❌ | ❌ | ❌ | ❌ | self | ✅ (egress for updates) |

Legend: ✅ = permitted, ❌ = denied, partial = host-and-port specific permits only.

## "Partial" Home → Server breakdown

The only VLAN with cross-VLAN reach is Home, and only into Server, and only
to specific hosts on specific ports:

| Destination | Port | Service | Why |
|-------------|------|---------|-----|
| `192.168.60.10` | tcp/8443 | UniFi controller | Wi-Fi config |
| `192.168.60.0/24` | tcp/8006 | Proxmox web UI | Hypervisor admin |
| `192.168.60.0/24` | tcp/22 | SSH | Server admin |
| `192.168.60.20` | any | Wazuh | SIEM access |
| `192.168.60.40` | any | Cortex | IOC enrichment |
| `192.168.60.60` | any | Velociraptor | EDR / DFIR |

Every other Home → Server packet is denied **and logged**.

## Outbound DNS path

All client VLANs must use the MikroTik forwarder (`10.0.0.1:53`); direct
outbound to public DNS resolvers (8.8.8.8, 1.1.1.1) is denied.

```
client → MikroTik 10.0.0.1:53 → AdGuard 192.168.60.30:53 → 1.1.1.1:853 (DoT)
                                                        → 9.9.9.9:853 (DoT)
```

This means:

- **Every** DNS query from **every** VLAN passes through AdGuard's
  blocklists.
- A client overriding its DNS (e.g. hard-coding 8.8.8.8) gets dropped at
  the ASA and logged.
- Encrypted DoH is blocked by destination IP at the ASA (ranges of known
  public DoH endpoints denied at section 6 of `wireless_access` —
  see `/policy/inter-vlan-acl.md`).

## Special cases

- **MGMT VLAN (10)** is reserved for switch / device management. No host
  IP is assigned to it on the ASA; access is via in-band SSH from the Home
  VLAN, restricted by an SSH ACL on each device.
- **DEFAULT VLAN (1)** is administratively pruned on every trunk and edge
  port. A device that lands on VLAN 1 is functionally isolated.
- **Honeypot host** (192.168.60.99) receives DNAT'd traffic from
  attacker-popular ports (tcp/4444, tcp/4445) on either WAN. It is on the
  Server VLAN but **the ACL deny `Home → Server` covers it**, so no
  internal client can reach it accidentally.
