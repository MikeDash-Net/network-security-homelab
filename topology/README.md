# Topology

A vertical view of the lab, from the internet edge down to the access layer. The networking here runs my home for real.

## Diagram (text)

```
                     Internet
                (dual-WAN · PPPoE ×2)
                         │
            ┌────────────┴────────────┐
            │   MikroTik RB5009        │   edge router
            │   PCC load-balance       │   NAT · DDNS
            │   + WAN failover         │   mgmt 10.0.0.1
            └────────────┬────────────┘
                         │   /30 transit  10.0.0.0/30
            ┌────────────┴────────────┐
            │   Cisco ASA 5515-X       │   L3 gateway / inter-VLAN router
            │   default-deny ACLs      │   NAT
            │   sub-interface per VLAN │   outside 10.0.0.2
            └────────────┬────────────┘
                         │   802.1Q trunk (all VLANs)
            ┌────────────┴────────────┐
            │   HPE Aruba 2530-24      │   L2 switch · PoE+
            │   port security · BPDU   │   mgmt 192.168.20.250
            └────────────┬────────────┘
        ┌───────┬────────┼────────┬────────┬─────────┐
      VLAN 20  VLAN 30  VLAN 40  VLAN 50  VLAN 60
       Home    Wireless   Kids    Guests  Server/Lab
                         │
                  UniFi U6+ AP  (each SSID tagged into its VLAN)
```

## Addressing

| Segment | Subnet | Gateway (ASA) | Notes |
|---------|--------|---------------|-------|
| Transit (MikroTik ↔ ASA) | 10.0.0.0/30 | — | MikroTik 10.0.0.1 · ASA 10.0.0.2 |
| VLAN 20 — Home | 192.168.20.0/24 | 192.168.20.1 | Aruba mgmt at 192.168.20.250 |
| VLAN 30 — Wireless | 192.168.30.0/24 | 192.168.30.1 | |
| VLAN 40 — Kids | 192.168.40.0/24 | 192.168.40.1 | |
| VLAN 50 — Guests | 192.168.50.0/24 | 192.168.50.1 | |
| VLAN 60 — Server / Lab | 192.168.60.0/24 | 192.168.60.1 | static addressing |

The ASA terminates the inside trunk on a sub-interface per VLAN, and that sub-interface (`.1`) is the default gateway for the segment.

> **Management VLAN (10):** also defined on the Aruba switch and reserved for
> device management, but **not yet populated** (no IP, no hosts) — management
> currently runs over VLAN 20. Migrating it onto VLAN 10 is a planned hardening
> step; it is not one of the five active segments above.

## Hardware in the path

| Role | Device |
|------|--------|
| Edge router | MikroTik RB5009UPr+S+ |
| L3 firewall / inter-VLAN router | Cisco ASA 5515-X |
| L2 switch | HPE Aruba 2530-24-PoE+ (J9779A) |
| Hypervisor | Dell Precision 7920 · dual Xeon Gold 6152 · 256 GB RAM · Proxmox VE 9.1 |
| Wi-Fi AP | Ubiquiti UniFi U6+ |

Idle **lab/practice gear** (powered off, not in the production path): Cisco ISR 4300, Catalyst 2960 — used for CCNA-style practice, not for routing live traffic.

## Traffic flow

- **Outbound to the internet** — a client's default gateway is its ASA VLAN sub-interface. The ASA applies the segment's inbound ACL, routes the permitted traffic over the `/30` transit to the MikroTik, which NATs out over the active WAN. PCC spreads sessions across both WANs and fails over if one drops.
- **Inter-VLAN** — denied by default. Only flows with an explicit, logged ACL entry cross between segments through the ASA (for example, the server segment reaching the switch for management).
- **Wi-Fi** — the UniFi AP maps each SSID to a VLAN and tags the frames; they travel the 802.1Q trunk to the Aruba and up to the ASA gateway. A device joining the guest SSID lands in VLAN 50 with no extra configuration.
