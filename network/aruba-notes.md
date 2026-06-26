# HPE Aruba 2530-24-PoE+ — notes

The Aruba is the Layer 2 access layer. It carries every VLAN to the ASA as a single 802.1Q trunk, provides PoE+ to the Wi-Fi AP, and handles the edge-port protections you want on a switch that anything can plug into. Management is at `192.168.20.250` on VLAN 20.

> Snippets below are **sanitized** and illustrative (HPE/Aruba-style CLI). No real credentials or serials.

## VLANs and the trunk to the ASA

VLANs are defined locally and tagged up to the ASA on the uplink; access ports carry their segment untagged:

```
vlan 60
   name "Server-Lab"
   tagged <uplink-to-asa>
   untagged <server-ports>
```

One tagged uplink carries all five VLANs to the ASA, which routes and filters between them.

## Spanning tree + BPDU protection

```
spanning-tree
spanning-tree <edge-ports> admin-edge-port
spanning-tree <edge-ports> bpdu-protection
```

Edge ports are treated as edge (fast transition) and shut if they ever receive a BPDU, so a misplaced switch or a loop can't disturb the topology.

## Port security and discovery

- Port security on access ports to limit which MACs can appear where.
- LLDP for neighbour discovery.
- SNMP exposed read-only to the monitoring host (Zabbix) for interface and health metrics.

## Management hardening

- SSH version 2 only; Telnet and the web UI disabled.
- Management restricted to VLAN 20.
- Consistent NTP across the device (shared with the rest of the lab) so logs and metrics line up.
