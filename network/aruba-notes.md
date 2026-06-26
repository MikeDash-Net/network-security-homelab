# HPE Aruba 2530-24-PoE+ — notes

The Aruba is the Layer 2 access layer. It carries every VLAN to the ASA as a single 802.1Q trunk, provides PoE+ to the Wi-Fi AP, and handles the edge-port protections you want on a switch that anything can plug into. Management is at `192.168.20.250` on VLAN 20.

> Snippets below are **sanitized** and illustrative (HPE/Aruba-style CLI). No real credentials or serials.

## VLANs and the trunk to the ASA

VLANs are defined locally and tagged up to the ASA on the uplink; access ports carry their segment untagged:

```
vlan 60
   name "Server"
   tagged <uplink-to-asa>
   untagged <server-ports>
```

One tagged uplink carries all five VLANs to the ASA, which routes and filters between them.

## Edge-port hardening — port security + BPDU protection

Empty access ports are the soft spot on a switch anyone can reach, so the edge ports get two controls while uplinks and infrastructure ports are deliberately left out.

```
! empty edge ports: pin to one MAC, shut on violation, guard against rogue BPDUs
port-security <edge-ports> learn-mode static address-limit 1 action send-disable
spanning-tree <edge-ports> admin-edge-port
spanning-tree <edge-ports> bpdu-protection
spanning-tree bpdu-protection-timeout 300
spanning-tree trap errant-bpdu
```

- **Port security** (`learn-mode static`, `address-limit 1`) learns and pins one MAC on each empty edge port and disables the port if a second appears — a hub or rogue device on a spare port takes itself offline.
- **BPDU protection** disables an edge port that ever receives a BPDU, so a misplaced switch or a loop can't influence spanning tree. `bpdu-protection-timeout 300` auto-recovers a tripped port after 5 minutes — a safety net for a change pushed remotely with no console at hand.
- **The management port is non-disruptive on purpose.** The port my admin station sits on uses `action send-alarm` with its MAC pinned, not `send-disable` — an alert to syslog rather than a port that could lock me out of my own switch.
- **Uplinks and infrastructure ports are excluded deliberately.** The trunk to the ASA, the AP port (many client MACs by design), the Proxmox/mirror port and the links to the MikroTik are left untouched — port security or BPDU guard on a trunk or router link would err-disable a working uplink. Scope was taken from the live MAC table and LLDP, not assumed.

## Discovery and SNMP

- **Unused ports are administratively disabled** — the simplest control for ports that should never carry traffic.
- **LLDP** for neighbour discovery — used to confirm what's actually on each port before applying the hardening above.
- **SNMP read-only** to the monitoring host for interface and health metrics; the management plane is locked by `ip authorized-managers` (full management from VLAN 20 only, monitoring host limited to operator/read).

## Management hardening

- SSH version 2 only; Telnet and the web UI disabled.
- Management restricted to VLAN 20 and enforced with `ip authorized-managers` (manager access from VLAN 20, operator/read for the monitoring host).
- Errant-BPDU and port-security intrusion events trapped to **syslog → Wazuh**, so a tripped port is visible rather than silent.
- Consistent NTP (SNTP) across the device, shared with the rest of the lab, so logs and metrics line up.
