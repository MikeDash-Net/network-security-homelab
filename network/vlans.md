# VLANs

The lab is segmented into **five** purpose-based VLANs. The VLANs draw the lines at Layer 2; the Cisco ASA enforces them at Layer 3, where inter-VLAN policy is **default-deny** with explicit, logged exceptions. Each segment has its own named ACL, applied inbound on the ASA sub-interface.

| VLAN | Name | Subnet | Gateway | Trust |
|------|------|--------|---------|-------|
| 20 | Home / MikeNetwork | 192.168.20.0/24 | 192.168.20.1 | Highest |
| 30 | Wireless | 192.168.30.0/24 | 192.168.30.1 | Low |
| 40 | Kids | 192.168.40.0/24 | 192.168.40.1 | Low |
| 50 | Guests | 192.168.50.0/24 | 192.168.50.1 | Untrusted |
| 60 | Server / Lab | 192.168.60.0/24 | 192.168.60.1 | Restricted |

## VLAN 20 — Home / MikeNetwork

The trusted zone: my personal machines and the devices I actually keep data on. It gets the fewest inbound paths from anywhere else, because this is what everything else is being kept away from. The Aruba switch's management interface (`192.168.20.250`) lives here, reachable only from permitted sources.

## VLAN 30 — Wireless

Everyday phones, tablets and laptops on Wi-Fi. More trusted than a random IoT device, but these roam, install apps and join other networks, so they don't belong on the same segment as the wired personal machines. Internet-only by policy.

## VLAN 40 — Kids

The kids' devices, kept separate so content filtering and time-based access live in one place — and so a compromised game or app has no path into the personal or server segments. The isolation protects them and everyone else.

## VLAN 50 — Guests

Visitor devices. Internet and nothing else — no view of the personal network or the server segment. I have no idea what's running on a guest's phone, so it's untrusted by definition and isolated.

## VLAN 60 — Server / Lab

The busiest segment: the Proxmox hypervisor, the SOC stack and EVE-NG, all on static addressing. It's where I deliberately break things, so keeping it contained matters. Cross-segment access in or out of here is the most tightly scoped — for example, the server segment is allowed to reach the switch for SSH/SNMP management and is denied toward the personal segment, with the rest dropped by the implicit deny.

## Policy summary

- **Default-deny** between segments on the ASA; the implicit deny is the backstop, not the plan.
- **Named ACL per segment** (`home_access`, `wireless_access`, `Server_VLAN_access_in`, …), each applied inbound on its sub-interface.
- **Specific denies above broad permits**, and **denies are logged** so cross-boundary attempts are visible.
- **No blanket `permit ip any any`** — every allow is scoped to a source, destination and, where it matters, a port.
- **Wi-Fi is mapped to VLANs by SSID** at the UniFi AP, so segment membership is decided at join time.
