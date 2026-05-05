# Inter-VLAN ACL — `home_access` (Cisco ASA 5515-X)

> The complete ACL applied on the ASA `inside` interface for traffic
> originating from the **Home** VLAN (192.168.20.0/24). Default is implicit
> deny; every permit is explicit; every deny is explicit and commented.

## Design principles

1. **Default deny** between client VLANs. Home is the only VLAN with any
   inter-VLAN reach.
2. **Permits are protocol-and-port specific.** No `permit ip any any` for
   any client VLAN.
3. **Selective Server access.** Home reaches only the management ports of
   the SOC stack hosts, not the full Server subnet on every protocol.
4. **Internet egress is always permitted last** — the deny rules above
   it short-circuit unwanted destinations first.
5. **Line-level commentary in the running config.** Future-me has to
   understand why a line exists without opening this repo.

---

## Full ACL with commentary

```text
! ============================================================
! Inter-VLAN ACL: home_access
! Applied:  access-group home_access in interface inside
! Source:   192.168.20.0/24 (Home VLAN)
! Default:  implicit deny at the bottom
! Reviewed: 2026-04-29
! ============================================================

! ---- 1. DNS to the MikroTik resolver --------------------
! Home clients use the MikroTik as their primary resolver
! (which forwards to AdGuard then upstream). Both UDP and
! TCP/53 — TCP is needed for large responses (DNSSEC).

access-list home_access extended permit udp 192.168.20.0 255.255.255.0 host 10.0.0.1 eq 53
access-list home_access extended permit tcp 192.168.20.0 255.255.255.0 host 10.0.0.1 eq 53

! ---- 2. MikroTik mgmt from Home only --------------------
! Winbox (8291) and SSH (22) for routine MikroTik admin.
! Restricted to Home so a compromised wireless client can
! never reach the router's mgmt plane.

access-list home_access extended permit tcp 192.168.20.0 255.255.255.0 host 10.0.0.1 eq 8291
access-list home_access extended permit tcp 192.168.20.0 255.255.255.0 host 10.0.0.1 eq 22

! ---- 3. UniFi controller (Server VLAN) ------------------
! UniFi inform protocol + admin UI. Only the controller
! host, not the rest of the Server subnet.

access-list home_access extended permit tcp 192.168.20.0 255.255.255.0 host 192.168.60.10 eq 8443

! ---- 4. Proxmox web UI ----------------------------------
! Web console on tcp/8006 for hypervisor management. SSH
! on tcp/22 for shell access. Whole /24 is ok here — every
! Server-VLAN host runs sshd and Proxmox guests need it.

access-list home_access extended permit tcp 192.168.20.0 255.255.255.0 192.168.60.0 255.255.255.0 eq 8006
access-list home_access extended permit tcp 192.168.20.0 255.255.255.0 192.168.60.0 255.255.255.0 eq 22

! ---- 5. SOC dashboards (Home → Server, full IP) ---------
! Specific hosts only — Wazuh, Cortex, Velociraptor.
! Wide-open `permit ip` is acceptable here because the
! destination is a single host, not a subnet.

access-list home_access extended permit ip 192.168.20.0 255.255.255.0 host 192.168.60.20
! ^ Wazuh (dashboard 443, agent 1514/1515, API 55000)

access-list home_access extended permit ip 192.168.20.0 255.255.255.0 host 192.168.60.40
! ^ Cortex analyzer engine (UI on 9001, jobs API)

access-list home_access extended permit ip 192.168.20.0 255.255.255.0 host 192.168.60.60
! ^ Velociraptor server (GUI 8889, comms 8000)

! ---- 6. Cross-VLAN denies (explicit) --------------------
! Belt-and-braces: even though the implicit deny at the
! bottom would catch these, naming them explicitly means a
! `show access-list home_access | include hit` makes intent
! visible to the next reader.

access-list home_access extended deny ip any 192.168.30.0 255.255.255.0 log
! ^ Home → Wireless: blocked
access-list home_access extended deny ip any 192.168.40.0 255.255.255.0 log
! ^ Home → Kids: blocked
access-list home_access extended deny ip any 192.168.50.0 255.255.255.0 log
! ^ Home → Guests: blocked
access-list home_access extended deny ip any 192.168.60.0 255.255.255.0 log
! ^ Home → Server (catch-all): blocked. Specific permits
!   above this line are matched first. Everything else
!   targeting Server hits this and is logged.

! ---- 7. Internet egress (last) --------------------------
! Anything that survived the denies is on its way to the
! Internet. This permit must remain at the bottom of the
! list.

access-list home_access extended permit ip 192.168.20.0 255.255.255.0 any

! ---- 8. Implicit deny (ASA default) ---------------------
! No additional rule needed; the ASA enforces this.
```

---

## Why explicit deny + log ?

Without the explicit deny + `log` lines, the implicit deny would silently
absorb cross-VLAN attempts. With explicit denies, the ASA emits a syslog
event for every dropped packet — Wazuh decodes those into events with the
source IP, source port, dest IP, and ACL name. That gives me a daily
heat-map of "things in Home that tried to reach Server (or another VLAN)
and got blocked".

That signal is **valuable**. It tells me when a client misconfigures its
DNS, when a piece of software phones home to a CDN that happens to share
an internal subnet octet, and (most importantly) when something on Home is
genuinely scanning the rest of the network.

---

## Maintenance

| Trigger | Action |
|---------|--------|
| New SOC tool added on Server VLAN | Add a host-specific permit at section 5, never widen section 4 |
| New VLAN added | Add an explicit deny in section 6 above the Internet permit |
| Hit count on a permit drops to zero for 30+ days | Confirm the service is still running; if obsolete, remove the permit and write the change up |
| Wazuh rule for `deny home_access` fires more than 10×/day from a single source | Investigate that endpoint — either misconfigured DNS, malware beacon, or scanning |

---

## Related

- [`/runbooks/02-suricata-rule-tuning.md`](../runbooks/02-suricata-rule-tuning.md) — the corresponding NIDS-side rule that flags Wireless → Server attempts at L2.
- [`/incidents/2026-04-27-envisionite-dhcp-outage.md`](../incidents/2026-04-27-envisionite-dhcp-outage.md) — example of a cross-VLAN dependency where the ACL was correct but an upstream config was wrong.
