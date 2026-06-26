# Cisco ASA 5515-X — notes

The ASA is the Layer 3 gateway for every internal VLAN and the place inter-VLAN policy is actually enforced. It sits one hop behind the MikroTik: one interface faces the edge over the `/30` transit (`outside`, `10.0.0.2`), one physical interface faces the Aruba as an 802.1Q trunk, split into a sub-interface per VLAN. One physical inside cable, five logical gateways — router-on-a-stick, where the stick is a firewall.

> Snippets below are **sanitized** and illustrative (RFC1918 only, generic ports). No real credentials, keys or serials.

## Sub-interface per VLAN

Each VLAN terminates on its own tagged sub-interface, which is the segment's default gateway:

```
interface GigabitEthernet0/1.20
 vlan 20
 nameif home
 security-level 100
 ip address 192.168.20.1 255.255.255.0
```

A security level is **not** a policy. By default the ASA lets higher-security interfaces reach lower ones with no ACL involved, so I don't lean on levels for inter-VLAN decisions — every flow goes through an ACL I wrote on purpose.

## Inter-VLAN ACLs (default-deny)

Each segment has a named ACL applied inbound on its sub-interface. The intent is: permit the specific flows that must exist, deny the rest, log the denies. Example for the server segment reaching the switch for management only:

```
! Server VLAN may reach the Aruba switch for management only; deny the rest
access-list Server_VLAN_access_in extended permit tcp 192.168.60.0 255.255.255.0 host 192.168.20.250 eq ssh
access-list Server_VLAN_access_in extended permit udp 192.168.60.0 255.255.255.0 host 192.168.20.250 eq snmp
access-list Server_VLAN_access_in extended deny   ip  192.168.60.0 255.255.255.0 192.168.20.0 255.255.255.0
access-group Server_VLAN_access_in in interface server
```

The ACL is read top to bottom and the **first match wins**, so specific denies go above broad permits and the implicit deny at the end is the backstop, not the plan.

## NAT

Internet-bound traffic is NATed out at the MikroTik; on the ASA the relevant cases are translation toward the edge and **no-NAT exemptions** for internal flows that must arrive as themselves (for example, syslog from the firewall to the SIEM on the server segment). NAT is order-sensitive — a general rule will eat traffic before a more specific exemption if placed wrong, so specific exemptions come first.

## Management hardening

- SSH version 2 only; Telnet and the web/ASDM management plane disabled.
- SSH allowed only from permitted management sources, not from anywhere internal.
- AAA for logins, a login banner, RSA 2048 key.
- Remote **syslog to the SIEM** so the ASA's denies and events are visible in Wazuh rather than guessed at.
- Console access kept available — remote management is hardened from a position where a mistake is a quick recovery, not a lockout.
