# MikroTik RB5009 — notes

The MikroTik owns the edge: two PPPoE WAN uplinks, load-balancing and failover across them, NAT, DNS and dynamic DNS. It hands off to the ASA over a `/30` transit link (`10.0.0.1` on the MikroTik side); management lives at `10.0.0.1`.

> Snippets below are **sanitized** and illustrative. No real credentials, ISP details or the WireGuard endpoint.

## Dual-WAN — PCC load-balance + failover

Both WANs are PPPoE. Per-Connection Classifier (PCC) spreads new connections across the two uplinks by a hash of the connection, keeping each connection pinned to one WAN, and routing falls back to the surviving link if one goes down. The concept, sanitized:

```
# mark new connections per WAN, then mark routing so each pins to its uplink
/ip firewall mangle
 add chain=prerouting in-interface=<lan> connection-mark=no-mark \
   per-connection-classifier=both-addresses-and-ports:2/0 action=mark-connection new-connection-mark=wan1_conn
 add chain=prerouting in-interface=<lan> connection-mark=no-mark \
   per-connection-classifier=both-addresses-and-ports:2/1 action=mark-connection new-connection-mark=wan2_conn
```

Failover is handled with route distances / check-gateway so traffic moves to the healthy WAN automatically. I verified failover by simulating a WAN outage and watching sessions continue on the surviving uplink.

## NAT

```
/ip firewall nat
 add chain=srcnat out-interface-list=WAN action=masquerade
```

Internal VLANs reach the internet through the ASA and out via this masquerade on the active WAN.

## DNS

DNS requests are forwarded to a filtering resolver over DNS-over-TLS; AdGuard Home on the server segment also provides network-wide DNS filtering. Dynamic DNS keeps a stable name pointed at the changing WAN address.

## Hardening

- SSH hardened; management restricted to the admin/home segment.
- Telnet, FTP and the HTTP admin service disabled.
- Default-deny on the WAN input chain — only expected traffic is accepted inbound.
- Scheduled daily configuration backups.
