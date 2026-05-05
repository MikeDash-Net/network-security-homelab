# Runbook 05 — Port mirror trunk to Suricata IDS sensor

> Scope: configure SPAN (port mirroring) on the HP Aruba 2530 such that all
> inter-VLAN traffic between the ASA inside interface and the switch trunk
> is copied to a dedicated sniffer port feeding the Suricata sensor.

| | |
|---|---|
| **Target switch** | HP Aruba 2530-24-PoE+ (J9779A), ArubaOS-Switch 16.11.0029 |
| **Source ports** | port 1 (ASA inside, trunk all VLANs) |
| **Destination port** | port 24 (mirror to Suricata sensor NIC) |
| **Sensor** | Suricata LXC, NIC bridged onto `vmbr0` |
| **Risk** | Low — mirror only copies frames; no traffic loss path |

---

## Why mirror at L2 and not L3

Suricata can also be deployed inline (IPS mode), but I want detection without
risk of dropping production traffic on a false-positive rule. SPAN gives me:

- **Read-only NIDS** — alerts ship to Wazuh, no action on the live path.
- **L2 visibility** — captures ARP, DHCP, LLDP, things a routed sniff misses.
- **No CPU on the data path** — the switch ASIC duplicates frames; Suricata
  drops late frames if the sensor cannot keep up.

---

## Aruba SPAN configuration

```text
HP-2530# configure terminal
HP-2530(config)# mirror 1 port 24
HP-2530(config)# interface 1
HP-2530(eth-1)# monitor all both mirror 1
HP-2530(eth-1)# exit
HP-2530(config)# write memory
```

Decomposition:

- `mirror 1 port 24` — declares mirror session ID 1, destination port 24.
- `monitor all both mirror 1` — on the source port (1), copy **all** frames
  in **both** directions to mirror session 1.
- `write memory` — persist to flash.

Verify:

```text
HP-2530# show monitor
 Network Monitoring Port :  Active

 Mirror Sessions
 Session   Source                          Destination
 -------   ------                          -----------
 1         port 1 both                     port 24
```

---

## Suricata sensor side

The destination port (24) is patched into a dedicated NIC on the Proxmox
host. That NIC is **not** bridged into any production VLAN — it is added as
a raw interface to the Suricata LXC's config:

```bash
# /etc/pve/lxc/202.conf  (Suricata LXC)
lxc.net.1.type: phys
lxc.net.1.link: enp1s0f1
lxc.net.1.flags: up
lxc.net.1.name: span0
```

Inside the Suricata LXC, configure AF_PACKET against `span0`:

```yaml
# /etc/suricata/suricata.yaml (excerpt)
af-packet:
  - interface: span0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes
    ring-size: 200000
    block-size: 1048576
    checksum-checks: no   # SPAN can deliver re-segmented frames
```

Note `checksum-checks: no` — SPAN destinations can receive frames whose
checksums were already validated and dropped/re-computed by the source NIC.
Leaving checksum validation on causes Suricata to flag thousands of
"bad-checksum" events that are not real.

---

## Promiscuous mode + drop counter sanity check

```bash
root@suricata:~# ip link set span0 promisc on
root@suricata:~# ip -s link show span0
2: span0: <BROADCAST,MULTICAST,PROMISC,UP,LOWER_UP> mtu 1500 qdisc fq_codel
    RX:  bytes  packets  errors  dropped overrun mcast
       1.4G    8.2M     0       0       0       4123
```

`dropped` should stay at 0 for routine traffic. If it climbs, the sensor is
not keeping up — either the ring is too small or the LXC needs more CPU.

---

## Suricata health verification

```bash
root@suricata:~# tail -f /var/log/suricata/eve.json | jq -r 'select(.event_type=="stats") | .stats.capture'
{
  "kernel_packets": 8234112,
  "kernel_drops": 0,
  "errors": 0
}
```

`kernel_drops` is the number that matters. Anything other than 0 over a
24-hour window → tune the ring or the threads.

---

## Test — generate a known signature and look for it

ICMP from a Wireless VLAN host to a Server VLAN host should be **denied** by
the ASA, but should still be **visible** at L2 from port 1's perspective —
the SYN reaches the ASA inside interface, the ASA drops it, no reply leaves
the trunk.

```bash
# Wireless VLAN host
$ ping -c 3 192.168.60.20
PING 192.168.60.20 (192.168.60.20): 56 data bytes
Request timeout for icmp_seq 0
Request timeout for icmp_seq 1
```

In Suricata logs:

```bash
root@suricata:~# tail -f /var/log/suricata/eve.json | jq 'select(.src_ip=="192.168.30.42" and .dest_ip=="192.168.60.20")'
{
  "event_type": "alert",
  "src_ip": "192.168.30.42",
  "dest_ip": "192.168.60.20",
  "alert": {
    "signature_id": 1000041,
    "signature": "LOCAL: Wireless VLAN reaching Server VLAN on unexpected port",
    "category": "Potentially Bad Traffic"
  }
}
```

The mirror caught the L2 frame, the local rule fired, the alert reached the
SIEM. Loop closed.

---

## Anti-patterns (do not do)

- ❌ **Mirror to a port that is also a member of an active VLAN.** Frames
  injected onto a SPAN destination can leak back into the production path on
  some platforms. Keep the destination port in `monitor` role and not on a
  VLAN.
- ❌ **Mirror more than the ASIC can sustain.** Aruba 2530 throughput is
  finite. Mirroring two trunk ports both directions on a switch already at
  60% backplane utilisation will cause **production traffic loss**.
- ❌ **Forget that mirrored traffic does not return through the source port.**
  Suricata is a read-only sensor. Anything that requires bidirectional
  state needs a real inline tap or a separate inline IPS.
