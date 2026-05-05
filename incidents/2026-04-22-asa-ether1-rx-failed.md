# 2026-04-22 — Cisco ASA `ether1` RX-failed: PPPoE migrated to `ether4`

| | |
|---|---|
| **Component** | Cisco ASA 5515-X (`outside1` interface backed by physical `GigabitEthernet0/0`) |
| **Severity** | High — primary WAN down, dual-WAN degraded to single uplink |
| **Detected by** | Wazuh dashboard alert (`ifInOctets` flat-line) + manual `show int` |
| **Time to detect** | ~6 min from packet stop |
| **Time to resolve** | ~45 min (including hardware diagnosis) |
| **Status** | Resolved — PPPoE re-homed to physical port `GigabitEthernet0/3` (`ether4` upstream of MikroTik) |

---

## Symptoms

- ISP1 uplink stopped passing traffic. ICMP to ISP1 gateway returned 100% loss.
- ASA syslog showed continuous `%ASA-4-411004` link-flap messages on `GigabitEthernet0/0`.
- `show interface GigabitEthernet0/0` reported the port `up`, line protocol `up`,
  but **input rate 0 bps** with `input errors` counter incrementing.
- The MikroTik upstream of that port logged the matching peer as
  `pppoe-out1: terminating - peer not responding`.

## Detection

The Wazuh dashboard surfaced the issue first — the `ifInOctets` series for
`GigabitEthernet0/0` flat-lined at zero while `ifOutOctets` continued to climb
(retransmits). I had previously written a Wazuh rule (`local_rules.xml`,
sid 100210) firing on five consecutive zero deltas of `ifInOctets` while the
interface remained `oper=up`.

```text
2026-04-22 14:31:08  rule 100210  level 7
  iface=GigabitEthernet0/0  inOctets_delta=0  outOctets_delta=14821
  msg="WAN interface up but no inbound packets — possible RX failure"
```

## Investigation

### Step 1 — confirm the symptom is real, not a counter glitch

```text
asa# show interface GigabitEthernet0/0 | include packets|errors|input rate
  16384 packets input, 1574208 bytes
  0 packets output, 0 bytes
  0 input errors, 0 CRC, 0 frame, 4127 overrun
  Input rate 0 bits/sec, 0 packets/sec
```

Overrun counter incrementing without any matching `output errors` was the first
hint that the issue was on the physical RX side of the ASA NIC, not on the
MikroTik or the line.

### Step 2 — bypass the upstream

I unplugged the MikroTik patch cord from `Gi0/0` and connected a laptop with a
known-good cable. The laptop's ARP request for the ASA `outside1` address timed
out. With the same laptop on `Gi0/3`, ARP succeeded.

### Step 3 — confirm at packet level using switch port mirror

The Aruba 2530 is configured with a permanent SPAN destination on port 24
feeding a Suricata sensor. I temporarily mirrored both the ASA-facing port and
the laptop port, captured 30 s, and compared the two PCAPs in Wireshark.

```text
laptop → ASA Gi0/0   : ARP request, no reply, retried 3×
laptop → ASA Gi0/3   : ARP request → reply in 0.4 ms
```

The L2 flow toward `Gi0/0` reached the ASA but no reply ever left the ASA.
Combined with the overrun counter, the conclusion was: physical RX path on
`Gi0/0` is broken at the SFP-cage / PHY level, even though the link partner sees
link.

### Step 4 — hardware swap

I removed the patch cord, blew out the cage, swapped to a different cable —
no change. Issue persists on `Gi0/0` only. Hardware fault.

## Root cause

Hardware degradation on the `GigabitEthernet0/0` PHY of the ASA 5515-X. Link
state is asserted but the receive path corrupts frames upstream of the FIFO,
which the ASA reports as `overrun` rather than `CRC` because the corruption
occurs before frame validation. No firmware update changed the behaviour, and
the port stayed broken across reboots and clean configs.

## Fix

Re-homed the PPPoE uplink from `Gi0/0` to `Gi0/3`:

```text
asa(config)# interface GigabitEthernet0/3
asa(config-if)# nameif outside1
asa(config-if)# security-level 0
asa(config-if)# pppoe client vpdn group ISP1
asa(config-if)# ip address pppoe setroute
asa(config-if)# no shutdown

asa(config)# interface GigabitEthernet0/0
asa(config-if)# shutdown
asa(config-if)# description ** RX-failed 2026-04-22 — do not use **
```

Updated the upstream MikroTik patch panel mapping accordingly. PPPoE re-negotiated
within 9 s, default route re-installed, ICMP to ISP1 gateway recovered.

`Gi0/0` administratively shut to prevent accidental re-use; left in the config
with a description so the failure is visible to the next reader.

## Verification

```text
asa# show interface GigabitEthernet0/3 | include rate|address|line
  GigabitEthernet0/3 is up, line protocol is up
  IP address: XX.XX.XX.X via PPPoE
  Input rate 1.2 Mbps, Output rate 384 Kbps

asa# show route 0.0.0.0
S* 0.0.0.0 0.0.0.0 [1/0] via XX.XX.XX.X, outside1
```

Dashboard `ifInOctets` resumed climbing within 30 s. Wazuh rule 100210 cleared
on the next polling interval.

## Lessons learned

1. **Trust the Wazuh rule, but always confirm at L2.** Counters can lie. Switch
   port mirror with a parallel PCAP is the only way to be sure the frame is
   actually arriving at the device PHY.
2. **A spare physical port matters.** The ASA 5515-X has six physical ports;
   only two were in active use. Having `Gi0/3` already wired into the patch
   panel meant the migration was a config change, not a re-cable.
3. **Document a failed port at the config layer, not just in a ticket.** The
   `description ** RX-failed 2026-04-22 — do not use **` line means the next
   engineer (or me, six months from now) sees the hazard the moment they read
   the running config.

## Detection rule used

`local_rules.xml` (Wazuh) — surfaces an interface that is administratively up
but receiving zero packets, which is the signature of a one-sided physical
failure:

```xml
<group name="snmp,interface,">
  <rule id="100210" level="7" frequency="5" timeframe="300">
    <if_sid>17000</if_sid>
    <field name="ifInOctets_delta">^0$</field>
    <field name="ifOperStatus">^1$</field>
    <description>WAN interface up but no inbound packets — possible RX failure</description>
    <mitre><id>T1499.004</id></mitre>
  </rule>
</group>
```
