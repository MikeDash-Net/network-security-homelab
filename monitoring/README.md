# Monitoring — Zabbix

Zabbix 7.0 watches the lab for availability and health, with email alerting when something goes down or comes under pressure. It runs as an LXC container on the Server / Lab segment (`zabbix` · 192.168.60.51).

## What's monitored

**12 monitored hosts** — the count Zabbix's host-availability view reports (9 via agent, 3 via SNMP):

- **1** Proxmox hypervisor (agent)
- **7** LXC service containers (agent)
- the **Zabbix server** itself (agent)
- **3** network devices — ASA, MikroTik, Aruba — via **SNMP**

It also pulls the **Proxmox VE API** and runs **website uptime** checks — extra data sources, not separate hosts in the count above.

## Collection

- **~1,700 metrics** actively collecting, **0 unsupported**.
- Agent-based on the Linux hosts/containers, **SNMP** on the network devices, **API** for Proxmox, and uptime checks for the website.

> These are the real, actively-collecting figures — node and metric counts, not template/prototype item counts.

## Alerting

Email alerting on:

- host / link / service **down**
- resource **pressure** (CPU, memory, storage, interface saturation)

## Dashboards

- **Dual-WAN throughput** across both ISP uplinks
- **Device health** across the monitored nodes

Monitoring closes the loop with the segmentation work: the boundaries the ASA enforces are also the things worth watching, and Zabbix is where device and link health stay visible.
