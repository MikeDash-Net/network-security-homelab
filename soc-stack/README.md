# SOC stack — learning environment

**Honest framing first:** this is a deliberate **learning environment**, not production or professional experience. I've built the pipeline end to end and I'm actively learning to operate it — triage, tuning and judgement are the hard 80% that doesn't come from an install. The networking elsewhere in this repo runs my home for real; this stack is where I study blue-team fundamentals.

The tools aren't separate products — they're layers of one pipeline: something has to **see** events, something has to **collect and correlate** them, something lets me **go look closer**, and something turns a real one into a **case**.

```
Sources                         Collect & correlate     Investigate        Case
─────────────────────────       ─────────────────       ───────────        ─────────────
Suricata (IDS, host bridge)  ┐
Host/endpoint agents         ┤
ASA / Aruba / MikroTik syslog├──►  Wazuh (SIEM hub) ──►  Velociraptor ──►  TheHive + Cortex
AdGuard (DNS telemetry)      ┘                           (EDR)             (case mgmt + enrichment)
```

All SOC services run as LXC containers / on the Proxmox host on the **Server / Lab segment (VLAN 60)**.

## Components

### Wazuh 4.9.2 — SIEM (the hub)
Where everything lands. **5 enrolled agents** (a Windows PC, the Proxmox host, and LXC hosts) send logs and file-integrity events; the ASA, Aruba and MikroTik send syslog; Suricata events flow in. Wazuh runs it against its rules and turns a pile of raw events into something searchable and alertable in one place. — `wazuh-soc` · 192.168.60.20

### Suricata 7.0.10 — network IDS
Runs on the Proxmox host, listening on the bridge that every VLAN crosses, so it sees traffic across the whole lab rather than one segment. ~**65k rules**; matches are written out and shipped to Wazuh. Detection at the wire level — it cares about what's actually on the network, not what a host claims.

### Velociraptor 0.76.2 — EDR
Agents on the hosts; from one console I can run VQL hunts across all of them — what processes are running, what changed, what's where it shouldn't be. The "walk over to the machine and look" layer once Wazuh flags something. — `velociraptor` · 192.168.60.60

### TheHive 5.2 + Cortex 3.1.8 — case management + enrichment
When an alert is real it stops being a dashboard line and becomes a case to investigate and document, with Cortex analyzers pulling in reputation/enrichment automatically. This is the layer I'm furthest along on learning to use properly. — `thehive` + `cortex` · 192.168.60.40

### AdGuard Home — DNS filtering (and a telemetry source)
Network-wide DNS filtering. It earns its place in the SOC view because DNS is one of the most useful things to watch — a lot of bad behaviour shows up first as a device asking for a domain it has no business asking for. — `adguard` · 192.168.60.30

## What I'm learning here

- How the parts connect and where the data flows (build complete).
- Separating signal from a firehose of normal behaviour — tuning rules to *this* environment.
- Working an alert by hand: see it in Suricata, pivot in Wazuh, identify the host, decide if it's worth a closer look in Velociraptor or a case in TheHive.

Write-up: [Building a home SOC lab](https://mihailpascal.com/articles/home-soc-lab).
