# Cortex — IOC enrichment engine

> Analyzer engine for IOC enrichment (URL, hash, IP). Wired against a
> future TheHive deployment for case management. Currently used as a
> standalone enrichment service, queryable via API.

| | |
|---|---|
| **Host** | 192.168.60.40 (LXC, Debian 12, 2 vCPU / 4 GB RAM) |
| **Version** | Cortex 3.x with the open analyzers catalog |
| **API** | https://192.168.60.40:9001/api |
| **Auth** | API key per integration; no shared keys |

---

## Why standalone

In a typical SOC, Cortex is paired with TheHive for case management:
analyst opens a case, attaches IOCs, fires off analyzers, results land in
the case timeline. I do not have TheHive running yet — partly because the
case volume in a single-engineer home lab does not justify the operational
overhead.

Cortex by itself, however, is **immediately useful** as an API surface:
"give me the VirusTotal score for this hash", "look up this IP in
abuse.ch", "is this domain on URLhaus". Velociraptor can call it during
triage; Wazuh can call it during alert enrichment.

---

## Install

```bash
root@cortex:~# apt install openjdk-11-jre cassandra=3.11.16
root@cortex:~# wget https://download.thehive-project.org/cortex/cortex_3.1.7-1_all.deb
root@cortex:~# dpkg -i cortex_3.1.7-1_all.deb
root@cortex:~# systemctl enable --now cortex
```

Cortex needs Cassandra (single-node is fine for a home lab). Configure the
Cassandra cluster name and listen address before starting Cortex.

`/etc/cortex/application.conf`:

```hocon
db.janusgraph.storage.cql.cluster-name = "cortex"
db.janusgraph.storage.hostname = ["127.0.0.1"]
db.janusgraph.storage.cql.keyspace = "cortex"

play.http.secret.key = "REDACTED"
search.index = "cortex"

analyzer.urls = [
  "/etc/cortex/Cortex-Analyzers/analyzers"
]
```

Restart and complete the web setup wizard at https://192.168.60.40:9001/.

---

## Analyzers in use

| Analyzer | Type | API key needed |
|----------|------|----------------|
| VirusTotal_GetReport | Hash, URL, IP, domain | Yes (free tier) |
| AbuseIPDB | IP | Yes (free tier) |
| URLhaus | URL | No |
| MalwareBazaar | Hash | No |
| OTXQuery | IP, domain, hash | Yes (free) |
| Onyphe | IP, domain | Yes (free tier) |
| Shodan_Host | IP | Yes |
| MISP | IOC | No (self-hosted MISP not deployed yet) |

API keys are stored in `/etc/cortex/application.conf` under the analyzer
config block. **Each key is scoped to its analyzer.** Compromise of one
analyzer key does not expose the others.

---

## Velociraptor → Cortex enrichment

Velociraptor can POST IOC observations into Cortex via VQL:

```sql
LET cortex_url = "https://192.168.60.40:9001/api/analyzer/_search"
LET cortex_token = secret(name="cortex_api_token")

SELECT * FROM http_client(
    url=cortex_url,
    method="POST",
    headers=dict(Authorization='Bearer ' + cortex_token),
    data=serialize(format='json', item=dict(
        analyzerType='ip',
        data=client_ip,
        tlp=1
    ))
)
```

This is wired into a Velociraptor monitoring artifact: any time a client's
EDR sees an outbound connection to a non-RFC-1918 IP that is **not** on the
known-good list, the IP is auto-submitted to Cortex for enrichment, and the
result is written to a server-side notebook.

---

## Wazuh → Cortex on-alert enrichment

For Suricata alerts containing a public destination IP, an active-response
script POSTs the IP to Cortex and writes the verdict back into the alert
context:

```bash
#!/usr/bin/env bash
# /var/ossec/active-response/bin/cortex-enrich-ip.sh
set -euo pipefail

DEST_IP="$2"
TOKEN="$(cat /etc/wazuh/cortex.token)"

response=$(curl -sk -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    https://192.168.60.40:9001/api/analyzer/_search \
    -d "{\"analyzerType\":\"ip\",\"data\":\"$DEST_IP\",\"tlp\":1}")

echo "$response" | jq -r '.[] | "verdict=\(.report.taxonomies[0].value) source=\(.analyzerName)"' \
    | logger -t cortex-enrich -p local6.info
```

The `cortex-enrich` syslog tag has its own Wazuh decoder, so the verdict
appears in the dashboard joined with the originating Suricata alert.

---

## Hardening

- HTTPS-only (self-signed cert, pinned by clients).
- Cortex admin restricted to the Home VLAN at the ASA layer (see
  [`inter-vlan-acl.md`](../policy/inter-vlan-acl.md), section 5).
- Per-integration API tokens, no shared "admin" token used for automation.
- Cortex audit log → Wazuh: every analyzer run is recorded.
- TLP (Traffic Light Protocol) = AMBER for any IOC submitted, so it is
  not automatically shared upstream by analyzers that respect TLP.

---

## Operational notes

- Free-tier API quotas are the bottleneck: VirusTotal limits to 4
  requests/min on a free key. Velociraptor enrichment is throttled to
  1 request / 30 s per IOC.
- Analyzer responses cached in Cortex for 24 h to avoid re-querying APIs
  for IOCs that just resolved.
- TheHive deployment is on the roadmap once incident volume justifies it
  (probably when the lab gets a second user).
