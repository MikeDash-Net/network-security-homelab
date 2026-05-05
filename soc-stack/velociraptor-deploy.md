# Velociraptor deployment notes

> Self-hosted EDR / DFIR server with four Linux clients enrolled. Used for
> live triage VQL queries against running endpoints during incident
> exercises, and for periodic artifact collection (running processes, open
> sockets, package inventory, persistence locations).

| | |
|---|---|
| **Server IP** | 192.168.60.60 |
| **Version** | 0.7.x (pinned) |
| **GUI** | https://192.168.60.60:8889 |
| **Client comms** | tcp/8000 |
| **Clients** | 4 Linux endpoints (pve-host, npm, envisionite-app, mgmt-tools) |

---

## Why Velociraptor

Wazuh agents handle FIM, log forwarding, and rule-based alerting. What they
do not give me is **on-demand interactive query** of a live host. When I need
to ask "what processes were running with `tcp/8443` listening at 14:30 last
Tuesday?" Velociraptor runs that as a VQL query against the persistent
client-side artifact store and returns rows.

That capability is the difference between "we have logs" and "we have a
DFIR workflow".

---

## Install — server

```bash
root@velo:~# curl -sLO https://github.com/Velocidex/velociraptor/releases/download/v0.7.5/velociraptor-v0.7.5-linux-amd64
root@velo:~# install -m 0755 ./velociraptor-v0.7.5-linux-amd64 /usr/local/bin/velociraptor

root@velo:~# velociraptor config generate -i \
    > /etc/velociraptor/server.config.yaml
# (interactive — pick "Self-signed", set frontend hostname, GUI port, etc.)

root@velo:~# velociraptor --config /etc/velociraptor/server.config.yaml \
    user add admin --role administrator
```

Capture the admin password to the vault. Velociraptor will not show it again.

systemd unit:

```ini
# /etc/systemd/system/velociraptor.service
[Unit]
Description=Velociraptor server
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend -v
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
root@velo:~# systemctl daemon-reload
root@velo:~# systemctl enable --now velociraptor
```

---

## Client deployment

The server's `frontend` config can produce a self-installing MSI/DEB/RPM
keyed to that specific server. Generate once, distribute:

```bash
root@velo:~# velociraptor --config /etc/velociraptor/server.config.yaml \
    debian client \
    --output velociraptor-client.deb
```

On each Linux client:

```bash
root@npm:~# scp root@192.168.60.60:/root/velociraptor-client.deb /tmp/
root@npm:~# dpkg -i /tmp/velociraptor-client.deb
root@npm:~# systemctl status velociraptor_client
```

Within ~10 s the client appears in the Velociraptor GUI under
`Search → All clients`.

---

## Useful artifact collections

Run these via the GUI under **Server > Hunts** to collect data across all
clients on a schedule.

| Artifact | Frequency | Purpose |
|----------|-----------|---------|
| `Linux.Sys.Pslist` | weekly | Process tree snapshot — diff to detect persistence |
| `Linux.Network.Netstat` | weekly | All listening sockets — useful baseline for "did a new service appear" |
| `Linux.Sys.Packages` | weekly | dpkg/rpm package inventory |
| `Linux.Search.FileFinder` | on-demand | Glob across the fleet, e.g. `**/.ssh/authorized_keys` |
| `Linux.Sys.Crontab` | weekly | Crontab inventory — persistence detection |
| `Linux.Forensics.Bash` | on-demand | Bash history collection during incident response |

---

## VQL — live triage examples

### What is listening on the network?

```sql
SELECT * FROM Artifact.Linux.Network.Netstat()
WHERE State = 'LISTEN'
ORDER BY ProcessID
```

### Has any user run `sudo` in the last 24h?

```sql
SELECT * FROM Artifact.Linux.Sys.AuditdLog(
    Glob='/var/log/auth.log*'
)
WHERE Body =~ 'sudo' AND Time > now() - 86400
```

### Find files modified within a time window

```sql
SELECT FullPath, Size, Mtime
FROM glob(globs=['/etc/**', '/usr/local/**'], accessor='file')
WHERE Mtime > timestamp(string='2026-04-22T11:00:00Z')
  AND Mtime < timestamp(string='2026-04-22T15:00:00Z')
```

These three queries each take seconds against a live fleet — the equivalent
of SSHing into every host and running shell pipes by hand, but reproducible,
recorded, and replayable.

---

## Hardening

- TLS-only frontend (port 8889 GUI is HTTPS).
- Self-signed CA per server install — clients are pinned to that CA at
  install time. Replacing the CA invalidates every client → forces a
  controlled redeploy.
- API access tokens scoped per role (read-only token for the SIEM
  enrichment integration).
- GUI access restricted to the Home VLAN at the ASA layer (see
  [`inter-vlan-acl.md`](../policy/inter-vlan-acl.md), section 5).
- Velociraptor server's own logs forwarded to Wazuh — every login attempt
  recorded.

---

## Operational notes

- Disk usage on the server: ~150 MB / week with weekly hunts on four
  clients. Old artifact data trimmed at 90 days.
- Each new artifact collection has a corresponding "purpose / expected
  output / what would be anomalous" note in `/etc/velociraptor/notes/`.
- After every kernel upgrade on a client (see
  [`/incidents/2026-04-26-proxmox-kernel-gpu-regression.md`](../incidents/2026-04-26-proxmox-kernel-gpu-regression.md)),
  re-run `Linux.Sys.Pslist` to baseline the new kernel.
