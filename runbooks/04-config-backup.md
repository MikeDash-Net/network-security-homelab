# Runbook 04 — Daily configuration backup

> Scope: capture a clean text export of every network device config every
> 24 hours, store on the management host with rotation, and ship a SHA-256
> digest to Wazuh so config drift is observable.

| | |
|---|---|
| **Targets** | MikroTik RB5009UPr+S+, Cisco ASA 5515-X, HP Aruba 2530-24-PoE+ |
| **Backup host** | `mgmt-tools` LXC at `192.168.60.10` |
| **Schedule** | 03:00 daily, via systemd timer |
| **Retention** | 7 daily + 4 weekly + 12 monthly |
| **Risk** | Low — read-only operations on the network devices |

---

## What "backup" means here

A backup is **only** useful if it can be diffed and replayed. So:

- **Plain-text exports**, not vendor-proprietary blobs.
- **Sanitized of secrets** before storage. Passwords, pre-shared keys, and
  certificates are scrubbed and stored separately in an encrypted vault.
- **Hash-shipped to Wazuh**, so an unexpected change between two daily runs
  triggers an alert.

---

## Procedure — MikroTik (`/export`)

The MikroTik exposes plain-text config via `/export terse`. SSH from the
backup host with a key, capture stdout, redact:

```bash
# /usr/local/bin/backup-mikrotik
#!/usr/bin/env bash
set -euo pipefail
HOST="192.168.60.1"          # mgmt VLAN address of the MikroTik
USER="backup-readonly"        # read-only group on the router
KEY="/root/.ssh/backup_ed25519"
OUT_DIR="/var/backup/mikrotik"
TS=$(date +%F)

mkdir -p "$OUT_DIR"

ssh -i "$KEY" -o StrictHostKeyChecking=yes "$USER@$HOST" \
    "/export terse" > "$OUT_DIR/raw-$TS.rsc"

# Redact: PPPoE secrets, SNMP communities, IPSec keys, RADIUS shared secrets
sed -E '
    s/(secret=)"[^"]*"/\1"REDACTED"/g
    s/(password=)"[^"]*"/\1"REDACTED"/g
    s/(community=)"[^"]*"/\1"REDACTED"/g
    s/(shared-secret=)"[^"]*"/\1"REDACTED"/g
    s/(pre-shared-key=)"[^"]*"/\1"REDACTED"/g
' "$OUT_DIR/raw-$TS.rsc" > "$OUT_DIR/mikrotik-$TS.rsc.example"

# Hash and ship
sha256sum "$OUT_DIR/mikrotik-$TS.rsc.example" \
    | logger -t config-backup -p local6.info

# Cleanup raw file (contains secrets)
shred -u "$OUT_DIR/raw-$TS.rsc"
```

The Wazuh agent on the backup host has a custom decoder for the
`config-backup` tag — a SHA-256 that differs from the previous day's value
fires `local_rules.xml` rule 100330 with severity 7.

---

## Procedure — Cisco ASA (`show running-config`)

Same pattern — SSH, capture, redact:

```bash
# /usr/local/bin/backup-asa
#!/usr/bin/env bash
set -euo pipefail
HOST="192.168.20.1"
USER="backup-readonly"
KEY="/root/.ssh/backup_ed25519"
OUT_DIR="/var/backup/asa"
TS=$(date +%F)

mkdir -p "$OUT_DIR"

ssh -i "$KEY" -o StrictHostKeyChecking=yes "$USER@$HOST" \
    "show running-config" > "$OUT_DIR/raw-$TS.cfg"

# Redact: encrypted secrets, AAA shared keys, certificate blobs
sed -E '
    s/(enable secret).*$/\1 REDACTED/
    s/(password) [^ ]+(.*)/\1 REDACTED\2/
    s/(key 7) [^ ]+/\1 REDACTED/
    s/(passphrase) [^ ]+/\1 REDACTED/
    /^-----BEGIN CERTIFICATE-----$/,/^-----END CERTIFICATE-----$/d
' "$OUT_DIR/raw-$TS.cfg" > "$OUT_DIR/asa-$TS.cfg.example"

sha256sum "$OUT_DIR/asa-$TS.cfg.example" \
    | logger -t config-backup -p local6.info

shred -u "$OUT_DIR/raw-$TS.cfg"
```

---

## Procedure — HP Aruba 2530 (`show running`)

The Aruba prints to a pager by default; disable it with `no page`:

```bash
# /usr/local/bin/backup-aruba
#!/usr/bin/env bash
set -euo pipefail
HOST="192.168.20.250"
USER="backup-readonly"
KEY="/root/.ssh/backup_ed25519"
OUT_DIR="/var/backup/aruba"
TS=$(date +%F)

mkdir -p "$OUT_DIR"

ssh -i "$KEY" -o StrictHostKeyChecking=yes -tt "$USER@$HOST" \
    "no page; show running; exit" > "$OUT_DIR/raw-$TS.cfg"

# Redact: SNMP community, AAA keys, password hashes
sed -E '
    s/(snmp-server community ")[^"]+("\s.*)/\1REDACTED\2/
    s/(password) [^ ]+(.*)/\1 REDACTED\2/
    s/(operator|manager).*$/\1 REDACTED/
' "$OUT_DIR/raw-$TS.cfg" > "$OUT_DIR/aruba-$TS.cfg.example"

sha256sum "$OUT_DIR/aruba-$TS.cfg.example" \
    | logger -t config-backup -p local6.info

shred -u "$OUT_DIR/raw-$TS.cfg"
```

---

## systemd unit + timer

`/etc/systemd/system/network-backup.service`:

```ini
[Unit]
Description=Network device config backup
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/backup-mikrotik
ExecStart=/usr/local/bin/backup-asa
ExecStart=/usr/local/bin/backup-aruba
ExecStartPost=/usr/local/bin/rotate-backups
User=root
```

`/etc/systemd/system/network-backup.timer`:

```ini
[Unit]
Description=Daily network device config backup

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

Enable:

```bash
root@mgmt-tools:~# systemctl daemon-reload
root@mgmt-tools:~# systemctl enable --now network-backup.timer
root@mgmt-tools:~# systemctl list-timers | grep network-backup
```

---

## Rotation script

`/usr/local/bin/rotate-backups`:

```bash
#!/usr/bin/env bash
set -euo pipefail
ROOT=/var/backup
# Keep daily for 7 days
find "$ROOT" -maxdepth 2 -name '*.cfg.example' -mtime +7 \
    ! -name '*-mon-*' ! -name '*-w*' -delete
find "$ROOT" -maxdepth 2 -name '*.rsc.example' -mtime +7 \
    ! -name '*-mon-*' ! -name '*-w*' -delete
# (weekly + monthly snapshots are pulled out by a separate cron, by name)
```

---

## Verification

```bash
root@mgmt-tools:~# ls -la /var/backup/{mikrotik,asa,aruba}/ | tail -10
-rw-r--r-- 1 root root  18234 May  4 03:00 mikrotik-2026-05-04.rsc.example
-rw-r--r-- 1 root root  42118 May  4 03:00 asa-2026-05-04.cfg.example
-rw-r--r-- 1 root root  21455 May  4 03:00 aruba-2026-05-04.cfg.example

root@mgmt-tools:~# tail /var/log/syslog | grep config-backup
May  4 03:00:14 mgmt config-backup: a3f9... mikrotik-2026-05-04.rsc.example
May  4 03:00:18 mgmt config-backup: 7b21... asa-2026-05-04.cfg.example
May  4 03:00:21 mgmt config-backup: c8d4... aruba-2026-05-04.cfg.example
```

Wazuh dashboard: `rule.id:100330` events fire only on hash differences, never
on identical days. Diff between two daily exports is a normal `git diff` —
exactly what config drift detection should look like.

---

## Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty file produced | SSH session terminated before output flushed (Aruba) | Use `ssh -tt` and end with `exit` |
| File contains pager prompts (`-- MORE --`) | Forgot `no page` on Aruba | Add it to the SSH command |
| Hash never changes | sed accidentally redacting timestamps | Restrict sed expressions to actual secret fields |
| Hash changes every day | A field is being included that shouldn't (e.g. counters) | Strip volatile fields with grep -v before hashing |
