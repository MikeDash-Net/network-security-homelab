# Runbook 03 — Wazuh agent enrollment

> Scope: enroll a new endpoint into the Wazuh manager. Use for every new LXC
> container, the Proxmox host itself, and the Windows admin PC.

| | |
|---|---|
| **Target** | Wazuh manager (single-node), running on `192.168.60.20` |
| **Agent versions** | 4.7.x — pinned (do **not** auto-upgrade across major versions) |
| **Pre-reqs** | Manager reachable on TCP/1514 + TCP/1515 from agent, SSH access to the agent host |
| **Risk** | Low — failed enrollment leaves the agent in a clean uninstall state |
| **Duration** | ~5 min per agent |

---

## Why version pinning matters

A 4.7 manager will refuse a 4.8 agent's `agent_keep_alive` message, and the
agent will appear as "Disconnected" in the dashboard with a generic
"connection error" in the agent log. The fix is upgrading the manager, but
that is a planned change — not something I want to discover by accident
during an enrollment.

→ Always check `wazuh-control info` on the manager and match the agent
package to that version before installing.

---

## Procedure — Linux LXC enrollment

### 1. Confirm manager version

```bash
root@wazuh:~# /var/ossec/bin/wazuh-control info
WAZUH_VERSION="v4.7.5"
WAZUH_REVISION="40720"
```

### 2. Add the apt repo and install the **matching** version

```bash
root@new-lxc:~# curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
root@new-lxc:~# echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
    https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
root@new-lxc:~# apt update
root@new-lxc:~# apt install wazuh-agent=4.7.5-1
root@new-lxc:~# apt-mark hold wazuh-agent
```

`apt-mark hold` is the version pin — without it, `apt upgrade` will silently
break the agent on the next routine update.

### 3. Register against the manager

```bash
root@new-lxc:~# /var/ossec/bin/agent-auth -m 192.168.60.20 -A new-lxc
INFO: Started (pid: 31337).
INFO: Using agent name as: new-lxc
INFO: Using IP address: 'src'
INFO: Waiting for server reply
INFO: Valid key received
INFO: Waiting for connection.
```

The agent now has a key. The key is written to `/var/ossec/etc/client.keys`.

### 4. Configure the agent to talk to the manager

`/var/ossec/etc/ossec.conf` — minimum:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.60.20</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>192.168.60.20</manager_address>
    </enrollment>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
</ossec_config>
```

### 5. Start, enable, verify

```bash
root@new-lxc:~# systemctl enable --now wazuh-agent
root@new-lxc:~# systemctl status wazuh-agent --no-pager
root@new-lxc:~# tail -n 30 /var/ossec/logs/ossec.log | grep -i 'connected\|started'
2026-04-29 14:08:22 wazuh-agentd: INFO: (4102): Connected to the server
```

### 6. Confirm on the manager

```bash
root@wazuh:~# /var/ossec/bin/agent_control -l
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-mgr (server), IP: 127.0.0.1, Active/Local
   ID: 003, Name: new-lxc, IP: any, Active
```

The agent should appear as `Active`. If `Disconnected`, see "Common failures".

---

## Procedure — Windows endpoint enrollment

```powershell
# Download package matching the manager version (4.7.5 → wazuh-agent-4.7.5-1.msi)
PS> Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi `
    -OutFile $env:TEMP\wazuh-agent.msi

# Silent install with manager pre-baked
PS> msiexec /i $env:TEMP\wazuh-agent.msi /q `
    WAZUH_MANAGER="192.168.60.20" `
    WAZUH_AGENT_NAME="admin-pc" `
    WAZUH_REGISTRATION_SERVER="192.168.60.20"

# Register and start
PS> & "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m 192.168.60.20 -A admin-pc
PS> Start-Service WazuhSvc
PS> Get-Service WazuhSvc
```

Disable Windows automatic updates for the Wazuh service explicitly — Windows
Update has been known to roll the agent into "needs reinstall" state on
major OS upgrades.

---

## Verification

- Wazuh dashboard → Agents → status `Active` and `Last keep alive` < 30 s.
- New agent triggers Rootcheck and SCA scans on first connect — confirm the
  scan results show up under `Security configuration assessment`.
- `journalctl -u wazuh-agent` (Linux) or `Get-EventLog -Source WazuhSvc`
  (Windows) is clean.

---

## Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Unable to connect to manager` in agent log | Firewall blocks TCP/1514 inbound on manager | Allow the source IP on the ASA `home_access` ACL |
| Agent stuck in "Pending" state | Manager-side `client.keys` entry has wrong agent name | Re-run `agent-auth` with the exact same name as on the manager |
| Agent shows version mismatch warning | Major-version drift between agent and manager | `apt install wazuh-agent=<manager-version>` and reinstall |
| All agents disconnected after manager reboot | Manager started before its own networking | `systemctl restart wazuh-manager` once networking is up |
