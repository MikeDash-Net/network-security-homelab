# 2026-04-27 — `envisionite.ro` total outage: backend LXC DHCP lease change

| | |
|---|---|
| **Component** | Reverse-proxy chain — Cloudflare → MikroTik DNAT → NPM (Nginx Proxy Manager) LXC → backend application LXC |
| **Severity** | Critical — public website returning HTTP 502, full outage |
| **Detected by** | External uptime check + manual report |
| **Time to detect** | ~4 min from first 502 |
| **Time to resolve** | ~35 min |
| **Status** | Resolved — backend LXC moved from DHCP to static reservation, NPM upstream re-pointed |

---

## Symptoms

- Public hostname `envisionite.ro` resolved fine via DNS.
- Cloudflare edge returned `HTTP/2 502` consistently for every request, including a `curl -I`.
- Direct access to the NPM admin UI at `192.168.60.50:81` from the Home VLAN
  showed the proxy host marked **online**, but the live test for the upstream
  showed `connection refused`.
- The backend application LXC was reachable on **its new IP**, but NPM was
  configured against the **previous IP**.

## Detection

External uptime monitoring fires a Wazuh alert when the public site returns
non-200 for two consecutive checks 30 s apart:

```text
2026-04-27 09:14:32 rule 100307  level 9
  http_code=502  url=https://envisionite.ro/
  consecutive_fail=2
```

That is the alert that paged me. The internal NPM dashboard had not raised
anything because, from NPM's point of view, the upstream simply timed out —
which is indistinguishable from "the application crashed" or "the host is
under heavy load". NPM does not know the difference between "the app is gone"
and "the IP I'm pointing at is no longer the app".

## Investigation

### Step 1 — verify the failure plane

```bash
$ curl -I https://envisionite.ro/
HTTP/2 502
server: cloudflare
cf-ray: 932c1f2e0c3a-OTP

$ curl -I --resolve envisionite.ro:443:XX.XX.XX.X https://envisionite.ro/
HTTP/2 502
server: nginx
```

The 502 came back even when bypassing Cloudflare and hitting the public IP
directly. So Cloudflare is innocent — the failure is at NPM or below.

### Step 2 — check NPM → backend

From the NPM LXC:

```bash
root@npm:~# curl -v -H 'Host: envisionite.ro' http://192.168.60.55/
*   Trying 192.168.60.55:80...
* connect to 192.168.60.55 port 80 failed: Connection refused
```

So NPM cannot reach `192.168.60.55:80`. Either the backend is down, or the
backend has moved.

### Step 3 — find the backend

```bash
root@pve:~# pct list | grep envision
106    running    envisionite-app
root@pve:~# pct exec 106 -- ip -4 addr show eth0 | awk '/inet /'
    inet 192.168.60.62/24 brd 192.168.60.255 scope global eth0
```

The container is running. Its IP is `192.168.60.62`. NPM is pointing at
`192.168.60.55`. The IPs do not match. **The backend changed addresses.**

### Step 4 — figure out why the IP changed

The MikroTik runs a DHCP server on the Server VLAN with a 24h lease. The
backend LXC was configured to take DHCP at provision time and had been on
`.55` for months — a stable enough address that I had hard-coded it in NPM
without thinking about it.

```text
> /ip dhcp-server lease print where mac-address=02:00:00:00:00:62
 #   ADDRESS         MAC-ADDRESS         HOST-NAME           STATUS
 0   192.168.60.62   02:00:00:00:00:62   envisionite-app     bound
```

The lease for `.55` had expired during a maintenance window earlier that
morning when the LXC was briefly stopped. When it came back, MikroTik's DHCP
pool had rotated and handed it `.62`. The container booted, took the new
address, started its application — and from its point of view, everything was
fine. NPM, with its upstream still pointing at `.55`, started returning 502.

## Root cause

Backend LXC was running on a DHCP-assigned address (`192.168.60.55`) that was
not protected by a static reservation. The IP rotated to `192.168.60.62` after
a brief downtime, and the NPM upstream had a hard-coded reference to the old
address.

This is a classic anti-pattern: a service whose address is "stable in
practice" until the day it isn't.

## Fix

### Step 1 — restore service immediately

Updated NPM proxy host upstream from `192.168.60.55` → `192.168.60.62`.

```bash
# from NPM admin UI:
#   Hosts → Proxy Hosts → envisionite.ro → Edit
#   Forward Hostname / IP: 192.168.60.62
#   Save
# verified live test passes
```

`curl -I https://envisionite.ro/` returns `HTTP/2 200`. **3-minute** restore.

### Step 2 — make the failure mode impossible going forward

Added a static DHCP reservation on the MikroTik:

```text
> /ip dhcp-server lease add \
    server=dhcp-vlan60 \
    address=192.168.60.62 \
    mac-address=02:00:00:00:00:62 \
    comment="envisionite-app static reservation"

> /ip dhcp-server lease make-static [find mac-address=02:00:00:00:00:62]
```

The lease is now permanent for that MAC. The container can be stopped and
restarted indefinitely without losing its address.

### Step 3 — audit every other NPM upstream

Reviewed all 14 NPM proxy hosts. Three more were pointing at DHCP-assigned
addresses without reservations. Created static reservations for all of them
in a single change window:

```text
> /ip dhcp-server lease make-static [find dynamic=yes]
```

(Followed by manual review of each made-static lease — the MAC-to-hostname
mapping needs to be human-verified before being committed.)

## Verification

```bash
$ curl -I https://envisionite.ro/
HTTP/2 200
server: cloudflare

$ curl -s -o /dev/null -w "%{time_total}\n" https://envisionite.ro/
0.184

# from the MikroTik
> /ip dhcp-server lease print where comment~"static reservation"
# 14 entries, all dynamic=no
```

External uptime monitor reports the site green. Wazuh rule 100307 cleared on
the next check.

## Lessons learned

1. **Hard-coding a DHCP-assigned IP is a latent bug, not a working
   configuration.** It is correct on day one and wrong on the day the lease
   rotates. The fix is structural — make the address stable — not "remember
   to update NPM next time".
2. **NPM's "online" indicator means the proxy is reachable; it does not
   mean the upstream is reachable.** The actual upstream health check is
   the live-test button. I now have a Wazuh rule that scrapes the NPM API
   every 5 min and alerts on any upstream returning non-2xx.
3. **A 502 alert is not enough on its own.** Without the lease history on
   the MikroTik, the investigation would have been guess-and-check. Routine
   logging of DHCP lease grants into Wazuh would have made the timeline
   visible immediately. Added that to the syslog facility list on the
   MikroTik.

## Detection rule added afterwards

`local_rules.xml` — fires when an NPM upstream live-test returns non-2xx
for two consecutive 5-min polls:

```xml
<group name="npm,reverse-proxy,">
  <rule id="100308" level="10" frequency="2" timeframe="600">
    <decoded_as>npm-upstream-poll</decoded_as>
    <field name="upstream_status">^(0|5..)$</field>
    <description>NPM upstream unreachable — backend service may have moved IP</description>
    <mitre><id>T1499.004</id></mitre>
  </rule>
</group>
```
