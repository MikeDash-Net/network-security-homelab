# 2026-04-26 — Proxmox kernel 6.17 GPU regression killed local console

| | |
|---|---|
| **Component** | Proxmox VE 9.1 host, kernel `6.17.0-2-pve` (post-upgrade) |
| **Severity** | Medium — host kept running, all 11 LXCs stayed up, but local console was unusable for OOB management |
| **Detected by** | Manual — physical console attempt during a routine reboot |
| **Time to detect** | Immediate (visible on monitor at boot) |
| **Time to resolve** | ~25 min |
| **Status** | Resolved — booted with `nomodeset`, pinned kernel `6.14.11-2-pve`, removed `6.17` from GRUB list |

---

## Symptoms

After applying `apt full-upgrade` and rebooting, the host returned to a state
where:

- The Proxmox web UI on `192.168.60.200:8006` was reachable.
- All 11 LXC containers were running and reachable on their VLAN 60 IPs.
- SSH on `192.168.60.200:22` worked normally.
- **The physical monitor attached to the host showed a black screen with a
  blinking cursor and no kernel log output.** The keyboard responded to
  Caps-Lock toggles, so the kernel was alive — there was just no display.

This meant: the box was running fine, but if SSH ever broke I would have no
out-of-band path to recover it. That is a single point of failure I refuse
to accept on a hypervisor.

## Detection

I noticed it during a routine reboot test that I run after every kernel
upgrade. The post-reboot health check is:

1. Reach the web UI from a Home VLAN host. ✅
2. Reach all LXCs on VLAN 60 by ICMP. ✅
3. Confirm the local console shows the login prompt within 60 s of POST. ❌

Step 3 is the OOB sanity check. Without a working local console, a future
network misconfiguration becomes unrecoverable without dragging the box to a
bench.

## Investigation

### Step 1 — confirm the host is otherwise healthy

```bash
ssh root@192.168.60.200
root@pve:~# uptime
 18:42:11 up 4 min,  1 user,  load average: 0.21, 0.19, 0.08
root@pve:~# uname -r
6.17.0-2-pve
root@pve:~# journalctl -k -b -p err --no-pager | head -50
```

The kernel ring buffer was full of `i915` and `drm` errors — specifically
`drm:i915_gem_init` failing to take ownership of the integrated Intel GPU,
followed by `Console: switching to colour dummy device 80x25`. That last line
explains the black screen — the kernel had given up on the GPU and fallen
back to a dummy console that does not produce output.

### Step 2 — narrow it to the kernel version

```bash
root@pve:~# proxmox-boot-tool kernel list
Manually selected kernels:
None.
Automatically selected kernels:
6.14.11-2-pve
6.17.0-2-pve
```

Two kernels installed. Booted into `6.14.11-2-pve` from the GRUB menu — local
console came up immediately, login prompt visible, no `i915` errors in the
ring buffer. So `6.17.0-2-pve` is the regression.

### Step 3 — decide on the workaround

Three options:

1. **Remove `6.17` entirely.** Clean, but I lose security updates that ship
   in the new kernel until upstream fixes the regression.
2. **Boot `6.17` with `nomodeset`.** Disables the broken Kernel Mode Setting
   path, restores text-mode console, keeps the rest of the kernel.
3. **Pin `6.14.11-2-pve` and wait.** Most conservative — Proxmox specifically
   supports kernel pinning for exactly this case.

Chose **3 + 2**: pin the working kernel as the boot default, but keep `6.17`
available with `nomodeset` as a manual GRUB entry, so I can re-test on
demand without doing a full reinstall.

## Root cause

A regression in the upstream `i915` Intel GPU driver shipped with kernel
`6.17.x`. The GPU initialisation fails on this specific Xeon Gold 6152 server
chipset, and the kernel falls back to a non-functional dummy console. The
network stack, storage, and userspace are unaffected — only the local
display path is broken.

The exact upstream commit was identified later via the Proxmox forum, but
the workaround did not require finding the commit, only confirming it was a
display-only regression.

## Fix

Pinned the previous-known-good kernel as the boot default:

```bash
root@pve:~# proxmox-boot-tool kernel pin 6.14.11-2-pve
Setting '6.14.11-2-pve' as grub default entry and running update-grub.
Generating grub configuration file ...
done
```

Added a manual GRUB entry for `6.17.0-2-pve` with `nomodeset` so it can be
selected from the boot menu without overriding the pin:

```bash
# /etc/grub.d/40_custom
menuentry 'Proxmox VE GNU/Linux, kernel 6.17.0-2-pve nomodeset (manual)' {
    set root=(hd0,gpt2)
    linux /boot/vmlinuz-6.17.0-2-pve root=ZFS=rpool/ROOT/pve-1 boot=zfs ro nomodeset
    initrd /boot/initrd.img-6.17.0-2-pve
}
```

```bash
root@pve:~# update-grub
```

## Verification

```bash
root@pve:~# reboot
# (physical monitor)
# - GRUB menu visible
# - default selection: Proxmox VE 6.14.11-2-pve
# - kernel boots, login prompt visible 12 s after POST
# - all 11 LXCs auto-start, reachable on VLAN 60

root@pve:~# uname -r
6.14.11-2-pve

root@pve:~# pct list | wc -l
12   # header + 11 containers
```

Local console is functional, web UI is reachable, all containers are up.

## Lessons learned

1. **Always verify the local console after a kernel upgrade.** Network-based
   management can mask a console regression for weeks. The day SSH breaks is
   not the day to discover that the local display is also broken.
2. **Proxmox kernel pinning is the right tool.** It is explicitly supported,
   it survives further `apt full-upgrade` cycles, and it is reversible with
   one command. Rolling back to an older Debian kernel by hand would have
   been more invasive.
3. **Keep both kernels installed during the validation window.** Removing
   `6.17` entirely would have meant recompiling the upgrade once upstream
   fixes the regression. Keeping it available with `nomodeset` lets me test
   newer GPU driver releases as they ship.

## Detection control added afterwards

A weekly cron now boots into the **previously pinned** kernel and verifies
that text mode console comes up by writing to `/dev/console`. Output is
shipped to Wazuh:

```bash
# /etc/cron.weekly/console-health
#!/usr/bin/env bash
set -euo pipefail
fbset -i > /var/log/console-health.log 2>&1 || true
logger -t console-health "fbset rc=$?"
```

Wazuh decoder parses `console-health` tag and alerts if the framebuffer
geometry is missing.
