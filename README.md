# Ubuntu VM Management

A small toolkit for **creating** Ubuntu VMs with a secure baseline and **hardening**
existing Ubuntu VMs to the same standard.

The project is intentionally:

- **Generic** (no environment-specific assumptions baked in)
- **Repeatable** (optional root-owned profiles)
- **Safe** (preflight summaries + confirmation gates)
- **Boring** (predictable defaults, no hidden side effects)

## Contents

- `create-vm.sh` — unattended Ubuntu VM creation using Canonical cloud images
- `hardening-vm.sh` — idempotent hardening for existing Ubuntu VMs
- `maintenance.sh` — scheduled maintenance for hosts/VMs (systemd timer; wget self-update; profile-driven)
- `COMMANDS.md` — operational runbook / quick-reference
- `CHANGELOG.md` — project history

---

## Create

### What it does

- Downloads and verifies an Ubuntu **cloud image** (by codename + flavor)
- Creates VM disks in either:
  - `overlay` mode (fast, space-efficient), or
  - `copy` mode (fully independent image)
- Generates a cloud-init NoCloud seed ISO that:
  - creates an admin user (password-based SSH)
  - disables root SSH login
  - configures UFW:
    - SSH allowed **only** from LAN/VPN CIDRs
    - optional public service ports (open to Anywhere)
  - enables serial console
  - enables `qemu-guest-agent` (where available)
- Provides a full **plan summary** + confirmation before creating anything
- Writes a per-run log file under `/var/log/create-vm` (configurable)
- Optional post-create checks (best-effort):
  - VM state
  - IP discovery (may not work on bridged networks)
  - SSH reachability from host (best-effort)
  - guest-side cloud-init / service status when agent/SSH allows

### Profiles

`create-vm.sh` can load/save a root-owned profile:

- `/etc/create-vm-profile.conf`

Typical items that can be stored:

- timezone
- LAN/VPN SSH CIDRs
- bridge interface
- codename/flavor defaults
- post-check toggles / timeouts

> Profiles are **not** intended to be committed to git.

### When to use

Use `create-vm.sh` when:

- you want a secure baseline from first boot
- you want an unattended install path (cloud-image import)
- you want a CLI-friendly VM (serial + SSH), with optional VNC if needed

Do **not** use it for retrofitting existing installations.

---

## Hardening

### What it does

- Applies the baseline to an **existing** Ubuntu VM
- Safe, repeatable UFW policy:
  - resets firewall rules (with preflight + warnings)
  - re-applies SSH allowlists (LAN/VPN CIDRs)
  - optionally imports existing public allow rules
- SSH policy:
  - disables root SSH login
  - enables password authentication
- Ensures serial console and QEMU guest agent are enabled where supported
- APT repair helpers (optional), including:
  - detect malformed source files and offer to disable them
  - optionally migrate Ubuntu sources to Deb822 with `Signed-By`
  - reduce “Missing Signed-By” warnings

### Profiles

`hardening-vm.sh` can load/save a root-owned profile:

- `/etc/hardening-profile.conf`

---

## Maintenance

### What it does

The `maintenance` script provides a **safe, repeatable maintenance routine** for both **hosts and VMs**, suitable for manual execution or unattended scheduling via a systemd timer.

It performs standard OS upkeep without modifying security posture or making environment-specific assumptions.

**Core tasks:**

- Runs full APT hygiene:
  - `apt-get update`, `full-upgrade`, `autoremove --purge`, `autoclean`, `check`
- Attempts best-effort package repair if needed (`dpkg --audit`, `dpkg --configure -a`)

**Additional upkeep (best-effort):**

- Refreshes Snap packages if Snap is installed
- Vacuums systemd journal logs (keeps last 30 days)
- Performs filesystem trim (`fstrim`) when appropriate

**Environment-aware checks:**

- Detects host vs VM and runs relevant status checks
- Hosts: verifies `libvirt-guests` and lists VMs
- VMs: checks `qemu-guest-agent` and cloud-init services

**Post-run visibility:**

- Indicates whether a reboot is required
- Shows recent unattended-upgrades activity
- Displays network, disk, and memory summaries
- Lists currently upgradable packages (preview)

**Scheduling & updates:**

- Supports unattended runs via a systemd timer
- Can self-update via `wget` from a user-supplied URL stored in a profile
- Never reboots by default; reboot behaviour is always explicit or profile-driven

### Profiles

`maintenance.sh` can load/save a root-owned profile:

- `/etc/maintenance-profile.conf`

---

## Recommended filesystem layout

```text
/opt/ubuntu-vm-management/              # git checkout
/usr/local/sbin/create-vm               # symlink to create-vm.sh
/usr/local/sbin/hardening-vm            # symlink to hardening-vm.sh
/usr/local/sbin/maintenance             # symlink to maintenance.sh
/etc/create-vm-profile.conf             # local-only (not in git)
/etc/hardening-profile.conf             # local-only (not in git)
/etc/maintenance-profile.conf           # local-only (not in git)
```

---

## Install (host)

See `COMMANDS.md`.

---

## Security model (intentional choices)

- Password-based SSH is allowed, but restricted to LAN/VPN CIDRs
- Root login is disabled
- Default-deny inbound firewall policy (UFW)
- Public services must be explicitly declared
- Serial console is enabled for recovery
- Optional VNC can be enabled at creation time for troubleshooting

---

## License

MIT — see `LICENSE`.
