# VM Creation & Hardening Toolkit

This repository contains two complementary scripts used to create and secure Linux virtual machines in a consistent, repeatable way.

The design goals are:

- Create new VMs with a secure baseline from first boot
- Harden existing VMs to the same standard
- Avoid hidden assumptions, hardcoded environment details, or unsafe automation

---

## Overview

| Script | Purpose | When to use |
|------|--------|------------|
| `create-vm.sh` | Create a new Ubuntu VM with a secure baseline using cloud-init | **Before first boot** |
| `hardening-vm.sh` | Apply or re-apply security baseline to an existing VM | **After install / on legacy VMs** |

The two scripts share the same philosophy and configuration model but operate at different lifecycle stages.

---

## create-vm.sh

### What it does

- Downloads and verifies the requested Ubuntu Server ISO
- Creates a VM using `virt-install` (CLI-only, serial console)
- Generates a cloud-init seed that:
  - creates an admin user (password-based SSH)
  - disables root login
  - enables serial console
  - enables `qemu-guest-agent`
  - configures SSH securely
  - configures UFW:
    - SSH allowed **only** from LAN/VPN CIDRs
    - optional public service ports (open to Anywhere)
- Provides a full summary and confirmation **before** creating anything
- Optionally cleans up:
  - per-VM cloud-init artifacts
  - old Ubuntu ISO directories

### Configuration model

- Uses **generic defaults only** (safe for any environment)
- Prompts for required values if missing
- Can load/save a **root-owned profile**:

```
/etc/create-vm-profile.conf
```

This allows consistent reuse of:
- timezone
- LAN/VPN SSH CIDRs
- bridge interface
- public ports
- Ubuntu version and OS variant

### When to use

Use `create-vm.sh` when:

- building a **new VM**
- you want security applied **from first boot**
- you want no GUI / no VNC / serial + SSH only

Do **not** use it on existing VMs.

---

## hardening-vm.sh

### What it does

- Applies the same security baseline to an **existing VM**
- Detects and optionally imports existing UFW public rules
- Resets and re-applies firewall rules safely
- Disables root SSH login and enables password authentication
- Ensures serial console and QEMU guest agent are enabled
- Performs **APT repair tasks** if needed:
  - detects malformed sources
  - optionally converts legacy sources to Deb822
  - removes “Missing Signed-By” warnings
- Provides a detailed preflight summary and confirmation gate

### Configuration model

- Loads/saves a **root-owned profile**:

```
/etc/hardening-profile.conf
```

- Prompts for missing values using generic defaults
- Never assumes environment-specific CIDRs

### When to use

Use `hardening-vm.sh` when:

- hardening a **legacy VM**
- re-applying the baseline after manual changes
- repairing broken APT sources
- standardising firewall and SSH configuration

The script is safe to re-run and is designed to be idempotent.

---

## Relationship Between the Scripts

- `create-vm.sh` applies the baseline early via cloud-init
- `hardening-vm.sh` enforces the same baseline later, if needed
- Not all logic is shared:
  - APT source repair belongs **only** in hardening
  - VM creation logic belongs **only** in create-vm

The scripts are aligned by design, not duplicated.

---

## Security Model (Intentional Choices)

- SSH is password-based and restricted to LAN/VPN CIDRs
- Root login is disabled
- No VNC, SPICE, or GUI access
- Serial console + SSH only
- Firewall defaults to deny incoming
- Public services must be explicitly declared

---

## Filesystem Layout (Recommended)

```
/usr/local/sbin/create-vm.sh
/usr/local/sbin/hardening-vm.sh

/etc/create-vm-profile.conf
/etc/hardening-profile.conf
```

---

## Philosophy

- No `curl | bash`
- No silent destructive actions
- No environment-specific assumptions
- Everything visible before it happens
- Everything repeatable later

These scripts are meant to be **boring, predictable, and safe**.
