# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project loosely follows Semantic Versioning.

- MAJOR: breaking changes or redesigns
- MINOR: new features, safer defaults, improved UX
- PATCH: bug fixes only

---

## [0.3.0]

### Added

- Unattended VM provisioning using Ubuntu cloud images (`virt-install --import`) instead of interactive ISO installs (standard or minimal image flavor).
- Optional VNC console toggle during VM creation (default remains off; serial console/SSH remain primary).
- Dependency prompts for missing tooling (e.g., `cloud-image-utils` / `cloud-localds`, `qemu-img`).

### Changed

- Download verification now uses SHA256SUMS entries in a robust way (supports `*filename` format), fixing “no properly formatted checksum lines found”.
- Bridge/interface selection is now safe to capture (no multi-line output captured into `--network`).
- Boot artifacts are stored under a codename+flavor path (e.g., `/var/lib/libvirt/boot/ubuntu-noble-standard/`) to avoid collisions.

### Fixed

- VM creation failures caused by invalid bridge interface capture / newline contamination.
- ISO-driven installs that appeared to “stop halfway” (cloud image import avoids installer flow entirely).

---

## [0.2.1]

### Fixed

- Fixed bridge selection prompting in `create-vm.sh` so only the chosen interface is written to stdout (prevents invalid interface names being passed to `virt-install`).
- Improved bridge/interface discovery to avoid spurious entries and present a clean list of valid devices.

---

## [0.2.0]

### Added

- Interactive dependency checks in `create-vm.sh` with optional installation prompts for required tooling.
- Automatic detection of available network bridges with interactive selection if the configured bridge is not found.
- Preflight plan summary in `create-vm.sh` showing VM resources, networking, ISO paths, and firewall intent before execution.
- Robust ISO checksum verification compatible with Ubuntu `SHA256SUMS` formats.

### Changed

- `create-vm.sh` now always prompts for SSH CIDRs with generic defaults instead of embedding environment-specific values.
- Bridge interface is no longer assumed to be `br0`; user confirmation is required when the default is unavailable.
- Improved error handling and messaging for missing cloud-init seed generation tools.
- Clearer separation of host responsibilities (VM creation) and guest responsibilities (hardening).

### Fixed

- ISO verification failure caused by `*filename` entries in Ubuntu `SHA256SUMS`.
- Hard failure when host bridge interface name differed from script defaults.
- Ambiguous dependency error messages during cloud-init seed creation.

---

## [0.1.0]

### Added

- `create-vm.sh`: Ubuntu VM creation via `virt-install` with a secure cloud-init baseline (serial console, SSH policy, UFW baseline, guest agent).
- `hardening-vm.sh`: Idempotent hardening script for existing VMs with preflight summary and confirmation gates.
- Root-owned profile support for repeatable configuration:
  - `/etc/create-vm-profile.conf`
  - `/etc/hardening-profile.conf`

### Security

- Root SSH login disabled.
- Password-based SSH enabled and restricted to LAN/VPN CIDRs.
- Default-deny inbound firewall policy using UFW.
- Optional, explicitly-declared public service ports.
- No GUI / VNC / SPICE access by default.

### Changed

- Consistent “review then confirm” workflow before any destructive or security-sensitive actions.
