# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project loosely follows Semantic Versioning.

## [Unreleased]

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