# COMMANDS

Practical runbook commands for `ubuntu-vm-management`.

This file is intentionally **generic** (no service-specific VM names). Use placeholders
like `<vm-name>`, `<admin-user>`, and `<vm-ip>`.

---

## VM creation and destruction

### Create a new VM (interactive)

```bash
create-vm
```

### Destroy a VM created with `create-vm`

Safely stops, undefines, and removes associated artifacts (with confirmation):

```bash
create-vm --destroy <vm-name>
```

Example:

```bash
create-vm --destroy vm1
```

---

## libvirt / VM management

### List all VMs

```bash
sudo virsh list --all
```

### Start / stop a VM

```bash
sudo virsh start <vm-name>
sudo virsh destroy <vm-name>
```

### Remove VM definition

```bash
sudo virsh undefine <vm-name> --nvram
```

### Attach to serial console

```bash
sudo virsh console <vm-name>
# Exit with Ctrl + ]
```

### Show VM disks

```bash
sudo virsh domblklist <vm-name> --details
```

### Attempt to discover VM IP (may not work on bridged networks)

```bash
sudo virsh domifaddr <vm-name>
```

---

## Disk & artifact cleanup (manual fallback)

### List VM disks

```bash
ls -lh /var/lib/libvirt/images/
```

### Remove a VM disk (common layout)

```bash
sudo rm -f /var/lib/libvirt/images/<vm-name>.qcow2
```

### Remove cloud-init seed directories (if any remain)

```bash
sudo rm -rf /var/lib/libvirt/boot/ubuntu-*/cloud-init/<vm-name>
```

---

## Guest access & diagnostics (inside VM)

### Check network configuration

```bash
ip link
ip -4 addr
ip route
```

### Check network service

```bash
systemctl status systemd-networkd
```

### Check guest agent

```bash
systemctl status qemu-guest-agent
```

### Restart networking (if needed)

```bash
sudo systemctl restart systemd-networkd
```

---

## SSH & firewall

### SSH into a VM

```bash
ssh <admin-user>@<vm-ip>
```

### Check UFW status

```bash
sudo ufw status verbose
```

### Reload SSH service (Ubuntu typically uses `ssh.service`)

```bash
sudo systemctl reload ssh || sudo systemctl restart ssh
```

---

## Host preparation & Git

### Clone the repository

```bash
sudo git clone https://github.com/<you>/<repo>.git /opt/ubuntu-vm-management
cd /opt/ubuntu-vm-management
```

### Ensure scripts are executable

```bash
sudo chmod 0755 /opt/ubuntu-vm-management/create-vm.sh
sudo chmod 0755 /opt/ubuntu-vm-management/hardening-vm.sh
```

### Install script entrypoints into PATH

```bash
sudo ln -sf /opt/ubuntu-vm-management/create-vm.sh /usr/local/sbin/create-vm
sudo ln -sf /opt/ubuntu-vm-management/hardening-vm.sh /usr/local/sbin/hardening-vm
```

### Fix Git “dubious ownership” warning (if you see it)

```bash
git config --global --add safe.directory /opt/ubuntu-vm-management
```

### Stash local changes before pulling updates

```bash
git stash -k
git pull
git stash pop
```

---

## Notes

- On **bridged networks**, `virsh domifaddr` may not show an IP even when DHCP succeeded.
  Check your router / UniFi DHCP leases using the VM MAC address.
- Keep cloud-init seed directories until first boot is confirmed, unless you’re sure the VM
  has completed cloud-init successfully.

## Install / update hardening inside a VM (no git)

```bash
sudo wget -O /usr/local/sbin/hardening-vm \
  https://raw.githubusercontent.com/<you>/<repo>/main/hardening-vm.sh
sudo chmod 0755 /usr/local/sbin/hardening-vm

# update later
hardening-vm --self-update
```

## maintenance.sh

```bash
# Install
sudo install -m 0755 -o root -g root maintenance.sh /usr/local/sbin/maintenance

# Run now (interactive)
maintenance

# Run unattended (for timers)
maintenance --unattended

# Install/enable systemd timer+service (profile-driven schedule)
maintenance --install

# List / inspect timer
systemctl status maintenance.timer maintenance.service --no-pager
systemctl list-timers --all | grep -i maintenance || true
systemctl cat maintenance.service maintenance.timer

# Self-update (wget-based; requires UPSTREAM_URL in /etc/maintenance-profile.conf)
maintenance --self-update
```
