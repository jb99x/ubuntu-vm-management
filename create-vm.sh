#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# create-vm.sh — Create an Ubuntu Server VM (libvirt/virt-install) with cloud-init
# v0.3.0: cloud-image import (unattended), standard/minimal, VNC optional
# ==============================================================================

# ===============================
# Defaults (safe to keep in-script)
# ===============================
UBUNTU_CODENAME_DEFAULT="noble"            # Ubuntu 24.04 LTS codename
IMAGE_FLAVOR_DEFAULT="standard"           # standard|minimal
ARCH_DEFAULT="amd64"

RAM_MB_DEFAULT="4096"
MAX_RAM_MB_DEFAULT="8192"
VCPUS_DEFAULT="2"
MAX_VCPUS_DEFAULT="2"
DISK_SIZE_GB_DEFAULT="50"

BRIDGE_IF_DEFAULT="bridge0"                   # prompted if not found
OS_VARIANT_DEFAULT="ubuntu24.04"

LAN_SSH_CIDR_DEFAULT="192.168.1.0/24"
VPN_SSH_CIDR_DEFAULT="192.168.254.0/24"
TIMEZONE_DEFAULT="Europe/London"

VNC_DEFAULT="off"                         # off|on
VNC_LISTEN_DEFAULT="127.0.0.1"            # keep local by default

CREATE_PROFILE_PATH="/etc/create-vm-profile.conf"

PUBLIC_ALLOW_RULES_DEFAULT=(
  # "443/tcp"
)

CLEANUP_VM_CLOUDINIT_DIR=true
KEEP_UBUNTU_BOOT_DIRS=2

# ===============================
# Helpers
# ===============================
need_cmd() { command -v "$1" >/dev/null 2>&1; }

confirm_yn() {
  local prompt="$1" ans=""
  while true; do
    read -r -p "${prompt} [y/N]: " ans
    case "${ans}" in
      [yY]|[yY][eE][sS]) return 0 ;;
      ""|[nN]|[nN][oO])  return 1 ;;
      *) echo "Please enter y or n." ;;
    esac
  done
}

prompt_nonempty() {
  local varname="$1" prompt="$2" value=""
  while [[ -z "${value}" ]]; do
    read -r -p "${prompt}" value
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
  done
  printf -v "${varname}" '%s' "${value}"
}

prompt_with_default() {
  local varname="$1" prompt="$2" current="$3" value=""
  read -r -p "${prompt} [${current}]: " value
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ -n "$value" ]]; then
    printf -v "${varname}" '%s' "${value}"
  else
    printf -v "${varname}" '%s' "${current}"
  fi
}

validate_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]
}

validate_password() {
  # Practical guardrails to avoid “surprise login failures”:
  # - 8..64 chars
  # - printable ASCII
  # - no spaces (easy to mistype in consoles)
  local p="$1"
  [[ "${#p}" -ge 8 && "${#p}" -le 64 ]] || return 1
  [[ "$p" =~ ^[[:graph:]]+$ ]] || return 1
  [[ "$p" != *" "* ]] || return 1
  return 0
}

prompt_password() {
  local p1="" p2=""
  while true; do
    read -r -s -p "Enter admin password (8-64 chars, no spaces): " p1; echo
    read -r -s -p "Confirm admin password: " p2; echo
    [[ "$p1" == "$p2" ]] || { echo "Passwords do not match. Try again."; continue; }
    validate_password "$p1" || { echo "Password rejected: use 8-64 printable chars, no spaces."; continue; }
    ADMIN_PASS_PLAIN="$p1"
    break
  done
}

apt_install_prompt() {
  local pkg="$1"
  if confirm_yn "Missing dependency. Install '${pkg}' now via apt?"; then
    sudo apt-get update
    sudo apt-get install -y "${pkg}"
  else
    echo "ERROR: required dependency '${pkg}' is missing."
    exit 1
  fi
}

ensure_cmd_or_install() {
  local cmd="$1" pkg="$2"
  need_cmd "$cmd" || apt_install_prompt "$pkg"
}

vm_exists() { sudo virsh dominfo "${1}" >/dev/null 2>&1; }

safe_rm_rf() {
  local path="$1"
  if [[ -z "${path}" || "${path}" == "/" || "${#path}" -lt 10 ]]; then
    echo "FAIL: refusing to delete suspicious path: '${path}'"
    return 1
  fi
  sudo rm -rf -- "${path}" && echo "OK: deleted ${path}" || { echo "FAIL: could not delete ${path}"; return 1; }
}

cleanup_cloudinit_dir() {
  local dir="$1"
  [[ "${CLEANUP_VM_CLOUDINIT_DIR}" == "true" ]] || return 0
  [[ -d "$dir" ]] || return 0
  if [[ "$dir" != /var/lib/libvirt/boot/*/cloud-init/* ]]; then
    echo "WARN: refusing to clean unexpected cloud-init path: $dir"
    return 0
  fi
  echo
  echo "Cleanup candidate (cloud-init artifacts for this VM):"
  echo "  - ${dir}"
  sudo find "$dir" -maxdepth 1 -type f -printf "  - %p\n" 2>/dev/null || true
  if confirm_yn "Delete this cloud-init directory now?"; then
    safe_rm_rf "$dir" || true
  else
    echo "Skipped deleting cloud-init directory."
  fi
}

cleanup_old_ubuntu_boot_dirs() {
  local base="/var/lib/libvirt/boot"
  local keep="${KEEP_UBUNTU_BOOT_DIRS}"
  mapfile -t dirs < <(sudo find "$base" -maxdepth 1 -type d -name 'ubuntu-*' -printf '%f\n' 2>/dev/null | sort -V)
  local count="${#dirs[@]}"
  (( count > keep )) || return 0

  local to_delete_count=$((count - keep))
  local -a delete_paths=()
  for ((i=0; i<to_delete_count; i++)); do
    local d="${dirs[$i]}"
    local full="${base}/${d}"
    [[ "$d" =~ ^ubuntu- ]] && delete_paths+=( "$full" )
  done

  (( ${#delete_paths[@]} > 0 )) || return 0

  echo
  echo "Cleanup candidates (old Ubuntu boot dirs):"
  for p in "${delete_paths[@]}"; do echo "  - ${p}"; done
  if confirm_yn "Delete these old Ubuntu boot directories now?"; then
    local failures=0
    for p in "${delete_paths[@]}"; do safe_rm_rf "$p" || failures=$((failures+1)); done
    (( failures == 0 )) || echo "WARN: cleanup completed with ${failures} failure(s)."
  fi
}

detect_bridges() {
  if ip -o link show type bridge >/dev/null 2>&1; then
    ip -o link show type bridge | awk -F': ' '{print $2}' | sort -u
    return 0
  fi
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sort -u || true
}

ensure_iface_exists_or_prompt() {
  # Prints ONLY the chosen interface on stdout.
  local current="$1"
  if ip link show "$current" >/dev/null 2>&1; then
    printf '%s\n' "$current"
    return 0
  fi

  {
    echo
    echo "Interface '${current}' not found."
    echo "Detected interfaces (may include bridges):"
    detect_bridges | sed 's/^/  - /' || true
    echo
  } >&2

  local chosen=""
  while true; do
    prompt_with_default chosen "Bridge interface to attach VM NICs to" "${current}"
    if ip link show "$chosen" >/dev/null 2>&1; then
      printf '%s\n' "$chosen"
      return 0
    fi
    echo "Interface '${chosen}' still not found. Try again." >&2
  done
}

verify_sha256_from_sums() {
  # Supports both:
  #   <hash>  *filename
  #   <hash>   filename
  local file_path="$1" file_name="$2" sums_path="$3"
  awk -v name="$file_name" -v fpath="$file_path" '
    $2 ~ ("\\*?" name "$") { print $1 " " fpath }
  ' "$sums_path" | sha256sum -c -
}

# ===============================
# Safety / sudo
# ===============================
if [[ "$EUID" -eq 0 ]]; then
  echo "Run as a normal user with sudo, not root."
  exit 1
fi
sudo -v

# ===============================
# Optional create-profile (kept, but no private defaults)
# ===============================
load_create_profile_if_present() {
  if [[ -f "${CREATE_PROFILE_PATH}" ]]; then
    echo "Create-profile detected: ${CREATE_PROFILE_PATH}"
    echo "Loading create-profile..."
    local tmp; tmp="$(mktemp)"
    sudo cat "${CREATE_PROFILE_PATH}" > "${tmp}"
    # shellcheck disable=SC1090
    source "${tmp}"
    rm -f "${tmp}"
    echo "Create-profile loaded."
  else
    echo "No create-profile found at ${CREATE_PROFILE_PATH}."
  fi

  # Ensure PUBLIC_ALLOW_RULES_DEFAULT is an array
  if declare -p PUBLIC_ALLOW_RULES_DEFAULT >/dev/null 2>&1; then
    if ! declare -p PUBLIC_ALLOW_RULES_DEFAULT | grep -q 'declare \-a'; then
      local tmpv="${PUBLIC_ALLOW_RULES_DEFAULT:-}"
      unset PUBLIC_ALLOW_RULES_DEFAULT
      declare -a PUBLIC_ALLOW_RULES_DEFAULT=()
      [[ -n "${tmpv}" ]] && PUBLIC_ALLOW_RULES_DEFAULT+=( "${tmpv}" )
    fi
  else
    declare -a PUBLIC_ALLOW_RULES_DEFAULT=()
  fi
}

save_create_profile() {
  echo
  echo "Create-profile save preview (will write to ${CREATE_PROFILE_PATH}):"
  echo "  TIMEZONE_DEFAULT=${TIMEZONE}"
  echo "  LAN_SSH_CIDR_DEFAULT=${LAN_SSH_CIDR}"
  echo "  VPN_SSH_CIDR_DEFAULT=${VPN_SSH_CIDR}"
  echo "  BRIDGE_IF_DEFAULT=${BRIDGE_IF}"
  echo "  OS_VARIANT_DEFAULT=${OS_VARIANT}"
  echo "  UBUNTU_CODENAME_DEFAULT=${UBUNTU_CODENAME}"
  echo "  IMAGE_FLAVOR_DEFAULT=${IMAGE_FLAVOR}"
  echo "  VNC_DEFAULT=${VNC_MODE}"
  if (( ${#PUBLIC_ALLOW_RULES[@]} > 0 )); then
    echo "  PUBLIC_ALLOW_RULES_DEFAULT:"
    for p in "${PUBLIC_ALLOW_RULES[@]}"; do echo "    - ${p}"; done
  else
    echo "  PUBLIC_ALLOW_RULES_DEFAULT: (none)"
  fi
  echo

  confirm_yn "Save these defaults to ${CREATE_PROFILE_PATH} for future runs?" || { echo "Skipped saving create-profile."; return 0; }

  local tmp; tmp="$(mktemp)"
  {
    echo "# Generated by create-vm.sh on $(date -Is)"
    echo "# This file is bash-sourceable."
    echo
    printf 'TIMEZONE_DEFAULT=%q\n' "${TIMEZONE}"
    printf 'LAN_SSH_CIDR_DEFAULT=%q\n' "${LAN_SSH_CIDR}"
    printf 'VPN_SSH_CIDR_DEFAULT=%q\n' "${VPN_SSH_CIDR}"
    printf 'BRIDGE_IF_DEFAULT=%q\n' "${BRIDGE_IF}"
    printf 'OS_VARIANT_DEFAULT=%q\n' "${OS_VARIANT}"
    printf 'UBUNTU_CODENAME_DEFAULT=%q\n' "${UBUNTU_CODENAME}"
    printf 'IMAGE_FLAVOR_DEFAULT=%q\n' "${IMAGE_FLAVOR}"
    printf 'VNC_DEFAULT=%q\n' "${VNC_MODE}"
    echo "PUBLIC_ALLOW_RULES_DEFAULT=("
    for p in "${PUBLIC_ALLOW_RULES[@]}"; do printf '  %q\n' "${p}"; done
    echo ")"
    echo
  } > "${tmp}"

  sudo install -m 600 -o root -g root "${tmp}" "${CREATE_PROFILE_PATH}"
  rm -f "${tmp}"
  echo "OK: saved create-profile to ${CREATE_PROFILE_PATH}"
}

load_create_profile_if_present

# ===============================
# Dependencies (prompt to install)
# ===============================
ensure_cmd_or_install wget wget
ensure_cmd_or_install sha256sum coreutils
ensure_cmd_or_install awk gawk
ensure_cmd_or_install grep grep
ensure_cmd_or_install ip iproute2
ensure_cmd_or_install openssl openssl
ensure_cmd_or_install virt-install virtinst
ensure_cmd_or_install virsh libvirt-clients
ensure_cmd_or_install qemu-img qemu-utils

HAVE_CLOUD_LOCALDS=0
if need_cmd cloud-localds; then
  HAVE_CLOUD_LOCALDS=1
else
  apt_install_prompt cloud-image-utils
  HAVE_CLOUD_LOCALDS=1
fi

# ===============================
# Interactive inputs
# ===============================
prompt_nonempty VM_NAME "VM name (e.g. rustdesk, minecraft): "
prompt_nonempty ADMIN_USER "Admin username (e.g. admin): "
prompt_password

prompt_with_default UBUNTU_CODENAME "Ubuntu codename" "${UBUNTU_CODENAME_DEFAULT}"
prompt_with_default IMAGE_FLAVOR "Image flavor (standard|minimal)" "${IMAGE_FLAVOR_DEFAULT}"
prompt_with_default OS_VARIANT "libosinfo os-variant" "${OS_VARIANT_DEFAULT}"

while true; do
  prompt_with_default LAN_SSH_CIDR "LAN subnet allowed for SSH (CIDR)" "${LAN_SSH_CIDR_DEFAULT}"
  validate_cidr "${LAN_SSH_CIDR}" && break
  echo "Invalid CIDR. Example: ${LAN_SSH_CIDR_DEFAULT}"
done

while true; do
  prompt_with_default VPN_SSH_CIDR "VPN subnet allowed for SSH (CIDR)" "${VPN_SSH_CIDR_DEFAULT}"
  validate_cidr "${VPN_SSH_CIDR}" && break
  echo "Invalid CIDR. Example: ${VPN_SSH_CIDR_DEFAULT}"
done

prompt_with_default TIMEZONE "Timezone" "${TIMEZONE_DEFAULT}"
prompt_with_default RAM_MB "RAM (MB)" "${RAM_MB_DEFAULT}"
prompt_with_default MAX_RAM_MB "Max RAM (MB)" "${MAX_RAM_MB_DEFAULT}"
prompt_with_default VCPUS "vCPUs" "${VCPUS_DEFAULT}"
prompt_with_default MAX_VCPUS "Max vCPUs" "${MAX_VCPUS_DEFAULT}"
prompt_with_default DISK_SIZE_GB "Disk size (GB)" "${DISK_SIZE_GB_DEFAULT}"

BRIDGE_IF="$(ensure_iface_exists_or_prompt "${BRIDGE_IF_DEFAULT}")"

prompt_with_default VNC_MODE "VNC console (off|on)" "${VNC_DEFAULT}"
prompt_with_default VNC_LISTEN "VNC listen address" "${VNC_LISTEN_DEFAULT}"

VM_HOSTNAME="${VM_NAME}"
ADMIN_PASS_HASH="$(printf '%s' "${ADMIN_PASS_PLAIN}" | openssl passwd -6 -stdin)"
unset ADMIN_PASS_PLAIN

declare -a PUBLIC_ALLOW_RULES=("${PUBLIC_ALLOW_RULES_DEFAULT[@]}")

echo
if confirm_yn "Add any public ports to allow from the internet (UFW allow Anywhere)?"; then
  echo "Enter <port>/<proto> e.g. 25565/tcp, 21116/udp. Blank line to finish."
  while true; do
    read -r -p "> " input
    [[ -z "${input}" ]] && break
    [[ "${input}" =~ ^[0-9]{1,5}/(tcp|udp)$ ]] || { echo "Invalid format."; continue; }
    PUBLIC_ALLOW_RULES+=( "${input}" )
  done
fi

# ===============================
# Derived paths/URLs (cloud images)
# ===============================
BOOT_DIR="/var/lib/libvirt/boot/ubuntu-${UBUNTU_CODENAME}-${IMAGE_FLAVOR}"
sudo mkdir -p "${BOOT_DIR}"

# Cloud image source (standard vs minimal)
if [[ "${IMAGE_FLAVOR}" == "minimal" ]]; then
  CLOUD_BASE_URL="https://cloud-images.ubuntu.com/minimal/releases/${UBUNTU_CODENAME}/release"
  IMAGE_NAME="ubuntu-24.04-minimal-cloudimg-${ARCH_DEFAULT}.img"
else
  CLOUD_BASE_URL="https://cloud-images.ubuntu.com/releases/${UBUNTU_CODENAME}/release"
  IMAGE_NAME="ubuntu-24.04-server-cloudimg-${ARCH_DEFAULT}.img"
fi

IMAGE_PATH="${BOOT_DIR}/${IMAGE_NAME}"
SHA256SUMS_PATH="${BOOT_DIR}/SHA256SUMS"

DISK_PATH="/var/lib/libvirt/images/${VM_NAME}.qcow2"

CI_DIR="${BOOT_DIR}/cloud-init/${VM_NAME}"
CI_USER_DATA="${CI_DIR}/user-data"
CI_META_DATA="${CI_DIR}/meta-data"
CI_SEED_ISO="${CI_DIR}/seed-cidata.iso"

# ===============================
# PLAN SUMMARY
# ===============================
echo
echo "================== PLAN SUMMARY =================="
echo "VM:"
echo "  Name:        ${VM_NAME}"
echo "  Hostname:    ${VM_HOSTNAME}"
echo "  Admin user:  ${ADMIN_USER}"
echo "Resources:"
echo "  RAM:         ${RAM_MB} MB (max ${MAX_RAM_MB} MB)"
echo "  vCPUs:       ${VCPUS} (max ${MAX_VCPUS})"
echo "  Disk:        ${DISK_SIZE_GB} GB (${DISK_PATH})"
echo "Networking:"
echo "  Bridge:      ${BRIDGE_IF}"
echo "  SSH CIDRs:   LAN ${LAN_SSH_CIDR} | VPN ${VPN_SSH_CIDR}"
echo "Ubuntu:"
echo "  Codename:    ${UBUNTU_CODENAME}"
echo "  Flavor:      ${IMAGE_FLAVOR}"
echo "  Cloud image: ${CLOUD_BASE_URL}/${IMAGE_NAME}"
echo "  os-variant:  ${OS_VARIANT}"
echo "Console:"
echo "  VNC:         ${VNC_MODE} (listen ${VNC_LISTEN})"
echo "Cloud-init:"
echo "  Seed ISO:    ${CI_SEED_ISO}"
echo "UFW:"
if (( ${#PUBLIC_ALLOW_RULES[@]} > 0 )); then
  echo "  Public allow:"
  for p in "${PUBLIC_ALLOW_RULES[@]}"; do echo "    - ${p}"; done
else
  echo "  Public allow: (none)"
fi
echo "=================================================="
echo

# ===============================
# Idempotency checks
# ===============================
if vm_exists "${VM_NAME}"; then
  echo "VM '${VM_NAME}' already exists. Nothing to do."
  exit 0
fi

if [[ -e "${DISK_PATH}" ]]; then
  echo "ERROR: Disk already exists but VM does not: ${DISK_PATH}"
  echo "Refusing to overwrite. Choose a different VM name or remove the disk."
  exit 1
fi

confirm_yn "Proceed to create VM '${VM_NAME}' and generate artifacts?" || { echo "Aborted."; exit 0; }

# ===============================
# Download cloud image + verify
# ===============================
echo "Preparing Ubuntu cloud image (${IMAGE_FLAVOR})..."
cd "${BOOT_DIR}"

if [[ ! -f "${SHA256SUMS_PATH}" ]]; then
  echo "Downloading SHA256SUMS..."
  sudo wget -O "${SHA256SUMS_PATH}" "${CLOUD_BASE_URL}/SHA256SUMS"
else
  echo "SHA256SUMS already present: ${SHA256SUMS_PATH}"
fi

if [[ ! -f "${IMAGE_PATH}" ]]; then
  echo "Downloading ${IMAGE_NAME}..."
  sudo wget -O "${IMAGE_PATH}" "${CLOUD_BASE_URL}/${IMAGE_NAME}"
else
  echo "Cloud image already present: ${IMAGE_PATH}"
fi

echo "Verifying cloud image checksum..."
verify_sha256_from_sums "${IMAGE_PATH}" "${IMAGE_NAME}" "${SHA256SUMS_PATH}"

# ===============================
# Create VM disk from base image + resize
# ===============================
echo "Creating VM disk from cloud image..."
sudo qemu-img convert -O qcow2 "${IMAGE_PATH}" "${DISK_PATH}"
sudo qemu-img resize "${DISK_PATH}" "${DISK_SIZE_GB}G"

# ===============================
# Create cloud-init seed ISO (CIDATA / NoCloud)
# ===============================
echo "Creating cloud-init NoCloud seed (CIDATA)..."
sudo mkdir -p "${CI_DIR}"

UFW_PUBLIC_BLOCK=""
for rule in "${PUBLIC_ALLOW_RULES[@]}"; do
  UFW_PUBLIC_BLOCK+="ufw allow ${rule}\n"
done

sudo tee "${CI_USER_DATA}" >/dev/null <<EOF
#cloud-config
hostname: ${VM_HOSTNAME}
manage_etc_hosts: true
timezone: ${TIMEZONE}

users:
  - name: ${ADMIN_USER}
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
    passwd: ${ADMIN_PASS_HASH}

ssh_pwauth: true
disable_root: true

package_update: true
package_upgrade: false
packages:
  - ufw
  - qemu-guest-agent
  - unattended-upgrades
  - openssh-server

runcmd:
  - [ systemctl, enable, --now, "serial-getty@ttyS0.service" ]
  - [ systemctl, enable, --now, "qemu-guest-agent.service" ]

  - |
    set -e
    SSHD=/etc/ssh/sshd_config

    # Disable root SSH login
    if grep -qE '^\s*#?\s*PermitRootLogin' "\$SSHD"; then
      sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin no/' "\$SSHD"
    else
      echo 'PermitRootLogin no' >> "\$SSHD"
    fi

    # Enable password auth
    if grep -qE '^\s*#?\s*PasswordAuthentication' "\$SSHD"; then
      sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/' "\$SSHD"
    else
      echo 'PasswordAuthentication yes' >> "\$SSHD"
    fi

    # Ensure PAM enabled
    if grep -qE '^\s*#?\s*UsePAM' "\$SSHD"; then
      sed -i 's/^\s*#\?\s*UsePAM.*/UsePAM yes/' "\$SSHD"
    else
      echo 'UsePAM yes' >> "\$SSHD"
    fi

    systemctl reload ssh || systemctl restart ssh || true
    systemctl reload sshd || systemctl restart sshd || true

  - |
    set -e
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    ufw allow from ${LAN_SSH_CIDR} to any port 22 proto tcp
    ufw allow from ${VPN_SSH_CIDR} to any port 22 proto tcp

$(printf "%b" "${UFW_PUBLIC_BLOCK}")

    ufw logging low
    ufw --force enable

final_message: "cloud-init complete on \$hostname"
EOF

sudo tee "${CI_META_DATA}" >/dev/null <<EOF
instance-id: ${VM_NAME}-${UBUNTU_CODENAME}-${IMAGE_FLAVOR}
local-hostname: ${VM_HOSTNAME}
EOF

sudo cloud-localds -v "${CI_SEED_ISO}" "${CI_USER_DATA}" "${CI_META_DATA}"

# ===============================
# Create VM (import disk)
# ===============================
echo "Creating VM '${VM_NAME}' (import cloud image)..."

GRAPHICS_ARGS=(--graphics none)
if [[ "${VNC_MODE}" == "on" ]]; then
  GRAPHICS_ARGS=(--graphics "vnc,listen=${VNC_LISTEN},port=-1")
fi

sudo virt-install \
  --name "${VM_NAME}" \
  --os-variant "${OS_VARIANT}" \
  --memory "${RAM_MB}",maxmemory="${MAX_RAM_MB}" \
  --vcpus "${VCPUS}",maxvcpus="${MAX_VCPUS}" \
  --disk path="${DISK_PATH}",format=qcow2,bus=virtio,discard=unmap \
  --disk path="${CI_SEED_ISO}",device=cdrom,readonly=on \
  --network bridge="${BRIDGE_IF}",model=virtio \
  "${GRAPHICS_ARGS[@]}" \
  --console pty,target_type=serial \
  --import \
  --noautoconsole

echo "VM '${VM_NAME}' created."

# ===============================
# Cleanup
# ===============================
cleanup_cloudinit_dir "${CI_DIR}"
cleanup_old_ubuntu_boot_dirs

echo
echo "Done."
echo "Next:"
echo "  - Check DHCP lease on your LAN router/DHCP server for '${VM_NAME}'"
echo "  - Serial console: Cockpit → Machines → ${VM_NAME} → Console (Serial)"
echo "  - SSH from LAN (${LAN_SSH_CIDR}) or VPN (${VPN_SSH_CIDR}) as '${ADMIN_USER}'"