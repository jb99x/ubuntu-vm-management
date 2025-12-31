#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

# ==============================================================================
# hardening-vm.sh
# - Generic baseline hardening for existing Ubuntu VMs
# - Safe-by-default: preflight summary + confirmation gates
# - Optional root-owned profile at /etc/hardening-profile.conf
#
# Self-update (wget-based; no git required inside VMs):
#   hardening-vm --self-update
#   hardening-vm --self-update --url <raw-url> [--sha256 <expected>]
#
# NOTE: This script intentionally stores NO default upstream URL.
#       If you want self-update, set UPSTREAM_URL in the profile, or pass --url.
# ==============================================================================

# -------------------------------
# Defaults (fallback prompts only)
# -------------------------------
DEFAULT_LAN_SSH_CIDR="192.168.1.0/24"
DEFAULT_VPN_SSH_CIDR="192.168.254.0/24"
DEFAULT_TIMEZONE="Europe/London"

OFFER_APT_SOURCES_CLEANUP=true
PROFILE_PATH="/etc/hardening-profile.conf"

# -------------------------------
# Effective config (profile/prompt)
# -------------------------------
TIMEZONE=""
LAN_SSH_CIDR=""
VPN_SSH_CIDR=""
declare -a PUBLIC_ALLOW_RULES=()

# Self-update settings (profile/CLI; no baked-in default)
UPSTREAM_URL=""
UPSTREAM_SHA256=""

# -------------------------------
# SSH hardening (generic, compatible with password auth)
# -------------------------------
SSHD_MAX_AUTH_TRIES="4"
SSHD_LOGIN_GRACE_TIME="30s"
SSHD_CLIENT_ALIVE_INTERVAL="300"
SSHD_CLIENT_ALIVE_COUNT_MAX="2"

# ==============================================================================
# Helpers
# ==============================================================================
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: missing required command: $1"; exit 1; }; }

confirm_yn() {
  local ans=""
  while true; do
    read -r -p "$1 [y/N]: " ans
    case "${ans}" in
      [yY]|[yY][eE][sS]) return 0 ;;
      ""|[nN]|[nN][oO])  return 1 ;;
      *) echo "Please enter y or n." ;;
    esac
  done
}

run_step() {
  local name="$1"; shift
  echo
  echo "==> $name"
  if "$@"; then
    echo "OK: $name"
  else
    echo "FAIL: $name"
    exit 1
  fi
}

prompt_with_default() {
  local varname="$1"
  local prompt="$2"
  local current="$3"
  local value=""
  read -r -p "${prompt} [${current}]: " value
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ -n "$value" ]]; then
    printf -v "${varname}" '%s' "${value}"
  else
    printf -v "${varname}" '%s' "${current}"
  fi
}

prompt_nonempty() {
  local varname="$1"
  local prompt="$2"
  local current="${3:-}"
  local value=""
  while true; do
    if [[ -n "${current}" ]]; then
      read -r -p "${prompt} [${current}]: " value
      value="${value#"${value%%[![:space:]]*}"}"
      value="${value%"${value##*[![:space:]]}"}"
      [[ -z "${value}" ]] && value="${current}"
    else
      read -r -p "${prompt}: " value
      value="${value#"${value%%[![:space:]]*}"}"
      value="${value%"${value##*[![:space:]]}"}"
    fi
    if [[ -n "${value}" ]]; then
      printf -v "${varname}" '%s' "${value}"
      return 0
    fi
    echo "Value cannot be empty."
  done
}

validate_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]
}

array_contains() { local n="$1"; shift; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }
array_add_unique() { local v="$1"; array_contains "$v" "${PUBLIC_ALLOW_RULES[@]}" || PUBLIC_ALLOW_RULES+=( "$v" ); }

warn() { echo "WARN: $*" >&2; }
info() { echo "INFO: $*"; }

# ==============================================================================
# Self-update / install helpers (wget-based; no git required)
# ==============================================================================
sha256_of_file() {
  local f="$1"
  sha256sum "$f" | awk '{print $1}'
}

self_update() {
  local url="${1:-}"
  local expected="${2:-}"
  local tmp
  tmp="$(mktemp)"

  if [[ -z "${url}" ]]; then
    echo "No UPSTREAM_URL configured."
    echo "You can either:"
    echo "  - pass --url <raw-url>, or"
    echo "  - save UPSTREAM_URL into ${PROFILE_PATH}"
    echo
    prompt_nonempty url "Enter upstream raw URL for hardening-vm.sh"
  fi

  info "Downloading upstream script..."
  info "  URL: ${url}"
  need_cmd wget

  wget -qO "$tmp" "$url" || { echo "ERROR: failed to download: $url"; rm -f "$tmp"; exit 1; }
  chmod 0644 "$tmp"

  local got
  got="$(sha256_of_file "$tmp")"
  echo
  echo "Upstream info:"
  echo "  URL:  ${url}"
  echo "  SHA256 (downloaded): ${got}"
  if [[ -n "$expected" ]]; then
    echo "  SHA256 (expected):   ${expected}"
    if [[ "$got" != "$expected" ]]; then
      echo "ERROR: checksum mismatch; refusing to install."
      rm -f "$tmp"
      exit 1
    fi
  fi

  echo
  echo "Install destination:"
  local dest="/usr/local/sbin/hardening-vm"
  echo "  ${dest}"
  echo
  echo "This will overwrite the existing installed copy (if any)."
  confirm_yn "Proceed with install/update?" || { echo "Aborted."; rm -f "$tmp"; exit 0; }

  sudo install -m 0755 -o root -g root "$tmp" "$dest"
  rm -f "$tmp"
  echo "OK: installed ${dest}"
  echo "Tip: run 'hardening-vm --version' to confirm."
  exit 0
}

print_version() {
  # Update manually when you cut a release/tag
  echo "hardening-vm.sh v1.0.2"
}

usage() {
  cat <<'EOF'
Usage:
  hardening-vm [--self-update] [--url <raw-url>] [--sha256 <expected>] [--version] [--help]

Normal run (interactive):
  hardening-vm

Self-update (download via wget, install to /usr/local/sbin/hardening-vm):
  hardening-vm --self-update
  hardening-vm --self-update --url <raw-url> [--sha256 <expected>]

Notes:
  - This script stores NO default upstream URL.
  - For repeatable self-update, save UPSTREAM_URL in /etc/hardening-profile.conf
EOF
}

# ==============================================================================
# Profile
# ==============================================================================
load_profile_if_present() {
  if [[ -f "${PROFILE_PATH}" ]]; then
    echo "Profile detected: ${PROFILE_PATH}"
    echo "Loading profile..."

    local tmp
    tmp="$(mktemp)"
    # Read root-only profile via sudo, then source as current user
    sudo cat "${PROFILE_PATH}" > "${tmp}"
    # shellcheck disable=SC1090
    source "${tmp}"
    rm -f "${tmp}"

    echo "Profile loaded."
  else
    echo "No profile found at ${PROFILE_PATH}."
  fi

  # Ensure PUBLIC_ALLOW_RULES is an array even if profile/mistakes define it differently
  if ! declare -p PUBLIC_ALLOW_RULES >/dev/null 2>&1; then
    declare -a PUBLIC_ALLOW_RULES=()
  else
    if ! declare -p PUBLIC_ALLOW_RULES | grep -q 'declare \-a'; then
      local tmpv="${PUBLIC_ALLOW_RULES:-}"
      unset PUBLIC_ALLOW_RULES
      declare -a PUBLIC_ALLOW_RULES=()
      [[ -n "$tmpv" ]] && PUBLIC_ALLOW_RULES+=( "$tmpv" )
    fi
  fi
}

ensure_required_inputs() {
  if [[ -z "${TIMEZONE:-}" ]]; then
    prompt_with_default TIMEZONE "Timezone" "${DEFAULT_TIMEZONE}"
  fi

  if [[ -z "${LAN_SSH_CIDR:-}" ]]; then
    while true; do
      prompt_with_default LAN_SSH_CIDR "LAN subnet allowed for SSH (CIDR)" "${DEFAULT_LAN_SSH_CIDR}"
      validate_cidr "${LAN_SSH_CIDR}" && break
      echo "Invalid CIDR. Example: ${DEFAULT_LAN_SSH_CIDR}"
    done
  fi

  if [[ -z "${VPN_SSH_CIDR:-}" ]]; then
    while true; do
      prompt_with_default VPN_SSH_CIDR "VPN subnet allowed for SSH (CIDR)" "${DEFAULT_VPN_SSH_CIDR}"
      validate_cidr "${VPN_SSH_CIDR}" && break
      echo "Invalid CIDR. Example: ${DEFAULT_VPN_SSH_CIDR}"
    done
  fi
}

save_profile() {
  echo
  echo "Profile save preview (will write to ${PROFILE_PATH}):"
  echo "  TIMEZONE=${TIMEZONE}"
  echo "  LAN_SSH_CIDR=${LAN_SSH_CIDR}"
  echo "  VPN_SSH_CIDR=${VPN_SSH_CIDR}"
  if [[ -n "${UPSTREAM_URL:-}" ]]; then
    echo "  UPSTREAM_URL=${UPSTREAM_URL}"
  else
    echo "  UPSTREAM_URL=(not set)"
  fi
  if (( ${#PUBLIC_ALLOW_RULES[@]} > 0 )); then
    echo "  PUBLIC_ALLOW_RULES:"
    for p in "${PUBLIC_ALLOW_RULES[@]}"; do echo "    - ${p}"; done
  else
    echo "  PUBLIC_ALLOW_RULES: (none)"
  fi
  echo

  confirm_yn "Save these settings to ${PROFILE_PATH}?" || { echo "Skipped saving profile."; return 0; }

  local tmp
  tmp="$(mktemp)"
  {
    echo "# Generated by hardening-vm.sh on $(date -Is)"
    echo "# This file is bash-sourceable."
    echo
    printf 'TIMEZONE=%q\n' "${TIMEZONE}"
    printf 'LAN_SSH_CIDR=%q\n' "${LAN_SSH_CIDR}"
    printf 'VPN_SSH_CIDR=%q\n' "${VPN_SSH_CIDR}"
    # Optional, for self-update
    if [[ -n "${UPSTREAM_URL:-}" ]]; then
      printf 'UPSTREAM_URL=%q\n' "${UPSTREAM_URL}"
    fi
    echo "PUBLIC_ALLOW_RULES=("
    for p in "${PUBLIC_ALLOW_RULES[@]}"; do
      printf '  %q\n' "${p}"
    done
    echo ")"
    echo
  } > "${tmp}"

  sudo install -m 600 -o root -g root "${tmp}" "${PROFILE_PATH}"
  rm -f "${tmp}"
  echo "OK: saved profile to ${PROFILE_PATH}"
}

# ==============================================================================
# UFW discovery / prompts
# ==============================================================================
detect_ufw_public_ports() {
  command -v ufw >/dev/null 2>&1 || return 0

  local out
  out="$(sudo ufw status verbose 2>/dev/null || true)"
  echo "$out" | grep -q '^Status: active' || return 0

  echo "$out" | awk '
    BEGIN { inrules=0 }
    /^To[[:space:]]+Action[[:space:]]+From/ { inrules=1; next }
    inrules==1 && $0 ~ /ALLOW IN/ && $0 ~ /Anywhere/ { print $1 }
  ' | tr -d '\r' | grep -E '^[0-9]{1,5}/(tcp|udp)$' | sort -u || true
}

prompt_import_existing_ufw_public_ports() {
  local detected=()
  mapfile -t detected < <(detect_ufw_public_ports)
  (( ${#detected[@]} > 0 )) || return 0

  echo
  echo "Detected existing UFW public allow rules (ALLOW IN Anywhere):"
  for p in "${detected[@]}"; do echo "  - ${p}"; done
  echo

  if confirm_yn "Import these into this run (and into the profile if saved)?"; then
    for p in "${detected[@]}"; do array_add_unique "$p"; done
    echo "OK: imported detected public ports."
  else
    echo "Skipped importing detected public ports."
  fi
}

prompt_additional_public_ports() {
  local input="" ports=()

  echo
  confirm_yn "Add any additional public ports (open to internet)?" || return 0

  echo "Enter <port>/<proto> e.g. 25565/tcp, 21116/udp. Blank line to finish."
  while true; do
    read -r -p "> " input
    [[ -z "$input" ]] && break
    if [[ "$input" =~ ^[0-9]{1,5}/(tcp|udp)$ ]]; then
      ports+=( "$input" )
    else
      echo "Invalid format."
    fi
  done

  (( ${#ports[@]} > 0 )) || { echo "No additional ports added."; return 0; }

  echo "Proposed additional public ports:"
  for p in "${ports[@]}"; do echo "  - $p"; done

  if confirm_yn "Confirm adding these?"; then
    for p in "${ports[@]}"; do array_add_unique "$p"; done
    echo "OK: added additional public ports."
  else
    echo "Cancelled."
  fi
}

# ==============================================================================
# APT helpers
# ==============================================================================
disable_repo_file() {
  local f="$1"
  [[ -f "$f" ]] || { warn "not found: $f"; return 0; }
  local new="${f}.disabled.$(date +%Y%m%d-%H%M%S)"
  echo "Disabling repo file: $f -> $new"
  sudo mv "$f" "$new"
}

find_sources_paths_from_apt_output() {
  local out_file="$1"
  grep -Eo '/etc/apt/sources\.list(\.d/[^ )]+)?' "$out_file" | sort -u || true
}

check_and_fix_malformed_sources() {
  echo "APT preflight: running apt-get update..."
  local out
  out="$(mktemp)"
  set +e
  sudo apt-get update 2>&1 | tee "$out"
  local rc="${PIPESTATUS[0]}"
  set -e

  if [[ "$rc" -eq 0 ]]; then
    echo "APT preflight OK."
    rm -f "$out"
    return 0
  fi

  echo "APT update failed."
  local files=()
  mapfile -t files < <(find_sources_paths_from_apt_output "$out")

  if (( ${#files[@]} == 0 )); then
    echo "Could not auto-identify offending file. Output:"
    cat "$out"
    rm -f "$out"
    return 1
  fi

  echo "Potential offending source file(s):"
  for f in "${files[@]}"; do echo "  - $f"; done

  if confirm_yn "Disable identified /etc/apt/sources.list.d/* entries (not /etc/apt/sources.list) and retry?"; then
    for f in "${files[@]}"; do
      [[ "$f" == "/etc/apt/sources.list" ]] && continue
      disable_repo_file "$f"
    done
    sudo apt-get update
    rm -f "$out"
    return 0
  fi

  echo "Skipped. Output:"
  cat "$out"
  rm -f "$out"
  return 1
}

detect_ubuntu_codename() { . /etc/os-release; echo "${VERSION_CODENAME:-}"; }

sources_list_contains_ubuntu_deb_lines() {
  sudo grep -Eqs '^\s*deb\s+http(s)?://(archive|security)\.ubuntu\.com/ubuntu' /etc/apt/sources.list
}

comment_out_ubuntu_lines_in_sources_list() {
  sudo sed -i \
    -e 's|^\(\s*deb\s\+http[s]\?://archive\.ubuntu\.com/ubuntu\)|# \1|g' \
    -e 's|^\(\s*deb\s\+http[s]\?://security\.ubuntu\.com/ubuntu\)|# \1|g' \
    /etc/apt/sources.list
}

create_deb822_ubuntu_sources() {
  local codename="$1"
  local target="/etc/apt/sources.list.d/ubuntu.sources"
  local keyring="/usr/share/keyrings/ubuntu-archive-keyring.gpg"
  [[ -f "$keyring" ]] || { echo "ERROR: missing keyring: $keyring"; return 1; }

  sudo tee "$target" >/dev/null <<EOF
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: ${codename} ${codename}-updates ${codename}-backports
Components: main restricted universe multiverse
Signed-By: ${keyring}

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: ${codename}-security
Components: main restricted universe multiverse
Signed-By: ${keyring}
EOF
}

clean_up_apt_sources() {
  [[ "${OFFER_APT_SOURCES_CLEANUP}" == "true" ]] || return 0
  [[ -f /etc/apt/sources.list ]] || return 0
  sources_list_contains_ubuntu_deb_lines || return 0

  local codename
  codename="$(detect_ubuntu_codename)"
  [[ -n "$codename" ]] || { warn "cannot detect codename; skipping APT cleanup."; return 0; }

  echo
  echo "APT cleanup available (reduce 'Missing Signed-By' warnings):"
  echo "  - create /etc/apt/sources.list.d/ubuntu.sources (Deb822 + Signed-By)"
  echo "  - comment Ubuntu lines in /etc/apt/sources.list"
  confirm_yn "Apply this cleanup now?" || { echo "Skipped APT cleanup."; return 0; }

  create_deb822_ubuntu_sources "$codename"
  comment_out_ubuntu_lines_in_sources_list
  sudo apt-get update
}

# ==============================================================================
# Service helpers
# ==============================================================================
reload_ssh_service() {
  # Ubuntu typically uses ssh.service, not sshd.service
  if systemctl list-unit-files 2>/dev/null | grep -qE '^ssh\.service'; then
    sudo systemctl reload ssh || sudo systemctl restart ssh
  elif systemctl list-unit-files 2>/dev/null | grep -qE '^sshd\.service'; then
    sudo systemctl reload sshd || sudo systemctl restart sshd
  else
    warn "neither ssh.service nor sshd.service found; reload skipped"
  fi
}

ensure_qemu_guest_agent() {
  sudo apt-get update -y >/dev/null 2>&1 || true
  sudo apt-get install -y qemu-guest-agent >/dev/null 2>&1 || true

  if systemctl list-unit-files 2>/dev/null | grep -q '^qemu-guest-agent\.service'; then
    sudo systemctl start qemu-guest-agent.service || true
    # often "static"; enabling may warn - that's OK
    sudo systemctl enable qemu-guest-agent.service 2>/dev/null || true
    sudo systemctl --no-pager --full status qemu-guest-agent.service || true
  else
    warn "qemu-guest-agent.service not found (may not be available on this image)"
  fi
}

enable_unattended_security_updates() {
  # Install + enable canonical timers (idempotent)
  sudo apt-get update
  sudo apt-get install -y unattended-upgrades

  # Enable apt timers if present
  for t in apt-daily.timer apt-daily-upgrade.timer; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${t}"; then
      sudo systemctl enable --now "$t" >/dev/null 2>&1 || true
    fi
  done

  # Ensure unattended-upgrades is enabled
  if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
    sudo sed -i \
      -e 's/^\s*APT::Periodic::Update-Package-Lists.*/APT::Periodic::Update-Package-Lists "1";/' \
      -e 's/^\s*APT::Periodic::Unattended-Upgrade.*/APT::Periodic::Unattended-Upgrade "1";/' \
      /etc/apt/apt.conf.d/20auto-upgrades || true
  else
    cat <<'EOF' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  fi
}

# ==============================================================================
# Preflight scans (before Proceed?)
# ==============================================================================
show_preflight_bundle() {
  echo
  echo "========== PREFLIGHT SUMMARY =========="
  echo "OS / init:"
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "  - ${PRETTY_NAME:-unknown} (${VERSION_CODENAME:-unknown})"
  else
    echo "  - /etc/os-release not found"
  fi
  echo "  - PID 1: $(ps -p 1 -o comm= 2>/dev/null || echo unknown)"

  echo "Network:"
  echo "  - Default route:"
  ip -4 route show default 2>/dev/null | sed 's/^/      /' || echo "      (none)"
  echo "  - IPv4 addresses:"
  ip -4 addr show 2>/dev/null | sed 's/^/      /' || echo "      (none)"
  echo "  - Planned SSH allowlists:"
  echo "      * LAN: ${LAN_SSH_CIDR}"
  echo "      * VPN: ${VPN_SSH_CIDR}"

  echo "UFW:"
  if command -v ufw >/dev/null 2>&1; then
    local status
    status="$(sudo ufw status verbose 2>/dev/null || true)"
    if echo "$status" | grep -q '^Status: active'; then
      echo "  - ufw is active"
      local detected=()
      mapfile -t detected < <(detect_ufw_public_ports)
      if (( ${#detected[@]} > 0 )); then
        echo "  - Existing public allow rules detected (ALLOW IN Anywhere):"
        for p in "${detected[@]}"; do echo "      * ${p}"; done
      else
        echo "  - No existing public allow rules detected."
      fi
      echo "  - Current ufw status (verbose):"
      echo "$status" | sed 's/^/      /'
    else
      echo "  - ufw is inactive"
    fi
  else
    echo "  - ufw not installed (script will install it)."
  fi

  echo "SSH:"
  if command -v sshd >/dev/null 2>&1; then
    sudo sshd -t >/dev/null 2>&1 && echo "  - sshd config syntax: OK (sshd -t)" || echo "  - sshd config syntax: FAIL (sshd -t)"
  else
    echo "  - sshd binary not found (openssh-server may not be installed yet)"
  fi

  echo "Disk / memory:"
  df -h / 2>/dev/null | sed 's/^/      /' || true
  command -v free >/dev/null 2>&1 && free -h 2>/dev/null | sed 's/^/      /' || true

  echo "APT sources (inventory only):"
  sudo ls -1 /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | sed 's/^/  - /' || echo "  - (none?)"

  echo "======================================="
  echo
  echo "Note: This script resets UFW rules (ufw --force reset)."
  echo "      If your SSH CIDRs are wrong, you could lock yourself out."
}

# ==============================================================================
# Mutations
# ==============================================================================
configure_grub_serial() {
  set -e
  local GRUB=/etc/default/grub
  [[ -f "$GRUB" ]] || return 0

  sudo sed -i \
    -e 's/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"/' \
    -e 's/^GRUB_TERMINAL=.*/GRUB_TERMINAL="serial console"/' \
    -e 's/^GRUB_SERIAL_COMMAND=.*/GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"/' \
    "$GRUB" 2>/dev/null || true

  grep -q '^GRUB_CMDLINE_LINUX=' "$GRUB" || echo 'GRUB_CMDLINE_LINUX="console=tty0 console=ttyS0,115200n8"' | sudo tee -a "$GRUB" >/dev/null
  grep -q '^GRUB_TERMINAL=' "$GRUB" || echo 'GRUB_TERMINAL="serial console"' | sudo tee -a "$GRUB" >/dev/null
  grep -q '^GRUB_SERIAL_COMMAND=' "$GRUB" || echo 'GRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"' | sudo tee -a "$GRUB" >/dev/null
  sudo update-grub
}

configure_sshd() {
  set -e
  local SSHD=/etc/ssh/sshd_config
  [[ -f "$SSHD" ]] || { warn "missing $SSHD"; return 0; }

  # Disable root SSH login
  if grep -qE '^\s*#?\s*PermitRootLogin' "$SSHD"; then
    sudo sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin no/' "$SSHD"
  else
    echo 'PermitRootLogin no' | sudo tee -a "$SSHD" >/dev/null
  fi

  # Enable SSH password authentication (intentional choice; rely on UFW CIDRs)
  if grep -qE '^\s*#?\s*PasswordAuthentication' "$SSHD"; then
    sudo sed -i 's/^\s*#\?\s*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD"
  else
    echo 'PasswordAuthentication yes' | sudo tee -a "$SSHD" >/dev/null
  fi

  # Ensure PAM enabled
  if grep -qE '^\s*#?\s*UsePAM' "$SSHD"; then
    sudo sed -i 's/^\s*#\?\s*UsePAM.*/UsePAM yes/' "$SSHD"
  else
    echo 'UsePAM yes' | sudo tee -a "$SSHD" >/dev/null
  fi

  # Lightweight daemon-side brute-force mitigation
  if grep -qE '^\s*#?\s*MaxAuthTries' "$SSHD"; then
    sudo sed -i "s/^\s*#\?\s*MaxAuthTries.*/MaxAuthTries ${SSHD_MAX_AUTH_TRIES}/" "$SSHD"
  else
    echo "MaxAuthTries ${SSHD_MAX_AUTH_TRIES}" | sudo tee -a "$SSHD" >/dev/null
  fi

  if grep -qE '^\s*#?\s*LoginGraceTime' "$SSHD"; then
    sudo sed -i "s/^\s*#\?\s*LoginGraceTime.*/LoginGraceTime ${SSHD_LOGIN_GRACE_TIME}/" "$SSHD"
  else
    echo "LoginGraceTime ${SSHD_LOGIN_GRACE_TIME}" | sudo tee -a "$SSHD" >/dev/null
  fi

  if grep -qE '^\s*#?\s*ClientAliveInterval' "$SSHD"; then
    sudo sed -i "s/^\s*#\?\s*ClientAliveInterval.*/ClientAliveInterval ${SSHD_CLIENT_ALIVE_INTERVAL}/" "$SSHD"
  else
    echo "ClientAliveInterval ${SSHD_CLIENT_ALIVE_INTERVAL}" | sudo tee -a "$SSHD" >/dev/null
  fi

  if grep -qE '^\s*#?\s*ClientAliveCountMax' "$SSHD"; then
    sudo sed -i "s/^\s*#\?\s*ClientAliveCountMax.*/ClientAliveCountMax ${SSHD_CLIENT_ALIVE_COUNT_MAX}/" "$SSHD"
  else
    echo "ClientAliveCountMax ${SSHD_CLIENT_ALIVE_COUNT_MAX}" | sudo tee -a "$SSHD" >/dev/null
  fi

  # Validate config if possible
  if command -v sshd >/dev/null 2>&1; then
    sudo sshd -t
  fi
}

configure_ufw() {
  set -e
  sudo ufw --force reset
  sudo ufw default deny incoming
  sudo ufw default allow outgoing

  sudo ufw allow from "${LAN_SSH_CIDR}" to any port 22 proto tcp
  sudo ufw allow from "${VPN_SSH_CIDR}" to any port 22 proto tcp

  if (( ${#PUBLIC_ALLOW_RULES[@]} > 0 )); then
    for p in "${PUBLIC_ALLOW_RULES[@]}"; do
      sudo ufw allow "${p}"
    done
  fi

  sudo ufw logging low
  sudo ufw --force enable
  sudo ufw status verbose
}

# ==============================================================================
# Arg parsing (minimal)
# ==============================================================================
DO_SELF_UPDATE=0
CLI_URL=""
CLI_SHA256=""

i=1
while [[ $i -le $# ]]; do
  a="${!i}"
  case "$a" in
    --help|-h) usage; exit 0 ;;
    --version) print_version; exit 0 ;;
    --self-update) DO_SELF_UPDATE=1 ;;
    --url) i=$((i+1)); CLI_URL="${!i:-}" ;;
    --sha256) i=$((i+1)); CLI_SHA256="${!i:-}" ;;
  esac
  i=$((i+1))
done

# ==============================================================================
# Main
# ==============================================================================
need_cmd sudo
need_cmd systemctl
need_cmd sed
need_cmd grep
need_cmd apt-get
need_cmd ip
need_cmd ps
need_cmd df

if [[ "$EUID" -eq 0 ]]; then
  echo "Run as a normal user with sudo, not root."
  exit 1
fi

# Warm up sudo (avoid prompt mid-steps)
sudo -v

load_profile_if_present

# If self-update: allow CLI override, else use profile UPSTREAM_URL (prompt if empty)
if [[ "$DO_SELF_UPDATE" -eq 1 ]]; then
  if [[ -n "${CLI_URL}" ]]; then
    UPSTREAM_URL="${CLI_URL}"
  fi
  if [[ -n "${CLI_SHA256}" ]]; then
    UPSTREAM_SHA256="${CLI_SHA256}"
  fi

  # If still no URL, prompt and offer to save it.
  if [[ -z "${UPSTREAM_URL:-}" ]]; then
    echo
    prompt_nonempty UPSTREAM_URL "Upstream raw URL for hardening-vm.sh"
    echo
    if confirm_yn "Save this UPSTREAM_URL to ${PROFILE_PATH} for future self-updates?"; then
      # ensure other prompts have values before saving (use defaults as needed)
      ensure_required_inputs
      run_step "Save hardening profile" save_profile
    fi
  fi

  self_update "${UPSTREAM_URL}" "${UPSTREAM_SHA256}"
fi

ensure_required_inputs

show_preflight_bundle

echo "Effective settings for this run:"
echo "  TIMEZONE:     ${TIMEZONE}"
echo "  LAN_SSH_CIDR: ${LAN_SSH_CIDR}"
echo "  VPN_SSH_CIDR: ${VPN_SSH_CIDR}"
echo

confirm_yn "Proceed to apply hardening?" || { echo "Aborted."; exit 0; }

prompt_import_existing_ufw_public_ports
prompt_additional_public_ports

echo
echo "Final public ports to open (Anywhere):"
if (( ${#PUBLIC_ALLOW_RULES[@]} > 0 )); then
  for p in "${PUBLIC_ALLOW_RULES[@]}"; do echo "  - ${p}"; done
else
  echo "  (none)"
fi

if confirm_yn "Save these settings to ${PROFILE_PATH} for future runs?"; then
  run_step "Save hardening profile" save_profile
fi

run_step "Set timezone" sudo timedatectl set-timezone "${TIMEZONE}"
run_step "APT preflight (fix malformed sources if needed)" check_and_fix_malformed_sources

run_step "Install baseline packages" bash -c '
sudo apt-get update
sudo apt-get install -y ufw unattended-upgrades openssh-server
'

run_step "Enable unattended security updates" enable_unattended_security_updates
run_step "Ensure QEMU guest agent (best-effort)" ensure_qemu_guest_agent
run_step "Enable serial console" sudo systemctl enable --now serial-getty@ttyS0
run_step "Configure GRUB for serial console" configure_grub_serial
run_step "Configure SSH (disable root; allow passwords; safe hardening knobs)" configure_sshd
run_step "Reload SSH service" reload_ssh_service
run_step "Configure UFW" configure_ufw
run_step "APT sources cleanup (optional)" clean_up_apt_sources

echo
echo "Baseline applied successfully."
echo "RECOMMENDED: reboot the VM so GRUB serial settings take effect:"
echo "  sudo reboot"
