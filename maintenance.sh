#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail

# ==============================================================================
# maintenance.sh — Generic Ubuntu host/VM maintenance (safe defaults)
#
# Goals:
# - Works on both hosts and VMs (no assumptions about environment)
# - Can run interactively OR unattended via systemd timer
# - Uses a root-owned profile for unattended runs (no prompts required)
# - Optional self-update via wget (no git required on VMs)
#
# Install location (recommended): /usr/local/sbin/maintenance
# Profile (root-owned):          /etc/maintenance-profile.conf
#
# Version: v1.2.1
# ==============================================================================

VERSION="1.2.1"

PROFILE_PATH="/etc/maintenance-profile.conf"

# -------------------------------
# Defaults (fallback prompts only)
# -------------------------------
DEFAULT_TIMEZONE="Europe/London"

# Behaviour toggles (may be overridden by profile)
TIMEZONE=""
UNATTENDED="false"         # true when running from timer
DO_APT_MAINT="true"        # apt update/upgrade/autoremove/autoclean/check
DO_UNATTENDED_UPGRADES="true"
DO_TRIM="auto"             # auto|true|false  (auto => only if fstrim exists)
DO_JOURNAL_VACUUM="true"   # vacuum persistent journal
JOURNAL_MAX_AGE="30d"
DO_LOGROTATE="true"
DO_REBOOT_IF_REQUIRED="false"   # if /var/run/reboot-required exists
DO_SCHEDULED_REBOOT="false"     # force a reboot on schedule (host use)

# Timer/install settings (profile-driven)
TIMER_MODE="auto"          # auto|host|vm
TIMER_SCHEDULE="monthly"   # weekly|monthly
WEEKLY_DAY="Sun"           # Mon..Sun
WEEKLY_TIME="04:00"        # HH:MM (24h)
MONTHLY_DOM="1"            # 1-28 recommended
MONTHLY_TIME="04:00"       # HH:MM
ONCALENDAR_OVERRIDE=""     # if set, used as OnCalendar verbatim

# Self-update settings (profile/CLI; no baked-in default URL)
UPSTREAM_URL=""
UPSTREAM_SHA256=""

# -------------------------------
# Helpers
# -------------------------------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

die() { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }
info() { echo "INFO: $*"; }

confirm_yn() {
  local prompt="$1" ans=""
  [[ "${UNATTENDED}" == "true" ]] && return 0
  while true; do
    read -r -p "${prompt} [y/N]: " ans
    case "${ans}" in
      [yY]|[yY][eE][sS]) return 0 ;;
      ""|[nN]|[nN][oO])  return 1 ;;
      *) echo "Please enter y or n." ;;
    esac
  done
}

prompt_with_default() {
  local varname="$1" prompt="$2" current="$3" value=""
  [[ "${UNATTENDED}" == "true" ]] && { printf -v "${varname}" '%s' "${current}"; return 0; }
  read -r -p "${prompt} [${current}]: " value
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  if [[ -n "$value" ]]; then printf -v "${varname}" '%s' "${value}"
  else printf -v "${varname}" '%s' "${current}"; fi
}

prompt_nonempty() {
  local varname="$1" prompt="$2" current="${3:-}" value=""
  [[ "${UNATTENDED}" == "true" ]] && { [[ -n "$current" ]] || die "Missing required '${varname}' in profile for unattended run"; printf -v "${varname}" '%s' "${current}"; return 0; }
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
    [[ -n "${value}" ]] && { printf -v "${varname}" '%s' "${value}"; return 0; }
    echo "Value cannot be empty."
  done
}

is_vm() {
  # Best-effort heuristics; returns 0 if likely VM/guest.
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    [[ "$(systemd-detect-virt --quiet && echo yes || echo no)" == "yes" ]] && return 0
  fi
  # Fallback: presence of virt-what or dmi hints is variable; keep simple.
  return 1
}

# -------------------------------
# Profile handling (root-owned)
# -------------------------------
load_profile_if_present() {
  if [[ -f "${PROFILE_PATH}" ]]; then
    info "Profile detected: ${PROFILE_PATH}"
    local tmp; tmp="$(mktemp)"
    sudo cat "${PROFILE_PATH}" > "${tmp}"
    # shellcheck disable=SC1090
    source "${tmp}"
    rm -f "${tmp}"
    info "Profile loaded."
  else
    info "No profile found at ${PROFILE_PATH}."
  fi
}

save_profile() {
  [[ "${UNATTENDED}" == "true" ]] && return 0
  echo
  echo "Profile save preview (will write to ${PROFILE_PATH}):"
  echo "  TIMEZONE=${TIMEZONE}"
  echo "  UPSTREAM_URL=${UPSTREAM_URL:-"(not set)"}"
  echo "  TIMER_MODE=${TIMER_MODE}"
  echo "  TIMER_SCHEDULE=${TIMER_SCHEDULE}"
  echo "  WEEKLY_DAY=${WEEKLY_DAY} WEEKLY_TIME=${WEEKLY_TIME}"
  echo "  MONTHLY_DOM=${MONTHLY_DOM} MONTHLY_TIME=${MONTHLY_TIME}"
  echo "  ONCALENDAR_OVERRIDE=${ONCALENDAR_OVERRIDE:-"(none)"}"
  echo "  DO_APT_MAINT=${DO_APT_MAINT}"
  echo "  DO_UNATTENDED_UPGRADES=${DO_UNATTENDED_UPGRADES}"
  echo "  DO_JOURNAL_VACUUM=${DO_JOURNAL_VACUUM} JOURNAL_MAX_AGE=${JOURNAL_MAX_AGE}"
  echo "  DO_TRIM=${DO_TRIM}"
  echo "  DO_LOGROTATE=${DO_LOGROTATE}"
  echo "  DO_REBOOT_IF_REQUIRED=${DO_REBOOT_IF_REQUIRED}"
  echo "  DO_SCHEDULED_REBOOT=${DO_SCHEDULED_REBOOT}"
  echo
  confirm_yn "Save these settings to ${PROFILE_PATH}?" || { info "Skipped saving profile."; return 0; }

  local tmp; tmp="$(mktemp)"
  {
    echo "# Generated by maintenance.sh on $(date -Is)"
    echo "# This file is bash-sourceable."
    echo
    printf 'TIMEZONE=%q
' "${TIMEZONE}"
    [[ -n "${UPSTREAM_URL:-}" ]] && printf 'UPSTREAM_URL=%q
' "${UPSTREAM_URL}"
    [[ -n "${UPSTREAM_SHA256:-}" ]] && printf 'UPSTREAM_SHA256=%q
' "${UPSTREAM_SHA256}"
    printf 'TIMER_MODE=%q
' "${TIMER_MODE}"
    printf 'TIMER_SCHEDULE=%q
' "${TIMER_SCHEDULE}"
    printf 'WEEKLY_DAY=%q
' "${WEEKLY_DAY}"
    printf 'WEEKLY_TIME=%q
' "${WEEKLY_TIME}"
    printf 'MONTHLY_DOM=%q
' "${MONTHLY_DOM}"
    printf 'MONTHLY_TIME=%q
' "${MONTHLY_TIME}"
    [[ -n "${ONCALENDAR_OVERRIDE:-}" ]] && printf 'ONCALENDAR_OVERRIDE=%q
' "${ONCALENDAR_OVERRIDE}"
    printf 'DO_APT_MAINT=%q
' "${DO_APT_MAINT}"
    printf 'DO_UNATTENDED_UPGRADES=%q
' "${DO_UNATTENDED_UPGRADES}"
    printf 'DO_JOURNAL_VACUUM=%q
' "${DO_JOURNAL_VACUUM}"
    printf 'JOURNAL_MAX_AGE=%q
' "${JOURNAL_MAX_AGE}"
    printf 'DO_TRIM=%q
' "${DO_TRIM}"
    printf 'DO_LOGROTATE=%q
' "${DO_LOGROTATE}"
    printf 'DO_REBOOT_IF_REQUIRED=%q
' "${DO_REBOOT_IF_REQUIRED}"
    printf 'DO_SCHEDULED_REBOOT=%q
' "${DO_SCHEDULED_REBOOT}"
    echo
  } > "${tmp}"

  sudo install -m 600 -o root -g root "${tmp}" "${PROFILE_PATH}"
  rm -f "${tmp}"
  info "Saved profile to ${PROFILE_PATH}"
}

# -------------------------------
# Self-update (wget-based)
# -------------------------------
sha256_of_file() { sha256sum "$1" | awk '{print $1}'; }

self_update() {
  local url="${1:-${UPSTREAM_URL:-}}"
  local expected="${2:-${UPSTREAM_SHA256:-}}"
  [[ -n "${url}" ]] || die "No upstream URL set. Provide --url or set UPSTREAM_URL in ${PROFILE_PATH}"

  need_cmd wget || die "wget is required for self-update"
  local tmp; tmp="$(mktemp)"
  info "Downloading upstream script: ${url}"
  wget -qO "${tmp}" "${url}" || { rm -f "${tmp}"; die "Failed to download ${url}"; }
  chmod 0644 "${tmp}"

  local got; got="$(sha256_of_file "${tmp}")"
  echo "Downloaded SHA256: ${got}"
  if [[ -n "${expected}" ]]; then
    echo "Expected  SHA256: ${expected}"
    [[ "${got}" == "${expected}" ]] || { rm -f "${tmp}"; die "Checksum mismatch; refusing to install"; }
  fi

  local dest="/usr/local/sbin/maintenance"
  confirm_yn "Install/update to ${dest}?" || { rm -f "${tmp}"; info "Aborted."; exit 0; }
  sudo install -m 0755 -o root -g root "${tmp}" "${dest}"
  rm -f "${tmp}"
  info "Installed ${dest}"
  exit 0
}

# -------------------------------
# Timer install
# -------------------------------
choose_oncalendar() {
  if [[ -n "${ONCALENDAR_OVERRIDE:-}" ]]; then
    echo "${ONCALENDAR_OVERRIDE}"
    return 0
  fi
  if [[ "${TIMER_SCHEDULE}" == "weekly" ]]; then
    echo "${WEEKLY_DAY} *-*-* ${WEEKLY_TIME}:00"
  else
    # monthly
    echo "*-*-$(printf '%02d' "${MONTHLY_DOM}") ${MONTHLY_TIME}:00"
  fi
}

install_timer() {
  local mode="${1:-auto}"
  local unit="maintenance"
  local oncal; oncal="$(choose_oncalendar)"

  # Determine if we should default to installing a reboot timer on host only.
  local effective_mode="${mode}"
  if [[ "${effective_mode}" == "auto" ]]; then
    if is_vm; then effective_mode="vm"; else effective_mode="host"; fi
  fi

  echo
  echo "About to install systemd units:"
  echo "  - /etc/systemd/system/${unit}.service"
  echo "  - /etc/systemd/system/${unit}.timer"
  echo
  echo "Schedule (OnCalendar): ${oncal}"
  echo "Mode: ${effective_mode}"
  echo

  confirm_yn "Proceed with install/enable?" || { info "Skipped timer installation."; return 0; }

  local svc_tmp; svc_tmp="$(mktemp)"
  local tmr_tmp; tmr_tmp="$(mktemp)"

  cat > "${svc_tmp}" <<EOF
[Unit]
Description=Maintenance (unattended)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/maintenance --unattended
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF

  cat > "${tmr_tmp}" <<EOF
[Unit]
Description=Maintenance schedule

[Timer]
OnCalendar=${oncal}
Persistent=true

[Install]
WantedBy=timers.target
EOF

  sudo install -m 0644 -o root -g root "${svc_tmp}" "/etc/systemd/system/${unit}.service"
  sudo install -m 0644 -o root -g root "${tmr_tmp}" "/etc/systemd/system/${unit}.timer"
  rm -f "${svc_tmp}" "${tmr_tmp}"

  sudo systemctl daemon-reload
  sudo systemctl enable --now "${unit}.timer"
  info "Installed and enabled ${unit}.timer"
}

# -------------------------------
# Maintenance steps
# -------------------------------
ensure_timezone() {
  [[ -n "${TIMEZONE}" ]] || TIMEZONE="${DEFAULT_TIMEZONE}"
  sudo timedatectl set-timezone "${TIMEZONE}" >/dev/null 2>&1 || true
}

ensure_unattended_upgrades() {
  [[ "${DO_UNATTENDED_UPGRADES}" == "true" ]] || return 0
  sudo apt-get update -qq
  sudo apt-get install -y unattended-upgrades >/dev/null
  # Enable apt timers/services (Ubuntu uses systemd timers)
  sudo systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true
  sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
  # Ensure /etc/apt/apt.conf.d/20auto-upgrades is sane
  sudo tee /etc/apt/apt.conf.d/20auto-upgrades >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

apt_maintenance() {
  [[ "${DO_APT_MAINT}" == "true" ]] || return 0
  # Noninteractive reduces prompts; preserve config files sensibly.
  export DEBIAN_FRONTEND=noninteractive
  sudo apt-get update
  sudo apt-get -y full-upgrade
  sudo apt-get -y autoremove
  sudo apt-get -y autoclean
  sudo apt-get check || true
}

journal_vacuum() {
  [[ "${DO_JOURNAL_VACUUM}" == "true" ]] || return 0
  need_cmd journalctl || return 0
  sudo journalctl --vacuum-time="${JOURNAL_MAX_AGE}" >/dev/null 2>&1 || true
}

run_logrotate() {
  [[ "${DO_LOGROTATE}" == "true" ]] || return 0
  [[ -x /usr/sbin/logrotate ]] || return 0
  sudo logrotate -f /etc/logrotate.conf >/dev/null 2>&1 || true
}

run_trim() {
  case "${DO_TRIM}" in
    true) ;;
    false) return 0 ;;
    auto) need_cmd fstrim || return 0 ;;
    *) warn "Unknown DO_TRIM='${DO_TRIM}', skipping"; return 0 ;;
  esac
  sudo fstrim -av >/dev/null 2>&1 || true
}

reboot_if_required() {
  [[ "${DO_REBOOT_IF_REQUIRED}" == "true" ]] || return 0
  [[ -f /var/run/reboot-required ]] || return 0
  info "Reboot required flag present: /var/run/reboot-required"
  if [[ "${UNATTENDED}" == "true" ]]; then
    info "Unattended run: rebooting now."
    sudo systemctl reboot
  else
    confirm_yn "Reboot now?" && sudo systemctl reboot
  fi
}

scheduled_reboot_if_enabled() {
  [[ "${DO_SCHEDULED_REBOOT}" == "true" ]] || return 0
  if [[ "${UNATTENDED}" == "true" ]]; then
    info "Scheduled reboot enabled: rebooting now."
    sudo systemctl reboot
  else
    confirm_yn "Scheduled reboot enabled. Reboot now?" && sudo systemctl reboot
  fi
}

show_summary() {
  echo
  echo "========== MAINTENANCE SUMMARY =========="
  echo "Version: ${VERSION}"
  echo "Host:    $(hostname)"
  echo "User:    $(id -un)"
  echo "Virt:    $(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || echo unknown)"
  echo "Uptime:  $(uptime -p 2>/dev/null || true)"
  echo
  echo "Disk:"
  df -h / 2>/dev/null | sed 's/^/  /' || true
  echo
  echo "APT:"
  apt-cache policy 2>/dev/null | head -n 1 | sed 's/^/  /' || true
  echo "========================================="
  echo
}

usage() {
  cat <<'EOF'
Usage:
  maintenance                 # interactive run (may prompt; can save profile)
  maintenance --unattended    # unattended run (for systemd timer)
  maintenance --install       # install/enable systemd timer (uses profile/prompt)
  maintenance --self-update   # download+install latest via wget (needs UPSTREAM_URL)
  maintenance --self-update --url <raw_url> [--sha256 <sum>]
  maintenance --version

Notes:
  - For unattended runs (timer), put required settings in /etc/maintenance-profile.conf
  - This script stores NO default upstream URL; you must provide it.
EOF
}

# -------------------------------
# Arg parsing
# -------------------------------
INSTALL_TIMER="false"
DO_SELF_UPDATE="false"
SELF_URL=""
SELF_SHA=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install) INSTALL_TIMER="true"; shift ;;
    --unattended) UNATTENDED="true"; shift ;;
    --self-update) DO_SELF_UPDATE="true"; shift ;;
    --url) SELF_URL="${2:-}"; shift 2 ;;
    --sha256) SELF_SHA="${2:-}"; shift 2 ;;
    --version) echo "maintenance.sh v${VERSION}"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# -------------------------------
# Safety / sudo
# -------------------------------
if [[ "$EUID" -eq 0 ]]; then
  die "Run as a normal user with sudo, not root."
fi
sudo -v

load_profile_if_present

if [[ "${DO_SELF_UPDATE}" == "true" ]]; then
  self_update "${SELF_URL}" "${SELF_SHA}"
fi

# Interactive prompts only when not unattended
if [[ "${UNATTENDED}" != "true" ]]; then
  prompt_with_default TIMEZONE "Timezone" "${TIMEZONE:-${DEFAULT_TIMEZONE}}"

  # If no upstream URL set, optionally prompt (but do not require)
  if [[ -z "${UPSTREAM_URL:-}" ]]; then
    if confirm_yn "Configure an upstream URL now for future '--self-update'?"; then
      prompt_nonempty UPSTREAM_URL "Enter upstream raw URL for maintenance.sh"
    fi
  fi

  # Timer defaults: keep as-is unless user wants to set up the timer now
  if [[ "${INSTALL_TIMER}" == "false" ]]; then
    if confirm_yn "Install/enable a maintenance systemd timer on this machine?"; then
      INSTALL_TIMER="true"
    fi
  fi

  if [[ "${INSTALL_TIMER}" == "true" ]]; then
    prompt_with_default TIMER_MODE "Timer mode (auto|host|vm)" "${TIMER_MODE}"
    prompt_with_default TIMER_SCHEDULE "Schedule (weekly|monthly)" "${TIMER_SCHEDULE}"

    if [[ "${TIMER_SCHEDULE}" == "weekly" ]]; then
      prompt_with_default WEEKLY_DAY "Weekly day (Mon..Sun)" "${WEEKLY_DAY}"
      prompt_with_default WEEKLY_TIME "Weekly time (HH:MM)" "${WEEKLY_TIME}"
    else
      prompt_with_default MONTHLY_DOM "Monthly day-of-month (1-28 recommended)" "${MONTHLY_DOM}"
      prompt_with_default MONTHLY_TIME "Monthly time (HH:MM)" "${MONTHLY_TIME}"
    fi

    if confirm_yn "Override OnCalendar directly (advanced)?"; then
      prompt_nonempty ONCALENDAR_OVERRIDE "Enter systemd OnCalendar expression" "${ONCALENDAR_OVERRIDE:-}"
    fi

    if confirm_yn "Force a scheduled reboot when the timer runs? (host-only recommended)"; then
      DO_SCHEDULED_REBOOT="true"
    fi

    save_profile
    install_timer "${TIMER_MODE}"
    echo
    info "Timer installed. You can run 'systemctl list-timers | grep maintenance' to confirm."
  else
    # Not installing timer; still offer profile save for future unattended
    if confirm_yn "Save a maintenance profile for future unattended runs?"; then
      save_profile
    fi
  fi

  show_summary
  confirm_yn "Proceed to run maintenance now?" || { info "Aborted."; exit 0; }
else
  # Unattended: ensure timezone has some value
  [[ -n "${TIMEZONE:-}" ]] || TIMEZONE="${DEFAULT_TIMEZONE}"
fi

# -------------------------------
# Execute maintenance
# -------------------------------
ensure_timezone
ensure_unattended_upgrades
apt_maintenance
journal_vacuum
run_logrotate
run_trim

reboot_if_required
scheduled_reboot_if_enabled

info "Maintenance complete."