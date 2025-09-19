#!/usr/bin/env bash
# install.sh — Idempotent Laurel deployment for RHEL9 (and compatible)
# - Installs laurel binary, config, audit plugin, audit rules
# - Creates _laurel system user if missing
# - Installs SELinux policy if present and SELinux is enabled
# - restorecon labels
# - Loads audit rules (augenrules --load)
# - HUPs auditd safely
set -euo pipefail
umask 022

log(){ printf '[+] %s\n' "$*" >&2; }
warn(){ printf '[!] %s\n' "$*" >&2; }
die(){ printf '[x] %s\n' "$*" >&2; exit 1; }

require_root(){
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root."
}

have(){ command -v "$1" >/dev/null 2>&1; }

SELINUX_ENABLED=0
if have selinuxenabled && selinuxenabled; then
  SELINUX_ENABLED=1
fi

# Filled by builder at packaging time:
LAUREL_EXPECTED_SHA256="cb80a29c9150874ce77abdf4c07e0303c0031fcdb9dc682e726139ab79c014aa"

DIST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

main(){
  require_root

  # 1) Ensure _laurel system user
  if ! id -u _laurel >/dev/null 2>&1; then
    log "Creating system user _laurel..."
    useradd --system --home-dir /var/log/laurel --create-home _laurel
  else
    log "System user _laurel already exists."
  fi

  # 2) Directories
  install -d -m 0750 -o _laurel -g _laurel /var/log/laurel
  install -d -m 0750 -o _laurel -g root     /etc/laurel
  install -d -m 0755 -o root    -g root     /etc/audit/plugins.d
  install -d -m 0755 -o root    -g root     /etc/audit/rules.d

  # 3) Install laurel binary (verify hash if provided)
  if [[ -f "$DIST_DIR/usr/local/sbin/laurel" ]]; then
    install -D -m 0755 -o root -g root "$DIST_DIR/usr/local/sbin/laurel" /usr/local/sbin/laurel
    if have sha256sum && [[ "$LAUREL_EXPECTED_SHA256" != "cb80a29c9150874ce77abdf4c07e0303c0031fcdb9dc682e726139ab79c014aa" ]]; then
      actual="$(sha256sum /usr/local/sbin/laurel | awk '{print $1}')"
      if [[ "$actual" != "$LAUREL_EXPECTED_SHA256" ]]; then
        warn "SHA256 mismatch for /usr/local/sbin/laurel (expected $LAUREL_EXPECTED_SHA256, got $actual)."
        warn "Proceeding, but you should investigate."
      else
        log "Laurel binary SHA256 verified."
      fi
    fi
  else
    die "Missing payload: $DIST_DIR/usr/local/sbin/laurel"
  fi

  # 4) Config + plugin
  if [[ -f "$DIST_DIR/etc/laurel/config.toml" ]]; then
    install -D -m 0640 -o _laurel -g _laurel "$DIST_DIR/etc/laurel/config.toml" /etc/laurel/config.toml
  else
    warn "Missing payload: etc/laurel/config.toml (skipping)"
  fi

  if [[ -f "$DIST_DIR/etc/audit/plugins.d/laurel.conf" ]]; then
    install -D -m 0640 -o root -g root "$DIST_DIR/etc/audit/plugins.d/laurel.conf" /etc/audit/plugins.d/laurel.conf
  else
    warn "Missing payload: etc/audit/plugins.d/laurel.conf (skipping)"
  fi

  # 5) Audit rules
  shopt -s nullglob
  for rf in "$DIST_DIR"/etc/audit/rules.d/*.rules; do
    base="$(basename "$rf")"
    install -D -m 0640 -o root -g root "$rf" "/etc/audit/rules.d/$base"
  done
  shopt -u nullglob

  # 6) SELinux policy (if packed and SELinux enabled)
  if (( SELINUX_ENABLED == 1 )); then
    if [[ -f "$DIST_DIR/selinux/laurel.pp" ]]; then
      if have semodule; then
        log "Installing SELinux module laurel.pp ..."
        semodule -i "$DIST_DIR/selinux/laurel.pp"
      else
        warn "semodule not found; cannot install SELinux policy."
      fi
    else
      log "No selinux/laurel.pp in dist; skipping SELinux module."
    fi
    # Apply contexts if SELinux present (policy may set custom types)
    if have restorecon; then
      restorecon -v -R -F /usr/local/sbin/laurel /etc/laurel /var/log/laurel /etc/audit/plugins.d/laurel.conf || true
    fi
  fi

  # 7) Ensure auditd is running
  if have systemctl; then
    if ! systemctl is-active --quiet auditd; then
      log "Starting auditd..."
      systemctl enable --now auditd || true
    fi
  fi

  # 8) Load audit rules (compile with augenrules -> push with auditctl)
  if have augenrules; then
    log "Loading audit rules with augenrules..."
    if ! augenrules --load; then
      warn "augenrules --load failed; attempting to fall back to auditctl -R"
      if [[ -f /etc/audit/audit.rules ]]; then
        auditctl -R /etc/audit/audit.rules || warn "auditctl -R also failed."
      fi
    fi
  else
    warn "augenrules not found; skipping rules load."
  fi

  # 9) HUP auditd to re-read plugin configs
  if have systemctl; then
    log "Sending HUP to auditd..."
    systemctl kill -s HUP auditd || true
  fi
  if pidof auditd >/dev/null 2>&1; then
    kill -HUP "$(pidof auditd)" || true
  fi

  # 10) Quick health info
  if have auditctl; then
    auditctl -s || true
    auditctl -l | head -n 50 || true
  fi

  log "Laurel deploy complete."
}

main "$@"
