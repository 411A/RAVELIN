pub const DB_URL: &str = "sqlite://ravelin.db?mode=rwc";
pub const LOG_CAP: usize = 200;
pub const HISTORY_CAP: usize = 32;
pub const IP_HISTORY_KEY_CAP: usize = 512;
pub const RECENT_EVENT_CAP: usize = 20_000;
pub const SUSPECT_CAP: usize = 1_000;
pub const AUTO_BLOCK_SCORE_THRESHOLD: u32 = 100;
pub const MIN_AUTO_BLOCK_EVENTS: u32 = 5;
pub const SSH_FAILURE_SCORE: u32 = 10;
pub const IDS_ALERT_SCORE: u32 = 25;
pub const HTTP_CLIENT_ERROR_SCORE: u32 = 2;
pub const HTTP_SERVER_ERROR_SCORE: u32 = 1;
pub const HTTP_ERROR_BURST_SCORE: u32 = 18;
pub const HTTP_SUCCESS_BURST_SCORE: u32 = 8;
pub const MAX_REASON_LEN: usize = 180;
pub const MAX_UI_LOG_LEN: usize = 512;
pub const MAX_HISTORY_LINE_LEN: usize = 1_024;
pub const MAX_LOG_LINE_BYTES: usize = 8_192;
pub const MAX_COMMAND_BUFFER_CHARS: usize = 256;
pub const HTTP_BEHAVIOR_IP_CAP: usize = 1_024;
pub const HTTP_BEHAVIOR_EVENT_CAP: usize = 128;
pub const HTTP_BEHAVIOR_WINDOW_SECS: i64 = 60;
pub const HTTP_BEHAVIOR_SIGNAL_COOLDOWN_SECS: i64 = 30;
pub const HTTP_BURST_WINDOW_SECS: i64 = 10;
pub const HTTP_BURST_MIN_REQUESTS: usize = 30;
pub const HTTP_ERROR_BURST_MIN_ERRORS: usize = 8;
pub const HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS: usize = 100;
pub const HTTP_NO_SUCCESS_FLOOD_SCORE: u32 = 125;
pub const HTTP_SUCCESS_BURST_MIN_REQUESTS: usize = 40;
pub const HTTP_REGULAR_MIN_REQUESTS: usize = 12;
pub const HTTP_REGULAR_MIN_AVG_GAP_MS: i64 = 250;
pub const HTTP_REGULAR_MAX_AVG_GAP_MS: i64 = 1_500;
pub const HTTP_REGULAR_MAX_JITTER_MS: i64 = 250;

pub const EVENT_POLL_INTERVAL_MS: u64 = 100;
pub const SURICATA_POLL_SECS: u64 = 2;
pub const SURICATA_MAX_LINES_PER_POLL: usize = 1_000;
pub const SYSLOG_POLL_SECS: u64 = 5;

pub const SURICATA_EVE_PATH: &str = "/var/log/suricata/eve.json";

pub const IPSET_NAME: &str = "sentinel_block";
pub const SETUP_PATH_PREFIX: &str = "/tmp/ravelin_setup_";
pub const MANUAL_BLOCK_REASON: &str = "Manual Block";
pub const TRUSTED_IPS_ENV: &str = "RAVELIN_TRUSTED_IPS";
pub const BACKBONE_SERVICE_NAME: &str = "ravelin.service";

pub const INSTALLER_SCRIPT: &str = r#"#!/bin/bash
set -euo pipefail

echo "[RAVELIN] Self-Check Initiated..."

if [ "$(id -u)" -ne 0 ]; then
  echo "[RAVELIN] Error: self-check must run as root." >&2
  exit 1
fi

if [ -f /etc/debian_version ]; then
  missing=()
  for pkg in suricata ipset jq iptables; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "[RAVELIN] Installing Dependencies (apt)..."
    apt-get update -qq || echo "[RAVELIN] Warning: apt update reported repository warnings; using available package indexes." >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
  fi
elif [ -f /etc/redhat-release ]; then
  missing=()
  for pkg in suricata ipset jq iptables; do
    if ! rpm -q "$pkg" >/dev/null 2>&1; then
      missing+=("$pkg")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "[RAVELIN] Installing Dependencies (yum)..."
    yum install -y epel-release || true
    yum install -y "${missing[@]}"
  fi
fi

echo "[RAVELIN] Configuring Firewall Defense..."
ipset create sentinel_block hash:ip timeout 0 -exist 2>/dev/null || true

ensure_drop_rule() {
  chain="$1"
  if ! iptables -L "$chain" -n >/dev/null 2>&1; then
    return
  fi

  while iptables -D "$chain" -m set --match-set sentinel_block src -j DROP 2>/dev/null; do
    true
  done

  iptables -I "$chain" 1 -m set --match-set sentinel_block src -j DROP
  echo "[RAVELIN] IPTables $chain Drop Rule Ready."
}

ensure_drop_rule INPUT
ensure_drop_rule DOCKER-USER

echo "[RAVELIN] Tuning Network Stack..."
sysctl -w net.core.netdev_max_backlog=500000 >/dev/null || true
sysctl -w net.core.rmem_max=134217728 >/dev/null || true

echo "[RAVELIN] Bounding Suricata log storage..."
cat >/etc/logrotate.d/ravelin-suricata <<'LOGROTATE'
/var/log/suricata/eve.json /var/log/suricata/fast.log /var/log/suricata/stats.log {
  size 64M
  rotate 4
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
LOGROTATE

echo "[RAVELIN] System Ready."
"#;
