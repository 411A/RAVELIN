// SQLite database URL. Root uses /var/lib/ravelin/, non-root uses ~/.ravelin/.
pub const DB_URL: &str = "sqlite://ravelin.db?mode=rwc";

// Max log lines shown in the LIVE FEED panel.
pub const LOG_CAP: usize = 200;
// Max raw log lines stored per IP for the INSPECT view.
pub const HISTORY_CAP: usize = 32;
// Max distinct IPs kept in history to bound memory.
pub const IP_HISTORY_KEY_CAP: usize = 512;
// Dedup window: recent event hashes to prevent double-counting.
pub const RECENT_EVENT_CAP: usize = 20_000;
// Max suspects displayed in the SUSPECTS panel.
pub const SUSPECT_CAP: usize = 1_000;

// Score at which an IP gets auto-blocked (after MIN_AUTO_BLOCK_EVENTS).
pub const AUTO_BLOCK_SCORE_THRESHOLD: u32 = 100;
// Minimum events from one IP before auto-block eligibility.
pub const MIN_AUTO_BLOCK_EVENTS: u32 = 5;

// Score per known-vulnerable path hit (.env, .git/config, phpinfo, etc.).
pub const SCANNER_PATH_SCORE: u32 = 50;
// Unique scanner paths before immediate auto-block.
pub const SCANNER_AUTO_BLOCK_THRESHOLD: usize = 10;
// Max IPs tracked for path scanner detection.
pub const SCANNER_IP_CAP: usize = 512;

// Points added per SSH auth failure.
pub const SSH_FAILURE_SCORE: u32 = 10;
// Points added per Suricata IDS alert.
pub const IDS_ALERT_SCORE: u32 = 25;
// Points added per HTTP 4xx client error.
pub const HTTP_CLIENT_ERROR_SCORE: u32 = 2;
// Points added per HTTP 5xx server error.
pub const HTTP_SERVER_ERROR_SCORE: u32 = 1;
// Points added for an HTTP error burst pattern.
pub const HTTP_ERROR_BURST_SCORE: u32 = 18;
// Points added for an HTTP success burst (scanner fingerprint).
pub const HTTP_SUCCESS_BURST_SCORE: u32 = 8;

// Max chars for a suspect's reason string in the UI.
pub const MAX_REASON_LEN: usize = 180;
// Max chars for a single LIVE FEED log line.
pub const MAX_UI_LOG_LEN: usize = 512;
// Max chars for a raw history line in INSPECT view.
pub const MAX_HISTORY_LINE_LEN: usize = 1_024;
// Max bytes per log line read from disk (longer lines are skipped).
pub const MAX_LOG_LINE_BYTES: usize = 8_192;
// Max chars for the command input buffer.
pub const MAX_COMMAND_BUFFER_CHARS: usize = 256;

// Max distinct IPs tracked for HTTP behavior analysis.
pub const HTTP_BEHAVIOR_IP_CAP: usize = 1_024;
// Max HTTP events kept per IP for behavior scoring.
pub const HTTP_BEHAVIOR_EVENT_CAP: usize = 128;
// Sliding window (seconds) for HTTP behavior analysis.
pub const HTTP_BEHAVIOR_WINDOW_SECS: i64 = 60;
// Cooldown (seconds) between behavioral signals per IP.
pub const HTTP_BEHAVIOR_SIGNAL_COOLDOWN_SECS: i64 = 30;

// Sliding window (seconds) for detecting HTTP bursts.
pub const HTTP_BURST_WINDOW_SECS: i64 = 10;
// Min total HTTP requests in burst window to evaluate.
pub const HTTP_BURST_MIN_REQUESTS: usize = 30;
// Min errors in burst window to flag as suspicious.
pub const HTTP_ERROR_BURST_MIN_ERRORS: usize = 8;
// Min requests with zero successes to trigger immediate block.
pub const HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS: usize = 100;
// Score for a 100% failure flood (immediate block).
pub const HTTP_NO_SUCCESS_FLOOD_SCORE: u32 = 125;
// Min requests in a success-only burst to flag as scanner.
pub const HTTP_SUCCESS_BURST_MIN_REQUESTS: usize = 40;

// Min total requests to evaluate predictable cadence.
pub const HTTP_REGULAR_MIN_REQUESTS: usize = 12;
// Min avg gap (ms) between requests to consider cadence regular.
pub const HTTP_REGULAR_MIN_AVG_GAP_MS: i64 = 250;
// Max avg gap (ms) — above this is too slow to be automated.
pub const HTTP_REGULAR_MAX_AVG_GAP_MS: i64 = 1_500;
// Max jitter (ms) — below this means machine-like timing.
pub const HTTP_REGULAR_MAX_JITTER_MS: i64 = 250;

// TUI event loop poll interval (ms). Lower = more responsive, higher CPU.
pub const EVENT_POLL_INTERVAL_MS: u64 = 100;
// How often (seconds) to poll Suricata eve.json for new lines.
pub const SURICATA_POLL_SECS: u64 = 2;
// Max lines to read from Suricata per poll cycle.
pub const SURICATA_MAX_LINES_PER_POLL: usize = 1_000;
// How often (seconds) to poll syslog for new entries.
pub const SYSLOG_POLL_SECS: u64 = 5;

// Path to Suricata's JSON event log.
pub const SURICATA_EVE_PATH: &str = "/var/log/suricata/eve.json";

// ipset name used by iptables DROP rules.
pub const IPSET_NAME: &str = "sentinel_block";
// Temp path prefix for the self-check installer script.
pub const SETUP_PATH_PREFIX: &str = "/tmp/ravelin_setup_";
// Reason string stored when user manually blocks an IP.
pub const MANUAL_BLOCK_REASON: &str = "Manual Block";
// Env var to list trusted IPs (comma-separated) that should never be blocked.
pub const TRUSTED_IPS_ENV: &str = "RAVELIN_TRUSTED_IPS";
// systemd unit name for the Ravelin daemon.
pub const BACKBONE_SERVICE_NAME: &str = "ravelin.service";

// Embedded bash script run by system_self_check to install deps and set up firewall.
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
