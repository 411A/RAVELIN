pub const DB_URL: &str = "sqlite://ravelin.db?mode=rwc";
pub const LEARNING_PERIOD_HOURS: i64 = 12;
pub const LOG_CAP: usize = 200;
pub const HISTORY_CAP: usize = 32;
pub const IP_HISTORY_KEY_CAP: usize = 512;
pub const RECENT_EVENT_CAP: usize = 20_000;
pub const SUSPECT_CAP: usize = 1_000;
pub const AUTO_BLOCK_SCORE_THRESHOLD: u32 = 100;
pub const MIN_AUTO_BLOCK_EVENTS: u32 = 5;
pub const MIN_AUTO_BLOCK_HIGH_CONFIDENCE_EVENTS: u32 = 3;
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
pub const HTTP_BEHAVIOR_EVENT_CAP: usize = 64;
pub const HTTP_BEHAVIOR_WINDOW_SECS: i64 = 60;
pub const HTTP_BEHAVIOR_SIGNAL_COOLDOWN_SECS: i64 = 30;
pub const HTTP_BURST_WINDOW_SECS: i64 = 10;
pub const HTTP_BURST_MIN_REQUESTS: usize = 30;
pub const HTTP_ERROR_BURST_MIN_ERRORS: usize = 8;
pub const HTTP_SUCCESS_BURST_MIN_REQUESTS: usize = 40;
pub const HTTP_REGULAR_MIN_REQUESTS: usize = 12;
pub const HTTP_REGULAR_MIN_AVG_GAP_MS: i64 = 250;
pub const HTTP_REGULAR_MAX_AVG_GAP_MS: i64 = 1_500;
pub const HTTP_REGULAR_MAX_JITTER_MS: i64 = 250;

pub const EVENT_POLL_INTERVAL_MS: u64 = 100;
pub const SURICATA_POLL_SECS: u64 = 2;
pub const SURICATA_MAX_LINES_PER_POLL: usize = 1_000;

pub const SURICATA_EVE_PATH: &str = "/var/log/suricata/eve.json";

pub const IPSET_NAME: &str = "sentinel_block";
pub const SETUP_PATH: &str = "/tmp/ravelin_setup.sh";
pub const MANUAL_BLOCK_REASON: &str = "Manual Block";
pub const TRUSTED_IPS_ENV: &str = "RAVELIN_TRUSTED_IPS";
pub const BACKBONE_SERVICE_NAME: &str = "ravelin.service";

pub const INSTALLER_SCRIPT: &str = r#"
#!/bin/bash
set -e

echo "[RAVELIN] Self-Check Initiated..."

if [ -f /etc/debian_version ]; then
  if ! dpkg -s suricata ipset jq >/dev/null 2>&1; then
    echo "[RAVELIN] Installing Dependencies (apt)..."
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y suricata ipset jq
  fi
elif [ -f /etc/redhat-release ]; then
  if ! rpm -q suricata ipset jq >/dev/null 2>&1; then
    echo "[RAVELIN] Installing Dependencies (yum)..."
    yum install -y epel-release
    yum install -y suricata ipset jq
  fi
fi

echo "[RAVELIN] Configuring Firewall Defense..."
ipset create sentinel_block hash:ip timeout 0 -exist 2>/dev/null

if ! iptables -C INPUT -m set --match-set sentinel_block src -j DROP 2>/dev/null; then
  iptables -I INPUT -m set --match-set sentinel_block src -j DROP
  echo "[RAVELIN] IPTables INPUT Drop Rule Injected."
fi

if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  if ! iptables -C DOCKER-USER -m set --match-set sentinel_block src -j DROP 2>/dev/null; then
    iptables -I DOCKER-USER -m set --match-set sentinel_block src -j DROP
    echo "[RAVELIN] IPTables DOCKER-USER Drop Rule Injected."
  fi
fi

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
