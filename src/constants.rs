pub const DB_URL: &str = "sqlite://ravelin.db?mode=rwc";
pub const LEARNING_PERIOD_HOURS: i64 = 12;
pub const LOG_CAP: usize = 100;
pub const HISTORY_CAP: usize = 500;
pub const RECENT_EVENT_CAP: usize = 5_000;
pub const SUSPECT_CAP: usize = 2_000;
pub const AUTO_BLOCK_SCORE_THRESHOLD: u32 = 50;
pub const MAX_REASON_LEN: usize = 180;

pub const EVENT_POLL_INTERVAL_MS: u64 = 100;
pub const SURICATA_POLL_SECS: u64 = 2;
pub const SSH_POLL_SECS: u64 = 2;
pub const DOCKER_POLL_SECS: u64 = 10;
pub const DOCKER_LOG_SINCE_SECS: u64 = 15;
pub const DOCKER_LOG_TAIL: &str = "200";

pub const SURICATA_EVE_PATH: &str = "/var/log/suricata/eve.json";
pub const AUTH_LOG_PATH: &str = "/var/log/auth.log";
pub const SECURE_LOG_PATH: &str = "/var/log/secure";

pub const IPSET_NAME: &str = "sentinel_block";
pub const SETUP_PATH: &str = "/tmp/ravelin_setup.sh";
pub const MANUAL_BLOCK_REASON: &str = "Manual Block";

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

echo "[RAVELIN] System Ready."
"#;
