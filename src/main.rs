// main.rs
use anyhow::Result;
use chrono::{DateTime, Utc};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use lazy_static::lazy_static;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use regex::Regex;
use sqlx::{sqlite::SqlitePoolOptions, Pool, Row, Sqlite};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, Permissions},
    io::{self, Stdout},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    sync::Arc,
};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
    sync::Mutex,
    time,
};

// --- CONFIGURATION ---
const DB_URL: &str = "sqlite://ravelin.db?mode=rwc";
const LEARNING_PERIOD_HOURS: i64 = 12;
const LOG_CAP: usize = 100;
const HISTORY_CAP: usize = 500; // per-ip history cap

// Auto-Block Configuration
// Note: These thresholds apply to suspicious events (SSH failures, HTTP errors, IDS alerts), not all requests
const AUTO_BLOCK_SUSPICIOUS_EVENTS_THRESHOLD: u32 = 200;  // Minimum suspicious events before checking for auto-block
const AUTO_BLOCK_FAILURE_PERCENT: u32 = 95;       // Percentage of failed suspicious events required (95% = 95)

// --- EMBEDDED INSTALLER SCRIPT ---
const INSTALLER_SCRIPT: &str = r#"
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
# Create the hash:ip set
ipset create sentinel_block hash:ip timeout 0 -exist 2>/dev/null

# 1. Protect the Host (INPUT Chain)
if ! iptables -C INPUT -m set --match-set sentinel_block src -j DROP 2>/dev/null; then
  iptables -I INPUT -m set --match-set sentinel_block src -j DROP
  echo "[RAVELIN] IPTables INPUT Drop Rule Injected."
fi

# 2. Protect Docker Containers (DOCKER-USER Chain)
# Check if DOCKER-USER chain exists (Docker installed/running)
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  if ! iptables -C DOCKER-USER -m set --match-set sentinel_block src -j DROP 2>/dev/null; then
    iptables -I DOCKER-USER -m set --match-set sentinel_block src -j DROP
    echo "[RAVELIN] IPTables DOCKER-USER Drop Rule Injected."
  fi
fi

echo "[RAVELIN] Tuning Network Stack..."
sysctl -w net.core.netdev_max_backlog=500000 >/dev/null
sysctl -w net.core.rmem_max=134217728 >/dev/null

echo "[RAVELIN] System Ready."
"#;

// --- REGEX INTELLIGENCE ---
lazy_static! {
    static ref RE_SSH_SUCCESS: Regex = Regex::new(
        r"Accepted (?:publickey|password) for .* from (\d+\.\d+\.\d+\.\d+)"
    ).unwrap();
    static ref RE_SSH_FAIL: Regex = Regex::new(
        // Added "Connection closed" and "Received disconnect" to catch early scanners
        r"(?i)(?:Failed password|Invalid user|authentication failure|Disconnected from authenticating user|Connection closed by|Received disconnect from).*?(\d+\.\d+\.\d+\.\d+)"
    ).unwrap();
    static ref RE_HTTP_ERROR: Regex = Regex::new(
        r#"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] ".*?" [45]\d{2}"#
    ).unwrap();
    static ref RE_IPV4: Regex = Regex::new(
        r"(\d+\.\d+\.\d+\.\d+)"
    ).unwrap();
}

// --- DATA STRUCTURES ---
#[derive(Clone, Debug)]
struct Suspect {
    ip: String,
    reason: String,
    score: u32,
    last_seen: DateTime<Utc>,
    source_type: String,
}

#[derive(Clone, Debug)]
struct RequestStats {
    suspicious_events_total: u32,  // Only counts events matched by Regex (SSH Fail, IDS, etc)
    confirmed_failures: u32,       // Counts specific "high confidence" failure keywords
    last_updated: DateTime<Utc>,
}

// --- LOCAL IP DETECTION ---
fn get_local_ips() -> HashSet<String> {
    let mut local_ips = HashSet::new();
    
    // Add localhost
    local_ips.insert("127.0.0.1".to_string());
    local_ips.insert("::1".to_string());
    
    // Try to get all interface IPs via hostname -I command
    if let Ok(output) = Command::new("hostname").arg("-I").output() {
        let ips_str = String::from_utf8_lossy(&output.stdout);
        for ip in ips_str.split_whitespace() {
            if !ip.is_empty() && ip.contains('.') {
                local_ips.insert(ip.to_string());
            }
        }
    }
    
    // Fallback: try ip addr show
    if local_ips.len() <= 1 {
        if let Ok(output) = Command::new("ip").args(["addr", "show"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("inet ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip_part = parts[1].split('/').next().unwrap_or("");
                        if !ip_part.is_empty() && ip_part != "127.0.0.1" {
                            local_ips.insert(ip_part.to_string());
                        }
                    }
                }
            }
        }
    }
    
    // Get public IP using multiple services with fallback
    // List of reliable public IP services
    let ip_services = [
        "ifconfig.me",
        "icanhazip.com",
        "checkip.amazonaws.com",
        "ipecho.net/plain",
        "ident.me",
        "ipinfo.io/ip",
        "api.ipify.org",
    ];
    
    for service in &ip_services {
        let _ = Command::new("timeout")
            .args(["3", "curl", "-s", service])
            .output()
            .map(|output| {
                let public_ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !public_ip.is_empty() && public_ip.contains('.') {
                    local_ips.insert(public_ip);
                }
            });
        
        // If we got a public IP, we can stop trying
        if local_ips.len() > 2 {
            break;
        }
    }
    
    local_ips
}

#[derive(Clone, Debug, sqlx::FromRow)]
struct BlockedIp {
    ip: String,
    blocked_at: DateTime<Utc>,
    reason: String,
}

#[derive(Clone)]
struct AppState {
    logs: Vec<String>,                       // Top Window (chronological oldest -> newest)
    suspects: Vec<Suspect>,                  // Mid-Left Window
    blocked: Vec<BlockedIp>,                 // Mid-Right Window
    whitelisted_dynamic: HashSet<String>,    // Dynamic Friendly IPs
    local_ips: HashSet<String>,              // Local server IPs (to exclude from suspects)
    input_buffer: String,                    // Bottom Window (command mode)
    input_mode: InputMode,
    selected_suspect_idx: usize,
    selected_block_idx: usize,
    active_window: ActiveWindow,
    start_time: DateTime<Utc>,
    
    // scroll offsets and history
    logs_scroll: usize,                      // 0 = show newest
    suspects_scroll: usize,
    blocked_scroll: usize,
    ip_history: HashMap<String, Vec<String>>, // full raw lines per ip (for inspect)
    
    detail_open: bool,
    detail_ip: Option<String>,
    detail_scroll: usize,
    detail_scroll_x: usize,
    
    search_filter: Option<String>,
    request_stats: HashMap<String, RequestStats>, // Track requests per IP for auto-blocking
}

#[derive(Clone, PartialEq)]
enum InputMode {
    Normal,
    Command,
}

#[derive(Clone, PartialEq)]
enum ActiveWindow {
    Suspects,
    Blocked,
}

// --- SYSTEM SETUP ENGINE ---
fn system_self_check() -> Result<()> {
    // Check if critical tools exist
    let has_ipset = Command::new("which").arg("ipset").output()?.status.success();
    let has_suricata = Command::new("which").arg("suricata").output()?.status.success();

    if !has_ipset || !has_suricata {
        println!("⚠️ Dependencies missing or updates needed. Running embedded installer script (Requires Sudo)...");
        let setup_path = "/tmp/ravelin_setup.sh";
        fs::write(setup_path, INSTALLER_SCRIPT)?;
        fs::set_permissions(setup_path, Permissions::from_mode(0o755))?;

        let status = Command::new("sudo").arg(setup_path).status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("Installer script failed."));
        }
    } else {
        // Run installer anyway to ensure IPTables rules are injected even if dependencies exist
        let setup_path = "/tmp/ravelin_setup.sh";
        fs::write(setup_path, INSTALLER_SCRIPT)?;
        fs::set_permissions(setup_path, Permissions::from_mode(0o755))?;
        let _ = Command::new("sudo").arg(setup_path).status();
    }
    Ok(())
}

// --- DATABASE LAYER ---
async fn init_db() -> Result<Pool<Sqlite>> {
    let pool = SqlitePoolOptions::new().max_connections(5).connect(DB_URL).await?;

    // blocked_ips
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at DATETIME,
            reason TEXT
        )",
    )
    .execute(&pool)
    .await?;

    // system_state for persistent values
    sqlx::query("CREATE TABLE IF NOT EXISTS system_state (key TEXT PRIMARY KEY, value TEXT)")
        .execute(&pool)
        .await?;

    Ok(pool)
}

/// Retrieves persisted start_time (RFC3339), or writes now and returns it.
async fn get_start_time(pool: &Pool<Sqlite>) -> Result<DateTime<Utc>> {
    let row = sqlx::query("SELECT value FROM system_state WHERE key = 'start_time'")
        .fetch_optional(pool)
        .await?;

    if let Some(r) = row {
        let ts_str: String = r.try_get(0)?;
        if let Ok(ts) = DateTime::parse_from_rfc3339(&ts_str) {
            return Ok(ts.with_timezone(&Utc));
        }
    }

    let now = Utc::now();
    let _ = sqlx::query("INSERT OR IGNORE INTO system_state (key, value) VALUES ('start_time', ?)")
        .bind(now.to_rfc3339())
        .execute(pool)
        .await?;

    Ok(now)
}

// --- LOG HARVESTER ENGINE ---
async fn harvest_logs(app_state: Arc<Mutex<AppState>>, _pool: Pool<Sqlite>) {
    // 1. Suricata watcher
    {
        let app_clone = app_state.clone();
        tokio::spawn(async move {
            let file_path = "/var/log/suricata/eve.json";
            loop {
                if let Ok(f) = File::open(file_path).await {
                    let reader = BufReader::new(f);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        // lightweight filter
                        if line.contains("alert") || line.contains("http") {
                            process_log_line(&line, "Suricata", &app_clone).await;
                        }
                    }
                }
                time::sleep(time::Duration::from_secs(5)).await;
            }
        });
    }

    // 2. SSH watcher
    {
        let app_clone = app_state.clone();
        tokio::spawn(async move {
            let path = if Path::new("/var/log/auth.log").exists() {
                "/var/log/auth.log"
            } else {
                "/var/log/secure"
            };
            loop {
                if let Ok(f) = File::open(path).await {
                    let reader = BufReader::new(f);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        process_log_line(&line, "SSH", &app_clone).await;
                    }
                }
                time::sleep(time::Duration::from_secs(3)).await;
            }
        });
    }

    // 3. Docker harvester
    {
        let app_clone = app_state.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(output) = Command::new("docker").arg("ps").arg("-q").output() {
                    let ids = String::from_utf8_lossy(&output.stdout).to_string();
                    for id in ids.lines() {
                        // tail last 20 lines
                        if let Ok(logs) =
                            Command::new("docker").args(["logs", "--tail", "20", id]).output()
                        {
                            let log_str = String::from_utf8_lossy(&logs.stdout);
                            for line in log_str.lines() {
                                process_log_line(line, &format!("Docker-{}", &id[0..4]), &app_clone)
                                    .await;
                            }
                        }
                    }
                }
                time::sleep(time::Duration::from_secs(10)).await;
            }
        });
    }
}

// --- CORE INTELLIGENCE LOGIC ---
async fn process_log_line(line: &str, source: &str, state: &Arc<Mutex<AppState>>) {
    let mut suspect_ip: Option<String> = None;
    let mut reason = String::new();
    let mut ips_found: Vec<String> = vec![];

    // collect ips referenced in the line
    for caps in RE_IPV4.captures_iter(line) {
        if let Some(m) = caps.get(1) {
            ips_found.push(m.as_str().to_string());
        }
    }

    // parse specific patterns
    if let Some(caps) = RE_SSH_SUCCESS.captures(line) {
        if let Some(ip) = caps.get(1) {
            reason = "SSH Success".to_string();
            ips_found.push(ip.as_str().to_string());
        }
    }
    if let Some(caps) = RE_SSH_FAIL.captures(line) {
        suspect_ip = Some(caps.get(1).unwrap().as_str().to_string());
        reason = "SSH Auth Failure".to_string();
    } else if let Some(caps) = RE_HTTP_ERROR.captures(line) {
        suspect_ip = Some(caps.get(1).unwrap().as_str().to_string());
        reason = "HTTP 4xx/5xx Error".to_string();
    } else if source == "Suricata" && line.contains("alert") {
        if let Some(caps) = RE_IPV4.captures(line) {
            suspect_ip = Some(caps.get(1).unwrap().as_str().to_string());
            reason = "IDS Alert".to_string();
        }
    }

    {
        let mut app = state.lock().await;

        for ip in &ips_found {
            let v = app.ip_history.entry(ip.clone()).or_insert_with(Vec::new);
            v.push(format!("[{}] {}", source, line));
            if v.len() > HISTORY_CAP {
                v.drain(0..(v.len() - HISTORY_CAP));
            }
        }

        if reason == "SSH Success" {
            if let Some(ip_str) = ips_found.last() {
                app.whitelisted_dynamic.insert(ip_str.clone());
                app.logs
                    .push(format!("🟢 [SAFE] {} Authenticated successfully via SSH", ip_str));
                app.suspects.retain(|s| s.ip != *ip_str);
                if app.logs.len() > LOG_CAP {
                    app.logs.remove(0);
                }
            }
            return;
        }

        if let Some(ip) = suspect_ip {
            // Skip local/server IPs
            if app.local_ips.contains(&ip) {
                return;
            }
            
            if app.whitelisted_dynamic.contains(&ip) {
                return;
            }

            // If we already blocked them, don't re-add them to suspects!
            if app.blocked.iter().any(|b| b.ip == ip) {
                return;
            }

            // --- SMART WEIGHTING SYSTEM ---
            // SSH is high risk, give it 20 points. (10 attempts = 200 score = BLOCK)
            // IDS is medium risk, give it 10 points. (20 alerts = 200 score = BLOCK)
            // HTTP is low risk, give it 1 point. (200 errors = 200 score = BLOCK)
            let weight: u32 = if reason.contains("SSH") {
                20 
            } else if reason.contains("IDS") || source == "Suricata" {
                10
            } else {
                1
            };

            let log_entry = format!("⚠️ [{}] {} | {} (Severity: {})", source, ip, reason, weight);
            
            // Log de-duplication
            let should_push = match app.logs.last() {
                Some(last) => last != &log_entry,
                None => true,
            };

            if should_push {
                app.logs.push(log_entry.clone());
                if app.logs.len() > LOG_CAP {
                    app.logs.remove(0);
                }
            }

            // Track request statistics for auto-blocking
            let stats = app.request_stats.entry(ip.clone()).or_insert_with(|| RequestStats {
                suspicious_events_total: 0,
                confirmed_failures: 0,
                last_updated: Utc::now(),
            });

            // Add WEIGHT instead of just 1
            stats.suspicious_events_total += weight;
            stats.last_updated = Utc::now();
            
            // Determine if this is a "High Confidence" failure
            let is_failure = reason.contains("Failure") 
                || reason.contains("Fail") 
                || reason.contains("Error") 
                || reason.contains("Invalid")
                || reason.contains("Alert");
                
            if is_failure {
                // If it failed, it failed with high severity
                stats.confirmed_failures += weight;
            }

            // Update UI Suspect List
            if let Some(existing) = app.suspects.iter_mut().find(|s| s.ip == ip) {
                existing.score += weight; // Update Score by weight
                existing.last_seen = Utc::now();
                existing.reason = reason.clone();
                existing.source_type = source.to_string();
            } else {
                app.suspects.push(Suspect {
                    ip: ip.clone(),
                    reason: reason.clone(),
                    score: weight, // Start with weight
                    last_seen: Utc::now(),
                    source_type: source.to_string(),
                });
            }

            app.suspects.sort_by(|a, b| b.score.cmp(&a.score));
            let suspect_len = app.suspects.len();
            if suspect_len > 2000 {
                app.suspects.drain(2000..);
            }
        }
    }
}

// --- ACTIONS ---
async fn block_ip(ip: String, display_reason: String, db_reason: String, pool: &Pool<Sqlite>, state: &Arc<Mutex<AppState>>) -> Result<()> {
    // Ensure ipset exists (installer should create it), then add IP
    // Note: We don't need to re-run iptables -I here because the rule points to the set.
    // As long as the IP is in the set, the existing iptables rule will drop it.
    let _ = Command::new("sudo")
        .args(["ipset", "create", "sentinel_block", "hash:ip", "timeout", "0", "-exist"])
        .output();
        
    Command::new("sudo")
        .args(["ipset", "add", "sentinel_block", &ip, "-exist"])
        .output()?;

    sqlx::query("INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason) VALUES (?, ?, ?)")
        .bind(&ip)
        .bind(Utc::now())
        .bind(&db_reason)
        .execute(pool)
        .await?;

    let mut app = state.lock().await;
    app.suspects.retain(|s| s.ip != ip);
    app.request_stats.remove(&ip); // Clean up request stats for blocked IP
    app.blocked.push(BlockedIp {
        ip: ip.clone(),
        blocked_at: Utc::now(),
        reason: display_reason.clone(),
    });

    Ok(())
}

async fn unblock_ip(ip: String, pool: &Pool<Sqlite>, state: &Arc<Mutex<AppState>>) -> Result<()> {
    Command::new("sudo").args(["ipset", "del", "sentinel_block", &ip]).output()?;

    sqlx::query("DELETE FROM blocked_ips WHERE ip = ?")
        .bind(&ip)
        .execute(pool)
        .await?;

    let mut app = state.lock().await;
    app.blocked.retain(|b| b.ip != ip);

    Ok(())
}

/// Normalizes the reason text for display purposes.
/// Extracts "Auto Block" from detailed reason strings like "Auto Block: >200 suspicious events with >95% failure rate".
fn normalize_reason_for_display(reason: &str) -> String {
    if reason.starts_with("Auto Block:") {
        "Auto Block".to_string()
    } else {
        reason.to_string()
    }
}

/// Checks if an IP should be auto-blocked based on request rate and failure percentage.
/// Returns Ok(true) if the IP was blocked, Ok(false) if it shouldn't be blocked, or Err if blocking failed.
async fn check_auto_block(ip: String, pool: &Pool<Sqlite>, state: &Arc<Mutex<AppState>>) -> Result<bool> {
    let should_block = {
        let app = state.lock().await;
        
        // 1. Safety Whitelist (Smart System)
        if app.whitelisted_dynamic.contains(&ip) {
            return Ok(false);
        }
        
        // 2. Already Blocked?
        if app.blocked.iter().any(|b| b.ip == ip) {
            return Ok(false);
        }
        
        // 3. Double Verification Logic
        if let Some(stats) = app.request_stats.get(&ip) {
            // CHECK A: Quantity (Do we have enough data?)
            if stats.suspicious_events_total >= AUTO_BLOCK_SUSPICIOUS_EVENTS_THRESHOLD {
                
                // CHECK B: Quality (Is the "Failure Percentage" high enough?)
                // This uses your AUTO_BLOCK_FAILURE_PERCENT config!
                let failure_percent = if stats.suspicious_events_total > 0 {
                    (stats.confirmed_failures * 100) / stats.suspicious_events_total
                } else {
                    0
                };

                // Only block if BOTH quantity and quality thresholds are met
                failure_percent >= AUTO_BLOCK_FAILURE_PERCENT
            } else {
                false
            }
        } else {
            false
        }
    };
    
    if should_block {
        let display_reason = "Auto Block".to_string();
        let db_reason = format!(
            "Auto Block: >{} suspicious events with >{}% failure rate", 
            AUTO_BLOCK_SUSPICIOUS_EVENTS_THRESHOLD, 
            AUTO_BLOCK_FAILURE_PERCENT
        );
        block_ip(ip, display_reason, db_reason, pool, state).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// --- UI ---
fn ui_render(f: &mut Frame, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30), // logs
            Constraint::Percentage(60), // lists or detail
            Constraint::Length(3),      // command
        ])
        .split(f.area());

    let mid_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    // --- LOGS ---
    let log_visible = chunks[0].height.saturating_sub(2) as usize;
    let total_logs = app.logs.len();
    let end = total_logs.saturating_sub(app.logs_scroll);
    let start = if end > log_visible { end - log_visible } else { 0 };

    let visible_logs = app
        .logs
        .get(start..end)
        .unwrap_or(&[])
        .iter()
        .rev()
        .map(|line| ListItem::new(Line::from(line.as_str())))
        .collect::<Vec<_>>();

    let logs_title = format!(" 📡 LIVE FEED (Docker/Syslog/Suricata)");
    let logs_widget = List::new(visible_logs).block(Block::default().borders(Borders::ALL).title(logs_title));
    f.render_widget(logs_widget, chunks[0]);

    // --- MIDDLE AREA ---
    if app.detail_open {
        let detail_rect = chunks[1];
        let mut lines: Vec<ListItem> = vec![];
        if let Some(ip) = &app.detail_ip {
            let history = app.ip_history.get(ip).map(|v| v.as_slice()).unwrap_or(&[]);
            let total = history.len();
            let visible = detail_rect.height.saturating_sub(2) as usize;

            let start = app.detail_scroll.min(total.saturating_sub(1));
            let end = (start + visible).min(total);

            for line in &history[start..end] {
                let raw_str = line.as_str();
                let skip_amount = app.detail_scroll_x.min(raw_str.len());
                let content = &raw_str[skip_amount..];
                lines.push(ListItem::new(Line::from(content)));
            }
            let title = format!(" 🔍 INSPECT: {} | Scroll: {}/{} | < > Horz ", ip, start, total);
            let list = List::new(lines).block(Block::default().borders(Borders::ALL).title(title));
            f.render_widget(list, detail_rect);
        } else {
            let empty = Paragraph::new("No history for selected IP").block(Block::default().borders(Borders::ALL).title(" DETAIL "));
            f.render_widget(empty, detail_rect);
        }
    } else {
        // Suspects
        let left = mid_chunks[0];
        let mid_visible = left.height.saturating_sub(2) as usize;

        let filtered: Vec<&Suspect> = if let Some(filter) = &app.search_filter {
            let f_low = filter.to_lowercase();
            app.suspects
                .iter()
                .filter(|s| {
                    s.ip.to_lowercase().contains(&f_low) || s.reason.to_lowercase().contains(&f_low) || s.source_type.to_lowercase().contains(&f_low)
                })
                .collect()
        } else {
            app.suspects.iter().collect()
        };

        let total_filtered = filtered.len();
        let start = app.suspects_scroll.min(total_filtered);
        let end = usize::min(start + mid_visible, total_filtered);

        let suspects: Vec<ListItem> = filtered[start..end]
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let global_idx = start + i;
                let style = if global_idx == app.selected_suspect_idx && app.active_window == ActiveWindow::Suspects {
                    Style::default().fg(Color::Black).bg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Red)
                };
                ListItem::new(format!("{} | [{}] {} | Score: {} | {}", global_idx + 1, s.source_type, s.ip, s.score, s.reason)).style(style)
            })
            .collect();
        let suspects_widget = List::new(suspects).block(Block::default().borders(Borders::ALL).title(" 🕵️ SUSPECTS (Enter: Block) "));
        f.render_widget(suspects_widget, left);

        // Blocked
        let right = mid_chunks[1];
        let right_visible = right.height.saturating_sub(2) as usize;
        let total_blocked = app.blocked.len();
        let bstart = app.blocked_scroll.min(total_blocked);
        let bend = usize::min(bstart + right_visible, total_blocked);

        let blocked: Vec<ListItem> = app.blocked[bstart..bend]
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let global_idx = bstart + i;
                let style = if global_idx == app.selected_block_idx && app.active_window == ActiveWindow::Blocked {
                    Style::default().fg(Color::Black).bg(Color::Green)
                } else {
                    Style::default().fg(Color::Gray)
                };
                ListItem::new(format!("{} | {} | {} | Since: {}", global_idx + 1, b.ip, b.reason, b.blocked_at.format("%Y-%m-%d %H:%M:%S"))).style(style)
            })
            .collect();
        let blocked_widget = List::new(blocked).block(Block::default().borders(Borders::ALL).title(" 🚫 BLOCKED (Enter: Unblock) "));
        f.render_widget(blocked_widget, right);
    }

    // Bottom
    let time_alive = Utc::now().signed_duration_since(app.start_time).num_hours();
    let mode_text = if time_alive < LEARNING_PERIOD_HOURS {
        format!("🛡️ LEARNING MODE ({}h remaining) - No Auto-Block", LEARNING_PERIOD_HOURS - time_alive)
    } else {
        "⚔️ ACTIVE DEFENSE MODE".to_string()
    };

    let input_text = if app.input_mode == InputMode::Command {
        app.input_buffer.clone()
    } else {
        format!("{} | [TAB] Switch Lists | [j/k] Move | [PgUp/PgDn] Scroll | [i] Inspect | [/] Search | [Q] Quit | [:] Cmd Mode", mode_text)
    };

    let cmd_widget = Paragraph::new(input_text)
        .style(Style::default().fg(Color::Cyan))
        .block(Block::default().borders(Borders::ALL).title(" COMMAND CENTER "));
    f.render_widget(cmd_widget, chunks[2]);
}

// --- RUN UI ---
async fn run_ui(terminal: &mut Terminal<CrosstermBackend<Stdout>>, pool: Pool<Sqlite>, state: Arc<Mutex<AppState>>) -> Result<()> {
    // Spawn auto-block task in the background (doesn't block UI)
    {
        let pool_clone = pool.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(time::Duration::from_secs(5));
            loop {
                interval.tick().await; // Wait for next 5-second interval
                
                let app = state_clone.lock().await;
                let time_alive = Utc::now().signed_duration_since(app.start_time).num_hours();
                drop(app);
                
                // Only auto-block after learning period
                if time_alive >= LEARNING_PERIOD_HOURS {
                    let mut ips_to_check: Vec<String> = Vec::new();
                    {
                        let app = state_clone.lock().await;
                        for (ip, stats) in &app.request_stats {
                            // Only check IPs that have reached the threshold
                            if stats.suspicious_events_total >= AUTO_BLOCK_SUSPICIOUS_EVENTS_THRESHOLD {
                                ips_to_check.push(ip.clone());
                            }
                        }
                    }
                    
                    for ip in ips_to_check {
                        match check_auto_block(ip.clone(), &pool_clone, &state_clone).await {
                            Ok(blocked) => {
                                if blocked {
                                    let mut app = state_clone.lock().await;
                                    app.logs.push(format!("🔒 [AUTO-BLOCK] {} blocked automatically", ip));
                                    if app.logs.len() > LOG_CAP {
                                        app.logs.remove(0);
                                    }
                                }
                            }
                            Err(e) => {
                                let mut app = state_clone.lock().await;
                                app.logs.push(format!("❌ [AUTO-BLOCK ERROR] Failed to block {}: {}", ip, e));
                                if app.logs.len() > LOG_CAP {
                                    app.logs.remove(0);
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    
    loop {
        
        // 1. RENDER
        {
            let app = state.lock().await;
            terminal.draw(|f| ui_render(f, &app))?;
        }

        // 2. EVENT
        if event::poll(time::Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                let mut should_block_ip: Option<String> = None;
                let mut should_unblock_ip: Option<String> = None;

                {
                    let mut app = state.lock().await;
                    let term_height = terminal.size()?.height;
                    let list_visible_height = (term_height as u16 * 60 / 100).saturating_sub(2) as usize;

                    match app.input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('q') => return Ok(()),
                            KeyCode::Char(':') => {
                                app.input_mode = InputMode::Command;
                                app.input_buffer.clear();
                                app.input_buffer.push(':');
                            }
                            KeyCode::Char('/') => {
                                app.input_mode = InputMode::Command;
                                app.input_buffer.clear();
                                app.input_buffer.push('/');
                            }
                            KeyCode::Tab => {
                                app.active_window = if app.active_window == ActiveWindow::Suspects { ActiveWindow::Blocked } else { ActiveWindow::Suspects };
                            }
                            // NAV DOWN
                            KeyCode::Down | KeyCode::Char('j') => {
                                if app.detail_open {
                                    app.detail_scroll = app.detail_scroll.saturating_add(1);
                                } else if app.active_window == ActiveWindow::Suspects {
                                    if app.selected_suspect_idx + 1 < app.suspects.len() {
                                        app.selected_suspect_idx += 1;
                                        if app.selected_suspect_idx >= app.suspects_scroll + list_visible_height {
                                            app.suspects_scroll = app.selected_suspect_idx + 1 - list_visible_height;
                                        }
                                    }
                                } else {
                                    if app.selected_block_idx + 1 < app.blocked.len() {
                                        app.selected_block_idx += 1;
                                        if app.selected_block_idx >= app.blocked_scroll + list_visible_height {
                                            app.blocked_scroll = app.selected_block_idx + 1 - list_visible_height;
                                        }
                                    }
                                }
                            }
                            // NAV UP
                            KeyCode::Up | KeyCode::Char('k') => {
                                if app.detail_open {
                                    app.detail_scroll = app.detail_scroll.saturating_sub(1);
                                } else if app.active_window == ActiveWindow::Suspects {
                                    if app.selected_suspect_idx > 0 {
                                        app.selected_suspect_idx -= 1;
                                        if app.selected_suspect_idx < app.suspects_scroll {
                                            app.suspects_scroll = app.selected_suspect_idx;
                                        }
                                    }
                                } else {
                                    if app.selected_block_idx > 0 {
                                        app.selected_block_idx -= 1;
                                        if app.selected_block_idx < app.blocked_scroll {
                                            app.blocked_scroll = app.selected_block_idx;
                                        }
                                    }
                                }
                            }
                            // HORZ
                            KeyCode::Left | KeyCode::Char('h') => {
                                if app.detail_open {
                                    app.detail_scroll_x = app.detail_scroll_x.saturating_sub(5);
                                }
                            }
                            KeyCode::Right | KeyCode::Char('l') => {
                                if app.detail_open {
                                    app.detail_scroll_x = app.detail_scroll_x.saturating_add(5);
                                }
                            }
                            KeyCode::PageDown => {
                                if app.detail_open {
                                    app.detail_scroll = app.detail_scroll.saturating_add(10);
                                } else {
                                    app.logs_scroll = app.logs_scroll.saturating_sub(10);
                                }
                            }
                            KeyCode::PageUp => {
                                if app.detail_open {
                                    app.detail_scroll = app.detail_scroll.saturating_sub(10);
                                } else {
                                    app.logs_scroll = app.logs_scroll.saturating_add(10);
                                }
                            }
                            KeyCode::Enter => {
                                if app.detail_open {
                                } else if app.active_window == ActiveWindow::Suspects && !app.suspects.is_empty() {
                                    let ip = app.suspects[app.selected_suspect_idx].ip.clone();
                                    should_block_ip = Some(ip);
                                } else if app.active_window == ActiveWindow::Blocked && !app.blocked.is_empty() {
                                    let ip = app.blocked[app.selected_block_idx].ip.clone();
                                    should_unblock_ip = Some(ip);
                                }
                            }
                            KeyCode::Char('i') => {
                                if !app.suspects.is_empty() && app.active_window == ActiveWindow::Suspects {
                                    let ip = app.suspects[app.selected_suspect_idx].ip.clone();
                                    app.detail_open = true;
                                    app.detail_ip = Some(ip);
                                    app.detail_scroll = 0;
                                    app.detail_scroll_x = 0;
                                }
                            }
                            KeyCode::Esc => {
                                if app.detail_open {
                                    app.detail_open = false;
                                    app.detail_ip = None;
                                    app.detail_scroll = 0;
                                }
                            }
                            _ => {}
                        },
                        InputMode::Command => match key.code {
                            KeyCode::Enter => {
                                let cmd = app.input_buffer.trim().to_string();
                                if cmd.starts_with(":block ") {
                                    should_block_ip = cmd.split_whitespace().nth(1).map(String::from);
                                } else if cmd.starts_with(":unblock ") {
                                    should_unblock_ip = cmd.split_whitespace().nth(1).map(String::from);
                                } else if cmd.starts_with(":whitelist ") {
                                    if let Some(ip) = cmd.split_whitespace().nth(1) { app.whitelisted_dynamic.insert(ip.to_string()); }
                                } else if cmd.starts_with(":clearlogs") {
                                    app.logs.clear();
                                } else if cmd.starts_with(":search ") {
                                    if let Some(pattern) = cmd.split_whitespace().nth(1) {
                                        app.search_filter = Some(pattern.to_string());
                                        app.suspects_scroll = 0;
                                        app.selected_suspect_idx = 0;
                                    }
                                } else if cmd == ":clearfilter" {
                                    app.search_filter = None;
                                } else if cmd.starts_with('/') {
                                    let pattern = cmd.trim_start_matches('/').to_string();
                                    if pattern.is_empty() {
                                        app.search_filter = None;
                                    } else {
                                        app.search_filter = Some(pattern);
                                    }
                                    app.suspects_scroll = 0;
                                    app.selected_suspect_idx = 0;
                                } else {
                                    app.logs.push(format!("Unknown: {}", cmd));
                                    if app.logs.len() > LOG_CAP { app.logs.remove(0); }
                                }
                                app.input_mode = InputMode::Normal;
                                app.input_buffer.clear();
                            }
                            KeyCode::Esc => { app.input_mode = InputMode::Normal; app.input_buffer.clear(); },
                            KeyCode::Char(c) => app.input_buffer.push(c),
                            KeyCode::Backspace => { app.input_buffer.pop(); },
                            _ => {}
                        }
                    }
                }

                if let Some(ip) = should_block_ip {
                    let display_reason = "Manual Block".to_string();
                    let db_reason = "Manual Block".to_string();
                    let _ = block_ip(ip, display_reason, db_reason, &pool, &state).await;
                }
                if let Some(ip) = should_unblock_ip {
                    let _ = unblock_ip(ip, &pool, &state).await;
                }
            }
        }
    }
}

// --- ENTRY POINT ---
#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting Ravelin TUI — ensuring dependencies & DB...");

    // 1. SELF-DEPLOYMENT PHASE
    if let Err(e) = system_self_check() {
        eprintln!("Fatal Error during self-setup: {}", e);
        return Ok(());
    }

    // 2. INIT DB & state
    let pool = init_db().await?;
    let start_time = get_start_time(&pool).await?;

    // load persisted blocked list
    let initial_blocked: Vec<BlockedIp> = {
        let db_entries: Vec<BlockedIp> =
            sqlx::query_as::<_, BlockedIp>("SELECT ip, blocked_at, reason FROM blocked_ips")
                .fetch_all(&pool)
                .await
                .unwrap_or_default();
        
        // Normalize reasons for display
        db_entries.into_iter()
            .map(|mut entry| {
                entry.reason = normalize_reason_for_display(&entry.reason);
                entry
            })
            .collect()
    };

    // FIX: RESTORE FIREWALL STATE
    // This loops through the DB entries and re-applies them to IPSet so reboot doesn't clear them.
    if !initial_blocked.is_empty() {
        println!("Restoring firewall rules for {} blocked IPs...", initial_blocked.len());
        for b in &initial_blocked {
            let _ = Command::new("sudo")
                .args(["ipset", "add", "sentinel_block", &b.ip, "-exist"])
                .output();
        }
    }

    // 3. INIT TERMINAL (TUI)
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 4. APP STATE
    let local_ips = get_local_ips();
    let app_state = Arc::new(Mutex::new(AppState {
        logs: vec![],
        suspects: vec![],
        blocked: initial_blocked,
        whitelisted_dynamic: HashSet::new(),
        local_ips,
        input_buffer: String::new(),
        input_mode: InputMode::Normal,
        selected_suspect_idx: 0,
        selected_block_idx: 0,
        active_window: ActiveWindow::Suspects,
        start_time,
        logs_scroll: 0,
        suspects_scroll: 0,
        blocked_scroll: 0,
        ip_history: HashMap::new(),
        detail_open: false,
        detail_ip: None,
        detail_scroll: 0,
        detail_scroll_x: 0,
        search_filter: None,
        request_stats: HashMap::new(),
    }));

    // 5. START HARVESTERS
    harvest_logs(app_state.clone(), pool.clone()).await;

    // 6. RUN UI LOOPY
    let res = run_ui(&mut terminal, pool.clone(), app_state.clone()).await;

    // 7. CLEANUP TUI
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {:?}", err);
    }

    Ok(())
}
