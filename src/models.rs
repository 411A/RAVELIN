use chrono::{DateTime, Utc};
use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
};

use crate::constants::{
    HISTORY_CAP, HTTP_BEHAVIOR_EVENT_CAP, HTTP_BEHAVIOR_IP_CAP, HTTP_BEHAVIOR_WINDOW_SECS,
    IP_HISTORY_KEY_CAP, LOG_CAP, MAX_HISTORY_LINE_LEN, MAX_UI_LOG_LEN, RECENT_EVENT_CAP,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suspect {
    pub ip: String,
    pub reason: String,
    pub score: u32,
    pub events: u32,
    pub high_confidence_events: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub source_type: String,
    pub auto_block_eligible: bool,
}

#[derive(Clone, Debug, sqlx::FromRow, PartialEq, Eq)]
pub struct BlockedIp {
    pub ip: String,
    pub blocked_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct AppState {
    pub logs: Vec<String>,
    pub suspects: Vec<Suspect>,
    pub blocked: Vec<BlockedIp>,
    pub whitelisted_dynamic: HashSet<String>,
    pub local_ips: HashSet<String>,
    pub input_buffer: String,
    pub input_mode: InputMode,
    pub selected_suspect_idx: usize,
    pub selected_block_idx: usize,
    pub active_window: ActiveWindow,
    pub logs_scroll: usize,
    pub suspects_scroll: usize,
    pub blocked_scroll: usize,
    pub ip_history: HashMap<String, Vec<String>>,
    pub http_behaviors: HashMap<String, HttpBehavior>,
    pub detail_open: bool,
    pub detail_ip: Option<String>,
    pub detail_scroll: usize,
    pub detail_scroll_x: usize,
    pub search_filter: Option<String>,
    pub runtime_mode: RuntimeMode,
    recent_event_keys: VecDeque<u64>,
    recent_event_set: HashSet<u64>,
    ip_history_order: VecDeque<String>,
    http_behavior_order: VecDeque<String>,
}

impl AppState {
    pub fn new(
        blocked: Vec<BlockedIp>,
        local_ips: HashSet<String>,
        runtime_mode: RuntimeMode,
    ) -> Self {
        Self {
            logs: Vec::new(),
            suspects: Vec::new(),
            blocked,
            whitelisted_dynamic: HashSet::new(),
            local_ips,
            input_buffer: String::new(),
            input_mode: InputMode::Normal,
            selected_suspect_idx: 0,
            selected_block_idx: 0,
            active_window: ActiveWindow::Suspects,
            logs_scroll: 0,
            suspects_scroll: 0,
            blocked_scroll: 0,
            ip_history: HashMap::new(),
            http_behaviors: HashMap::new(),
            detail_open: false,
            detail_ip: None,
            detail_scroll: 0,
            detail_scroll_x: 0,
            search_filter: None,
            runtime_mode,
            recent_event_keys: VecDeque::new(),
            recent_event_set: HashSet::new(),
            ip_history_order: VecDeque::new(),
            http_behavior_order: VecDeque::new(),
        }
    }

    pub fn push_log(&mut self, entry: &str) {
        let entry = bounded_string(entry, MAX_UI_LOG_LEN);
        if self.logs.last().is_some_and(|last| last == &entry) {
            return;
        }

        self.logs.push(entry);
        let overflow = self.logs.len().saturating_sub(LOG_CAP);
        if overflow > 0 {
            self.logs.drain(..overflow);
        }
    }

    pub fn push_history(&mut self, ip: &str, entry: &str) {
        if !self.ip_history.contains_key(ip) {
            self.ip_history_order.push_back(ip.to_owned());
        }

        let lines = self.ip_history.entry(ip.to_owned()).or_default();
        lines.push(bounded_string(entry, MAX_HISTORY_LINE_LEN));

        let overflow = lines.len().saturating_sub(HISTORY_CAP);
        if overflow > 0 {
            lines.drain(..overflow);
        }

        while self.ip_history.len() > IP_HISTORY_KEY_CAP {
            if let Some(oldest_ip) = self.ip_history_order.pop_front() {
                self.ip_history.remove(&oldest_ip);
            }
        }
    }

    pub fn observe_http(
        &mut self,
        ip: &str,
        status: u16,
        now: DateTime<Utc>,
    ) -> HttpBehaviorSnapshot {
        if !self.http_behaviors.contains_key(ip) {
            self.http_behavior_order.push_back(ip.to_owned());
        }

        let snapshot = {
            let behavior = self.http_behaviors.entry(ip.to_owned()).or_default();
            behavior.observe(status, now);
            behavior.snapshot(now)
        };

        while self.http_behaviors.len() > HTTP_BEHAVIOR_IP_CAP {
            if let Some(oldest_ip) = self.http_behavior_order.pop_front() {
                self.http_behaviors.remove(&oldest_ip);
            }
        }

        snapshot
    }

    pub fn remember_event(&mut self, source: &str, line: &str) -> bool {
        let key = compact_event_key(source, line);
        if self.recent_event_set.contains(&key) {
            return false;
        }

        self.recent_event_set.insert(key);
        self.recent_event_keys.push_back(key);

        while self.recent_event_keys.len() > RECENT_EVENT_CAP {
            if let Some(old) = self.recent_event_keys.pop_front() {
                self.recent_event_set.remove(&old);
            }
        }

        true
    }

    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked.iter().any(|blocked| blocked.ip == ip)
    }

    pub fn clamp_selected_indexes(&mut self) {
        self.selected_suspect_idx = clamp_index(self.selected_suspect_idx, self.suspects.len());
        self.selected_block_idx = clamp_index(self.selected_block_idx, self.blocked.len());
        self.suspects_scroll = self
            .suspects_scroll
            .min(self.suspects.len().saturating_sub(1));
        self.blocked_scroll = self
            .blocked_scroll
            .min(self.blocked.len().saturating_sub(1));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveWindow {
    Suspects,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeMode {
    Tui,
    Daemon,
    Standalone,
}

impl RuntimeMode {
    pub fn from_arg(arg: Option<&str>) -> Self {
        match arg {
            Some("daemon" | "--daemon") => Self::Daemon,
            Some("standalone" | "--standalone") => Self::Standalone,
            _ => Self::Tui,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Tui => "TUI",
            Self::Daemon => "DAEMON",
            Self::Standalone => "STANDALONE",
        }
    }

    pub const fn requires_privileged_setup(self) -> bool {
        matches!(self, Self::Daemon | Self::Standalone)
    }

    pub const fn command_hint(self) -> &'static str {
        match self {
            Self::Tui => "ravelin",
            Self::Daemon => "sudo ravelin daemon",
            Self::Standalone => "sudo ravelin standalone",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoBlock {
    pub ip: String,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct HttpBehavior {
    events: VecDeque<HttpObservation>,
    pub last_signal_at: Option<DateTime<Utc>>,
}

impl HttpBehavior {
    fn observe(&mut self, status: u16, now: DateTime<Utc>) {
        self.events.push_back(HttpObservation { at: now, status });

        while self.events.len() > HTTP_BEHAVIOR_EVENT_CAP {
            self.events.pop_front();
        }

        let cutoff = now - chrono::Duration::seconds(HTTP_BEHAVIOR_WINDOW_SECS);
        while self.events.front().is_some_and(|event| event.at < cutoff) {
            self.events.pop_front();
        }
    }

    fn snapshot(&self, now: DateTime<Utc>) -> HttpBehaviorSnapshot {
        let mut total = 0;
        let mut successes = 0;
        let mut errors = 0;
        let mut burst_total = 0;
        let mut burst_errors = 0;
        let mut previous_at = None;
        let mut gaps_ms = Vec::new();
        let burst_cutoff =
            now - chrono::Duration::seconds(crate::constants::HTTP_BURST_WINDOW_SECS);

        for event in &self.events {
            total += 1;
            if is_success_status(event.status) {
                successes += 1;
            } else if is_error_status(event.status) {
                errors += 1;
            }

            if event.at >= burst_cutoff {
                burst_total += 1;
                if is_error_status(event.status) {
                    burst_errors += 1;
                }
            }

            if let Some(previous) = previous_at {
                gaps_ms.push(event.at.signed_duration_since(previous).num_milliseconds());
            }
            previous_at = Some(event.at);
        }

        let (average_gap_ms, jitter_ms) = gap_summary(&gaps_ms);
        HttpBehaviorSnapshot {
            total,
            successes,
            errors,
            burst_total,
            burst_errors,
            average_gap_ms,
            jitter_ms,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpBehaviorSnapshot {
    pub total: usize,
    pub successes: usize,
    pub errors: usize,
    pub burst_total: usize,
    pub burst_errors: usize,
    pub average_gap_ms: Option<i64>,
    pub jitter_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
struct HttpObservation {
    at: DateTime<Utc>,
    status: u16,
}

fn clamp_index(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { index.min(len - 1) }
}

fn bounded_string(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }

    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }

    let mut bounded = value[..end].to_owned();
    bounded.push_str("...");
    bounded
}

fn compact_event_key(source: &str, line: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    source.hash(&mut hasher);
    line.hash(&mut hasher);
    hasher.finish()
}

const fn is_success_status(status: u16) -> bool {
    status >= 200 && status < 400
}

const fn is_error_status(status: u16) -> bool {
    status >= 400
}

fn gap_summary(gaps_ms: &[i64]) -> (Option<i64>, Option<i64>) {
    let Some(total) = gaps_ms
        .iter()
        .try_fold(0_i64, |acc, gap| acc.checked_add(*gap))
    else {
        return (None, None);
    };
    let Some(count) = i64::try_from(gaps_ms.len()).ok().filter(|count| *count > 0) else {
        return (None, None);
    };

    let average = total / count;
    let jitter = gaps_ms
        .iter()
        .map(|gap| (*gap - average).abs())
        .max()
        .unwrap_or_default();

    (Some(average), Some(jitter))
}

#[cfg(test)]
mod tests {
    use super::RuntimeMode;

    #[test]
    fn default_runtime_mode_is_simple_tui() {
        let mode = RuntimeMode::from_arg(None);

        assert_eq!(mode, RuntimeMode::Tui);
        assert!(!mode.requires_privileged_setup());
        assert_eq!(mode.command_hint(), "ravelin");
    }

    #[test]
    fn protector_modes_require_privileged_setup() {
        for mode in [RuntimeMode::Daemon, RuntimeMode::Standalone] {
            assert!(mode.requires_privileged_setup());
        }
    }
}
