use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::constants::{HISTORY_CAP, LOG_CAP, RECENT_EVENT_CAP};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suspect {
    pub ip: String,
    pub reason: String,
    pub score: u32,
    pub last_seen: DateTime<Utc>,
    pub source_type: String,
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
    pub start_time: DateTime<Utc>,
    pub logs_scroll: usize,
    pub suspects_scroll: usize,
    pub blocked_scroll: usize,
    pub ip_history: HashMap<String, Vec<String>>,
    pub detail_open: bool,
    pub detail_ip: Option<String>,
    pub detail_scroll: usize,
    pub detail_scroll_x: usize,
    pub search_filter: Option<String>,
    recent_event_keys: VecDeque<String>,
    recent_event_set: HashSet<String>,
}

impl AppState {
    pub fn new(
        blocked: Vec<BlockedIp>,
        local_ips: HashSet<String>,
        start_time: DateTime<Utc>,
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
            recent_event_keys: VecDeque::new(),
            recent_event_set: HashSet::new(),
        }
    }

    pub fn push_log(&mut self, entry: String) {
        if self.logs.last().is_some_and(|last| last == &entry) {
            return;
        }

        self.logs.push(entry);
        let overflow = self.logs.len().saturating_sub(LOG_CAP);
        if overflow > 0 {
            self.logs.drain(..overflow);
        }
    }

    pub fn push_history(&mut self, ip: &str, entry: String) {
        let lines = self.ip_history.entry(ip.to_owned()).or_default();
        lines.push(entry);

        let overflow = lines.len().saturating_sub(HISTORY_CAP);
        if overflow > 0 {
            lines.drain(..overflow);
        }
    }

    pub fn remember_event(&mut self, key: String) -> bool {
        if self.recent_event_set.contains(&key) {
            return false;
        }

        self.recent_event_set.insert(key.clone());
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoBlock {
    pub ip: String,
    pub reason: String,
}

fn clamp_index(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { index.min(len - 1) }
}
