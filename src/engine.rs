use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    constants::{AUTO_BLOCK_SCORE_THRESHOLD, LEARNING_PERIOD_HOURS, SUSPECT_CAP},
    models::{AppState, AutoBlock, Suspect},
    network::is_blockable_ip,
    parser::{SuspectSignal, parse_log_line},
};

pub async fn process_log_line(
    line: &str,
    source: &str,
    state: &Arc<Mutex<AppState>>,
) -> Option<AutoBlock> {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return None;
    }

    let signal = parse_log_line(line, source);
    if signal.ips_found.is_empty() && signal.safe_ip.is_none() && signal.suspect.is_none() {
        return None;
    }

    let event_key = format!("{source}\0{line}");
    let mut app = state.lock().await;
    if !app.remember_event(event_key) {
        return None;
    }

    for ip in &signal.ips_found {
        app.push_history(ip, format!("[{source}] {line}"));
    }

    if let Some(ip) = signal.safe_ip {
        app.whitelisted_dynamic.insert(ip.clone());
        app.suspects.retain(|suspect| suspect.ip != ip);
        app.push_log(format!("🟢 [SAFE] {ip} authenticated successfully via SSH"));
        app.clamp_selected_indexes();
        drop(app);
        return None;
    }

    let Some(suspect) = signal.suspect else {
        drop(app);
        return None;
    };
    let auto_block = process_suspect_signal(&mut app, suspect, source);
    drop(app);

    auto_block
}

fn process_suspect_signal(
    app: &mut AppState,
    suspect: SuspectSignal,
    source: &str,
) -> Option<AutoBlock> {
    if app.local_ips.contains(&suspect.ip)
        || app.whitelisted_dynamic.contains(&suspect.ip)
        || app.is_blocked(&suspect.ip)
        || !is_blockable_ip(&suspect.ip)
    {
        return None;
    }

    app.push_log(format!("⚠️ [{source}] {} | {}", suspect.ip, suspect.reason));

    let now = Utc::now();
    let score = if let Some(existing) = app
        .suspects
        .iter_mut()
        .find(|existing| existing.ip == suspect.ip)
    {
        existing.score = existing.score.saturating_add(1);
        existing.last_seen = now;
        existing.reason.clone_from(&suspect.reason);
        source.clone_into(&mut existing.source_type);
        existing.score
    } else {
        app.suspects.push(Suspect {
            ip: suspect.ip.clone(),
            reason: suspect.reason.clone(),
            score: 1,
            last_seen: now,
            source_type: source.to_owned(),
        });
        1
    };

    app.suspects.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.last_seen.cmp(&left.last_seen))
    });

    if app.suspects.len() > SUSPECT_CAP {
        app.suspects.truncate(SUSPECT_CAP);
    }
    app.clamp_selected_indexes();

    let learning_complete =
        now.signed_duration_since(app.start_time).num_hours() >= LEARNING_PERIOD_HOURS;

    if learning_complete && score >= AUTO_BLOCK_SCORE_THRESHOLD {
        return Some(AutoBlock {
            ip: suspect.ip,
            reason: format!(
                "Auto Block: {} after score {score} (threshold {AUTO_BLOCK_SCORE_THRESHOLD})",
                suspect.reason
            ),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use std::{collections::HashSet, sync::Arc};
    use tokio::sync::Mutex;

    use super::process_log_line;
    use crate::{constants::AUTO_BLOCK_SCORE_THRESHOLD, models::AppState};

    #[tokio::test]
    async fn duplicate_log_lines_do_not_increase_score() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            Utc::now(),
        )));
        let line = "Jun 23 host sshd[1]: Failed password for root from 8.8.8.8 port 22 ssh2";

        assert!(process_log_line(line, "SSH", &state).await.is_none());
        assert!(process_log_line(line, "SSH", &state).await.is_none());

        {
            let app = state.lock().await;
            assert_eq!(app.suspects.len(), 1);
            assert_eq!(app.suspects[0].score, 1);
            drop(app);
        }
    }

    #[tokio::test]
    async fn returns_auto_block_after_learning_period_and_threshold() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            Utc::now() - Duration::hours(13),
        )));

        let mut auto_block = None;
        for attempt in 0..AUTO_BLOCK_SCORE_THRESHOLD {
            let line = format!(
                "Jun 23 host sshd[1]: Failed password for root from 8.8.4.4 port {attempt} ssh2"
            );
            auto_block = process_log_line(&line, "SSH", &state).await;
        }

        let auto_block = auto_block.expect("threshold crossing should return an auto-block action");
        assert_eq!(auto_block.ip, "8.8.4.4");
        assert!(auto_block.reason.contains("Auto Block"));
    }
}
