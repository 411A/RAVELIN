use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    constants::{
        AUTO_BLOCK_SCORE_THRESHOLD, LEARNING_PERIOD_HOURS, MIN_AUTO_BLOCK_EVENTS,
        MIN_AUTO_BLOCK_HIGH_CONFIDENCE_EVENTS, SUSPECT_CAP,
    },
    models::{AppState, AutoBlock, Suspect},
    network::is_blockable_ip,
    parser::{SignalConfidence, SuspectSignal, parse_log_line},
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

    let mut app = state.lock().await;
    if !app.remember_event(source, line) {
        return None;
    }

    if let Some(ip) = signal.safe_ip {
        app.push_history(&ip, &format!("[{source}] {line}"));
        app.whitelisted_dynamic.insert(ip.clone());
        app.suspects.retain(|suspect| suspect.ip != ip);
        app.push_log(&format!(
            "🟢 [SAFE] {ip} authenticated successfully via SSH"
        ));
        app.clamp_selected_indexes();
        drop(app);
        return None;
    }

    let Some(suspect) = signal.suspect else {
        drop(app);
        return None;
    };
    app.push_history(&suspect.ip, &format!("[{source}] {line}"));
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

    app.push_log(&format!(
        "⚠️ [{source}] {} | {}",
        suspect.ip, suspect.reason
    ));

    let now = Utc::now();
    let score = if let Some(existing) = app
        .suspects
        .iter_mut()
        .find(|existing| existing.ip == suspect.ip)
    {
        existing.score = existing.score.saturating_add(suspect.score_delta);
        existing.events = existing.events.saturating_add(1);
        if suspect.confidence == SignalConfidence::High {
            existing.high_confidence_events = existing.high_confidence_events.saturating_add(1);
        }
        existing.last_seen = now;
        existing.reason.clone_from(&suspect.reason);
        source.clone_into(&mut existing.source_type);
        existing.auto_block_eligible = auto_block_eligible(existing);
        existing.score
    } else {
        let high_confidence_events = u32::from(suspect.confidence == SignalConfidence::High);
        app.suspects.push(Suspect {
            ip: suspect.ip.clone(),
            reason: suspect.reason.clone(),
            score: suspect.score_delta,
            events: 1,
            high_confidence_events,
            first_seen: now,
            last_seen: now,
            source_type: source.to_owned(),
            auto_block_eligible: false,
        });
        suspect.score_delta
    };

    if let Some(existing) = app
        .suspects
        .iter_mut()
        .find(|existing| existing.ip == suspect.ip)
    {
        existing.auto_block_eligible = auto_block_eligible(existing);
    }

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

    let auto_block_eligible = app
        .suspects
        .iter()
        .find(|existing| existing.ip == suspect.ip)
        .is_some_and(auto_block_eligible);

    if learning_complete && score >= AUTO_BLOCK_SCORE_THRESHOLD && auto_block_eligible {
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

const fn auto_block_eligible(suspect: &Suspect) -> bool {
    suspect.events >= MIN_AUTO_BLOCK_EVENTS
        && suspect.high_confidence_events >= MIN_AUTO_BLOCK_HIGH_CONFIDENCE_EVENTS
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use std::{collections::HashSet, sync::Arc};
    use tokio::sync::Mutex;

    use super::process_log_line;
    use crate::{
        constants::{AUTO_BLOCK_SCORE_THRESHOLD, SSH_FAILURE_SCORE},
        models::AppState,
    };

    #[tokio::test]
    async fn duplicate_log_lines_do_not_increase_score() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            Utc::now(),
            crate::models::RuntimeMode::Standalone,
        )));
        let line = "Jun 23 host sshd[1]: Failed password for root from 8.8.8.8 port 22 ssh2";

        assert!(process_log_line(line, "SSH", &state).await.is_none());
        assert!(process_log_line(line, "SSH", &state).await.is_none());

        {
            let app = state.lock().await;
            assert_eq!(app.suspects.len(), 1);
            assert_eq!(app.suspects[0].score, SSH_FAILURE_SCORE);
            assert_eq!(app.suspects[0].events, 1);
            drop(app);
        }
    }

    #[tokio::test]
    async fn returns_auto_block_after_learning_period_and_threshold() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            Utc::now() - Duration::hours(13),
            crate::models::RuntimeMode::Standalone,
        )));

        let mut auto_block = None;
        for attempt in 0..AUTO_BLOCK_SCORE_THRESHOLD {
            let line = format!(
                r#"{{"event_type":"alert","src_ip":"8.8.4.4","dest_ip":"198.51.100.10","alert":{{"signature":"test scan {attempt}","category":"Attempted Information Leak","severity":1}}}}"#
            );
            auto_block = process_log_line(&line, "Suricata", &state).await;
        }

        let auto_block = auto_block.expect("threshold crossing should return an auto-block action");
        assert_eq!(auto_block.ip, "8.8.4.4");
        assert!(auto_block.reason.contains("Auto Block"));
    }

    #[tokio::test]
    async fn repeated_low_confidence_http_errors_do_not_auto_block() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            Utc::now() - Duration::hours(13),
            crate::models::RuntimeMode::Standalone,
        )));

        let mut auto_block = None;
        for attempt in 0..200 {
            let line = format!(
                r#"{{"event_type":"http","src_ip":"8.8.4.4","dest_ip":"198.51.100.10","http":{{"status":404,"hostname":"example.com","url":"/missing-{attempt}","http_method":"GET"}}}}"#
            );
            auto_block = process_log_line(&line, "Suricata", &state).await;
        }

        assert!(auto_block.is_none());
    }
}
