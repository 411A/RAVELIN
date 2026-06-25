use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    constants::{
        AUTO_BLOCK_SCORE_THRESHOLD, HTTP_BEHAVIOR_SIGNAL_COOLDOWN_SECS, HTTP_BURST_MIN_REQUESTS,
        HTTP_ERROR_BURST_MIN_ERRORS, HTTP_ERROR_BURST_SCORE, HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
        HTTP_NO_SUCCESS_FLOOD_SCORE, HTTP_REGULAR_MAX_AVG_GAP_MS, HTTP_REGULAR_MAX_JITTER_MS,
        HTTP_REGULAR_MIN_AVG_GAP_MS, HTTP_REGULAR_MIN_REQUESTS, HTTP_SUCCESS_BURST_MIN_REQUESTS,
        HTTP_SUCCESS_BURST_SCORE, MIN_AUTO_BLOCK_EVENTS, SUSPECT_CAP,
    },
    models::{AppState, AutoBlock, HttpBehaviorSnapshot, Suspect},
    network::is_blockable_ip,
    parser::{HttpSignal, SignalConfidence, SuspectSignal, parse_log_line},
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

    if let Some(http) = &signal.http
        && source == "Suricata"
        && let Some(suspect) = behavior_signal(&mut app, http)
    {
        app.push_history(&suspect.ip, &format!("[{source}] {line}"));
        let auto_block = process_suspect_signal(&mut app, suspect, source);
        drop(app);
        return auto_block;
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

fn behavior_signal(app: &mut AppState, http: &HttpSignal) -> Option<SuspectSignal> {
    if app.local_ips.contains(&http.ip)
        || app.whitelisted_dynamic.contains(&http.ip)
        || app.is_blocked(&http.ip)
        || !is_blockable_ip(&http.ip)
    {
        return None;
    }

    let now = Utc::now();
    let snapshot = app.observe_http(&http.ip, http.status, now);
    let signal = classify_http_behavior(http, snapshot)?;
    let behavior = app.http_behaviors.get_mut(&http.ip)?;
    if !signal.immediate_block
        && behavior.last_signal_at.is_some_and(|last_signal_at| {
            now.signed_duration_since(last_signal_at).num_seconds()
                < HTTP_BEHAVIOR_SIGNAL_COOLDOWN_SECS
        })
    {
        return None;
    }
    behavior.last_signal_at = Some(now);
    Some(signal)
}

fn classify_http_behavior(
    http: &HttpSignal,
    snapshot: HttpBehaviorSnapshot,
) -> Option<SuspectSignal> {
    if is_no_success_flood(snapshot) {
        return Some(SuspectSignal {
            ip: http.ip.clone(),
            reason: format!(
                "HTTP no-success flood: {} failed / {} requests in 10s; latest {} {}{} => {}",
                snapshot.burst_errors,
                snapshot.burst_total,
                http.method,
                http.host,
                http.url,
                http.status
            ),
            score_delta: HTTP_NO_SUCCESS_FLOOD_SCORE,
            confidence: SignalConfidence::High,
            immediate_block: true,
        });
    }

    if snapshot.burst_errors >= HTTP_ERROR_BURST_MIN_ERRORS
        && snapshot.burst_total >= HTTP_BURST_MIN_REQUESTS
    {
        return Some(SuspectSignal {
            ip: http.ip.clone(),
            reason: format!(
                "HTTP error burst: {} errors / {} requests; latest {} {}{} => {}",
                snapshot.burst_errors,
                snapshot.burst_total,
                http.method,
                http.host,
                http.url,
                http.status
            ),
            score_delta: HTTP_ERROR_BURST_SCORE,
            confidence: SignalConfidence::Medium,
            immediate_block: false,
        });
    }

    if snapshot.burst_total >= HTTP_SUCCESS_BURST_MIN_REQUESTS && snapshot.errors == 0 {
        return Some(SuspectSignal {
            ip: http.ip.clone(),
            reason: format!(
                "HTTP success burst: {} successful responses; latest {} {}{} => {}",
                snapshot.successes, http.method, http.host, http.url, http.status
            ),
            score_delta: HTTP_SUCCESS_BURST_SCORE,
            confidence: SignalConfidence::Low,
            immediate_block: false,
        });
    }

    if is_predictable_cadence(snapshot) && snapshot.errors == 0 {
        return Some(SuspectSignal {
            ip: http.ip.clone(),
            reason: format!(
                "HTTP predictable cadence: {} successful responses; avg gap {:?}ms jitter {:?}ms; latest {} {}{} => {}",
                snapshot.successes,
                snapshot.average_gap_ms,
                snapshot.jitter_ms,
                http.method,
                http.host,
                http.url,
                http.status
            ),
            score_delta: HTTP_SUCCESS_BURST_SCORE,
            confidence: SignalConfidence::Low,
            immediate_block: false,
        });
    }

    None
}

const fn is_no_success_flood(snapshot: HttpBehaviorSnapshot) -> bool {
    snapshot.burst_total >= HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS
        && snapshot.successes == 0
        && snapshot.burst_total == snapshot.burst_errors
}

const fn is_predictable_cadence(snapshot: HttpBehaviorSnapshot) -> bool {
    if snapshot.total < HTTP_REGULAR_MIN_REQUESTS {
        return false;
    }

    match (snapshot.average_gap_ms, snapshot.jitter_ms) {
        (Some(average_gap_ms), Some(jitter_ms)) => {
            average_gap_ms >= HTTP_REGULAR_MIN_AVG_GAP_MS
                && average_gap_ms <= HTTP_REGULAR_MAX_AVG_GAP_MS
                && jitter_ms <= HTTP_REGULAR_MAX_JITTER_MS
        }
        _ => false,
    }
}

fn process_suspect_signal(
    app: &mut AppState,
    suspect: SuspectSignal,
    source: &str,
) -> Option<AutoBlock> {
    if app.local_ips.contains(&suspect.ip)
        || app.whitelisted_dynamic.contains(&suspect.ip)
        || app.is_blocked(&suspect.ip)
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
        existing.last_seen = now;
        existing.reason.clone_from(&suspect.reason);
        source.clone_into(&mut existing.source_type);
        existing.auto_block_eligible = auto_block_eligible(existing);
        existing.score
    } else {
        app.suspects.push(Suspect {
            ip: suspect.ip.clone(),
            reason: suspect.reason.clone(),
            score: suspect.score_delta,
            events: 1,
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

    if !is_blockable_ip(&suspect.ip) {
        return None;
    }

    if suspect.immediate_block {
        return Some(AutoBlock {
            ip: suspect.ip,
            reason: format!(
                "Auto Block: {} (high-confidence no-success flood)",
                suspect.reason
            ),
        });
    }

    let auto_block_eligible = app
        .suspects
        .iter()
        .find(|existing| existing.ip == suspect.ip)
        .is_some_and(auto_block_eligible);

    if score >= AUTO_BLOCK_SCORE_THRESHOLD && auto_block_eligible {
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
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};
    use tokio::sync::Mutex;

    use super::{classify_http_behavior, process_log_line};
    use crate::{
        constants::{
            AUTO_BLOCK_SCORE_THRESHOLD, HTTP_ERROR_BURST_SCORE, HTTP_NO_SUCCESS_FLOOD_SCORE,
        },
        constants::{HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS, SSH_FAILURE_SCORE},
        models::{AppState, HttpBehaviorSnapshot},
        parser::{HttpSignal, SignalConfidence},
    };

    #[tokio::test]
    async fn duplicate_log_lines_do_not_increase_score() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
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
    async fn returns_auto_block_after_threshold() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
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
    async fn repeated_http_errors_below_no_success_flood_do_not_auto_block() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            crate::models::RuntimeMode::Standalone,
        )));

        let mut auto_block = None;
        for attempt in 0..HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS - 1 {
            let line = format!(
                r#"{{"event_type":"http","src_ip":"8.8.4.4","dest_ip":"198.51.100.10","http":{{"status":404,"hostname":"example.com","url":"/missing-{attempt}","http_method":"GET"}}}}"#
            );
            auto_block = process_log_line(&line, "Suricata", &state).await;
        }

        assert!(auto_block.is_none());
    }

    #[tokio::test]
    async fn single_suricata_http_error_only_updates_behavior() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            crate::models::RuntimeMode::Standalone,
        )));

        let line = r#"{"event_type":"http","src_ip":"8.8.4.4","dest_ip":"198.51.100.10","http":{"status":404,"hostname":"example.com","url":"/missing","http_method":"GET"}}"#;
        assert!(process_log_line(line, "Suricata", &state).await.is_none());

        let (has_no_suspects, has_no_history, tracks_behavior) = {
            let app = state.lock().await;
            (
                app.suspects.is_empty(),
                app.ip_history.is_empty(),
                app.http_behaviors.contains_key("8.8.4.4"),
            )
        };
        assert!(has_no_suspects);
        assert!(has_no_history);
        assert!(tracks_behavior);
    }

    #[test]
    fn http_error_burst_becomes_medium_confidence_behavior_signal() {
        let http = http_signal(404);
        let signal = classify_http_behavior(
            &http,
            HttpBehaviorSnapshot {
                total: 30,
                successes: 22,
                errors: 8,
                burst_total: 30,
                burst_errors: 8,
                average_gap_ms: Some(300),
                jitter_ms: Some(120),
            },
        )
        .expect("error burst should be suspicious");

        assert_eq!(signal.ip, "8.8.4.4");
        assert_eq!(signal.score_delta, HTTP_ERROR_BURST_SCORE);
        assert_eq!(signal.confidence, SignalConfidence::Medium);
        assert!(!signal.immediate_block);
    }

    #[test]
    fn sparse_non_linear_successful_http_is_not_suspicious() {
        let signal = classify_http_behavior(
            &http_signal(200),
            HttpBehaviorSnapshot {
                total: 8,
                successes: 8,
                errors: 0,
                burst_total: 2,
                burst_errors: 0,
                average_gap_ms: Some(4_000),
                jitter_ms: Some(3_200),
            },
        );

        assert!(signal.is_none());
    }

    #[test]
    fn predictable_successful_cadence_is_low_confidence_behavior_signal() {
        let signal = classify_http_behavior(
            &http_signal(200),
            HttpBehaviorSnapshot {
                total: 12,
                successes: 12,
                errors: 0,
                burst_total: 6,
                burst_errors: 0,
                average_gap_ms: Some(750),
                jitter_ms: Some(20),
            },
        )
        .expect("machine-like cadence should be suspicious");

        assert_eq!(signal.confidence, SignalConfidence::Low);
        assert!(signal.reason.contains("predictable cadence"));
        assert!(!signal.immediate_block);
    }

    #[test]
    fn no_success_http_flood_is_high_confidence_immediate_block() {
        let http = http_signal(404);
        let signal = classify_http_behavior(
            &http,
            HttpBehaviorSnapshot {
                total: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
                successes: 0,
                errors: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
                burst_total: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
                burst_errors: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
                average_gap_ms: Some(80),
                jitter_ms: Some(20),
            },
        )
        .expect("100% failure burst should be an immediate block signal");

        assert_eq!(signal.score_delta, HTTP_NO_SUCCESS_FLOOD_SCORE);
        assert_eq!(signal.confidence, SignalConfidence::High);
        assert!(signal.immediate_block);
        assert!(signal.reason.contains("no-success flood"));
    }

    #[tokio::test]
    async fn no_success_http_flood_returns_auto_block_immediately() {
        let state = Arc::new(Mutex::new(AppState::new(
            Vec::new(),
            HashSet::new(),
            crate::models::RuntimeMode::Standalone,
        )));

        let mut auto_block = None;
        for attempt in 0..HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS {
            let line = format!(
                r#"{{"event_type":"http","src_ip":"8.8.4.4","dest_ip":"198.51.100.10","http":{{"status":404,"hostname":"example.com","url":"/scan-{attempt}","http_method":"GET"}}}}"#
            );
            auto_block = process_log_line(&line, "Suricata", &state).await;
        }

        let auto_block =
            auto_block.expect("no-success HTTP flood should bypass the learning period");
        assert_eq!(auto_block.ip, "8.8.4.4");
        assert!(auto_block.reason.contains("no-success flood"));
    }

    #[test]
    fn mixed_success_traffic_is_not_no_success_flood() {
        let signal = classify_http_behavior(
            &http_signal(404),
            HttpBehaviorSnapshot {
                total: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
                successes: 1,
                errors: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS - 1,
                burst_total: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS,
                burst_errors: HTTP_NO_SUCCESS_FLOOD_MIN_REQUESTS - 1,
                average_gap_ms: Some(80),
                jitter_ms: Some(20),
            },
        )
        .expect("mixed failure bursts should remain suspicious without immediate blocking");

        assert_eq!(signal.confidence, SignalConfidence::Medium);
        assert!(!signal.immediate_block);
    }

    fn http_signal(status: u16) -> HttpSignal {
        HttpSignal {
            ip: "8.8.4.4".to_owned(),
            status,
            method: "GET".to_owned(),
            host: "example.com".to_owned(),
            url: "/probe".to_owned(),
        }
    }
}
