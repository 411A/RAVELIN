use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite};
use std::{collections::HashSet, io::SeekFrom, path::Path, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, AsyncWriteExt, BufReader},
    process::Command,
    sync::Mutex,
    sync::watch,
    time::{self, Duration},
};

use crate::{
    actions,
    constants::{
        EVE_RETENTION_BLOCK_HOURS, EVE_RETENTION_NON_BLOCK_HOURS, SURICATA_CLEANUP_SECS,
        SURICATA_EVE_PATH, SURICATA_MAX_LINES_PER_POLL, SURICATA_POLL_SECS, SYSLOG_POLL_SECS,
    },
    engine::process_log_line,
    models::AppState,
};

pub fn start_harvesters(
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    shutdown: watch::Receiver<bool>,
) {
    {
        let state = app_state.clone();
        tokio::spawn(async move {
            state
                .lock()
                .await
                .push_log(&format!("ℹ️ [Suricata] monitoring {SURICATA_EVE_PATH}"));
        });
    }

    tokio::spawn(follow_file(
        FileFollower {
            path: SURICATA_EVE_PATH,
            source: "Suricata",
            interval: Duration::from_secs(SURICATA_POLL_SECS),
            lightweight_suricata_filter: true,
            max_lines: SURICATA_MAX_LINES_PER_POLL,
            read_from_start: true,
        },
        app_state.clone(),
        pool.clone(),
        shutdown.clone(),
    ));

    tokio::spawn(follow_ssh(
        app_state.clone(),
        pool.clone(),
        shutdown.clone(),
    ));
    tokio::spawn(follow_docker(
        app_state.clone(),
        pool.clone(),
        shutdown.clone(),
    ));
    tokio::spawn(follow_syslog(
        app_state.clone(),
        pool.clone(),
        shutdown.clone(),
    ));
    {
        let state = app_state.clone();
        tokio::spawn(async move {
            state.lock().await.push_log(
                "ℹ️ [Core] all harvesters started — watching SSH, Docker, Syslog, Suricata",
            );
        });
    }
    tokio::spawn(suricata_cleanup_task(pool, app_state, shutdown));
}

#[derive(Clone, Copy)]
struct FileFollower {
    path: &'static str,
    source: &'static str,
    interval: Duration,
    lightweight_suricata_filter: bool,
    max_lines: usize,
    read_from_start: bool,
}

async fn follow_file(
    config: FileFollower,
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut position: u64 = 0;
    let mut initialized = config.read_from_start;
    let mut missing_log_reported = false;

    loop {
        match read_new_lines(
            config.path,
            &mut position,
            &mut initialized,
            config.lightweight_suricata_filter,
            config.max_lines,
        )
        .await
        {
            Ok(lines) => {
                if missing_log_reported {
                    push_harvest_status(
                        &app_state,
                        config.source,
                        &format!("{} is available; live harvesting resumed", config.path),
                    )
                    .await;
                    missing_log_reported = false;
                }

                for line in lines {
                    handle_line(&line, config.source, &app_state, &pool).await;
                }
            }
            Err(error) => {
                if is_not_found(&error) {
                    if !missing_log_reported {
                        push_harvest_status(
                            &app_state,
                            config.source,
                            &format!("waiting for {} to be created", config.path),
                        )
                        .await;
                        missing_log_reported = true;
                    }
                } else {
                    push_harvest_error(&app_state, config.source, &error).await;
                }
            }
        }

        if sleep_or_shutdown(config.interval, &mut shutdown).await {
            return;
        }
    }
}

async fn read_new_lines(
    path: &str,
    position: &mut u64,
    initialized: &mut bool,
    lightweight_suricata_filter: bool,
    max_lines: usize,
) -> Result<Vec<String>> {
    let mut file = File::open(path).await?;
    let len = file.metadata().await?.len();

    if !*initialized {
        *position = len;
        *initialized = true;
    } else if len < *position {
        *position = 0;
    }

    file.seek(SeekFrom::Start(*position)).await?;

    let mut reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break;
        }

        *position = position.saturating_add(bytes as u64);
        if line.len() > crate::constants::MAX_LOG_LINE_BYTES {
            continue;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if !lightweight_suricata_filter
            || trimmed.contains("\"alert\"")
            || trimmed.contains("\"http\"")
        {
            lines.push(trimmed.to_owned());
            if lines.len() >= max_lines {
                break;
            }
        }
    }

    Ok(lines)
}

async fn handle_line(
    line: &str,
    source: &str,
    app_state: &Arc<Mutex<AppState>>,
    pool: &Pool<Sqlite>,
) {
    let Some(auto_block) = process_log_line(line, source, app_state).await else {
        return;
    };

    match actions::block_ip(auto_block.ip, auto_block.reason, pool, app_state).await {
        Ok(()) => {}
        Err(error) => {
            let msg = format!("{error}");
            let is_perm = msg.contains("Operation not permitted")
                || msg.contains("exit status")
                || msg.contains("sudo");
            if is_perm {
                actions::push_action_error(
                    app_state,
                    "auto-block requires root — run: sudo ravelin standalone",
                    &error,
                )
                .await;
            } else {
                actions::push_action_error(app_state, "auto-block failed", &error).await;
            }
        }
    }
}

async fn push_harvest_error(app_state: &Arc<Mutex<AppState>>, source: &str, error: &anyhow::Error) {
    app_state
        .lock()
        .await
        .push_log(&format!("⚠️ [{source}] log harvest error: {error}"));
}

async fn push_harvest_status(app_state: &Arc<Mutex<AppState>>, source: &str, message: &str) {
    app_state
        .lock()
        .await
        .push_log(&format!("ℹ️ [{source}] {message}"));
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn is_permission_denied(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
}

async fn sleep_or_shutdown(interval: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = time::sleep(interval) => false,
        changed = shutdown.changed() => changed.is_ok() && *shutdown.borrow(),
    }
}

async fn follow_ssh(
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let path = if Path::new("/var/log/auth.log").exists() {
        "/var/log/auth.log"
    } else {
        "/var/log/secure"
    };

    let mut position: u64 = 0;
    let mut initialized = true;
    let mut missing_log_reported = false;

    loop {
        match read_new_lines(
            path,
            &mut position,
            &mut initialized,
            false,
            SURICATA_MAX_LINES_PER_POLL,
        )
        .await
        {
            Ok(lines) => {
                if missing_log_reported {
                    push_harvest_status(
                        &app_state,
                        "SSH",
                        &format!("{path} is available; live harvesting resumed"),
                    )
                    .await;
                    missing_log_reported = false;
                }
                for line in &lines {
                    if line.contains("Failed password")
                        || line.contains("Invalid user")
                        || line.contains("Disconnected from authenticating user")
                        || line.contains("Accepted")
                    {
                        handle_line(line, "SSH", &app_state, &pool).await;
                    }
                }
            }
            Err(error) => {
                if is_not_found(&error) {
                    if !missing_log_reported {
                        push_harvest_status(
                            &app_state,
                            "SSH",
                            &format!("waiting for {path} to be created"),
                        )
                        .await;
                        missing_log_reported = true;
                    }
                } else if is_permission_denied(&error) {
                    if !missing_log_reported {
                        push_harvest_status(
                            &app_state,
                            "SSH",
                            &format!(
                                "permission denied reading {path} — add your user to the adm group: sudo usermod -aG adm $USER"
                            ),
                        )
                        .await;
                        missing_log_reported = true;
                    }
                } else {
                    push_harvest_error(&app_state, "SSH", &error).await;
                }
            }
        }

        if sleep_or_shutdown(Duration::from_secs(3), &mut shutdown).await {
            return;
        }
    }
}

async fn follow_docker(
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut missing_reported = false;

    loop {
        match Command::new("docker").arg("ps").arg("-q").output().await {
            Ok(output) if output.status.success() => {
                if missing_reported {
                    push_harvest_status(
                        &app_state,
                        "Docker",
                        "Docker is available; live harvesting resumed",
                    )
                    .await;
                    missing_reported = false;
                }
                let ids = String::from_utf8_lossy(&output.stdout);
                for id in ids.lines().filter(|l| !l.is_empty()) {
                    if let Ok(logs) = Command::new("docker")
                        .args(["logs", "--tail", "20", id])
                        .output()
                        .await
                    {
                        let log_str = String::from_utf8_lossy(&logs.stdout);
                        for line in log_str.lines() {
                            handle_line(
                                line,
                                &format!("Docker-{}", &id[..id.len().min(4)]),
                                &app_state,
                                &pool,
                            )
                            .await;
                        }
                    }
                }
            }
            Ok(_) | Err(_) => {
                if !missing_reported {
                    push_harvest_status(
                        &app_state,
                        "Docker",
                        "Docker not available; skipping container log harvesting",
                    )
                    .await;
                    missing_reported = true;
                }
            }
        }

        if sleep_or_shutdown(Duration::from_secs(10), &mut shutdown).await {
            return;
        }
    }
}

async fn follow_syslog(
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let path = if Path::new("/var/log/syslog").exists() {
        "/var/log/syslog"
    } else if Path::new("/var/log/messages").exists() {
        "/var/log/messages"
    } else {
        push_harvest_status(&app_state, "Syslog", "no syslog file found; skipping").await;
        return;
    };

    let mut position: u64 = 0;
    let mut initialized = true;
    let mut missing_log_reported = false;

    loop {
        match read_new_lines(
            path,
            &mut position,
            &mut initialized,
            false,
            SURICATA_MAX_LINES_PER_POLL,
        )
        .await
        {
            Ok(lines) => {
                if missing_log_reported {
                    push_harvest_status(
                        &app_state,
                        "Syslog",
                        &format!("{path} is available; live harvesting resumed"),
                    )
                    .await;
                    missing_log_reported = false;
                }
                for line in &lines {
                    if line.contains("Failed password")
                        || line.contains("Invalid user")
                        || line.contains("authentication failure")
                        || line.contains("session opened")
                        || line.contains("session closed")
                        || line.contains("segfault")
                        || line.contains("oom-killer")
                        || line.contains("blocked")
                    {
                        handle_line(line, "Syslog", &app_state, &pool).await;
                    }
                }
            }
            Err(error) => {
                if is_not_found(&error) {
                    if !missing_log_reported {
                        push_harvest_status(
                            &app_state,
                            "Syslog",
                            &format!("waiting for {path} to be created"),
                        )
                        .await;
                        missing_log_reported = true;
                    }
                } else if is_permission_denied(&error) {
                    if !missing_log_reported {
                        push_harvest_status(
                            &app_state,
                            "Syslog",
                            &format!(
                                "permission denied reading {path} — add your user to the adm group: sudo usermod -aG adm $USER"
                            ),
                        )
                        .await;
                        missing_log_reported = true;
                    }
                } else {
                    push_harvest_error(&app_state, "Syslog", &error).await;
                }
            }
        }

        if sleep_or_shutdown(Duration::from_secs(SYSLOG_POLL_SECS), &mut shutdown).await {
            return;
        }
    }
}

async fn suricata_cleanup_task(
    pool: Pool<Sqlite>,
    app_state: Arc<Mutex<AppState>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if sleep_or_shutdown(Duration::from_secs(SURICATA_CLEANUP_SECS), &mut shutdown).await {
            return;
        }

        match compact_eve_json(&pool).await {
            Ok(pruned) => {
                if pruned > 0 {
                    push_harvest_status(
                        &app_state,
                        "Cleanup",
                        &format!("pruned {pruned} stale entries from eve.json"),
                    )
                    .await;
                }
            }
            Err(error) => {
                push_harvest_error(&app_state, "Cleanup", &error).await;
            }
        }
    }
}

async fn compact_eve_json(pool: &Pool<Sqlite>) -> Result<usize> {
    let blocked_ips = crate::db::get_blocked_ips(pool).await?;
    let blocked_set: HashSet<String> = blocked_ips.into_iter().collect();

    let meta = tokio::fs::metadata(SURICATA_EVE_PATH).await?;
    if meta.len() == 0 {
        return Ok(0);
    }

    let now = Utc::now();
    let tmp_path = format!("{SURICATA_EVE_PATH}.tmp.{}", std::process::id());

    let file = File::open(SURICATA_EVE_PATH).await?;
    let reader = BufReader::new(file);
    let mut lines_iter = reader.lines();
    let mut tmp_file = File::create(&tmp_path).await?;
    let mut total_lines = 0usize;
    let mut kept_lines = 0usize;

    while let Some(line_result) = lines_iter.next_line().await? {
        total_lines += 1;
        let trimmed = line_result.trim();
        if trimmed.is_empty() {
            continue;
        }

        if !trimmed.contains("\"alert\"") && !trimmed.contains("\"http\"") {
            continue;
        }

        let src_ip = extract_json_str(trimmed, "src_ip");
        let timestamp = extract_json_str(trimmed, "timestamp");

        let is_blocked = src_ip.is_some_and(|ip| blocked_set.contains(ip));

        let age_hours = timestamp
            .and_then(parse_iso_timestamp)
            .map_or(i64::MAX, |ts| (now - ts).num_hours());

        let keep = if is_blocked {
            age_hours < EVE_RETENTION_BLOCK_HOURS
        } else {
            age_hours < EVE_RETENTION_NON_BLOCK_HOURS
        };

        if keep {
            tmp_file.write_all(line_result.as_bytes()).await?;
            tmp_file.write_all(b"\n").await?;
            kept_lines += 1;
        }
    }

    tmp_file.flush().await?;
    drop(tmp_file);

    let pruned = total_lines.saturating_sub(kept_lines);
    if pruned == 0 {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Ok(0);
    }

    tokio::fs::rename(&tmp_path, SURICATA_EVE_PATH).await?;

    Ok(pruned)
}

fn extract_json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();

    if rest.starts_with('"') {
        let value_start = 1;
        let value_end = rest[value_start..].find('"')?;
        Some(&rest[value_start..value_start + value_end])
    } else {
        None
    }
}

fn parse_iso_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::is_not_found;

    #[test]
    fn detects_missing_suricata_log_errors() {
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing eve.json",
        ));

        assert!(is_not_found(&error));
    }

    #[test]
    fn keeps_other_harvest_errors_visible() {
        let error = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));

        assert!(!is_not_found(&error));
    }
}
