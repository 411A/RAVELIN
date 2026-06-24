use anyhow::Result;
use sqlx::{Pool, Sqlite};
use std::{io::SeekFrom, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    sync::Mutex,
    sync::watch,
    time::{self, Duration},
};

use crate::{
    actions,
    constants::{SURICATA_EVE_PATH, SURICATA_MAX_LINES_PER_POLL, SURICATA_POLL_SECS},
    engine::process_log_line,
    models::AppState,
};

pub fn start_harvesters(
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(follow_file(
        FileFollower {
            path: SURICATA_EVE_PATH,
            source: "Suricata",
            interval: Duration::from_secs(SURICATA_POLL_SECS),
            lightweight_suricata_filter: true,
            max_lines: SURICATA_MAX_LINES_PER_POLL,
        },
        app_state,
        pool,
        shutdown,
    ));
}

#[derive(Clone, Copy)]
struct FileFollower {
    path: &'static str,
    source: &'static str,
    interval: Duration,
    lightweight_suricata_filter: bool,
    max_lines: usize,
}

async fn follow_file(
    config: FileFollower,
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut position = 0;
    let mut initialized = false;
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
                            &format!("waiting for {} to be created by Suricata", config.path),
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

    if let Err(error) = actions::block_ip(auto_block.ip, auto_block.reason, pool, app_state).await {
        actions::push_action_error(app_state, "auto-block failed", &error).await;
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

async fn sleep_or_shutdown(interval: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = time::sleep(interval) => false,
        changed = shutdown.changed() => changed.is_ok() && *shutdown.borrow(),
    }
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
