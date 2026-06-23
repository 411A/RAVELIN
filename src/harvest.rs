use anyhow::Result;
use sqlx::{Pool, Sqlite};
use std::{io::SeekFrom, path::Path, sync::Arc};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncSeekExt, BufReader},
    process::Command as TokioCommand,
    sync::Mutex,
    sync::watch,
    time::{self, Duration},
};

use crate::{
    actions,
    constants::{
        AUTH_LOG_PATH, DOCKER_LOG_SINCE_SECS, DOCKER_LOG_TAIL, DOCKER_POLL_SECS, SECURE_LOG_PATH,
        SSH_POLL_SECS, SURICATA_EVE_PATH, SURICATA_MAX_LINES_PER_POLL, SURICATA_POLL_SECS,
    },
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
        app_state.clone(),
        pool.clone(),
        shutdown.clone(),
    ));

    tokio::spawn(follow_auth_log(
        Duration::from_secs(SSH_POLL_SECS),
        app_state.clone(),
        pool.clone(),
        shutdown.clone(),
    ));

    tokio::spawn(harvest_docker_logs(
        Duration::from_secs(DOCKER_POLL_SECS),
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

async fn follow_auth_log(
    interval: Duration,
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut active_path = "";
    let mut position = 0;
    let mut initialized = false;

    loop {
        let path = if Path::new(AUTH_LOG_PATH).exists() {
            AUTH_LOG_PATH
        } else {
            SECURE_LOG_PATH
        };

        if path != active_path {
            active_path = path;
            position = 0;
            initialized = false;
        }

        match read_new_lines(
            path,
            &mut position,
            &mut initialized,
            false,
            crate::constants::DEFAULT_MAX_LINES_PER_POLL,
        )
        .await
        {
            Ok(lines) => {
                for line in lines {
                    handle_line(&line, "SSH", &app_state, &pool).await;
                }
            }
            Err(error) => {
                push_harvest_error(&app_state, "SSH", &error).await;
            }
        }

        if sleep_or_shutdown(interval, &mut shutdown).await {
            return;
        }
    }
}

async fn follow_file(
    config: FileFollower,
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut position = 0;
    let mut initialized = false;

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
                for line in lines {
                    handle_line(&line, config.source, &app_state, &pool).await;
                }
            }
            Err(error) => {
                push_harvest_error(&app_state, config.source, &error).await;
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

async fn harvest_docker_logs(
    interval: Duration,
    app_state: Arc<Mutex<AppState>>,
    pool: Pool<Sqlite>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if let Ok(container_ids) = docker_container_ids().await {
            for id in container_ids {
                if let Ok(lines) = docker_recent_logs(&id).await {
                    let source = format!("Docker-{}", id.chars().take(4).collect::<String>());
                    for line in lines {
                        handle_line(&line, &source, &app_state, &pool).await;
                    }
                }
            }
        }

        if sleep_or_shutdown(interval, &mut shutdown).await {
            return;
        }
    }
}

async fn docker_container_ids() -> Result<Vec<String>> {
    let output = TokioCommand::new("docker")
        .args(["ps", "-q"])
        .output()
        .await?;
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .take(crate::constants::DOCKER_MAX_LINES_PER_POLL)
        .collect();

    Ok(ids)
}

async fn docker_recent_logs(id: &str) -> Result<Vec<String>> {
    let since = format!("{DOCKER_LOG_SINCE_SECS}s");
    let output = TokioCommand::new("docker")
        .args(["logs", "--since", &since, "--tail", DOCKER_LOG_TAIL, id])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|line| !line.trim().is_empty())
        .map(ToOwned::to_owned)
        .collect();

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

async fn sleep_or_shutdown(interval: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = time::sleep(interval) => false,
        changed = shutdown.changed() => changed.is_ok() && *shutdown.borrow(),
    }
}
