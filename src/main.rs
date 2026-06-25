mod actions;
mod constants;
mod db;
mod engine;
mod firewall;
mod harvest;
mod models;
mod network;
mod parser;
mod ui;

use anyhow::{Result, bail};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{env, io, sync::Arc};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{Mutex, watch},
};

use crate::{
    models::{AppState, RuntimeMode},
    network::{get_local_ips, trusted_ips_from_env},
};

#[tokio::main]
async fn main() -> Result<()> {
    let runtime_mode = RuntimeMode::from_arg(env::args().nth(1).as_deref());
    println!(
        "Starting Ravelin {} ({})...",
        runtime_mode.label(),
        runtime_mode.command_hint()
    );

    if runtime_mode.requires_privileged_setup() {
        ensure_root(runtime_mode)?;
        println!("Ensuring Ravelin dependencies, firewall rules, and database are ready...");
        firewall::system_self_check()?;
    } else {
        println!("Opening local TUI. Start protection with: sudo systemctl start ravelin");
    }

    let pool = db::init_db().await?;
    let start_time = db::get_start_time(&pool).await?;
    let initial_blocked = db::load_blocked(&pool).await?;

    if runtime_mode.requires_privileged_setup() && !initial_blocked.is_empty() {
        println!(
            "Restoring firewall rules for {} blocked IPs...",
            initial_blocked.len()
        );
        firewall::restore_blocked_ips(initial_blocked.iter().map(|blocked| blocked.ip.as_str()))?;
    }

    let app_state = build_app_state(initial_blocked, start_time, runtime_mode);

    match runtime_mode {
        RuntimeMode::Tui => run_tui(pool, app_state).await,
        RuntimeMode::Daemon => run_daemon(pool, app_state).await,
        RuntimeMode::Standalone => run_standalone(pool, app_state).await,
    }
}

fn ensure_root(runtime_mode: RuntimeMode) -> Result<()> {
    if running_as_root() {
        return Ok(());
    }

    bail!(
        "Ravelin {} needs root for Suricata, ipset, and firewall setup. Run: {}",
        runtime_mode.label(),
        runtime_mode.command_hint()
    );
}

fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|uid| uid.trim() == "0")
}

fn build_app_state(
    initial_blocked: Vec<models::BlockedIp>,
    start_time: chrono::DateTime<chrono::Utc>,
    runtime_mode: RuntimeMode,
) -> Arc<Mutex<AppState>> {
    let mut local_ips = get_local_ips();
    local_ips.extend(trusted_ips_from_env());
    Arc::new(Mutex::new(AppState::new(
        initial_blocked,
        local_ips,
        start_time,
        runtime_mode,
    )))
}

async fn run_tui(pool: sqlx::Pool<sqlx::Sqlite>, app_state: Arc<Mutex<AppState>>) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    harvest::start_harvesters(app_state.clone(), pool.clone(), shutdown_rx);
    let result = with_terminal(pool, app_state).await;
    let _ = shutdown_tx.send(true);
    result
}

async fn run_standalone(
    pool: sqlx::Pool<sqlx::Sqlite>,
    app_state: Arc<Mutex<AppState>>,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    harvest::start_harvesters(app_state.clone(), pool.clone(), shutdown_rx);
    let result = with_terminal(pool, app_state).await;
    let _ = shutdown_tx.send(true);
    result
}

async fn run_daemon(pool: sqlx::Pool<sqlx::Sqlite>, app_state: Arc<Mutex<AppState>>) -> Result<()> {
    println!("Ravelin backbone running. Stop it with: systemctl stop ravelin.service");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    harvest::start_harvesters(app_state, pool, shutdown_rx);
    wait_for_shutdown_signal().await?;
    let _ = shutdown_tx.send(true);
    Ok(())
}

async fn with_terminal(
    pool: sqlx::Pool<sqlx::Sqlite>,
    app_state: Arc<Mutex<AppState>>,
) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = ui::run_ui(&mut terminal, pool, app_state).await;

    let cleanup_result = execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .and_then(|()| {
        disable_raw_mode()?;
        terminal.show_cursor()
    });

    cleanup_result?;
    result
}

async fn wait_for_shutdown_signal() -> Result<()> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }

    Ok(())
}
