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

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, sync::Arc};
use tokio::sync::Mutex;

use crate::{models::AppState, network::get_local_ips};

#[tokio::main]
async fn main() -> Result<()> {
    println!("Starting Ravelin TUI - ensuring dependencies and DB...");

    firewall::system_self_check()?;

    let pool = db::init_db().await?;
    let start_time = db::get_start_time(&pool).await?;
    let initial_blocked = db::load_blocked(&pool).await?;

    if !initial_blocked.is_empty() {
        println!(
            "Restoring firewall rules for {} blocked IPs...",
            initial_blocked.len()
        );
        firewall::restore_blocked_ips(initial_blocked.iter().map(|blocked| blocked.ip.as_str()))?;
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let local_ips = get_local_ips();
    let app_state = Arc::new(Mutex::new(AppState::new(
        initial_blocked,
        local_ips,
        start_time,
    )));

    harvest::start_harvesters(app_state.clone(), pool.clone());
    let result = ui::run_ui(&mut terminal, pool, app_state).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}
