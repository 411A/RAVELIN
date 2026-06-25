use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use sqlx::{Pool, Sqlite};
use std::{io::Stdout, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use crate::{
    actions,
    constants::{
        BACKBONE_SERVICE_NAME, EVENT_POLL_INTERVAL_MS, MANUAL_BLOCK_REASON,
        MAX_COMMAND_BUFFER_CHARS,
    },
    models::{ActiveWindow, AppState, InputMode, Suspect},
    network::normalize_ipv4,
};

pub async fn run_ui(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    pool: Pool<Sqlite>,
    state: Arc<Mutex<AppState>>,
) -> Result<()> {
    loop {
        {
            let app = state.lock().await;
            terminal.draw(|frame| ui_render(frame, &app))?;
        }

        if !event::poll(Duration::from_millis(EVENT_POLL_INTERVAL_MS))? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };

        let term_height = terminal.size()?.height;
        let list_visible_height = (term_height * 60 / 100).saturating_sub(2) as usize;
        let action = {
            let mut app = state.lock().await;
            handle_key_code(key.code, &mut app, list_visible_height)
        };

        match action {
            UiAction::Quit => return Ok(()),
            UiAction::Block(ip) => {
                if let Err(error) =
                    actions::block_ip(ip, MANUAL_BLOCK_REASON.to_owned(), &pool, &state).await
                {
                    actions::push_action_error(&state, "manual block failed", &error).await;
                }
            }
            UiAction::Unblock(ip) => {
                if let Err(error) = actions::unblock_ip(ip, &pool, &state).await {
                    actions::push_action_error(&state, "manual unblock failed", &error).await;
                }
            }
            UiAction::None => {}
        }
    }
}

fn ui_render(frame: &mut Frame<'_>, app: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(60),
            Constraint::Length(3),
        ])
        .split(frame.area());

    render_logs(frame, app, chunks[0]);

    if app.detail_open {
        render_detail(frame, app, chunks[1]);
    } else {
        let mid_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(chunks[1]);
        render_suspects(frame, app, mid_chunks[0]);
        render_blocked(frame, app, mid_chunks[1]);
    }

    render_command_bar(frame, app, chunks[2]);
}

fn render_logs(frame: &mut Frame<'_>, app: &AppState, area: Rect) {
    let visible = area.height.saturating_sub(2) as usize;
    let total = app.logs.len();
    let end = total.saturating_sub(app.logs_scroll);
    let start = end.saturating_sub(visible);
    let lines = app
        .logs
        .get(start..end)
        .unwrap_or(&[])
        .iter()
        .rev()
        .map(|line| ListItem::new(Line::from(line.as_str())))
        .collect::<Vec<_>>();

    let widget = List::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 📡 LIVE FEED (Docker/Syslog/Suricata)"),
    );
    frame.render_widget(widget, area);
}

fn render_detail(frame: &mut Frame<'_>, app: &AppState, area: Rect) {
    let Some(ip) = &app.detail_ip else {
        let empty = Paragraph::new("No history for selected IP")
            .block(Block::default().borders(Borders::ALL).title(" DETAIL "));
        frame.render_widget(empty, area);
        return;
    };

    let history: &[String] = app.ip_history.get(ip).map_or(&[], Vec::as_slice);
    let total = history.len();
    let visible = area.height.saturating_sub(2) as usize;
    let start = app.detail_scroll.min(total.saturating_sub(1));
    let end = (start + visible).min(total);

    let lines = history[start..end]
        .iter()
        .map(|line| {
            let content = line.chars().skip(app.detail_scroll_x).collect::<String>();
            ListItem::new(Line::from(content))
        })
        .collect::<Vec<_>>();

    let title = format!(" 🔍 INSPECT: {ip} | Scroll: {start}/{total} | < > Horz ");
    let widget = List::new(lines).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(widget, area);
}

fn render_suspects(frame: &mut Frame<'_>, app: &AppState, area: Rect) {
    let indices = suspect_indices(app);
    let visible = area.height.saturating_sub(2) as usize;
    let total = indices.len();
    let start = app.suspects_scroll.min(total);
    let end = (start + visible).min(total);

    let suspects = indices[start..end]
        .iter()
        .enumerate()
        .map(|(offset, suspect_idx)| {
            let filtered_idx = start + offset;
            let suspect = &app.suspects[*suspect_idx];
            let style = if filtered_idx == app.selected_suspect_idx
                && app.active_window == ActiveWindow::Suspects
            {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::Red)
            };
            suspect_list_item(filtered_idx, suspect).style(style)
        })
        .collect::<Vec<_>>();

    let widget = List::new(suspects).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 🕵️ SUSPECTS (Enter: Block) "),
    );
    frame.render_widget(widget, area);
}

fn render_blocked(frame: &mut Frame<'_>, app: &AppState, area: Rect) {
    let visible = area.height.saturating_sub(2) as usize;
    let total = app.blocked.len();
    let start = app.blocked_scroll.min(total);
    let end = (start + visible).min(total);

    let blocked = app.blocked[start..end]
        .iter()
        .enumerate()
        .map(|(offset, blocked)| {
            let index = start + offset;
            let style =
                if index == app.selected_block_idx && app.active_window == ActiveWindow::Blocked {
                    Style::default().fg(Color::Black).bg(Color::Green)
                } else {
                    Style::default().fg(Color::Gray)
                };
            ListItem::new(format!(
                "{} | {} | {} | Since: {}",
                index + 1,
                blocked.ip,
                blocked.reason,
                blocked.blocked_at.format("%Y-%m-%d %H:%M:%S")
            ))
            .style(style)
        })
        .collect::<Vec<_>>();

    let widget = List::new(blocked).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" 🚫 BLOCKED (Enter: Unblock) "),
    );
    frame.render_widget(widget, area);
}

fn render_command_bar(frame: &mut Frame<'_>, app: &AppState, area: Rect) {
    let input_text = if app.input_mode == InputMode::Command {
        app.input_buffer.clone()
    } else {
        format!(
            "{} | ⚔️ ACTIVE DEFENSE MODE | [TAB] Lists | [j/k] Move | [i] Inspect | [/] Search | [Esc/Q] Exit TUI | systemctl stop {BACKBONE_SERVICE_NAME} stops protection",
            app.runtime_mode.label()
        )
    };

    let widget = Paragraph::new(input_text)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" COMMAND CENTER "),
        );
    frame.render_widget(widget, area);
}

fn suspect_list_item(index: usize, suspect: &Suspect) -> ListItem<'_> {
    ListItem::new(format!(
        "{} | [{}] {} | Score: {} | {}",
        index + 1,
        suspect.source_type,
        suspect.ip,
        suspect.score,
        suspect.reason
    ))
}

fn handle_key_code(code: KeyCode, app: &mut AppState, list_visible_height: usize) -> UiAction {
    clamp_ui_selection(app);
    if code == KeyCode::Esc {
        if app.detail_open {
            app.detail_open = false;
            app.detail_ip = None;
            app.detail_scroll = 0;
            app.detail_scroll_x = 0;
            return UiAction::None;
        }
        return UiAction::Quit;
    }

    match app.input_mode {
        InputMode::Normal => handle_normal_key(code, app, list_visible_height),
        InputMode::Command => handle_command_key(code, app),
    }
}

fn handle_normal_key(code: KeyCode, app: &mut AppState, list_visible_height: usize) -> UiAction {
    match code {
        KeyCode::Char('q') => UiAction::Quit,
        KeyCode::Char(':') => {
            app.input_mode = InputMode::Command;
            app.input_buffer.clear();
            app.input_buffer.push(':');
            UiAction::None
        }
        KeyCode::Char('/') => {
            app.input_mode = InputMode::Command;
            app.input_buffer.clear();
            app.input_buffer.push('/');
            UiAction::None
        }
        KeyCode::Tab => {
            app.active_window = if app.active_window == ActiveWindow::Suspects {
                ActiveWindow::Blocked
            } else {
                ActiveWindow::Suspects
            };
            UiAction::None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            move_selection_down(app, list_visible_height);
            UiAction::None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            move_selection_up(app);
            UiAction::None
        }
        KeyCode::Left | KeyCode::Char('h') => {
            if app.detail_open {
                app.detail_scroll_x = app.detail_scroll_x.saturating_sub(5);
            }
            UiAction::None
        }
        KeyCode::Right | KeyCode::Char('l') => {
            if app.detail_open {
                app.detail_scroll_x = app.detail_scroll_x.saturating_add(5);
            }
            UiAction::None
        }
        KeyCode::PageDown => {
            page_down(app);
            UiAction::None
        }
        KeyCode::PageUp => {
            page_up(app);
            UiAction::None
        }
        KeyCode::Enter => enter_selection(app),
        KeyCode::Char('i') => {
            inspect_selected_suspect(app);
            UiAction::None
        }
        _ => UiAction::None,
    }
}

fn handle_command_key(code: KeyCode, app: &mut AppState) -> UiAction {
    match code {
        KeyCode::Enter => run_command_buffer(app),
        KeyCode::Char(ch) => {
            if app.input_buffer.chars().count() >= MAX_COMMAND_BUFFER_CHARS {
                return UiAction::None;
            }
            app.input_buffer.push(ch);
            UiAction::None
        }
        KeyCode::Backspace => {
            app.input_buffer.pop();
            UiAction::None
        }
        _ => UiAction::None,
    }
}

fn run_command_buffer(app: &mut AppState) -> UiAction {
    let command = app.input_buffer.trim().to_owned();
    app.input_mode = InputMode::Normal;
    app.input_buffer.clear();

    if let Some(ip) = command.strip_prefix(":block ").and_then(parse_command_ip) {
        return UiAction::Block(ip);
    }

    if let Some(ip) = command.strip_prefix(":unblock ").and_then(parse_command_ip) {
        return UiAction::Unblock(ip);
    }

    if let Some(ip) = command
        .strip_prefix(":whitelist ")
        .and_then(parse_command_ip)
    {
        app.whitelisted_dynamic.insert(ip.clone());
        app.suspects.retain(|suspect| suspect.ip != ip);
        app.push_log(&format!("🟢 [WHITELISTED] {ip}"));
        app.clamp_selected_indexes();
        return UiAction::None;
    }

    if command == ":clearlogs" {
        app.logs.clear();
    } else if let Some(pattern) = command.strip_prefix(":search ") {
        set_search_filter(app, pattern.trim());
    } else if command == ":clearfilter" {
        app.search_filter = None;
        app.suspects_scroll = 0;
        app.selected_suspect_idx = 0;
    } else if let Some(pattern) = command.strip_prefix('/') {
        set_search_filter(app, pattern.trim());
    } else if !command.is_empty() {
        app.push_log(&format!("Unknown: {command}"));
    }

    UiAction::None
}

fn move_selection_down(app: &mut AppState, visible_height: usize) {
    if app.detail_open {
        app.detail_scroll = app.detail_scroll.saturating_add(1);
        return;
    }

    if app.active_window == ActiveWindow::Suspects {
        let count = suspect_count(app);
        if app.selected_suspect_idx + 1 < count {
            app.selected_suspect_idx += 1;
            if app.selected_suspect_idx >= app.suspects_scroll + visible_height {
                app.suspects_scroll = app.selected_suspect_idx + 1 - visible_height;
            }
        }
    } else if app.selected_block_idx + 1 < app.blocked.len() {
        app.selected_block_idx += 1;
        if app.selected_block_idx >= app.blocked_scroll + visible_height {
            app.blocked_scroll = app.selected_block_idx + 1 - visible_height;
        }
    }
}

fn move_selection_up(app: &mut AppState) {
    if app.detail_open {
        app.detail_scroll = app.detail_scroll.saturating_sub(1);
        return;
    }

    if app.active_window == ActiveWindow::Suspects {
        app.selected_suspect_idx = app.selected_suspect_idx.saturating_sub(1);
        if app.selected_suspect_idx < app.suspects_scroll {
            app.suspects_scroll = app.selected_suspect_idx;
        }
    } else {
        app.selected_block_idx = app.selected_block_idx.saturating_sub(1);
        if app.selected_block_idx < app.blocked_scroll {
            app.blocked_scroll = app.selected_block_idx;
        }
    }
}

const fn page_down(app: &mut AppState) {
    if app.detail_open {
        app.detail_scroll = app.detail_scroll.saturating_add(10);
    } else {
        app.logs_scroll = app.logs_scroll.saturating_sub(10);
    }
}

const fn page_up(app: &mut AppState) {
    if app.detail_open {
        app.detail_scroll = app.detail_scroll.saturating_sub(10);
    } else {
        app.logs_scroll = app.logs_scroll.saturating_add(10);
    }
}

fn enter_selection(app: &AppState) -> UiAction {
    if app.detail_open {
        return UiAction::None;
    }

    if app.active_window == ActiveWindow::Suspects {
        selected_suspect_ip(app).map_or(UiAction::None, UiAction::Block)
    } else {
        app.blocked
            .get(app.selected_block_idx)
            .map_or(UiAction::None, |blocked| {
                UiAction::Unblock(blocked.ip.clone())
            })
    }
}

fn inspect_selected_suspect(app: &mut AppState) {
    if app.active_window != ActiveWindow::Suspects {
        return;
    }

    if let Some(ip) = selected_suspect_ip(app) {
        app.detail_open = true;
        app.detail_ip = Some(ip);
        app.detail_scroll = 0;
        app.detail_scroll_x = 0;
    }
}

fn set_search_filter(app: &mut AppState, pattern: &str) {
    if pattern.is_empty() {
        app.search_filter = None;
    } else {
        app.search_filter = Some(pattern.to_owned());
    }
    app.suspects_scroll = 0;
    app.selected_suspect_idx = 0;
}

fn selected_suspect_ip(app: &AppState) -> Option<String> {
    suspect_indices(app)
        .get(app.selected_suspect_idx)
        .and_then(|idx| app.suspects.get(*idx))
        .map(|suspect| suspect.ip.clone())
}

fn parse_command_ip(raw: &str) -> Option<String> {
    raw.split_whitespace().next().and_then(normalize_ipv4)
}

fn suspect_count(app: &AppState) -> usize {
    suspect_indices(app).len()
}

fn suspect_indices(app: &AppState) -> Vec<usize> {
    let Some(filter) = app
        .search_filter
        .as_ref()
        .filter(|filter| !filter.is_empty())
    else {
        return (0..app.suspects.len()).collect();
    };

    let filter = filter.to_lowercase();
    app.suspects
        .iter()
        .enumerate()
        .filter_map(|(idx, suspect)| suspect_matches_filter(suspect, &filter).then_some(idx))
        .collect()
}

fn suspect_matches_filter(suspect: &Suspect, filter: &str) -> bool {
    suspect.ip.to_lowercase().contains(filter)
        || suspect.reason.to_lowercase().contains(filter)
        || suspect.source_type.to_lowercase().contains(filter)
}

fn clamp_ui_selection(app: &mut AppState) {
    let suspect_count = suspect_count(app);
    app.selected_suspect_idx = clamp_index(app.selected_suspect_idx, suspect_count);
    app.suspects_scroll = app.suspects_scroll.min(suspect_count.saturating_sub(1));

    app.selected_block_idx = clamp_index(app.selected_block_idx, app.blocked.len());
    app.blocked_scroll = app.blocked_scroll.min(app.blocked.len().saturating_sub(1));
}

fn clamp_index(index: usize, len: usize) -> usize {
    if len == 0 { 0 } else { index.min(len - 1) }
}

enum UiAction {
    None,
    Quit,
    Block(String),
    Unblock(String),
}
