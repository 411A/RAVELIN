use anyhow::{Context, Result, bail};
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{
    db, firewall,
    models::{AppState, BlockedIp},
    network::{is_blockable_ip, normalize_ipv4},
};

pub async fn block_ip(
    ip: String,
    reason: String,
    pool: &Pool<Sqlite>,
    state: &Arc<Mutex<AppState>>,
) -> Result<()> {
    let ip = normalize_ipv4(&ip).with_context(|| format!("invalid IPv4 address: {ip}"))?;

    if !is_blockable_ip(&ip) {
        bail!("refusing to block non-public IPv4 address {ip}");
    }

    {
        let app = state.lock().await;
        if app.local_ips.contains(&ip) {
            bail!("refusing to block local server IP {ip}");
        }
        if app.is_blocked(&ip) {
            return Ok(());
        }
    }

    firewall::block_ipset(&ip)?;
    let blocked_at = db::upsert_blocked(pool, &ip, &reason).await?;

    let mut app = state.lock().await;
    app.suspects.retain(|suspect| suspect.ip != ip);

    if let Some(existing) = app.blocked.iter_mut().find(|blocked| blocked.ip == ip) {
        existing.blocked_at = blocked_at;
        existing.reason.clone_from(&reason);
    } else {
        app.blocked.push(BlockedIp {
            ip: ip.clone(),
            blocked_at,
            reason: reason.clone(),
        });
    }

    app.push_log(format!("🚫 [BLOCKED] {ip} | {reason}"));
    app.clamp_selected_indexes();
    drop(app);

    Ok(())
}

pub async fn unblock_ip(
    ip: String,
    pool: &Pool<Sqlite>,
    state: &Arc<Mutex<AppState>>,
) -> Result<()> {
    let ip = normalize_ipv4(&ip).with_context(|| format!("invalid IPv4 address: {ip}"))?;

    firewall::unblock_ipset(&ip)?;
    db::delete_blocked(pool, &ip).await?;

    let mut app = state.lock().await;
    app.blocked.retain(|blocked| blocked.ip != ip);
    app.push_log(format!("✅ [UNBLOCKED] {ip}"));
    app.clamp_selected_indexes();
    drop(app);

    Ok(())
}

pub async fn push_action_error(state: &Arc<Mutex<AppState>>, action: &str, error: &anyhow::Error) {
    state.lock().await.push_log(format!("❌ {action}: {error}"));
}
