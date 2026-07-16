use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};
use std::env;

use crate::{constants::DB_URL, models::BlockedIp};

fn resolve_db_url() -> String {
    if running_as_root() {
        let dir = "/var/lib/ravelin";
        let _ = std::fs::create_dir_all(dir);
        format!("sqlite:{dir}/ravelin.db?mode=rwc")
    } else if let Ok(home) = env::var("HOME") {
        let dir = format!("{home}/.ravelin");
        let _ = std::fs::create_dir_all(&dir);
        format!("sqlite:{dir}/ravelin.db?mode=rwc")
    } else {
        DB_URL.to_owned()
    }
}

fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .is_some_and(|uid| uid.trim() == "0")
}

pub async fn init_db() -> Result<Pool<Sqlite>> {
    let db_url = resolve_db_url();
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .with_context(|| format!("failed to open database at {db_url}"))?;

    sqlx::query("PRAGMA journal_mode = WAL")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA synchronous = NORMAL")
        .execute(&pool)
        .await?;
    sqlx::query("PRAGMA busy_timeout = 5000")
        .execute(&pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_at DATETIME NOT NULL,
            reason TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

pub async fn load_blocked(pool: &Pool<Sqlite>) -> Result<Vec<BlockedIp>> {
    let blocked = sqlx::query_as::<_, BlockedIp>("SELECT ip, blocked_at, reason FROM blocked_ips")
        .fetch_all(pool)
        .await?;

    Ok(blocked)
}

pub async fn upsert_blocked(pool: &Pool<Sqlite>, ip: &str, reason: &str) -> Result<DateTime<Utc>> {
    let blocked_at = Utc::now();
    sqlx::query("INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason) VALUES (?, ?, ?)")
        .bind(ip)
        .bind(blocked_at)
        .bind(reason)
        .execute(pool)
        .await?;

    Ok(blocked_at)
}

pub async fn delete_blocked(pool: &Pool<Sqlite>, ip: &str) -> Result<()> {
    sqlx::query("DELETE FROM blocked_ips WHERE ip = ?")
        .bind(ip)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn get_blocked_ips(pool: &Pool<Sqlite>) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT ip FROM blocked_ips")
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|(ip,)| ip).collect())
}
