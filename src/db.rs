use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Row, Sqlite, sqlite::SqlitePoolOptions};

use crate::{constants::DB_URL, models::BlockedIp};

pub async fn init_db() -> Result<Pool<Sqlite>> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(DB_URL)
        .await?;

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

pub async fn get_start_time(pool: &Pool<Sqlite>) -> Result<DateTime<Utc>> {
    let row = sqlx::query("SELECT value FROM system_state WHERE key = 'start_time'")
        .fetch_optional(pool)
        .await?;

    if let Some(row) = row {
        let ts_str: String = row.try_get(0)?;
        if let Ok(ts) = DateTime::parse_from_rfc3339(&ts_str) {
            return Ok(ts.with_timezone(&Utc));
        }
    }

    let now = Utc::now();
    sqlx::query("INSERT OR REPLACE INTO system_state (key, value) VALUES ('start_time', ?)")
        .bind(now.to_rfc3339())
        .execute(pool)
        .await?;

    Ok(now)
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
