// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL sessions that remain recoverable when a Spot node disappears.
//!
//! Session advisory locks are owned by the server connection, not the client
//! process. A vanished node therefore does not release its lock until
//! PostgreSQL detects the dead TCP peer. Linux defaults can take hours. Every
//! lake session that owns a long-lived advisory lock is configured with an
//! explicit keepalive/user-timeout envelope, and contenders use observable,
//! bounded `pg_try_advisory_lock` polling instead of blocking silently.

use anyhow::{bail, Context, Result};
use sqlx::postgres::PgConnection;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::time::{Duration, Instant};

const TCP_KEEPALIVES_IDLE: &str = "30";
const TCP_KEEPALIVES_INTERVAL: &str = "10";
const TCP_KEEPALIVES_COUNT: &str = "3";
const TCP_USER_TIMEOUT: &str = "45s";
pub const ADVISORY_LOCK_WAIT: Duration = Duration::from_secs(45);
const ADVISORY_LOCK_POLL: Duration = Duration::from_millis(250);

pub async fn connect_ownership(database_url: &str, application_name: &str) -> Result<sqlx::pool::PoolConnection<Postgres>> {
    validate_application_name(application_name)?;
    let pool = connect_spot_safe_pool(database_url, application_name, 1).await?;
    let mut connection = nanosiem_core::db::pooler::session_connection(&pool).await
        .context("connect direct ownership session")?;
    configure_spot_safe_session(&mut connection, application_name).await?;
    Ok(connection)
}

/// Ordinary one-shot queries use the transaction transport and no session GUCs.
pub async fn connect_spot_safe(database_url: &str, application_name: &str) -> Result<sqlx::pool::PoolConnection<Postgres>> {
    let pool = connect_spot_safe_pool(database_url, application_name, 1).await?;
    Ok(pool.acquire().await?)
}

pub async fn connect_spot_safe_pool(
    database_url: &str,
    application_name: &str,
    max_connections: u32,
) -> Result<PgPool> {
    validate_application_name(application_name)?;
    if max_connections == 0 {
        bail!("PostgreSQL pool must allow at least one connection");
    }
    let options = nanosiem_core::db::pooler::options(database_url)?
        .application_name(application_name);
    Ok(nanosiem_core::db::connection_budget::pool_options(max_connections)
        .connect_lazy_with(options))
}

pub async fn configure_spot_safe_session(
    connection: &mut PgConnection,
    application_name: &str,
) -> Result<()> {
    validate_application_name(application_name)?;
    for (setting, value) in [
        ("application_name", application_name),
        ("tcp_keepalives_idle", TCP_KEEPALIVES_IDLE),
        ("tcp_keepalives_interval", TCP_KEEPALIVES_INTERVAL),
        ("tcp_keepalives_count", TCP_KEEPALIVES_COUNT),
        ("tcp_user_timeout", TCP_USER_TIMEOUT),
    ] {
        sqlx::query("SELECT set_config($1, $2, false)")
            .bind(setting)
            .bind(value)
            .execute(&mut *connection)
            .await
            .with_context(|| format!("configure PostgreSQL {setting}"))?;
    }
    Ok(())
}

pub async fn acquire_advisory_lock(
    connection: &mut PgConnection,
    lock_name: &str,
    description: &'static str,
) -> Result<()> {
    acquire_advisory_lock_with_wait(connection, lock_name, description, ADVISORY_LOCK_WAIT).await
}

/// Poll on the owning backend, including diagnostics in the total wait budget.
pub async fn acquire_advisory_lock_with_wait(
    connection: &mut PgConnection,
    lock_name: &str,
    description: &'static str,
    wait: Duration,
) -> Result<()> {
    validate_lock_name(lock_name)?;
    let started = Instant::now();
    tokio::time::timeout(wait, async {
        let mut next_diagnostic = Duration::ZERO;
        loop {
            let acquired: bool = sqlx::query_scalar(
                "SELECT pg_try_advisory_lock(hashtextextended($1, 0))",
            )
            .bind(lock_name)
            .fetch_one(&mut *connection)
            .await?;
            if acquired {
                tracing::info!(description, waited_ms = started.elapsed().as_millis(),
                    "acquired PostgreSQL advisory lock");
                return Ok(());
            }
            if started.elapsed() >= next_diagnostic {
                // Same database and the bigint advisory-lock namespace. Do not
                // open another session just to diagnose ownership contention.
                let holders: Vec<(i32, Option<String>)> = sqlx::query_as(
                    "SELECT l.pid, a.backend_start::text FROM pg_locks l \
                     LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
                     WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1 \
                     AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                     AND l.classid::bigint = ((hashtextextended($1, 0) >> 32) & 4294967295) \
                     AND l.objid::bigint = (hashtextextended($1, 0) & 4294967295)",
                )
                .bind(lock_name)
                .fetch_all(&mut *connection)
                .await?;
                tracing::info!(description, ?holders, waited_ms = started.elapsed().as_millis(),
                    "waiting for PostgreSQL advisory lock (holder pid, backend_start)");
                next_diagnostic = started.elapsed() + Duration::from_secs(5);
            }
            tokio::time::sleep(ADVISORY_LOCK_POLL).await;
        }
    })
    .await
    .with_context(|| format!("timed out waiting for {description} PostgreSQL advisory lock"))?
}

pub async fn acquire_advisory_xact_lock(
    transaction: &mut Transaction<'_, Postgres>,
    lock_name: &str,
    description: &'static str,
) -> Result<()> {
    validate_lock_name(lock_name)?;
    let started = Instant::now();
    let mut waiting_logged = false;
    loop {
        let acquired: bool =
            sqlx::query("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS acquired")
                .bind(lock_name)
                .fetch_one(&mut **transaction)
                .await?
                .try_get("acquired")?;
        if acquired {
            tracing::info!(
                description,
                waited_ms = started.elapsed().as_millis(),
                "acquired PostgreSQL transaction advisory lock"
            );
            return Ok(());
        }
        if !waiting_logged {
            tracing::info!(
                description,
                "waiting for PostgreSQL transaction advisory lock"
            );
            waiting_logged = true;
        }
        if started.elapsed() >= ADVISORY_LOCK_WAIT {
            bail!("timed out waiting for {description} PostgreSQL transaction advisory lock");
        }
        tokio::time::sleep(ADVISORY_LOCK_POLL).await;
    }
}

fn validate_lock_name(lock_name: &str) -> Result<()> {
    if lock_name.is_empty() || lock_name.len() > 1_024 || lock_name.chars().any(char::is_control) {
        bail!("PostgreSQL advisory-lock identity is invalid");
    }
    Ok(())
}

fn validate_application_name(application_name: &str) -> Result<()> {
    if application_name.is_empty()
        || application_name.len() > 128
        || !application_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("PostgreSQL application name is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires NAN2418_TEST_DATABASE_URL pointing at disposable PostgreSQL"]
    async fn advisory_wait_times_out_then_succeeds_after_owner_closes() -> Result<()> {
        let url = std::env::var("NAN2418_TEST_DATABASE_URL")?;
        let lock = uuid::Uuid::new_v4().to_string();
        let mut owner = connect_ownership(&url, "nan2418-owner").await?;
        let mut contender = connect_ownership(&url, "nan2418-contender").await?;
        acquire_advisory_lock(&mut owner, &lock, "test").await?;
        let error = acquire_advisory_lock_with_wait(
            &mut contender, &lock, "test", Duration::from_millis(500),
        ).await.unwrap_err();
        assert!(error.to_string().contains("timed out waiting for test"));
        owner.close().await?;
        acquire_advisory_lock_with_wait(
            &mut contender, &lock, "test", Duration::from_secs(2),
        ).await?;
        contender.close().await?;
        Ok(())
    }

    #[test]
    fn application_names_are_bounded_and_log_safe() {
        assert!(validate_application_name("nano-lake-bronze-publish").is_ok());
        assert!(validate_application_name("").is_err());
        assert!(validate_application_name("lake\nforged").is_err());
        assert!(validate_application_name(&"a".repeat(129)).is_err());
    }

    #[test]
    fn dead_session_and_lock_wait_bounds_are_shorter_than_spot_notice() {
        assert_eq!(TCP_KEEPALIVES_IDLE, "30");
        assert_eq!(TCP_KEEPALIVES_INTERVAL, "10");
        assert_eq!(TCP_KEEPALIVES_COUNT, "3");
        assert_eq!(TCP_USER_TIMEOUT, "45s");
        assert!(ADVISORY_LOCK_WAIT < Duration::from_secs(120));
    }
}

#[cfg(test)]
mod transaction_pool_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires local transaction PgBouncer; see scripts/pgbouncer/local"]
    async fn transaction_pool_lock_commit_and_rollback_release() -> Result<()> {
        use sqlx::Connection;
        let url = std::env::var("PGBOUNCER_TEST_DATABASE_URL")?;
        let pool = connect_spot_safe_pool(&url, "transaction-pool-test", 4).await?;
        assert_eq!(pool.options().get_min_connections(), 0);
        assert!(pool.options().get_idle_timeout().unwrap() <= Duration::from_secs(60));
        assert!(pool.options().get_max_lifetime().unwrap() <= Duration::from_secs(1800));
        let key = uuid::Uuid::new_v4().to_string();
        for commit in [true, false] {
            let mut owner = pool.begin().await?;
            acquire_advisory_xact_lock(&mut owner, &key, "test ownership").await?;
            let mut contender = pool.begin().await?;
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(&key).fetch_one(&mut *contender).await?;
            assert!(!acquired);
            if commit { owner.commit().await?; } else { owner.rollback().await?; }
            acquire_advisory_xact_lock(&mut contender, &key, "test handoff").await?;
            assert_eq!((&mut *contender).cached_statements_size(), 0);
            contender.commit().await?;
        }
        pool.close().await;
        Ok(())
    }
}
