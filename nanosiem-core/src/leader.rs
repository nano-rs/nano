// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL advisory lock-based leader election
//!
//! Ensures exactly one replica runs leader-only tasks. Uses `pg_try_advisory_lock`
//! on a dedicated connection — if the leader pod crashes, PostgreSQL closes the
//! connection and releases the lock automatically, allowing another instance to
//! take over.
//!
//! IMPORTANT: The connection MUST be opened outside the pool. Advisory locks are
//! session-level — returning a pooled connection does not release the lock, so
//! on the next retry the election would deadlock against itself.
//!
//! Used by both the Jobs service (scheduler leadership) and the Search service
//! (active/standby traffic gating).

use sqlx::{Connection, PgConnection, PgPool};
use std::future::Future;
use tokio::sync::watch;

use crate::shutdown::ShutdownToken;

/// Well-known lock IDs for each service.
pub mod lock_ids {
    /// API scheduler leader (`NSLEAD` in hex) — used for tuning + enrichment sync.
    pub const API_SCHEDULER: i64 = 0x4e53_4c45_4144;
    /// Search active/standby leader (`NSSEAC` in hex).
    pub const SEARCH_ACTIVE: i64 = 0x4e53_5345_4143;
    /// Signal processor leader (`NSSGPR` in hex) — serial watermark processing.
    pub const SIGNAL_PROCESSOR: i64 = 0x4e53_5349_4750;
    /// Disk pressure monitor leader (`NSDISC` in hex).
    pub const DISK_PRESSURE: i64 = 0x4e53_4449_534b;
}

/// Leader election using PostgreSQL session-level advisory locks.
///
/// One instance holds the lock and acts as the leader; all others are standby.
/// Leadership state is communicated via a `watch` channel.
pub struct LeaderElection {
    pool: PgPool,
    lock_id: i64,
}

impl LeaderElection {
    pub fn new(pool: PgPool, lock_id: i64) -> Self {
        Self { pool, lock_id }
    }

    /// Spawn the election loop with explicit lifecycle ownership.
    ///
    /// The returned handle resolves only after cancellation has closed the
    /// dedicated PostgreSQL connection and therefore released any advisory lock.
    ///
    /// Every dedicated-connection database operation is both cancellable on
    /// shutdown (NAN-1778 graceful shutdown) and hard-timeout bounded so a
    /// blackholed connection cannot pin leadership forever (NAN-1781 fencing).
    pub fn start(
        &self,
        shutdown: ShutdownToken,
    ) -> (watch::Receiver<bool>, tokio::task::JoinHandle<()>) {
        let pool = self.pool.clone();
        let lock_id = self.lock_id;

        let heartbeat_secs = parse_env("LEADER_HEARTBEAT_SECS", 15);
        let heartbeat_timeout_secs = parse_env("LEADER_HEARTBEAT_TIMEOUT_SECS", 5).max(1);
        let retry_secs = parse_env("LEADER_RETRY_SECS", 15);
        let database_timeout = std::time::Duration::from_secs(heartbeat_timeout_secs);

        let (tx, rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            // Extract connect options from the pool so we can open dedicated
            // connections outside pool management.
            let connect_options = pool.connect_options().clone();

            loop {
                // Open a dedicated connection OUTSIDE the pool. Advisory locks
                // are session-level — a pooled connection returned to the pool
                // still holds the lock, causing self-deadlock on retry. The
                // attempt is cancellable on shutdown and hard-timeout bounded.
                let mut conn = match shutdown
                    .run_until_cancelled(hard_timeout(
                        database_timeout,
                        PgConnection::connect_with(&connect_options),
                    ))
                    .await
                {
                    None => break,
                    Some(Ok(Ok(connection))) => connection,
                    Some(Ok(Err(error))) => {
                        tracing::warn!(
                            "Leader election: failed to open dedicated connection: {}",
                            error
                        );
                        if shutdown
                            .run_until_cancelled(tokio::time::sleep(
                                std::time::Duration::from_secs(retry_secs),
                            ))
                            .await
                            .is_none()
                        {
                            break;
                        }
                        continue;
                    }
                    Some(Err(_)) => {
                        tracing::warn!(
                            timeout_secs = heartbeat_timeout_secs,
                            "Leader election: dedicated connection attempt timed out"
                        );
                        if shutdown
                            .run_until_cancelled(tokio::time::sleep(
                                std::time::Duration::from_secs(retry_secs),
                            ))
                            .await
                            .is_none()
                        {
                            break;
                        }
                        continue;
                    }
                };

                let acquired: bool = match shutdown
                    .run_until_cancelled(hard_timeout(
                        database_timeout,
                        sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                            .bind(lock_id)
                            .fetch_one(&mut conn),
                    ))
                    .await
                {
                    None => {
                        drop(conn);
                        break;
                    }
                    Some(Ok(Ok(acquired))) => acquired,
                    Some(Ok(Err(error))) => {
                        tracing::warn!("Leader election: lock query failed: {}", error);
                        drop(conn);
                        if shutdown
                            .run_until_cancelled(tokio::time::sleep(
                                std::time::Duration::from_secs(retry_secs),
                            ))
                            .await
                            .is_none()
                        {
                            break;
                        }
                        continue;
                    }
                    Some(Err(_)) => {
                        tracing::warn!(
                            timeout_secs = heartbeat_timeout_secs,
                            "Leader election: lock query timed out"
                        );
                        drop(conn);
                        if shutdown
                            .run_until_cancelled(tokio::time::sleep(
                                std::time::Duration::from_secs(retry_secs),
                            ))
                            .await
                            .is_none()
                        {
                            break;
                        }
                        continue;
                    }
                };

                if !acquired {
                    tracing::info!("Leader election: another instance is leader (lock_id=0x{:X}), retrying in {}s", lock_id, retry_secs);
                    // Drop closes the dedicated connection, no lock leak
                    drop(conn);
                    if shutdown
                        .run_until_cancelled(tokio::time::sleep(std::time::Duration::from_secs(
                            retry_secs,
                        )))
                        .await
                        .is_none()
                    {
                        break;
                    }
                    continue;
                }

                // --- We are the leader ---
                tracing::info!(
                    "Leader election: this instance is now the leader (lock_id=0x{:X})",
                    lock_id
                );
                let _ = tx.send(true);

                // Heartbeat loop — keep the dedicated connection alive
                let heartbeat_interval = std::time::Duration::from_secs(heartbeat_secs);
                let mut cancelled = false;
                loop {
                    if shutdown
                        .run_until_cancelled(tokio::time::sleep(heartbeat_interval))
                        .await
                        .is_none()
                    {
                        cancelled = true;
                        break;
                    }

                    match shutdown
                        .run_until_cancelled(hard_timeout(
                            database_timeout,
                            sqlx::query("SELECT 1").execute(&mut conn),
                        ))
                        .await
                    {
                        None => {
                            cancelled = true;
                            break;
                        }
                        Some(Ok(Ok(_))) => {
                            tracing::debug!(
                                "Leader election: heartbeat OK (lock_id=0x{:X})",
                                lock_id
                            );
                        }
                        Some(Ok(Err(error))) => {
                            tracing::warn!(
                                "Leader election: heartbeat failed ({}), releasing leadership",
                                error
                            );
                            break;
                        }
                        Some(Err(_)) => {
                            tracing::error!(
                                timeout_secs = heartbeat_timeout_secs,
                                lock_id = format_args!("0x{:X}", lock_id),
                                "Leader election: heartbeat timed out; dropping leadership connection"
                            );
                            break;
                        }
                    }
                }

                // Lost leadership — drop closes the dedicated connection and
                // releases the advisory lock, then notify watchers
                drop(conn);
                let _ = tx.send(false);

                if cancelled || shutdown.is_cancelled() {
                    break;
                }

                tracing::info!(
                    "Leader election: leadership lost (lock_id=0x{:X}), will retry in {}s",
                    lock_id,
                    retry_secs
                );
                if shutdown
                    .run_until_cancelled(tokio::time::sleep(std::time::Duration::from_secs(
                        retry_secs,
                    )))
                    .await
                    .is_none()
                {
                    break;
                }
            }

            let _ = tx.send(false);
            tracing::info!(
                "Leader election stopped and advisory lock released (lock_id=0x{:X})",
                lock_id
            );
        });

        (rx, handle)
    }
}

async fn hard_timeout<F: Future>(
    timeout: std::time::Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    tokio::time::timeout(timeout, future).await
}

fn parse_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn cancelled_election_returns_owned_handle_without_connecting() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:9/nanosiem")
            .unwrap();
        let election = LeaderElection::new(pool, lock_ids::API_SCHEDULER);
        let shutdown = ShutdownToken::new();
        shutdown.cancel();

        let (mut leadership, handle) = election.start(shutdown);
        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("cancelled election task must stop")
            .expect("election task must not panic");

        assert!(!*leadership.borrow());
        while leadership.changed().await.is_ok() {
            assert!(!*leadership.borrow());
        }
    }

    #[tokio::test]
    async fn hard_timeout_bounds_a_blackholed_heartbeat() {
        let result = hard_timeout(
            std::time::Duration::from_millis(5),
            std::future::pending::<()>(),
        )
        .await;
        assert!(result.is_err());
    }
}
