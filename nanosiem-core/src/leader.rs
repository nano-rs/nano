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
use tokio::sync::watch;

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

    /// Spawn the election loop. Returns a `watch::Receiver<bool>` that fires
    /// `true` when this instance wins the lock and `false` when leadership is lost.
    pub fn start(&self) -> watch::Receiver<bool> {
        let pool = self.pool.clone();
        let lock_id = self.lock_id;

        let heartbeat_secs = parse_env("LEADER_HEARTBEAT_SECS", 15);
        let retry_secs = parse_env("LEADER_RETRY_SECS", 15);

        let (tx, rx) = watch::channel(false);

        tokio::spawn(async move {
            // Extract connect options from the pool so we can open dedicated
            // connections outside pool management.
            let connect_options = pool.connect_options().clone();

            loop {
                // Open a dedicated connection OUTSIDE the pool. Advisory locks
                // are session-level — a pooled connection returned to the pool
                // still holds the lock, causing self-deadlock on retry.
                let mut conn = match PgConnection::connect_with(&connect_options).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            "Leader election: failed to open dedicated connection: {}",
                            e
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
                        continue;
                    }
                };

                let acquired: bool = match sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
                    .bind(lock_id)
                    .fetch_one(&mut conn)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("Leader election: lock query failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
                        continue;
                    }
                };

                if !acquired {
                    tracing::info!("Leader election: another instance is leader (lock_id=0x{:X}), retrying in {}s", lock_id, retry_secs);
                    // Drop closes the dedicated connection, no lock leak
                    drop(conn);
                    tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
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
                loop {
                    tokio::time::sleep(heartbeat_interval).await;

                    match sqlx::query("SELECT 1").execute(&mut conn).await {
                        Ok(_) => {
                            tracing::debug!(
                                "Leader election: heartbeat OK (lock_id=0x{:X})",
                                lock_id
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Leader election: heartbeat failed ({}), releasing leadership",
                                e
                            );
                            break;
                        }
                    }
                }

                // Lost leadership — drop closes the dedicated connection and
                // releases the advisory lock, then notify watchers
                drop(conn);
                let _ = tx.send(false);
                tracing::info!(
                    "Leader election: leadership lost (lock_id=0x{:X}), will retry in {}s",
                    lock_id,
                    retry_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(retry_secs)).await;
            }
        });

        rx
    }
}

fn parse_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
