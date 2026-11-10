// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5217: the cluster-wide "pause ingestion" control and its enforcement.
//!
//! The pause is decided in one place, `system_settings.ingestion_paused` in
//! PostgreSQL, either by the disk-pressure monitor at the emergency level
//! (`source = disk_pressure`) or by an administrator (`source = manual`).
//! Every host reads the same row, so every app host reports the same answer.
//!
//! Three things enforce it:
//!
//! 1. **ClickHouse guard (every write path).** While paused, the ingest
//!    ClickHouse users (`nanosiem_vector`, `nanosiem_ingest` by default) get
//!    the settings profile [`PAUSE_PROFILE`] with `readonly = 1`. Every INSERT
//!    by those users then fails with `READONLY` (HTTP 500), which the Vector
//!    ClickHouse sink retries. Vector keeps the events in its bounded disk
//!    buffer and, once that is full, blocks its sources (back-pressure). Pull
//!    sources (S3/SQS, Kafka, ...) stop pulling because their acknowledgements
//!    stop. Tenzir's `to_clickhouse` writes are refused. Nothing reaches the
//!    ingest tables, and nothing acknowledged is dropped. The profile is
//!    additive (it never touches the user's own settings), works for
//!    `users.xml` users, and lifting the pause is a `DROP SETTINGS PROFILE`.
//! 2. **Ingest edge admission (HTTP, HEC, OTLP through nginx).** nginx asks
//!    `GET /api/internal/ingest-admission` before proxying an ingest request
//!    and answers `503` with `Retry-After` while paused, so senders keep the
//!    data and retry. Nothing enters Vector, so a resumed sender delivers each
//!    event exactly once.
//! 3. **Connector runner.** It claims no new feed runs while paused.
//!
//! The leader's disk-pressure cycle reconciles the ClickHouse guard with the
//! PostgreSQL flag every check interval, so a failed DDL, a restarted node or
//! a manual change made on another host converges.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use clickhouse::Client as ClickHouseClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, warn};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::db::dual_pool::on_cluster_clause;

/// The ClickHouse settings profile that holds the ingest users read-only while
/// ingestion is paused.
pub const PAUSE_PROFILE: &str = "nano_ingest_pause";

/// ClickHouse users whose writes are ingestion: Vector and the direct
/// (Tenzir) ingest user. Overridden by `NANO_INGEST_PAUSE_CLICKHOUSE_USERS`.
pub const DEFAULT_PAUSE_USERS: &[&str] = &["nanosiem_vector", "nanosiem_ingest"];

/// How long an admission answer may be reused by this process.
const ADMISSION_CACHE_TTL: Duration = Duration::from_secs(1);

/// Suggested sender retry delay while paused (seconds).
pub const PAUSED_RETRY_AFTER_SECS: u64 = 30;

/// PostgreSQL advisory lock serialising every pause transition (flag write +
/// ClickHouse DDL), on every host: without it a pause racing a resume could
/// leave the guard disagreeing with the flag until the next reconcile.
const TRANSITION_LOCK_KEY: i64 = 0x4e41_4e5f_3532_3137; // "NAN_5217"

/// Longest operator-supplied reason kept.
const MAX_REASON_LEN: usize = 500;

/// Who paused ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IngestionPauseSource {
    /// The disk-pressure monitor, at the emergency level.
    DiskPressure,
    /// An administrator.
    Manual,
}

impl IngestionPauseSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DiskPressure => "disk_pressure",
            Self::Manual => "manual",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "disk_pressure" => Some(Self::DiskPressure),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// The cluster-wide ingestion pause state, as stored in PostgreSQL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct IngestionPauseState {
    /// Whether ingestion is paused.
    pub paused: bool,
    /// Who paused it. `null` when not paused (or paused by a release before
    /// NAN-5217, which only the disk-pressure monitor could do).
    pub source: Option<IngestionPauseSource>,
    /// Operator-supplied or automatic reason.
    pub reason: Option<String>,
    /// When the pause started.
    pub paused_at: Option<DateTime<Utc>>,
    /// The administrator who paused it (manual pauses only).
    pub paused_by: Option<Uuid>,
}

impl IngestionPauseState {
    /// Whether the disk-pressure recovery may lift this pause. A manual pause
    /// is lifted only by an administrator.
    pub fn auto_resumable(&self) -> bool {
        self.paused && self.source != Some(IngestionPauseSource::Manual)
    }
}

/// Whether the ClickHouse guard is in place, as observed on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum IngestionGuardState {
    /// The read-only profile is applied to the ingest users.
    Applied,
    /// No guard is in place.
    Absent,
    /// ClickHouse could not be asked.
    Unknown,
}

#[derive(Debug, Error)]
pub enum IngestionPauseError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("ClickHouse error: {0}")]
    ClickHouse(String),
}

/// Reads, changes and enforces the ingestion pause. Cheap to share (`Arc`).
pub struct IngestionPauseService {
    pg: PgPool,
    ch_admin: ClickHouseClient,
    users: Vec<String>,
    cache: RwLock<Option<(Instant, IngestionPauseState)>>,
}

impl IngestionPauseService {
    pub fn new(pg: PgPool, ch_admin: ClickHouseClient) -> Self {
        let users = std::env::var("NANO_INGEST_PAUSE_CLICKHOUSE_USERS")
            .ok()
            .map(|v| parse_user_list(&v))
            .unwrap_or_else(|| DEFAULT_PAUSE_USERS.iter().map(|u| u.to_string()).collect());
        Self {
            pg,
            ch_admin,
            users,
            cache: RwLock::new(None),
        }
    }

    /// The ClickHouse users the guard applies to.
    pub fn guarded_users(&self) -> &[String] {
        &self.users
    }

    /// The current state, read from PostgreSQL.
    pub async fn state(&self) -> Result<IngestionPauseState, IngestionPauseError> {
        let row: Option<(bool, Option<String>, Option<String>, Option<DateTime<Utc>>, Option<Uuid>)> =
            sqlx::query_as(
                "SELECT ingestion_paused, ingestion_pause_source, ingestion_pause_reason, \
                        ingestion_paused_at, ingestion_paused_by \
                 FROM system_settings WHERE id = 'default'",
            )
            .fetch_optional(&self.pg)
            .await?;
        let state = match row {
            Some((paused, source, reason, paused_at, paused_by)) => IngestionPauseState {
                paused,
                source: source.as_deref().and_then(IngestionPauseSource::parse),
                reason,
                paused_at,
                paused_by,
            },
            None => IngestionPauseState::default(),
        };
        self.store_cache(&state);
        Ok(state)
    }

    /// Whether ingestion is paused, for the per-request admission check. Reuses
    /// an answer up to one second old. When PostgreSQL cannot be read it keeps
    /// the last known answer, or admits when there is none (an unreachable
    /// database must not stop ingestion that was never paused).
    pub async fn admission_paused(&self) -> bool {
        if let Some((at, state)) = self.cache.read().ok().and_then(|c| c.clone()) {
            if at.elapsed() < ADMISSION_CACHE_TTL {
                return state.paused;
            }
        }
        match self.state().await {
            Ok(state) => state.paused,
            Err(error) => {
                warn!(%error, "ingestion admission: pause state unreadable; using the last known state");
                self.cache
                    .read()
                    .ok()
                    .and_then(|c| c.as_ref().map(|(_, s)| s.paused))
                    .unwrap_or(false)
            }
        }
    }

    fn store_cache(&self, state: &IngestionPauseState) {
        if let Ok(mut cache) = self.cache.write() {
            *cache = Some((Instant::now(), state.clone()));
        }
    }

    /// Pause ingestion. Returns the new state and whether this call changed
    /// it (a caller audits only a change). A manual pause over an automatic
    /// one takes it over, so the disk-pressure recovery no longer lifts it.
    /// The ClickHouse guard is applied when missing; a guard failure is logged
    /// and repaired by the next reconcile, and the state stays paused (the
    /// edge and the connector runner already honour it).
    pub async fn pause(
        &self,
        source: IngestionPauseSource,
        reason: Option<&str>,
        actor: Option<Uuid>,
    ) -> Result<(IngestionPauseState, bool), IngestionPauseError> {
        let lock = self.lock_transitions().await?;
        let result = self.pause_locked(source, reason, actor).await;
        unlock_transitions(lock).await;
        result
    }

    async fn pause_locked(
        &self,
        source: IngestionPauseSource,
        reason: Option<&str>,
        actor: Option<Uuid>,
    ) -> Result<(IngestionPauseState, bool), IngestionPauseError> {
        let reason = reason.map(clean_reason).filter(|r| !r.is_empty());
        let changed = sqlx::query(
            "UPDATE system_settings SET \
                ingestion_paused = true, \
                ingestion_pause_source = $1, \
                ingestion_pause_reason = $2, \
                ingestion_paused_at = now(), \
                ingestion_paused_by = $3 \
             WHERE id = 'default' \
               AND (ingestion_paused = false \
                    OR ($1 = 'manual' AND ingestion_pause_source IS DISTINCT FROM 'manual'))",
        )
        .bind(source.as_str())
        .bind(reason.as_deref())
        .bind(actor)
        .execute(&self.pg)
        .await?
        .rows_affected()
            > 0;
        // Repeated calls (the emergency level re-asserts every check) issue no
        // DDL once the guard is in place.
        if changed || self.guard_state().await != IngestionGuardState::Applied {
            if let Err(error) = self.apply_guard().await {
                warn!(%error, "ingestion pause: ClickHouse guard not applied; the next reconcile retries");
            }
        }
        let state = self.state().await?;
        if changed {
            warn!(source = source.as_str(), reason = ?state.reason, "Ingestion PAUSED");
        }
        Ok((state, changed))
    }

    /// Resume ingestion. `only_auto` lifts only an automatic pause (the
    /// disk-pressure recovery); an administrator passes `false`. Returns the
    /// state before the call and whether this call changed it.
    pub async fn resume(
        &self,
        only_auto: bool,
    ) -> Result<(IngestionPauseState, bool), IngestionPauseError> {
        let lock = self.lock_transitions().await?;
        let result = self.resume_locked(only_auto).await;
        unlock_transitions(lock).await;
        result
    }

    async fn resume_locked(
        &self,
        only_auto: bool,
    ) -> Result<(IngestionPauseState, bool), IngestionPauseError> {
        let before = self.state().await?;
        let changed = sqlx::query(
            "UPDATE system_settings SET \
                ingestion_paused = false, \
                ingestion_pause_source = NULL, \
                ingestion_pause_reason = NULL, \
                ingestion_paused_at = NULL, \
                ingestion_paused_by = NULL \
             WHERE id = 'default' AND ingestion_paused = true \
               AND (NOT $1 OR ingestion_pause_source IS DISTINCT FROM 'manual')",
        )
        .bind(only_auto)
        .execute(&self.pg)
        .await?
        .rows_affected()
            > 0;
        // The disk-pressure recovery calls this every check at normal usage, so
        // it issues DDL only on a real transition (`reconcile` repairs a guard
        // left behind). An administrator's resume always drops it.
        if changed || !only_auto {
            if let Err(error) = self.remove_guard().await {
                warn!(%error, "ingestion resume: ClickHouse guard not removed; the next reconcile retries");
            }
        }
        if changed {
            info!(source = ?before.source, "Ingestion RESUMED");
        }
        Ok((before, changed))
    }

    /// Make the ClickHouse guard match PostgreSQL. Run by the jobs leader every
    /// disk-pressure cycle.
    pub async fn reconcile(&self) -> Result<(), IngestionPauseError> {
        let lock = self.lock_transitions().await?;
        let result = self.reconcile_locked().await;
        unlock_transitions(lock).await;
        result
    }

    async fn reconcile_locked(&self) -> Result<(), IngestionPauseError> {
        let state = self.state().await?;
        let guard = self.guard_state().await;
        match (state.paused, guard) {
            (true, IngestionGuardState::Applied) | (false, IngestionGuardState::Absent) => Ok(()),
            (true, _) => {
                warn!("ingestion is paused but the ClickHouse guard is missing; applying it");
                self.apply_guard().await
            }
            (false, _) => {
                info!("ingestion is active; removing the ClickHouse guard");
                self.remove_guard().await
            }
        }
    }

    /// Whether the guard is in place on every reachable ClickHouse node.
    pub async fn guard_state(&self) -> IngestionGuardState {
        let (profiles, nodes) = guard_presence_sql(cluster_name().as_deref());
        let present: Result<u64, _> = self
            .ch_admin
            .query(&profiles)
            .bind(PAUSE_PROFILE)
            .fetch_one()
            .await;
        let total: Result<u64, _> = self.ch_admin.query(&nodes).fetch_one().await;
        match (present, total) {
            (Ok(present), Ok(total)) => classify_guard(present, total),
            (Err(error), _) | (_, Err(error)) => {
                warn!(%error, "ingestion pause: could not read the ClickHouse guard state");
                IngestionGuardState::Unknown
            }
        }
    }

    async fn apply_guard(&self) -> Result<(), IngestionPauseError> {
        // `TO` an unknown user fails the whole statement, so name only the
        // users this server has (a deployment without Tenzir may have no
        // `nanosiem_ingest`).
        let existing: Vec<String> = self
            .ch_admin
            .query("SELECT name FROM system.users WHERE has(?, name) ORDER BY name")
            .bind(&self.users)
            .fetch_all()
            .await
            .map_err(|e| IngestionPauseError::ClickHouse(e.to_string()))?;
        let Some(sql) = apply_guard_sql(&on_cluster_clause(), &existing) else {
            warn!(users = ?self.users, "ingestion pause: none of the ingest ClickHouse users exist; no guard applied");
            return Ok(());
        };
        self.ch_admin
            .query(&sql)
            .execute()
            .await
            .map_err(|e| IngestionPauseError::ClickHouse(e.to_string()))?;
        info!(users = ?existing, "ingestion pause: ClickHouse ingest users are read-only");
        Ok(())
    }

    async fn remove_guard(&self) -> Result<(), IngestionPauseError> {
        self.ch_admin
            .query(&remove_guard_sql(&on_cluster_clause()))
            .execute()
            .await
            .map_err(|e| IngestionPauseError::ClickHouse(e.to_string()))
    }
}

impl IngestionPauseService {
    /// Take the transition lock on a dedicated connection (session-level, so
    /// it spans the ClickHouse DDL, and is released if the connection dies).
    async fn lock_transitions(
        &self,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, IngestionPauseError> {
        let mut conn = self.pg.acquire().await?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(TRANSITION_LOCK_KEY)
            .execute(&mut *conn)
            .await?;
        Ok(conn)
    }
}

async fn unlock_transitions(mut conn: sqlx::pool::PoolConnection<sqlx::Postgres>) {
    if let Err(error) = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(TRANSITION_LOCK_KEY)
        .execute(&mut *conn)
        .await
    {
        // Never return a connection that may still hold the lock to the pool:
        // closing it releases the lock.
        warn!(%error, "ingestion pause: advisory unlock failed; closing the connection");
        drop(conn.detach());
    }
}

fn cluster_name() -> Option<String> {
    std::env::var("CLICKHOUSE_CLUSTER").ok().and_then(|c| {
        let t = c.trim();
        (!t.is_empty()).then(|| t.to_string())
    })
}

/// Parse `NANO_INGEST_PAUSE_CLICKHOUSE_USERS` (comma separated). Names that are
/// not plain identifiers are dropped: they are spliced into DDL.
pub fn parse_user_list(value: &str) -> Vec<String> {
    let mut users: Vec<String> = value
        .split(',')
        .map(str::trim)
        .filter(|u| is_plain_identifier(u))
        .map(str::to_string)
        .collect();
    users.sort();
    users.dedup();
    users
}

fn is_plain_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn clean_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_REASON_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// `CREATE SETTINGS PROFILE OR REPLACE` holding `users` read-only, or `None`
/// with no user to guard. `OR REPLACE` keeps the `TO` list current.
pub fn apply_guard_sql(on_cluster: &str, users: &[String]) -> Option<String> {
    let users: Vec<String> = users
        .iter()
        .filter(|u| is_plain_identifier(u))
        .map(|u| format!("`{u}`"))
        .collect();
    if users.is_empty() {
        return None;
    }
    Some(format!(
        "CREATE SETTINGS PROFILE OR REPLACE `{PAUSE_PROFILE}`{on_cluster} SETTINGS readonly = 1 TO {}",
        users.join(", ")
    ))
}

/// Lift the guard.
pub fn remove_guard_sql(on_cluster: &str) -> String {
    format!("DROP SETTINGS PROFILE IF EXISTS `{PAUSE_PROFILE}`{on_cluster}")
}

/// The two reads behind [`IngestionPauseService::guard_state`]: how many nodes
/// hold the profile (bind its name), and how many nodes answered. Every node
/// on a cluster, the one server otherwise.
pub fn guard_presence_sql(cluster: Option<&str>) -> (String, String) {
    match cluster {
        Some(cl) => {
            let cl = cl.replace('\'', "");
            (
                format!(
                    "SELECT count() FROM clusterAllReplicas('{cl}', system.settings_profiles) WHERE name = ?"
                ),
                format!("SELECT count() FROM clusterAllReplicas('{cl}', system.one)"),
            )
        }
        None => (
            "SELECT count() FROM system.settings_profiles WHERE name = ?".to_string(),
            "SELECT count() FROM system.one".to_string(),
        ),
    }
}

/// `present` nodes hold the profile out of `total` that answered.
pub fn classify_guard(present: u64, total: u64) -> IngestionGuardState {
    if total == 0 {
        IngestionGuardState::Unknown
    } else if present >= total {
        IngestionGuardState::Applied
    } else if present == 0 {
        IngestionGuardState::Absent
    } else {
        // Partial: neither, so `reconcile` re-applies (paused) or drops
        // (active) on every node.
        IngestionGuardState::Unknown
    }
}

#[cfg(test)]
#[path = "ingestion_pause_tests.rs"]
mod tests;
