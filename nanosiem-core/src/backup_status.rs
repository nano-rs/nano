// SPDX-License-Identifier: AGPL-3.0-or-later

//! Automatic backup status (NAN-5204).
//!
//! The optional `nano-backup` compose sidecar runs `scripts/nano backup` on a
//! schedule and, after every attempt, reports the outcome to nano-api
//! (`POST /api/internal/backup-status`). The latest state lives in the
//! single-row `backup_status` table (migration 325). Admins read it back
//! (`GET /api/system/backup-status`), SIEM Health raises a finding when it is
//! stale, and the web app shows a banner and a "Last backup" card.
//!
//! Open core; nothing here leaves the deployment.
//!
//! The staleness rule lives in ONE place, [`is_stale`], shared by the API
//! response and the SIEM Health finding.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;

/// A backup older than this (or none since automatic backups were enabled)
/// is stale. Daily schedule + 12h grace for one slow or retried run.
pub const STALE_AFTER_HOURS: i64 = 36;

/// Longest destination accepted (`s3://bucket/prefix` or a host path).
pub const MAX_DESTINATION_LEN: usize = 512;
/// Error text is truncated to this many characters, not rejected.
pub const MAX_ERROR_CHARS: usize = 1000;
/// Longest schedule string (`HH:MM`, or a short cron-like expression).
pub const MAX_SCHEDULE_LEN: usize = 64;
/// Longest backup id (`nano-<ts>-<rand>-<host>`).
pub const MAX_BACKUP_ID_LEN: usize = 200;
/// Upper bound for `keep` (retained backup count).
pub const MAX_KEEP: i32 = 10_000;

/// Outcome of one scheduled attempt. `disabled` is sent once when the
/// schedule is turned off. `partial`: a restorable backup was stored but
/// part of the default scope is missing (the ClickHouse lookup rows when
/// ClickHouse was unreachable); it counts as the latest backup and its
/// warning is kept as the last error, so it is never shown as a clean success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BackupOutcome {
    Success,
    Partial,
    Failure,
    Disabled,
}

impl BackupOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Partial => "partial",
            Self::Failure => "failure",
            Self::Disabled => "disabled",
        }
    }
}

/// Where backups are uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BackupDestinationKind {
    Path,
    S3,
}

impl BackupDestinationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::S3 => "s3",
        }
    }
}

/// Whether the backup includes ClickHouse log data (NAN-5202: excluded by
/// default; PostgreSQL metadata is always included).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum BackupClickhouseData {
    Included,
    Excluded,
}

impl BackupClickhouseData {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Included => "included",
            Self::Excluded => "excluded",
        }
    }
}

/// Body of `POST /api/internal/backup-status`, as sent by the sidecar.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupStatusReport {
    /// Whether the schedule is on. `outcome: disabled` forces false.
    pub enabled: bool,
    pub outcome: BackupOutcome,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    /// Success only; `^[A-Za-z0-9._-]{1,200}$`.
    #[serde(default)]
    pub backup_id: Option<String>,
    /// Success only.
    #[serde(default)]
    pub size_bytes: Option<i64>,
    pub destination_kind: BackupDestinationKind,
    /// `s3://bucket/prefix` or a host path. Never carries credentials.
    pub destination: String,
    pub clickhouse_data: BackupClickhouseData,
    /// Daily run time, e.g. `02:00`.
    pub schedule: String,
    /// Backups retained at the destination.
    pub keep: i32,
    #[serde(default)]
    pub next_run_at: Option<DateTime<Utc>>,
    /// Failure only; truncated to 1000 characters.
    #[serde(default)]
    pub error: Option<String>,
}

/// A report that passed [`BackupStatusReport::validate`]: enum-checked,
/// length-bounded, with outcome-irrelevant fields dropped.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedBackupReport {
    pub enabled: bool,
    pub outcome: BackupOutcome,
    pub finished_at: DateTime<Utc>,
    pub backup_id: Option<String>,
    pub size_bytes: Option<i64>,
    pub destination_kind: BackupDestinationKind,
    pub destination: String,
    pub clickhouse_data: BackupClickhouseData,
    pub schedule: String,
    pub keep: i32,
    pub next_run_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackupStatusValidationError {
    #[error("destination must be 1..={MAX_DESTINATION_LEN} characters")]
    Destination,
    #[error("destination must not contain credentials")]
    DestinationCredentials,
    #[error("backup_id must match ^[A-Za-z0-9._-]{{1,{MAX_BACKUP_ID_LEN}}}$")]
    BackupId,
    #[error("size_bytes must be >= 0")]
    SizeBytes,
    #[error("schedule must be 1..={MAX_SCHEDULE_LEN} characters")]
    Schedule,
    #[error("keep must be between 0 and {MAX_KEEP}")]
    Keep,
}

fn has_control_chars(s: &str) -> bool {
    s.chars().any(char::is_control)
}

fn valid_backup_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_BACKUP_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `scheme://user:pass@host` style userinfo — the sidecar never sends it, so
/// its presence means a misconfiguration we refuse to persist.
fn destination_has_userinfo(destination: &str) -> bool {
    match destination.split_once("://") {
        Some((_, rest)) => rest.split('/').next().is_some_and(|authority| authority.contains('@')),
        None => false,
    }
}

/// Truncate to at most `max` characters (not bytes) without splitting a
/// character.
pub fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((idx, _)) => s[..idx].to_string(),
        None => s.to_string(),
    }
}

impl BackupStatusReport {
    pub fn validate(self) -> Result<ValidatedBackupReport, BackupStatusValidationError> {
        let destination = self.destination.trim().to_string();
        if destination.is_empty()
            || destination.len() > MAX_DESTINATION_LEN
            || has_control_chars(&destination)
        {
            return Err(BackupStatusValidationError::Destination);
        }
        if destination_has_userinfo(&destination) {
            return Err(BackupStatusValidationError::DestinationCredentials);
        }
        let schedule = self.schedule.trim().to_string();
        if schedule.is_empty() || schedule.len() > MAX_SCHEDULE_LEN || has_control_chars(&schedule)
        {
            return Err(BackupStatusValidationError::Schedule);
        }
        if !(0..=MAX_KEEP).contains(&self.keep) {
            return Err(BackupStatusValidationError::Keep);
        }
        if let Some(id) = &self.backup_id {
            if !valid_backup_id(id) {
                return Err(BackupStatusValidationError::BackupId);
            }
        }
        if self.size_bytes.is_some_and(|s| s < 0) {
            return Err(BackupStatusValidationError::SizeBytes);
        }

        let success = matches!(self.outcome, BackupOutcome::Success | BackupOutcome::Partial);
        let failure = matches!(self.outcome, BackupOutcome::Failure | BackupOutcome::Partial);
        let error = if failure {
            self.error
                .map(|e| truncate_chars(e.trim(), MAX_ERROR_CHARS))
                .filter(|e| !e.is_empty())
        } else {
            None
        };
        Ok(ValidatedBackupReport {
            enabled: self.enabled && self.outcome != BackupOutcome::Disabled,
            outcome: self.outcome,
            finished_at: self.finished_at,
            backup_id: if success { self.backup_id } else { None },
            size_bytes: if success { self.size_bytes } else { None },
            destination_kind: self.destination_kind,
            destination,
            clickhouse_data: self.clickhouse_data,
            schedule,
            keep: self.keep,
            next_run_at: self.next_run_at,
            error,
        })
    }
}

/// The stored `backup_status` row.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow)]
pub struct BackupStatus {
    pub enabled: bool,
    pub enabled_since: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_outcome: Option<String>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_success_backup_id: Option<String>,
    pub last_success_size_bytes: Option<i64>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_failure_error: Option<String>,
    pub consecutive_failures: i32,
    pub destination_kind: Option<String>,
    pub destination: Option<String>,
    pub clickhouse_data: Option<String>,
    pub schedule: Option<String>,
    pub keep: Option<i32>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// THE staleness rule: automatic backups are on and the later of the newest
/// successful backup and the moment they were (re)enabled is more than
/// [`STALE_AFTER_HOURS`] old. Disabled schedules are never stale.
pub fn is_stale(status: &BackupStatus, now: DateTime<Utc>) -> bool {
    if !status.enabled {
        return false;
    }
    // The later of the last success and the moment backups were (re)enabled:
    // turning backups back on after a long pause gets a fresh 36-hour window.
    let reference = match (status.last_success_at, status.enabled_since) {
        (Some(success), Some(enabled)) => Some(success.max(enabled)),
        (success, enabled) => success.or(enabled),
    };
    match reference {
        Some(since) => now - since > Duration::hours(STALE_AFTER_HOURS),
        None => false,
    }
}

const SELECT_COLUMNS: &str = "enabled, enabled_since, last_attempt_at, last_outcome, \
     last_success_at, last_success_backup_id, last_success_size_bytes, last_failure_at, \
     last_failure_error, consecutive_failures, destination_kind, destination, clickhouse_data, \
     schedule, keep, next_run_at, updated_at";

/// Upsert of one report into the singleton row.
///
/// - success: records the backup, resets `consecutive_failures`.
/// - failure: records the error, increments `consecutive_failures`.
/// - disabled: only flips `enabled` off and refreshes the config columns;
///   the attempt history is kept for the card.
/// - `enabled_since` is set (server clock) on the first report and whenever
///   `enabled` flips false -> true, and kept otherwise.
const UPSERT_SQL: &str = r#"
INSERT INTO backup_status AS b (
    id, enabled, enabled_since, last_attempt_at, last_outcome,
    last_success_at, last_success_backup_id, last_success_size_bytes,
    last_failure_at, last_failure_error, consecutive_failures,
    destination_kind, destination, clickhouse_data, schedule, keep, next_run_at, updated_at
) VALUES (
    1, $1, CASE WHEN $1 THEN now() END,
    CASE WHEN $2 <> 'disabled' THEN $3 END,
    CASE WHEN $2 <> 'disabled' THEN $2 END,
    CASE WHEN $2 IN ('success', 'partial') THEN $3 END, $4, $5,
    CASE WHEN $2 IN ('failure', 'partial') THEN $3 END, $6,
    CASE WHEN $2 = 'failure' THEN 1 ELSE 0 END,
    $7, $8, $9, $10, $11, $12, now()
)
ON CONFLICT (id) DO UPDATE SET
    enabled = EXCLUDED.enabled,
    enabled_since = CASE
        WHEN EXCLUDED.enabled AND (NOT b.enabled OR b.enabled_since IS NULL) THEN now()
        ELSE b.enabled_since
    END,
    last_attempt_at = CASE WHEN $2 <> 'disabled' THEN $3 ELSE b.last_attempt_at END,
    last_outcome = CASE WHEN $2 <> 'disabled' THEN $2 ELSE b.last_outcome END,
    last_success_at = CASE WHEN $2 IN ('success', 'partial') THEN $3 ELSE b.last_success_at END,
    last_success_backup_id = CASE WHEN $2 IN ('success', 'partial') THEN $4 ELSE b.last_success_backup_id END,
    last_success_size_bytes = CASE WHEN $2 IN ('success', 'partial') THEN $5 ELSE b.last_success_size_bytes END,
    last_failure_at = CASE WHEN $2 IN ('failure', 'partial') THEN $3 ELSE b.last_failure_at END,
    last_failure_error = CASE WHEN $2 IN ('failure', 'partial') THEN $6 ELSE b.last_failure_error END,
    consecutive_failures = CASE $2
        WHEN 'success' THEN 0
        WHEN 'partial' THEN 0
        WHEN 'failure' THEN b.consecutive_failures + 1
        ELSE b.consecutive_failures
    END,
    destination_kind = EXCLUDED.destination_kind,
    destination = EXCLUDED.destination,
    clickhouse_data = EXCLUDED.clickhouse_data,
    schedule = EXCLUDED.schedule,
    keep = EXCLUDED.keep,
    next_run_at = EXCLUDED.next_run_at,
    updated_at = now()
RETURNING enabled, enabled_since, last_attempt_at, last_outcome, last_success_at,
    last_success_backup_id, last_success_size_bytes, last_failure_at, last_failure_error,
    consecutive_failures, destination_kind, destination, clickhouse_data, schedule, keep,
    next_run_at, updated_at
"#;

/// Data access for the singleton `backup_status` row.
#[derive(Clone)]
pub struct BackupStatusRepository {
    pool: PgPool,
}

impl BackupStatusRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The stored status, `None` when no report was ever received.
    pub async fn get(&self) -> Result<Option<BackupStatus>, sqlx::Error> {
        sqlx::query_as::<_, BackupStatus>(&format!(
            "SELECT {SELECT_COLUMNS} FROM backup_status WHERE id = 1"
        ))
        .fetch_optional(&self.pool)
        .await
    }

    /// Record one report. Returns the row before and after, so callers can
    /// tell a state change from a repeat.
    pub async fn record(
        &self,
        report: &ValidatedBackupReport,
    ) -> Result<(Option<BackupStatus>, BackupStatus), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let before = sqlx::query_as::<_, BackupStatus>(&format!(
            "SELECT {SELECT_COLUMNS} FROM backup_status WHERE id = 1 FOR UPDATE"
        ))
        .fetch_optional(&mut *tx)
        .await?;
        let after = sqlx::query_as::<_, BackupStatus>(UPSERT_SQL)
            .bind(report.enabled)
            .bind(report.outcome.as_str())
            .bind(report.finished_at)
            .bind(report.backup_id.as_deref())
            .bind(report.size_bytes)
            .bind(report.error.as_deref())
            .bind(report.destination_kind.as_str())
            .bind(&report.destination)
            .bind(report.clickhouse_data.as_str())
            .bind(&report.schedule)
            .bind(report.keep)
            .bind(report.next_run_at)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((before, after))
    }
}

#[cfg(test)]
#[path = "backup_status_tests.rs"]
mod tests;
