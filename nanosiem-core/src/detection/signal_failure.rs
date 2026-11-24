// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5428: per-signal failure isolation for the real-time signal processor.
//!
//! The processor drains `signals` in `(inserted_at, id)` order behind ONE
//! persisted watermark, so a signal that fails holds the watermark for every
//! real-time rule. Before this module, any failure was retried with an
//! exponential backoff until ten consecutive errors (about five minutes), and
//! the signal was then skipped with one log line: no alert, no record, health
//! stayed ok.
//!
//! Each failure is now classified with the NAN-5424 classification (error
//! TYPE, ClickHouse `Code: N`, PostgreSQL SQLSTATE class; never message text):
//!
//! - **Infrastructure** (ClickHouse transport / timeout / server pressure,
//!   PostgreSQL connection, pool, SQLSTATE 08/40/53/57/58, and 23505 from a
//!   concurrent-write race): the backend, not the signal, is at fault. The
//!   watermark is held with no attempt cap (a ClickHouse restart must not turn
//!   real alerts into gaps, audit D7) and the held signal's rule is marked
//!   failing, which raises detection health to critical.
//! - **Bad data** (a ClickHouse data-evaluation code, PostgreSQL SQLSTATE 22 /
//!   54, a row that does not decode): this signal's own content. Retrying
//!   cannot help, so it is dead-lettered on the first failure.
//! - **Unrecognised** (everything else, including query / schema codes): a
//!   small retry cap, then dead-lettered, behind a breaker: once the same
//!   error key has dead-lettered [`SYSTEMIC_BREAKER_THRESHOLD`] different
//!   signals in a row with no success between, it is treated as a systemic
//!   fault (schema skew, a broken query) and the watermark is held with the
//!   rule marked failing, instead of dropping every signal at full speed.
//!
//! The breaker deliberately does not cover positively identified bad data:
//! an attacker controls event content, and a breaker there would let a few
//! crafted events hold the whole real-time lane again.
//!
//! Dead-lettering records the dropped signal in `detection_coverage_gaps`
//! (rule, event-time window, attempts, redacted class + code) BEFORE the
//! watermark moves past it, so the drop is visible in SIEM health and
//! replayable by hand; for bad data in an Alerting rule a minimal reference
//! alert is raised too. If the gap record cannot be written, the signal is
//! held rather than dropped silently. A crash between the gap insert and the
//! watermark commit replays the signal and can record a duplicate gap row;
//! that ordering is accepted (a duplicate gap is visible, a lost one is not).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::repository::detection_rules::DetectionRuleRepositoryError;
use crate::db::repository::AlertRepositoryError;
use crate::detection::error::{sqlx_error_is_data, sqlx_error_is_transient};
use crate::search::SearchError;

/// Total attempts (first try included) of a signal failing with an
/// unrecognised error before it is dead-lettered.
pub(crate) const MAX_UNRECOGNISED_ATTEMPTS: u32 = 3;

/// Consecutive dead-letters with the same unrecognised error key (each a
/// different signal, no success between) that mark the fault as systemic.
pub(crate) const SYSTEMIC_BREAKER_THRESHOLD: u32 = 3;

/// Width of the event-time window recorded for a dropped signal.
const GAP_WINDOW_SECS: i64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalFailureClass {
    /// The backend is unreachable or under pressure; hold, no cap.
    Infrastructure,
    /// This signal's data; dead-letter now.
    BadData,
    /// Neither; small cap, then dead-letter behind the systemic breaker.
    Unrecognised,
}

impl SignalFailureClass {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Infrastructure => "infrastructure",
            Self::BadData => "data",
            Self::Unrecognised => "unrecognised",
        }
    }
}

/// A classified failure. `key` identifies the error for the systemic breaker
/// and the redacted record: `ch:<code>`, `pg:<sqlstate>`, a client error kind,
/// never message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignalFailure {
    pub class: SignalFailureClass,
    pub key: String,
}

impl SignalFailure {
    fn new(class: SignalFailureClass, key: impl Into<String>) -> Self {
        Self { class, key: key.into() }
    }
}

/// What the processor does with a failed signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignalDisposition {
    /// Keep the watermark on the signal and retry it next poll.
    Retry,
    /// Keep the watermark and raise detection health (rule marked failing).
    HoldAndAlarm,
    /// Record it as a coverage gap and move past it.
    DeadLetter,
}

/// Decide what to do with a signal that failed `attempts` times in a row
/// (this failure included). `streak` is the number of consecutive signals
/// already dead-lettered with this failure's key.
pub(crate) fn disposition(failure: &SignalFailure, attempts: u32, streak: u32) -> SignalDisposition {
    match failure.class {
        SignalFailureClass::Infrastructure => SignalDisposition::HoldAndAlarm,
        SignalFailureClass::BadData => SignalDisposition::DeadLetter,
        SignalFailureClass::Unrecognised if attempts < MAX_UNRECOGNISED_ATTEMPTS => {
            SignalDisposition::Retry
        }
        SignalFailureClass::Unrecognised if streak >= SYSTEMIC_BREAKER_THRESHOLD => {
            SignalDisposition::HoldAndAlarm
        }
        SignalFailureClass::Unrecognised => SignalDisposition::DeadLetter,
    }
}

/// Classify a `process_signal` (or poll) error by walking its source chain.
pub(crate) fn classify_signal_error(error: &anyhow::Error) -> SignalFailure {
    for cause in error.chain() {
        if let Some(e) = cause.downcast_ref::<sqlx::Error>() {
            return classify_sqlx(e);
        }
        if let Some(AlertRepositoryError::DatabaseError(e)) = cause.downcast_ref() {
            return classify_sqlx(e);
        }
        if let Some(DetectionRuleRepositoryError::DatabaseError(e)) = cause.downcast_ref() {
            return classify_sqlx(e);
        }
        if let Some(e) = cause.downcast_ref::<clickhouse::error::Error>() {
            return classify_clickhouse(e);
        }
        if cause.downcast_ref::<serde_json::Error>().is_some()
            || cause.downcast_ref::<std::str::Utf8Error>().is_some()
            || cause.downcast_ref::<std::string::FromUtf8Error>().is_some()
        {
            return SignalFailure::new(SignalFailureClass::BadData, "decode");
        }
        if cause.downcast_ref::<std::io::Error>().is_some() {
            return SignalFailure::new(SignalFailureClass::Infrastructure, "io");
        }
    }
    SignalFailure::new(SignalFailureClass::Unrecognised, "other")
}

fn classify_sqlx(error: &sqlx::Error) -> SignalFailure {
    let key = match error {
        sqlx::Error::Database(db) => format!("pg:{}", db.code().as_deref().unwrap_or("?")),
        other => format!("pg:{}", sqlx_kind(other)),
    };
    // 23505 here is a concurrent-write race (case grouping, emissions), not
    // the signal's content: retry it like a transient error.
    let unique_race = matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"));
    let class = if sqlx_error_is_transient(error) || unique_race {
        SignalFailureClass::Infrastructure
    } else if sqlx_error_is_data(error)
        || matches!(error, sqlx::Error::Encode(_))
    {
        SignalFailureClass::BadData
    } else {
        SignalFailureClass::Unrecognised
    };
    SignalFailure::new(class, key)
}

fn sqlx_kind(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::Io(_) => "io",
        sqlx::Error::PoolTimedOut => "pool-timed-out",
        sqlx::Error::PoolClosed => "pool-closed",
        sqlx::Error::WorkerCrashed => "worker-crashed",
        sqlx::Error::Tls(_) => "tls",
        sqlx::Error::Encode(_) => "encode",
        sqlx::Error::Decode(_) | sqlx::Error::ColumnDecode { .. } => "decode",
        sqlx::Error::Protocol(_) => "protocol",
        _ => "other",
    }
}

fn classify_clickhouse(error: &clickhouse::error::Error) -> SignalFailure {
    use clickhouse::error::Error as Ch;
    // The row's bytes do not decode (RowBinary String with invalid UTF-8):
    // this signal's data.
    if let Ch::InvalidUtf8Encoding(_) = error {
        return SignalFailure::new(SignalFailureClass::BadData, "ch:invalid-utf8");
    }
    // NAN-5424 mapping: transport by type, server errors by `Code: N` only.
    let code_key = match error {
        Ch::BadResponse(message) => crate::search::clickhouse_error_code(message)
            .map(|code| format!("ch:{code}"))
            .unwrap_or_else(|| "ch:bad-response".to_string()),
        Ch::SchemaMismatch(_) => "ch:schema-mismatch".to_string(),
        Ch::NotEnoughData => "ch:not-enough-data".to_string(),
        Ch::Custom(_) => "ch:deserialize".to_string(),
        _ => "ch:client".to_string(),
    };
    // NAN-5817: the pure classifier. `search_error_from_error` also reports
    // a rejection of generated search SQL at ERROR, which is not what this is
    // and would log event text the signal path deliberately keeps out.
    let class = match crate::search::classify_clickhouse_failure(error) {
        SearchError::Unavailable(_)
        | SearchError::Timeout(_)
        | SearchError::Cancelled
        | SearchError::ResourceLimit(_) => SignalFailureClass::Infrastructure,
        SearchError::DataError { .. } => SignalFailureClass::BadData,
        _ => SignalFailureClass::Unrecognised,
    };
    let key = match error {
        Ch::Network(_) => "ch:network".to_string(),
        Ch::TimedOut => "ch:timeout".to_string(),
        _ => code_key,
    };
    SignalFailure::new(class, key)
}

/// The coverage-gap row for one dead-lettered signal. The error text is
/// redacted to class + key: ClickHouse / PostgreSQL messages can quote event
/// values (U+0000, line breaks, escape sequences).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DroppedSignalGap {
    pub rule_id: Uuid,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    pub attempts: i32,
    pub error_message: String,
}

impl DroppedSignalGap {
    pub(crate) fn new(
        signal_id: Uuid,
        rule_id: Uuid,
        event_ts: DateTime<Utc>,
        attempts: u32,
        failure: &SignalFailure,
    ) -> Self {
        Self {
            rule_id,
            window_start: event_ts,
            window_end: event_ts + chrono::Duration::seconds(GAP_WINDOW_SECS),
            attempts: i32::try_from(attempts).unwrap_or(i32::MAX),
            error_message: crate::db::repository::detection_rules::rule_error_text(&format!(
                "[{}] real-time signal {signal_id} dropped after {attempts} attempt(s) ({})",
                failure.class.as_str(),
                failure.key
            )),
        }
    }
}

/// Persist a dead-lettered signal as a coverage gap. A rule deleted since the
/// signal fired has nothing left to cover, so its missing foreign key counts
/// as recorded.
pub(crate) async fn record_dropped_signal(
    pool: &sqlx::PgPool,
    gap: &DroppedSignalGap,
) -> Result<(), sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO detection_coverage_gaps
            (rule_id, window_start, window_end, attempts, error_message)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(gap.rule_id)
    .bind(gap.window_start)
    .bind(gap.window_end)
    .bind(gap.attempts)
    .bind(&gap.error_message)
    .execute(pool)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23503") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Raise detection health for a real-time rule whose signal is being held:
/// `consecutive_failures > 0` makes the rule "currently failing" (critical)
/// in the NAN-5424 health rollup. Real-time rules are never claimed by the
/// scheduler, so these counters are the processor's alone for them.
pub(crate) async fn mark_realtime_rule_failing(
    pool: &sqlx::PgPool,
    rule_id: Uuid,
    message: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE detection_rules SET
            consecutive_failures = LEAST(consecutive_failures + 1, 32767),
            failing_since = COALESCE(failing_since, NOW()),
            last_error = $2,
            last_error_at = NOW()
        WHERE id = $1 AND detection_mode <> 'scheduled'
        "#,
    )
    .bind(rule_id)
    .bind(crate::db::repository::detection_rules::rule_error_text(message))
    .execute(pool)
    .await
    .map(|_| ())
}

/// Clear the failing state set by [`mark_realtime_rule_failing`] once the held
/// signal goes through (`last_error` stays as the 24h "degraded" trace).
pub(crate) async fn clear_realtime_rule_failing(
    pool: &sqlx::PgPool,
    rule_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE detection_rules SET consecutive_failures = 0, failing_since = NULL
        WHERE id = $1 AND detection_mode <> 'scheduled'
        "#,
    )
    .bind(rule_id)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Poll-level infrastructure outage (the signal poll itself keeps failing, so
/// no signal is held and no single rule is at fault): mark every active
/// real-time rule failing so detection health goes critical while real-time
/// detection is down. Cleared by [`clear_all_realtime_rules_failing`] on the
/// next successful poll.
pub(crate) async fn mark_all_realtime_rules_failing(
    pool: &sqlx::PgPool,
    message: &str,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE detection_rules SET
            consecutive_failures = LEAST(consecutive_failures + 1, 32767),
            failing_since = COALESCE(failing_since, NOW()),
            last_error = $1,
            last_error_at = NOW()
        WHERE detection_mode <> 'scheduled'
          AND realtime_enabled = true
          AND archived = false
          AND mode IN ('live', 'alerting')
        "#,
    )
    .bind(crate::db::repository::detection_rules::rule_error_text(message))
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

/// Clear the failing state of every real-time rule after a fully successful
/// poll (no signal is held at that point).
pub(crate) async fn clear_all_realtime_rules_failing(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE detection_rules SET consecutive_failures = 0, failing_since = NULL
        WHERE detection_mode <> 'scheduled' AND consecutive_failures > 0
        "#,
    )
    .execute(pool)
    .await
    .map(|_| ())
}

/// A poll-level failure that keeps the processor stuck past its skip
/// threshold, when the cause is not infrastructure: record the skipped
/// `_inserted_at` second as a coverage gap for every active real-time rule
/// (the signals in it are unknown), so the skip is never silent.
pub(crate) async fn record_poll_skip_gaps(
    pool: &sqlx::PgPool,
    window_start: DateTime<Utc>,
    attempts: u32,
    failure: &SignalFailure,
) -> Result<u64, sqlx::Error> {
    let message = crate::db::repository::detection_rules::rule_error_text(&format!(
        "[{}] real-time signal poll failed {attempts} times; signals inserted in this \
         second were skipped ({})",
        failure.class.as_str(),
        failure.key
    ));
    sqlx::query(
        r#"
        INSERT INTO detection_coverage_gaps
            (rule_id, window_start, window_end, attempts, error_message)
        SELECT id, $1, $1 + make_interval(secs => $2), $3, $4
        FROM detection_rules
        WHERE realtime_enabled = true
          AND archived = false
          AND mode IN ('live', 'alerting')
        "#,
    )
    .bind(window_start)
    .bind(GAP_WINDOW_SECS as f64)
    .bind(i32::try_from(attempts).unwrap_or(i32::MAX))
    .bind(message)
    .execute(pool)
    .await
    .map(|r| r.rows_affected())
}

#[cfg(test)]
#[path = "signal_failure_tests.rs"]
mod tests;
