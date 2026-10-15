// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded collector diagnostics for the lean enrichment coordinator (NAN-3765).
//!
//! Vector's `lake_collector_errors` sink (config/vector/92-metrics.toml) posts
//! its own WARN/ERROR internal logs to `/v1/collector-errors/batch` on the
//! tenant coordinator, and the API's log-source health reads them back with
//! `GET /v1/collector-errors` (`LakeCollectorDiagnosticsClient`). The gen1
//! coordinator kept them in PostgreSQL; the lean coordinator has no database,
//! only its tenant scratch volume, so the rows live in one JSONL file there.
//!
//! The store is metadata only (no customer event payload) and bounded twice:
//! 14 days of retention and [`MAX_ROWS`] rows, oldest dropped first. Every
//! accepted batch rewrites the file atomically (temp file + rename). A missing
//! or unreadable file starts the store empty — diagnostics must never stop the
//! coordinator from serving enrichment.

use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Retention, matching the gen1 coordinator's PostgreSQL cleanup.
pub const RETENTION_DAYS: i64 = 14;
/// Hard row cap across all components; the oldest rows are dropped first.
pub const MAX_ROWS: usize = 20_000;
/// Rows accepted per batch (Vector's sink batches at most 1000 events).
pub const MAX_BATCH_ROWS: usize = 1_000;
/// Bytes accepted per batch.
pub const MAX_BATCH_BYTES: usize = 8 * 1_024 * 1_024;

const FILE_NAME: &str = "collector-errors.jsonl";

/// One stored Vector WARN/ERROR internal log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorDiagnostic {
    pub occurred_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub error_code: String,
    pub error_type: String,
    pub stage: String,
    pub component_id: String,
    pub component_kind: String,
    pub component_type: String,
    pub collector_host: String,
}

impl CollectorDiagnostic {
    fn into_api(self) -> nanosiem_core::log_sources::CollectorError {
        nanosiem_core::log_sources::CollectorError {
            timestamp: self.occurred_at,
            level: self.level,
            message: self.message,
            error_code: self.error_code,
            error_type: self.error_type,
            stage: self.stage,
            component_type: self.component_type,
        }
    }
}

/// Parse one Vector `internal_logs` event under the gen1 coordinator's
/// bounded metadata contract (`ioc_coordinator::parse_collector_diagnostic`).
pub fn parse_diagnostic(
    value: &serde_json::Value,
    now: DateTime<Utc>,
) -> Result<CollectorDiagnostic, &'static str> {
    let text = |path: &str| -> String {
        let mut current = value;
        for segment in path.split('.') {
            let Some(next) = current.get(segment) else {
                return String::new();
            };
            current = next;
        }
        current.as_str().unwrap_or_default().to_string()
    };
    let nested_level = text("metadata.level");
    let level = if nested_level.is_empty() {
        text("level")
    } else {
        nested_level
    }
    .to_ascii_uppercase();
    if !matches!(level.as_str(), "WARN" | "ERROR") {
        return Err("collector diagnostic level must be WARN or ERROR");
    }
    let occurred_at = text("timestamp").parse::<DateTime<Utc>>().unwrap_or(now);
    if occurred_at > now + Duration::minutes(5)
        || occurred_at < now - Duration::days(RETENTION_DAYS)
    {
        return Err("collector diagnostic timestamp is outside retention bounds");
    }
    let record = CollectorDiagnostic {
        occurred_at,
        received_at: now,
        level,
        message: text("message"),
        error_code: text("error_code"),
        error_type: text("error_type"),
        stage: text("stage"),
        component_id: text("vector.component_id"),
        component_kind: text("vector.component_kind"),
        component_type: text("vector.component_type"),
        collector_host: text("host"),
    };
    if record.message.is_empty()
        || record.message.len() > 8_192
        || record.collector_host.len() > 1_024
        || [
            &record.error_code,
            &record.error_type,
            &record.stage,
            &record.component_id,
            &record.component_kind,
            &record.component_type,
        ]
        .iter()
        .any(|value| value.len() > 512 || value.chars().any(char::is_control))
    {
        return Err("collector diagnostic exceeds its bounded metadata contract");
    }
    Ok(record)
}

/// Parse a Vector NDJSON batch. Blank lines are skipped; any invalid row
/// refuses the whole batch, as the gen1 coordinator does.
pub fn parse_batch(
    body: &[u8],
    now: DateTime<Utc>,
) -> Result<Vec<CollectorDiagnostic>, &'static str> {
    if body.len() > MAX_BATCH_BYTES {
        return Err("collector diagnostics body is too large");
    }
    let mut records = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= MAX_BATCH_ROWS {
            return Err("collector diagnostic batch exceeds 1000 rows");
        }
        let value = serde_json::from_slice::<serde_json::Value>(line)
            .map_err(|_| "collector diagnostic row is not valid JSON")?;
        records.push(parse_diagnostic(&value, now)?);
    }
    if records.is_empty() {
        return Err("collector diagnostic batch contains no rows");
    }
    Ok(records)
}

/// The tenant's bounded, file-backed collector diagnostics.
pub struct CollectorErrorLog {
    path: PathBuf,
    rows: Mutex<VecDeque<CollectorDiagnostic>>,
}

impl std::fmt::Debug for CollectorErrorLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectorErrorLog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl CollectorErrorLog {
    /// Open (or create) the store under `<scratch>/collector-errors/`.
    /// Unparseable lines are skipped with a warning rather than failing boot.
    pub fn open(scratch: &Path) -> anyhow::Result<Self> {
        let directory = scratch.join("collector-errors");
        std::fs::create_dir_all(&directory)
            .with_context(|| format!("create {}", directory.display()))?;
        let path = directory.join(FILE_NAME);
        let mut rows = VecDeque::new();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let mut skipped = 0usize;
                for line in bytes.split(|byte| *byte == b'\n') {
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    match serde_json::from_slice::<CollectorDiagnostic>(line) {
                        Ok(row) => rows.push_back(row),
                        Err(_) => skipped += 1,
                    }
                }
                if skipped > 0 {
                    tracing::warn!(
                        skipped,
                        path = %path.display(),
                        "skipped unreadable collector diagnostic rows"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    path = %path.display(),
                    "collector diagnostics unreadable; starting empty"
                );
            }
        }
        prune(&mut rows, Utc::now());
        Ok(Self {
            path,
            rows: Mutex::new(rows),
        })
    }

    /// Append a parsed batch, prune, and persist. In memory changes only once
    /// the file has been replaced, so a failed write loses nothing already held.
    pub async fn append(
        &self,
        records: Vec<CollectorDiagnostic>,
        now: DateTime<Utc>,
    ) -> anyhow::Result<usize> {
        let accepted = records.len();
        let mut rows = self.rows.lock().await;
        let mut next = rows.clone();
        next.extend(records);
        prune(&mut next, now);
        let mut encoded = Vec::new();
        for row in &next {
            serde_json::to_writer(&mut encoded, row)?;
            encoded.push(b'\n');
        }
        let temporary = self.path.with_extension("jsonl.tmp");
        tokio::fs::write(&temporary, &encoded)
            .await
            .with_context(|| format!("write {}", temporary.display()))?;
        tokio::fs::rename(&temporary, &self.path)
            .await
            .with_context(|| format!("replace {}", self.path.display()))?;
        *rows = next;
        Ok(accepted)
    }

    /// Newest-first errors of one component, plus that component's 24 h count.
    pub async fn list(
        &self,
        component_id: &str,
        limit: usize,
        now: DateTime<Utc>,
    ) -> (Vec<nanosiem_core::log_sources::CollectorError>, i64) {
        let since = now - Duration::hours(24);
        let rows = self.rows.lock().await;
        let mut recent: Vec<&CollectorDiagnostic> = rows
            .iter()
            .filter(|row| row.component_id == component_id && row.occurred_at >= since)
            .collect();
        recent.sort_by(|a, b| b.occurred_at.cmp(&a.occurred_at));
        let total = recent.len() as i64;
        let errors = recent
            .into_iter()
            .take(limit)
            .cloned()
            .map(CollectorDiagnostic::into_api)
            .collect();
        (errors, total)
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.rows.lock().await.len()
    }
}

fn prune(rows: &mut VecDeque<CollectorDiagnostic>, now: DateTime<Utc>) {
    let horizon = now - Duration::days(RETENTION_DAYS);
    rows.retain(|row| row.occurred_at >= horizon && row.received_at >= horizon);
    while rows.len() > MAX_ROWS {
        rows.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_line(component: &str, timestamp: DateTime<Utc>, message: &str) -> String {
        serde_json::json!({
            "timestamp": timestamp.to_rfc3339(),
            "message": message,
            "metadata": {"kind": "event", "level": "ERROR", "module_path": "vector::internal_events::http_client", "target": "vector::internal_events::http_client"},
            "pid": 1,
            "source_type": "internal_logs",
            "vector": {"component_id": component, "component_kind": "source", "component_type": "http_client"},
            "host": "vector-0",
            "error_code": "failed_fetching_events",
            "error_type": "request_failed",
            "stage": "receiving",
            "internal_log_rate_limit": true
        })
        .to_string()
    }

    #[test]
    fn parses_vector_internal_log_shape() {
        let now = Utc::now();
        let body = format!("{}\n\n", vector_line("okta_source", now, "Failed to fetch"));
        let rows = parse_batch(body.as_bytes(), now).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].level, "ERROR");
        assert_eq!(rows[0].component_id, "okta_source");
        assert_eq!(rows[0].component_type, "http_client");
        assert_eq!(rows[0].collector_host, "vector-0");
    }

    #[test]
    fn refuses_invalid_batches() {
        let now = Utc::now();
        assert!(parse_batch(b"\n \n", now).is_err(), "empty");
        assert!(parse_batch(b"not json\n", now).is_err(), "invalid JSON");
        let info = r#"{"message":"x","metadata":{"level":"INFO"}}"#;
        assert!(parse_batch(info.as_bytes(), now).is_err(), "INFO level");
        let stale = vector_line("a", now - Duration::days(15), "old");
        assert!(
            parse_batch(stale.as_bytes(), now).is_err(),
            "outside retention"
        );
        let many = (0..=MAX_BATCH_ROWS)
            .map(|_| vector_line("a", now, "m"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(parse_batch(many.as_bytes(), now).is_err(), "row cap");
    }

    #[tokio::test]
    async fn persists_lists_newest_first_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let log = CollectorErrorLog::open(directory.path()).unwrap();
        let now = Utc::now();
        let body = [
            vector_line("okta_source", now - Duration::minutes(2), "older"),
            vector_line("okta_source", now - Duration::minutes(1), "newer"),
            vector_line("other_source", now, "unrelated"),
            vector_line("okta_source", now - Duration::hours(30), "outside 24h"),
        ]
        .join("\n");
        let rows = parse_batch(body.as_bytes(), now).unwrap();
        assert_eq!(log.append(rows, now).await.unwrap(), 4);

        let (errors, total) = log.list("okta_source", 1, now).await;
        assert_eq!(total, 2);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "newer");

        drop(log);
        let reopened = CollectorErrorLog::open(directory.path()).unwrap();
        let (errors, total) = reopened.list("okta_source", 20, now).await;
        assert_eq!(total, 2);
        assert_eq!(
            errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>(),
            vec!["newer", "older"]
        );
        assert_eq!(reopened.len().await, 4);
    }

    #[tokio::test]
    async fn prunes_by_retention_and_row_cap() {
        let directory = tempfile::tempdir().unwrap();
        let log = CollectorErrorLog::open(directory.path()).unwrap();
        let now = Utc::now();
        let row = |occurred_at: DateTime<Utc>, received_at: DateTime<Utc>, message: &str| {
            CollectorDiagnostic {
                occurred_at,
                received_at,
                level: "ERROR".into(),
                message: message.into(),
                error_code: String::new(),
                error_type: String::new(),
                stage: String::new(),
                component_id: "c".into(),
                component_kind: String::new(),
                component_type: String::new(),
                collector_host: String::new(),
            }
        };
        let old = now - Duration::days(RETENTION_DAYS + 1);
        log.append(vec![row(old, old, "expired"), row(now, now, "kept")], now)
            .await
            .unwrap();
        assert_eq!(log.len().await, 1);

        let flood: Vec<_> = (0..MAX_ROWS + 5)
            .map(|i| row(now, now, &format!("m{i}")))
            .collect();
        log.append(flood, now).await.unwrap();
        assert_eq!(log.len().await, MAX_ROWS);
        let (errors, _) = log.list("c", 100, now).await;
        assert!(
            errors.iter().all(|e| e.message != "kept"),
            "oldest dropped first"
        );
    }

    #[tokio::test]
    async fn corrupt_file_starts_empty_and_is_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let store_dir = directory.path().join("collector-errors");
        std::fs::create_dir_all(&store_dir).unwrap();
        std::fs::write(store_dir.join(FILE_NAME), b"{not json\n\xff\xfe\n").unwrap();
        let log = CollectorErrorLog::open(directory.path()).unwrap();
        assert_eq!(log.len().await, 0);
        let now = Utc::now();
        let rows = parse_batch(vector_line("a", now, "m").as_bytes(), now).unwrap();
        log.append(rows, now).await.unwrap();
        assert_eq!(
            CollectorErrorLog::open(directory.path())
                .unwrap()
                .len()
                .await,
            1
        );
    }
}
