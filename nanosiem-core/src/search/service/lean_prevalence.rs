// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3088: Prevalence export and the rare-artifact list on a lean-lake cell.
//!
//! Both are the same computation: every artifact of the tenant's prevalence
//! window whose distinct-host count is under the rarity threshold. On a lean
//! tenant that aggregates hundreds of thousands of entities per hour, so it
//! never runs inline. It is a durable `PrevalenceExportV1` job on the tenant's
//! own cell:
//!
//! * the job is admitted by [`SearchService::durable_view_admission`] over
//!   `[max(retention cutoff, now - window), now]`;
//! * the runner signs the moving retention-cutoff proof over that range;
//! * query[T] builds the prevalence window relation (the same part partials
//!   and exact edge rows `| prevalence` reads) over the proof's CURRENT
//!   clamped window, so the result is exact at the cutoff;
//! * every read of the result re-checks the proof.
//!
//! The rare list pages the newest matching job result of the caller (or
//! queues one) instead of recomputing, so a warm page answers in one result
//! page read.

use super::*;
use crate::search::jobs::{SearchJob, SearchJobStatus, SearchJobSummary};

/// Rows one lean prevalence export (and the rare list read from it) holds.
/// The same bound as the queued tenant export (`PREVALENCE_EXPORT_MAX_ROWS`).
pub const LEAN_PREVALENCE_EXPORT_MAX_ROWS: usize = 100_000;

/// A rare-list result is reused for this long before a new job is queued.
pub const LEAN_PREVALENCE_RARE_REUSE_MS: u64 = 10 * 60 * 1_000;

/// What a lean prevalence job is for. The purpose is part of the job's query
/// text so a rare list never reuses an export and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeanPrevalencePurpose {
    Export,
    Rare,
}

/// The typed parameters of one lean prevalence job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanPrevalenceJob {
    pub purpose: LeanPrevalencePurpose,
    pub window: PrevalenceTimeWindow,
    /// `hash`, `domain` or `ip`.
    pub artifact_type: Option<String>,
    pub max_prevalence: u64,
    /// `csv` or `json` (the download format; a rare list is `json`).
    pub format: String,
}

impl LeanPrevalenceJob {
    /// The job's stable text: the key a rare list reuses a result by, and the
    /// query preview the Active Searches panel shows.
    pub fn query_text(&self) -> String {
        let purpose = match self.purpose {
            LeanPrevalencePurpose::Export => "export",
            LeanPrevalencePurpose::Rare => "rare",
        };
        format!(
            "prevalence {purpose} window={} type={} max_prevalence={} format={}",
            self.window,
            self.artifact_type.as_deref().unwrap_or("all"),
            self.max_prevalence,
            self.format,
        )
    }

    pub fn task(&self) -> crate::search::DurableLakeTask {
        crate::search::DurableLakeTask::PrevalenceExportV1 {
            window: self.window.to_string(),
            artifact_type: self.artifact_type.clone(),
            max_prevalence: self.max_prevalence,
            format: self.format.clone(),
        }
    }

    /// Whether `job` is exactly this job (task and text), so a caller-named
    /// job id can never page another export's or another window's result.
    pub fn matches(&self, job: &SearchJob) -> bool {
        job.task.as_ref() == Some(&self.task()) && job.request.query == self.query_text()
    }

    /// The newest reusable job of this shape among the caller's own jobs:
    /// queued, running or completed, created within `max_age_ms`.
    pub fn reusable<'a>(&self, jobs: &'a [SearchJobSummary], now_ms: u64, max_age_ms: u64) -> Option<&'a SearchJobSummary> {
        let text = self.query_text();
        jobs.iter()
            .filter(|job| {
                job.task_kind.as_deref() == Some("prevalence_export_v1")
                    && job.query == text
                    && matches!(job.status, SearchJobStatus::Queued | SearchJobStatus::Running | SearchJobStatus::Completed)
                    && now_ms.saturating_sub(job.created_at_ms) <= max_age_ms
            })
            .max_by_key(|job| job.created_at_ms)
    }
}

impl SearchService {
    /// Queue a lean prevalence job on the tenant's own cell (NAN-3088).
    ///
    /// Refused unless this view serves a lean-lake cell with its hosted job
    /// runner; a shared view additionally needs its current retention
    /// identity (`durable_view_admission`). The admitted range is
    /// `[now - window, now]` bound to the retention cutoff.
    pub async fn enqueue_lean_prevalence_job(
        &self,
        job: &LeanPrevalenceJob,
        scope: &crate::auth::ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        if !self.serves_lake_cell() {
            return Err(SearchError::ServiceUnavailable(
                "lean Prevalence exports run on the tenant's lean-lake cell".to_string(),
            ));
        }
        let task = job.task();
        task.validate()
            .map_err(|error| SearchError::SqlValidationError(error.to_string()))?;
        let end = chrono::Utc::now();
        let requested = TimeRange::new(end - chrono::Duration::hours(job.window.hours()), end);
        let (generation_pin, range) = self
            .durable_view_admission("durable Prevalence exports", &requested)
            .await?;
        let request = SearchRequest {
            query: job.query_text(),
            time_range: TimeRangeInput::new(range.start, range.end),
            limit: Some(LEAN_PREVALENCE_EXPORT_MAX_ROWS),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &task,
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Prevalence export admission failed: {error}"
                ))
            })
    }
}

/// One rare-list row from a lean prevalence result page, in the
/// `PrevalenceData` wire shape. `first_seen` / `last_seen` are RFC3339.
pub fn lean_prevalence_row(row: &serde_json::Value) -> Option<PrevalenceData> {
    let text = |key: &str| row.get(key).and_then(serde_json::Value::as_str);
    let number = |key: &str| {
        row.get(key).and_then(|value| {
            value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
    };
    let time = |key: &str| {
        let raw = text(key)?;
        chrono::DateTime::parse_from_rfc3339(raw)
            .map(|time| time.with_timezone(&chrono::Utc))
            .ok()
            .or_else(|| {
                chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f")
                    .ok()
                    .map(|time| time.and_utc())
            })
    };
    let artifact_type = serde_json::from_value(serde_json::Value::String(text("artifact_type")?.to_string())).ok()?;
    Some(PrevalenceData {
        artifact: text("artifact")?.to_string(),
        artifact_type,
        host_count: number("host_count")?,
        host_count_saturated: false,
        total_occurrences: number("total_occurrences").unwrap_or_default(),
        first_seen: time("first_seen")?,
        last_seen: time("last_seen")?,
        is_rare: row.get("is_rare").and_then(serde_json::Value::as_bool).unwrap_or(true),
        prevalence_score: number("prevalence_score").and_then(|score| u8::try_from(score).ok()).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(purpose: LeanPrevalencePurpose) -> LeanPrevalenceJob {
        LeanPrevalenceJob {
            purpose,
            window: PrevalenceTimeWindow::TwentyFourHours,
            artifact_type: Some("hash".into()),
            max_prevalence: 3,
            format: "json".into(),
        }
    }

    fn summary(id: &str, query: &str, status: SearchJobStatus, created_at_ms: u64) -> SearchJobSummary {
        SearchJobSummary {
            job_id: id.into(),
            status,
            query: query.into(),
            created_at_ms,
            elapsed_ms: 0,
            queue_position: None,
            priority: crate::search::QueryPriority::Analytics,
            task_kind: Some("prevalence_export_v1".into()),
        }
    }

    #[test]
    fn a_rare_list_reuses_only_its_own_fresh_live_job() {
        let rare = job(LeanPrevalencePurpose::Rare);
        let text = rare.query_text();
        assert_eq!(text, "prevalence rare window=24h type=hash max_prevalence=3 format=json");
        assert_ne!(text, job(LeanPrevalencePurpose::Export).query_text(), "an export is never reused as a rare list");
        let now = 100 * 60 * 1_000;
        let jobs = vec![
            summary("old", &text, SearchJobStatus::Completed, now - LEAN_PREVALENCE_RARE_REUSE_MS - 1),
            summary("failed", &text, SearchJobStatus::Failed, now - 1_000),
            summary("other-window", &text.replace("24h", "7d"), SearchJobStatus::Completed, now - 1_000),
            summary("fresh", &text, SearchJobStatus::Completed, now - 60_000),
            summary("running", &text, SearchJobStatus::Running, now - 30_000),
        ];
        assert_eq!(rare.reusable(&jobs, now, LEAN_PREVALENCE_RARE_REUSE_MS).unwrap().job_id, "running");
        assert!(rare.reusable(&jobs[..3], now, LEAN_PREVALENCE_RARE_REUSE_MS).is_none());
    }

    #[test]
    fn the_task_is_the_closed_prevalence_export() {
        let export = job(LeanPrevalencePurpose::Export);
        let task = export.task();
        task.validate().unwrap();
        assert!(task.is_lean_view());
        assert_eq!(task.kind(), "prevalence_export_v1");
    }

    #[test]
    fn result_rows_decode_both_timestamp_spellings() {
        let row = serde_json::json!({
            "artifact": "d41d8cd98f00b204e9800998ecf8427e", "artifact_type": "hash_md5", "host_count": 1,
            "total_occurrences": "7", "first_seen": "2026-09-30T11:00:00.000000Z",
            "last_seen": "2026-09-30 12:00:00.500000", "is_rare": true, "prevalence_score": 7,
        });
        let data = lean_prevalence_row(&row).unwrap();
        assert_eq!(data.host_count, 1);
        assert_eq!(data.total_occurrences, 7);
        assert!(data.last_seen > data.first_seen);
        assert!(lean_prevalence_row(&serde_json::json!({"artifact": "x"})).is_none());
    }
}
