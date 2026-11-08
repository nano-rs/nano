// SPDX-License-Identifier: AGPL-3.0-or-later

//! Job request normalization and the attach identity.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use chrono::{DateTime, Utc};

use crate::auth::ScopeSet;
use crate::search::types::{SearchError, SearchRequest};

/// Freeze the request's search window ONCE (Codex P1-2).
///
/// `earliest=` / `latest=` modifiers in the query text override
/// `time_range` inside `SearchService::search`, resolved against a fresh
/// `Utc::now()` on every execution. Stored verbatim, a job submitted at 12:00
/// as `error earliest=-1h` would scan 11:30–12:30 if claimed at 12:30, and
/// shift again on every reclaimed attempt. This resolves the modifiers against
/// the single captured `now`, writes the result into `time_range`, and removes
/// them (and comments, exactly as the search path does) from the query, so the
/// stored request is absolute and every attempt scans the same window.
/// Idempotent: freezing an already-frozen request changes nothing.
pub fn freeze_time_window(
    request: &SearchRequest,
    now: DateTime<Utc>,
) -> Result<SearchRequest, SearchError> {
    let (cleaned, earliest, latest) =
        crate::search::service::extract_time_bounds_at(&request.query, now)?;
    let mut frozen = request.clone();
    if earliest.is_none() && latest.is_none() {
        return Ok(frozen);
    }
    frozen.query = cleaned;
    if let Some(start) = earliest {
        frozen.time_range.start = start;
    }
    if let Some(end) = latest {
        frozen.time_range.end = end;
    }
    frozen.time_range.validate()?;
    Ok(frozen)
}

/// The request a background job actually executes.
///
/// * `limit` becomes the background result cap and `offset` is dropped: the
///   job stores the whole (capped) result so every later page is served from
///   the results table instead of a re-scan. The caller's page size is applied
///   when reading.
/// * Per-request transport fields (`request_id`, `async_mode`, `priority`,
///   `use_cache`) are cleared — the worker assigns its own query id and tier.
/// * The query text is trimmed so whitespace-only differences attach.
///
/// Callers freeze the window first ([`freeze_time_window`]); the time range is
/// then absolute and kept as-is, so a job is bound to exactly the window that
/// was asked for.
pub fn normalize_job_request(request: &SearchRequest, result_cap: usize) -> SearchRequest {
    let mut normalized = request.clone();
    normalized.query = request.query.trim().to_string();
    normalized.limit = Some(result_cap);
    normalized.offset = None;
    normalized.request_id = None;
    normalized.async_mode = false;
    normalized.priority = None;
    normalized.use_cache = false;
    normalized
}

/// Digest that decides whether two submissions are "the same search".
///
/// Bound to: the normalized request (query, absolute time range, dataset, view
/// and companion flags, result cap), the owner, and BOTH halves of the owner's
/// effective source scope. Two submissions that differ in any of these would
/// produce different rows, so they never share a job. Field order is fixed and
/// every field is length-prefixed, so no two distinct inputs share a preimage.
pub fn identity_hash(normalized: &SearchRequest, owner: Uuid, scope: &ScopeSet) -> String {
    let mut hasher = Sha256::new();
    let mut field = |name: &str, value: &str| {
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    };
    field("v", "1");
    field("owner", &owner.to_string());
    field("query", &normalized.query);
    field(
        "start",
        &normalized.time_range.start.timestamp_micros().to_string(),
    );
    field("end", &normalized.time_range.end.timestamp_micros().to_string());
    field("dataset", normalized.dataset.as_deref().unwrap_or(""));
    field("table_view", bool_str(normalized.table_view));
    field("skip_histogram", bool_str(normalized.skip_histogram));
    field("skip_field_stats", bool_str(normalized.skip_field_stats));
    field(
        "include_sql",
        bool_str(normalized.include_sql.unwrap_or(false)),
    );
    field(
        "limit",
        &normalized.limit.map(|l| l.to_string()).unwrap_or_default(),
    );
    field("deny", &join_sorted(scope.deny_set()));
    field("artifact_deny", &join_sorted(scope.artifact_deny_set()));
    hex::encode(hasher.finalize())
}

fn bool_str(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

/// BTreeSet iteration is already sorted; NUL cannot appear in a source_type.
fn join_sorted(set: &std::collections::BTreeSet<String>) -> String {
    set.iter().map(String::as_str).collect::<Vec<_>>().join("\0")
}
