// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lookup table ingestion-history handler.
//!
//! Powers the **History** tab on the redesigned LookupTableView (NAN-510
//! slice 3 PR 3 / NAN-512). Returns a merged, time-sorted list of recent
//! activity on a lookup table:
//!
//! - **Refresh** events come from `scheduled_jobs.last_run_*` (the
//!   ingestion-runs table only persists the most-recent run, so callers
//!   currently get at most one refresh entry — see `TODO(NAN-512)` below).
//! - **Edit / upload** events come from the ClickHouse audit log, scoped
//!   to `source = "lookup"` and matched to this table by `resource_name`.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::Utc;
use serde::Deserialize;
use tracing::instrument;
use utoipa::IntoParams;

use nanosiem_core::audit::ClickHouseAuditQuery;
use nanosiem_core::auth::permissions;
use nanosiem_core::{
    LookupHistoryEntry, LookupHistoryKind, SchedulerService,
};

use super::lookup_error_to_api;
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Default and ceiling for the `limit` query parameter.
const DEFAULT_LIMIT: i64 = 50;
const MAX_LIMIT: i64 = 200;

/// How far back we look in the audit log when assembling history. The
/// LookupTableView History tab is meant to surface "recent" activity — older
/// audit volume on lookups is uninteresting and would slow the ClickHouse
/// scan.
const AUDIT_LOOKBACK_DAYS: i64 = 90;

/// Query parameters for [`get_lookup_table_ingestion_history`].
#[derive(Debug, Deserialize, IntoParams)]
pub struct LookupHistoryQuery {
    /// Maximum number of entries to return (default 50, max 200).
    pub limit: Option<i64>,
}

/// Get the ingestion + edit history for a lookup table
///
/// `GET /api/lookup-tables/{name}/ingestion-history?limit=50`
///
/// Returns a merged, time-sorted (descending) list of recent activity on the
/// table — automated refresh runs plus user edit / upload events from the
/// audit log.
///
/// # Stub behavior
///
/// * Refresh entries currently come from `scheduled_jobs.last_run_*`, which
///   only stores the **most recent** run. Until a per-execution history table
///   is added, callers will get at most one `kind = "refresh"` entry. See
///   `TODO(NAN-512)` below.
/// * Refresh `note` strings do not include row deltas
///   (`+N · −M · K total`) for the same reason — the schema does not persist
///   per-run row counts. The note is `"completed"` / `"failed: <error>"`.
#[utoipa::path(
    get,
    path = "/api/lookup-tables/{name}/ingestion-history",
    tag = "lookup",
    params(
        ("name" = String, Path, description = "Lookup table name"),
        LookupHistoryQuery,
    ),
    responses(
        (status = 200, description = "Recent activity on the lookup table", body = Vec<LookupHistoryEntry>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Lookup table not found"),
    ),
    security(("api_key" = []))
)]
#[instrument(skip(state, auth))]
pub async fn get_lookup_table_ingestion_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(name): Path<String>,
    Query(params): Query<LookupHistoryQuery>,
) -> Result<Json<Vec<LookupHistoryEntry>>, ApiError> {
    check_permission(&auth, permissions::LOOKUP_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: lookup:view".to_string()))?;

    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);

    // 404 if the table doesn't exist — preserves the "endpoint is scoped to a
    // real table" contract and matches GET /:name behavior.
    let lookup_service = state.lookup_service.clone();
    let _table = lookup_service
        .get_table(&name)
        .await
        .map_err(lookup_error_to_api)?;

    let mut entries: Vec<LookupHistoryEntry> = Vec::new();

    // ---------------------------------------------------------------------
    // 1. Refresh runs from the scheduler (single most-recent run, if any).
    //
    // TODO(NAN-512): replace this with a `lookup_ingestion_runs` table
    // capturing every execution + row deltas (`rows_added`, `rows_removed`,
    // `rows_total`) so the history shows the full refresh timeline and
    // notes can be rendered as `"+N rows · −M rows · K total"`.
    // ---------------------------------------------------------------------
    let scheduler_service = SchedulerService::new(state.pool.clone());
    if let Some(job) = scheduler_service
        .get_job_for_lookup_table(&name)
        .await
        .map_err(|e| {
            tracing::warn!(lookup_table = %name, error = %e, "Failed to load scheduler job for lookup history");
            ApiError::InternalError("Failed to load ingestion history".to_string())
        })?
    {
        if let (Some(when), Some(status)) = (job.last_run_at, job.last_run_status) {
            let note = format_refresh_note(status.as_str(), job.last_run_error.as_deref());
            entries.push(LookupHistoryEntry {
                when,
                actor: "scheduler".to_string(),
                kind: LookupHistoryKind::Refresh,
                note,
            });
        }
    }

    // ---------------------------------------------------------------------
    // 2. Edit / upload events from the audit log (ClickHouse).
    //
    // We pull the last `AUDIT_LOOKBACK_DAYS` of `source = "lookup"` events
    // and filter to this table by `resource_name`. The audit query service
    // doesn't support filtering on `resource_name` directly; the volume of
    // lookup-source audit events is low so a Rust-side filter is fine.
    // ---------------------------------------------------------------------
    // We pull a buffer of audit events (4× the caller's limit) before
    // Rust-side filtering by `resource_name`, since the audit query
    // service can't filter on that field directly. Capped at the
    // service's own 1000-row hard limit.
    let ch_audit_limit = (limit.saturating_mul(4)).min(1000);
    let ch_query = ClickHouseAuditQuery {
        source: Some("lookup".to_string()),
        start_time: Some(Utc::now() - chrono::Duration::days(AUDIT_LOOKBACK_DAYS)),
        limit: Some(ch_audit_limit),
        ..Default::default()
    };

    match state.audit_query_service.query(&ch_query).await {
        Ok(rows) => {
            for row in rows {
                if row.resource_name.as_deref() != Some(name.as_str()) {
                    continue;
                }
                let action = row.action.as_deref().unwrap_or("");
                let Some(kind) = classify_audit_action(action) else {
                    continue;
                };
                entries.push(LookupHistoryEntry {
                    when: row.timestamp,
                    actor: row.user.unwrap_or_else(|| "system".to_string()),
                    kind,
                    note: humanize_audit_action(action),
                });
            }
        }
        Err(e) => {
            // Don't fail the whole endpoint if ClickHouse is briefly
            // unavailable — refresh entries (from PG) are still useful.
            tracing::warn!(
                lookup_table = %name,
                error = %e,
                "Failed to query audit log for lookup history; returning refresh-only history",
            );
        }
    }

    // Sort descending by timestamp + truncate.
    entries.sort_by(|a, b| b.when.cmp(&a.when));
    entries.truncate(limit as usize);

    Ok(Json(entries))
}

/// Render the `note` string for a refresh entry from the scheduler's
/// `last_run_status` + `last_run_error`.
///
/// TODO(NAN-512): once a per-execution table exists, prefer
/// `"+N rows · −M rows · K total"` when row deltas are available, falling
/// back to this string only on failure or when deltas weren't recorded.
fn format_refresh_note(status: &str, error: Option<&str>) -> String {
    match status {
        "success" => "completed".to_string(),
        "failed" => match error {
            Some(e) if !e.is_empty() => format!("failed: {}", truncate_error(e)),
            _ => "failed".to_string(),
        },
        "running" => "in progress".to_string(),
        other => other.to_string(),
    }
}

/// Cap an error message so a misbehaving fetcher can't blow up the response.
fn truncate_error(s: &str) -> String {
    const MAX_ERROR_LEN: usize = 200;
    if s.chars().count() <= MAX_ERROR_LEN {
        return s.to_string();
    }
    let mut out: String = s.chars().take(MAX_ERROR_LEN.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Map an audit `action` string to a [`LookupHistoryKind`].
///
/// Returns `None` for actions we don't surface in the history tab (e.g. the
/// catch-all `LOOKUP_TABLE_DELETED` — by the time history is queried the
/// table is gone, so a delete entry would be unreachable; we still classify
/// it as `Edit` here so logs filtered before deletion render sensibly).
fn classify_audit_action(action: &str) -> Option<LookupHistoryKind> {
    use nanosiem_core::audit::{
        LOOKUP_ROWS_ADDED, LOOKUP_ROWS_DELETED, LOOKUP_ROW_UPDATED, LOOKUP_TABLE_CREATED,
        LOOKUP_TABLE_DELETED,
    };

    if action == LOOKUP_TABLE_CREATED {
        // First create is conceptually the initial upload of the table.
        Some(LookupHistoryKind::Upload)
    } else if action == LOOKUP_ROWS_ADDED {
        // Bulk row additions = an upload (CSV, paste, ingestion replay).
        Some(LookupHistoryKind::Upload)
    } else if action == LOOKUP_ROW_UPDATED || action == LOOKUP_ROWS_DELETED {
        Some(LookupHistoryKind::Edit)
    } else if action == LOOKUP_TABLE_DELETED {
        Some(LookupHistoryKind::Edit)
    } else {
        None
    }
}

/// Humanize an audit action constant for display.
///
/// TODO(NAN-512): the audit `details` JSON could carry richer context (e.g.
/// row counts, column-type changes). Once edit emitters populate
/// `details.row_count` / `details.column` / `details.from_type` etc., this
/// can render strings like `"changed confidence column type int → float"` or
/// `"+47 rows"`. For now we return a simple humanized form of the action.
fn humanize_audit_action(action: &str) -> String {
    use nanosiem_core::audit::{
        LOOKUP_ROWS_ADDED, LOOKUP_ROWS_DELETED, LOOKUP_ROW_UPDATED, LOOKUP_TABLE_CREATED,
        LOOKUP_TABLE_DELETED,
    };

    if action == LOOKUP_TABLE_CREATED {
        "table created".to_string()
    } else if action == LOOKUP_TABLE_DELETED {
        "table deleted".to_string()
    } else if action == LOOKUP_ROWS_ADDED {
        "rows added".to_string()
    } else if action == LOOKUP_ROW_UPDATED {
        "row updated".to_string()
    } else if action == LOOKUP_ROWS_DELETED {
        "rows deleted".to_string()
    } else {
        action.replace('_', " ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::audit::{
        LOOKUP_ROWS_ADDED, LOOKUP_ROWS_DELETED, LOOKUP_ROW_UPDATED, LOOKUP_TABLE_CREATED,
        LOOKUP_TABLE_DELETED,
    };

    #[test]
    fn refresh_note_success() {
        assert_eq!(format_refresh_note("success", None), "completed");
        assert_eq!(format_refresh_note("success", Some("ignored")), "completed");
    }

    #[test]
    fn refresh_note_failed_with_error() {
        assert_eq!(
            format_refresh_note("failed", Some("HTTP 500")),
            "failed: HTTP 500"
        );
    }

    #[test]
    fn refresh_note_failed_without_error() {
        assert_eq!(format_refresh_note("failed", None), "failed");
        assert_eq!(format_refresh_note("failed", Some("")), "failed");
    }

    #[test]
    fn refresh_note_running() {
        assert_eq!(format_refresh_note("running", None), "in progress");
    }

    #[test]
    fn truncate_error_caps_long_strings() {
        let long = "x".repeat(500);
        let out = truncate_error(&long);
        assert!(out.chars().count() <= 200);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_error_passes_short_strings_through() {
        assert_eq!(truncate_error("boom"), "boom");
    }

    #[test]
    fn classify_recognized_actions() {
        assert_eq!(
            classify_audit_action(LOOKUP_TABLE_CREATED),
            Some(LookupHistoryKind::Upload)
        );
        assert_eq!(
            classify_audit_action(LOOKUP_ROWS_ADDED),
            Some(LookupHistoryKind::Upload)
        );
        assert_eq!(
            classify_audit_action(LOOKUP_ROW_UPDATED),
            Some(LookupHistoryKind::Edit)
        );
        assert_eq!(
            classify_audit_action(LOOKUP_ROWS_DELETED),
            Some(LookupHistoryKind::Edit)
        );
        assert_eq!(
            classify_audit_action(LOOKUP_TABLE_DELETED),
            Some(LookupHistoryKind::Edit)
        );
    }

    #[test]
    fn classify_unknown_actions() {
        assert_eq!(classify_audit_action("login_success"), None);
        assert_eq!(classify_audit_action(""), None);
    }

    #[test]
    fn humanize_known_actions() {
        assert_eq!(humanize_audit_action(LOOKUP_TABLE_CREATED), "table created");
        assert_eq!(humanize_audit_action(LOOKUP_ROWS_ADDED), "rows added");
        assert_eq!(humanize_audit_action(LOOKUP_ROW_UPDATED), "row updated");
        assert_eq!(humanize_audit_action(LOOKUP_ROWS_DELETED), "rows deleted");
        assert_eq!(humanize_audit_action(LOOKUP_TABLE_DELETED), "table deleted");
    }

    #[test]
    fn humanize_unknown_action_replaces_underscores() {
        assert_eq!(humanize_audit_action("foo_bar_baz"), "foo bar baz");
    }
}
