// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure unit tests for durable search jobs. The DB-backed lease / attach /
//! cancel / restart proofs live in
//! `nanosiem-core/tests/search_background_jobs_integration.rs`.

use std::collections::BTreeSet;

use chrono::{TimeZone, Utc};
use uuid::Uuid;

use super::*;
use crate::auth::{ScopeSet, compose_viewer_scope};
use crate::search::jobs::SearchJobStatus;
use crate::search::types::{SearchError, SearchRequest, TimeRangeInput};

fn request(query: &str) -> SearchRequest {
    SearchRequest {
        query: query.to_string(),
        time_range: TimeRangeInput::new(
            Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 2, 0, 0, 0).unwrap(),
        ),
        limit: Some(500),
        offset: Some(1000),
        include_sql: None,
        skip_histogram: false,
        skip_field_stats: false,
        use_cache: true,
        table_view: true,
        request_id: Some("client-req-1".to_string()),
        async_mode: true,
        priority: Some("analytics".to_string()),
        dataset: None,
    }
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn normalization_strips_transport_fields_and_pins_the_cap() {
    let n = normalize_job_request(&request("  error | stats count by src_ip  "), 1234);
    assert_eq!(n.query, "error | stats count by src_ip");
    assert_eq!(n.limit, Some(1234), "the job stores the whole capped result");
    assert_eq!(n.offset, None, "pages are applied on read, never at execution");
    assert_eq!(n.request_id, None, "the worker assigns the attempt query id");
    assert!(!n.async_mode);
    assert_eq!(n.priority, None);
    assert!(!n.use_cache);
    // Result-shaping fields are preserved.
    assert!(n.table_view);
}

#[test]
fn identity_ignores_transport_fields_and_whitespace() {
    let owner = Uuid::now_v7();
    let scope = ScopeSet::unrestricted();
    let a = normalize_job_request(&request("error"), 100);
    let mut other = request("   error ");
    other.request_id = Some("different".into());
    other.offset = Some(0);
    other.limit = Some(10);
    let b = normalize_job_request(&other, 100);
    assert_eq!(identity_hash(&a, owner, &scope), identity_hash(&b, owner, &scope));
}

#[test]
fn identity_is_bound_to_query_time_owner_and_scope() {
    let owner = Uuid::now_v7();
    let scope = ScopeSet::unrestricted();
    let base = normalize_job_request(&request("error"), 100);
    let h = identity_hash(&base, owner, &scope);

    let other_query = normalize_job_request(&request("warning"), 100);
    assert_ne!(h, identity_hash(&other_query, owner, &scope));

    let mut shifted = base.clone();
    shifted.time_range.end += chrono::Duration::seconds(1);
    assert_ne!(h, identity_hash(&shifted, owner, &scope), "time range is part of identity");

    assert_ne!(h, identity_hash(&base, Uuid::now_v7(), &scope), "never shared across owners");

    let restricted = ScopeSet::from_denied(set(&["okta"]));
    assert_ne!(h, identity_hash(&base, owner, &restricted), "scope is part of identity");

    // Same deny-set, different split between row-filter-only and artifact
    // deny must not collide either (it changes prevalence provenance gates).
    let audit_gate = compose_viewer_scope(&ScopeSet::unrestricted(), false);
    let audit_rbac = ScopeSet::from_denied(set(&["audit"]));
    assert_eq!(audit_gate.deny_set(), audit_rbac.deny_set());
    assert_ne!(
        identity_hash(&base, owner, &audit_gate),
        identity_hash(&base, owner, &audit_rbac)
    );

    let mut other_dataset = base.clone();
    other_dataset.dataset = Some("spans".into());
    assert_ne!(h, identity_hash(&other_dataset, owner, &scope));
}

#[test]
fn durable_ids_round_trip_and_never_claim_legacy_ids() {
    let id = Uuid::now_v7();
    let public = encode_job_id(&id);
    assert!(public.starts_with("sjob_"));
    assert!(is_durable_job_id(&public));
    assert_eq!(decode_job_id(&public), Some(id));

    // Legacy in-memory job ids are bare UUID strings: they must keep routing
    // to the legacy store (decode's bare-UUID fallback is NOT honored).
    let legacy = Uuid::now_v7().to_string();
    assert!(!is_durable_job_id(&legacy));
    assert_eq!(decode_job_id(&legacy), None);
    assert_eq!(decode_job_id("sjobx_abc"), None);
    assert_eq!(decode_job_id("sjob_notbase32!!"), None);
}

fn job_with_scope(deny: &[&str], artifact: &[&str]) -> DurableSearchJob {
    let now = Utc::now();
    DurableSearchJob {
        id: Uuid::now_v7(),
        owner_user_id: Uuid::now_v7(),
        identity_hash: String::new(),
        query: "error".into(),
        request: request("error"),
        page_limit: None,
        scope_deny: set(deny),
        scope_artifact_deny: set(artifact),
        origin: JobOrigin::Submitted,
        state: SearchJobStatus::Completed,
        attempt: 1,
        max_attempts: 3,
        lease_owner: None,
        lease_expires_at: None,
        ch_query_id: None,
        progress: None,
        result_attempt: Some(1),
        row_count: Some(0),
        result_truncated: false,
        result_meta: None,
        error_kind: None,
        error_message: None,
        created_at: now,
        started_at: None,
        heartbeat_at: None,
        finished_at: None,
        expires_at: now,
    }
}

#[test]
fn stamped_scope_rebuilds_the_executed_scope_exactly() {
    // Viewer without audit:view and one RBAC-denied source.
    let viewer = compose_viewer_scope(&ScopeSet::from_denied(set(&["okta"])), false);
    let job = job_with_scope(
        &viewer.deny_set().iter().map(String::as_str).collect::<Vec<_>>(),
        &viewer
            .artifact_deny_set()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    assert_eq!(job.scope(), viewer, "the worker must execute under the stamped scope");
}

#[test]
fn result_visibility_is_rechecked_against_current_scope() {
    let job = job_with_scope(&["audit", "okta"], &["okta"]);
    assert!(job.result_visible_under(&set(&[])), "widened scope may read");
    assert!(job.result_visible_under(&set(&["okta"])));
    assert!(job.result_visible_under(&set(&["audit", "okta"])));
    assert!(
        !job.result_visible_under(&set(&["okta", "m365"])),
        "a source denied after submission hides the result"
    );
}

#[test]
fn error_classification_is_typed_and_masks_internals() {
    let (k, _) = classify_search_error(&SearchError::Cancelled);
    assert_eq!(k, JobErrorKind::Cancelled);

    let (k, _) = classify_search_error(&SearchError::Timeout(1000));
    assert_eq!(k, JobErrorKind::Timeout);

    let (k, _) = classify_search_error(&SearchError::ResponseTooLarge(10, 5));
    assert_eq!(k, JobErrorKind::QueryTooLarge);

    let (k, msg) = classify_search_error(&SearchError::ParseError("Unexpected token".into()));
    assert_eq!(k, JobErrorKind::InvalidQuery);
    assert!(msg.contains("Unexpected token"), "parse errors reach the owner");

    let (k, msg) =
        classify_search_error(&SearchError::SqlGenError("failed to build CTE stage".into()));
    assert_eq!(k, JobErrorKind::InvalidQuery);
    assert_eq!(msg, "Query processing failed", "internal generation detail is masked");

    let (k, _) = classify_search_error(&crate::search::parse_clickhouse_error(
        "Code: 241. DB::Exception: Memory limit (for query) exceeded: (MEMORY_LIMIT_EXCEEDED)",
    ));
    assert_eq!(k, JobErrorKind::QueryTooLarge);

    let (k, _) = classify_search_error(&crate::search::parse_clickhouse_error(
        "Code: 159. DB::Exception: Timeout exceeded: elapsed 1800 seconds (TIMEOUT_EXCEEDED)",
    ));
    assert_eq!(k, JobErrorKind::Timeout);

    let (k, msg) = classify_search_error(&SearchError::PrevalenceError(
        "ClickHouse error: connection refused to 10.0.0.5".into(),
    ));
    assert_eq!(k, JobErrorKind::Internal);
    assert!(!msg.contains("10.0.0.5"), "internal detail must not leak: {msg}");
}

#[test]
fn error_kinds_round_trip_through_their_db_names() {
    for kind in [
        JobErrorKind::Cancelled,
        JobErrorKind::Timeout,
        JobErrorKind::QueryTooLarge,
        JobErrorKind::InvalidQuery,
        JobErrorKind::WorkerLost,
        JobErrorKind::Internal,
    ] {
        assert_eq!(JobErrorKind::parse(kind.as_str()), Some(kind));
        // serde name == DB name, so the API and the CHECK constraint agree.
        assert_eq!(
            serde_json::to_value(kind).unwrap(),
            serde_json::Value::String(kind.as_str().to_string())
        );
    }
}

#[test]
fn background_settings_rank_below_interactive() {
    let cfg = BackgroundJobConfig::default();
    let bg = cfg.ch_settings();
    let interactive = crate::search::QueryPriority::Interactive.to_ch_settings();
    assert!(
        bg.priority > interactive.priority,
        "ClickHouse schedules lower numbers first: background must yield to interactive"
    );
    assert_eq!(bg.max_execution_time, cfg.max_execution_secs);
    assert!(bg.max_threads <= interactive.max_threads);
}

#[test]
fn heartbeat_interval_never_exceeds_a_third_of_the_lease() {
    // This test owns these variable names; nothing else reads them.
    std::env::set_var("SEARCH_JOB_LEASE_SECS", "6");
    std::env::set_var("SEARCH_JOB_HEARTBEAT_SECS", "60");
    let cfg = BackgroundJobConfig::from_env();
    std::env::remove_var("SEARCH_JOB_LEASE_SECS");
    std::env::remove_var("SEARCH_JOB_HEARTBEAT_SECS");
    assert_eq!(cfg.lease_ttl.as_secs(), 6);
    assert!(cfg.heartbeat_interval <= cfg.lease_ttl / 3);
}

#[test]
fn relative_modifiers_are_frozen_once_and_stripped() {
    let t = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let raw = request("error earliest=-1h latest=now | stats count by user");
    let frozen = freeze_time_window(&raw, t).unwrap();
    assert_eq!(frozen.time_range.start, t - chrono::Duration::hours(1));
    assert_eq!(frozen.time_range.end, t);
    assert!(!frozen.query.contains("earliest"), "modifier stripped: {}", frozen.query);
    assert!(!frozen.query.contains("latest"));
    assert!(frozen.query.contains("stats count by user"));

    // A worker claiming 30 minutes later (or a reclaimed attempt) sees the
    // frozen request: freezing it again at T+30m changes nothing.
    let later = t + chrono::Duration::minutes(30);
    let again = freeze_time_window(&frozen, later).unwrap();
    assert_eq!(again.time_range.start, frozen.time_range.start);
    assert_eq!(again.time_range.end, frozen.time_range.end);
    assert_eq!(again.query, frozen.query);
    // Whereas the RAW query re-resolved at T+30m would have moved the window.
    let drifted = freeze_time_window(&raw, later).unwrap();
    assert_ne!(drifted.time_range.start, frozen.time_range.start);
}

#[test]
fn identity_hashes_the_frozen_window_not_the_relative_text() {
    let owner = Uuid::now_v7();
    let scope = ScopeSet::unrestricted();
    let t = Utc.with_ymd_and_hms(2026, 11, 3, 12, 0, 0).unwrap();
    let raw = request("error earliest=-1h latest=now");
    let at_t = normalize_job_request(&freeze_time_window(&raw, t).unwrap(), 10);
    let at_t2 = normalize_job_request(
        &freeze_time_window(&raw, t + chrono::Duration::minutes(5)).unwrap(),
        10,
    );
    assert_ne!(
        identity_hash(&at_t, owner, &scope),
        identity_hash(&at_t2, owner, &scope),
        "the same relative text at different times is a different window"
    );
}

#[test]
fn a_request_without_modifiers_is_left_untouched() {
    let raw = request("error | stats count by user  // a comment");
    let frozen = freeze_time_window(&raw, Utc::now()).unwrap();
    assert_eq!(frozen.query, raw.query, "no modifiers: query text unchanged");
    assert_eq!(frozen.time_range.start, raw.time_range.start);
}

/// Codex P2-6: cancel must KILL every companion query a search can spawn. Scan
/// the executor sources for derived `{query_id}-<suffix>` ids and require each
/// suffix to be in the exact kill set (a new companion without a kill-set entry
/// fails here instead of running on after cancel).
#[test]
fn kill_set_covers_every_derived_companion_query_id() {
    let kill_set = crate::search::service::all_query_ids("Q");
    let sources = [
        include_str!("../execution/clickhouse_executor/paginated.rs"),
        include_str!("../service/core_search.rs"),
        include_str!("../service/streaming.rs"),
    ];
    let mut found = std::collections::BTreeSet::new();
    for src in sources {
        for (i, _) in src.match_indices("format!(\"{query_id}-") {
            let rest = &src[i + "format!(\"{query_id}-".len()..];
            let suffix: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            found.insert(suffix);
        }
    }
    assert!(found.contains("aggregate-count"), "scan found: {found:?}");
    for suffix in found {
        assert!(
            kill_set.contains(&format!("Q-{suffix}")),
            "companion query id suffix `-{suffix}` is not in all_query_ids — cancel would leave it running"
        );
    }
}
