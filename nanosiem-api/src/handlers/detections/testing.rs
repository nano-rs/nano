// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule testing, formatting, and validation

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{Duration, Utc};
use dashmap::DashMap;
use nanosiem_core::auth::permissions;
use nanosiem_core::search::TimeRangeInput;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::HistoricalAnalysisResult;
use std::sync::Arc;
use uuid::Uuid;

use super::strip_comments;
use super::types::*;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Default test range when the client doesn't pass one. Matches Chronicle's
/// "Run rule against historical data" default. Short on purpose so the
/// drawer opens cheaply — explicit longer ranges are an opt-in click.
const DEFAULT_TEST_RANGE_HOURS: i64 = 1;

/// RAII guard that holds a per-user slot in the in-flight test tracker.
/// Releases on drop so panics, early returns, and cancelled requests all
/// clear the slot. Without this, a single failed test would block that
/// user's API key forever.
struct TestInFlightGuard {
    map: Arc<DashMap<Uuid, ()>>,
    user_id: Uuid,
}

impl Drop for TestInFlightGuard {
    fn drop(&mut self) {
        self.map.remove(&self.user_id);
    }
}

/// Try to claim the per-user test slot. Returns `None` if a test is already
/// in flight for this user — caller should respond 429.
fn try_claim_test_slot(
    map: &Arc<DashMap<Uuid, ()>>,
    user_id: Uuid,
) -> Option<TestInFlightGuard> {
    use dashmap::mapref::entry::Entry;
    match map.entry(user_id) {
        Entry::Occupied(_) => None,
        Entry::Vacant(v) => {
            v.insert(());
            Some(TestInFlightGuard {
                map: map.clone(),
                user_id,
            })
        }
    }
}

/// Resolve the test time window from the request. Falls back to the legacy
/// `days` field for back-compat with older clients, then to a 1-hour default.
fn resolve_test_range(request: &TestRuleRequest) -> TimeRangeInput {
    if let Some(tr) = &request.time_range {
        return TimeRangeInput::new(tr.start, tr.end);
    }
    let end = Utc::now();
    let start = if request.days > 0 {
        end - Duration::days(request.days)
    } else {
        end - Duration::hours(DEFAULT_TEST_RANGE_HOURS)
    };
    TimeRangeInput::new(start, end)
}

/// Test a detection rule against historical data using the same per-window
/// evaluation the production scheduler would perform (NAN-741).
///
/// For a rule with `schedule: */5 * * * *` and `lookback: 15m`, a 1-hour test
/// runs the query 12 times — once per cron tick within the user-selected
/// range, against `[tick - 15m, tick]` — and aggregates per-window match
/// counts. Hard-capped at 14 days. Per-user concurrency capped at one
/// in-flight test (returns 429 otherwise) so click-spam can't amplify the
/// fanout against ClickHouse.
#[utoipa::path(
    post,
    path = "/api/rules/{id}/test",
    tag = "detections",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    request_body = TestRuleRequest,
    responses(
        (status = 200, description = "Historical analysis results", body = HistoricalAnalysisResult),
        (status = 400, description = "Invalid request (e.g. range exceeds 14 days)", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 429, description = "Another rule test is already in flight for this user", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn test_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<TestRuleRequest>,
) -> Result<Json<HistoricalAnalysisResult>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let _guard = try_claim_test_slot(&state.rule_test_in_flight, auth.user_id())
        .ok_or_else(|| {
            ApiError::TooManyRequests(
                "A rule test is already running. Wait for it to finish before starting another."
                    .to_string(),
            )
        })?;

    let time_range = resolve_test_range(&request);
    let clean_query = strip_comments(&request.query);

    // Look up the saved rule so we can step at its actual schedule + lookback.
    let rule = state.detection_service.get_rule(*id).await?;

    let result = if clean_query.is_empty() {
        // Standard case: testing the saved rule as-is.
        state
            .detection_service
            .analyze_rule_stepped(&rule, time_range)
            .await?
    } else {
        // The drawer lets users edit the query before testing without saving.
        // Step at the saved rule's schedule + lookback against the new query.
        state
            .detection_service
            .analyze_query_stepped(
                &clean_query,
                time_range,
                rule.schedule_cron.as_deref(),
                rule.lookback_minutes.map(|m| m as i64),
                rule.dataset.clone(),
            )
            .await?
    };
    Ok(Json(result))
}

/// Test a query without creating a rule (NAN-741).
///
/// Uses the same stepped per-window evaluator as `test_detection`. The
/// caller can pass `schedule_cron` and `lookback_minutes` in the request to
/// match a specific rule shape; otherwise defaults to a 5-min schedule and
/// 15-min lookback so the histogram reflects something close to what a
/// typical scheduled rule would produce.
#[utoipa::path(
    post,
    path = "/api/rules/test",
    tag = "detections",
    request_body = TestRuleRequest,
    responses(
        (status = 200, description = "Historical analysis results", body = HistoricalAnalysisResult),
        (status = 400, description = "Invalid request (e.g. range exceeds 14 days)", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:create", body = ErrorResponse),
        (status = 429, description = "Another rule test is already in flight for this user", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn test_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<TestRuleRequest>,
) -> Result<Json<HistoricalAnalysisResult>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_CREATE)?;

    let _guard = try_claim_test_slot(&state.rule_test_in_flight, auth.user_id())
        .ok_or_else(|| {
            ApiError::TooManyRequests(
                "A rule test is already running. Wait for it to finish before starting another."
                    .to_string(),
            )
        })?;

    let time_range = resolve_test_range(&request);
    let clean_query = strip_comments(&request.query);

    // NAN-1561: validate the dataset selector up front. `Dataset::from_selector`
    // maps any unknown string to `Logs`, so a typo (`sapns`) would otherwise
    // silently preview the rule against logs and report wrong/zero matches —
    // diverging from rule create/update, which DO validate. Reject here so the
    // ad-hoc test and the saved rule agree.
    if let Some(ref ds) = request.dataset {
        if !nanosiem_core::models::detection_rule::VALID_DATASETS.contains(&ds.as_str()) {
            return Err(ApiError::ValidationError(format!(
                "invalid dataset '{ds}' (expected one of: logs, spans, metrics)"
            )));
        }
    }

    let result = state
        .detection_service
        .analyze_query_stepped(
            &clean_query,
            time_range,
            request.schedule_cron.as_deref(),
            request.lookback_minutes,
            request.dataset.clone(),
        )
        .await?;
    Ok(Json(result))
}

/// Format a query using the pretty printer
///
/// Takes a query string and returns it formatted with proper indentation
/// and newlines for piped commands.
#[utoipa::path(
    post,
    path = "/api/rules/format",
    tag = "detections",
    request_body = FormatQueryRequest,
    responses(
        (status = 200, description = "Formatted query", body = FormatQueryResponse),
        (status = 400, description = "Failed to parse query", body = ErrorResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn format_query(
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<FormatQueryRequest>,
) -> Result<Json<FormatQueryResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    use nanosiem_core::{parse_query, PrettyPrint};

    // Parse the query
    let parsed = parse_query(&request.query)
        .map_err(|e| ApiError::ValidationError(format!("Failed to parse query: {}", e)))?;

    // Format it using pretty_print
    let formatted = parsed.pretty_print();

    // Add newlines before pipes for better readability
    let formatted_with_newlines = formatted.split(" | ").collect::<Vec<_>>().join("\n  | ");

    Ok(Json(FormatQueryResponse {
        formatted_query: formatted_with_newlines,
    }))
}

/// Validate a detection rule configuration before creation
///
/// Returns information about:
/// - What detection mode will be used (and why)
/// - Whether a materialized view will be created
/// - Any query syntax errors
/// - Fields referenced in the query
///
/// POST /api/rules/validate
#[utoipa::path(
    post,
    path = "/api/rules/validate",
    tag = "detections",
    request_body = ValidateDetectionRequest,
    responses(
        (status = 200, description = "Validation results", body = ValidateDetectionResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn validate_detection(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ValidateDetectionRequest>,
) -> Result<Json<ValidateDetectionResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    use nanosiem_core::detection::materialized_view::{
        MaterializedViewError, MaterializedViewGenerator,
    };
    use nanosiem_core::parse_query;

    let mut errors = Vec::new();
    let mut warning = None;
    let mut referenced_fields = Vec::new();

    // Strip comments from the query before parsing
    let clean_query = strip_comments(&request.query);

    // Debug: log the query being parsed
    tracing::debug!("Validating query (raw): {:?}", request.query);
    tracing::debug!("Validating query (clean): {:?}", clean_query);

    // Parse the query to validate syntax
    let parse_result = parse_query(&clean_query);
    let valid = parse_result.is_ok();

    // Collect field names created by pipeline commands (stats aliases, eval assignments, etc.)
    // so we don't report false "Unknown field" errors for derived fields.
    let mut derived_fields = if let Ok(ref q) = parse_result {
        nanosiem_core::collect_derived_fields(q)
    } else {
        std::collections::HashSet::new()
    };

    // Regex fallback: extract eval-assigned and stats-aliased field names directly from the
    // raw text. This prevents false "Unknown field" errors when the parser fails on complex
    // expressions (e.g., multi-line case() with OR conditions inside eval).
    use std::sync::OnceLock;
    static EVAL_ASSIGN_RE: OnceLock<regex::Regex> = OnceLock::new();
    static AS_ALIAS_RE: OnceLock<regex::Regex> = OnceLock::new();
    let eval_assign_regex = EVAL_ASSIGN_RE
        .get_or_init(|| regex::Regex::new(r#"(?i)\beval\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*="#).unwrap());
    let as_alias_regex = AS_ALIAS_RE.get_or_init(|| {
        // Require ) or , before AS to match stats/aggregation aliases, not mid-string words
        regex::Regex::new(r#"(?i)[),]\s*as\s+([a-zA-Z_][a-zA-Z0-9_]*)"#).unwrap()
    });
    for cap in eval_assign_regex.captures_iter(&clean_query) {
        if let Some(field) = cap.get(1) {
            derived_fields.insert(field.as_str().to_lowercase());
        }
    }
    for cap in as_alias_regex.captures_iter(&clean_query) {
        if let Some(field) = cap.get(1) {
            derived_fields.insert(field.as_str().to_lowercase());
        }
    }

    if let Err(ref e) = parse_result {
        tracing::warn!("Query parse failed: {:?}", e);
        errors.push(format!("Query syntax error: {}", e));
    }

    // Extract field names from the query (basic extraction)
    // This is a simple approach - just look for field=value patterns
    let field_regex = regex::Regex::new(r#"([a-zA-Z_][a-zA-Z0-9_]*)\s*[=!<>]"#).unwrap();
    for cap in field_regex.captures_iter(&clean_query) {
        if let Some(field) = cap.get(1) {
            let field_name = field.as_str().to_string();
            if !referenced_fields.contains(&field_name) {
                referenced_fields.push(field_name);
            }
        }
    }

    // Validate field names against:
    // 1. Direct ClickHouse columns (fast, indexed queries)
    // 2. Valid UDM fields (can be accessed via ext.* JSON column)
    // 3. The active schema profile's field universe — so OCSF dotted fields
    //    (e.g. `src_endpoint.ip`, `actor.process.cmd_line`) are accepted when the
    //    deployment runs the OCSF profile (NAN-1241). Under UDM this is a superset
    //    of branches 1+2, so UDM validation stays byte-identical.
    use nanosiem_core::udm::UdmField;

    let profile = state.config.schema_profile();

    static CLICKHOUSE_COLUMNS: &[&str] = &[
        "_inserted_at",
        "answer",
        "auth_result",
        "auth_type",
        "authentication_method",
        "bytes_in",
        "bytes_out",
        "category",
        "change_type",
        "cloud_account_id",
        "cloud_account_name",
        "cloud_provider",
        "cloud_region",
        "cloud_service",
        "cve",
        "dest_host",
        "dest_ip",
        "dest_mac",
        "dest_port",
        "dest_user",
        "direction",
        "dns_answers",
        "duration",
        "dvc",
        "dvc_ip",
        "dvc_mac",
        "enrich_time",
        "event_type",
        "ext",
        "file_action",
        "file_hash",
        "file_name",
        "file_path",
        "file_size",
        "http_content_type",
        "http_method",
        "http_referrer",
        "http_user_agent",
        "id",
        "ingest_time",
        "message",
        "message_id",
        "metadata",
        "mfa_used",
        "mitre_technique_id",
        "namespace",
        "packets_in",
        "packets_out",
        "command_line",
        "parent_command_line",
        "parent_process_guid",
        "parent_process_id",
        "parent_process_path",
        "process_guid",
        "process_hash",
        "process_id",
        "process_name",
        "process_path",
        "protocol",
        "query",
        "query_type",
        "recipient",
        "recipient_domain",
        "record_type",
        "registry_key_name",
        "registry_path",
        "registry_value_data",
        "registry_value_name",
        "resource_id",
        "resource_name",
        "resource_type",
        "response_time",
        "result",
        "risk_entity",
        "risk_factors",
        "risk_level",
        "risk_score",
        "rule_id",
        "rule_name",
        "sender",
        "sender_domain",
        "session_id",
        "severity",
        "signature",
        "signature_id",
        "source",
        "source_type",
        "src_host",
        "src_ip",
        "src_mac",
        "src_port",
        "src_user",
        "status",
        "status_code",
        "subject",
        "timestamp",
        "uri_path",
        "url",
        "url_domain",
        "user",
        "user_agent",
        "user_domain",
        "user_id",
        "user_name",
        "user_type",
        "vendor_product",
        "vlan",
    ];
    let keywords = [
        "and",
        "or",
        "not",
        "in",
        "like",
        "contains",
        "startswith",
        "endswith",
        "matches",
        "true",
        "false",
    ];

    // Command parameters (not UDM fields)
    let command_params = [
        "enrich",
        "window",
        "current",
        "span",
        "limit",
        "as",
        "field",
        "mode",
        "score",
        "entity",
        "factor",
        "weight",
        "maxspan",
        "maxevents",
        "keeplast",
        "case_insensitive",
        "threshold",
        "method",
        "hop",
        "parent",
        "child",
        "label",
        "detail",
        "prevalence",
        "process",
        "web",
        "root",
        "max_age",
        "by",
        "value",
        "count",
        "output",
    ];

    for field_name in &referenced_fields {
        let lower = field_name.to_lowercase();
        // Skip keywords
        if keywords.contains(&lower.as_str()) {
            continue;
        }
        // Skip command parameters (score, entity, factor, etc.)
        if command_params.contains(&lower.as_str()) {
            continue;
        }
        // Skip fields created by pipeline commands (stats aliases, eval assignments, etc.)
        if derived_fields.contains(&lower) {
            continue;
        }
        // 1. Check if it's a direct ClickHouse column
        if CLICKHOUSE_COLUMNS.contains(&lower.as_str()) {
            continue;
        }
        // 2. Allow enriched_*, ioc_*, custom_* prefixes (dynamic enrichment columns)
        if lower.starts_with("enriched_")
            || lower.starts_with("ioc_")
            || lower.starts_with("custom_")
        {
            continue;
        }
        // 3. Allow prevalence-enriched fields (added by `prevalence enrich=true`)
        if lower.starts_with("prevalence_")
            || lower == "hash_prevalence"
            || lower == "domain_prevalence"
            || lower == "hash_first_seen"
            || lower == "domain_first_seen"
            || lower == "host_count"
            || lower == "is_rare"
            || lower == "total_occurrences"
            || lower == "first_seen"
            || lower == "last_seen"
        {
            continue;
        }
        // 4. Check if it's a valid UDM field (accessible via ext.*)
        if field_name.parse::<UdmField>().is_ok() {
            continue;
        }
        // 5. Check if it's a known field in the active schema profile. For OCSF
        //    this accepts the promoted dotted columns; for UDM it's a superset of
        //    the checks above (no UDM field that passed before can fail here).
        if profile.is_known_field(field_name) || profile.is_known_field(&lower) {
            continue;
        }
        // Not valid - suggest common fields
        errors.push(format!(
            "Unknown field '{}'. Did you mean 'src_ip', 'dest_ip', 'user', 'src_host'?",
            field_name
        ));
    }

    // Determine detection mode
    let requested_mode = request
        .detection_mode
        .as_ref()
        .map(|m| m.to_lowercase())
        .unwrap_or_else(|| "scheduled".to_string());

    // NAN-1688: query-shape real-time (materialized-view) eligibility, evaluated
    // once from the parsed query and reused for BOTH the requested-mode routing
    // below and the scheduled-rule nudge in the response. This is the single
    // source of truth — the same `check_query_realtime_eligible` gate the MV
    // path applies at DDL-generation time — so validation can never promise an
    // MV (or nudge toward one) that DDL generation would then reject (e.g. a
    // real-time request carrying `ioc`/`IN [...]`, previously reported as
    // creating an MV before failing downstream).
    //
    // `Ok(())` = eligible; `Err(reason)` carries a clean, user-facing reason.
    // Dataset (logs-only) and risk-entity gating is applied by the UI, which
    // knows the rule's dataset.
    let realtime_shape: Result<(), String> = match parse_result.as_ref() {
        Ok(parsed) => MaterializedViewGenerator::check_query_realtime_eligible(parsed).map_err(
            |e| match e {
                // `check_query_realtime_eligible` only ever returns `InvalidRule`,
                // whose inner string is already user-facing.
                MaterializedViewError::InvalidRule(msg) => msg,
                other => other.to_string(),
            },
        ),
        Err(_) => Err("query has parse errors".to_string()),
    };

    let (realtime_eligible, realtime_eligible_reason) = match &realtime_shape {
        Ok(()) => (
            true,
            Some(
                "Simple filter query — can stream via a materialized view (10–30s latency) \
                 instead of running on a cron schedule"
                    .to_string(),
            ),
        ),
        Err(reason) => (false, Some(reason.clone())),
    };

    // Determine effective mode and whether an MV will be created.
    let (effective_mode, creates_mv, mode_reason) = if requested_mode == "real-time"
        || requested_mode == "realtime"
    {
        match &realtime_shape {
            Ok(()) => (
                "real-time".to_string(),
                true,
                "Real-time mode: simple filter query will create a ClickHouse materialized view"
                    .to_string(),
            ),
            // Requested real-time but the query didn't parse — surface the errors
            // rather than an auto-conversion warning.
            Err(_) if parse_result.is_err() => (
                "real-time".to_string(),
                false, // Won't create MV if query is invalid
                "Real-time mode requested but query has errors".to_string(),
            ),
            // Parsed, but the shape isn't MV-eligible (piped commands, keyword
            // search, subsearch, or the `ioc` term). Auto-convert to scheduled,
            // mirroring the create/update path in `crud.rs`.
            Err(reason) => {
                warning = Some(format!(
                    "{reason}. The rule will be automatically converted to scheduled mode \
                     with a 30-second interval."
                ));
                (
                    "scheduled".to_string(),
                    false,
                    format!("Auto-converted to scheduled: {reason}"),
                )
            }
        }
    } else {
        (
            "scheduled".to_string(),
            false,
            "Scheduled mode: will run on a cron schedule".to_string(),
        )
    };

    // valid is false if parsing failed OR if we found invalid fields
    let valid = valid && errors.is_empty();

    Ok(Json(ValidateDetectionResponse {
        valid,
        effective_mode,
        creates_materialized_view: creates_mv && valid,
        mode_reason,
        realtime_eligible: realtime_eligible && valid,
        realtime_eligible_reason: if realtime_eligible && valid {
            realtime_eligible_reason
        } else {
            None
        },
        warning,
        errors,
        referenced_fields,
    }))
}
