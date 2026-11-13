// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule testing, formatting, and validation

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{Duration, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::search::TimeRangeInput;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::HistoricalAnalysisResult;

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

/// NAN-2047: compose the caller's EFFECTIVE per-source deny scope for the rule
/// tester — the per-source RBAC deny set (NAN-1799) unioned with the `audit`
/// source unless the caller holds `audit:view`. Identical composition to the
/// canonical search / alert / dashboard surfaces (`effective_viewer_scope` in
/// handlers/alerts.rs), so the tester cannot become an unrestricted alternate
/// search surface. An unrestricted caller with `audit:view` yields an empty
/// deny set → byte-identical SQL to before.
///
/// NAN-2055: the composition now lives on `AuthContext`; this stays as a local
/// alias for the call sites below.
fn effective_viewer_scope(auth: &AuthContext) -> nanosiem_core::auth::ScopeSet {
    auth.effective_viewer_scope()
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
        (status = 403, description = "Missing permission: detections:view + search:execute", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
        (status = 429, description = "Another rule test is already in flight for this user", body = ErrorResponse),
        (status = 503, description = "Distributed rule-test admission is unavailable", body = ErrorResponse),
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
    // NAN-2047: this executes stepped ClickHouse searches over logs and returns
    // raw `sample_events` — the same data surface as POST /api/search, which
    // requires search:execute (NAN-2028). Require it here too; detections:view
    // alone let a principal denied canonical search read sampled log rows. (When
    // the drawer supplies a query override below, that's an even stronger reason.)
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

    let _guard = state
        .rule_test_admission
        .acquire(auth.user_id())
        .await
        .map_err(|error| ApiError::ServiceUnavailable(error.to_string()))?
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

    // NAN-2047: run the tester's searches under the caller's effective scope so
    // a source-restricted principal can't read denied sources through it.
    let scope = effective_viewer_scope(&auth);
    let result = if clean_query.is_empty() {
        // Standard case: testing the saved rule as-is.
        state
            .detection_service
            .analyze_rule_stepped(&rule, time_range, &scope)
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
                &scope,
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
        (status = 403, description = "Missing permission: detections:create + search:execute", body = ErrorResponse),
        (status = 429, description = "Another rule test is already in flight for this user", body = ErrorResponse),
        (status = 503, description = "Distributed rule-test admission is unavailable", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn test_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<TestRuleRequest>,
) -> Result<Json<HistoricalAnalysisResult>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_CREATE)?;
    // NAN-2047: executes an arbitrary caller-supplied query as stepped ClickHouse
    // searches and returns raw `sample_events` — require search:execute, matching
    // POST /api/search. detections:create alone was an alternate raw-log surface.
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

    let _guard = state
        .rule_test_admission
        .acquire(auth.user_id())
        .await
        .map_err(|error| ApiError::ServiceUnavailable(error.to_string()))?
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

    // NAN-2047: run under the caller's effective scope (see effective_viewer_scope).
    let scope = effective_viewer_scope(&auth);
    let result = state
        .detection_service
        .analyze_query_stepped(
            &clean_query,
            time_range,
            request.schedule_cron.as_deref(),
            request.lookback_minutes,
            request.dataset.clone(),
            &scope,
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

/// NAN-4372: the MITRE verdict a rule write would return, or `None` when the
/// request carries no mapping (validate stays database-free for the common
/// query-only call) or leaves the edited rule's stored mapping unchanged (the
/// write trigger skips that UPDATE too).
async fn mitre_mapping_error(
    pool: &sqlx::PgPool,
    rule_id: Option<uuid::Uuid>,
    tactics: Option<&[String]>,
    techniques: Option<&[String]>,
) -> Result<Option<String>, ApiError> {
    if tactics.is_none() && techniques.is_none() {
        return Ok(None);
    }
    let mut stored: Option<(Option<Vec<String>>, Option<Vec<String>>)> = None;
    if let Some(rule_id) = rule_id {
        stored = sqlx::query_as(
            "SELECT mitre_tactics, mitre_techniques FROM detection_rules WHERE id = $1",
        )
        .bind(rule_id)
        .fetch_optional(pool)
        .await
        .map_err(ApiError::from)?;
        if nanosiem_core::mitre::mitre_mapping_unchanged(stored.as_ref(), tactics, techniques) {
            return Ok(None);
        }
    }
    // A list the request omits keeps the stored value on UPDATE, so validate
    // the merged mapping, not `[]` for the omitted half (NAN-4902 review).
    let (tactics, techniques) =
        nanosiem_core::mitre::effective_mitre_mapping(stored.as_ref(), tactics, techniques);
    nanosiem_core::mitre::validate_mitre_mapping_for_write(pool, tactics, techniques)
        .await
        .map_err(ApiError::from)
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
    let referenced_fields: Vec<String>;

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

    // Field-name check (NAN-5275): schema- and dataset-aware. A rule on
    // `dataset=risk` validates against the risk grain's columns (`score_24h`,
    // `entity`, …); a logs rule on an OCSF tenant validates against the OCSF
    // columns plus the alias layer, and suggestions come from the same set.
    referenced_fields = super::field_check::referenced_fields(&clean_query);
    let profile = state.config.schema_profile();
    // Unmapped UDM names on OCSF come back as warnings, not errors, so an
    // existing rule that uses one is never blocked from being saved.
    let mut field_warnings: Vec<String> = Vec::new();
    match super::field_check::parse_dataset(request.dataset.as_deref()) {
        Ok(dataset) => {
            let check = super::field_check::check_fields(
                &referenced_fields,
                &derived_fields,
                dataset,
                &profile,
            );
            errors.extend(check.errors);
            field_warnings = check.warnings;
        }
        Err(e) => errors.push(e),
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

    // NAN-1691 (P1-C): prevalence-pushdown safety — the same single-source gate
    // the search router applies, so validation can't green-light a `| prevalence`
    // FILTER shape the router then sends down the in-memory fallback path.
    let prevalence_shape: Result<(), String> = match parse_result.as_ref() {
        Ok(parsed) => {
            nanosiem_core::search::query_processing::check_prevalence_pushdown_eligible(parsed)
        }
        Err(_) => Ok(()), // parse errors already surfaced via `valid`
    };
    let (prevalence_pushdown_safe, prevalence_pushdown_reason) = match &prevalence_shape {
        Ok(()) => (true, None),
        Err(reason) => {
            // Fold into the existing `warning` so current UIs that only read
            // `warning` still surface the eligibility feedback.
            if warning.is_none() {
                warning = Some(reason.clone());
            }
            (false, Some(reason.clone()))
        }
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

    // NAN-4372: the MITRE mapping a create/update would reject (shape,
    // catalog, tactic/technique pairing) is reported here instead of first
    // surfacing at create.
    if let Some(error) = mitre_mapping_error(
        &state.pool,
        request.rule_id,
        request.mitre_tactics.as_deref(),
        request.mitre_techniques.as_deref(),
    )
    .await?
    {
        errors.push(error);
    }

    // valid is false if parsing failed OR if we found invalid fields
    let valid = valid && errors.is_empty();

    // Field warnings go after the mode / prevalence notes, which set `warning`
    // above (`warning` is a single string on the wire).
    if !field_warnings.is_empty() {
        let fields = field_warnings.join(" ");
        warning = Some(match warning {
            Some(existing) => format!("{existing} {fields}"),
            None => fields,
        });
    }

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
        prevalence_pushdown_safe,
        prevalence_pushdown_reason,
        warning,
        errors,
        // NAN-5326: the returned list drops command params (`| risk score=…`)
        // and adds group-by fields; the check above used the raw list.
        referenced_fields: super::field_check::display_referenced_fields(
            &clean_query,
            &derived_fields,
        ),
    }))
}
