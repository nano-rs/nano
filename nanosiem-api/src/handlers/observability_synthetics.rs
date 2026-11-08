// SPDX-License-Identifier: AGPL-3.0-or-later

//! Synthetic-check CRUD for the Observability console (NAN-1538).
//!
//! Synthetic-check *definitions* are PostgreSQL-backed
//! (`observability_synthetic_checks`, migration 210). Their probe *results*
//! live in ClickHouse (`nanosiem.synthetic_check_results`, migration 142),
//! written by the nanosiem-jobs synthetics runner. The live summary
//! (`uptime_pct`, `p50_latency_ms`) and the last-N `history` are NOT stored on
//! the definition — they are computed on read from ClickHouse via the search
//! service's `observability_synthetics_summary` / `observability_synthetic_history`
//! glue and merged onto each definition here. This mirrors the SLO subsystem
//! (`observability_slos.rs`): keeping only the definition persisted means the
//! numbers are always consistent with the recorded probe results.
//!
//! The list endpoint computes the live summary + history from ClickHouse, so it
//! requires `search:view` AND `search:execute` (NAN-2084): a view-only principal
//! that is denied canonical search must not be able to run these
//! summary/history reads through the wrapper. Mutations require
//! `settings:system` (checks are configuration) and return only the persisted
//! definition, so they never execute ClickHouse reads as a side effect
//! (NAN-2139).

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ErrorResponse};
use crate::middleware::{AuthContext, ensure_permission};
use crate::state::AppState;
use nanosiem_core::auth::permissions;
use nanosiem_core::observability::{
    SYNTHETIC_CHECK_TYPES, SYNTHETIC_MAX_INTERVAL_SECS, SYNTHETIC_MIN_INTERVAL_SECS, SyntheticCheck,
    SyntheticCheckRepository, SyntheticCheckRepositoryError,
};
use nanosiem_core::query::TimeRange;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::webhooks::WebhookService;

const NAME_MAX_LEN: usize = 200;
const TARGET_URL_MAX_LEN: usize = 2048;
const DEFAULT_EXPECTED_STATUS: i32 = 200;
const DEFAULT_TIMEOUT_SECS: i32 = 10;
/// Per-check history window surfaced to the console (last 90 runs).
const HISTORY_LIMIT: u32 = 90;
/// How far back to look for results when computing the summary / history. The
/// runner writes a row every `interval_secs` (≤ 3600s), so a 7-day window
/// always covers the last 90 runs and keeps the ClickHouse scan bounded.
const SUMMARY_WINDOW_DAYS: i64 = 7;

/// A synthetic check with its live summary merged in. Flattens the stored
/// [`SyntheticCheck`] definition and adds the computed fields.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Check {
    #[serde(flatten)]
    #[schema(value_type = SyntheticCheck)]
    pub definition: SyntheticCheck,
    /// Whether the check has any recorded runs in the summary window (O33).
    /// `false` for a just-created check with no probe results yet — the console
    /// renders a neutral "no data" state for these and excludes them from the
    /// up/down status counts and the overall-uptime average, so a fresh check no
    /// longer reads as a phantom outage.
    pub has_runs: bool,
    /// Uptime over the summary window as a percentage (`0..100`). `null` when the
    /// check has no recorded runs yet (`has_runs == false`) — a no-data state,
    /// deliberately NOT `0`, which would render as a red "Down".
    pub uptime_pct: Option<f64>,
    /// Median (p50) latency in ms over the window. `null` when there are no
    /// recorded runs.
    pub p50_latency_ms: Option<f64>,
    /// The last ≤90 runs, chronological (oldest-first), for the uptime bar.
    #[schema(value_type = Vec<serde_json::Value>)]
    pub history: Vec<serde_json::Value>,
}

/// Response for the synthetic-check list.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListChecksResponse {
    pub checks: Vec<Check>,
}

/// Request body for creating / updating a synthetic check.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CheckRequest {
    pub name: String,
    /// The URL to probe.
    pub target_url: String,
    /// How often to run the check, in seconds (30..=3600).
    pub interval_secs: i32,
    /// HTTP status that counts as a success. Defaults to 200.
    #[serde(default)]
    pub expected_status: Option<i32>,
    /// Per-run request timeout in seconds. Defaults to 10.
    #[serde(default)]
    pub timeout_secs: Option<i32>,
    /// Whether the check is active. Defaults to `true`.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Request body for *partially* updating a synthetic check (PATCH-style PUT).
///
/// Every field is optional: the console fires a body of only `{ "enabled": … }`
/// for the pause/resume toggle, while the editor sends the full set. Omitted
/// fields are merged from the persisted definition before validation, so a
/// partial body never blanks the other columns. (NAN-1537 contract fix — the
/// create-shaped `CheckRequest` rejected the toggle's partial body with a 422.)
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateCheckRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub interval_secs: Option<i32>,
    #[serde(default)]
    pub expected_status: Option<i32>,
    #[serde(default)]
    pub timeout_secs: Option<i32>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl UpdateCheckRequest {
    /// Merge this partial body onto the persisted definition, producing a full
    /// `CheckRequest` that then runs through the shared `validate()`.
    fn merge_onto(self, existing: &SyntheticCheck) -> CheckRequest {
        CheckRequest {
            name: self.name.unwrap_or_else(|| existing.name.clone()),
            target_url: self
                .target_url
                .unwrap_or_else(|| existing.target_url.clone()),
            interval_secs: self.interval_secs.unwrap_or(existing.interval_secs),
            expected_status: Some(self.expected_status.unwrap_or(existing.expected_status)),
            timeout_secs: Some(self.timeout_secs.unwrap_or(existing.timeout_secs)),
            enabled: Some(self.enabled.unwrap_or(existing.enabled)),
        }
    }
}

/// Validated + normalized request fields.
struct ValidatedCheck {
    name: String,
    target_url: String,
    interval_secs: i32,
    expected_status: i32,
    timeout_secs: i32,
    enabled: bool,
}

impl CheckRequest {
    /// Validate + normalize. Interval/check-type bounds are also enforced by
    /// the repository (and the PG CHECK is the backstop); the field-level
    /// checks here produce clean 400s before the DB round-trip.
    fn validate(&self) -> Result<ValidatedCheck, ApiError> {
        let name = self.name.trim().to_string();
        let target_url = self.target_url.trim().to_string();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name must not be empty".to_string()));
        }
        if name.len() > NAME_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "name exceeds {NAME_MAX_LEN} chars"
            )));
        }
        if target_url.is_empty() {
            return Err(ApiError::BadRequest(
                "target_url must not be empty".to_string(),
            ));
        }
        if target_url.len() > TARGET_URL_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "target_url exceeds {TARGET_URL_MAX_LEN} chars"
            )));
        }
        if !(target_url.starts_with("http://") || target_url.starts_with("https://")) {
            return Err(ApiError::BadRequest(
                "target_url must be an http(s) URL".to_string(),
            ));
        }
        if !(SYNTHETIC_MIN_INTERVAL_SECS..=SYNTHETIC_MAX_INTERVAL_SECS).contains(&self.interval_secs)
        {
            return Err(ApiError::BadRequest(format!(
                "interval_secs must be in {SYNTHETIC_MIN_INTERVAL_SECS}..={SYNTHETIC_MAX_INTERVAL_SECS}"
            )));
        }
        let expected_status = self.expected_status.unwrap_or(DEFAULT_EXPECTED_STATUS);
        if !(100..=599).contains(&expected_status) {
            return Err(ApiError::BadRequest(
                "expected_status must be a valid HTTP status (100..=599)".to_string(),
            ));
        }
        let timeout_secs = self.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if !(1..=120).contains(&timeout_secs) {
            return Err(ApiError::BadRequest(
                "timeout_secs must be in 1..=120".to_string(),
            ));
        }
        Ok(ValidatedCheck {
            name,
            target_url,
            interval_secs: self.interval_secs,
            expected_status,
            timeout_secs,
            enabled: self.enabled.unwrap_or(true),
        })
    }
}

fn map_repo_err(e: SyntheticCheckRepositoryError) -> ApiError {
    match e {
        SyntheticCheckRepositoryError::NotFound(_) => {
            ApiError::NotFound("Synthetic check not found".to_string())
        }
        SyntheticCheckRepositoryError::Invalid(msg) => ApiError::BadRequest(msg),
        SyntheticCheckRepositoryError::DatabaseError(db) => ApiError::DatabaseError(db.to_string()),
    }
}

/// Merge the live summary + history (from ClickHouse) onto one definition.
/// `summaries` is keyed by the check's UUID-string (the search-layer key). The
/// summary only carries an entry for a check that has ≥1 run in the window
/// (`observability_synthetics_summary` GROUP BYs check_id), so a missing entry
/// means "no recorded runs yet" → `has_runs = false`, `uptime_pct = null`
/// (a neutral no-data state, NOT `0%`, which would render as "Down" — O33).
async fn enrich(
    state: &AppState,
    def: SyntheticCheck,
    summaries: &std::collections::HashMap<String, serde_json::Value>,
    time_range: &TimeRange,
) -> Result<Check, ApiError> {
    let key = def.id.to_string();

    let (has_runs, uptime_pct, p50_latency_ms) = match summaries.get(&key) {
        Some(s) => (
            true,
            s.get("uptime_pct").and_then(|v| v.as_f64()),
            s.get("p50_latency_ms").and_then(|v| v.as_f64()),
        ),
        None => (false, None, None),
    };

    let history = state
        .search_service
        .observability_synthetic_history(&key, time_range, Some(HISTORY_LIMIT))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, check_id = %key, "synthetic history fetch failed");
            ApiError::InternalError("Failed to fetch synthetic-check history".to_string())
        })?;

    Ok(Check {
        definition: def,
        has_runs,
        uptime_pct,
        p50_latency_ms,
        history,
    })
}

/// The summary time window: `now - SUMMARY_WINDOW_DAYS .. now`.
fn summary_time_range() -> TimeRange {
    let now = chrono::Utc::now();
    let begin = now - chrono::Duration::days(SUMMARY_WINDOW_DAYS);
    TimeRange::new(begin, now)
}

/// List all synthetic checks with their live summary + recent history.
#[utoipa::path(
    get,
    path = "/api/observability/synthetics",
    tag = "observability",
    responses(
        (status = 200, description = "Synthetic checks with live summary", body = ListChecksResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_synthetics(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListChecksResponse>, ApiError> {
    // NAN-2084: this endpoint runs a fleet-wide `synthetic_check_results` summary
    // plus a per-check history read. Gate on `search:execute` (not just the view
    // capability) before any query, so a view-only principal cannot reach probe
    // results through this wrapper. The summary query must not run on a denied
    // request, so the check precedes it (and the empty-list fanout).
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;

    let repo = SyntheticCheckRepository::new(state.pool.clone());
    let defs = repo.list().await.map_err(map_repo_err)?;

    let time_range = summary_time_range();
    let summaries = state
        .search_service
        .observability_synthetics_summary(&time_range)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "synthetics summary fetch failed");
            ApiError::InternalError("Failed to compute synthetic-check summary".to_string())
        })?;

    let mut checks = Vec::with_capacity(defs.len());
    for def in defs {
        checks.push(enrich(&state, def, &summaries, &time_range).await?);
    }

    Ok(Json(ListChecksResponse { checks }))
}

/// Create a new synthetic check.
#[utoipa::path(
    post,
    path = "/api/observability/synthetics",
    tag = "observability",
    request_body = CheckRequest,
    responses(
        (status = 201, description = "Synthetic check definition created", body = SyntheticCheck),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_synthetic(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CheckRequest>,
) -> Result<(StatusCode, Json<SyntheticCheck>), ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let v = req.validate()?;
    // NAN-1759: reject SSRF targets (loopback, link-local, cloud-metadata, and
    // alternate IP encodings) before persistence, matching the webhook surface's
    // shared validator. The synthetics runner also validates at fire time (defense
    // in depth), but a persisted internal URL is itself a leak — it is readable by
    // any `search:view` principal via the list/get endpoints.
    WebhookService::validate_url(&v.target_url)
        .await
        .map_err(ApiError::BadRequest)?;

    let repo = SyntheticCheckRepository::new(state.pool.clone());

    // NAN-1544: tier-cap the number of synthetic checks before insert.
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await?;
    if tier_limits.is_enforced() {
        let current = repo.list().await.map_err(map_repo_err)?.len() as u32;
        nanosiem_core::check_limit(
            "synthetic checks",
            current,
            tier_limits.max_synthetic_checks,
            tier_limits.tier,
            "Upgrade your plan for more synthetic checks.",
        )?;
    }

    let def = repo
        .create(
            &v.name,
            // Only 'http' ships today; pinned here until the type is requestable.
            SYNTHETIC_CHECK_TYPES[0],
            &v.target_url,
            v.interval_secs,
            v.expected_status,
            v.timeout_secs,
            v.enabled,
            Some(auth.user_id()),
        )
        .await
        .map_err(map_repo_err)?;

    Ok((StatusCode::CREATED, Json(def)))
}

/// Update an existing synthetic check.
#[utoipa::path(
    put,
    path = "/api/observability/synthetics/{id}",
    tag = "observability",
    params(("id" = String, Path, description = "Check typeid (synth_<base32>) or bare UUID")),
    request_body = UpdateCheckRequest,
    responses(
        (status = 200, description = "Synthetic check definition updated", body = SyntheticCheck),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Synthetic check not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_synthetic(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<UpdateCheckRequest>,
) -> Result<Json<SyntheticCheck>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let repo = SyntheticCheckRepository::new(state.pool.clone());
    // PATCH-style: merge the partial body onto the persisted definition so a
    // body of only `{ "enabled": … }` (the console toggle) doesn't blank the
    // other columns or fail validation. (NAN-1537 contract fix.)
    let existing = repo.get(*id).await.map_err(map_repo_err)?;
    // Only re-run the SSRF check when the URL is actually being changed, so a
    // pause/resume toggle (a body of just `{ "enabled": … }`) on an existing
    // check isn't blocked by it (NAN-1759). A newly-supplied URL is validated.
    let url_changed = req.target_url.is_some();
    let v = req.merge_onto(&existing).validate()?;
    if url_changed {
        WebhookService::validate_url(&v.target_url)
            .await
            .map_err(ApiError::BadRequest)?;
    }

    let def = repo
        .update(
            *id,
            &v.name,
            SYNTHETIC_CHECK_TYPES[0],
            &v.target_url,
            v.interval_secs,
            v.expected_status,
            v.timeout_secs,
            v.enabled,
        )
        .await
        .map_err(map_repo_err)?;

    Ok(Json(def))
}

/// Delete a synthetic check.
#[utoipa::path(
    delete,
    path = "/api/observability/synthetics/{id}",
    tag = "observability",
    params(("id" = String, Path, description = "Check typeid (synth_<base32>) or bare UUID")),
    responses(
        (status = 204, description = "Synthetic check deleted"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Synthetic check not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_synthetic(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let repo = SyntheticCheckRepository::new(state.pool.clone());
    let deleted = repo.delete(*id).await.map_err(map_repo_err)?;
    if !deleted {
        return Err(ApiError::NotFound("Synthetic check not found".to_string()));
    }
    // O49: the delete removes only the PG *definition*. Any probe already in
    // flight for this check re-checks existence before it writes its result or
    // raises an alert (see `SyntheticRunner::probe_and_record`), so a mid-tick
    // delete can't emit a late result/alert. The check's ClickHouse result rows
    // are left to age out under the table's 30d TTL (migration 142) rather than
    // deleted synchronously here — an explicit CH `ALTER … DELETE` on delete is a
    // possible follow-up but not needed for correctness.
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_synthetics, create_synthetic, update_synthetic, delete_synthetic),
    components(schemas(Check, ListChecksResponse, CheckRequest, UpdateCheckRequest, SyntheticCheck))
)]
pub struct ObservabilitySyntheticsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    #[test]
    fn mutation_responses_are_definition_only() {
        let spec = serde_json::to_value(ObservabilitySyntheticsApiDoc::openapi())
            .expect("OpenAPI document serializes");

        for (path, method, status) in [
            ("/api/observability/synthetics", "post", "201"),
            ("/api/observability/synthetics/{id}", "put", "200"),
        ] {
            assert_eq!(
                spec["paths"][path][method]["responses"][status]["content"]["application/json"]["schema"]
                    ["$ref"],
                "#/components/schemas/SyntheticCheck",
                "{method} {path} must not promise live search-derived fields"
            );
        }

        assert_eq!(
            spec["paths"]["/api/observability/synthetics"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/ListChecksResponse",
            "the read endpoint remains the explicitly enriched surface"
        );
    }
}
