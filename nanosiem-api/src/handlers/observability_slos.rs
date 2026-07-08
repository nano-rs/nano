// SPDX-License-Identifier: AGPL-3.0-or-later

//! SLO (service-level objective) CRUD for the Observability console (NAN-1536).
//!
//! SLO *definitions* are PostgreSQL-backed (`observability_slos`, migration
//! 209). Their live *attainment* — `current` SLI, `budget_remaining_pct`,
//! `burn_rate`, `status` — is NOT stored; it is computed on read from
//! `otel_spans` over the SLO's rolling `window_days` window via the search
//! service's `observability_slo_compute` glue and merged onto the definition
//! here. Keeping only the definition persisted means the number is always
//! consistent with the spans and there is no recompute job.
//!
//! Read endpoints require `search:view` (the console is a search-adjacent
//! surface); mutations require `settings:system` (SLOs are configuration).

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
use nanosiem_core::observability::{SloDefinition, SloRepository, SloRepositoryError, SloSliKind};
use nanosiem_core::query::TimeRange;
use nanosiem_core::typeid::TypeIdParam;

const NAME_MAX_LEN: usize = 200;
const SERVICE_MAX_LEN: usize = 200;
// O5 (NAN-1721): the window cap ties `window_days` to the 30-day TTL on
// `otel_spans` (clickhouse/138) and the RED rollups (clickhouse/143). A window
// longer than retention would compute attainment over TTL-dropped spans and
// silently overstate it — old breaches age out and the budget resets toward
// ~100% while the window still claims to cover them. We enforce ≤ 30 here in the
// handler rather than in the shipped PG migration 209 CHECK (which still permits
// ≤ 90 and must not be modified).
const WINDOW_DAYS_MAX: i32 = 30;

/// An SLO with its live attainment merged in. Flattens the stored
/// [`SloDefinition`] and adds the computed fields.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Slo {
    #[serde(flatten)]
    #[schema(value_type = SloDefinition)]
    pub definition: SloDefinition,
    /// Current SLI attainment in `0..1` over the window.
    pub current: f64,
    /// Error budget remaining as a percentage of the allowed budget
    /// (`100` = full budget; `0` = budget exhausted; can go negative when
    /// breaching). `100` when the SLO is perfectly met.
    pub budget_remaining_pct: f64,
    /// Burn rate: how fast the budget is being consumed relative to the
    /// window. `1.0` = on track to exactly exhaust the budget at window end;
    /// `>1` = burning too fast. `0` when there is budget to spare / no errors.
    pub burn_rate: f64,
    /// Rollup status: `ok` | `at_risk` | `breaching` | `no_data`.
    pub status: &'static str,
}

/// Response for the SLO list.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListSlosResponse {
    pub slos: Vec<Slo>,
}

/// Request body for creating / updating an SLO.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SloRequest {
    pub name: String,
    pub service: String,
    /// `availability` | `latency`.
    pub sli_kind: SloSliKind,
    /// Objective as a fraction in (0,1], e.g. 0.995.
    pub target: f64,
    /// Rolling evaluation window in days (1..=30, capped at span retention).
    pub window_days: i32,
    /// Required when `sli_kind = latency`: per-span duration threshold (ms).
    #[serde(default)]
    pub latency_threshold_ms: Option<f64>,
}

impl SloRequest {
    /// Validate + normalize the request. Returns the trimmed (name, service)
    /// and the threshold appropriate to the kind.
    fn validate(&self) -> Result<(String, String, Option<f64>), ApiError> {
        let name = self.name.trim().to_string();
        let service = self.service.trim().to_string();
        if name.is_empty() {
            return Err(ApiError::BadRequest("name must not be empty".to_string()));
        }
        if service.is_empty() {
            return Err(ApiError::BadRequest(
                "service must not be empty".to_string(),
            ));
        }
        if name.len() > NAME_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "name exceeds {NAME_MAX_LEN} chars"
            )));
        }
        if service.len() > SERVICE_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "service exceeds {SERVICE_MAX_LEN} chars"
            )));
        }
        if !(self.target > 0.0 && self.target <= 1.0) {
            return Err(ApiError::BadRequest(
                "target must be a fraction in (0, 1]".to_string(),
            ));
        }
        if !(1..=WINDOW_DAYS_MAX).contains(&self.window_days) {
            return Err(ApiError::BadRequest(format!(
                "window_days must be in 1..={WINDOW_DAYS_MAX} (capped at the {WINDOW_DAYS_MAX}-day span retention)"
            )));
        }
        let threshold = match self.sli_kind {
            SloSliKind::Latency => {
                let t = self.latency_threshold_ms.filter(|v| v.is_finite() && *v > 0.0);
                if t.is_none() {
                    return Err(ApiError::BadRequest(
                        "latency_threshold_ms (positive) is required for sli_kind=latency"
                            .to_string(),
                    ));
                }
                t
            }
            // Availability ignores any supplied threshold (DB CHECK requires NULL).
            SloSliKind::Availability => None,
        };
        Ok((name, service, threshold))
    }
}

fn map_repo_err(e: SloRepositoryError) -> ApiError {
    match e {
        SloRepositoryError::NotFound(_) => ApiError::NotFound("SLO not found".to_string()),
        SloRepositoryError::Invalid(msg) => ApiError::BadRequest(msg),
        SloRepositoryError::DatabaseError(db) => ApiError::DatabaseError(db.to_string()),
    }
}

/// Compute the live attainment for one SLO definition from `otel_spans` and
/// merge it into a [`Slo`]. `current` is the SLI fraction over the window; the
/// budget / burn / status math is layered on here.
async fn enrich(state: &AppState, def: SloDefinition) -> Result<Slo, ApiError> {
    let now = chrono::Utc::now();
    let begin = now - chrono::Duration::days(def.window_days as i64);
    let time_range = TimeRange::new(begin, now);

    let (current, _total, no_data) = state
        .search_service
        .observability_slo_compute(
            &def.service,
            def.sli_kind.to_query_kind(),
            def.latency_threshold_ms,
            &time_range,
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, slo_service = %def.service, "SLO compute failed");
            ApiError::InternalError("Failed to compute SLO attainment".to_string())
        })?;

    // Error budget: allowed failure fraction is (1 - target). Consumed is
    // (1 - current). Remaining as a percentage of the allowed budget.
    let allowed = (1.0 - def.target).max(f64::EPSILON);
    let consumed = (1.0 - current).max(0.0);
    let budget_remaining_pct = ((allowed - consumed) / allowed) * 100.0;
    // Burn rate: consumed budget relative to the allowance (1.0 = exactly on
    // track to exhaust by window end).
    let burn_rate = consumed / allowed;

    // O17 (NAN-1721): a zero-traffic window computes `current = 1.0` (no spans →
    // nothing failed), which would otherwise read as a perfectly-met SLO. A
    // hard-down service or a stopped collector produces exactly this, and the
    // rolling window sliding past old errors makes the SLO *improve* while the
    // service is dead. Surface `no_data` so the API does not report ok/attained;
    // the FE renders it neutrally and the scheduler does not alert on it.
    let status = if no_data {
        "no_data"
    } else if current < def.target {
        "breaching"
    } else if budget_remaining_pct < 25.0 {
        "at_risk"
    } else {
        "ok"
    };

    Ok(Slo {
        definition: def,
        current,
        budget_remaining_pct,
        burn_rate,
        status,
    })
}

/// List all SLOs with live attainment.
#[utoipa::path(
    get,
    path = "/api/observability/slos",
    tag = "observability",
    responses(
        (status = 200, description = "SLOs with live attainment", body = ListSlosResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_slos(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListSlosResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;

    let repo = SloRepository::new(state.pool.clone());
    let defs = repo.list().await.map_err(map_repo_err)?;

    let mut slos = Vec::with_capacity(defs.len());
    for def in defs {
        slos.push(enrich(&state, def).await?);
    }

    Ok(Json(ListSlosResponse { slos }))
}

/// Create a new SLO.
#[utoipa::path(
    post,
    path = "/api/observability/slos",
    tag = "observability",
    request_body = SloRequest,
    responses(
        (status = 201, description = "SLO created (with live attainment)", body = Slo),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_slo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<SloRequest>,
) -> Result<(StatusCode, Json<Slo>), ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let (name, service, threshold) = req.validate()?;

    let repo = SloRepository::new(state.pool.clone());

    // NAN-1544: tier-cap the number of SLOs before insert.
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await?;
    if tier_limits.is_enforced() {
        let current = repo.list().await.map_err(map_repo_err)?.len() as u32;
        nanosiem_core::check_limit(
            "SLOs",
            current,
            tier_limits.max_slos,
            tier_limits.tier,
            "Upgrade your plan for more SLOs.",
        )?;
    }

    let def = repo
        .create(
            &name,
            &service,
            req.sli_kind,
            req.target,
            req.window_days,
            threshold,
            Some(auth.user_id()),
        )
        .await
        .map_err(map_repo_err)?;

    let slo = enrich(&state, def).await?;
    Ok((StatusCode::CREATED, Json(slo)))
}

/// Update an existing SLO.
#[utoipa::path(
    put,
    path = "/api/observability/slos/{id}",
    tag = "observability",
    params(("id" = String, Path, description = "SLO typeid (slo_<base32>) or bare UUID")),
    request_body = SloRequest,
    responses(
        (status = 200, description = "SLO updated (with live attainment)", body = Slo),
        (status = 400, description = "Invalid input", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "SLO not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_slo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<SloRequest>,
) -> Result<Json<Slo>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let (name, service, threshold) = req.validate()?;

    let repo = SloRepository::new(state.pool.clone());
    let def = repo
        .update(
            *id,
            &name,
            &service,
            req.sli_kind,
            req.target,
            req.window_days,
            threshold,
        )
        .await
        .map_err(map_repo_err)?;

    let slo = enrich(&state, def).await?;
    Ok(Json(slo))
}

/// Delete an SLO.
#[utoipa::path(
    delete,
    path = "/api/observability/slos/{id}",
    tag = "observability",
    params(("id" = String, Path, description = "SLO typeid (slo_<base32>) or bare UUID")),
    responses(
        (status = 204, description = "SLO deleted"),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "SLO not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_slo(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;

    let repo = SloRepository::new(state.pool.clone());
    let deleted = repo.delete(*id).await.map_err(map_repo_err)?;
    if !deleted {
        return Err(ApiError::NotFound("SLO not found".to_string()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_slos, create_slo, update_slo, delete_slo),
    components(schemas(Slo, ListSlosResponse, SloRequest, SloDefinition, SloSliKind))
)]
pub struct ObservabilitySlosApiDoc;
