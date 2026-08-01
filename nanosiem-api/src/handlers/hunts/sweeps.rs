// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sweep detail and the report-ingest endpoint.
//!
//! `POST /api/hunts/sweeps/{id}/report` is the ONLY place `hunts:report`
//! applies. It is the whole write surface an unattended sweep key has, and the
//! shape it accepts is deliberately narrow: measurements the RUNNER took, plus
//! a [`SweepReport`](nanosiem_core::hunts::SweepReport) that has no field for a
//! score, a fingerprint, a provenance manifest or a suppression.

use std::str::FromStr;

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{BudgetUsage, HuntSweep, SubmitSweepReportRequest, SweepReportAccepted};
use nanosiem_core::typeid::TypeIdParam;

use super::{artifact_scope, service};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Get one sweep
#[utoipa::path(
    get,
    path = "/api/hunts/sweeps/{id}",
    tag = "hunts",
    params(("id" = String, Path, description = "Sweep TypeID")),
    responses(
        (status = 200, description = "Sweep retrieved; trail redacted for a source-scoped reader", body = HuntSweep),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_sweep(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<HuntSweep>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    Ok(Json(
        service(&state).get_sweep(*id, &artifact_scope(&auth)).await?,
    ))
}

/// Submit a sweep's results
///
/// The server resolves every cited event out of the log store under this
/// principal's own source scope, corroborates each claimed entity against what
/// it actually read, derives the provenance manifest from what resolved,
/// measures prevalence and prior history itself, and only then — inside one
/// transaction that reasserts the runner's fence under lock — derives the
/// fingerprint and computes the score.
///
/// A `409` means the lease is gone: the sweep was reassigned, expired, or has
/// already finished. The runner must STOP rather than retry, because the
/// results it is holding belong to a generation of work that no longer exists.
#[utoipa::path(
    post,
    path = "/api/hunts/sweeps/{id}/report",
    tag = "hunts",
    params(("id" = String, Path, description = "Sweep TypeID")),
    request_body = SubmitSweepReportRequest,
    responses(
        (status = 200, description = "Report committed", body = SweepReportAccepted),
        (status = 400, description = "Invalid runner id"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "The lease is no longer valid — do not retry"),
    ),
    security(("api_key" = []))
)]
pub async fn report_sweep(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<SubmitSweepReportRequest>,
) -> Result<Json<SweepReportAccepted>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_REPORT)?;

    let runner_id = TypeIdParam::from_str(req.runner_id.trim())
        .map_err(|e| ApiError::BadRequest(format!("invalid runner_id: {e}")))?;

    // The evidence lookup runs under the SWEEP PRINCIPAL's live-data scope, not
    // the eventual reader's. A sweep key denied a source must not be able to
    // launder that source's events into a lead by citing their ids — and the
    // lead it does produce is re-evaluated against every later reader's own
    // scope, against the manifest this call stamps.
    let scope = auth.effective_viewer_scope();

    let accepted = service(&state)
        .submit_sweep_report(
            *id,
            *runner_id,
            req.runner_fence,
            BudgetUsage {
                turns: req.turns_used,
                tool_calls: req.tool_calls_used,
                rows_read: req.rows_read,
                wall_seconds: req.wall_seconds,
            },
            req.report,
            &scope,
        )
        .await?;
    Ok(Json(accepted))
}
