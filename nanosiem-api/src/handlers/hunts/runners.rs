// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runner registration, heartbeat, and sweep claim.
//!
//! "Designated runner" is a euphemism unless the server tracks who is running,
//! when they were last alive, and holds a fence against a recovered stale runner
//! reporting after failover. These three endpoints are that machinery.
//!
//! Heartbeat and claim carry `hunts:report` — the scope minted into an
//! unattended sweep key and held by no human role. Registration is
//! `hunts:manage`, because declaring a machine eligible to run autonomous hunts
//! against the estate is an administrative act, not something a runner may do
//! for itself.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::actions::{
    HUNT_RUNNER_AGY_WAIVER_GRANTED, HUNT_RUNNER_AGY_WAIVER_REVOKED,
};
use nanosiem_core::audit::{AuditEvent, AuditSource};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{ClaimSweepRequest, HuntRunner, RegisterRunnerRequest};
use nanosiem_core::typeid::TypeIdParam;

use super::service;
use super::types::{ClaimSweepOutcome, ListRunnersResponse};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use nanosiem_core::ClientContext;
use crate::{error::ApiError, state::AppState};

/// List hunt runners
#[utoipa::path(
    get,
    path = "/api/hunts/runners",
    tag = "hunts",
    responses(
        (status = 200, description = "Runners retrieved", body = ListRunnersResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_runners(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListRunnersResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let runners = service(&state).list_runners().await?;
    Ok(Json(ListRunnersResponse { runners }))
}

/// Register a runner
#[utoipa::path(
    post,
    path = "/api/hunts/runners",
    tag = "hunts",
    request_body = RegisterRunnerRequest,
    responses(
        (status = 201, description = "Runner registered", body = HuntRunner),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn register_runner(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<RegisterRunnerRequest>,
) -> Result<(StatusCode, Json<HuntRunner>), ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let runner = service(&state)
        .register_runner(&req, Some(auth.user_id()))
        .await?;
    Ok((StatusCode::CREATED, Json(runner)))
}

/// Runner heartbeat
///
/// Deliberately does NOT extend a lease. If it did, a runner that had wedged
/// mid-sweep but whose heartbeat thread was still alive would hold its sweep
/// forever — the exact failure the lease exists to bound.
#[utoipa::path(
    post,
    path = "/api/hunts/runners/{id}/heartbeat",
    tag = "hunts",
    params(("id" = String, Path, description = "Runner TypeID")),
    responses(
        (status = 200, description = "Heartbeat recorded", body = HuntRunner),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Runner not found or disabled"),
    ),
    security(("api_key" = []))
)]
pub async fn runner_heartbeat(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<HuntRunner>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_REPORT)?;
    Ok(Json(service(&state).heartbeat_runner(*id).await?))
}

/// Grant this runner the Antigravity sweep waiver
///
/// See [`nanosiem_core::audit::actions::HUNT_RUNNER_AGY_WAIVER_GRANTED`] for
/// what is being accepted. `hunts:manage`, not `hunts:report`: this is the same
/// administrative act as declaring the machine a runner in the first place, and
/// a runner must never be able to widen its own authority — the sweep key holds
/// only `hunts:report`, so the grant is unreachable from inside a sweep.
#[utoipa::path(
    post,
    path = "/api/hunts/runners/{id}/agy-waiver",
    tag = "hunts",
    params(("id" = String, Path, description = "Runner TypeID")),
    responses(
        (status = 200, description = "Waiver granted", body = HuntRunner),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Runner not found"),
    ),
    security(("api_key" = []))
)]
pub async fn grant_runner_agy_waiver(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<HuntRunner>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let runner = service(&state)
        .set_runner_agy_waiver(*id, true, Some(auth.user_id()))
        .await?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_RUNNER_AGY_WAIVER_GRANTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_runner", Some(runner.id), Some(runner.label.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "hostname": runner.hostname,
                "agent_tool": runner.agent_tool,
            }))
            .build(),
    );
    Ok(Json(runner))
}

/// Withdraw this runner's Antigravity sweep waiver
///
/// # What "takes effect" means, precisely
///
/// The waiver is a RECORD here and a gate in the runner, not a server-side
/// enforcement point — the server cannot tell which CLI a workstation actually
/// spawned, so claiming to enforce it would be a stronger promise than the
/// architecture can keep. A runner re-reads this on every heartbeat (60s), so a
/// withdrawal stops agy sweeps on that machine within about a minute, without
/// anyone touching the desktop.
///
/// A sweep already in flight is not killed. That is deliberate — a half-finished
/// sweep that is stopped mid-run still had whatever reach it had, so killing it
/// buys nothing the revocation has not already bought, and it would lose the
/// leads the run had already recorded.
#[utoipa::path(
    delete,
    path = "/api/hunts/runners/{id}/agy-waiver",
    tag = "hunts",
    params(("id" = String, Path, description = "Runner TypeID")),
    responses(
        (status = 200, description = "Waiver withdrawn", body = HuntRunner),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Runner not found"),
    ),
    security(("api_key" = []))
)]
pub async fn revoke_runner_agy_waiver(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<HuntRunner>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let runner = service(&state)
        .set_runner_agy_waiver(*id, false, Some(auth.user_id()))
        .await?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_RUNNER_AGY_WAIVER_REVOKED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_runner", Some(runner.id), Some(runner.label.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "hostname": runner.hostname,
                "granted_at": runner.agy_waiver_granted_at,
            }))
            .build(),
    );
    Ok(Json(runner))
}

/// Claim the next sweep
///
/// Returns `200 {"sweep": null}` when there is nothing to do. A runner polls
/// every few seconds and an empty queue is the normal case; making it a 404
/// would fill the log with failures that mean "everything is fine".
///
/// The response carries the fence issued with the lease. The runner echoes it
/// back on the report, where it is reasserted under lock — that reassertion is
/// what stops a runner that slept through its lease appending to work that has
/// since been reassigned.
#[utoipa::path(
    post,
    path = "/api/hunts/runners/{id}/claim",
    tag = "hunts",
    params(("id" = String, Path, description = "Runner TypeID")),
    request_body = ClaimSweepRequest,
    responses(
        (status = 200, description = "A sweep, or null when the queue is empty", body = ClaimSweepOutcome),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Runner not found or disabled"),
    ),
    security(("api_key" = []))
)]
pub async fn claim_sweep(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ClaimSweepRequest>,
) -> Result<Json<ClaimSweepOutcome>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_REPORT)?;
    let sweep = service(&state).claim_sweep(*id, req.lease_seconds).await?;
    Ok(Json(ClaimSweepOutcome { sweep }))
}
