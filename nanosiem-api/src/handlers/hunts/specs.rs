// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hunt definition CRUD, plus the manual sweep trigger.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{
    CreateHuntRequest, Hunt, HuntSummary, HuntSweep, ListSweepsQuery, SetScheduleRequest, ToggleHuntRequest,
    UpdateHuntRequest,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, HUNT_SCHEDULE_DISABLED, HUNT_SCHEDULE_SET, HUNT_SCHEDULE_ENABLED,
};
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::ClientContext;

use super::types::{page_size, ListHuntsParams, ListHuntsResponse, ListSweepsParams,
    ListSweepsResponse};
use super::{artifact_scope, service};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List hunts
#[utoipa::path(
    get,
    path = "/api/hunts",
    tag = "hunts",
    params(ListHuntsParams),
    responses(
        (status = 200, description = "Hunts retrieved", body = ListHuntsResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_hunts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListHuntsParams>,
) -> Result<Json<ListHuntsResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let hunts = service(&state)
        .list_hunts(
            params.enabled_only,
            page_size(params.limit),
            params.offset.unwrap_or(0).max(0),
        )
        .await?;
    Ok(Json(ListHuntsResponse { hunts }))
}

/// Create a hunt
///
/// The hunt is created DISABLED. Authoring a hunt and putting it on a cron
/// against production telemetry are different decisions, and only the second
/// needs `hunts:run` — so creation cannot be a way to reach the schedule
/// without holding it.
#[utoipa::path(
    post,
    path = "/api/hunts",
    tag = "hunts",
    request_body = CreateHuntRequest,
    responses(
        (status = 201, description = "Hunt created (disabled)", body = Hunt),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateHuntRequest>,
) -> Result<(StatusCode, Json<Hunt>), ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let hunt = service(&state)
        .create_hunt(&req, Some(auth.user_id()))
        .await?;
    Ok((StatusCode::CREATED, Json(hunt)))
}

/// Get a hunt
#[utoipa::path(
    get,
    path = "/api/hunts/{id}",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    responses(
        (status = 200, description = "Hunt retrieved", body = Hunt),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Hunt>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    Ok(Json(service(&state).get_hunt(*id).await?))
}

/// Update a hunt
///
/// A PATCH that touches `enabled`, `schedule_cron` or `schedule_timezone`
/// additionally requires `hunts:run`. Bundling a schedule change into an
/// otherwise innocuous metadata edit is the obvious way around a
/// permission split like this, so the request is asked rather than the field
/// list eyeballed.
#[utoipa::path(
    patch,
    path = "/api/hunts/{id}",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    request_body = UpdateHuntRequest,
    responses(
        (status = 200, description = "Hunt updated", body = Hunt),
        (status = 400, description = "Invalid input"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<UpdateHuntRequest>,
) -> Result<Json<Hunt>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    if req.touches_schedule() {
        ensure_permission(&auth, permissions::HUNTS_RUN)?;
    }
    Ok(Json(service(&state).update_hunt(*id, &req).await?))
}

/// Archive a hunt
#[utoipa::path(
    delete,
    path = "/api/hunts/{id}",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    responses(
        (status = 204, description = "Hunt archived and disabled"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn archive_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    service(&state).archive_hunt(*id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Trigger a manual sweep
///
/// The window comes from the hunt's own `lookback_window`, never from the
/// caller. Accepting a caller-supplied window would let a `hunts:run` holder
/// aim an autonomous agent at an arbitrary slice of history, which is a
/// different authority from "run this hunt".
#[utoipa::path(
    post,
    path = "/api/hunts/{id}/sweeps",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    responses(
        (status = 202, description = "Sweep queued", body = HuntSweep),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 409, description = "A sweep is already in flight for this hunt"),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_sweep(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<(StatusCode, Json<HuntSweep>), ApiError> {
    ensure_permission(&auth, permissions::HUNTS_RUN)?;
    let sweep = service(&state).trigger_manual_sweep(*id).await?;
    Ok((StatusCode::ACCEPTED, Json(sweep)))
}

/// Enable or disable a hunt's schedule
///
/// Its own endpoint rather than a PATCH field so the authority being exercised
/// is obvious at the call site — and so no import or draft path can reach it by
/// accident. A hunt's `schedule` is a SUGGESTED cadence; this is the only thing
/// that acts on it.
/// Set or clear a hunt's cadence
///
/// Its own endpoint rather than a PATCH field, for the same reason `/toggle` is:
/// the authority being exercised is distinct, and it must be auditable as
/// itself. `PATCH /api/hunts/{id}` is `COALESCE` on every column, so a null
/// there means "unchanged" — there is no way to express "manual only" through
/// it, and an analyst clearing a cadence got a silent no-op.
///
/// `schedule_cron: null` means MANUAL ONLY. It is not the same as disabling: a
/// manual hunt can still be swept on demand, it simply has no cadence for the
/// scheduler to see. The scheduler needs `enabled AND schedule_cron IS NOT
/// NULL`, so these are two independent halves of "does this run by itself".
#[utoipa::path(
    post,
    path = "/api/hunts/{id}/schedule",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    request_body = SetScheduleRequest,
    responses(
        (status = 200, description = "Cadence set", body = Hunt),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn set_hunt_schedule(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<SetScheduleRequest>,
) -> Result<Json<Hunt>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_RUN)?;
    let hunt = service(&state)
        .set_hunt_schedule(
            *id,
            req.schedule_cron.as_deref().map(str::trim).filter(|c| !c.is_empty()),
            req.schedule_timezone.as_deref(),
        )
        .await?;

    // Audited for the same reason the toggle is: a cadence is the authority to
    // run unattended against production telemetry on a repeat, and "who put this
    // on a schedule" is a question an incident review asks.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_SCHEDULE_SET)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt", Some(hunt.playbook_id), Some(hunt.title.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "schedule_cron": hunt.schedule_cron,
                "schedule_timezone": hunt.schedule_timezone,
                "enabled": hunt.enabled,
            }))
            .build(),
    );

    Ok(Json(hunt))
}

#[utoipa::path(
    post,
    path = "/api/hunts/{id}/toggle",
    tag = "hunts",
    params(("id" = String, Path, description = "Hunt TypeID")),
    request_body = ToggleHuntRequest,
    responses(
        (status = 200, description = "Schedule toggled", body = Hunt),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn toggle_hunt(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<ToggleHuntRequest>,
) -> Result<Json<Hunt>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_RUN)?;
    let hunt = service(&state).set_hunt_enabled(*id, req.enabled).await?;

    // Audited because this is the single decision that puts an autonomous agent
    // on production telemetry — the "who turned this on" question an incident
    // review asks first.
    state.emit_audit(
        AuditEvent::builder(
            AuditSource::Hunt,
            if req.enabled {
                HUNT_SCHEDULE_ENABLED
            } else {
                HUNT_SCHEDULE_DISABLED
            },
        )
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("hunt", Some(hunt.playbook_id), Some(hunt.title.clone()))
        .client_context(&client)
        .details(serde_json::json!({
            "schedule_cron": hunt.schedule_cron,
            "enabled": hunt.enabled,
        }))
        .build(),
    );
    Ok(Json(hunt))
}

/// List a hunt's sweeps
///
/// Sweeps are NOT hidden from a source-scoped reader — a sweep row records that
/// a run happened, which is scheduler state rather than derived content. What
/// IS withheld is the agent-authored half: `trail` and `outcome_detail` are
/// blanked and `redacted` is set, so the UI can say the trail is withheld
/// instead of implying the sweep did nothing.
#[utoipa::path(
    get,
    path = "/api/hunts/{id}/sweeps",
    tag = "hunts",
    params(
        ("id" = String, Path, description = "Hunt TypeID"),
        ListSweepsParams,
    ),
    responses(
        (status = 200, description = "Sweeps retrieved", body = ListSweepsResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_hunt_sweeps(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(params): Query<ListSweepsParams>,
) -> Result<Json<ListSweepsResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let sweeps = service(&state)
        .list_sweeps(
            &ListSweepsQuery {
                playbook_id: Some(*id),
                status: params.status,
                limit: page_size(params.limit),
                offset: params.offset.unwrap_or(0).max(0),
            },
            &artifact_scope(&auth),
        )
        .await?;
    Ok(Json(ListSweepsResponse { sweeps }))
}

/// Hunting rail summary
///
/// One call for the four rail badges plus the cold-start facts. Four separate
/// pages would be four round trips and four chances to render a rail whose
/// numbers were measured at different instants.
///
/// `never_swept` is the load-bearing one: it is what distinguishes "nothing was
/// found" from "nothing ran", and an empty bench means very different things in
/// each case.
#[utoipa::path(
    get,
    path = "/api/hunts/summary",
    tag = "hunts",
    responses(
        (status = 200, description = "Rail summary", body = HuntSummary),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn hunts_summary(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<HuntSummary>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    Ok(Json(service(&state).summary(&artifact_scope(&auth)).await?))
}
