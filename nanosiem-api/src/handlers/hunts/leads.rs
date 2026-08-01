// SPDX-License-Identifier: AGPL-3.0-or-later

//! The lead bench and triage.
//!
//! Every read here passes the caller's [`ArtifactScope`] down to SQL. Nothing
//! is filtered in the handler: a post-fetch filter still pages over denied rows,
//! which leaves the page size as an oracle for how many exist.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{
    parse_lead_states, DismissLeadRequest, DismissLeadResponse, HuntLeadDetail, HuntSuppression,
    ListLeadsQuery, PromoteLeadRequest, PromoteLeadResponse, DEFAULT_AGENT_SUPPRESSION_TTL_DAYS,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, HUNT_LEAD_DISMISSED, HUNT_LEAD_PROMOTED, HUNT_SUPPRESSION_RECORDED,
    HUNT_SUPPRESSION_REVOKED,
};
use nanosiem_core::typeid::TypeIdParam;
use std::str::FromStr;
use nanosiem_core::ClientContext;

use super::types::{
    optional_typeid, page_size, ListLeadsParams, ListLeadsResponse, ListSuppressionsParams,
    ListSuppressionsResponse, ProfileResponse,
};
use super::{artifact_scope, service};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List leads (the bench)
///
/// Ordered by the SERVER-computed score. There is no way to sort by anything an
/// agent supplied, because an agent supplies nothing that could be sorted on.
#[utoipa::path(
    get,
    path = "/api/hunts/leads",
    tag = "hunts",
    params(ListLeadsParams),
    responses(
        (status = 200, description = "Leads retrieved", body = ListLeadsResponse),
        (status = 400, description = "Invalid filter"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_leads(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListLeadsParams>,
) -> Result<Json<ListLeadsResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    // Comma-joined and validated server-side (`parse_lead_states`): the bench
    // sends multi-state segments, an unknown state is a 400 rather than a
    // filter that quietly matches nothing, and only validated values are ever
    // bound into the statement.
    let states = match params.state.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => Vec::new(),
        Some(raw) => parse_lead_states(raw).map_err(ApiError::BadRequest)?,
    };
    let query = ListLeadsQuery {
        playbook_id: optional_typeid(params.playbook_id.as_deref(), "playbook_id")?,
        sweep_id: optional_typeid(params.sweep_id.as_deref(), "sweep_id")?,
        states,
        reviewed_by: params.mine.then(|| auth.user_id()),
        min_score: params.min_score,
        limit: page_size(params.limit),
        offset: params.offset.unwrap_or(0).max(0),
    };
    let scope = artifact_scope(&auth);
    let leads = service(&state).list_leads(&query, &scope).await?;
    // The same filters and the same scope, without the page window — the
    // header count must describe exactly the queue the rows came from.
    let total_count = service(&state).count_leads(&query, &scope).await?;
    Ok(Json(ListLeadsResponse { leads, total_count }))
}

/// Get one lead with its evidence
///
/// The evidence rows are pointers into ClickHouse, not copies. The log store
/// stays the system of record so a duplicated body cannot outlive its retention
/// or its ACL.
#[utoipa::path(
    get,
    path = "/api/hunts/leads/{id}",
    tag = "hunts",
    params(("id" = String, Path, description = "Lead TypeID")),
    responses(
        (status = 200, description = "Lead retrieved", body = HuntLeadDetail),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, or not visible under this caller's source scope"),
    ),
    security(("api_key" = []))
)]
pub async fn get_lead(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<HuntLeadDetail>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    Ok(Json(
        service(&state).get_lead(*id, &artifact_scope(&auth)).await?,
    ))
}

/// Promote a lead to a case
///
/// Analyst-confirmed, idempotent, one transaction. Calling it twice returns the
/// SAME case with `already_promoted: true` rather than opening a second one —
/// two analysts clicking at once serialize on the lead row.
///
/// Automatic promotion is deliberately unrepresentable in v1:
/// `hunt_specs_no_auto_promote_v1` is a hard CHECK, because a threshold cannot
/// be calibrated until real promotion outcomes exist and any auto-promote
/// configured before then is a guess with case-creation authority.
///
/// # What the case does and does not carry
///
/// The case gets the hunt name, the entity, and a pointer back to the lead. It
/// does NOT get the narrative: `cases` has no source-provenance columns, so
/// anything copied into one is copied past the gate that protects it. The lead
/// remains the artifact that carries provenance, and the case links to it.
#[utoipa::path(
    post,
    path = "/api/hunts/leads/{id}/promote",
    tag = "hunts",
    params(("id" = String, Path, description = "Lead TypeID")),
    request_body = PromoteLeadRequest,
    responses(
        (status = 200, description = "Promoted (or already promoted)", body = PromoteLeadResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, or not visible under this caller's source scope"),
    ),
    security(("api_key" = []))
)]
pub async fn promote_lead(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<PromoteLeadRequest>,
) -> Result<Json<PromoteLeadResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_TRIAGE)?;
    // Promotion CREATES a case, so it needs the authority to create one as well
    // as the authority to triage a lead. Deriving one from the other would let
    // a `hunts:triage` grant quietly confer case creation.
    ensure_permission(&auth, permissions::CASES_CREATE)?;
    let promoted = service(&state)
        .promote_lead(*id, &req, auth.user_id(), &artifact_scope(&auth))
        .await?;

    // Only audited when this call actually created the case. An idempotent
    // repeat is not a second promotion, and recording it as one would make the
    // audit trail disagree with the case count.
    if !promoted.already_promoted {
        state.emit_audit(
            AuditEvent::builder(AuditSource::Hunt, HUNT_LEAD_PROMOTED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("hunt_lead", Some(promoted.lead_id), None)
                .client_context(&client)
                .details(serde_json::json!({
                    "case_id": promoted.case_id,
                    "case_number": promoted.case_number,
                }))
                .build(),
        );
    }
    Ok(Json(promoted))
}

/// Dismiss a lead
///
/// Always writes a tenant-visible suppression. There is no "dismiss without
/// remembering": per-machine dismissal memory is worthless, and a bench that
/// re-serves yesterday's rejects is abandoned in week three. The analyst chooses
/// WIDTH (`hunt` or `tenant`) and EXPIRY, never whether.
///
/// Suppressions are analyst-only. No path reachable from a sweep report writes
/// one — an agent that could suppress could blind its own successors.
#[utoipa::path(
    post,
    path = "/api/hunts/leads/{id}/dismiss",
    tag = "hunts",
    params(("id" = String, Path, description = "Lead TypeID")),
    request_body = DismissLeadRequest,
    responses(
        (status = 200, description = "Dismissed; the suppression it wrote is returned", body = DismissLeadResponse),
        (status = 400, description = "A reason is required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, or not visible under this caller's source scope"),
        (status = 409, description = "The lead was promoted; close its case instead"),
    ),
    security(("api_key" = []))
)]
pub async fn dismiss_lead(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<DismissLeadRequest>,
) -> Result<Json<DismissLeadResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_TRIAGE)?;
    let dismissed = service(&state)
        .dismiss_lead(*id, &req, auth.user_id(), &artifact_scope(&auth))
        .await?;

    // A dismissal writes a suppression that hides a shape from EVERY analyst
    // from now on. `hunt_suppressions.created_by` is `ON DELETE SET NULL`, so a
    // departing employee's attribution vanishes from the row — the audit log is
    // the system of record for who decided this, and it has to carry the width
    // and expiry to be worth reading.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_LEAD_DISMISSED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_lead", Some(dismissed.lead.id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "suppression_id": dismissed.suppression.id,
                "fingerprint": dismissed.suppression.fingerprint,
                "width": if dismissed.suppression.playbook_id.is_some() { "hunt" } else { "tenant" },
                "expires_at": dismissed.suppression.expires_at,
            }))
            .build(),
    );
    Ok(Json(dismissed))
}

/// List suppressions
#[utoipa::path(
    get,
    path = "/api/hunts/suppressions",
    tag = "hunts",
    params(ListSuppressionsParams),
    responses(
        (status = 200, description = "Suppressions retrieved", body = ListSuppressionsResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_suppressions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListSuppressionsParams>,
) -> Result<Json<ListSuppressionsResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let suppressions = service(&state)
        .list_suppressions(params.include_revoked, &artifact_scope(&auth))
        .await?;
    Ok(Json(ListSuppressionsResponse { suppressions }))
}

/// What a runner submits on a sweep's behalf.
///
/// Deliberately NOT a general suppression-creation body. There is no
/// `playbook_id`, no `entity_type`/`entity_value`, and no `origin` — the broad
/// forms stay unreachable from this path, and an agent cannot forge an
/// analyst-authored row.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct RecordSuppressionRequest {
    /// The ENTITY the sweep recorded a lead for — exactly what it passed to
    /// `record_lead`. NOT a fingerprint: a fingerprint is derived server-side
    /// and the agent has no way to obtain one, so asking for it would be a
    /// contract nothing could satisfy. The server resolves entity → lead →
    /// fingerprint, which also removes the last server-derived value a caller
    /// could have supplied.
    pub entity_type: String,
    pub entity_value: String,
    /// The sweep authoring it. Stamped by the runner from the lease it holds.
    pub sweep_id: String,
    /// Required, and refused when blank.
    pub reason: String,
    /// Clamped to `MIN..=MAX_AGENT_SUPPRESSION_TTL_DAYS`.
    #[serde(default)]
    pub ttl_days: Option<i64>,
}

/// Record a suppression from a sweep
///
/// The one write on this table an AGENT can reach, and the most dangerous write
/// in the hunt system: it is what an attacker who has got text into a log line
/// would most like to touch. Four things bound it, and none of them are this
/// handler's to enforce — they are structural, in the schema and the statement:
///
/// * It does not HIDE. Suppression zeroes a lead's score; the lead is still
///   recorded, still browsable, still attributable to the sweep that suppressed
///   it. A poisoned suppression costs attention, never existence.
/// * It EXPIRES, always — a database CHECK, not a convention.
/// * It is NARROW — one exact fingerprint, and only one belonging to a lead this
///   same sweep filed. There is no wildcard or playbook-wide form to reach.
/// * It is VISIBLE — `origin = 'agent'` is what the bench highlights on.
///
/// Gated on `hunts:report`: the scope withheld from every human role and held
/// only by the runner's minted key, so this is reachable by the RUNNER, never by
/// the sweep's own agent process. The agent writes to a local file with no key
/// and no network; the runner submits.
#[utoipa::path(
    post,
    path = "/api/hunts/suppressions",
    tag = "hunts",
    request_body = RecordSuppressionRequest,
    responses(
        (status = 200, description = "Suppression recorded", body = HuntSuppression),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "No lead with that fingerprint belongs to this sweep"),
    ),
    security(("api_key" = []))
)]
pub async fn record_suppression(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<RecordSuppressionRequest>,
) -> Result<Json<HuntSuppression>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_REPORT)?;

    let reason = req.reason.trim();
    if reason.is_empty() {
        // Refused rather than defaulted. An unexplained agent suppression cannot
        // be reviewed, and an unreviewable one is indistinguishable from the
        // silent blinding this whole design exists to avoid.
        return Err(ApiError::BadRequest(
            "`reason` is required — an agent suppression an analyst cannot evaluate is not              reviewable, and the review is what makes it safe."
                .to_string(),
        ));
    }
    let sweep_id = TypeIdParam::from_str(&req.sweep_id)
        .map_err(|_| ApiError::BadRequest("`sweep_id` is not a sweep id".to_string()))?;

    let recorded = service(&state)
        .record_agent_suppression(
            *sweep_id,
            req.entity_type.trim(),
            req.entity_value.trim(),
            reason,
            req.ttl_days.unwrap_or(DEFAULT_AGENT_SUPPRESSION_TTL_DAYS),
        )
        .await?
        .ok_or_else(|| {
            ApiError::NotFound(
                "No lead with that fingerprint belongs to this sweep. A sweep may only                  suppress a finding it actually filed."
                    .to_string(),
            )
        })?;

    // Audited as a security-relevant action, because it is one: this is a
    // machine deciding an analyst does not need to look at something.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_SUPPRESSION_RECORDED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_suppression", Some(recorded.id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(recorded))
}

/// Revoke a suppression
///
/// The shape reaches the bench again on the next sweep. Attribution for both the
/// original dismissal and this revocation survives in the audit log, which is
/// the system of record for who-did-what.
#[utoipa::path(
    delete,
    path = "/api/hunts/suppressions/{id}",
    tag = "hunts",
    params(("id" = String, Path, description = "Suppression TypeID")),
    responses(
        (status = 204, description = "Revoked"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, already revoked, or not visible under this caller's source scope"),
    ),
    security(("api_key" = []))
)]
pub async fn revoke_suppression(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_TRIAGE)?;
    let revoked = service(&state)
        .revoke_suppression(*id, auth.user_id(), &artifact_scope(&auth))
        .await?;
    if !revoked {
        return Err(ApiError::NotFound("Suppression not found".to_string()));
    }
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_SUPPRESSION_REVOKED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_suppression", Some(*id), None)
            .client_context(&client)
            .build(),
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Get the latest recon profile
///
/// `null` when recon has never run — the cold-start state the Profile screen
/// renders. The profile is built from AGGREGATES only: no raw event reaches the
/// model that writes the fingerprint narrative, which is simultaneously the cost
/// argument, the injection-surface argument, and the "no raw events left the
/// cluster" claim the screen makes.
#[utoipa::path(
    get,
    path = "/api/hunts/profile",
    tag = "hunts",
    responses(
        (status = 200, description = "The latest profile, or null", body = ProfileResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn get_latest_profile(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ProfileResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let profile = service(&state).latest_profile(&artifact_scope(&auth)).await?;
    Ok(Json(ProfileResponse { profile }))
}
