// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule ideas — recurring lead shapes offered as detection candidates.
//!
//! # What "send" is, and what it deliberately is not
//!
//! An unattended sweep may only ever create an INERT record. It gets no repo
//! mount, no git credentials, and no write-capable nanodac tools. Shipping stays
//! human-triggered and interactive, because otherwise attacker-influenced lead
//! content would have a path into a detection rule.
//!
//! So `send` does exactly two things: it re-derives the gate from the idea's
//! basis rows, and — if the shape has earned it — records the human's own
//! reference and marks the idea `sent`. It writes nothing outside this database
//! and calls nothing.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::{
    RejectRuleIdeaRequest, RuleIdeaDecision, RuleIdeaVerdict, SendRuleIdeaRequest,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, HUNT_RULE_IDEA_REJECTED, HUNT_RULE_IDEA_SENT,
};
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::ClientContext;

use super::types::{optional_typeid, ListRuleIdeasParams, ListRuleIdeasResponse};
use super::{artifact_scope, service};
use crate::handlers::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List rule ideas
///
/// `basis_sweep_count` / `basis_promoted_count` on each row are a CACHE of
/// `hunt_rule_idea_basis`, refreshed whenever a sweep or a promotion changes
/// them. The gate is never decided on them — see `send`.
#[utoipa::path(
    get,
    path = "/api/hunts/rule-ideas",
    tag = "hunts",
    params(ListRuleIdeasParams),
    responses(
        (status = 200, description = "Rule ideas retrieved", body = ListRuleIdeasResponse),
        (status = 400, description = "Invalid filter"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_rule_ideas(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListRuleIdeasParams>,
) -> Result<Json<ListRuleIdeasResponse>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_VIEW)?;
    let playbook_id = optional_typeid(params.playbook_id.as_deref(), "playbook_id")?;
    let rule_ideas = service(&state)
        .list_rule_ideas(playbook_id, &artifact_scope(&auth))
        .await?;
    Ok(Json(ListRuleIdeasResponse { rule_ideas }))
}

/// Send a rule idea to detection-as-code
///
/// Re-derives the "3 sweeps, 2 promotions" gate FROM `hunt_rule_idea_basis`
/// inside the same transaction and refuses with `409` if the shape has not
/// earned it. The cached counters are never what authorizes shipping: the CHECK
/// over them is satisfied by writing 3 and 2, and this is one human click away
/// from a detection rule.
///
/// The record stays inert. `dac_reference` is whatever the human pastes — a PR
/// url or a branch — recorded verbatim for traceability. Nothing here mounts a
/// repo, holds a credential, or writes a rule.
#[utoipa::path(
    post,
    path = "/api/hunts/rule-ideas/{id}/send",
    tag = "hunts",
    params(("id" = String, Path, description = "Rule idea TypeID")),
    request_body = SendRuleIdeaRequest,
    responses(
        (status = 200, description = "Marked sent", body = RuleIdeaDecision),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, or not visible under this caller's source scope"),
        (status = 409, description = "The shape has not cleared the 3-sweep / 2-promotion gate"),
    ),
    security(("api_key" = []))
)]
pub async fn send_rule_idea(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<SendRuleIdeaRequest>,
) -> Result<Json<RuleIdeaDecision>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let decision = service(&state)
        .decide_rule_idea(
            *id,
            RuleIdeaVerdict::Send,
            req.dac_reference.as_deref(),
            &artifact_scope(&auth),
        )
        .await?;

    // The audit record carries the counts the gate was evaluated on, so the
    // decision can be re-justified later even if the basis rows have since aged
    // out with their sweeps.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_RULE_IDEA_SENT)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_rule_idea", Some(decision.id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "dac_reference": req.dac_reference,
                "distinct_sweeps": decision.counts.distinct_sweeps,
                "promoted_leads": decision.counts.promoted_leads,
            }))
            .build(),
    );
    Ok(Json(decision))
}

/// Reject a rule idea
///
/// Terminal. A later recount will not resurrect it — `rejected` is a human
/// decision and the recompute path deliberately leaves it alone.
#[utoipa::path(
    post,
    path = "/api/hunts/rule-ideas/{id}/reject",
    tag = "hunts",
    params(("id" = String, Path, description = "Rule idea TypeID")),
    request_body = RejectRuleIdeaRequest,
    responses(
        (status = 200, description = "Rejected", body = RuleIdeaDecision),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found, or not visible under this caller's source scope"),
    ),
    security(("api_key" = []))
)]
pub async fn reject_rule_idea(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<RejectRuleIdeaRequest>,
) -> Result<Json<RuleIdeaDecision>, ApiError> {
    ensure_permission(&auth, permissions::HUNTS_MANAGE)?;
    let decision = service(&state)
        .decide_rule_idea(
            *id,
            RuleIdeaVerdict::Reject,
            req.reason.as_deref(),
            &artifact_scope(&auth),
        )
        .await?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_RULE_IDEA_REJECTED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_rule_idea", Some(decision.id), None)
            .client_context(&client)
            .details(serde_json::json!({ "reason": req.reason }))
            .build(),
    );
    Ok(Json(decision))
}
