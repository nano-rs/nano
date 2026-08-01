// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recon — the primitives an agent drives, plus the closed run it replaced.
//!
//! # The shape, and why it is four endpoints rather than one
//!
//! Recon used to be a single closed job: a fixed probe list, an aggregates-only
//! rule, and nothing that could step outside either. That is wrong for a
//! product whose identity is that the AGENT uses it — a major capability the
//! agent can neither invoke nor steer is an inconsistency, not a safety
//! feature.
//!
//! So the layers are split by whether they are arithmetic or judgement:
//!
//! | endpoint | who decides | why |
//! |---|---|---|
//! | `POST /api/hunts/profile/census` | server | arithmetic over aggregates; a model re-deriving counts gives approximately-right numbers that move between runs |
//! | `POST /api/hunts/profile/surface` | server | a fixed mapping; if a model derives it the rail badge and the Profile page disagree about how many gaps exist |
//! | `POST /api/hunts/profile` | agent | the fingerprint is a reading of an estate |
//! | `POST /api/hunts/drafts` | agent | where to hunt next is an opinion |
//!
//! MCP is an interface; what runs behind a tool may be server code. Putting the
//! first two behind endpoints does not make them less deterministic — it makes
//! them reachable.
//!
//! `POST /api/hunts/profile/run` stays as the deterministic non-agent path. It
//! is the fallback when no agent is available, and it is what the desktop calls
//! headlessly.
//!
//! # The permission, and why it is its own scope
//!
//! `hunts:run` is authority to start a sweep of a hunt somebody already
//! authored and reviewed. Recon is not that: it reads across the whole log
//! estate and CREATES hunt definitions. The drafts it writes land disabled with
//! no schedule, so the second decision (`hunts:run`) is still a separate one
//! taken by a human.
//!
//! Every endpoint here accepts EITHER
//! [`HUNTS_PROFILE_WRITE`](nanosiem_core::auth::permissions::HUNTS_PROFILE_WRITE)
//! or [`HUNTS_MANAGE`](nanosiem_core::auth::permissions::HUNTS_MANAGE) — see
//! [`ensure_recon_write`].
//!
//! `hunts:manage` alone was wrong for the agent case. It is the same scope that
//! EDITS and ARCHIVES hunts, so a key minted to write one profile could delete
//! the hunt library — and a minted key is `requested set ∩ the minter's own
//! permissions`, so asking for a subset of `hunts:manage` just gets you
//! `hunts:manage`. The subset has to be a scope that exists, which is what
//! migration 9000060 adds.
//!
//! `/profile/run` takes the same gate as the four primitives rather than a
//! stricter one. It is exactly census + surface + save + drafts in a single
//! call, so a principal that may make those four calls can already produce
//! everything it produces; requiring more for the convenience wrapper would be
//! theatre, not a boundary.
//!
//! # Why these are synchronous
//!
//! The whole of a run shares one wall-clock budget
//! ([`RECON_WALL_BUDGET`](nanosiem_core::hunts::recon::RECON_WALL_BUDGET) —
//! every probe past it is skipped with a note rather than started), so the
//! response time is bounded and the caller learns exactly what degraded. Making
//! it a background job would buy nothing except a second surface for reporting
//! the same partial result.
//!
//! # What is audited, and what is not
//!
//! The census and the surface are READS. They are expensive reads — which is
//! why they are POSTs — but they leave nothing behind, and an agent that polls
//! them while narrowing an estate would turn a per-call audit write into noise
//! that buries the two records that matter. Saving a profile and creating
//! drafts have lasting effects, so those are audited.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, HUNT_DRAFTS_CREATED, HUNT_PROFILE_SAVED, HUNT_RECON_RAN,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::hunts::recon::{
    CensusReport, CreateDraftsRequest, DraftBatchOutcome, ReconRunSummary, ReconService,
    SaveProfileRequest, SurfaceDetail, SurfaceResponse,
};
use serde::Deserialize;
use nanosiem_core::hunts::HuntProfile;
use nanosiem_core::ClientContext;

use crate::handlers::AuditExt;
use crate::middleware::AuthContext;
use crate::{error::ApiError, state::AppState};

/// The gate on every recon write.
///
/// Either scope admits. `hunts:profile_write` is the narrow one an agent recon
/// key is minted with; `hunts:manage` is accepted too so that every principal
/// and every key that could call recon before this scope existed still can.
/// The relationship is one-way — this widens, never narrows.
fn ensure_recon_write(auth: &AuthContext) -> Result<(), ApiError> {
    const ACCEPTED: &[&str] = &[permissions::HUNTS_PROFILE_WRITE, permissions::HUNTS_MANAGE];
    if auth.has_any_permission(ACCEPTED) {
        return Ok(());
    }
    // Names both, because a caller told only "missing hunts:profile_write"
    // cannot tell whether the broader scope would also have worked.
    Err(ApiError::Forbidden(format!(
        "Missing permission: {} or {}",
        permissions::HUNTS_PROFILE_WRITE,
        permissions::HUNTS_MANAGE
    )))
}

/// Run recon
///
/// The DETERMINISTIC, non-agent path: rebuilds the deployment profile in one
/// call — the per-source telemetry census, the ATT&CK huntable surface, the
/// aggregates-only org fingerprint, and one DISABLED draft hunt per
/// newly-identified gap.
///
/// Prefer driving `profile/census`, `profile/surface`, `profile` and `drafts`
/// from an agent. This exists because a deployment with no AI provider must
/// still get a profile, and because the desktop needs something that works
/// headlessly.
///
/// A run that could not read part of the log store, or that ran while a
/// hunt-required source was unhealthy, still stores a profile — stamped
/// `degraded` with the reason, so the census rows and the techniques that
/// flipped `covered → blind` can be marked rather than silently believed.
#[utoipa::path(
    post,
    path = "/api/hunts/profile/run",
    tag = "hunts",
    responses(
        (status = 200, description = "Profile rebuilt (possibly degraded)", body = ReconRunSummary),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Recon could not read the source inventory or store the profile"),
    ),
    security(("api_key" = []))
)]
pub async fn run_recon_profile(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<Json<ReconRunSummary>, ApiError> {
    ensure_recon_write(&auth)?;

    let summary = recon_service(&state).await.run(Some(auth.user_id())).await?;

    // The audit record carries what the run CONCLUDED, not merely that it ran:
    // draft creation is the part with a lasting effect, and the degraded flag is
    // what explains a profile that later looks wrong.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_RECON_RAN)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_profile", Some(summary.profile.id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "census_rows": summary.census_rows,
                "covered": summary.covered,
                "gaps": summary.gaps,
                "blind": summary.blind,
                "unmapped": summary.unmapped,
                "drafts_created": summary.drafts_created,
                "drafts_skipped": summary.drafts_skipped,
                "fingerprint_available": summary.fingerprint_available,
                "degraded": summary.degraded,
                "degraded_detail": summary.degraded_detail,
            }))
            .build(),
    );

    Ok(Json(summary))
}

/// Compute the telemetry census
///
/// Deterministic. Per `source_type`: volume, a 24-hour sparkline, field
/// population, history depth, and health as PROSE — `"stale 14h · 61 of 480
/// hosts"` — because the useful thing about a degraded source is the shape of
/// the degradation, which a red/amber/green chip throws away.
///
/// The invariant: **every source type any hunt requires appears, even when it
/// is entirely absent.** A census assembled only from what is ingesting would
/// omit the one source whose absence explains why half the hunt library is
/// held.
///
/// A POST because it is an expensive read across the whole estate, not because
/// it writes anything. Nothing is persisted and nothing is audited.
#[utoipa::path(
    post,
    path = "/api/hunts/profile/census",
    tag = "hunts",
    responses(
        (status = 200, description = "Census computed (possibly degraded)", body = CensusReport),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "The source inventory could not be read"),
    ),
    security(("api_key" = []))
)]
pub async fn recon_census(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<CensusReport>, ApiError> {
    ensure_recon_write(&auth)?;
    Ok(Json(recon_service(&state).await.census().await?))
}

/// How much of the surface to return.
///
/// A query parameter rather than a body field because the two calls differ only
/// in what crosses the wire — the server computes the same thing either way —
/// and because a GET-shaped knob on a POST is still the knob a caller reaches
/// for first.
#[derive(Debug, Clone, Copy, Default, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SurfaceQuery {
    /// `summary` (default) or `full`. See [`SurfaceDetail`].
    #[serde(default)]
    pub detail: SurfaceDetail,
}

/// Compute the huntable surface
///
/// Deterministic. For each ATT&CK technique, its declared data sources are
/// turned into nano `source_type`s, compared against what is configured AND
/// healthy, and only then crossed with rule coverage:
///
/// * `blind` — no mapped source is live. Sourcing work, not hunting work: a
///   hunt here could only ever return nothing.
/// * `gap` — telemetry is there and no rule covers it. This is where hunts
///   come from.
/// * `covered` — telemetry plus at least one live/alerting rule.
/// * `unmapped` — nano has no mapping for the technique's data sources. NOT
///   folded into `blind`: the mapping table is a curated subset by design, and
///   claiming "you are blind here" because our table is incomplete would be a
///   lie in the operator's least favourite direction. Counts toward neither.
///
/// # `detail=summary` is the default, and why
///
/// A real Google-Workspace-only deployment answered the old
/// always-full response with **371,233 characters** — `tactics[]` was 99.9% of
/// it, 697 techniques of which 615 were `blind`, and there were no covered
/// techniques and no gaps at all. The agent harness rejected the result, and
/// because a recon agent runs in a mode that disallows reading files, there was
/// no route back to the data: 371 KB spent to say "nothing is huntable yet".
///
/// `summary` therefore carries the counts, the FULL rows for `gap` techniques
/// (the only ones a hunt can be drafted from), a ranked count of the source
/// types missing across `blind` techniques (the sourcing backlog, which is what
/// a blind estate actually needs), `unmapped` as ids, and the live source types.
/// Every cap it applies is stated in the payload.
///
/// `detail=full` returns the unchanged nested tactic-column shape the rail badge
/// tallies and the Profile page renders. Ask for it when you are going to render
/// the matrix; you no longer need it in order to save a profile, because
/// `POST /api/hunts/profile` recomputes the surface when the body omits it.
#[utoipa::path(
    post,
    path = "/api/hunts/profile/surface",
    tag = "hunts",
    params(SurfaceQuery),
    responses(
        (status = 200, description = "Surface computed (possibly degraded). `SurfaceSummaryReport` unless `detail=full`, in which case `SurfaceReport`.", body = SurfaceResponse),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "The source inventory or ATT&CK catalog could not be read"),
    ),
    security(("api_key" = []))
)]
pub async fn recon_surface(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<SurfaceQuery>,
) -> Result<Json<SurfaceResponse>, ApiError> {
    ensure_recon_write(&auth)?;
    let report = recon_service(&state).await.surface().await?;
    Ok(Json(match query.detail {
        SurfaceDetail::Summary => SurfaceResponse::Summary(Box::new(report.into_summary())),
        SurfaceDetail::Full => SurfaceResponse::Full(Box::new(report)),
    }))
}

/// Save a deployment profile
///
/// Takes the judgement halves the agent wrote — `fingerprint` and
/// `actor_weighting` — and, OPTIONALLY, the deterministic halves (`census`,
/// `huntable_surface`).
///
/// **Omit the deterministic halves.** The agent authors neither; requiring them
/// only made it shuttle two large server-computed structures back unchanged,
/// which is what made agent-driven recon unusable. When either is absent the
/// server recomputes it here from the same reads the census and surface
/// endpoints use — and the result is a profile whose two halves were measured at
/// one instant rather than stitched from two calls minutes apart. Both are still
/// accepted when present.
///
/// **The server stamps provenance.** `source_types` and
/// `source_types_complete` are derived here from the same source inventory the
/// census and surface reads enumerate, and the request has no field for either.
/// The manifest is an authorization input — every source-scoped reader of the
/// stored profile is judged against it — so a caller able to set it would be
/// choosing who may read what it wrote.
///
/// `degraded` merges monotonically: a body saying `false` cannot clear a flag
/// the server raised, and a body saying `true` is believed.
///
/// Prose is capped, structural over-caps are rejected, and the whole body is
/// bounded at 2 MiB — this is model-written text reaching a shared column.
///
/// Returns the STORED profile, `id` included. A caller must not infer "did this
/// write land" by comparing the newest-profile id before and after: that
/// answers "newest changed", which is a different question the moment two
/// runners exist, and it mis-attributes which path produced the row.
#[utoipa::path(
    post,
    path = "/api/hunts/profile",
    tag = "hunts",
    request_body = SaveProfileRequest,
    responses(
        (status = 201, description = "Profile stored; body is the created profile including its id", body = HuntProfile),
        (status = 400, description = "A structural cap was exceeded"),
        (status = 403, description = "Forbidden"),
        (status = 413, description = "Body larger than 2 MiB"),
    ),
    security(("api_key" = []))
)]
pub async fn save_recon_profile(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<SaveProfileRequest>,
) -> Result<(StatusCode, Json<HuntProfile>), ApiError> {
    ensure_recon_write(&auth)?;

    let profile = recon_service(&state)
        .await
        .save_profile(request, Some(auth.user_id()))
        .await?;

    // The manifest is in the record because it is the thing a later access
    // review asks about: a profile a source-scoped analyst cannot read is
    // explained by these two fields and nothing else.
    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_PROFILE_SAVED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt_profile", Some(profile.id), None)
            .client_context(&client)
            .details(serde_json::json!({
                "census_rows": profile.census.as_array().map(|rows| rows.len()).unwrap_or(0),
                "degraded": profile.degraded,
                "degraded_detail": profile.degraded_detail,
                "source_types": profile.source_types,
                "source_types_complete": profile.source_types_complete,
            }))
            .build(),
    );

    Ok((StatusCode::CREATED, Json(profile)))
}

/// Create draft hunts
///
/// Every draft lands with `enabled = FALSE` and `schedule_cron = NULL` written
/// as SQL LITERALS rather than bind parameters, so there is no proposal —
/// however shaped — that can put a generated hunt on a cron. A suggested
/// cadence lives in the prose doc. Nothing generated ever schedules itself.
///
/// One malformed proposal is reported and skipped rather than failing the
/// batch; the response says what happened to each, because an agent that gets
/// back "3 created" with no idea which three cannot fix the two that failed.
#[utoipa::path(
    post,
    path = "/api/hunts/drafts",
    tag = "hunts",
    request_body = CreateDraftsRequest,
    responses(
        (status = 200, description = "Per-draft outcomes", body = DraftBatchOutcome),
        (status = 400, description = "More drafts than one call may create"),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_hunt_drafts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateDraftsRequest>,
) -> Result<Json<DraftBatchOutcome>, ApiError> {
    ensure_recon_write(&auth)?;

    let outcome = recon_service(&state)
        .await
        .create_drafts(request, Some(auth.user_id()))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Hunt, HUNT_DRAFTS_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("hunt", None, None)
            .client_context(&client)
            .details(serde_json::json!({
                "created": outcome.created,
                "skipped": outcome.skipped,
                "rejected": outcome.rejected,
                "techniques": outcome
                    .drafts
                    .iter()
                    .map(|draft| draft.mitre_technique.as_str())
                    .collect::<Vec<_>>(),
            }))
            .build(),
    );

    Ok(Json(outcome))
}

/// Build the recon service for one request.
///
/// The AI client is `Option` and stays `None` on open-core: the deterministic
/// run's fingerprint is the only layer that needs a model, and a deployment
/// without one must still get its census and its huntable surface. See
/// [`ReconService::run`](nanosiem_core::hunts::recon::ReconService::run) — a
/// missing provider is recorded on the fingerprint card, not as a failed run.
/// The agent-driven endpoints never touch it at all: the agent IS the model.
async fn recon_service(state: &AppState) -> ReconService {
    #[cfg(feature = "enterprise")]
    let ai = {
        use nanosiem_core::extensions::AiClient;
        use std::sync::Arc;
        state
            .melod_service
            .read()
            .await
            .as_ref()
            .map(|service| service.ai_client_arc())
            .map(|shared| {
                Arc::new(nanosiem_enterprise::melod::MelodAiClientBridge::new(shared))
                    as Arc<dyn AiClient>
            })
    };
    #[cfg(not(feature = "enterprise"))]
    let ai = None;

    ReconService::new(
        state.pool.clone(),
        state.dual_pool().clickhouse().clone(),
        state.dual_pool().table_names(),
        ai,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
    use nanosiem_core::auth::TokenClaims;
    use uuid::Uuid;

    fn holding(scopes: &[&str]) -> AuthContext {
        AuthContext::from_jwt(TokenClaims {
            iss: DEFAULT_TOKEN_ISSUER.to_string(),
            aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
            sub: Uuid::now_v7(),
            roles: vec!["Admin".to_string()],
            permissions: scopes.iter().map(|s| (*s).to_string()).collect(),
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    /// The point of the narrow scope: a key minted to write one profile must be
    /// able to write it WITHOUT also being able to archive the hunt library.
    /// If this ever needs `hunts:manage` added to pass, the scope has stopped
    /// being narrower than the thing it was split out of.
    #[test]
    fn the_narrow_scope_alone_admits_a_recon_write() {
        assert!(ensure_recon_write(&holding(&[permissions::HUNTS_PROFILE_WRITE])).is_ok());
    }

    /// Nothing that worked before this scope existed may stop working. Every
    /// principal and every key holding `hunts:manage` still reaches recon.
    #[test]
    fn the_broad_scope_still_admits_a_recon_write() {
        assert!(ensure_recon_write(&holding(&[permissions::HUNTS_MANAGE])).is_ok());
    }

    /// And the adjacent hunt scopes do not. `hunts:view` is held by any custom
    /// role a tenant points at the bench; `hunts:report` is minted into every
    /// unattended sweep key, which must not be able to rewrite the profile its
    /// successors plan against.
    #[test]
    fn no_adjacent_hunt_scope_reaches_a_recon_write() {
        for scope in [
            permissions::HUNTS_VIEW,
            permissions::HUNTS_RUN,
            permissions::HUNTS_TRIAGE,
            permissions::HUNTS_REPORT,
        ] {
            let error = ensure_recon_write(&holding(&[scope])).expect_err(&format!(
                "{scope} must not reach a recon write"
            ));
            // Names both acceptable scopes: a caller told only about the narrow
            // one cannot tell whether the broad one would also have worked.
            let message = format!("{error:?}");
            assert!(message.contains("hunts:profile_write"), "{message}");
            assert!(message.contains("hunts:manage"), "{message}");
        }
        assert!(ensure_recon_write(&holding(&[])).is_err());
    }

    /// A permission the catalogue does not list cannot be granted through any
    /// path — `role_permissions` is FK'd to `permissions(id)` and NAN-2121's
    /// hold-to-grant rule reads the same table. An unlisted scope is an
    /// unusable endpoint, which is the bug 9000059 had to be written to fix.
    #[test]
    fn the_recon_write_scope_is_in_the_permission_catalogue() {
        assert!(
            nanosiem_core::auth::permissions::ALL_PERMISSIONS
                .contains(&permissions::HUNTS_PROFILE_WRITE),
            "hunts:profile_write must be in ALL_PERMISSIONS or it can never be minted"
        );
    }
}
