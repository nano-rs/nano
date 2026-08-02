// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — Active Hunter API.
//!
//! # The permission split, and why it is not `playbooks:*`
//!
//! A hunt DEFINITION is a `playbooks` row of `kind = 'hunt'`, but the two kinds
//! have different audiences and very different blast radii. `playbooks:manage`
//! is authority over case-response procedure a human steps through;
//! `hunts:manage` is authority over what an autonomous agent runs unattended
//! against the whole log estate on a schedule. Reusing one permission for both
//! would mean anyone who could write a runbook could also aim an agent.
//!
//! * `hunts:view` — the bench, sweeps, the recon profile.
//! * `hunts:manage` — author, edit, archive.
//! * `hunts:run` — enable a schedule, trigger a sweep. Deliberately separate
//!   from `manage`: writing a hunt and putting it on a cron are different
//!   decisions, and [`UpdateHuntRequest::touches_schedule`] is what stops a
//!   metadata PATCH smuggling the second past the first.
//! * `hunts:triage` — promote a lead to a case, dismiss it into a suppression.
//! * `hunts:report` — the ONLY scope minted into an unattended sweep key. It
//!   reaches sweep claim / heartbeat / report and nothing else. It is
//!   deliberately held by no human role (migration 9000054), because it exists
//!   to be intersected into a short-lived key rather than assigned to a session.
//!
//! # Provenance
//!
//! Every read handler passes the caller's [`ArtifactScope`] down to the
//! repository, which applies it in SQL. Nothing is filtered in the handler:
//! post-filtering leaves the page size as an oracle for how many rows exist.

mod ideas;
mod knowledge;
mod leads;
mod recon;
mod runners;
mod specs;
mod sweeps;
pub mod types;

pub use ideas::*;
pub use knowledge::*;
pub use leads::*;
pub use recon::*;
pub use runners::*;
pub use specs::*;
pub use sweeps::*;
pub use types::*;

use std::sync::Arc;

use nanosiem_core::auth::ArtifactScope;
use nanosiem_core::hunts::{ClickHouseEvidenceResolver, HuntRepository, HuntService};

use crate::middleware::AuthContext;
use crate::state::AppState;

/// Build the service for one request.
///
/// The ClickHouse client behind the resolver is a cheap clone of a pooled HTTP
/// client, so this matches the per-request construction the playbooks and
/// tuning handlers already use rather than adding another field to `AppState`.
pub(crate) fn service(state: &AppState) -> HuntService {
    HuntService::new(
        HuntRepository::new(state.pool.clone()),
        Arc::new(ClickHouseEvidenceResolver::new(state.dual_pool())),
    )
}

/// The caller's DERIVED-ARTIFACT scope (NAN-2219).
///
/// `from_scope` reads the artifact half, not the row-filter half. The two
/// differ by the `audit:view` gate, which must not make an otherwise-unscoped
/// analyst "restricted" against provenance gates — that is what made an earlier
/// feature hide every artifact from every non-admin on tenants with no source
/// scoping configured at all.
pub(crate) fn artifact_scope(auth: &AuthContext) -> ArtifactScope {
    ArtifactScope::from_scope(&auth.effective_viewer_scope())
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        // Rail
        hunts_summary,
        // Definitions
        list_hunts,
        create_hunt,
        get_hunt,
        update_hunt,
        archive_hunt,
        trigger_sweep,
        list_hunt_sweeps,
        toggle_hunt,
        set_hunt_schedule,
        // Runners
        list_runners,
        register_runner,
        runner_heartbeat,
        claim_sweep,
        grant_runner_agy_waiver,
        revoke_runner_agy_waiver,
        // Sweeps
        get_sweep,
        report_sweep,
        // Leads + triage
        list_leads,
        get_lead,
        promote_lead,
        dismiss_lead,
        list_suppressions,
        record_suppression,
        revoke_suppression,
        // Knowledge (NAN-2239)
        list_knowledge,
        record_knowledge,
        revoke_knowledge,
        // Recon + rule ideas
        get_latest_profile,
        run_recon_profile,
        recon_census,
        recon_surface,
        save_recon_profile,
        create_hunt_drafts,
        list_rule_ideas,
        send_rule_idea,
        reject_rule_idea,
    ),
    components(schemas(
        ListHuntsResponse,
        ListRunnersResponse,
        ListSweepsResponse,
        ListLeadsResponse,
        ListHuntSuppressionsResponse,
        ListRuleIdeasResponse,
        ListKnowledgeResponse,
        ClaimSweepOutcome,
        ProfileResponse,
        nanosiem_core::hunts::Hunt,
        nanosiem_core::hunts::HuntBudget,
        nanosiem_core::hunts::HuntSummary,
        nanosiem_core::hunts::ToggleHuntRequest,
        nanosiem_core::hunts::SetScheduleRequest,
        nanosiem_core::hunts::CreateHuntRequest,
        nanosiem_core::hunts::UpdateHuntRequest,
        nanosiem_core::hunts::HuntRunner,
        nanosiem_core::hunts::RegisterRunnerRequest,
        nanosiem_core::hunts::HuntSweep,
        nanosiem_core::hunts::ClaimedSweep,
        nanosiem_core::hunts::ClaimSweepRequest,
        nanosiem_core::hunts::SubmitSweepReportRequest,
        nanosiem_core::hunts::SweepReportAccepted,
        nanosiem_core::hunts::SweepReport,
        nanosiem_core::hunts::LeadCandidate,
        nanosiem_core::hunts::TrailStep,
        nanosiem_core::hunts::HuntLead,
        nanosiem_core::hunts::HuntLeadEvidence,
        nanosiem_core::hunts::HuntLeadDetail,
        nanosiem_core::hunts::HuntLeadProvenance,
        nanosiem_core::hunts::Contribution,
        nanosiem_core::hunts::PromoteLeadRequest,
        nanosiem_core::hunts::PromoteLeadResponse,
        nanosiem_core::hunts::DismissLeadRequest,
        nanosiem_core::hunts::DismissLeadResponse,
        nanosiem_core::hunts::SuppressionWidth,
        nanosiem_core::hunts::HuntSuppression,
        leads::RecordSuppressionRequest,
        nanosiem_core::hunts::HuntKnowledge,
        nanosiem_core::hunts::KnowledgeCategoryCount,
        nanosiem_core::hunts::RecordKnowledgeRequest,
        nanosiem_core::hunts::RecordKnowledgeResponse,
        nanosiem_core::hunts::RecordOutcome,
        nanosiem_core::hunts::RevokeKnowledgeRequest,
        nanosiem_core::hunts::HuntProfile,
        // Recon output. The three JSONB columns on `hunt_profiles` are opaque
        // `Value` on the model, so these are registered to document the shapes
        // the Profile screen actually parses out of them.
        nanosiem_core::hunts::recon::ReconRunSummary,
        nanosiem_core::hunts::recon::CensusRow,
        nanosiem_core::hunts::recon::FieldPopulation,
        nanosiem_core::hunts::recon::ReporterFraction,
        nanosiem_core::hunts::recon::SourceHealth,
        nanosiem_core::hunts::recon::HistoryBasis,
        nanosiem_core::hunts::recon::HuntableSurface,
        nanosiem_core::hunts::recon::SurfaceTactic,
        nanosiem_core::hunts::recon::SurfaceTechnique,
        nanosiem_core::hunts::recon::TechniqueState,
        nanosiem_core::hunts::recon::OrgFingerprint,
        nanosiem_core::hunts::recon::FingerprintAuthor,
        nanosiem_core::hunts::recon::FingerprintAggregates,
        nanosiem_core::hunts::recon::DimensionAggregate,
        // The agent-driven primitives. Registered as concrete types rather than
        // as opaque JSON so an MCP tool generated from this spec knows the
        // census it copies from `profile/census` into `profile` is the same
        // shape at both ends.
        nanosiem_core::hunts::recon::CensusReport,
        nanosiem_core::hunts::recon::SurfaceReport,
        // The bounded default shape of `profile/surface` (NAN-2243). Registered
        // beside the full one because a generated client has to know that the
        // response is one of two things and which field says which.
        nanosiem_core::hunts::recon::SurfaceResponse,
        nanosiem_core::hunts::recon::SurfaceSummaryReport,
        nanosiem_core::hunts::recon::SurfaceSummary,
        nanosiem_core::hunts::recon::SurfaceGap,
        nanosiem_core::hunts::recon::MissingSourceCount,
        nanosiem_core::hunts::recon::SurfaceDetail,
        nanosiem_core::hunts::recon::SaveProfileRequest,
        nanosiem_core::hunts::recon::ProfileFingerprint,
        nanosiem_core::hunts::recon::ActorWeight,
        nanosiem_core::hunts::recon::CreateDraftsRequest,
        nanosiem_core::hunts::recon::GeneratedDraft,
        nanosiem_core::hunts::recon::DraftBatchOutcome,
        nanosiem_core::hunts::recon::DraftOutcome,
        nanosiem_core::hunts::HuntRuleIdea,
        nanosiem_core::hunts::HuntRuleIdeaBasisCounts,
        nanosiem_core::hunts::SendRuleIdeaRequest,
        nanosiem_core::hunts::RejectRuleIdeaRequest,
        nanosiem_core::hunts::RuleIdeaDecision,
    ))
)]
pub struct HuntsApiDoc;

#[cfg(test)]
mod tests {
    use axum::routing::{delete, get, patch, post};
    use axum::Router;

    /// Every hunts path, in the same shapes `routes.rs` registers them.
    ///
    /// Kept as data so the router assertions below read as a list of routes
    /// rather than as a wall of builder calls.
    const HUNT_PATHS: &[(&str, &str)] = &[
        ("GET", "/api/hunts/summary"),
        ("GET", "/api/hunts"),
        ("POST", "/api/hunts"),
        ("GET", "/api/hunts/runners"),
        ("POST", "/api/hunts/runners"),
        ("POST", "/api/hunts/runners/{id}/heartbeat"),
        ("POST", "/api/hunts/runners/{id}/claim"),
        ("POST", "/api/hunts/runners/{id}/agy-waiver"),
        ("DELETE", "/api/hunts/runners/{id}/agy-waiver"),
        ("GET", "/api/hunts/sweeps/{id}"),
        ("POST", "/api/hunts/sweeps/{id}/report"),
        ("GET", "/api/hunts/leads"),
        ("GET", "/api/hunts/leads/{id}"),
        ("POST", "/api/hunts/leads/{id}/promote"),
        ("POST", "/api/hunts/leads/{id}/dismiss"),
        ("GET", "/api/hunts/knowledge"),
        ("POST", "/api/hunts/knowledge"),
        ("POST", "/api/hunts/knowledge/{id}/revoke"),
        ("GET", "/api/hunts/suppressions"),
        ("DELETE", "/api/hunts/suppressions/{id}"),
        ("GET", "/api/hunts/profile"),
        ("POST", "/api/hunts/profile"),
        ("POST", "/api/hunts/profile/census"),
        ("POST", "/api/hunts/profile/surface"),
        ("POST", "/api/hunts/profile/run"),
        ("POST", "/api/hunts/drafts"),
        ("GET", "/api/hunts/rule-ideas"),
        ("POST", "/api/hunts/rule-ideas/{id}/send"),
        ("POST", "/api/hunts/rule-ideas/{id}/reject"),
        ("GET", "/api/hunts/{id}"),
        ("PATCH", "/api/hunts/{id}"),
        ("DELETE", "/api/hunts/{id}"),
        ("GET", "/api/hunts/{id}/sweeps"),
        ("POST", "/api/hunts/{id}/sweeps"),
        ("POST", "/api/hunts/{id}/toggle"),
    ];

    /// The static collections (`runners`, `sweeps`, `leads`, `profile`,
    /// `suppressions`, `rule-ideas`, `summary`) sit at the same position as the
    /// `{id}` parameter, and several have children of their own. axum resolves
    /// that by giving a static segment priority, but a genuine conflict is a
    /// PANIC at router construction — i.e. the API does not boot at all, with no
    /// compiler error and no test to catch it.
    ///
    /// Building the same shapes here turns that boot failure into a test
    /// failure. It is not a formality: this route set is the first in the
    /// codebase to nest a parameter segment under BOTH `/{id}/…` and
    /// `/<static>/{id}/…` in the same subtree.
    #[test]
    fn the_hunt_routes_do_not_conflict_with_each_other() {
        let mut router: Router<()> = Router::new();
        for (method, path) in HUNT_PATHS {
            let handler = match *method {
                "GET" => get(|| async {}),
                "POST" => post(|| async {}),
                "PATCH" => patch(|| async {}),
                "DELETE" => delete(|| async {}),
                other => panic!("unhandled method {other}"),
            };
            router = router.route(path, handler);
        }
        // Consuming the router is what forces the route table to be built.
        let _ = router.into_service::<axum::body::Body>();
    }

    /// A regression guard for the path-count floor in `openapi.rs`: if a route
    /// is added here without the floor moving, the count assertion is a lower
    /// bound that has quietly stopped bounding anything.
    #[test]
    fn every_registered_hunt_path_template_is_counted_once() {
        let mut templates: Vec<&str> = HUNT_PATHS.iter().map(|(_, path)| *path).collect();
        templates.sort_unstable();
        templates.dedup();
        assert_eq!(
            templates.len(),
            27,
            "the hunts route set changed; update min_paths in openapi.rs to match"
        );
    }
}
