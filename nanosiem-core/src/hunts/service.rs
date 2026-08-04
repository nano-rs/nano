// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — the hunt service.
//!
//! This is where the narrow report contract is turned into facts. Everything
//! load-bearing happens here or below it, and none of it is reachable from the
//! wire type:
//!
//! ```text
//!   SweepReport ─► resolve evidence (server reads ClickHouse)
//!               ─► corroborate the claimed entity against what was READ
//!               ─► validate signals against the server's known set
//!               ─► accumulate provenance from what resolved
//!               ─► measure prevalence / prior history
//!               ─► [repository tx: reassert fence, derive fingerprint,
//!                   measure suppression + recurrence, score, persist]
//! ```
//!
//! # Why a candidate is dropped rather than the report
//!
//! A sweep that produced ten candidates, one of which names an entity that
//! appears in none of its evidence, has still done nine useful things. Rejecting
//! the whole report would mean one hallucinated entity discards a sweep's work
//! and — worse — that the failure is invisible, because the runner just sees a
//! 400. So bad candidates are counted into
//! [`SweepReportAccepted::candidates_rejected`] and the rest are committed. A
//! sweep whose candidates are ALL being rejected shows up as a run that reported
//! ten and created none, which is the signal an operator actually needs.

use std::collections::BTreeSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::auth::{ArtifactScope, ScopeSet};
use crate::hunts::capabilities::{
    evaluate_readiness, normalize_capability, normalize_requirements, readiness_candidates,
};
use crate::hunts::error::HuntError;
use crate::hunts::evidence::{EvidenceResolver, ResolvedEvidence};
use crate::hunts::fingerprint::{CanonicalEntity, ValidatedSignal};
use crate::hunts::knowledge::{
    clamp_ttl_days, normalize_category, normalize_evidence_refs, normalize_fact, normalize_subject,
    sanitize_confidence, KnowledgeCandidate, PreparedKnowledge,
};
use crate::hunts::models::*;
use crate::hunts::report::{BudgetUsage, LeadCandidate, SweepReport};
use crate::hunts::repository::{CommitInputs, HuntRepository, PreparedLead, RuleIdeaVerdict};

/// Entity types `hunt_leads_entity_type_check` accepts.
///
/// Checked in the service so an unknown type rejects ONE candidate with a
/// countable reason, instead of the constraint rejecting the whole transaction
/// and losing every good lead beside it.
const ALLOWED_ENTITY_TYPES: &[&str] = &[
    "ip", "user", "host", "domain", "hash", "process", "url", "email", "file",
];

/// Hard ceiling on candidates per report. The report is attacker-influenceable
/// through the model's context; without this, one sweep could enqueue an
/// unbounded number of ClickHouse round trips.
pub const MAX_CANDIDATES_PER_REPORT: usize = 50;

/// Hard ceiling on durable facts accepted from one sweep. Each fact may require
/// a ClickHouse evidence lookup, so this is both a storage and cross-database
/// work bound on attacker-influenceable model output.
pub const MAX_KNOWLEDGE_PER_REPORT: usize = 50;

#[derive(Clone)]
pub struct HuntService {
    repo: HuntRepository,
    resolver: Arc<dyn EvidenceResolver>,
}

impl HuntService {
    pub fn new(repo: HuntRepository, resolver: Arc<dyn EvidenceResolver>) -> Self {
        Self { repo, resolver }
    }

    pub fn repository(&self) -> &HuntRepository {
        &self.repo
    }

    // =========================================================================
    // Definitions / runners — thin pass-throughs, authorization lives in the
    // handler and provenance filtering in the repository.
    // =========================================================================

    pub async fn list_hunts(
        &self,
        enabled_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Hunt>, HuntError> {
        let hunts = self.repo.list_hunts(enabled_only, limit, offset).await?;
        self.hydrate_telemetry_readiness(hunts).await
    }

    pub async fn get_hunt(&self, playbook_id: Uuid) -> Result<Hunt, HuntError> {
        let hunt = self.repo.get_hunt(playbook_id).await?;
        self.hydrate_one_hunt(hunt).await
    }

    pub async fn create_hunt(
        &self,
        req: &CreateHuntRequest,
        created_by: Option<Uuid>,
    ) -> Result<Hunt, HuntError> {
        let mut normalized = req.clone();
        normalized.telemetry =
            normalize_requirements(&req.telemetry).map_err(HuntError::Validation)?;
        let hunt = self.repo.create_hunt(&normalized, created_by).await?;
        self.hydrate_one_hunt(hunt).await
    }

    pub async fn update_hunt(
        &self,
        playbook_id: Uuid,
        req: &UpdateHuntRequest,
    ) -> Result<Hunt, HuntError> {
        let mut normalized = req.clone();
        normalized.telemetry = req
            .telemetry
            .as_ref()
            .map(normalize_requirements)
            .transpose()
            .map_err(HuntError::Validation)?;
        let hunt = self.repo.update_hunt(playbook_id, &normalized).await?;
        self.hydrate_one_hunt(hunt).await
    }

    pub async fn archive_hunt(&self, playbook_id: Uuid) -> Result<(), HuntError> {
        self.repo.archive_hunt(playbook_id).await
    }

    pub async fn list_source_capability_bindings(
        &self,
    ) -> Result<Vec<SourceCapabilityBinding>, HuntError> {
        self.repo.list_source_capability_bindings().await
    }

    pub async fn set_source_capability_binding(
        &self,
        request: &SetSourceCapabilityBindingRequest,
        updated_by: Option<Uuid>,
    ) -> Result<SourceCapabilityBinding, HuntError> {
        let source_type = normalize_source_identity(&request.source_type)?;
        let capability =
            normalize_capability(&request.capability).map_err(HuntError::Validation)?;
        let state = request.state.trim().to_ascii_lowercase();
        if !matches!(state.as_str(), "mapped" | "ignored") {
            return Err(HuntError::Validation(
                "binding state must be `mapped` or `ignored`".into(),
            ));
        }
        self.repo
            .set_source_capability_binding(&source_type, &capability, &state, updated_by)
            .await
    }

    pub async fn reset_source_capability_binding(
        &self,
        request: &ResetSourceCapabilityBindingRequest,
    ) -> Result<bool, HuntError> {
        let source_type = normalize_source_identity(&request.source_type)?;
        let capability =
            normalize_capability(&request.capability).map_err(HuntError::Validation)?;
        self.repo
            .reset_source_capability_binding(&source_type, &capability)
            .await
    }

    async fn hydrate_one_hunt(&self, hunt: Hunt) -> Result<Hunt, HuntError> {
        self.hydrate_telemetry_readiness(vec![hunt])
            .await?
            .pop()
            .ok_or_else(|| HuntError::Internal("telemetry hydration lost a hunt".into()))
    }

    /// Resolve all rows with one binding read and one source-health probe. A
    /// 500-hunt library must not perform 500 ClickHouse round trips merely to
    /// draw its readiness chips.
    async fn hydrate_telemetry_readiness(
        &self,
        mut hunts: Vec<Hunt>,
    ) -> Result<Vec<Hunt>, HuntError> {
        if hunts.is_empty() {
            return Ok(hunts);
        }
        let bindings = self.repo.list_source_capability_bindings().await?;
        let candidates: Vec<String> = hunts
            .iter()
            .flat_map(|hunt| {
                readiness_candidates(&hunt.telemetry, &hunt.required_source_types, &bindings)
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let evaluated_at = Utc::now();
        let silent: BTreeSet<String> = if candidates.is_empty() {
            BTreeSet::new()
        } else {
            self.resolver
                .silent_source_types(&candidates, evaluated_at - Duration::hours(24))
                .await?
                .into_iter()
                .map(|source| source.trim().to_ascii_lowercase())
                .collect()
        };
        for hunt in &mut hunts {
            let hunt_candidates: BTreeSet<String> =
                readiness_candidates(&hunt.telemetry, &hunt.required_source_types, &bindings)
                    .into_iter()
                    .collect();
            let hunt_silent: BTreeSet<String> =
                silent.intersection(&hunt_candidates).cloned().collect();
            hunt.telemetry_readiness = Some(evaluate_readiness(
                &hunt.telemetry,
                &hunt.required_source_types,
                &bindings,
                &hunt_silent,
                evaluated_at,
            ));
        }
        Ok(hunts)
    }

    pub async fn list_runners(&self) -> Result<Vec<HuntRunner>, HuntError> {
        self.repo.list_runners().await
    }

    pub async fn register_runner(
        &self,
        req: &RegisterRunnerRequest,
        registered_by: Option<Uuid>,
    ) -> Result<HuntRunner, HuntError> {
        self.repo.register_runner(req, registered_by).await
    }

    pub async fn heartbeat_runner(&self, runner_id: Uuid) -> Result<HuntRunner, HuntError> {
        self.repo.heartbeat_runner(runner_id).await
    }

    /// Grant or withdraw a runner's Antigravity sweep waiver (NAN-2264).
    pub async fn set_runner_agy_waiver(
        &self,
        runner_id: Uuid,
        granted: bool,
        actor: Option<Uuid>,
    ) -> Result<HuntRunner, HuntError> {
        self.repo
            .set_runner_agy_waiver(runner_id, granted, actor)
            .await
    }

    // =========================================================================
    // Sweeps
    // =========================================================================

    /// Trigger a manual sweep over the hunt's own lookback window.
    ///
    /// The window is computed from `hunt_specs.lookback_window` — a
    /// server-owned value — rather than accepted from the caller. A
    /// caller-supplied window would let a `hunts:run` holder aim an autonomous
    /// agent at an arbitrary slice of history, which is a different authority
    /// from "run this hunt".
    pub async fn trigger_manual_sweep(&self, playbook_id: Uuid) -> Result<HuntSweep, HuntError> {
        let hunt = self.repo.get_hunt(playbook_id).await?;
        let window_end = Utc::now();
        let window_start = window_end - parse_lookback(&hunt.lookback_window);
        self.repo
            .enqueue_manual_sweep(playbook_id, window_start, window_end)
            .await
    }

    pub async fn claim_sweep(
        &self,
        runner_id: Uuid,
        lease_seconds: Option<i64>,
    ) -> Result<Option<ClaimedSweep>, HuntError> {
        // Skip a bounded batch of held work so one dead source does not block
        // every healthy hunt queued behind it. Each skipped row is FINISHED as
        // held under its lease fence before the next candidate is considered.
        const MAX_HELD_PER_CLAIM: usize = 64;
        for _ in 0..MAX_HELD_PER_CLAIM {
            let Some(mut claimed) = self.repo.claim_next_sweep(runner_id, lease_seconds).await?
            else {
                return Ok(None);
            };

            let readiness = self.hydrate_one_hunt(claimed.hunt.clone()).await;
            match readiness {
                Ok(hunt)
                    if hunt
                        .telemetry_readiness
                        .as_ref()
                        .is_some_and(|state| state.ready) =>
                {
                    claimed.hunt = hunt;
                    return Ok(Some(claimed));
                }
                Ok(hunt) => {
                    let detail = hunt
                        .telemetry_readiness
                        .as_ref()
                        .map(|state| state.blocking_reasons.join("; "))
                        .filter(|detail| !detail.is_empty())
                        .unwrap_or_else(|| "telemetry readiness could not be established".into());
                    self.repo
                        .complete_held_sweep(
                            claimed.sweep.id,
                            runner_id,
                            claimed.runner_fence,
                            &detail,
                        )
                        .await?;
                }
                Err(error) => {
                    // Fail closed and close the lease honestly. Returning the
                    // error here would strand the claimed row until expiry;
                    // running anyway would turn an unavailable health probe
                    // into an implicit permission to under-report.
                    self.repo
                        .complete_held_sweep(
                            claimed.sweep.id,
                            runner_id,
                            claimed.runner_fence,
                            &format!("telemetry readiness probe failed: {error}"),
                        )
                        .await?;
                }
            }
        }
        Ok(None)
    }

    pub async fn list_sweeps(
        &self,
        query: &ListSweepsQuery,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntSweep>, HuntError> {
        self.repo.list_sweeps(query, scope).await
    }

    pub async fn get_sweep(
        &self,
        sweep_id: Uuid,
        scope: &ArtifactScope,
    ) -> Result<HuntSweep, HuntError> {
        self.repo.get_sweep(sweep_id, scope).await
    }

    /// Turn a sweep report into scored leads.
    ///
    /// `scope` is the SWEEP PRINCIPAL's live-data scope, used when reading
    /// evidence out of ClickHouse. It is not the later reader's authorization —
    /// each lead is re-evaluated against whoever reads it, against the manifest
    /// this call stamps.
    pub async fn submit_sweep_report(
        &self,
        sweep_id: Uuid,
        runner_id: Uuid,
        runner_fence: i64,
        usage: BudgetUsage,
        report: SweepReport,
        scope: &ScopeSet,
    ) -> Result<SweepReportAccepted, HuntError> {
        // Preflight: cheap rejection of a stale runner BEFORE we spend a
        // ClickHouse round trip per candidate on work that cannot be committed.
        // Not authoritative — the fence reassertion inside the commit
        // transaction is.
        let context = self
            .repo
            .sweep_report_context(sweep_id, runner_id, runner_fence)
            .await?;

        let known_signals = self.repo.known_signals().await?;
        let window_start = context
            .window_start
            .unwrap_or_else(|| Utc::now() - Duration::days(1));
        let window_end = context.window_end.unwrap_or_else(Utc::now);

        let mut prepared = Vec::new();
        let mut rejected = 0usize;

        for candidate in report.candidates.iter().take(MAX_CANDIDATES_PER_REPORT) {
            match self
                .prepare_candidate(candidate, &known_signals, window_start, window_end, scope)
                .await?
            {
                Some(lead) => prepared.push(lead),
                None => rejected += 1,
            }
        }
        // Anything past the cap is a refusal, not an omission, and must be
        // counted so a sweep spraying candidates is visible.
        rejected += report
            .candidates
            .len()
            .saturating_sub(MAX_CANDIDATES_PER_REPORT);

        let mut knowledge = Vec::new();
        let mut knowledge_rejected = 0usize;
        for candidate in report.knowledge.iter().take(MAX_KNOWLEDGE_PER_REPORT) {
            match self.prepare_knowledge(candidate, scope).await? {
                Some(fact) => knowledge.push(fact),
                None => knowledge_rejected += 1,
            }
        }
        knowledge_rejected += report
            .knowledge
            .len()
            .saturating_sub(MAX_KNOWLEDGE_PER_REPORT);

        self.repo
            .commit_sweep_report(CommitInputs {
                sweep_id,
                runner_id,
                runner_fence,
                usage,
                trail: report.trail,
                claimed_outcome: report.claimed_outcome,
                note: report.note,
                leads: prepared,
                rejected,
                knowledge,
                knowledge_rejected,
            })
            .await
    }

    /// Normalize one durable fact and derive its evidence/provenance.
    ///
    /// Invalid agent claims reject only that fact, just as an uncorroborated
    /// entity rejects only one lead. Resolver failures still fail the report:
    /// persisting a fact with invented provenance would be worse than retrying
    /// the sweep commit.
    async fn prepare_knowledge(
        &self,
        candidate: &KnowledgeCandidate,
        scope: &ScopeSet,
    ) -> Result<Option<PreparedKnowledge>, HuntError> {
        let Ok(category) = normalize_category(&candidate.category) else {
            return Ok(None);
        };
        let Ok(subject) = normalize_subject(&candidate.subject) else {
            return Ok(None);
        };
        let Ok(fact) = normalize_fact(&candidate.fact) else {
            return Ok(None);
        };
        let Ok(confidence) = sanitize_confidence(candidate.confidence) else {
            return Ok(None);
        };
        let evidence_event_ids = normalize_evidence_refs(&candidate.evidence_event_ids);
        let ttl_days = clamp_ttl_days(candidate.ttl_days);
        let resolved = self.resolver.resolve(&evidence_event_ids, scope).await?;
        let provenance = resolved.provenance();
        let stored_refs = resolved
            .events
            .iter()
            .map(|event| event.canonical_event_id.clone())
            .collect();

        Ok(Some(PreparedKnowledge {
            category,
            subject,
            fact,
            confidence,
            evidence_event_ids: stored_refs,
            ttl_days,
            provenance,
        }))
    }

    /// Resolve one candidate into something the repository can persist, or
    /// `None` if the server declines to believe it.
    ///
    /// Three ways a candidate is refused, all of them silent-by-design failures
    /// if they were not checked:
    ///
    /// 1. **Unknown entity type** — would violate `hunt_leads_entity_type_check`
    ///    and abort the whole transaction, taking every good lead with it.
    /// 2. **Uncorroborated entity** — the agent named something that appears in
    ///    none of the evidence it attached. Either a hallucination or an attempt
    ///    to aim a lead at a fingerprint of its choosing; both get the same
    ///    answer.
    /// 3. **Nothing readable behind it** — every cited event resolved to
    ///    nothing the sweep principal could read. A lead with no evidence has a
    ///    narrative and no way to check it.
    async fn prepare_candidate(
        &self,
        candidate: &LeadCandidate,
        known_signals: &BTreeSet<String>,
        window_start: chrono::DateTime<Utc>,
        window_end: chrono::DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<Option<PreparedLead>, HuntError> {
        let entity_type = candidate.entity_type.trim().to_lowercase();
        if !ALLOWED_ENTITY_TYPES.contains(&entity_type.as_str()) {
            return Ok(None);
        }

        let resolved: ResolvedEvidence = self
            .resolver
            .resolve(&candidate.evidence_event_ids, scope)
            .await?;
        if resolved.events.is_empty() {
            return Ok(None);
        }

        // `resolve`, NOT `trusted`. `trusted` skips corroboration and exists for
        // server-originated entities (recon, backfills); reaching for it here
        // would let the agent choose its own fingerprint input, which is the
        // whole attack the corroboration check closes.
        let Some(entity) = CanonicalEntity::resolve(
            &entity_type,
            &candidate.entity_value,
            &resolved.observed_entities,
        ) else {
            return Ok(None);
        };

        // Unrecognised signals are DROPPED, not rejected. Rejecting the
        // candidate would let one junk signal remove a finding; dropping means a
        // suppressed lead resubmitted with a nonce still hashes the same.
        let signals: Vec<ValidatedSignal> = candidate
            .signals
            .iter()
            .filter_map(|s| ValidatedSignal::validate(s, known_signals))
            .collect();

        let prevalence = self
            .resolver
            .asset_prevalence(
                entity.entity_type(),
                entity.value(),
                window_start,
                window_end,
                scope,
            )
            .await?;
        let first_seen_in_window = !self
            .resolver
            .had_prior_history(entity.entity_type(), entity.value(), window_start, scope)
            .await?;

        // Keep only the events that actually mention the corroborated entity.
        //
        // Corroboration proves the entity appears SOMEWHERE in the batch; it
        // does not make every event in the batch evidence FOR it. Without this
        // filter the agent picks the batch, and the batch drives
        // `evidence_count`, `distinct_source_types` and the provenance manifest
        // — so attaching twenty unrelated but readable events from three source
        // types manufactures cross-source corroboration, which is the single
        // heaviest term in the score. That is the same defeat as the fingerprint
        // nonce: excluding the literal field is worthless while the agent still
        // chooses the inputs.
        //
        // It also tightens provenance. Stamping the manifest from unrelated
        // events marks a lead as derived from sources it never actually drew on,
        // which over-restricts honest readers and muddies the audit trail.
        // Completeness is read BEFORE the events are consumed: an unresolvable
        // cited id already made the batch incomplete, and filtering to the
        // corroborating subset must not launder that away.
        let batch_complete = resolved.provenance().is_complete();
        let corroborating: Vec<_> = resolved
            .events
            .into_iter()
            .filter(|event| {
                event.entities.iter().any(|(found_type, found_value)| {
                    found_type.trim().eq_ignore_ascii_case(entity.entity_type())
                        && CanonicalEntity::trusted(entity.entity_type(), found_value)
                            .is_some_and(|c| c.value() == entity.value())
                })
            })
            .collect();

        // Every candidate reaches here with a corroborated entity, so an empty
        // result means the extractor and the corroboration set disagree — fail
        // the candidate rather than emit a lead with no evidence behind it.
        if corroborating.is_empty() {
            return Ok(None);
        }

        let provenance = crate::auth::SourceProvenance::from_parts(
            corroborating.iter().map(|e| e.source_type.clone()),
            batch_complete,
        );

        Ok(Some(PreparedLead {
            provenance,
            evidence: corroborating,
            entity,
            signals,
            mitre_technique: candidate
                .mitre_technique
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(str::to_string),
            narrative: candidate.narrative.clone(),
            prevalence,
            first_seen_in_window,
        }))
    }

    // =========================================================================
    // Leads / triage
    // =========================================================================

    pub async fn list_leads(
        &self,
        query: &ListLeadsQuery,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntLead>, HuntError> {
        self.repo.list_leads(query, scope).await
    }

    /// The filter-matched total behind a page of leads — same filters, same
    /// scope, no page window.
    pub async fn count_leads(
        &self,
        query: &ListLeadsQuery,
        scope: &ArtifactScope,
    ) -> Result<i64, HuntError> {
        self.repo.count_leads(query, scope).await
    }

    pub async fn get_lead(
        &self,
        lead_id: Uuid,
        scope: &ArtifactScope,
    ) -> Result<HuntLeadDetail, HuntError> {
        self.repo.get_lead(lead_id, scope).await
    }

    pub async fn promote_lead(
        &self,
        lead_id: Uuid,
        req: &PromoteLeadRequest,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<PromoteLeadResponse, HuntError> {
        self.repo.promote_lead(lead_id, req, actor, scope).await
    }

    pub async fn dismiss_lead(
        &self,
        lead_id: Uuid,
        req: &DismissLeadRequest,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<DismissLeadResponse, HuntError> {
        self.repo.dismiss_lead(lead_id, req, actor, scope).await
    }

    pub async fn list_suppressions(
        &self,
        include_revoked: bool,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntSuppression>, HuntError> {
        self.repo.list_suppressions(include_revoked, scope).await
    }

    /// Author a suppression from a sweep (NAN-2240).
    ///
    /// A thin pass-through ON PURPOSE. Every bound that makes this safe —
    /// literal `'agent'` origin, clamped mandatory expiry, no broad forms, and
    /// the requirement that the fingerprint belong to a lead this sweep filed —
    /// lives in the repository, in the statement itself. Re-implementing any of
    /// it here would create a second place to get it right and a first place to
    /// get it wrong.
    pub async fn record_agent_suppression(
        &self,
        sweep_id: Uuid,
        entity_type: &str,
        entity_value: &str,
        reason: &str,
        ttl_days: i64,
    ) -> Result<Option<HuntSuppression>, HuntError> {
        self.repo
            .record_agent_suppression(sweep_id, entity_type, entity_value, reason, ttl_days)
            .await
    }

    pub async fn revoke_suppression(
        &self,
        suppression_id: Uuid,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<bool, HuntError> {
        self.repo
            .revoke_suppression(suppression_id, actor, scope)
            .await
    }

    pub async fn latest_profile(
        &self,
        scope: &ArtifactScope,
    ) -> Result<Option<HuntProfile>, HuntError> {
        self.repo.latest_profile(scope).await
    }

    pub async fn list_rule_ideas(
        &self,
        playbook_id: Option<Uuid>,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntRuleIdea>, HuntError> {
        self.repo.list_rule_ideas(playbook_id, scope).await
    }

    /// Ship or reject a rule idea. The gate is re-derived from the basis rows
    /// inside the same transaction — see
    /// [`HuntRepository::decide_rule_idea`].
    pub async fn decide_rule_idea(
        &self,
        idea_id: Uuid,
        decision: RuleIdeaVerdict,
        note: Option<&str>,
        scope: &ArtifactScope,
    ) -> Result<RuleIdeaDecision, HuntError> {
        self.repo
            .decide_rule_idea(idea_id, decision, note, scope)
            .await
    }

    /// Enable or disable a hunt's schedule.
    ///
    /// Its own method so the one write that decides what runs unattended is not
    /// buried inside a generic patch. `hunts:run` gates the handler.
    pub async fn set_hunt_enabled(
        &self,
        playbook_id: Uuid,
        enabled: bool,
    ) -> Result<Hunt, HuntError> {
        let hunt = self
            .repo
            .update_hunt(
                playbook_id,
                &UpdateHuntRequest {
                    enabled: Some(enabled),
                    ..Default::default()
                },
            )
            .await?;
        self.hydrate_one_hunt(hunt).await
    }

    /// Set or clear a hunt's cadence. `None` is manual-only, not "unchanged".
    pub async fn set_hunt_schedule(
        &self,
        playbook_id: Uuid,
        schedule_cron: Option<&str>,
        schedule_timezone: Option<&str>,
    ) -> Result<Hunt, HuntError> {
        let hunt = self
            .repo
            .set_hunt_schedule(playbook_id, schedule_cron, schedule_timezone)
            .await?;
        self.hydrate_one_hunt(hunt).await
    }

    /// Compose the rail summary.
    ///
    /// Three sources, deliberately: Postgres counts, the latest recon profile
    /// (itself provenance-gated), and a log-store health probe for the sources
    /// enabled hunts actually require. Everything the UI needs to distinguish
    /// "nothing found" from "nothing ran" from "we could not look".
    pub async fn summary(&self, scope: &ArtifactScope) -> Result<HuntSummary, HuntError> {
        let counts = self.repo.summary_counts(scope).await?;
        let profile = self.repo.latest_profile(scope).await?;

        let enabled_hunts = self.list_hunts(true, 10_000, 0).await?;
        let blocked_hunts = enabled_hunts
            .iter()
            .filter(|hunt| {
                hunt.telemetry_readiness
                    .as_ref()
                    .is_some_and(|readiness| !readiness.ready)
            })
            .count() as i64;
        let mut unhealthy_source_types = BTreeSet::new();
        let mut unresolved_capabilities = BTreeSet::new();
        for readiness in enabled_hunts
            .iter()
            .filter_map(|hunt| hunt.telemetry_readiness.as_ref())
        {
            let silent: BTreeSet<&str> = readiness
                .silent_source_types
                .iter()
                .map(String::as_str)
                .collect();
            unhealthy_source_types.extend(
                readiness
                    .required_source_types
                    .iter()
                    .filter(|source| silent.contains(source.as_str()))
                    .cloned(),
            );
            unhealthy_source_types.extend(
                readiness
                    .all_of
                    .iter()
                    .filter(|resolution| !resolution.satisfied)
                    .flat_map(|resolution| resolution.source_types.iter())
                    .filter(|source| silent.contains(source.as_str()))
                    .cloned(),
            );
            unresolved_capabilities.extend(
                readiness
                    .all_of
                    .iter()
                    .filter(|resolution| !resolution.satisfied)
                    .map(|resolution| resolution.capability.clone()),
            );
            if !readiness.one_of.is_empty()
                && !readiness
                    .one_of
                    .iter()
                    .any(|resolution| resolution.satisfied)
            {
                unresolved_capabilities.extend(
                    readiness
                        .one_of
                        .iter()
                        .map(|resolution| resolution.capability.clone()),
                );
                unhealthy_source_types.extend(
                    readiness
                        .one_of
                        .iter()
                        .flat_map(|resolution| resolution.source_types.iter())
                        .filter(|source| silent.contains(source.as_str()))
                        .cloned(),
                );
            }
        }

        let (hunt_gaps, blind_techniques) = profile
            .as_ref()
            .map(|p| count_surface(&p.huntable_surface))
            .unwrap_or((0, 0));

        Ok(HuntSummary {
            open_leads: counts.open_leads,
            hunts_total: counts.hunts_total,
            hunts_enabled: counts.hunts_enabled,
            sweeps_24h: counts.sweeps_24h,
            never_swept: counts.never_swept,
            rule_idea_candidates: counts.rule_idea_candidates,
            last_recon_at: profile.as_ref().map(|p| p.created_at),
            recon_degraded: profile.as_ref().is_some_and(|p| p.degraded),
            recon_degraded_detail: profile.as_ref().and_then(|p| p.degraded_detail.clone()),
            unhealthy_source_types: unhealthy_source_types.into_iter().collect(),
            blocked_hunts,
            unresolved_capabilities: unresolved_capabilities.into_iter().collect(),
            hunt_gaps,
            blind_techniques,
        })
    }
}

fn normalize_source_identity(raw: &str) -> Result<String, HuntError> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 255
        || normalized.chars().any(|character| character.is_control())
    {
        return Err(HuntError::Validation(
            "source_type must be 1-255 printable characters".into(),
        ));
    }
    Ok(normalized)
}

/// Count `gap` and `blind` techniques in a recon profile's huntable surface.
///
/// The surface is an OBJECT mapping a technique id to `covered` | `gap` |
/// `blind`, which is the shape migration 9000054 documents. Anything else
/// counts as zero rather than being guessed at: a rail badge that invents a
/// number from a shape it does not recognise is worse than one that shows none.
pub(crate) fn count_surface(surface: &serde_json::Value) -> (i64, i64) {
    let mut gaps = 0;
    let mut blind = 0;
    let mut tally = |status: &str| match status.trim().to_ascii_lowercase().as_str() {
        "gap" => gaps += 1,
        "blind" => blind += 1,
        _ => {}
    };

    // Canonical shape: tactic columns, each holding its techniques. This is what
    // the Profile screen renders — a 12-column matrix keyed to TELEMETRY rather
    // than to rules, answering "could we even look" as distinct from "do we
    // have a rule". Counting it here rather than storing separate totals keeps
    // the badge and the matrix from disagreeing, which is the failure mode
    // where a rail says 22 gaps and the page draws 25.
    if let Some(tactics) = surface.get("tactics").and_then(|t| t.as_array()) {
        for technique in tactics
            .iter()
            .filter_map(|tactic| tactic.get("techniques").and_then(|t| t.as_array()))
            .flatten()
        {
            if let Some(status) = technique.get("state").and_then(|s| s.as_str()) {
                tally(status);
            }
        }
        return (gaps, blind);
    }

    // Flat `technique_id -> state` map. Retained because it is the obvious shape
    // for a backfill or an external producer to emit, and silently counting zero
    // for it would show an empty rail beside a populated page.
    if let Some(map) = surface.as_object() {
        for status in map.values().filter_map(|v| v.as_str()) {
            tally(status);
        }
    }
    (gaps, blind)
}

/// Parse a `hunt_specs.lookback_window` value (`24h`, `7d`, `90m`).
///
/// Falls back to 24 hours rather than erroring: a malformed lookback should not
/// make a hunt permanently unrunnable, and 24h is the schema default so the
/// fallback matches what an operator who never set one would get.
pub fn parse_lookback(raw: &str) -> Duration {
    let trimmed = raw.trim();
    let (digits, unit) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(trimmed.len()),
    );
    let value: i64 = digits.parse().unwrap_or(0);
    if value <= 0 {
        return Duration::hours(24);
    }
    // Clamped: a hunt configured with `3650d` would open with a decade-wide
    // window, which is neither a hunt nor survivable.
    let duration = match unit.trim().to_ascii_lowercase().as_str() {
        "m" | "min" | "minutes" => Duration::minutes(value),
        "h" | "hr" | "hours" => Duration::hours(value),
        "d" | "days" => Duration::days(value),
        "w" | "weeks" => Duration::weeks(value),
        _ => Duration::hours(24),
    };
    duration.clamp(Duration::minutes(1), Duration::days(90))
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod service_tests;
