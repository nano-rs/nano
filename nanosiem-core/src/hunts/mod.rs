// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — Active Hunter: autonomous scheduled threat hunting.
//!
//! A **hunt** is proactive and case-less: it sweeps on a schedule, produces
//! scored **leads**, and — once a lead shape has recurred and been promoted
//! enough times — proposes a detection rule. It is the sibling of a response
//! playbook, not a variant of one.
//!
//! # Where the boundary sits
//!
//! Hunts and response playbooks **share the definition layer** and **split at
//! runtime**. A hunt is a `playbooks` row of `kind = 'hunt'` extended by
//! `hunt_specs`, so it inherits repository sync, versioning, review cadence and
//! the ACL for free. It does *not* share `playbook_runs`, whose `case_id` is
//! NOT NULL by construction: a hunt has no case and may never produce one.
//! Merging the runtimes would leave a table whose operator/TTR/outcome columns
//! are permanently NULL for half its rows.
//!
//! The database enforces the split — `playbooks_id_kind_key` plus constant-kind
//! composite FKs — and [`crate::playbooks::repository`] enforces the other
//! direction by scoping every one of its queries to `kind = 'response'`.
//!
//! # What the agent may and may not do
//!
//! The hunter runs on the analyst's own coding CLI (`claude` / `codex` / `agy`)
//! with a minted, short-lived key carrying exactly one write scope:
//! `hunts:report`. Inside a sweep it is deliberately **free** — it may open
//! with a raw query, pivot repeatedly, abandon its hypothesis, and follow a
//! thread into a source type its definition never mentioned. It is bounded by
//! *budget* (turns, tool calls, rows, wall-clock), not by prescribed method,
//! because constraining the shape of an investigation turns hunting back into a
//! saved search.
//!
//! That freedom is affordable only because the output contract is narrow. The
//! agent submits evidence identifiers and a narrative. It never submits:
//!
//! * a **score** — [`scoring`] computes it from facts the server measured;
//! * a **fingerprint** — [`fingerprint`] derives it from identifiers, never
//!   from prose the agent wrote;
//! * a **provenance manifest** — the server accumulates it from what the sweep
//!   actually read;
//! * a **suppression** — only analyst triage writes those, because an agent
//!   able to suppress could blind its own successors.
//!
//! # Provenance
//!
//! Leads, profiles, suppressions and rule ideas are DERIVED artifacts carrying
//! entity values lifted out of matched events. They use the shared
//! [`crate::auth::artifact_provenance`] contract established by NAN-2137:
//! producers stamp a [`SourceProvenance`](crate::auth::SourceProvenance) that
//! is monotonic toward failure, and every read applies
//! [`ArtifactScope`](crate::auth::ArtifactScope) so a reader denied a source
//! cannot recover its contents through a narrative.

//! # How a hunt gets here
//!
//! Hunts are authored in git and reach the product through the same repository
//! sync/import pipeline as response playbooks — [`spec`] turns a file's
//! frontmatter into the hunt-only configuration, [`repository`] writes it.
//! Both are built around one rule: **a synced hunt lands disabled.** Merge
//! access to a content repository must not become a way to start an
//! unattended process against production telemetry, so `schedule:` is a
//! *suggested cadence* that import records and a human applies.
//!
//! # What the agent may and may not do
//!
//! The hunter runs on the analyst's own coding CLI (`claude` / `codex` / `agy`)
//! with a minted, short-lived key carrying exactly one write scope:
//! `hunts:report`. Inside a sweep it is deliberately **free** — it may open
//! with a raw query, pivot repeatedly, abandon its hypothesis, and follow a
//! thread into a source type its definition never mentioned. It is bounded by
//! *budget* (turns, tool calls, rows, wall-clock), not by prescribed method,
//! because constraining the shape of an investigation turns hunting back into a
//! saved search.
//!
//! That freedom is affordable only because the output contract is narrow. The
//! agent submits evidence identifiers and a narrative. It never submits:
//!
//! * a **score** — [`scoring`] computes it from facts the server measured;
//! * a **fingerprint** — [`fingerprint`] derives it from identifiers, never
//!   from prose the agent wrote;
//! * a **provenance manifest** — the server accumulates it from what the sweep
//!   actually read;
//! * a **suppression** — only analyst triage writes those, because an agent
//!   able to suppress could blind its own successors.
//!
//! # Provenance
//!
//! Leads, profiles, suppressions and rule ideas are DERIVED artifacts carrying
//! entity values lifted out of matched events. They use the shared
//! [`crate::auth::artifact_provenance`] contract established by NAN-2137:
//! producers stamp a [`SourceProvenance`](crate::auth::SourceProvenance) that
//! is monotonic toward failure, and every read applies
//! [`ArtifactScope`](crate::auth::ArtifactScope) so a reader denied a source
//! cannot recover its contents through a narrative.

pub mod error;
pub mod evidence;
pub mod fingerprint;
pub mod knowledge;
pub mod models;
pub mod recon;
pub mod report;
pub mod repository;
pub mod scheduler;
pub mod scoring;
pub mod service;
pub mod spec;

pub use error::HuntError;
pub use evidence::{
    ClickHouseEvidenceResolver, EvidenceResolver, ResolvedEvent, ResolvedEvidence,
};
pub use fingerprint::{
    derive as derive_fingerprint, CanonicalEntity, FingerprintInput, ValidatedSignal,
};
// NAN-2239. Knowledge is exported alongside the rest of the hunt runtime but is
// deliberately NOT reachable from `HuntService`: the type that records a memory
// must have no method that can hide a finding. See `hunts::knowledge`.
pub use knowledge::{
    clamp_ttl_days, normalize_category, normalize_evidence_refs, normalize_fact,
    normalize_subject, sanitize_confidence, HuntKnowledge, KnowledgeCategoryCount, KnowledgeRepository,
    ListKnowledgeQuery, RecordKnowledgeRequest, RecordKnowledgeResponse, RecordOutcome,
    RevokeKnowledgeRequest, MAX_CATEGORY_CHARS, MAX_CATEGORY_ROLLUP, MAX_EVIDENCE_REFS, MAX_FACT_CHARS,
    MAX_REVOKE_REASON_CHARS, MAX_SUBJECT_CHARS, MAX_TTL_DAYS,
};
pub use models::*;
pub use recon::{
    build_census, build_surface, draft_for_gap, sanitize_draft, sanitize_profile_request,
    ActorWeight, CensusInputs, CensusReport, CensusRow, CreateDraftsRequest, DraftBatchOutcome,
    DraftOutcome, FieldPopulation, FingerprintAggregates, FingerprintAuthor, GeneratedDraft,
    HuntableSurface, OrgFingerprint, ProfileFingerprint, ProfileSubmission, ReconRunSummary,
    ReconService, ReporterFraction, SaveProfileRequest, SourceHealth, SurfaceReport, SurfaceTactic,
    SurfaceTechnique, TacticRef, TechniqueRef, TechniqueState,
};
pub use report::{
    reconcile_outcome, BudgetLimits, BudgetUsage, LeadCandidate, SweepReport, TrailStep,
};
pub use spec::HuntSpecDraft;
pub use repository::{CommitInputs, HuntRepository, PreparedLead, RuleIdeaVerdict, SummaryCounts};
pub use scheduler::{
    plan_slots, sweep_window, HuntScheduler, HuntSchedulerConfig, HuntSchedulerTick, SlotIssue,
    SlotPlan, SlotTrigger, SweepWindow,
};
pub use scoring::{score, Contribution, Score, ScoreInputs};
pub use service::HuntService;
