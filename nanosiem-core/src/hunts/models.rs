// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — wire and row types for the hunt runtime.
//!
//! # Why the read types carry their provenance columns
//!
//! Every derived artifact here ([`HuntLead`], [`HuntSuppression`],
//! [`HuntProfile`], [`HuntRuleIdea`], and [`HuntSweep`] for its trail) exposes
//! `source_types` / `source_types_complete` on the read model rather than
//! stripping them at the repository boundary. The SQL predicate
//! ([`crate::auth::ArtifactScope::sql_predicate`]) is the enforcement point, but
//! keeping the manifest visible on the type means a reviewer looking at a
//! response body can see whether an artifact is attributed at all — and a
//! caller that hand-builds a query without the predicate has the fields right
//! there to classify with [`crate::auth::ArtifactScope::allows`] instead of
//! silently returning an unattributed row.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::typeid;

// =============================================================================
// hunt_specs
// =============================================================================

/// A hunt: the `playbooks` row of `kind = 'hunt'` joined to its `hunt_specs`
/// extension. The two are always read together — a hunt spec without its
/// playbook has no title and no status, and a hunt playbook without its spec
/// cannot be swept.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Hunt {
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    /// Serialised as `id`.
    ///
    /// A hunt IS a `playbooks` row, so `playbook_id` is the honest column name
    /// — but it is this object's own identity on the wire, and every consumer
    /// keys rows by `id`. Renaming here rather than in each consumer keeps the
    /// database vocabulary accurate without exporting an internal join detail
    /// as public API.
    #[serde(rename = "id")]
    pub playbook_id: Uuid,
    /// Serialised as `name`. `title` is the shared `playbooks` column; a hunt
    /// is named, not titled.
    #[serde(rename = "name")]
    pub title: String,
    /// Serialised as `description`.
    #[serde(rename = "description")]
    pub subtitle: Option<String>,
    pub category: String,
    pub status: String,
    pub tags: Vec<String>,

    /// The nPL the sweep OPENS with. A starting point the agent may abandon.
    /// The hunt's markdown body — its HYPOTHESIS, not its query.
    ///
    /// Detail-only: populated by `get_hunt` and left `None` by `list_hunts`, so
    /// a 500-hunt library does not carry 500 markdown documents. Skipped from
    /// serialization when absent rather than sent as null, so "the list did not
    /// ask for this" and "this hunt has no doc" stay distinguishable.
    ///
    /// This was stored and never read back: `HUNT_SELECT` projected no `p.doc`,
    /// so every hunt reached the detail view with an undefined doc and rendered
    /// the "No doc — the nPL is the whole definition" fallback. A hunt IS its
    /// hypothesis; a hunt reduced to its opening query is a saved search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc: Option<String>,
    /// The cached step tree the playbook parser produces from `doc`. Detail-only
    /// for the same reason. `None` on a hunt whose body was never parsed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<serde_json::Value>)]
    pub steps: Option<serde_json::Value>,
    pub sweep_query: String,
    pub schedule_cron: Option<String>,
    pub schedule_timezone: String,
    pub required_source_types: Vec<String>,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub enabled: bool,

    pub budget_max_turns: i32,
    pub budget_max_tool_calls: i32,
    pub budget_max_rows: i32,
    pub budget_max_wall_seconds: i32,

    pub lookback_window: String,
    pub max_catchup_lookback: String,

    /// Observed schedule state. Rendered as `last_success` / `next_due` /
    /// `overdue` — never as a claim that the cadence was kept, because the
    /// runner is a workstation that may have been asleep.
    pub next_due_slot: Option<DateTime<Utc>>,
    pub coalesced_through_slot: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,

    pub auto_promote_threshold: Option<f64>,
    pub auto_promote: bool,
    pub generated_from_profile: bool,
    pub generated_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The budget block as it appears in hunt frontmatter.
///
/// Budget, not method. The agent is free to choose its own path — go raw on the
/// first query, pivot repeatedly, chase an undeclared source — and is bounded
/// only by total spend. Constraining the SHAPE of the investigation would turn
/// hunting back into a saved search.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct HuntBudget {
    #[serde(default)]
    pub max_turns: Option<i32>,
    #[serde(default)]
    pub max_tool_calls: Option<i32>,
    #[serde(default)]
    pub max_rows: Option<i32>,
    #[serde(default)]
    pub max_wall_seconds: Option<i32>,
}

/// Create a hunt. Writes both the `playbooks` row (`kind='hunt'`) and the
/// `hunt_specs` extension in one transaction.
///
/// # There is no `enabled` field, and that is the point
///
/// Frontmatter carries a `schedule`, and a repository import is a draft path.
/// Nothing here can set `hunt_specs.enabled`: a hunt is created disabled and
/// only `hunts:run` — through the toggle — can start it. A `schedule` is a
/// SUGGESTED cadence, so importing content that suggests one must never be the
/// act that puts an autonomous agent on production telemetry.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateHuntRequest {
    pub title: String,
    #[serde(default)]
    pub subtitle: Option<String>,
    /// Reuses the `playbooks_category_check` value set.
    pub category: String,
    /// Markdown describing the hypothesis. Stored in `playbooks.doc`.
    pub doc: String,
    #[serde(default)]
    pub tags: Vec<String>,

    pub sweep_query: String,
    /// SUGGESTED cadence. `schedule` is the frontmatter spelling.
    #[serde(default, alias = "schedule")]
    pub schedule_cron: Option<String>,
    #[serde(default, alias = "timezone")]
    pub schedule_timezone: Option<String>,
    #[serde(default)]
    pub required_source_types: Vec<String>,
    #[serde(default)]
    pub mitre_tactic: Option<String>,
    #[serde(default)]
    pub mitre_technique: Option<String>,

    /// Frontmatter's nested budget block. Takes precedence over the flat
    /// fields below, which exist for callers that patch one dimension.
    #[serde(default)]
    pub budget: Option<HuntBudget>,
    #[serde(default)]
    pub budget_max_turns: Option<i32>,
    #[serde(default)]
    pub budget_max_tool_calls: Option<i32>,
    #[serde(default)]
    pub budget_max_rows: Option<i32>,
    #[serde(default)]
    pub budget_max_wall_seconds: Option<i32>,
    #[serde(default)]
    pub lookback_window: Option<String>,
    #[serde(default)]
    pub max_catchup_lookback: Option<String>,
}

impl CreateHuntRequest {
    /// Resolve the budget, nested block winning over the flat fields.
    pub fn budget_values(&self) -> HuntBudget {
        let nested = self.budget.clone().unwrap_or_default();
        HuntBudget {
            max_turns: nested.max_turns.or(self.budget_max_turns),
            max_tool_calls: nested.max_tool_calls.or(self.budget_max_tool_calls),
            max_rows: nested.max_rows.or(self.budget_max_rows),
            max_wall_seconds: nested.max_wall_seconds.or(self.budget_max_wall_seconds),
        }
    }
}

/// Patch a hunt. Absent fields are left alone.
///
/// `enabled` and `schedule_cron` are called out in the handler because putting
/// a hunt on a cron against production telemetry needs `hunts:run`, not merely
/// `hunts:manage` — authoring and scheduling are different decisions.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct UpdateHuntRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub subtitle: Option<String>,
    #[serde(default)]
    pub doc: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub sweep_query: Option<String>,
    #[serde(default, alias = "schedule")]
    pub schedule_cron: Option<String>,
    #[serde(default, alias = "timezone")]
    pub schedule_timezone: Option<String>,
    #[serde(default)]
    pub required_source_types: Option<Vec<String>>,
    #[serde(default)]
    pub mitre_tactic: Option<String>,
    #[serde(default)]
    pub mitre_technique: Option<String>,
    /// Present only so an existing integration that PATCHes `enabled` keeps
    /// working; the handler routes any request carrying it through the same
    /// `hunts:run` gate as the toggle. New callers should use the toggle, which
    /// makes the authority being exercised obvious at the call site.
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub budget: Option<HuntBudget>,
    #[serde(default)]
    pub budget_max_turns: Option<i32>,
    #[serde(default)]
    pub budget_max_tool_calls: Option<i32>,
    #[serde(default)]
    pub budget_max_rows: Option<i32>,
    #[serde(default)]
    pub budget_max_wall_seconds: Option<i32>,
    #[serde(default)]
    pub lookback_window: Option<String>,
    #[serde(default)]
    pub max_catchup_lookback: Option<String>,
}

impl UpdateHuntRequest {
    /// Resolve the budget, nested block winning over the flat fields.
    pub fn budget_values(&self) -> HuntBudget {
        let nested = self.budget.clone().unwrap_or_default();
        HuntBudget {
            max_turns: nested.max_turns.or(self.budget_max_turns),
            max_tool_calls: nested.max_tool_calls.or(self.budget_max_tool_calls),
            max_rows: nested.max_rows.or(self.budget_max_rows),
            max_wall_seconds: nested.max_wall_seconds.or(self.budget_max_wall_seconds),
        }
    }

    /// Whether this patch changes anything that decides what runs unattended.
    ///
    /// Enabling a hunt, or changing when it fires, is a `hunts:run` decision.
    /// Bundling either into an otherwise innocuous metadata PATCH must not be a
    /// way around that, so the handler asks the request rather than eyeballing
    /// the field list at the call site.
    pub fn touches_schedule(&self) -> bool {
        self.enabled.is_some() || self.schedule_cron.is_some() || self.schedule_timezone.is_some()
    }
}

// =============================================================================
// hunt_runners
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntRunner {
    #[serde(with = "typeid::hunt_runner")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub label: String,
    pub hostname: Option<String>,
    pub agent_tool: Option<String>,
    pub agent_model: Option<String>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub registered_by: Option<Uuid>,
    /// Monotonic fence. A lease is valid only while it matches, so a runner
    /// that wakes from a long sleep cannot report for reassigned work.
    pub fence_token: i64,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    // ── The Antigravity sweep waiver (NAN-2264) ──────────────────────────────
    /// Whether this machine may currently run unattended sweeps on `agy`.
    ///
    /// DERIVED from the two timestamps rather than stored, so "granted, then
    /// revoked, then granted again" cannot disagree with itself. See
    /// [`agy_waiver_in_force`].
    pub agy_waiver_granted: bool,
    pub agy_waiver_granted_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub agy_waiver_granted_by: Option<Uuid>,
    /// When the waiver was last withdrawn. Kept after a re-grant: the ledger of
    /// a security decision that was taken back once is worth more than a tidy
    /// NULL, and the audit log is keyed to the same events.
    pub agy_waiver_revoked_at: Option<DateTime<Utc>>,
}

/// Whether an Antigravity sweep waiver is in force, from its two timestamps.
///
/// A grant AFTER the last revocation wins, so the pair can be re-armed without
/// erasing that it was once withdrawn. A row with neither timestamp has never
/// been waived, which is the safe default and the one every existing runner
/// gets when the columns are added.
pub fn agy_waiver_in_force(
    granted_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
) -> bool {
    match (granted_at, revoked_at) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(granted), Some(revoked)) => granted > revoked,
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RegisterRunnerRequest {
    pub label: String,
    #[serde(default)]
    pub hostname: Option<String>,
    /// `claude` | `codex` | `agy` — which coding CLI drives the sweep.
    #[serde(default)]
    pub agent_tool: Option<String>,
    #[serde(default)]
    pub agent_model: Option<String>,
}

// =============================================================================
// hunt_sweeps
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntSweep {
    #[serde(with = "typeid::hunt_sweep")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub playbook_version: i32,
    /// Present for `schedule` / `catchup`, absent for `manual` — the
    /// `hunt_sweeps_slot_matches_trigger` CHECK makes that exact.
    pub schedule_slot: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::hunt_runner::opt")]
    #[schema(value_type = Option<String>)]
    pub runner_id: Option<Uuid>,
    pub runner_fence: Option<i64>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub trigger: String,
    pub status: String,
    pub outcome: Option<String>,
    pub outcome_detail: Option<String>,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub turns_used: i32,
    pub tool_calls_used: i32,
    pub rows_read: i32,
    /// TRUE when a read hit a cap. Surfaced as "read 400 of 12,000 matching":
    /// a silent truncation reads as "that's all there was", which is a lie.
    pub rows_truncated: bool,
    /// How many leads this sweep filed — `COUNT(*)` over `hunt_leads`, computed
    /// at read time rather than stored, so a cascade delete or an analyst
    /// action can never leave a stale counter behind. `#[serde(default)]` is
    /// for DESERIALIZING an older server's JSON only; every query in the
    /// repository selects the count, so a serialized sweep always carries it
    /// (NAN-2243 — the ledger rendered `undefined leads` off this absence).
    #[serde(default)]
    pub leads_produced: i64,
    pub trail: serde_json::Value,
    pub query_sha: Option<String>,
    pub source_types: Vec<String>,
    pub source_types_complete: bool,
    pub created_at: DateTime<Utc>,
    /// TRUE when `trail` / `outcome_detail` were blanked for this reader. The
    /// UI must SAY so — a silently emptied trail reads as "the sweep did
    /// nothing", which is a different and wrong statement.
    #[serde(default)]
    pub redacted: bool,
}

impl HuntSweep {
    /// Blank the agent-authored halves of a sweep for a reader whose source
    /// scope the sweep's manifest cannot satisfy.
    ///
    /// # Why redact instead of hiding the row
    ///
    /// A sweep's `trail` is the ordered nPL the agent ran and `outcome_detail`
    /// is its free-text note; both are downstream of matched events and can
    /// carry values from a source the reader is denied. But the FACT that a
    /// sweep ran, when, and how it ended is scheduler state, not derived
    /// content — hiding the row would make "9 hunts swept in the last 24h" read
    /// as zero for every source-scoped analyst and turn a working feature into
    /// an apparently broken one.
    ///
    /// The manifest is accumulated from evidence the sweep CITED, which is
    /// necessarily a subset of what it read, so a sweep is never stamped
    /// complete and a restricted reader is always redacted. That is the
    /// conservative direction and it is deliberate: an under-reporting manifest
    /// that claimed completeness is precisely the leak the contract exists to
    /// prevent.
    pub fn redact_unattributed(&mut self, scope: &crate::auth::ArtifactScope) {
        if scope.allows(&self.source_types, self.source_types_complete) {
            return;
        }
        self.trail = serde_json::Value::Array(Vec::new());
        self.outcome_detail = None;
        self.query_sha = None;
        self.redacted = true;
    }
}

/// What a runner receives when it successfully claims a sweep.
///
/// `runner_fence` is echoed back on the report so the commit path can reassert
/// the same generation of work under lock. It is NOT a secret — the fence's
/// job is to detect staleness, not to authorize; authorization is the
/// `hunts:report` scope on the sweep key.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClaimedSweep {
    pub sweep: HuntSweep,
    pub hunt: Hunt,
    pub runner_fence: i64,
    pub lease_expires_at: DateTime<Utc>,
}

/// The runner identifies itself in the PATH, not the body — a body-supplied
/// identity is one copy-paste away from a runner claiming on another's behalf,
/// and the path form makes the subject of the request visible in the access log.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct ClaimSweepRequest {
    /// How long the runner is asking to hold the sweep. Clamped server-side —
    /// a runner that asks for a 30-day lease would make failover impossible,
    /// because reclaim only reassigns a sweep whose lease has EXPIRED.
    #[serde(default)]
    pub lease_seconds: Option<i64>,
}

/// A sweep result. The agent-authored half is [`crate::hunts::SweepReport`];
/// everything else here is measured by the RUNNER (a process the tenant
/// controls) rather than claimed by the model inside it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SubmitSweepReportRequest {
    #[schema(value_type = String)]
    pub runner_id: String,
    /// The fence issued at claim time. Reasserted under lock.
    pub runner_fence: i64,

    /// Observed spend. There is no honest cost figure to record — the sweep
    /// runs on the analyst's own subscription — so duration/turns/tool calls
    /// are what we report.
    #[serde(default)]
    pub turns_used: u32,
    #[serde(default)]
    pub tool_calls_used: u32,
    #[serde(default)]
    pub rows_read: u64,
    #[serde(default)]
    pub wall_seconds: u64,

    /// The narrow shape the agent is allowed to report: evidence ids,
    /// narratives, durable fact claims, and the trail. No score, no
    /// fingerprint, no manifest, no suppression — there is deliberately
    /// nowhere to put them.
    ///
    /// A NAMED field rather than a flattened one, so the boundary between the
    /// runner's measurements and the model's claims is visible in the wire
    /// format and in the generated docs. Someone reading a captured request
    /// should be able to see at a glance which half came from where.
    pub report: super::report::SweepReport,
}

/// What the server decided, returned to the runner so a sweep's log shows the
/// same numbers the bench does.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SweepReportAccepted {
    #[serde(with = "typeid::hunt_sweep")]
    #[schema(value_type = String)]
    pub sweep_id: Uuid,
    /// Reconciled against measured budget consumption, not taken on trust.
    pub outcome: String,
    pub leads_created: usize,
    /// Candidates the server refused: an entity that appeared in no resolved
    /// evidence, an unknown entity type, or evidence that resolved to nothing
    /// the sweep's principal could read. Surfaced rather than silently dropped.
    pub candidates_rejected: usize,
    pub evidence_attached: usize,
    /// Durable facts learned or reconfirmed in the report transaction.
    pub knowledge_recorded: usize,
    /// Malformed, over-limit, or analyst-revoked facts that were not recorded.
    pub knowledge_rejected: usize,
}

// =============================================================================
// hunt_leads
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntLead {
    #[serde(with = "typeid::hunt_lead")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::hunt_sweep")]
    #[schema(value_type = String)]
    pub sweep_id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub playbook_version: i32,
    /// Denormalized hunt title so the bench does not need a second round trip.
    pub hunt_title: Option<String>,

    pub entity_type: String,
    pub entity_value: String,
    /// What the agent actually FOUND — deliberately not inherited from the
    /// hunt definition.
    pub mitre_technique: Option<String>,

    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,

    /// Untrusted, attacker-influenceable prose. Size-capped by
    /// `hunt_leads_narrative_bounded`; render containment-first.
    pub narrative: Option<String>,

    /// Server-computed. The agent has no field to propose one.
    pub score: f64,
    /// The signed per-factor breakdown behind `score`. An opaque 0.86 is not
    /// reviewable; this is what lets the bench answer "why 0.86".
    pub score_contributions: serde_json::Value,
    pub fingerprint: String,

    pub state: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::case::opt")]
    #[schema(value_type = Option<String>)]
    pub promoted_case_id: Option<Uuid>,

    pub source_types: Vec<String>,
    pub source_types_complete: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntLeadEvidence {
    #[serde(with = "typeid::hunt_lead_evidence")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::hunt_lead")]
    #[schema(value_type = String)]
    pub lead_id: Uuid,
    pub event_timestamp: DateTime<Utc>,
    pub source_type: String,
    /// Pointer into ClickHouse. The body deliberately stays there so retention
    /// and ACL are not duplicated into Postgres.
    pub event_ref: serde_json::Value,
    pub canonical_event_id: String,
    pub summary: Option<String>,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

/// Who computes a lead's score. There is exactly one honest value: the score
/// is derived server-side ([`crate::hunts::scoring`]) from facts the server
/// measured, and the agent has no field to propose one. The bench renders this
/// verbatim — "scored by server, not the agent" — so it is a wire constant,
/// not a display string the client invents.
pub const LEAD_SCORED_BY: &str = "server";

/// Where a lead came from — the sweep/query provenance that makes it shareable
/// by link rather than a screenshot. Every field mirrors the desktop's
/// `WireLeadProvenance` exactly; do not add fields the bench does not render.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HuntLeadProvenance {
    /// The sweep that filed this lead.
    #[serde(with = "typeid::hunt_sweep")]
    #[schema(value_type = String)]
    pub sweep_id: Uuid,
    /// When that sweep finished — the moment the lead was committed. Scheduler
    /// state, so it is never redacted (the FACT that a sweep ran is not
    /// derived content; see [`HuntSweep::redact_unattributed`]).
    pub swept_at: Option<DateTime<Utc>>,
    /// SHA of the sweep query that ran. Withheld (`None`) for a reader whose
    /// source scope the SWEEP's manifest cannot satisfy — the same rule the
    /// sweep ledger applies, because the lead's own manifest may be narrower
    /// than the sweep's.
    pub query_sha: Option<String>,
    /// The hunt version the sweep executed.
    pub playbook_version: i32,
    /// Always [`LEAD_SCORED_BY`]. Rendered verbatim so the bench states who
    /// scored the lead.
    pub scored_by: String,
}

/// A lead plus everything the bench's expanded view renders: the raw-event
/// pointers, the signed score breakdown, and the sweep provenance.
///
/// # The wire shape is the desktop's `WireLeadDetail`, field for field
///
/// `lead` is NESTED, not flattened. An earlier shape `#[serde(flatten)]`ed the
/// lead, which meant the serialized body had no `lead` key at all — the
/// desktop reads `detail.lead.score`, `detail.contributions.map(…)` and
/// `detail.provenance` unguarded, and every one of those arrived `undefined`
/// and threw out of render, unmounting the window. TypeScript does not
/// validate at runtime, so the only defence is that this struct serializes
/// exactly the keys the client declares: `lead`, `evidence`, `contributions`,
/// `provenance`. The wire-contract test in `models_tests.rs` pins that set.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HuntLeadDetail {
    pub lead: HuntLead,
    pub evidence: Vec<HuntLeadEvidence>,
    /// The flat `{factor, value, detail}` breakdown behind `lead.score`,
    /// including zero-valued factors — "−0.00 no suppression matched" is worth
    /// rendering precisely because its absence looks like the check never ran.
    /// Derived from the (already redacted) `score_contributions` column; the
    /// per-factor basis stays out of this list because the bench does not read
    /// it.
    pub contributions: Vec<crate::hunts::scoring::Contribution>,
    pub provenance: HuntLeadProvenance,
}

/// Promote a lead into a case. Analyst-confirmed in v1 — `hunt_specs` carries a
/// `hunt_specs_no_auto_promote_v1` CHECK that makes the automatic path
/// unrepresentable until scores have been calibrated against real outcomes.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct PromoteLeadRequest {
    /// Overrides the derived title. The derived one names the hunt and the
    /// entity; it deliberately does NOT embed the narrative, which is
    /// attacker-influenceable prose.
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PromoteLeadResponse {
    #[serde(with = "typeid::hunt_lead")]
    #[schema(value_type = String)]
    pub lead_id: Uuid,
    #[serde(with = "typeid::case")]
    #[schema(value_type = String)]
    pub case_id: Uuid,
    pub case_number: i32,
    /// True when the lead was already promoted and this call returned the
    /// existing case rather than creating a second one.
    pub already_promoted: bool,
}

/// How wide a dismissal's memory reaches.
///
/// Maps onto the nullable `hunt_suppressions.playbook_id`, which is why that
/// column is nullable: a shape can be noise for ONE hunt (a hunt looking for
/// service-account logons will always surface the backup account) or noise
/// everywhere (a scanner the whole estate sees).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionWidth {
    /// This shape, for this hunt only. The default, because it is the narrow
    /// one — a dismissal should not silently blind every other hunt.
    #[default]
    Hunt,
    /// This shape, across every hunt.
    Tenant,
}

/// Dismiss a lead.
///
/// # Dismissal ALWAYS writes a suppression
///
/// There is deliberately no "dismiss without remembering" option. Per-machine
/// dismissal memory is worthless: if one analyst kills a lead and another sees
/// it again tomorrow, the bench fills with the same rejects daily and the
/// feature is abandoned in week three. The analyst chooses how WIDE the memory
/// is and how long it lasts — never whether there is any.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct DismissLeadRequest {
    /// Why. Required — an unexplained suppression is indistinguishable from a
    /// mistake six months later, and this is the text a future analyst reads
    /// when deciding whether it still applies.
    pub reason: String,
    #[serde(default)]
    pub width: SuppressionWidth,
    /// Bound a broad suppression so it cannot become permanent by accident.
    /// `None` means indefinite, which the UI must render as such.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

/// A dismissal, with the suppression it wrote.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DismissLeadResponse {
    pub lead: HuntLead,
    pub suppression: HuntSuppression,
}

/// Enable or disable a hunt's schedule. `hunts:run`.
///
/// Its own endpoint rather than a PATCH field so the authority being exercised
/// is obvious at the call site — and so no import, draft or metadata path can
/// reach it by accident.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ToggleHuntRequest {
    pub enabled: bool,
}

/// Set or clear a hunt's cadence.
///
/// `schedule_cron: null` means MANUAL ONLY — a real value, not "unchanged".
/// That distinction is the whole reason this is not a `PATCH` field: on
/// `UpdateHuntRequest` every column is `COALESCE`d, so null there means "leave
/// it alone" and manual-only is inexpressible.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SetScheduleRequest {
    #[serde(default)]
    pub schedule_cron: Option<String>,
    /// Left unchanged when absent — a timezone is a property of the hunt, not of
    /// this particular cadence change.
    #[serde(default)]
    pub schedule_timezone: Option<String>,
}

// =============================================================================
// hunt_suppressions
// =============================================================================

/// The ceiling on an agent-authored suppression's lifetime.
///
/// Short on purpose. The bounded lifetime is what makes an agent-authored
/// suppression survivable: a poisoned one self-heals, and the estate returns to
/// being hunted without anyone having to notice it had stopped. Lengthening this
/// weakens the mitigation that the whole feature rests on — an analyst who wants
/// a longer one can author it themselves, which is a decision with a person's
/// name on it.
pub const MAX_AGENT_SUPPRESSION_TTL_DAYS: i64 = 14;
/// Floor, so a zero or negative ttl cannot produce an already-expired row that
/// reads as an active suppression in the review queue.
pub const MIN_AGENT_SUPPRESSION_TTL_DAYS: i64 = 1;
/// Applied when a sweep names no ttl.
pub const DEFAULT_AGENT_SUPPRESSION_TTL_DAYS: i64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntSuppression {
    #[serde(with = "typeid::hunt_suppression")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub fingerprint: String,
    #[serde(default, with = "typeid::playbook::opt")]
    #[schema(value_type = Option<String>)]
    pub playbook_id: Option<Uuid>,
    pub entity_type: Option<String>,
    pub entity_value: Option<String>,
    pub reason: Option<String>,
    /// `analyst` or `agent` (migration 9000062). What the bench highlights on —
    /// an analyst must never mistake "the hunter decided this" for "a colleague
    /// decided this", and an agent suppression nobody reviews is
    /// indistinguishable from the silent blinding this table once forbade.
    pub origin: String,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    /// The sweep that authored an agent suppression. Mandatory when
    /// `origin = "agent"` and absent otherwise: a row names a person OR a sweep,
    /// never both, so "who decided this" stays answerable.
    #[serde(default, with = "typeid::hunt_sweep::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by_sweep_id: Option<Uuid>,
    #[serde(default, with = "typeid::hunt_lead::opt")]
    #[schema(value_type = Option<String>)]
    pub origin_lead_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub revoked_by: Option<Uuid>,
    pub source_types: Vec<String>,
    pub source_types_complete: bool,
}

// =============================================================================
// hunt_profiles
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntProfile {
    #[serde(with = "typeid::hunt_profile")]
    #[schema(value_type = String)]
    pub id: Uuid,
    /// Per-source-type facts. No model involved.
    pub census: serde_json::Value,
    /// Derived planes + the one-sentence summary — built from AGGREGATES only,
    /// which is simultaneously the cost argument, the injection-surface
    /// argument, and the "no raw events left the cluster" claim.
    pub fingerprint: serde_json::Value,
    /// technique → covered | gap | blind, keyed to TELEMETRY rather than to
    /// rules: "could we even look", as distinct from "do we have a rule".
    pub huntable_surface: serde_json::Value,
    pub actor_weighting: serde_json::Value,
    pub degraded: bool,
    pub degraded_detail: Option<String>,
    pub source_types: Vec<String>,
    pub source_types_complete: bool,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub generated_by: Option<Uuid>,
    #[serde(default, with = "typeid::hunt_runner::opt")]
    #[schema(value_type = Option<String>)]
    pub runner_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

// =============================================================================
// hunt_rule_ideas
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HuntRuleIdea {
    #[serde(with = "typeid::hunt_rule_idea")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::playbook")]
    #[schema(value_type = String)]
    pub playbook_id: Uuid,
    pub fingerprint: String,
    pub name: String,
    pub rationale: Option<String>,
    pub proposed_npl: String,
    pub proposed_severity: Option<String>,
    pub proposed_mode: String,
    pub mitre_technique: Option<String>,
    /// A CACHE of `hunt_rule_idea_basis`, refreshed by
    /// [`crate::hunts::service::HuntService::reevaluate_rule_idea`]. Never the
    /// gate — see [`HuntRuleIdeaBasisCounts`].
    pub basis_sweep_count: i32,
    pub basis_promoted_count: i32,
    pub precision_estimate: Option<f64>,
    pub backtest: Option<serde_json::Value>,
    pub state: String,
    pub dac_reference: Option<String>,
    pub source_types: Vec<String>,
    pub source_types_complete: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Counts recomputed FROM `hunt_rule_idea_basis` rows.
///
/// The counters on `hunt_rule_ideas` are a denormalized cache and the
/// `hunt_rule_ideas_counter_guard` CHECK over them is trivially satisfied by
/// writing 3 and 2 — it proves nothing about distinct sweeps or real
/// promotions. Anything that decides a state transition reads THIS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct HuntRuleIdeaBasisCounts {
    /// DISTINCT sweeps that produced a lead matching the idea's fingerprint.
    pub distinct_sweeps: i64,
    /// Basis rows whose lead was promoted, snapshotted at record time so the
    /// gate is stable if a lead is later re-triaged.
    pub promoted_leads: i64,
}

/// The gate: a shape must survive 3 sweeps and 2 promotions before it is
/// offered as a rule idea. Encoded once, here, so the SQL CHECK and the service
/// transition cannot drift apart.
pub const RULE_IDEA_MIN_SWEEPS: i64 = 3;
pub const RULE_IDEA_MIN_PROMOTIONS: i64 = 2;

impl HuntRuleIdeaBasisCounts {
    /// Whether the derived evidence clears the gate.
    pub fn clears_gate(&self) -> bool {
        self.distinct_sweeps >= RULE_IDEA_MIN_SWEEPS
            && self.promoted_leads >= RULE_IDEA_MIN_PROMOTIONS
    }
}

/// Ship a rule idea to detection-as-code.
///
/// v1 records the human's own reference (a PR url or branch) and marks the idea
/// `sent`. The unattended path may only ever create an INERT record: it gets no
/// repo mount, no git credentials and no write-capable nanodac tools, because
/// attacker-influenced lead content must not have a path into a detection rule.
/// Shipping stays human-triggered and interactive.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SendRuleIdeaRequest {
    /// PR url / branch, recorded verbatim for traceability.
    #[serde(default)]
    pub dac_reference: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct RejectRuleIdeaRequest {
    #[serde(default)]
    pub reason: Option<String>,
}

/// The outcome of a rule-idea decision, carrying the RECOMPUTED basis so the
/// UI shows the numbers the gate was actually evaluated on rather than the
/// cached counters it was rendered from.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RuleIdeaDecision {
    #[serde(with = "typeid::hunt_rule_idea")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub counts: HuntRuleIdeaBasisCounts,
    pub state: String,
    pub state_changed: bool,
}

// =============================================================================
// Rail summary
// =============================================================================

/// The four-badge rail aggregate, plus the cold-start facts.
///
/// One call rather than four pages, because every one of these is a COUNT the
/// rail needs before it can decide what to draw, and four round trips to render
/// four numbers is four chances to render a half-populated rail.
///
/// Counts over derived artifacts (`open_leads`, `rule_idea_candidates`, the
/// recon fields) are computed UNDER the caller's artifact scope. Counts of
/// scheduler ACTIVITY (`sweeps_24h`, `hunts_*`, `never_swept`) are not: a sweep
/// row is a record that a run happened, not a derived artifact, and hiding the
/// activity count would make "9 hunts swept in the last 24h" read as zero for
/// every source-scoped analyst. The sweep's agent-authored prose — its trail and
/// outcome note — is what carries provenance, and that is redacted on the reads
/// that return it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HuntSummary {
    /// Leads awaiting triage. The bench badge.
    pub open_leads: i64,
    /// Non-archived hunts.
    /// Serialised as `hunt_count` — the name the rail badge reads.
    #[serde(rename = "hunt_count")]
    pub hunts_total: i64,
    pub hunts_enabled: i64,
    /// Sweeps started in the last 24 hours — the "9 hunts swept" empty state.
    pub sweeps_24h: i64,
    /// Hunts that have never been attempted. Distinguishes "nothing found" from
    /// "nothing ran", which is the single most important cold-start
    /// distinction: an empty bench means very different things in each case.
    pub never_swept: i64,
    /// Rule ideas that have cleared the 3-sweep / 2-promotion gate.
    pub rule_idea_candidates: i64,

    /// When recon last ran, and whether it ran degraded. `None` = never, which
    /// is the cold-start state the Profile screen renders.
    pub last_recon_at: Option<DateTime<Utc>>,
    /// Serialised as `profile_degraded`, matching the Profile pane's vocabulary
    /// (the screen is "Profile"; "recon" is the job that produces it).
    #[serde(rename = "profile_degraded")]
    pub recon_degraded: bool,
    pub recon_degraded_detail: Option<String>,

    /// Source types at least one ENABLED hunt requires that have produced no
    /// telemetry recently. A hunt whose required source is unhealthy is HELD
    /// rather than run partial, so this is the list that explains why a hunt is
    /// not producing.
    pub unhealthy_source_types: Vec<String>,

    /// From the latest recon profile's `huntable_surface`, which maps a
    /// technique id to `covered` | `gap` | `blind`. `gap` = we have the
    /// telemetry and no hunt; `blind` = we could not look if we wanted to.
    /// Keyed to TELEMETRY, not to rules.
    pub hunt_gaps: i64,
    pub blind_techniques: i64,
}

// =============================================================================
// List filters
// =============================================================================

/// The lead states, mirroring the `hunt_leads_state_check` CHECK. The single
/// source of truth for validating a caller's state filter — anything not in
/// this list is rejected before it reaches SQL.
pub const LEAD_STATES: &[&str] = &["unreviewed", "in_review", "promoted", "dismissed"];

/// Parse a caller's comma-joined `state` filter into validated states.
///
/// The bench sends multi-state filters (`state=unreviewed,in_review`), so the
/// wire form is a comma-joined list. Each token is validated against
/// [`LEAD_STATES`] and an unknown one is REJECTED rather than dropped or
/// passed through: dropping would silently widen a triage filter, and passing
/// it through would bind a value that matches nothing — both of which read as
/// "the filter did nothing", the worst failure a triage queue can have.
/// Validated-and-bound also means no caller text is ever interpolated into the
/// statement.
pub fn parse_lead_states(raw: &str) -> Result<Vec<String>, String> {
    let mut states: Vec<String> = Vec::new();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if !LEAD_STATES.contains(&token) {
            return Err(format!(
                "invalid state `{token}` — expected one of: {}",
                LEAD_STATES.join(", ")
            ));
        }
        if !states.iter().any(|s| s == token) {
            states.push(token.to_string());
        }
    }
    Ok(states)
}

#[derive(Debug, Clone, Default)]
pub struct ListLeadsQuery {
    pub playbook_id: Option<Uuid>,
    pub sweep_id: Option<Uuid>,
    /// Validated states ([`parse_lead_states`]); empty means no state filter.
    /// A `Vec` rather than `Option<String>` because the bench's segments are
    /// multi-state (`unreviewed,in_review`) — the old single-string form was
    /// bound as an equality against the whole comma-joined value and matched
    /// nothing.
    pub states: Vec<String>,
    /// Only leads whose verdict THIS user recorded (`hunt_leads.reviewed_by`).
    /// This is what `mine=true` means server-side: `reviewed_by` is stamped by
    /// promote and dismiss — there is no assignment mechanism — so "mine" is
    /// "leads I triaged", not "leads waiting for me".
    pub reviewed_by: Option<Uuid>,
    pub min_score: Option<f64>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone, Default)]
pub struct ListSweepsQuery {
    pub playbook_id: Option<Uuid>,
    pub status: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_is_three_sweeps_and_two_promotions() {
        // Mirrors `hunt_rule_ideas_counter_guard`. If the SQL CHECK is ever
        // relaxed, this test is the reason someone has to come and change the
        // constant deliberately rather than by accident.
        assert!(!HuntRuleIdeaBasisCounts {
            distinct_sweeps: 2,
            promoted_leads: 5
        }
        .clears_gate());
        assert!(!HuntRuleIdeaBasisCounts {
            distinct_sweeps: 9,
            promoted_leads: 1
        }
        .clears_gate());
        assert!(HuntRuleIdeaBasisCounts {
            distinct_sweeps: 3,
            promoted_leads: 2
        }
        .clears_gate());
    }

    #[test]
    fn a_metadata_patch_that_smuggles_a_schedule_change_is_visible() {
        // The handler gates `touches_schedule()` on `hunts:run`. If this
        // returned false for a bundled `enabled: true`, a `hunts:manage`
        // holder could put a hunt on production telemetry without ever holding
        // the permission that decides it.
        let benign = UpdateHuntRequest {
            title: Some("renamed".into()),
            ..Default::default()
        };
        assert!(!benign.touches_schedule());

        for smuggled in [
            UpdateHuntRequest {
                title: Some("renamed".into()),
                enabled: Some(true),
                ..Default::default()
            },
            UpdateHuntRequest {
                schedule_cron: Some("*/5 * * * *".into()),
                ..Default::default()
            },
            UpdateHuntRequest {
                schedule_timezone: Some("Europe/London".into()),
                ..Default::default()
            },
        ] {
            assert!(
                smuggled.touches_schedule(),
                "a schedule change slipped past the hunts:run gate"
            );
        }
    }
}

#[cfg(test)]
mod wire_contract_tests {
    use super::*;

    /// The desktop's `WireHunt` is the consumer of this type, and TypeScript
    /// does not validate at runtime — a renamed field arrives as `undefined`
    /// and renders as a blank row rather than throwing. That failure mode is
    /// why this test exists: nothing else would catch it until someone opened
    /// the Hunting rail against a real instance and saw an empty library.
    #[test]
    fn hunt_serialises_the_identity_fields_the_client_reads() {
        let hunt = Hunt {
            playbook_id: uuid::Uuid::nil(),
            title: "Service account interactive logon".to_string(),
            subtitle: Some("machine accounts logging on like people".to_string()),
            doc: Some("## Hypothesis\nService accounts should not log on interactively.".to_string()),
            steps: None,
            category: "identity".to_string(),
            status: "live".to_string(),
            tags: vec![],
            sweep_query: "source_type=windows_security".to_string(),
            schedule_cron: None,
            schedule_timezone: "UTC".to_string(),
            required_source_types: vec![],
            mitre_tactic: None,
            mitre_technique: None,
            enabled: false,
            budget_max_turns: 40,
            budget_max_tool_calls: 120,
            budget_max_rows: 5000,
            budget_max_wall_seconds: 900,
            lookback_window: "24h".to_string(),
            max_catchup_lookback: "72h".to_string(),
            next_due_slot: None,
            coalesced_through_slot: None,
            last_attempt_at: None,
            last_success_at: None,
            auto_promote_threshold: None,
            auto_promote: false,
            generated_from_profile: false,
            generated_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let json = serde_json::to_value(&hunt).expect("serialises");

        for field in ["id", "name", "description"] {
            assert!(
                json.get(field).is_some(),
                "`{field}` is absent from the wire shape — the desktop keys and \
                 titles rows by it, and TypeScript will render `undefined` as a \
                 blank rather than failing loudly"
            );
        }
        // The internal column names must NOT leak: a consumer that started
        // reading `playbook_id` would keep working here and break the moment
        // anyone tidied the rename away.
        for internal in ["playbook_id", "title", "subtitle"] {
            assert!(
                json.get(internal).is_none(),
                "internal column name `{internal}` leaked onto the wire"
            );
        }

        // A hunt IS its hypothesis. `doc` was stored and never projected, so
        // every hunt reached the detail view with no body and rendered the
        // "the nPL is the whole definition" fallback — which turns a hunt into
        // a saved search, the exact thing the format exists to not be.
        assert_eq!(
            json.get("doc").and_then(|d| d.as_str()),
            Some("## Hypothesis\nService accounts should not log on interactively."),
            "`doc` must reach the wire when the detail projection supplied it"
        );

        // …and must be ABSENT, not null, when the list projection did not — so
        // "the list did not ask" stays distinguishable from "this hunt has no
        // doc", which is what the detail view's empty-state copy claims.
        let listed = Hunt { doc: None, steps: None, ..hunt };
        let listed = serde_json::to_value(&listed).expect("serialises");
        assert!(listed.get("doc").is_none(), "an absent doc must be omitted, not null");
    }
}

#[cfg(test)]
#[path = "models_tests.rs"]
mod models_tests;
