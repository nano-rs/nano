// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — the narrow shape a sweep is allowed to report.
//!
//! This module exists to make a class of bug *unrepresentable* rather than
//! merely forbidden. The design says the agent never supplies a score, a
//! fingerprint, or a provenance manifest. A repository method taking a fully
//! formed `HuntLead` would leave that as a convention — one careless handler
//! away from an agent-authored score reaching the bench, and invisible in
//! review because the call site looks correct.
//!
//! So the wire type has no field for any of them. There is nothing to ignore
//! and nothing to validate away: the report carries evidence identifiers,
//! narratives, durable fact claims, and the trail it took. Everything
//! load-bearing — including provenance for both leads and facts — is derived
//! server-side in one transaction.
//!
//! ```text
//!   agent  ──► SweepReport ──► [ server: resolve evidence, derive provenance,
//!                                measure inputs, score, fingerprint, dedupe ]
//!                          ──► HuntLead rows
//! ```
//!
//! The other half of the contract is the fence: the transaction that persists a
//! report reasserts `(sweep_id, runner_id, runner_fence, unexpired lease,
//! active status)` under lock before writing anything. A runner that slept
//! through its lease and woke to find the sweep reassigned must not be able to
//! append to it — the `hunt_sweeps_lease_shape` CHECK guarantees those columns
//! are populated for any sweep in a claimable state, and the reassertion is
//! what makes them mean something.

use serde::{Deserialize, Serialize};

/// What a sweep hands back when it finishes.
///
/// Note what is absent: no score, no fingerprint, no `source_types`, no state,
/// no case id, no suppression. Those are server-owned and there is deliberately
/// no field to put them in.
#[derive(Debug, Clone, Default, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SweepReport {
    /// Candidate findings. May be empty — a sweep that found nothing is a
    /// successful sweep and its `no_leads` outcome is useful signal.
    #[serde(default)]
    pub candidates: Vec<LeadCandidate>,
    /// Durable environment facts established by this sweep. They are resolved
    /// and committed with the report under the same lease/fence transaction;
    /// they never feed scoring or suppression.
    #[serde(default)]
    pub knowledge: Vec<super::knowledge::KnowledgeCandidate>,
    /// The ordered queries and pivots the sweep actually made.
    ///
    /// Recorded because the path distinguishes a hunt that is wandering
    /// productively from one that is lost, and because a hunt that always
    /// digresses to the same place is a candidate to become its own hunt.
    #[serde(default)]
    pub trail: Vec<TrailStep>,
    /// Why the sweep ended, from the agent's point of view. The server
    /// validates this against observed budget consumption rather than trusting
    /// it — a sweep that claims `completed` while having exhausted its turns is
    /// recorded as `budget_exhausted`.
    pub claimed_outcome: Option<String>,
    /// Free-text note about where it got to. Surfaced on `budget_exhausted` so
    /// "was following svc_backup across 3 hosts" reaches the analyst.
    pub note: Option<String>,
}

/// One candidate finding.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LeadCandidate {
    /// Canonical entity type. Validated against the `hunt_leads_entity_type`
    /// CHECK set server-side; an unknown type rejects the candidate rather than
    /// the whole report.
    pub entity_type: String,
    pub entity_value: String,
    /// What the agent believes it found. Free to differ from the hunt's own
    /// technique — a hunt scoped to lateral movement that surfaces a
    /// compromised service account did its job better than one that stayed on
    /// rails, and the lead records what was found rather than what was sought.
    pub mitre_technique: Option<String>,
    /// Stable signal identifiers backing this candidate — rule ids, technique
    /// ids, detector keys. These feed the fingerprint, so they must be
    /// identifiers; free prose here would reintroduce exactly the
    /// attacker-steerable fingerprint the design rules out.
    #[serde(default)]
    pub signals: Vec<String>,
    /// Canonical ClickHouse event identifiers. The server resolves each one,
    /// drops any the sweep's principal could not read, and derives both the
    /// evidence set and the provenance manifest from what survives.
    #[serde(default)]
    pub evidence_event_ids: Vec<String>,
    /// Untrusted, attacker-influenceable prose. Length-capped by
    /// `hunt_leads_narrative_bounded`; rendered containment-first.
    pub narrative: Option<String>,
}

/// One step in the sweep's investigative path.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TrailStep {
    /// `search`, `pivot`, `baseline`, `compute`, …
    pub kind: String,
    /// The nPL or compute-step identifier that ran.
    pub detail: String,
    /// Rows the step returned, before any cap was applied.
    #[serde(default)]
    pub rows_matched: u64,
    /// Rows actually read into context.
    #[serde(default)]
    pub rows_read: u64,
}

impl TrailStep {
    /// Whether this step hit a cap.
    ///
    /// Surfaced as "read 400 of 12,000 matching" rather than silently truncated:
    /// a truncation the analyst cannot see reads as "that is all there was",
    /// which is a lie the bench must never tell.
    pub fn was_truncated(&self) -> bool {
        self.rows_matched > self.rows_read
    }
}

/// Observed budget consumption, measured by the runner rather than claimed by
/// the agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetUsage {
    pub turns: u32,
    pub tool_calls: u32,
    pub rows_read: u64,
    pub wall_seconds: u64,
}

/// The ceiling a sweep was given, from `hunt_specs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimits {
    pub max_turns: u32,
    pub max_tool_calls: u32,
    pub max_rows: u64,
    pub max_wall_seconds: u64,
}

impl BudgetUsage {
    /// Whether any dimension of the budget was consumed.
    ///
    /// Used to override a claimed outcome: an agent that reports `completed`
    /// while having burned its whole budget did not complete, it ran out, and
    /// recording the difference is what makes "this hunt is too broad" visible
    /// instead of looking like a clean run that happened to find nothing.
    pub fn exhausted(&self, limits: &BudgetLimits) -> bool {
        self.turns >= limits.max_turns
            || self.tool_calls >= limits.max_tool_calls
            || self.rows_read >= limits.max_rows
            || self.wall_seconds >= limits.max_wall_seconds
    }
}

/// Reconcile what the agent claimed with what the runner measured.
///
/// The measurement wins. This is not distrust of the model so much as the
/// recognition that a process which ran out of room is poorly placed to notice.
pub fn reconcile_outcome(
    claimed: Option<&str>,
    usage: &BudgetUsage,
    limits: &BudgetLimits,
    lead_count: usize,
) -> &'static str {
    if usage.exhausted(limits) {
        return "budget_exhausted";
    }
    match claimed {
        Some("held") => "held",
        Some("error") => "error",
        Some("cancelled") => "cancelled",
        _ if lead_count == 0 => "no_leads",
        _ => "completed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> BudgetLimits {
        BudgetLimits {
            max_turns: 40,
            max_tool_calls: 120,
            max_rows: 5000,
            max_wall_seconds: 900,
        }
    }

    #[test]
    fn the_report_type_has_nowhere_to_put_a_score() {
        // A structural assertion, expressed the only way Rust allows: if a
        // `score`, `fingerprint` or `source_types` field is ever added to the
        // wire type, this deserialization stops ignoring them and someone has
        // to come read this test. serde ignores unknown fields by default, so
        // the guarantee is "no field exists to populate", not "input is
        // rejected" — and that is the guarantee we want, since the server
        // derives all three regardless of what an agent sends.
        let json = r#"{
            "candidates": [{
                "entity_type": "host",
                "entity_value": "srv-web06",
                "signals": ["T1021"],
                "evidence_event_ids": ["e1"],
                "score": 0.99,
                "fingerprint": "attacker-chosen",
                "source_types": ["windows_security"]
            }]
        }"#;
        let report: SweepReport = serde_json::from_str(json).expect("parses");
        let candidate = &report.candidates[0];
        assert_eq!(candidate.entity_value, "srv-web06");
        // The smuggled fields simply do not exist on the type.
        let round_tripped = serde_json::to_value(candidate).expect("serializes");
        assert!(round_tripped.get("score").is_none());
        assert!(round_tripped.get("fingerprint").is_none());
        assert!(round_tripped.get("source_types").is_none());
    }

    #[test]
    fn knowledge_is_optional_for_existing_report_callers() {
        let report: SweepReport = serde_json::from_str(r#"{"candidates":[]}"#).expect("parses");
        assert!(report.knowledge.is_empty());
    }

    #[test]
    fn knowledge_has_no_runner_control_fields() {
        let report: SweepReport = serde_json::from_str(
            r#"{
                "knowledge": [{
                    "category": "account",
                    "subject": "svc_backup",
                    "fact": "runs nightly",
                    "sweep_id": "hsweep_attacker_chosen",
                    "source_types": ["forged"]
                }]
            }"#,
        )
        .expect("parses");
        let serialized = serde_json::to_value(&report.knowledge[0]).expect("serializes");
        assert!(serialized.get("sweep_id").is_none());
        assert!(serialized.get("source_types").is_none());
    }

    #[test]
    fn exhausted_budget_overrides_a_claimed_completion() {
        let usage = BudgetUsage {
            turns: 40,
            tool_calls: 10,
            rows_read: 12,
            wall_seconds: 30,
        };
        assert_eq!(reconcile_outcome(Some("completed"), &usage, &limits(), 3), "budget_exhausted");
    }

    #[test]
    fn a_clean_sweep_with_no_findings_is_no_leads_not_completed() {
        // Distinguishable on the bench: "9 hunts swept, nothing found" is a
        // status, and conflating it with `completed` loses that.
        let usage = BudgetUsage {
            turns: 4,
            tool_calls: 9,
            rows_read: 120,
            wall_seconds: 40,
        };
        assert_eq!(reconcile_outcome(Some("completed"), &usage, &limits(), 0), "no_leads");
    }

    #[test]
    fn held_survives_reconciliation() {
        let usage = BudgetUsage::default();
        assert_eq!(reconcile_outcome(Some("held"), &usage, &limits(), 0), "held");
    }

    #[test]
    fn every_budget_dimension_can_trigger_exhaustion() {
        let l = limits();
        let dims = [
            BudgetUsage { turns: l.max_turns, ..Default::default() },
            BudgetUsage { tool_calls: l.max_tool_calls, ..Default::default() },
            BudgetUsage { rows_read: l.max_rows, ..Default::default() },
            BudgetUsage { wall_seconds: l.max_wall_seconds, ..Default::default() },
        ];
        for usage in dims {
            assert!(usage.exhausted(&l), "{usage:?} should count as exhausted");
        }
        assert!(!BudgetUsage::default().exhausted(&l));
    }

    #[test]
    fn truncation_is_detectable_per_step() {
        let step = TrailStep {
            kind: "search".to_string(),
            detail: "source_type=windows_security | head 400".to_string(),
            rows_matched: 12_000,
            rows_read: 400,
        };
        assert!(step.was_truncated());
    }
}
