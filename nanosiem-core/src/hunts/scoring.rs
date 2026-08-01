// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — server-side lead scoring.
//!
//! # Why the server scores and the agent does not
//!
//! "Promote when the score crosses a threshold" is only a meaningful gate if
//! the server owns every input to the score. An agent-supplied number is not a
//! measurement, it is a request: it varies run to run, it cannot be compared
//! across hunts, and — because the agent's context is filled with
//! attacker-authored log content — it is reachable by anyone who can write a
//! log line. A hunt that scored itself would let the thing being investigated
//! decide how interesting it is.
//!
//! So the agent submits *evidence* and *narrative*. This module turns evidence
//! into a number, deterministically, from facts already in the database.
//!
//! # Why the contributions are signed and stored
//!
//! An opaque 0.86 is not reviewable — an analyst cannot tell a strong finding
//! from a strong prior. Every factor is emitted with its own signed value and
//! persisted alongside the score, so the bench can show *why 0.86*, including
//! the factors that contributed nothing. A "−0.00 no suppression matched" line
//! is worth rendering precisely because its absence would be indistinguishable
//! from the check never having run.

use serde::{Deserialize, Serialize};

/// One named, signed input to a lead's score.
///
/// `ToSchema` because this is a wire type: `HuntLeadDetail.contributions`
/// serves the flat `{factor, value, detail}` list the bench renders.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Contribution {
    /// Stable key, safe to render and to match on in tests.
    ///
    /// `String` rather than `&'static str` because these round-trip through
    /// the `score_contributions` JSONB column — a borrowed key cannot be
    /// deserialized back out of storage.
    pub factor: String,
    /// Signed delta applied to the running score.
    pub value: f64,
    /// One plain-language clause explaining the number to an analyst.
    pub detail: String,
}

/// The full, inspectable result of scoring one lead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// Final score, clamped to `0.0..=1.0`.
    pub value: f64,
    pub contributions: Vec<Contribution>,
}

/// Server-owned facts about a candidate lead.
///
/// Every field here is measured by the server from the database — none is
/// copied from the agent's report. That is the whole point of the type.
#[derive(Debug, Clone, Default)]
pub struct ScoreInputs {
    /// Distinct canonical events attached as evidence.
    pub evidence_count: usize,
    /// Distinct source types the evidence spans.
    ///
    /// Corroboration across telemetry planes is the single strongest honest
    /// signal available: one source can be noisy or misconfigured, two
    /// agreeing rarely are.
    pub distinct_source_types: usize,
    /// Fraction of the tenant's assets that have exhibited this entity/pattern
    /// recently, in `0.0..=1.0`. Low is interesting.
    pub prevalence: Option<f64>,
    /// Whether the entity had no prior history before this window.
    pub first_seen_in_window: bool,
    /// Whether an active suppression matched this lead's fingerprint.
    ///
    /// A match zeroes the score outright rather than subtracting from it — see
    /// [`score`].
    pub suppressed: bool,
    /// How many previous sweeps produced this same fingerprint.
    pub prior_occurrences: u32,
}

/// Base score before any evidence is considered.
///
/// Deliberately low. A hunt firing at all is weak evidence; the interesting
/// signal is in corroboration and rarity, not in the fact that a query matched.
const BASE: f64 = 0.15;

/// Compute a lead's score.
///
/// Clamped to `0.0..=1.0` at the end, so no combination of factors can produce
/// a score outside the range the `hunt_leads_score_range` CHECK allows — a
/// scoring change must never be able to make an insert fail.
pub fn score(inputs: &ScoreInputs) -> Score {
    let mut contributions = Vec::new();
    let mut value = BASE;

    contributions.push(Contribution {
        factor: "base".to_string(),
        value: BASE,
        detail: "hunt matched".to_string(),
    });

    // Suppression is absolute, not a penalty. A subtractive suppression would
    // mean a sufficiently "strong" lead could outvote an analyst's explicit
    // decision to never see it again — which is precisely the behaviour that
    // makes a triage queue untrustworthy.
    if inputs.suppressed {
        contributions.push(Contribution {
            factor: "suppression".to_string(),
            value: -BASE,
            detail: "an active suppression matches this fingerprint".to_string(),
        });
        return Score {
            value: 0.0,
            contributions,
        };
    }
    contributions.push(Contribution {
        factor: "suppression".to_string(),
        value: 0.0,
        detail: "no suppression matched".to_string(),
    });

    // Evidence volume, with sharply diminishing returns: the step from one
    // event to three is meaningful, the step from thirty to three hundred is
    // usually just a noisy query.
    let evidence = match inputs.evidence_count {
        0 => 0.0,
        1 => 0.05,
        2..=4 => 0.12,
        5..=20 => 0.18,
        _ => 0.20,
    };
    value += evidence;
    contributions.push(Contribution {
        factor: "evidence_volume".to_string(),
        value: evidence,
        detail: format!("{} distinct events", inputs.evidence_count),
    });

    // Cross-source corroboration.
    let corroboration = match inputs.distinct_source_types {
        0 | 1 => 0.0,
        2 => 0.15,
        _ => 0.25,
    };
    value += corroboration;
    contributions.push(Contribution {
        factor: "corroboration".to_string(),
        value: corroboration,
        detail: match inputs.distinct_source_types {
            0 | 1 => "single source type".to_string(),
            n => format!("corroborated across {n} source types"),
        },
    });

    // Rarity. `None` contributes nothing rather than guessing — an unknown
    // prevalence is not evidence of rarity, and treating it as such is how a
    // hunt manufactures excitement about an unmeasured entity.
    //
    // A value that is not a finite fraction is treated as UNMEASURED rather
    // than classified. Without this, a NaN from a division by zero upstream
    // falls through every comparison to the "common" arm and renders "seen on
    // NaN% of assets", and a negative value compares as <= 0.01 and collects
    // the maximum rarity bonus — a corrupt measurement would read as the most
    // interesting possible finding.
    let prevalence = inputs
        .prevalence
        .filter(|p| p.is_finite() && (0.0..=1.0).contains(p));
    match prevalence {
        Some(p) if p <= 0.01 => {
            value += 0.25;
            contributions.push(Contribution {
                factor: "rarity".to_string(),
                value: 0.25,
                detail: format!("seen on {:.2}% of assets", p * 100.0),
            });
        }
        Some(p) if p <= 0.10 => {
            value += 0.12;
            contributions.push(Contribution {
                factor: "rarity".to_string(),
                value: 0.12,
                detail: format!("seen on {:.1}% of assets", p * 100.0),
            });
        }
        Some(p) => {
            contributions.push(Contribution {
                factor: "rarity".to_string(),
                value: 0.0,
                detail: format!("common — seen on {:.1}% of assets", p * 100.0),
            });
        }
        None => {
            contributions.push(Contribution {
                factor: "rarity".to_string(),
                value: 0.0,
                detail: "prevalence not measured".to_string(),
            });
        }
    }
    debug_assert!(
        prevalence.is_none() || inputs.prevalence.is_some_and(|p| p.is_finite()),
        "a non-finite prevalence reached classification"
    );

    if inputs.first_seen_in_window {
        value += 0.15;
        contributions.push(Contribution {
            factor: "first_seen".to_string(),
            value: 0.15,
            detail: "no prior history for this entity".to_string(),
        });
    } else {
        contributions.push(Contribution {
            factor: "first_seen".to_string(),
            value: 0.0,
            detail: "entity has prior history".to_string(),
        });
    }

    // Recurrence cuts both ways and we deliberately treat it as a mild
    // NEGATIVE. A shape that returns every sweep and has never been promoted is
    // background noise for this tenant, and letting it keep its original score
    // is how a bench fills with the same twelve rows. If it is genuinely worth
    // acting on, it earns its way to a rule idea through the promotion gate
    // instead.
    let recurrence = match inputs.prior_occurrences {
        0 => 0.0,
        1..=2 => -0.05,
        _ => -0.10,
    };
    value += recurrence;
    contributions.push(Contribution {
        factor: "recurrence".to_string(),
        value: recurrence,
        detail: match inputs.prior_occurrences {
            0 => "first time this shape has been seen".to_string(),
            n => format!("seen in {n} prior sweeps"),
        },
    });

    Score {
        value: value.clamp(0.0, 1.0),
        contributions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strong() -> ScoreInputs {
        ScoreInputs {
            evidence_count: 8,
            distinct_source_types: 3,
            prevalence: Some(0.004),
            first_seen_in_window: true,
            suppressed: false,
            prior_occurrences: 0,
        }
    }

    #[test]
    fn scoring_is_deterministic() {
        assert_eq!(score(&strong()), score(&strong()));
    }

    #[test]
    fn suppression_zeroes_rather_than_penalizes() {
        // The point: even a maximally strong lead cannot outvote an analyst who
        // said "never show me this again".
        let mut inputs = strong();
        inputs.suppressed = true;
        let result = score(&inputs);
        assert_eq!(result.value, 0.0);
    }

    #[test]
    fn a_suppression_check_that_found_nothing_is_still_recorded() {
        // Absence of the line would be indistinguishable from the check never
        // having run, which is exactly the ambiguity the bench must not have.
        let result = score(&strong());
        let entry = result
            .contributions
            .iter()
            .find(|c| c.factor == "suppression")
            .expect("suppression factor is always emitted");
        assert_eq!(entry.value, 0.0);
        assert_eq!(entry.detail, "no suppression matched");
    }

    #[test]
    fn unmeasured_prevalence_contributes_nothing() {
        // An unknown prevalence must not be laundered into evidence of rarity.
        let mut unknown = strong();
        unknown.prevalence = None;
        let mut common = strong();
        common.prevalence = Some(0.85);
        let unknown_rarity = rarity_of(&score(&unknown));
        let common_rarity = rarity_of(&score(&common));
        assert_eq!(unknown_rarity, 0.0);
        assert_eq!(common_rarity, 0.0);
    }

    fn rarity_of(result: &Score) -> f64 {
        result
            .contributions
            .iter()
            .find(|c| c.factor == "rarity")
            .map(|c| c.value)
            .expect("rarity factor is always emitted")
    }

    #[test]
    fn corrupt_prevalence_is_unmeasured_not_maximally_rare() {
        // A NaN from an upstream division by zero falls through every
        // comparison to the "common" arm and renders "seen on NaN%"; a negative
        // value compares <= 0.01 and collects the MAXIMUM rarity bonus, so a
        // broken measurement would read as the most interesting finding
        // available. Both must land as unmeasured.
        for corrupt in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.5, 1.5] {
            let mut inputs = strong();
            inputs.prevalence = Some(corrupt);
            let result = score(&inputs);
            let rarity = result
                .contributions
                .iter()
                .find(|c| c.factor == "rarity")
                .expect("rarity factor is always emitted");
            assert_eq!(rarity.value, 0.0, "corrupt prevalence {corrupt} scored as rare");
            assert_eq!(rarity.detail, "prevalence not measured");
            assert!(result.value.is_finite());
            assert!((0.0..=1.0).contains(&result.value));
        }
    }

    #[test]
    fn corroboration_beats_volume() {
        // Two sources agreeing should outrank one source shouting.
        let mut shouting = ScoreInputs {
            evidence_count: 500,
            distinct_source_types: 1,
            ..Default::default()
        };
        shouting.prevalence = Some(0.5);
        let agreeing = ScoreInputs {
            evidence_count: 3,
            distinct_source_types: 3,
            prevalence: Some(0.5),
            ..Default::default()
        };
        assert!(
            score(&agreeing).value > score(&shouting).value,
            "a single noisy source outscored cross-source corroboration"
        );
    }

    #[test]
    fn recurring_unpromoted_shapes_decay() {
        let mut recurring = strong();
        recurring.prior_occurrences = 9;
        assert!(score(&recurring).value < score(&strong()).value);
    }

    #[test]
    fn score_always_lands_inside_the_check_constraint_range() {
        // hunt_leads_score_range enforces 0..=1. A scoring change must never be
        // able to make an insert fail, so clamping is asserted rather than
        // assumed.
        let extremes = [
            ScoreInputs::default(),
            strong(),
            ScoreInputs {
                evidence_count: usize::MAX,
                distinct_source_types: usize::MAX,
                prevalence: Some(0.0),
                first_seen_in_window: true,
                suppressed: false,
                prior_occurrences: 0,
            },
            ScoreInputs {
                prior_occurrences: u32::MAX,
                prevalence: Some(1.0),
                ..Default::default()
            },
        ];
        for inputs in extremes {
            let value = score(&inputs).value;
            assert!(
                (0.0..=1.0).contains(&value),
                "score {value} outside the range hunt_leads_score_range allows"
            );
        }
    }

    #[test]
    fn every_contribution_is_named_and_explained() {
        for contribution in score(&strong()).contributions {
            assert!(!contribution.factor.is_empty());
            assert!(
                !contribution.detail.trim().is_empty(),
                "factor {} has no analyst-facing explanation",
                contribution.factor
            );
        }
    }
}
