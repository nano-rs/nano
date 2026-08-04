// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — hunt frontmatter → `hunt_specs`, with the enable switch absent
//! by construction.
//!
//! A hunt is authored as markdown in a git repository and reaches the product
//! through the same sync/import pipeline as a response playbook. That pipeline
//! is why this module exists in the shape it does: **whatever a merged file can
//! express, a reviewer of that file has granted.**
//!
//! So [`HuntSpecDraft`] is the exhaustive list of what a merge may decide, and
//! it does not contain `enabled`. Neither does [`PlaybookFrontmatter`], and
//! neither does the INSERT in [`super::repository`]. There are three
//! independent places a future change would have to add a field before
//! frontmatter could start a sweep, and a guard test on the last of them.
//!
//! Why that matters more than it looks: if a merge could enable a hunt, merge
//! access to a content repository would silently be equivalent to the
//! `hunts:run` permission — an autonomous process reading production telemetry
//! on a cron, granted by approving a markdown file, with the reviewer looking at
//! prose rather than a privilege grant. `schedule:` is recorded as a *suggested
//! cadence*; `hunt_specs.next_due_slot` stays NULL and the scheduler's poll
//! index (`idx_hunt_specs_due`) is partial on `enabled`, so a recorded cron is
//! not merely unapplied — it is unreachable until a human flips the switch in
//! the product, where it is visibly a decision.
//!
//! # Ceilings, not just validity
//!
//! The `budget:` block is checked against per-dimension ceilings rather than
//! only for being positive. The DB CHECK already stops zero and negative; what
//! it cannot stop is a merged file quietly handing an unattended process an
//! eight-hour wall clock and a million-row read against production telemetry.
//! A budget is the ceiling a sweep may spend, and the repository does not get
//! to raise the ceiling arbitrarily.

use crate::playbooks::models::{ParsedStepTree, PlaybookFrontmatter, PlaybookKind, PlaybookStep};

use super::capabilities::normalize_requirements;
use super::report::BudgetLimits;
use crate::playbooks::models::HuntTelemetryRequirements;

/// Ceilings a repository-authored budget may not exceed.
///
/// Generous — every stock hunt sits an order of magnitude below all four — but
/// finite. See the module docs for why finite is the point.
pub const MAX_BUDGET_TURNS: u32 = 200;
pub const MAX_BUDGET_TOOL_CALLS: u32 = 1_000;
pub const MAX_BUDGET_ROWS: u64 = 100_000;
pub const MAX_BUDGET_WALL_SECONDS: u64 = 3_600;

/// Ceiling on `lookback_window`, in minutes (30 days).
///
/// A hunt that scans a quarter to find one thing is a report, and it multiplies
/// the read spend of every sweep. The authoring guide says to prefer a narrow
/// window and a wide question; this is that guidance made non-optional.
const MAX_LOOKBACK_MINUTES: i64 = 30 * 24 * 60;

/// Defaults mirroring the `hunt_specs` column defaults in migration 9000054.
/// Kept in sync deliberately rather than read from the database: an import that
/// omits a column and one that writes the same value must produce the same row.
const DEFAULT_BUDGET: BudgetLimits = BudgetLimits {
    max_turns: 40,
    max_tool_calls: 120,
    max_rows: 5_000,
    max_wall_seconds: 900,
};
const DEFAULT_LOOKBACK_WINDOW: &str = "24h";
const DEFAULT_TIMEZONE: &str = "UTC";

/// Step kinds a hunt may not use.
///
/// From the authoring contract: `/decision` and `/review` are meaningless with
/// no human present, and `/action` changes the world — which is exactly what an
/// unattended process on a schedule must not do. Rejecting at import means a
/// file that asks for one never becomes a runnable hunt, rather than becoming
/// one whose forbidden steps are skipped at runtime and whose author believes
/// they will run.
const FORBIDDEN_HUNT_STEP_KINDS: &[&str] = &["decision", "review", "action"];

/// Step kinds that open a sweep by pulling data. The first one in document
/// order seeds `hunt_specs.sweep_query`.
const OPENING_STEP_KINDS: &[&str] = &["query", "baseline"];

/// Upper bounds on the free-text fields, so a merged file cannot write an
/// unbounded string into a shared table.
const MAX_SOURCE_TYPES: usize = 32;
const MAX_SOURCE_TYPE_LEN: usize = 64;
const MAX_SWEEP_QUERY_LEN: usize = 8_192;

/// Why a hunt file was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HuntSpecError {
    #[error("not a hunt: frontmatter declares kind = {0}")]
    NotAHunt(&'static str),
    #[error("hunt frontmatter is missing or unparseable")]
    MissingFrontmatter,
    #[error("a hunt needs an opening /query or /baseline step; this file has none")]
    NoOpeningStep,
    #[error("/{kind} is not available to hunts ({reason})")]
    ForbiddenStep { kind: String, reason: &'static str },
    #[error("invalid schedule `{expr}`: {detail}")]
    InvalidSchedule { expr: String, detail: String },
    #[error("invalid timezone `{0}`")]
    InvalidTimezone(String),
    #[error("invalid lookback_window `{0}`: expected a duration like 15m, 24h or 7d")]
    InvalidLookback(String),
    #[error("lookback_window {0} exceeds the {1}d ceiling")]
    LookbackTooLong(String, i64),
    #[error("budget.{field} must be greater than zero")]
    BudgetNotPositive { field: &'static str },
    #[error("budget.{field} of {value} exceeds the ceiling of {ceiling}")]
    BudgetTooLarge {
        field: &'static str,
        value: i64,
        ceiling: i64,
    },
    #[error("invalid required_source_types entry `{0}`")]
    InvalidSourceType(String),
    #[error("too many required_source_types ({0}); the ceiling is {MAX_SOURCE_TYPES}")]
    TooManySourceTypes(usize),
    #[error("invalid telemetry requirements: {0}")]
    InvalidTelemetry(String),
    #[error("invalid mitre_technique `{0}`: expected an ATT&CK id like T1021 or T1071.001")]
    InvalidTechnique(String),
    #[error("invalid mitre_tactic `{0}`")]
    InvalidTactic(String),
}

/// Everything a merged hunt file is allowed to decide.
///
/// Note what is absent, and stays absent: `enabled`, `auto_promote`,
/// `next_due_slot`, `generated_from_profile`. The first is the privilege grant
/// this whole module exists to withhold; the rest are server-owned scheduling
/// and promotion state that a document has no standing to assert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuntSpecDraft {
    /// Seed for the sweep, taken from the opening `/query` or `/baseline`
    /// step. Explicitly a starting point the agent may abandon — the authoring
    /// format states a hypothesis in prose rather than shipping nPL, so this is
    /// the opening step's text, not a query to execute verbatim.
    pub sweep_query: String,
    /// Suggested cadence, verbatim from frontmatter (validated, not rewritten —
    /// the UI shows the author's own `0 3 * * *`). NULL means manual-only.
    pub schedule_cron: Option<String>,
    pub schedule_timezone: String,
    pub lookback_window: String,
    pub required_source_types: Vec<String>,
    pub telemetry: HuntTelemetryRequirements,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
    pub budget: BudgetLimits,
}

impl HuntSpecDraft {
    /// Build a draft from a parsed hunt file.
    ///
    /// `fm` must declare `kind: hunt` — this function will not promote a
    /// response playbook, and callers must not decide the kind from the path
    /// the file was synced from.
    pub fn from_frontmatter(
        fm: Option<&PlaybookFrontmatter>,
        tree: &ParsedStepTree,
    ) -> Result<Self, HuntSpecError> {
        let fm = fm.ok_or(HuntSpecError::MissingFrontmatter)?;
        if fm.kind != PlaybookKind::Hunt {
            return Err(HuntSpecError::NotAHunt(fm.kind.as_str()));
        }

        reject_forbidden_steps(tree)?;

        let sweep_query = opening_step_seed(tree).ok_or(HuntSpecError::NoOpeningStep)?;

        let schedule_cron = match fm.schedule.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(expr) => {
                // Reuse the scheduler's own validator, including its 5-to-6
                // field normalization, so a cadence that imports is a cadence
                // the scheduler can actually parse. Validating with a different
                // rule than the one that runs it is how "it synced fine" turns
                // into a hunt that never fires.
                crate::scheduler::service::validate_cron(expr).map_err(|e| {
                    HuntSpecError::InvalidSchedule {
                        expr: expr.to_string(),
                        detail: e.to_string(),
                    }
                })?;
                Some(expr.to_string())
            }
        };

        let schedule_timezone = match fm.timezone.as_deref().map(str::trim) {
            None | Some("") => DEFAULT_TIMEZONE.to_string(),
            Some(tz) if is_plausible_timezone(tz) => tz.to_string(),
            Some(tz) => return Err(HuntSpecError::InvalidTimezone(tz.to_string())),
        };

        let lookback_window = match fm.lookback_window.as_deref().map(str::trim) {
            None | Some("") => DEFAULT_LOOKBACK_WINDOW.to_string(),
            Some(raw) => {
                let normalized = raw.to_ascii_lowercase();
                let minutes = parse_window_minutes(&normalized)
                    .ok_or_else(|| HuntSpecError::InvalidLookback(raw.to_string()))?;
                if minutes > MAX_LOOKBACK_MINUTES {
                    return Err(HuntSpecError::LookbackTooLong(
                        raw.to_string(),
                        MAX_LOOKBACK_MINUTES / (24 * 60),
                    ));
                }
                normalized
            }
        };

        let required_source_types = normalize_source_types(&fm.required_source_types)?;
        let telemetry =
            normalize_requirements(&fm.telemetry).map_err(HuntSpecError::InvalidTelemetry)?;
        let mitre_technique = fm
            .mitre_technique
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(normalize_technique)
            .transpose()?;
        let mitre_tactic = fm
            .mitre_tactic
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(normalize_tactic)
            .transpose()?;

        let budget = resolve_budget(fm)?;

        Ok(Self {
            sweep_query,
            schedule_cron,
            schedule_timezone,
            lookback_window,
            required_source_types,
            telemetry,
            mitre_tactic,
            mitre_technique,
            budget,
        })
    }
}

/// Walk every step in document order: pre-phase steps first, then each phase.
fn steps_in_order(tree: &ParsedStepTree) -> impl Iterator<Item = &PlaybookStep> {
    tree.steps
        .iter()
        .chain(tree.phases.iter().flat_map(|p| p.steps.iter()))
}

fn reject_forbidden_steps(tree: &ParsedStepTree) -> Result<(), HuntSpecError> {
    for step in steps_in_order(tree) {
        if FORBIDDEN_HUNT_STEP_KINDS.contains(&step.kind.as_str()) {
            let reason = match step.kind.as_str() {
                "action" => "an unattended sweep must not change the world",
                _ => "there is no human present to answer it",
            };
            return Err(HuntSpecError::ForbiddenStep {
                kind: step.kind.clone(),
                reason,
            });
        }
    }
    Ok(())
}

/// Render the opening data step as the sweep seed: its label, plus the
/// `from` / `window` / `where` parameters if the author supplied them.
///
/// Deliberately not the whole step body — the `note:` on a hunt step is
/// guidance for the agent and is carried in `playbooks.doc`, which the sweep
/// also reads. This field is the one-line "start here".
fn opening_step_seed(tree: &ParsedStepTree) -> Option<String> {
    let step = steps_in_order(tree).find(|s| OPENING_STEP_KINDS.contains(&s.kind.as_str()))?;
    let mut seed = step.label.trim().to_string();
    for key in ["from", "window", "where"] {
        if let Some(value) = step.params.get(key).and_then(|v| v.as_str()) {
            let value = value.trim();
            if !value.is_empty() {
                seed.push_str(&format!("\n{key}: {value}"));
            }
        }
    }
    let seed = seed.trim().to_string();
    if seed.is_empty() {
        return None;
    }
    Some(seed.truncate_on_char_boundary(MAX_SWEEP_QUERY_LEN))
}

/// `String::truncate` panics on a non-boundary index, and these strings come
/// from a file we did not write.
trait TruncateOnCharBoundary {
    fn truncate_on_char_boundary(self, max: usize) -> String;
}

impl TruncateOnCharBoundary for String {
    fn truncate_on_char_boundary(mut self, max: usize) -> String {
        if self.len() <= max {
            return self;
        }
        let mut end = max;
        while end > 0 && !self.is_char_boundary(end) {
            end -= 1;
        }
        self.truncate(end);
        self
    }
}

/// Accept `15m`, `24h`, `7d` (and the plain-number-free forms only).
///
/// A bare number is rejected on purpose. Elsewhere in the codebase a unitless
/// lookback means minutes; in a hunt file `lookback_window: 24` reads as hours
/// to every author who wrote `24h` on the line above. Guessing between the two
/// silently sweeps the wrong window, so the parse refuses and says what it
/// wanted.
fn parse_window_minutes(s: &str) -> Option<i64> {
    // Split by CHARACTER, not by byte. `str::split_at(len - 1)` panics when the
    // last character is multi-byte, and this string comes out of a file we did
    // not write — `lookback_window: 24µ` would take the process down rather
    // than fail the import.
    let mut chars = s.chars();
    let unit = chars.next_back()?;
    let value: i64 = chars.as_str().parse().ok()?;
    if value <= 0 {
        return None;
    }
    match unit {
        'm' => Some(value),
        'h' => value.checked_mul(60),
        'd' => value.checked_mul(24 * 60),
        _ => None,
    }
}

/// No tz database is linked into this crate, so this is a shape check rather
/// than a resolution: reject anything that could not be an IANA name, and let
/// the runner — which does have one — reject the rest.
fn is_plausible_timezone(tz: &str) -> bool {
    !tz.is_empty()
        && tz.len() <= 64
        && tz
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '+' | '-'))
}

fn normalize_source_types(raw: &[String]) -> Result<Vec<String>, HuntSpecError> {
    let mut out: Vec<String> = Vec::new();
    for entry in raw {
        let normalized = entry.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        if normalized.len() > MAX_SOURCE_TYPE_LEN
            || !normalized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(HuntSpecError::InvalidSourceType(entry.clone()));
        }
        if !out.contains(&normalized) {
            out.push(normalized);
        }
    }
    if out.len() > MAX_SOURCE_TYPES {
        return Err(HuntSpecError::TooManySourceTypes(out.len()));
    }
    Ok(out)
}

/// `T1021`, `T1071.001` — uppercased so the same technique written two ways
/// does not produce two coverage entries.
fn normalize_technique(raw: &str) -> Result<String, HuntSpecError> {
    let upper = raw.to_ascii_uppercase();
    let mut parts = upper.splitn(2, '.');
    let base = parts.next().unwrap_or_default();
    let sub = parts.next();
    let base_ok =
        base.len() == 5 && base.starts_with('T') && base[1..].chars().all(|c| c.is_ascii_digit());
    let sub_ok = match sub {
        None => true,
        Some(s) => s.len() == 3 && s.chars().all(|c| c.is_ascii_digit()),
    };
    if base_ok && sub_ok {
        Ok(upper)
    } else {
        Err(HuntSpecError::InvalidTechnique(raw.to_string()))
    }
}

/// ATT&CK tactic shortnames are lowercase kebab (`lateral-movement`).
fn normalize_tactic(raw: &str) -> Result<String, HuntSpecError> {
    let lower = raw.to_ascii_lowercase();
    if !lower.is_empty()
        && lower.len() <= 64
        && lower.chars().all(|c| c.is_ascii_lowercase() || c == '-')
    {
        Ok(lower)
    } else {
        Err(HuntSpecError::InvalidTactic(raw.to_string()))
    }
}

fn resolve_budget(fm: &PlaybookFrontmatter) -> Result<BudgetLimits, HuntSpecError> {
    let Some(budget) = fm.budget.as_ref() else {
        return Ok(DEFAULT_BUDGET);
    };
    Ok(BudgetLimits {
        max_turns: checked(
            budget.max_turns,
            DEFAULT_BUDGET.max_turns as i64,
            MAX_BUDGET_TURNS as i64,
            "max_turns",
        )? as u32,
        max_tool_calls: checked(
            budget.max_tool_calls,
            DEFAULT_BUDGET.max_tool_calls as i64,
            MAX_BUDGET_TOOL_CALLS as i64,
            "max_tool_calls",
        )? as u32,
        max_rows: checked(
            budget.max_rows,
            DEFAULT_BUDGET.max_rows as i64,
            MAX_BUDGET_ROWS as i64,
            "max_rows",
        )? as u64,
        max_wall_seconds: checked(
            budget.max_wall_seconds,
            DEFAULT_BUDGET.max_wall_seconds as i64,
            MAX_BUDGET_WALL_SECONDS as i64,
            "max_wall_seconds",
        )? as u64,
    })
}

fn checked(
    supplied: Option<i64>,
    default: i64,
    ceiling: i64,
    field: &'static str,
) -> Result<i64, HuntSpecError> {
    let value = match supplied {
        None => return Ok(default),
        Some(v) => v,
    };
    if value <= 0 {
        return Err(HuntSpecError::BudgetNotPositive { field });
    }
    if value > ceiling {
        return Err(HuntSpecError::BudgetTooLarge {
            field,
            value,
            ceiling,
        });
    }
    Ok(value)
}

#[cfg(test)]
#[path = "spec_tests.rs"]
mod tests;
