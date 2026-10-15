// SPDX-License-Identifier: AGPL-3.0-or-later

//! Watchlist entity suggestions (NAN-3249).
//!
//! Watchlist members match risk entities by EXACT normalized value (trim +
//! lowercase, [`super::watchlist::normalize_entity_value`]), so `jsmith`
//! never scores `CORP\jsmith` or `jsmith@corp.com`, and `web01` never scores
//! `web01.corp.local`. When an analyst types a value, the API looks up the
//! tenant's observed risk entities over [`SUGGEST_LOOKBACK_DAYS`] and offers
//! the observed variants, plus a `seen` flag ("no exact match: may never
//! score").
//!
//! This module is the pure half shared by both backends:
//!
//! * [`plan`] turns the typed values into a bounded list of match patterns
//!   (exact / prefix / suffix on the LOWERCASED entity). Matching is done with
//!   `=` / `startsWith` / `endsWith` — never `LIKE` — so `%` and `_` in a typed
//!   value are literal characters, and every pattern is a bound parameter.
//! * The lake worker (`risk_operation: "suggest"`) and the dedicated
//!   ClickHouse builder ([`super::clickhouse_sql::watchlist_suggest_query`])
//!   return [`RiskSuggestRow`]s: distinct entities that matched a pattern,
//!   at most [`SUGGEST_ROWS_PER_VALUE`] per value, under the caller's source
//!   scope.
//! * [`assemble`] re-checks every row against its pattern (a backend bug can
//!   never attribute a row to the wrong value), folds case variants, and caps
//!   the variants per value at [`SUGGEST_MAX_PER_VALUE`].

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::watchlist::{detect_entity_type, normalize_entity_value, WatchEntityType};

/// At most this many typed values per suggest request.
pub const SUGGEST_MAX_VALUES: usize = 50;
/// At most this many variant suggestions per typed value.
pub const SUGGEST_MAX_PER_VALUE: usize = 10;
/// Rows a backend may return per value: the variant cap plus headroom for
/// the exact matches (case variants of the value and of a host short name)
/// that sort first.
pub const SUGGEST_ROWS_PER_VALUE: u64 = 16;
/// Observation window. The lake risk ledger's detail horizon is 28 days
/// (`lookback_days` is bounded `1..=28` by the worker), and the dedicated
/// ClickHouse reader uses the same window so both modes answer alike.
pub const SUGGEST_LOOKBACK_DAYS: i64 = 28;
/// Upper bound on patterns per request (at most five per value).
pub const SUGGEST_MAX_PATTERNS: usize = SUGGEST_MAX_VALUES * 5;

/// How a pattern compares against the LOWERCASED observed entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestOp {
    Exact,
    Prefix,
    Suffix,
}

impl SuggestOp {
    /// Numeric code bound into SQL (`0` exact, `1` prefix, `2` suffix).
    pub fn code(self) -> u8 {
        match self {
            Self::Exact => 0,
            Self::Prefix => 1,
            Self::Suffix => 2,
        }
    }

    /// The same comparison the SQL performs, for [`assemble`]'s re-check.
    pub fn matches(self, lowered_entity: &str, text: &str) -> bool {
        match self {
            Self::Exact => lowered_entity == text,
            Self::Prefix => lowered_entity.starts_with(text),
            Self::Suffix => lowered_entity.ends_with(text),
        }
    }
}

/// One bound match pattern. `group` is the index of the typed value it
/// belongs to. Wire type of the lake worker's `suggest` operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskSuggestPattern {
    pub group: u16,
    pub op: SuggestOp,
    pub text: String,
}

/// Why a suggestion was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuggestMatchKind {
    /// The typed value itself (feeds `seen`; never a suggestion).
    Exact,
    /// `<domain>\value`.
    DomainUser,
    /// `value@<domain>`.
    UserPrincipal,
    /// `value.<domain>`.
    Fqdn,
    /// The short (first-label) name of a typed FQDN.
    ShortName,
}

/// One typed value, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedValue {
    pub value: String,
    pub entity_type: WatchEntityType,
}

/// The bounded pattern set for one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuggestPlan {
    pub values: Vec<PlannedValue>,
    pub patterns: Vec<RiskSuggestPattern>,
    /// Parallel to `patterns`.
    pub kinds: Vec<SuggestMatchKind>,
}

/// A suggest input (same shape as a member input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestInput {
    pub value: String,
    pub entity_type: Option<WatchEntityType>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SuggestPlanError(pub String);

/// Build the pattern set. Values are normalized exactly like members
/// (trim + lowercase) and deduplicated; 1..=[`SUGGEST_MAX_VALUES`] values.
///
/// Per value `v` (type explicit, else detected):
/// * always: exact `v`;
/// * users: suffix `\v`, and prefix `v@` unless `v` already has an `@`;
/// * hosts: prefix `v.`, and exact short name (first label) of a typed FQDN;
/// * a dotless value with NO explicit type is detected as a user but may be
///   a bare host name, so it also gets the host prefix `v.`;
/// * ip / hash: exact only.
pub fn plan(inputs: &[SuggestInput]) -> Result<SuggestPlan, SuggestPlanError> {
    if inputs.is_empty() || inputs.len() > SUGGEST_MAX_VALUES {
        return Err(SuggestPlanError(format!(
            "provide 1-{SUGGEST_MAX_VALUES} entity values"
        )));
    }
    let mut out = SuggestPlan::default();
    for input in inputs {
        let value = normalize_entity_value(&input.value).map_err(|e| SuggestPlanError(e.0))?;
        if out.values.iter().any(|planned| planned.value == value) {
            continue;
        }
        let explicit = input.entity_type;
        let entity_type = explicit.unwrap_or_else(|| detect_entity_type(&value));
        let group = out.values.len() as u16;
        let mut push = |op: SuggestOp, text: String, kind: SuggestMatchKind| {
            if text.is_empty() {
                return;
            }
            if out
                .patterns
                .iter()
                .any(|p| p.group == group && p.op == op && p.text == text)
            {
                return;
            }
            out.patterns.push(RiskSuggestPattern { group, op, text });
            out.kinds.push(kind);
        };
        push(SuggestOp::Exact, value.clone(), SuggestMatchKind::Exact);
        let bare = !value.contains('@') && !value.contains('\\');
        match entity_type {
            WatchEntityType::User => {
                push(SuggestOp::Suffix, format!("\\{value}"), SuggestMatchKind::DomainUser);
                if !value.contains('@') {
                    push(SuggestOp::Prefix, format!("{value}@"), SuggestMatchKind::UserPrincipal);
                }
                if explicit.is_none() && bare && !value.contains('.') {
                    push(SuggestOp::Prefix, format!("{value}."), SuggestMatchKind::Fqdn);
                }
            }
            WatchEntityType::Host => {
                if bare {
                    push(SuggestOp::Prefix, format!("{value}."), SuggestMatchKind::Fqdn);
                    if let Some((short, _)) = value.split_once('.') {
                        push(SuggestOp::Exact, short.to_string(), SuggestMatchKind::ShortName);
                    }
                }
            }
            WatchEntityType::Ip | WatchEntityType::Hash => {}
        }
        out.values.push(PlannedValue { value, entity_type });
    }
    debug_assert!(out.patterns.len() <= SUGGEST_MAX_PATTERNS);
    Ok(out)
}

/// One candidate row from either backend: a distinct observed entity and
/// the FIRST pattern (1-based index into the plan) it matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, clickhouse::Row)]
pub struct RiskSuggestRow {
    pub value_index: u16,
    pub entity: String,
    pub entity_type: String,
    pub last_seen_us: i64,
    pub pattern_index: u32,
}

/// One observed variant of a typed value.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct RiskWatchlistSuggestion {
    /// Normalized (lowercase) observed entity value; one click adds it.
    pub value: String,
    /// Observed risk entity type (`user`, `email`, `hostname`, `ip`,
    /// `cloud_account`).
    pub entity_type: String,
    pub last_seen: DateTime<Utc>,
    pub match_kind: SuggestMatchKind,
}

/// Suggestions and the `seen` flag for one typed value.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct RiskWatchlistSuggestResult {
    /// The normalized typed value.
    pub value: String,
    pub entity_type: WatchEntityType,
    /// An exact (case-insensitive) match exists in the window. `false` means
    /// the value may never score.
    pub seen: bool,
    pub last_seen: Option<DateTime<Utc>>,
    /// At most 10 observed variants, newest first (never the value itself).
    pub suggestions: Vec<RiskWatchlistSuggestion>,
}

/// Fold backend rows into one result per planned value.
pub fn assemble(plan: &SuggestPlan, rows: &[RiskSuggestRow]) -> Vec<RiskWatchlistSuggestResult> {
    let mut results: Vec<RiskWatchlistSuggestResult> = plan
        .values
        .iter()
        .map(|planned| RiskWatchlistSuggestResult {
            value: planned.value.clone(),
            entity_type: planned.entity_type,
            seen: false,
            last_seen: None,
            suggestions: Vec::new(),
        })
        .collect();
    // (group, normalized variant) -> (last_seen_us, kind, observed type)
    let mut variants: BTreeMap<(usize, String), (i64, SuggestMatchKind, String)> = BTreeMap::new();
    for row in rows {
        let Some(index) = (row.pattern_index as usize).checked_sub(1) else {
            continue;
        };
        let (Some(pattern), Some(kind)) = (plan.patterns.get(index), plan.kinds.get(index)) else {
            continue;
        };
        let group = pattern.group as usize;
        if row.value_index as usize != group || group >= results.len() {
            continue;
        }
        let lowered = row.entity.to_lowercase();
        if !pattern.op.matches(&lowered, &pattern.text) {
            continue;
        }
        let Ok(normalized) = normalize_entity_value(&row.entity) else {
            continue;
        };
        let result = &mut results[group];
        if normalized == result.value {
            result.seen = true;
            let at = DateTime::from_timestamp_micros(row.last_seen_us);
            if at > result.last_seen {
                result.last_seen = at;
            }
            continue;
        }
        let entry = variants
            .entry((group, normalized))
            .or_insert((row.last_seen_us, *kind, row.entity_type.clone()));
        if row.last_seen_us > entry.0 {
            *entry = (row.last_seen_us, *kind, row.entity_type.clone());
        }
    }
    for ((group, value), (last_seen_us, match_kind, entity_type)) in variants {
        let Some(last_seen) = DateTime::from_timestamp_micros(last_seen_us) else {
            continue;
        };
        results[group].suggestions.push(RiskWatchlistSuggestion {
            value,
            entity_type,
            last_seen,
            match_kind,
        });
    }
    for result in &mut results {
        result
            .suggestions
            .sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.value.cmp(&b.value)));
        result.suggestions.truncate(SUGGEST_MAX_PER_VALUE);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(value: &str) -> SuggestInput {
        SuggestInput { value: value.into(), entity_type: None }
    }

    fn typed(value: &str, entity_type: WatchEntityType) -> SuggestInput {
        SuggestInput { value: value.into(), entity_type: Some(entity_type) }
    }

    fn patterns(plan: &SuggestPlan, group: u16) -> Vec<(SuggestOp, &str, SuggestMatchKind)> {
        plan.patterns
            .iter()
            .zip(&plan.kinds)
            .filter(|(p, _)| p.group == group)
            .map(|(p, k)| (p.op, p.text.as_str(), *k))
            .collect()
    }

    #[test]
    fn plans_user_host_and_exact_only_patterns() {
        let plan = plan(&[
            input(" JSmith "),
            input("web01.corp.local"),
            typed("svc", WatchEntityType::User),
            input("10.0.0.5"),
            input("jsmith@corp.com"),
        ])
        .unwrap();
        assert_eq!(plan.values[0].value, "jsmith");
        assert_eq!(
            patterns(&plan, 0),
            vec![
                (SuggestOp::Exact, "jsmith", SuggestMatchKind::Exact),
                (SuggestOp::Suffix, "\\jsmith", SuggestMatchKind::DomainUser),
                (SuggestOp::Prefix, "jsmith@", SuggestMatchKind::UserPrincipal),
                // Undeclared dotless value: may be a bare host name.
                (SuggestOp::Prefix, "jsmith.", SuggestMatchKind::Fqdn),
            ]
        );
        assert_eq!(
            patterns(&plan, 1),
            vec![
                (SuggestOp::Exact, "web01.corp.local", SuggestMatchKind::Exact),
                (SuggestOp::Prefix, "web01.corp.local.", SuggestMatchKind::Fqdn),
                (SuggestOp::Exact, "web01", SuggestMatchKind::ShortName),
            ]
        );
        // Explicit user: no host guess.
        assert_eq!(patterns(&plan, 2).len(), 3);
        assert_eq!(patterns(&plan, 3), vec![(SuggestOp::Exact, "10.0.0.5", SuggestMatchKind::Exact)]);
        assert_eq!(
            patterns(&plan, 4),
            vec![
                (SuggestOp::Exact, "jsmith@corp.com", SuggestMatchKind::Exact),
                (SuggestOp::Suffix, "\\jsmith@corp.com", SuggestMatchKind::DomainUser),
            ]
        );
    }

    #[test]
    fn plan_is_bounded_and_validated() {
        assert!(plan(&[]).is_err());
        let fifty: Vec<_> = (0..SUGGEST_MAX_VALUES).map(|i| input(&format!("user{i}"))).collect();
        let ok = plan(&fifty).unwrap();
        assert_eq!(ok.values.len(), SUGGEST_MAX_VALUES);
        assert!(ok.patterns.len() <= SUGGEST_MAX_PATTERNS);
        let mut too_many = fifty.clone();
        too_many.push(input("one-more"));
        assert!(plan(&too_many).is_err());
        assert!(plan(&[input("   ")]).is_err());
        assert!(plan(&[input("a\u{0007}b")]).is_err());
        assert!(plan(&[input("10.0.0.0/8")]).is_err());
        // Duplicates (after normalization) collapse to one value.
        assert_eq!(plan(&[input("Bob"), input("bob ")]).unwrap().values.len(), 1);
    }

    /// LIKE metacharacters are literal: the patterns are compared with
    /// `=` / startsWith / endsWith, never LIKE, so `a_b` / `100%` cannot
    /// widen a match.
    #[test]
    fn like_metacharacters_are_literal() {
        let plan = plan(&[input("a_b"), input("100%")]).unwrap();
        for pattern in &plan.patterns {
            if pattern.text.contains('_') {
                assert!(!pattern.op.matches("axb", &pattern.text));
                assert!(!pattern.op.matches("corp\\axb", &pattern.text));
                assert!(!pattern.op.matches("axb@corp.com", &pattern.text));
            }
            if pattern.text.contains('%') {
                assert!(!pattern.op.matches("1000", &pattern.text));
                assert!(!pattern.op.matches("100xyz@corp.com", &pattern.text));
            }
        }
        let rows = vec![
            row(0, "AXB", "user", 10, 1),
            row(0, "corp\\axb", "user", 10, 2),
            row(1, "1000", "user", 10, 1),
            row(0, "CORP\\A_B", "user", 20, 2),
        ];
        let results = assemble(&plan, &rows);
        assert!(!results[0].seen);
        assert_eq!(results[0].suggestions.len(), 1);
        assert_eq!(results[0].suggestions[0].value, "corp\\a_b");
        assert!(!results[1].seen && results[1].suggestions.is_empty());
    }

    fn row(value_index: u16, entity: &str, entity_type: &str, last_seen_us: i64, pattern_index: u32) -> RiskSuggestRow {
        RiskSuggestRow {
            value_index,
            entity: entity.into(),
            entity_type: entity_type.into(),
            last_seen_us,
            pattern_index,
        }
    }

    #[test]
    fn assemble_sets_seen_folds_case_and_caps_variants() {
        let plan = plan(&[input("jsmith"), input("ghost")]).unwrap();
        let mut rows = vec![
            row(0, "JSmith", "user", 1_000, 1),
            row(0, "jsmith", "user", 5_000, 1),
            row(0, "CORP\\jsmith", "user", 4_000, 2),
            row(0, "corp\\JSMITH", "user", 9_000, 2),
            row(0, "jsmith@corp.com", "email", 3_000, 3),
        ];
        for i in 0..20 {
            rows.push(row(0, &format!("jsmith@d{i}.io"), "email", 100 + i, 3));
        }
        let results = assemble(&plan, &rows);
        let jsmith = &results[0];
        assert!(jsmith.seen);
        assert_eq!(jsmith.last_seen, DateTime::from_timestamp_micros(5_000));
        assert_eq!(jsmith.suggestions.len(), SUGGEST_MAX_PER_VALUE);
        assert_eq!(jsmith.suggestions[0].value, "corp\\jsmith");
        assert_eq!(jsmith.suggestions[0].last_seen, DateTime::from_timestamp_micros(9_000).unwrap());
        assert_eq!(jsmith.suggestions[0].match_kind, SuggestMatchKind::DomainUser);
        assert_eq!(jsmith.suggestions[1].value, "jsmith@corp.com");
        assert_eq!(jsmith.suggestions[1].entity_type, "email");
        assert!(jsmith.suggestions.iter().all(|s| s.value != "jsmith"));
        // Never seen: the warning flag.
        assert!(!results[1].seen);
        assert!(results[1].last_seen.is_none());
        assert!(results[1].suggestions.is_empty());
    }

    #[test]
    fn assemble_rejects_rows_that_do_not_match_their_pattern_or_group() {
        let plan = plan(&[input("alice"), input("bob")]).unwrap();
        let rows = vec![
            // Claims bob's exact pattern but is attributed to alice.
            row(0, "bob", "user", 1, 5),
            // Correct group, but the entity does not match the pattern.
            row(0, "mallory", "user", 1, 1),
            row(0, "alice2", "user", 1, 3),
            // Out-of-range / zero pattern indexes.
            row(0, "alice", "user", 1, 0),
            row(0, "alice", "user", 1, 999),
            row(7, "alice", "user", 1, 1),
        ];
        let results = assemble(&plan, &rows);
        assert!(!results[0].seen && results[0].suggestions.is_empty());
        assert!(!results[1].seen && results[1].suggestions.is_empty());
    }

    #[test]
    fn host_short_name_and_fqdn_variants() {
        let plan = plan(&[input("Web01.corp.local"), input("db02")]).unwrap();
        let short = plan.kinds.iter().position(|k| *k == SuggestMatchKind::ShortName).unwrap() as u32 + 1;
        let fqdn = plan
            .patterns
            .iter()
            .position(|p| p.group == 1 && p.op == SuggestOp::Prefix && p.text == "db02.")
            .unwrap() as u32
            + 1;
        let results = assemble(
            &plan,
            &[row(0, "WEB01", "user", 7, short), row(1, "db02.corp.local", "hostname", 8, fqdn)],
        );
        assert!(!results[0].seen);
        assert_eq!(results[0].suggestions[0].value, "web01");
        assert_eq!(results[0].suggestions[0].match_kind, SuggestMatchKind::ShortName);
        assert_eq!(results[1].suggestions[0].value, "db02.corp.local");
        assert_eq!(results[1].suggestions[0].match_kind, SuggestMatchKind::Fqdn);
    }
}
