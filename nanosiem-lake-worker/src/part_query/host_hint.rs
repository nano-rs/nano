// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3154: candidate hints for dotless hostname literals.
//!
//! `device.hostname="ws-1"` compiles to `= 'ws-1' OR startsWith(.., 'ws-1.')`
//! (short names match FQDNs), so the compiler can emit no exact-value entity
//! hint for it: a hint must be a SUPERSET of the predicate, and the FQDN
//! spellings are unknown at compile time (NAN-2361). Every part's
//! `partials/entity_ranges.parquet` holds the complete set of stored values per
//! identity path, so the engine resolves the prefix against them and hints the
//! concrete spellings instead (`Any` of exact `Entity` hints). Row groups are
//! then pruned by the part blooms exactly as for an FQDN literal.
//!
//! Soundness: the hint is only built when EVERY part of the window has a
//! verified entity-ranges partial; the lookup matches case-insensitively (a
//! superset of the raw compiled predicate); any error, an unsupported shape or
//! more than [`MAX_ALTERNATIVES`] spellings yields no hint, which only costs
//! pruning.
//!
//! Off unless [`FLAG`] is set (forwarded by the cell supervisor).
//!
//! Cost: answers are memoized per immutable part, bounded newest-first pages
//! read the memo only (they never fetch every part's partial before their
//! first rows), and a conjunct dense enough that blooms cannot prune
//! ([`DENSITY_DIVISOR`]) gets no hint, so it keeps the unhinted plan.

use std::collections::{BTreeMap, BTreeSet};

use nanosiem_core::query::{Comparator, Query, SearchExpr, Value};
use nanosiem_core::schema::{OcsfProfile, SchemaProfile};

use super::engine::PartQueryEngine;
use super::fetch::FileSet;
use crate::parts::format::{ENTITY_RANGE_PATHS, UID_PATH};
use crate::parts::provenance::PartialKind;
use crate::planner::CandidateHint;

/// Most exact spellings one resolved conjunct may hint (beyond it the bloom
/// probes cost more than they save, and the hint is dropped).
pub const MAX_ALTERNATIVES: usize = 64;

/// One OR leg of a hintable conjunct.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Leg {
    /// Exact literal on an identity path (what the compiler would hint).
    Exact { path: String, value: String },
    /// Dotless hostname literal: `= v OR startsWith(.., 'v.')`, lowercased.
    HostPrefix { path: String, value: String },
}

/// Rollout flag (default OFF): `NANO_LAKE_DOTLESS_HOST_HINT=1` (or `true`).
/// Measured neutral-to-negative on dense hosts (a 0.1-0.3 s first lookup per
/// part set, no pruning); turn it on where sparse dotless hosts are hunted.
pub const FLAG: &str = "NANO_LAKE_DOTLESS_HOST_HINT";

pub fn enabled() -> bool {
    crate::perf_overrides::probe_flag("dotless_host_hint", std::env::var(FLAG).is_ok_and(|value| matches!(value.as_str(), "1" | "true")))
}

/// The top-level AND conjuncts of the query's source search that are OR
/// groups of identity equalities with at least one dotless hostname leg.
pub fn dotless_host_conjuncts(query: &str, field_types: &BTreeMap<String, String>) -> Vec<Vec<Leg>> {
    if !enabled() || !query.contains("hostname") {
        return Vec::new();
    }
    let Ok(parsed) = nanosiem_core::query::parse_query(query) else { return Vec::new() };
    // Subsearches read the outer selection (NAN-2961): never prune for them.
    if nanosiem_core::search::query_processing::query_has_nested_scan(&parsed) {
        return Vec::new();
    }
    let Ok(types) = serde_json::from_value(serde_json::to_value(field_types).unwrap_or_default()) else { return Vec::new() };
    let Ok(profile) = OcsfProfile::try_lake_1_9_with_snapshot_field_types(types) else { return Vec::new() };
    let mut conjuncts = Vec::new();
    collect_conjuncts(source_search(&parsed), &mut conjuncts);
    conjuncts
        .into_iter()
        .filter_map(|conjunct| {
            let mut legs = Vec::new();
            or_legs(&profile, conjunct, &mut legs)?;
            legs.sort();
            legs.dedup();
            legs.iter().any(|leg| matches!(leg, Leg::HostPrefix { .. })).then_some(legs)
        })
        .collect()
}

fn source_search(query: &Query) -> &SearchExpr {
    match query {
        Query::Search(expression) => expression,
        Query::Piped { source, .. } => source_search(source),
    }
}

fn collect_conjuncts<'a>(expression: &'a SearchExpr, out: &mut Vec<&'a SearchExpr>) {
    match expression {
        SearchExpr::And(left, right) => {
            collect_conjuncts(left, out);
            collect_conjuncts(right, out);
        }
        SearchExpr::Group(inner) => collect_conjuncts(inner, out),
        other => out.push(other),
    }
}

fn or_legs(profile: &dyn SchemaProfile, expression: &SearchExpr, out: &mut Vec<Leg>) -> Option<()> {
    match expression {
        SearchExpr::Or(left, right) => {
            or_legs(profile, left, out)?;
            or_legs(profile, right, out)
        }
        SearchExpr::Group(inner) => or_legs(profile, inner, out),
        SearchExpr::InList { field, values, negated: false } => {
            for value in values {
                out.push(leg(profile, field, value)?);
            }
            Some(())
        }
        // A bareword may be a field reference (NAN-2380); one the generator
        // reads as a value (`device.hostname=ws-1`) is its quoted spelling
        // (NAN-3162).
        SearchExpr::FieldFilter { field, op: op @ Comparator::Eq, value, rhs }
            if nanosiem_core::query::rhs_compiles_as_value(profile, field, op, value, *rhs) =>
        {
            out.push(leg(profile, field, value)?);
            Some(())
        }
        _ => None,
    }
}

fn leg(profile: &dyn SchemaProfile, field: &str, value: &Value) -> Option<Leg> {
    let Value::String(text) = value else { return None };
    let path = profile.canonicalize(field).to_string();
    let text = text.trim();
    if path == UID_PATH
        // The resolver reads entity-range rows (NAN-3694).
        || !ENTITY_RANGE_PATHS.contains(&path.as_str())
        || text.is_empty()
        || text.len() > 2_048
        || !text.is_ascii()
        || text.contains(['*', '?', '/'])
        || text.chars().any(char::is_control)
    {
        return None;
    }
    if nanosiem_core::query::hostname_equality_expands(profile, field, text) {
        Some(Leg::HostPrefix { path, value: text.to_ascii_lowercase() })
    } else {
        Some(Leg::Exact { path, value: text.to_string() })
    }
}

/// A row group holding none of a conjunct's values is what a bloom prunes.
/// When the window's matching events reach a quarter of its row groups,
/// spread rows leave almost every group holding one, so the hint would only
/// route the query through the hinted (preselect + chunked) path for nothing.
/// Measured on a 12 h real tenant: every host was in 117/118 row groups and
/// the hinted path made a dotless `| head 100` 3x slower.
pub const DENSITY_DIVISOR: u64 = 4;
/// Tests set this to 0 to force hints on tiny fixtures (`u64::MAX`: unset).
#[cfg(test)]
pub(crate) static TEST_DENSITY_DIVISOR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

fn density_divisor() -> u64 {
    #[cfg(test)]
    {
        let divisor = TEST_DENSITY_DIVISOR.load(std::sync::atomic::Ordering::Relaxed);
        if divisor != u64::MAX {
            return divisor;
        }
    }
    DENSITY_DIVISOR
}

/// Memoized lookups per process (immutable parts: an answer never changes).
const MEMO_ENTRIES: usize = 16_384;
/// Most matching (part, value) rows one lookup may return.
const MAX_LOOKUP_ROWS: usize = 4_096;

/// One lookup term: an exact identity literal, or a dotless prefix leg.
type Term = (String, String, bool);
/// (tenant, part, term) -> matching stored spellings and their events.
type MemoKey = (String, crate::parts::format::PartId, Term);

fn memo() -> &'static std::sync::Mutex<BTreeMap<MemoKey, Vec<(String, u64)>>> {
    static MEMO: std::sync::OnceLock<std::sync::Mutex<BTreeMap<MemoKey, Vec<(String, u64)>>>> = std::sync::OnceLock::new();
    MEMO.get_or_init(Default::default)
}

fn term_of(leg: &Leg) -> Term {
    match leg {
        Leg::Exact { path, value } => (path.clone(), value.to_ascii_lowercase(), false),
        Leg::HostPrefix { path, value } => (path.clone(), value.clone(), true),
    }
}

fn term_matches(term: &Term, path: &str, value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    term.0 == path && (lowered == term.1 || (term.2 && lowered.strip_prefix(term.1.as_str()).is_some_and(|rest| rest.starts_with('.'))))
}

/// Resolve each conjunct against the window's entity-ranges partials. Returns
/// one `Any` hint per sparse, resolvable conjunct (AND semantics with the
/// compiler's hints); nothing whenever soundness is unproven. `fetch: false`
/// answers from the memo only: a bounded page must not fetch every part's
/// partial before its first rows (the membership rule).
pub async fn resolve(engine: &PartQueryEngine, conjuncts: &[Vec<Leg>], from_us: i64, to_us: i64, fetch: bool) -> Vec<CandidateHint> {
    if conjuncts.is_empty() {
        return Vec::new();
    }
    match resolve_inner(engine, conjuncts, from_us, to_us, fetch).await {
        Ok(hints) => hints,
        Err(error) => {
            tracing::debug!(error = %error, "dotless hostname hint unresolved; no hint");
            Vec::new()
        }
    }
}

async fn resolve_inner(
    engine: &PartQueryEngine,
    conjuncts: &[Vec<Leg>],
    from_us: i64,
    to_us: i64,
    fetch: bool,
) -> super::engine::QueryResult<Vec<CandidateHint>> {
    let unavailable = |error: anyhow::Error| super::engine::PartQueryError::Unavailable(format!("{error:#}"));
    let tenant = engine.settings().tenant_id.clone();
    let (parts, ..) = engine.snapshot(from_us, to_us).await?;
    if parts.is_empty() {
        return Ok(Vec::new());
    }
    let terms = conjuncts.iter().flatten().map(term_of).collect::<BTreeSet<_>>();
    let pending = {
        let memo = memo().lock().expect("host hint memo");
        parts
            .iter()
            .filter(|part| terms.iter().any(|term| !memo.contains_key(&(tenant.clone(), part.part_id.clone(), term.clone()))))
            .cloned()
            .collect::<Vec<_>>()
    };
    if !pending.is_empty() {
        if !fetch {
            return Ok(Vec::new());
        }
        let records = engine.fetcher().records(&pending).await.map_err(unavailable)?;
        if records.iter().any(|record| !record.files.partials.iter().any(|partial| partial.kind == PartialKind::EntityRanges)) {
            return Ok(Vec::new());
        }
        let local = engine.fetcher().ensure(&pending, &[FileSet::Partial(PartialKind::EntityRanges)]).await.map_err(unavailable)?;
        let by_path = local
            .of(FileSet::Partial(PartialKind::EntityRanges))
            .map(|file| (file.path.to_string_lossy().to_string(), file.part_id.clone()))
            .collect::<BTreeMap<_, _>>();
        if by_path.len() != pending.len() {
            return Ok(Vec::new());
        }
        let mut paths = by_path.keys().map(std::path::PathBuf::from).collect::<Vec<_>>();
        paths.sort();
        let mut params = vec![("partials".to_string(), super::partials::path_set(&paths)?)];
        let mut arms = Vec::new();
        for (index, (path, value, prefix)) in terms.iter().enumerate() {
            params.push((format!("p{index}"), path.clone()));
            params.push((format!("v{index}"), value.clone()));
            let prefix_arm = if *prefix {
                params.push((format!("d{index}"), format!("{value}.")));
                format!(" OR startsWith(lower(value), {{d{index}:String}})")
            } else {
                String::new()
            };
            arms.push(format!("(path = {{p{index}:String}} AND (lower(value) = {{v{index}:String}}{prefix_arm}))"));
        }
        let sql = format!(
            "SELECT _path AS file, path, value, sum(events) AS events FROM file({{partials:String}}, Parquet) \
             WHERE {} GROUP BY file, path, value LIMIT {}{}",
            arms.join(" OR "),
            MAX_LOOKUP_ROWS + 1,
            super::partials::settings(engine)
        );
        let rows = engine.execute_sql(sql, params).await?;
        drop(local);
        if rows.len() > MAX_LOOKUP_ROWS {
            return Ok(Vec::new());
        }
        let mut answers: BTreeMap<MemoKey, Vec<(String, u64)>> = BTreeMap::new();
        for part in &pending {
            for term in &terms {
                answers.insert((tenant.clone(), part.part_id.clone(), term.clone()), Vec::new());
            }
        }
        for row in &rows {
            let (Some(file), Some(path), Some(value)) = (row["file"].as_str(), row["path"].as_str(), row["value"].as_str()) else {
                return Ok(Vec::new());
            };
            let Some(part_id) = by_path.get(file) else { return Ok(Vec::new()) };
            let events = row["events"].as_u64().or_else(|| row["events"].as_str().and_then(|text| text.parse().ok())).unwrap_or(u64::MAX);
            for term in terms.iter().filter(|term| term_matches(term, path, value)) {
                if let Some(found) = answers.get_mut(&(tenant.clone(), part_id.clone(), term.clone())) {
                    found.push((value.to_string(), events));
                }
            }
        }
        let mut memo = memo().lock().expect("host hint memo");
        if memo.len() + answers.len() > MEMO_ENTRIES {
            memo.clear();
        }
        memo.extend(answers);
    }
    let memo = memo().lock().expect("host hint memo");
    let row_groups = parts.iter().map(|part| u64::from(part.row_groups)).sum::<u64>();
    let mut hints = Vec::new();
    for legs in conjuncts {
        let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut events = 0_u64;
        for leg in legs {
            let term = term_of(leg);
            for part in &parts {
                let Some(matches) = memo.get(&(tenant.clone(), part.part_id.clone(), term.clone())) else { return Ok(Vec::new()) };
                for (value, count) in matches {
                    events = events.saturating_add(*count);
                    found.entry(term.0.clone()).or_default().insert(value.clone());
                }
            }
        }
        if events.saturating_mul(density_divisor()) > row_groups {
            continue;
        }
        if let Some(hint) = hint_for(legs, &found) {
            hints.push(hint);
        }
    }
    Ok(hints)
}

/// The `Any` hint of one conjunct given the stored spellings `found` per path
/// (case-insensitive superset of every prefix leg). `None` past the bound.
pub fn hint_for(legs: &[Leg], found: &BTreeMap<String, BTreeSet<String>>) -> Option<CandidateHint> {
    let mut alternatives = BTreeSet::new();
    for leg in legs {
        match leg {
            Leg::Exact { path, value } => {
                alternatives.insert((path.clone(), value.clone()));
                for stored in found.get(path).into_iter().flatten() {
                    if stored.eq_ignore_ascii_case(value) {
                        alternatives.insert((path.clone(), stored.clone()));
                    }
                }
            }
            Leg::HostPrefix { path, value } => {
                // The literal itself is always probed (exact short name).
                alternatives.insert((path.clone(), value.clone()));
                let dotted = format!("{value}.");
                for stored in found.get(path).into_iter().flatten() {
                    let lowered = stored.to_ascii_lowercase();
                    if lowered == *value || lowered.starts_with(&dotted) {
                        alternatives.insert((path.clone(), stored.clone()));
                    }
                }
            }
        }
    }
    if alternatives.is_empty() || alternatives.len() > MAX_ALTERNATIVES {
        return None;
    }
    Some(CandidateHint::Any {
        alternatives: alternatives
            .into_iter()
            .map(|(source_path, value)| CandidateHint::Entity { source_path, value })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types() -> BTreeMap<String, String> {
        ["device.hostname", "src_endpoint.hostname", "dst_endpoint.hostname", "src_endpoint.ip", "user.name", "metadata.log_source"]
            .into_iter()
            .map(|path| (path.to_string(), "string".to_string()))
            .chain([("time".to_string(), "timestamp".to_string())])
            .collect()
    }

    #[test]
    fn only_dotless_host_conjuncts_are_hintable() {
        // Flag tests share the process environment; only this one sets it.
        std::env::set_var(FLAG, "1");
        let types = types();
        assert_eq!(
            dotless_host_conjuncts(r#"device.hostname="WS-1" | head 5"#, &types),
            vec![vec![Leg::HostPrefix { path: "device.hostname".into(), value: "ws-1".into() }]]
        );
        // FQDN: the compiler already hints it exactly.
        assert!(dotless_host_conjuncts(r#"device.hostname="ws-1.corp.local""#, &types).is_empty());
        // OR with an exact identity leg keeps both legs.
        assert_eq!(
            dotless_host_conjuncts(r#"(src_endpoint.hostname="ws-1" OR src_endpoint.ip="10.0.0.1") metadata.log_source="x""#, &types),
            vec![vec![
                Leg::Exact { path: "src_endpoint.ip".into(), value: "10.0.0.1".into() },
                Leg::HostPrefix { path: "src_endpoint.hostname".into(), value: "ws-1".into() },
            ]]
        );
        // An OR with a non-identity leg, a negation, or a wildcard is not hintable.
        assert!(dotless_host_conjuncts(r#"device.hostname="ws-1" OR metadata.log_source="x""#, &types).is_empty());
        assert!(dotless_host_conjuncts(r#"NOT device.hostname="ws-1""#, &types).is_empty());
        assert!(dotless_host_conjuncts(r#"device.hostname="ws-*""#, &types).is_empty());
        assert!(dotless_host_conjuncts(r#"device.hostname!="ws-1""#, &types).is_empty());
        // NAN-3162: a bareword VALUE is its quoted spelling; a bareword that
        // names a column is a field reference and is never hinted.
        assert_eq!(
            dotless_host_conjuncts("device.hostname=WS1 | head 5", &types),
            dotless_host_conjuncts(r#"device.hostname="WS1" | head 5"#, &types),
        );
        assert_eq!(
            dotless_host_conjuncts("device.hostname=ws1", &types),
            vec![vec![Leg::HostPrefix { path: "device.hostname".into(), value: "ws1".into() }]]
        );
        assert!(dotless_host_conjuncts("device.hostname=src_endpoint.hostname", &types).is_empty());
    }

    #[test]
    fn terms_match_like_the_compiled_predicate_case_insensitively() {
        let prefix = term_of(&Leg::HostPrefix { path: "device.hostname".into(), value: "ws-1".into() });
        assert!(term_matches(&prefix, "device.hostname", "WS-1"));
        assert!(term_matches(&prefix, "device.hostname", "ws-1.Corp.Local"));
        assert!(!term_matches(&prefix, "device.hostname", "ws-10.corp.local"));
        assert!(!term_matches(&prefix, "src_endpoint.hostname", "ws-1"));
        let exact = term_of(&Leg::Exact { path: "src_endpoint.ip".into(), value: "FE80::1".into() });
        assert!(term_matches(&exact, "src_endpoint.ip", "fe80::1"));
        assert!(!term_matches(&exact, "src_endpoint.ip", "fe80::1.x"), "exact legs never prefix-match");
    }

    #[test]
    fn hint_is_a_superset_of_the_prefix_predicate() {
        let legs = vec![Leg::HostPrefix { path: "device.hostname".into(), value: "ws-1".into() }];
        let found = BTreeMap::from([(
            "device.hostname".to_string(),
            BTreeSet::from(["ws-1.corp.local".to_string(), "WS-1.Lab".to_string(), "ws-10.corp.local".to_string()]),
        )]);
        let Some(CandidateHint::Any { alternatives }) = hint_for(&legs, &found) else { panic!("hint") };
        let values = alternatives
            .iter()
            .map(|hint| match hint {
                CandidateHint::Entity { value, .. } => value.as_str(),
                other => panic!("{other:?}"),
            })
            .collect::<Vec<_>>();
        // `ws-10.*` does not match `ws-1` or `ws-1.*`; the literal stays.
        assert_eq!(values, vec!["WS-1.Lab", "ws-1", "ws-1.corp.local"]);
        let many = BTreeMap::from([(
            "device.hostname".to_string(),
            (0..MAX_ALTERNATIVES).map(|i| format!("ws-1.d{i}")).collect::<BTreeSet<_>>(),
        )]);
        assert!(hint_for(&legs, &many).is_none(), "past the bound: no hint");
    }
}
