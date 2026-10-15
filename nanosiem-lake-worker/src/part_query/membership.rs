// SPDX-License-Identifier: AGPL-3.0-or-later

//! Value-membership pruning from the parts' rollup partials (P0 design
//! change 1: serve selective predicates from per-part indexes, not scans).
//!
//! The rollup partial (contract 3.2) holds, per 5-minute bucket, every value
//! seen for each of the 74 `COUNT_ROLLUP_FIELDS` (log source, users, hosts,
//! IPs, process names, all hash paths, …). That is a per-part, per-bucket
//! membership index. For a query whose search is an AND of equality
//! predicates (or ORs of them) on those fields, one chDB statement over the
//! selected parts' rollups returns the `(part, bucket)` pairs where every
//! predicate can hold. Parts with no such bucket are never fetched; within a
//! kept part only row groups whose time range touches a matching bucket are
//! read (parts are time-sorted, so row-group time statistics are tight).
//!
//! **Soundness.** Every extracted constraint is a superset of what the SQL
//! accepts, tested against the complete per-bucket value set: equality,
//! contains/starts/ends-with, `*` wildcards (ILIKE) and positive regexes
//! (`(?i)`) all compare case-insensitively; host fields that expand dotless
//! names also accept `v.` prefixes. CIDRs, IPv6, numbers, field references,
//! `NOT` and `!=` contribute no constraint. The complete
//! compiled predicate is always re-evaluated over the surviving rows. A part
//! without a rollup partial is kept.

use nanosiem_core::query::{Comparator, Query, RhsSyntax, SearchExpr, Value};
use nanosiem_core::schema::{OcsfProfile, SchemaProfile};
use std::collections::{BTreeMap, BTreeSet};

use crate::rollup::{COUNT_ROLLUP_BUCKET_US, COUNT_ROLLUP_FIELDS};

/// How a value is tested (all case-insensitive supersets of the SQL).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Test {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    /// `*`/`?` wildcard equality, as an ILIKE pattern.
    Like,
    /// A positive regex, evaluated with `(?i)`.
    Regex,
}

/// One accepted value of a field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Matcher {
    pub field_id: u16,
    pub test: Test,
    /// Lowercased literal (the raw pattern for `Regex`).
    pub value: String,
    /// Also accept `value.` prefixes (dotless host names expand to FQDNs).
    pub host_prefix: bool,
}

/// AND of OR-groups.
pub type Constraints = Vec<Vec<Matcher>>;

/// Bound on extracted matchers (the membership statement stays small).
const MAX_MATCHERS: usize = 64;

fn field_id(path: &str) -> Option<u16> {
    COUNT_ROLLUP_FIELDS.iter().find(|field| field.source_path == path).map(|field| field.field_id)
}

fn matcher(profile: &dyn SchemaProfile, expression: &SearchExpr) -> Option<Matcher> {
    let SearchExpr::FieldFilter { field, op, value, rhs } = expression else { return None };
    let canonical = profile.canonicalize(field).to_string();
    let field_id = field_id(&canonical)?;
    if let (Comparator::Regex, Value::Regex(pattern)) = (op, value) {
        if pattern.is_empty() || pattern.len() > 1_024 || regex_syntax::Parser::new().parse(pattern).is_err() {
            return None;
        }
        return Some(Matcher { field_id, test: Test::Regex, value: pattern.clone(), host_prefix: false });
    }
    let text = match value {
        Value::String(text) => text.clone(),
        Value::Ip(std::net::IpAddr::V4(ip)) => ip.to_string(),
        _ => return None,
    };
    // A bareword that names a known field is a field reference (NAN-2380).
    if matches!(rhs, RhsSyntax::Bareword) && profile.is_known_field(&text) {
        return None;
    }
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > 2_048 {
        return None;
    }
    let lower = trimmed.to_lowercase();
    let test = match op {
        Comparator::Eq if trimmed.contains(['/', ':']) => return None,
        Comparator::Eq if lower.trim_matches('*').is_empty() => return None,
        Comparator::Eq if trimmed.contains(['*', '?']) => Test::Like,
        Comparator::Eq => Test::Equals,
        Comparator::Contains if !trimmed.contains(['*', '?']) => Test::Contains,
        Comparator::StartsWith if !trimmed.contains(['*', '?']) => Test::StartsWith,
        Comparator::EndsWith if !trimmed.contains(['*', '?']) => Test::EndsWith,
        _ => return None,
    };
    Some(Matcher {
        field_id,
        test,
        value: lower,
        host_prefix: test == Test::Equals && nanosiem_core::query::hostname_equality_expands(profile, field, trimmed),
    })
}

fn or_group(profile: &dyn SchemaProfile, expression: &SearchExpr, out: &mut Vec<Matcher>) -> Option<()> {
    match expression {
        SearchExpr::Or(left, right) => {
            or_group(profile, left, out)?;
            or_group(profile, right, out)
        }
        SearchExpr::Group(inner) => or_group(profile, inner, out),
        SearchExpr::InList { field, values, negated: false } => {
            for value in values {
                out.push(matcher(profile, &SearchExpr::FieldFilter {
                    field: field.clone(),
                    op: Comparator::Eq,
                    value: value.clone(),
                    rhs: RhsSyntax::Literal,
                })?);
            }
            Some(())
        }
        other => {
            out.push(matcher(profile, other)?);
            Some(())
        }
    }
}

fn conjuncts(profile: &dyn SchemaProfile, expression: &SearchExpr, out: &mut Constraints) {
    match expression {
        SearchExpr::And(left, right) => {
            conjuncts(profile, left, out);
            conjuncts(profile, right, out);
        }
        SearchExpr::Group(inner) => conjuncts(profile, inner, out),
        other => {
            let mut group = Vec::new();
            if or_group(profile, other, &mut group).is_some() && !group.is_empty() {
                group.sort();
                group.dedup();
                out.push(group);
            }
        }
    }
}

fn source_search(query: &Query) -> &SearchExpr {
    match query {
        Query::Search(expression) => expression,
        Query::Piped { source, .. } => source_search(source),
    }
}

/// Constraints of an nPL query's source search (empty: none apply).
pub fn constraints(query: &str, field_types: &BTreeMap<String, String>) -> Constraints {
    let Ok(parsed) = nanosiem_core::query::parse_query(query) else { return Vec::new() };
    // NAN-2961: subsearches read the same pruned part set as the outer
    // search, so pruning by the outer search alone would hide the parts only a
    // subsearch matches. Correlation queries are never membership-pruned.
    if nanosiem_core::search::query_processing::query_has_nested_scan(&parsed) {
        return Vec::new();
    }
    let Ok(types) = serde_json::from_value(serde_json::to_value(field_types).unwrap_or_default()) else { return Vec::new() };
    let Ok(profile) = OcsfProfile::try_lake_1_9_with_snapshot_field_types(types) else { return Vec::new() };
    let mut out = Vec::new();
    conjuncts(&profile, source_search(&parsed), &mut out);
    // Keep the most selective-looking groups within the matcher bound.
    out.sort_by_key(Vec::len);
    let mut total = 0;
    out.retain(|group| {
        total += group.len();
        total <= MAX_MATCHERS
    });
    out
}

/// Bounded lookup keys for less restrictive queries: single conjuncts and
/// immediate parents. No subset enumeration or native reads. AND commutes,
/// so the existing stable constraint ordering is preserved for each subset.
/// Missing keys are unknown; present buckets are supersets of a child's.
pub fn parent_keys(constraints: &Constraints) -> Vec<std::sync::Arc<str>> {
    // SQL keys are hashed for each part. Keep the hot-path lookup work small
    // even for the maximum 64 matchers; larger queries use exact memos only.
    if !(2..=8).contains(&constraints.len()) {
        return Vec::new();
    }
    let mut keys = BTreeSet::new();
    for (index, group) in constraints.iter().enumerate() {
        keys.insert(statement(&vec![group.clone()], 0, i64::MAX).into());
        let parent = constraints.iter().enumerate().filter(|(i, _)| *i != index)
            .map(|(_, group)| group.clone()).collect();
        keys.insert(statement(&parent, 0, i64::MAX).into());
    }
    keys.into_iter().collect()
}

fn sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn like_pattern(wildcard: &str) -> String {
    let mut out = String::with_capacity(wildcard.len());
    for character in wildcard.chars() {
        match character {
            '*' => out.push('%'),
            '?' => out.push('_'),
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            other => out.push(other),
        }
    }
    out
}

fn matcher_sql(matcher: &Matcher) -> String {
    let value = sql_string(&matcher.value);
    let test = match matcher.test {
        Test::Equals if matcher.host_prefix => format!(
            "(lower(value) = {value} OR startsWith(lower(value), {}))",
            sql_string(&format!("{}.", matcher.value))
        ),
        Test::Equals => format!("lower(value) = {value}"),
        Test::Contains => format!("positionCaseInsensitiveUTF8(value, {value}) > 0"),
        Test::StartsWith => format!("startsWith(lower(value), {value})"),
        Test::EndsWith => format!("endsWith(lower(value), {value})"),
        Test::Like => format!("value ILIKE {}", sql_string(&like_pattern(&matcher.value))),
        Test::Regex => format!("match(value, {})", sql_string(&format!("(?i){}", matcher.value.strip_prefix("(?i)").unwrap_or(&matcher.value)))),
    };
    format!("(field_id = {} AND isNotNull(value) AND {test})", matcher.field_id)
}

/// The membership statement over a `{membership_rollups:String}` file set:
/// `(_path, bucket_start_us)` pairs where every group has a match. Values are
/// SQL-escaped literals from the parsed query (no request data reaches SQL
/// any other way).
pub fn statement(constraints: &Constraints, from_us: i64, to_us: i64) -> String {
    let field_ids = constraints.iter().flatten().map(|m| m.field_id).collect::<BTreeSet<_>>();
    let having = constraints
        .iter()
        .map(|group| format!("countIf({}) > 0", group.iter().map(matcher_sql).collect::<Vec<_>>().join(" OR ")))
        .collect::<Vec<_>>()
        .join(" AND ");
    let any = constraints.iter().flatten().map(matcher_sql).collect::<Vec<_>>().join(" OR ");
    format!(
        "SELECT _path AS path, bucket_start_us AS bucket FROM file({{membership_rollups:String}}, Parquet) \
         WHERE field_id IN ({}) AND bucket_start_us >= {} AND bucket_start_us <= {} AND ({any}) \
         GROUP BY path, bucket HAVING {having}",
        field_ids.iter().map(u16::to_string).collect::<Vec<_>>().join(", "),
        from_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US,
        to_us,
    )
}

/// Matching buckets per part. A part this membership evaluated but has no
/// buckets for provably does not match; a part it never saw is kept.
#[derive(Debug, Clone, Default)]
pub struct Membership {
    pub buckets: BTreeMap<crate::parts::format::PartId, BTreeSet<i64>>,
    /// Parts that had no rollup partial (always kept).
    pub unknown: BTreeSet<crate::parts::format::PartId>,
    /// Every part of the snapshot this membership was computed over. The
    /// selection takes its own (later) snapshot: a part added or merged in
    /// between (NAN-2984: an M merge output replacing the L0s) was never
    /// evaluated and must be kept, not read as "no match".
    pub evaluated: BTreeSet<crate::parts::format::PartId>,
}

impl Membership {
    /// `None`: keep every row of the part; `Some(buckets)`: only these.
    pub fn part(&self, id: &crate::parts::format::PartId) -> Option<Option<&BTreeSet<i64>>> {
        if self.unknown.contains(id) || !self.evaluated.contains(id) {
            return Some(None);
        }
        self.buckets.get(id).map(Some)
    }

    /// Does `[min_us, max_us]` touch a matching bucket?
    pub fn touches(buckets: &BTreeSet<i64>, min_us: i64, max_us: i64) -> bool {
        let first = min_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US;
        buckets.range(first..=max_us).next().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn types() -> BTreeMap<String, String> {
        [("metadata.log_source", "string"), ("user.name", "string"), ("device.hostname", "string"), ("src_endpoint.ip", "ip_address"), ("file.hashes.value", "array")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parent_keys_preserve_whole_or_groups_and_are_bounded() {
        let parent = constraints("metadata.log_source=windows_sysmon user.name IN (alice,bob)", &types());
        let child = constraints("metadata.log_source=windows_sysmon user.name IN (alice,bob) device.hostname=\"ws-1.corp.local\"", &types());
        assert_eq!(parent.len(), 2);
        assert_eq!(child.len(), 3);
        let keys = parent_keys(&child);
        assert!(keys.iter().any(|key| &**key == statement(&parent, 0, i64::MAX)));
        assert!(keys.len() <= child.len() * 2);
        assert!(parent_keys(&parent[..1].to_vec()).is_empty());
        assert!(parent_keys(&vec![parent[0].clone(); 9]).is_empty());
        // Removing a conjunct never removes a branch inside an OR.
        let or_parent = statement(&vec![parent[1].clone()], 0, i64::MAX);
        assert!(keys.iter().any(|key| &**key == or_parent));
    }

    #[test]
    fn correlation_queries_are_never_membership_pruned() {
        assert!(!constraints("user.name=intern01", &types()).is_empty());
        for query in [
            "user.name=intern01 | join device.hostname [search user.name=other]",
            "user.name=intern01 | append [search user.name=other]",
            "user.name=intern01 device.hostname IN [search user.name=other | return device.hostname]",
        ] {
            assert!(constraints(query, &types()).is_empty(), "{query}");
        }
    }

    #[test]
    fn extracts_only_provable_equality() {
        let c = constraints("metadata.log_source=audit user.name=intern01 | stats count", &types());
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|g| g.len() == 1));
        let c = constraints(r#"user.name=intern01 OR actor.user.name="Intern01""#, &types());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 2);
        assert!(c[0].iter().all(|m| m.value == "intern01"));
        // An OR with an unprovable branch contributes nothing.
        assert!(constraints("user.name=intern01 OR rundll32", &types()).is_empty());
        // CIDRs, negations, inequality, bare `*`: nothing.
        for query in ["src_endpoint.ip=10.0.0.0/8", "NOT user.name=x", "user.name!=x", "user.name=*"] {
            assert!(constraints(query, &types()).is_empty(), "{query}");
        }
        // Wildcards and regexes become ILIKE / (?i) regex tests.
        let c = constraints("user.name=adm*", &types());
        assert_eq!(c[0][0].test, Test::Like);
        assert!(statement(&c, 0, 1).contains("value ILIKE 'adm%'"));
        let c = constraints("user.name=/^admin-[a-z]+$/", &types());
        assert_eq!(c[0][0].test, Test::Regex);
        assert!(statement(&c, 0, 1).contains("match(value, '(?i)^admin-[a-z]+$')"), "{}", statement(&c, 0, 1));
        // A dotless host name also accepts FQDN prefixes.
        let c = constraints("device.hostname=ws-fin-011", &types());
        assert!(c[0][0].host_prefix);
        let sql = statement(&c, 0, 1);
        assert!(sql.contains("startsWith(lower(value), 'ws-fin-011.')"), "{sql}");
        // Literals are escaped.
        let c = constraints(r#"user.name="o'brien""#, &types());
        assert!(statement(&c, 0, 1).contains(r"'o\'brien'"));
    }

    /// NAN-2984: a merge (or add) landing between the membership snapshot
    /// and the selection snapshot must not prune the new part. Seen live as
    /// a count query missing ~75–90 s of just-merged rows.
    #[test]
    fn parts_outside_the_evaluated_snapshot_are_kept() {
        use crate::parts::format::PartId;
        let matched = PartId::parse("1790620000000-0000000000000001").unwrap();
        let no_match = PartId::parse("1790620000000-0000000000000002").unwrap();
        let no_rollup = PartId::parse("1790620000000-0000000000000003").unwrap();
        let merged_later = PartId::parse("1790620060000-0000000000000004").unwrap();
        let membership = Membership {
            buckets: BTreeMap::from([(matched.clone(), BTreeSet::from([0_i64]))]),
            unknown: BTreeSet::from([no_rollup.clone()]),
            evaluated: BTreeSet::from([matched.clone(), no_match.clone(), no_rollup.clone()]),
        };
        assert_eq!(membership.part(&matched), Some(Some(&BTreeSet::from([0_i64]))));
        assert_eq!(membership.part(&no_match), None, "evaluated without buckets: provably no match");
        assert_eq!(membership.part(&no_rollup), Some(None));
        assert_eq!(membership.part(&merged_later), Some(None), "never evaluated: keep every row");
    }

    #[test]
    fn bucket_touch() {
        let buckets = [0_i64, 600_000_000].into_iter().collect::<BTreeSet<_>>();
        assert!(Membership::touches(&buckets, 10, 20));
        assert!(!Membership::touches(&buckets, 300_000_000, 599_999_999));
        assert!(Membership::touches(&buckets, 599_999_999, 600_000_001));
    }
}
