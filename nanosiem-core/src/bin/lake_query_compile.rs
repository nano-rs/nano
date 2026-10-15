// SPDX-License-Identifier: AGPL-3.0-or-later

//! Compile one Nano nPL request into OCSF ClickHouse SQL for a lake worker.
//!
//! The output deliberately contains a fixed table placeholder rather than an
//! object URI or credentials. A worker replaces that exact token with its
//! tenant-fenced `s3(...)`/`gcs(...)`/`azureBlobStorage(...)` table function and
//! binds credentials as query parameters.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use nanosiem_core::query::{
    ClickHouseSqlGenerator, Command, Comparator, Query, QueryOptions, RhsSyntax, SearchExpr,
    TimeRange, Value,
    parse_query, validate_query_fields_with_profile,
};
use nanosiem_core::schema::{
    FieldResolution, FieldType, OcsfProfile, RiskProfile, SchemaId, SchemaProfile, profile_for_id,
};
use nanosiem_core::search::query_processing::{
    apply_auto_sort, apply_profile_product_semantics, contains_lake_post_processing_anywhere,
    query_has_nested_scan,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

/// The scalar `prevalence_*` names an OCSF 1.9 lake derives from its stamp
/// arrays (NAN-3451) or, on lean parts, stores physically.
const PREVALENCE_SCALARS: [&str; 5] = [
    "prevalence_file_hash",
    "prevalence_process_hash",
    "prevalence_dest_domain",
    "prevalence_dest_ip",
    "prevalence_min",
];

const SOURCE_PLACEHOLDER: &str = "__nano_lake_source__";
const RISK_SOURCE_PLACEHOLDER: &str = "__nano_risk_source__";
/// The public result limit is one million rows. The trusted worker asks the
/// compiler for one additional row so it can prove whether that public page is
/// complete instead of silently claiming completeness at the boundary.
const MAX_COMPILE_RESULT_LIMIT: usize = 1_000_001;
const INTERNAL_DISTINCT_VALUES_ALIAS: &str = "__nano_distinct_values";
const INTERNAL_DISTINCT_VALUES_LIMIT: usize = 10_001;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompileRequest {
    query: String,
    /// Internal interactive-page opt-in; durable exports keep their full SQL.
    #[serde(default)]
    stats_page: bool,
    #[serde(default)]
    stats_page_offset: usize,
    #[serde(default = "default_dataset")]
    dataset: String,
    start: String,
    end: String,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default = "default_table_view")]
    table_view: bool,
    #[serde(default = "default_event_contract")]
    event_contract: String,
    /// Exact typed leaves beneath OCSF's producer-owned `unmapped` object.
    /// The tenant-pinned worker derives this from its immutable source manifest.
    #[serde(default)]
    unmapped_field_types: BTreeMap<String, FieldType>,
    /// Typed physical leaves from the immutable, schema-validated snapshot.
    /// Native OCSF paths remain native; this inventory creates no aliases.
    #[serde(default)]
    snapshot_field_types: BTreeMap<String, FieldType>,
    /// NAN-2869: paths every part of the window proves lowercased at rest
    /// (signed provenance). Equality on them compares raw, literal lowered.
    #[serde(default)]
    lowercased_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CompileResponse {
    schema_version: u8,
    profile: &'static str,
    dataset: &'static str,
    source_placeholder: &'static str,
    query_sha256: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: usize,
    table_view: bool,
    /// True only when the compiler proves the output is an event timeline in
    /// descending event-time order. Workers may use this to execute disjoint
    /// newest-first source windows without changing result semantics.
    newest_first_event_rows: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stats_page: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    candidate_hints: Vec<CandidateHint>,
    required_columns: Vec<RequiredColumn>,
    /// Physical event columns the transformed query can actually read.
    /// Empty means the worker must conservatively charge the full event row.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    projected_scan_columns: Vec<String>,
    sql: String,
}

/// A compiler-proven safe superset lookup for the immutable serving sidecars.
///
/// This is deliberately only a hint. The worker always runs the complete
/// compiled query against the candidate blocks, so the sidecar never becomes
/// an event truth source and cannot introduce false-positive results.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CandidateHint {
    Entity { source_path: String, value: String },
    SourceFamily { value: String },
    /// NAN-3188: `class_uid = value`, emitted only as a top-level-AND
    /// conjunct (never inside OR / NOT). It lets the worker skip a whole
    /// source/class family file whose signed class is another value.
    Class { value: i64 },
    Keyword { mode: &'static str, value: String },
    Any { alternatives: Vec<CandidateHint> },
}

const ENTITY_SIDECAR_PATHS: &[&str] = &[
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "src_endpoint.mac",
    "dst_endpoint.mac",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "device.hostname",
    "user.name",
    "user.uid",
    "actor.user.name",
    "actor.user.uid",
    "process.name",
    "process.uid",
    "actor.process.name",
    "actor.process.uid",
    "file.hashes.value",
    "process.file.hashes.value",
    "url.hostname",
    "query.hostname",
    "url.url_string",
    "answers.rdata",
    "email.from",
    "email.to",
    "vulnerabilities.cve.uid",
    "resources.ip",
    "resources.hostname",
    "resources.device.hostname",
    "resources.user.name",
    "resources.user.uid",
    "resources.uid",
    "evidences.query.hostname",
    "evidences.url.url_string",
    "trace.uid",
    "trace.span.uid",
    "unmapped.trace_id",
    "unmapped.span_id",
    "metadata.uid",
    "enrichments.value",
    // NAN-3694: asset-pivot identities (worker `IDENTITY_PATHS` blooms). An
    // OR prunes only when every leg is hinted, so one unhinted `device.ip`
    // leg turned the whole IP pivot into a full scan.
    "device.ip",
    "device.uid",
    "user.email_addr",
    "actor.user.email_addr",
    "actor.process.user.name",
];

// The contract lives in `nanosiem_core::search::keyword_sidecar` so the lake
// worker that builds the index asserts against the same list. See that module
// for why a hinted-but-unindexed path is a silent zero-result, not a missed
// optimization.
use nanosiem_core::search::keyword_sidecar::KEYWORD_SIDECAR_PATHS;

const MAX_CANDIDATE_HINTS: usize = 8;

fn source_search_expression(query: &Query) -> &SearchExpr {
    match query {
        Query::Search(expression) => expression,
        Query::Piped { source, .. } => source_search_expression(source),
    }
}

fn exact_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Ip(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Return one literal token that every match of `pattern` must contain.
///
/// This deliberately accepts fewer regexes than ClickHouse can execute. A
/// missed optimization only causes a bounded source scan; an invented guard
/// could hide events, so alternations intersect their guarantees and optional
/// repetitions contribute nothing.
fn mandatory_regex_token(pattern: &str) -> Option<String> {
    use regex_syntax::hir::{Hir, HirKind};

    fn tokens(value: &[u8]) -> BTreeSet<String> {
        let Ok(value) = std::str::from_utf8(value) else {
            return BTreeSet::new();
        };
        value
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| token.chars().count() >= 3)
            .map(str::to_lowercase)
            .collect()
    }

    fn required(hir: &Hir) -> BTreeSet<String> {
        match hir.kind() {
            HirKind::Literal(literal) => tokens(&literal.0),
            HirKind::Capture(capture) => required(&capture.sub),
            HirKind::Repetition(repetition) if repetition.min > 0 => required(&repetition.sub),
            HirKind::Concat(expressions) => expressions
                .iter()
                .flat_map(required)
                .collect::<BTreeSet<_>>(),
            HirKind::Alternation(expressions) => {
                let mut expressions = expressions.iter();
                let Some(first) = expressions.next() else {
                    return BTreeSet::new();
                };
                expressions.fold(required(first), |common, expression| {
                    common
                        .intersection(&required(expression))
                        .cloned()
                        .collect()
                })
            }
            HirKind::Empty | HirKind::Class(_) | HirKind::Look(_) | HirKind::Repetition(_) => {
                BTreeSet::new()
            }
        }
    }

    // Nano executes positive regexes case-insensitively. Removing only the
    // leading global flag preserves the language while keeping literals as
    // literals in regex-syntax's HIR instead of expanded character classes.
    let pattern = pattern.strip_prefix("(?i)").unwrap_or(pattern);
    let hir = regex_syntax::Parser::new().parse(pattern).ok()?;
    required(&hir)
        .into_iter()
        .max_by_key(|token| token.chars().count())
}

/// The entity-sidecar columns an `=` filter on `field` compares, or `None`
/// when that comparison is not an exact match of sidecar-indexed columns.
///
/// A canonical sidecar path is itself. NAN-3162: a product alias resolves the
/// way the SQL generator resolves it -- `host` / `src_ip` / `dest_host` to
/// their one explicit column, and a class-split alias (`user`, `src_host`,
/// `process_name`) to BOTH of its columns, because it lowers to
/// `if(a != '', a, b) = v`: every matching row holds `v` in `a` or in `b`, so
/// the union of the two exact lookups is a superset. Anything else (JSON
/// paths, computed columns, a split with an unindexed side) yields no hint,
/// which is always sound.
fn entity_sidecar_paths(field: &str, profile: &dyn SchemaProfile) -> Option<Vec<&'static str>> {
    let indexed = |path: &str| ENTITY_SIDECAR_PATHS.iter().copied().find(|known| *known == path);
    if let Some(path) = indexed(field) {
        return Some(vec![path]);
    }
    if profile.source_computed_column(field).is_some() {
        return None;
    }
    if let Some((primary, fallback)) = profile.class_split_source_fields(field) {
        return Some(vec![indexed(primary)?, indexed(fallback)?]);
    }
    match profile.resolve(field) {
        FieldResolution::ExplicitColumn(column) => indexed(&column).map(|path| vec![path]),
        _ => None,
    }
}

/// `metadata.log_source` itself, or an alias the profile resolves to exactly
/// that column (`source_type`, `sourcetype`). NAN-3221: `source_type=audit`
/// compiled to the same `lower("metadata.log_source") = 'audit'` predicate
/// but carried no source-family hint, so no file was pruned by its signed
/// family and a 24 h page scanned every file (a 502 after 60 s).
fn is_log_source_field(field: &str, profile: &dyn SchemaProfile) -> bool {
    field == "metadata.log_source"
        || (profile.source_computed_column(field).is_none()
            && matches!(profile.resolve(field), FieldResolution::ExplicitColumn(column) if column == "metadata.log_source"))
}

fn candidate_hint_for_expression(
    expression: &SearchExpr,
    profile: &dyn SchemaProfile,
) -> Option<CandidateHint> {
    match expression {
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Eq,
            value,
            rhs,
        } if is_log_source_field(field, profile)
            && (*rhs == RhsSyntax::Literal
                || (*rhs == RhsSyntax::Bareword
                    && exact_text(value).is_some_and(|text| !profile.is_known_field(&text))))
            && exact_text(value).is_some_and(|text| !text.is_empty() && !text.contains(['*', '?'])) =>
        {
            Some(CandidateHint::SourceFamily {
                value: exact_text(value).expect("guarded above"),
            })
        }
        SearchExpr::Keyword(value) if !value.trim().is_empty() && value.trim() != "*" => {
            // A wildcard keyword (`svch*`, `*svchost*`, `c?d`) compiles to a
            // substring `iLike`, not `hasAllTokens`: its pieces may be PARTIAL
            // tokens. `token` mode would make the generation keyword sidecar
            // require the whole token `svch` and prune every `svchost` row;
            // `contains` expands pieces through the fragment lane (or falls
            // back), and part-index pruning keeps only interior tokens for both
            // modes (NAN-3032/NAN-3034).
            let mode = if value.contains(['*', '?']) { "contains" } else { "token" };
            Some(CandidateHint::Keyword {
                mode,
                value: value.clone(),
            })
        }
        // NAN-2380: a BAREWORD right-hand side may be a column reference
        // (`src_endpoint.ip = dest_endpoint.ip`), and a sidecar candidate hint
        // built from a column NAME would prune to the files containing that
        // text — i.e. none — turning a field-to-field hunt into a silent
        // zero-result. NAN-3162: so ask the generator's own classifier. A
        // bareword it reads as a VALUE (`host=web1.corp.local`, `user=alice`)
        // compiles to exactly the SQL of its quoted spelling and gets exactly
        // its hint; a column reference or an ambiguous token gets none.
        SearchExpr::FieldFilter {
            field,
            op,
            value,
            rhs,
        }
            if *op == Comparator::Eq
                && nanosiem_core::query::rhs_compiles_as_value(profile, field, op, value, *rhs)
                && entity_sidecar_paths(field, profile).is_some()
                && exact_text(value).is_some()
                // NAN-2361: a dotless literal on a host-entity field does NOT
                // compile to exact equality -- the SQL generator expands it to
                // `= v OR startsWith(col, 'v.')` so short names match FQDNs.
                // An exact-value entity hint is then NARROWER than the
                // predicate it accompanies, and candidates PRUNE the source, so
                // every object holding only the FQDN was discarded before the
                // SQL could accept it: `device.hostname="ws-fin-011"` returned
                // ZERO on promoted data while the identical query worked on the
                // hot tail (which carries no entity sidecar to prune with).
                // Emitting no hint is always sound -- it only costs pruning.
                && !nanosiem_core::query::hostname_equality_expands(
                    profile,
                    field,
                    &exact_text(value).expect("guarded above"),
                ) =>
        {
            let text = exact_text(value).expect("guarded above");
            let paths = entity_sidecar_paths(field, profile).expect("guarded above");
            // These Eq literals lower to empty/notEmpty, iLike, or IP range
            // predicates, so an exact-value hint could discard matching rows.
            let is_ip = |path: &str| {
                profile.entity_type(path) == Some(nanosiem_core::schema::EntityType::Ip)
                    || profile.field_type(path) == Some(nanosiem_core::schema::FieldType::IpAddress)
                    || path.ends_with(".ip")
            };
            if text.is_empty()
                || text.contains(['*', '?'])
                || (text.contains('/') && (is_ip(field) || paths.iter().any(|path| is_ip(path))))
            {
                return None;
            }
            let mut hints = paths
                .into_iter()
                .map(|path| CandidateHint::Entity {
                    source_path: path.to_string(),
                    value: text.clone(),
                })
                .collect::<Vec<_>>();
            Some(if hints.len() == 1 {
                hints.pop().expect("one hint")
            } else {
                CandidateHint::Any { alternatives: hints }
            })
        }
        SearchExpr::FieldFilter {
            field,
            op,
            value,
            rhs,
        }
            if nanosiem_core::query::rhs_compiles_as_value(profile, field, op, value, *rhs)
                && matches!(
                op,
                Comparator::Eq
                    | Comparator::Contains
                    | Comparator::StartsWith
                    | Comparator::EndsWith
            ) && KEYWORD_SIDECAR_PATHS.contains(&field.as_str())
                && matches!(value, Value::String(text) if !text.trim().is_empty()) =>
        {
            Some(CandidateHint::Keyword {
                mode: "contains",
                value: exact_text(value).expect("guarded above"),
            })
        }
        SearchExpr::FieldFilter { field, op, value, .. }
            if *op == Comparator::Regex
                && KEYWORD_SIDECAR_PATHS.contains(&field.as_str())
                && matches!(value, Value::Regex(pattern) if mandatory_regex_token(pattern).is_some()) =>
        {
            let Value::Regex(pattern) = value else {
                unreachable!("guarded above")
            };
            Some(CandidateHint::Keyword {
                mode: "regex_guard",
                value: mandatory_regex_token(pattern).expect("guarded above"),
            })
        }
        _ => None,
    }
}

/// NAN-3188: the class a positive `class_uid = <integer>` filter requires,
/// or `None`. Only the exact canonical field (after alias resolution) and an
/// integral literal qualify: a quoted literal must be the canonical decimal
/// spelling so it compares equal to the number. This is consulted only for
/// mandatory AND conjuncts, never under OR or NOT: a file of another class
/// can still hold rows matching another OR branch.
fn class_hint_for_expression(expression: &SearchExpr, profile: &dyn SchemaProfile) -> Option<CandidateHint> {
    let SearchExpr::FieldFilter { field, op: Comparator::Eq, value, rhs } = expression else {
        return None;
    };
    if profile.canonicalize(field).as_ref() != "class_uid"
        || !nanosiem_core::query::rhs_compiles_as_value(profile, field, &Comparator::Eq, value, *rhs)
    {
        return None;
    }
    let class = match value {
        Value::Number(number) if number.is_finite() && number.fract() == 0.0 && number.abs() < 9.0e15 => *number as i64,
        Value::String(text) => {
            let parsed = text.parse::<i64>().ok()?;
            (parsed.to_string() == *text).then_some(parsed)?
        }
        _ => return None,
    };
    Some(CandidateHint::Class { value: class })
}

// An OR can prune only when EVERY branch has a safe lookup. Keep the union
// explicit in the wire contract; the worker must never intersect its children.
fn disjunctive_hint(expression: &SearchExpr, profile: &dyn SchemaProfile) -> Option<CandidateHint> {
    fn collect(expression: &SearchExpr, profile: &dyn SchemaProfile, out: &mut Vec<CandidateHint>) -> Option<()> {
        if out.len() >= MAX_CANDIDATE_HINTS { return None; }
        match expression {
            SearchExpr::Or(left, right) => { collect(left, profile, out)?; collect(right, profile, out)?; }
            SearchExpr::Group(inner) => collect(inner, profile, out)?,
            // A class-split alias (`user=alice`) is itself a union; inside an
            // OR it contributes its alternatives, never a nested union.
            other => match candidate_hint_for_expression(other, profile)? {
                CandidateHint::Any { alternatives } => out.extend(alternatives),
                hint => out.push(hint),
            },
        }
        Some(())
    }
    let mut alternatives = Vec::new();
    collect(expression, profile, &mut alternatives)?;
    if alternatives.len() > MAX_CANDIDATE_HINTS {
        return None;
    }
    Some(CandidateHint::Any { alternatives })
}

/// Collect only predicates that are mandatory for every matching row.
///
/// A child of an `AND` remains a safe candidate superset: the complete query
/// is always rechecked against the selected blocks. `OR` requires a complete union of safe branch lookups; `NOT` stays opaque.
/// Selecting only one OR child could discard matching rows. Grouping is transparent. Keeping this proof in the compiler means
/// the worker never has to interpret analyst query syntax.
fn collect_conjunctive_hints(
    expression: &SearchExpr,
    profile: &dyn SchemaProfile,
    hints: &mut Vec<CandidateHint>,
) {
    let probes = hints.iter().map(|hint| match hint {
        CandidateHint::Any { alternatives } => alternatives.len(),
        _ => 1,
    }).sum::<usize>();
    if probes >= MAX_CANDIDATE_HINTS { return; }
    match expression {
        SearchExpr::And(left, right) => {
            collect_conjunctive_hints(left, profile, hints);
            collect_conjunctive_hints(right, profile, hints);
        }
        SearchExpr::Group(inner) => collect_conjunctive_hints(inner, profile, hints),
        SearchExpr::Or(_, _) => {
            if let Some(CandidateHint::Any { alternatives }) = disjunctive_hint(expression, profile) {
                // Preserve the existing total probe bound across AND groups.
                // A union that does not fit must be dropped in its entirety.
                if probes + alternatives.len() <= MAX_CANDIDATE_HINTS {
                    hints.push(CandidateHint::Any { alternatives });
                }
            }
        }
        expression => {
            // NAN-3188: a mandatory class equality is a whole-file class
            // hint. Its arm is reached only through AND / Group, never OR or
            // NOT, which are handled (or left opaque) above.
            if let Some(hint) = class_hint_for_expression(expression, profile) {
                if probes < MAX_CANDIDATE_HINTS && !hints.contains(&hint) {
                    hints.push(hint);
                }
                return;
            }
            if let Some(hint) = candidate_hint_for_expression(expression, profile) {
                let cost = match &hint {
                    CandidateHint::Any { alternatives } => alternatives.len(),
                    _ => 1,
                };
                if probes + cost <= MAX_CANDIDATE_HINTS && !hints.contains(&hint) {
                    hints.push(hint);
                }
            }
        }
    }
}

fn candidate_hints(
    query: &Query,
    dataset: &str,
    profile: &dyn SchemaProfile,
) -> Vec<CandidateHint> {
    // NAN-2961: every scan of a correlation query (join / append / IN
    // subsearch) binds the SAME candidate part set. Hints from the outer
    // search alone would drop the parts only a subsearch matches, so a
    // correlation query reads the full time-bounded part set.
    if dataset != "logs" || query_has_nested_scan(query) {
        return Vec::new();
    }
    let mut hints = Vec::new();
    collect_conjunctive_hints(source_search_expression(query), profile, &mut hints);
    collect_source_family_where_hints(query, profile, &mut hints);
    hints
}

/// A post-search `where` may be moved to file selection only while every
/// preceding command preserves the original log-source column and row set.
/// In particular, `head`, aggregation, and an eval that replaces log_source
/// make the pushdown unsound.
fn collect_source_family_where_hints(
    query: &Query,
    profile: &dyn SchemaProfile,
    hints: &mut Vec<CandidateHint>,
) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            if !collect_source_family_where_hints(source, profile, hints) {
                return false;
            }
            match command {
                Command::Eval { assignments } => assignments
                    .iter()
                    .all(|assignment| assignment.field != "metadata.log_source"),
                Command::Where { condition } => {
                    let mut candidates = Vec::new();
                    collect_conjunctive_hints(condition, profile, &mut candidates);
                    for candidate in candidates {
                        let source_only = match &candidate {
                            CandidateHint::SourceFamily { .. } => true,
                            CandidateHint::Any { alternatives } => alternatives.iter().all(
                                |alternative| matches!(alternative, CandidateHint::SourceFamily { .. }),
                            ),
                            _ => false,
                        };
                        if source_only && hints.len() < MAX_CANDIDATE_HINTS {
                            hints.push(candidate);
                        }
                    }
                    true
                }
                _ => false,
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct RequiredColumn {
    name: String,
    field_type: FieldType,
}

fn default_limit() -> usize {
    100
}

fn default_dataset() -> String {
    "logs".to_string()
}

fn default_table_view() -> bool {
    true
}

fn default_event_contract() -> String {
    "ocsf-1.9".to_string()
}

fn parse_timestamp(value: &str, name: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .with_context(|| format!("{name} must be RFC3339"))?
        .with_timezone(&Utc))
}

fn quoted_identifiers(sql: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut identifier = String::new();
        while let Some(ch) = chars.next() {
            if ch != '"' {
                identifier.push(ch);
                continue;
            }
            if chars.peek() == Some(&'"') {
                chars.next();
                identifier.push('"');
                continue;
            }
            break;
        }
        if !identifier.is_empty() {
            identifiers.push(identifier);
        }
    }
    identifiers
}

fn required_columns(
    query: &nanosiem_core::query::Query,
    sql: &str,
    table_view: bool,
    generator: &ClickHouseSqlGenerator,
    profile: &dyn SchemaProfile,
) -> Vec<RequiredColumn> {
    let mut columns = BTreeMap::new();
    for field in generator
        .required_fields_for_query(query, table_view)
        .unwrap_or_default()
        .into_iter()
        .chain(generator.referenced_fields_for_query(query))
    {
        if let Some((_, inputs)) = profile.source_computed_column(&field) {
            for input in inputs {
                columns.entry(input.to_string()).or_insert_with(|| profile.field_type(input).unwrap_or(FieldType::Array));
            }
            continue;
        }
        let canonical = profile.canonicalize(&field);
        // NAN-3059: a class-scoped enum (OCSF `activity_id`) compares a text
        // label against its SIBLING label column (`event_type=process_start`
        // emits `lower(activity_name) = …`). That column is never quoted in
        // the SQL, so the generated-SQL pass below cannot see it; without it
        // stage 0 of a projected plan (tree, stats, …) fails with Code 47.
        if let Some(nanosiem_core::schema::EnumIntMapping::LabelColumn(label)) =
            profile.enum_int_mapping(canonical.as_ref())
        {
            if let FieldResolution::ExplicitColumn(column) = profile.resolve(label) {
                columns
                    .entry(column)
                    .or_insert_with(|| profile.field_type(label).unwrap_or(FieldType::String));
            }
        }
        match profile.resolve(canonical.as_ref()) {
            FieldResolution::ExplicitColumn(column) => {
                if let Some(field_type) = profile.field_type(canonical.as_ref()) {
                    columns.entry(column).or_insert(field_type);
                }
            }
            FieldResolution::JsonPath { col, path }
                if matches!(col.as_str(), "unmapped" | "ext" | "event") && !path.is_empty() =>
            {
                let path = path.join(".");
                let field_type = profile
                    .field_type(canonical.as_ref())
                    .unwrap_or(FieldType::String);
                columns.entry(format!("{col}.{path}")).or_insert(field_type);
            }
            _ => {}
        }
    }
    for identifier in quoted_identifiers(sql) {
        if profile.source_computed_column(&identifier).is_some() {
            continue;
        }

        // A quoted output alias (for example stats BY `user`) is not a
        // physical Parquet column. Resolve it exactly as the generator does.
        // Class-spanning aliases need both inputs, never a synthetic source
        // column named after the alias.
        if let Some((primary, fallback)) = profile.class_split_source_fields(&identifier) {
            for column in [primary, fallback] {
                columns
                    .entry(column.to_string())
                    .or_insert_with(|| profile.field_type(column).unwrap_or(FieldType::String));
            }
        } else if let FieldResolution::ExplicitColumn(column) = profile.resolve(&identifier) {
            let field_type = profile.field_type(&column).unwrap_or(FieldType::String);
            columns.entry(column).or_insert(field_type);
        } else if identifier.starts_with("unmapped.")
            || identifier.starts_with("ext.")
            || identifier.starts_with("event.")
        {
            columns
                .entry(identifier.clone())
                .or_insert_with(|| profile.field_type(&identifier).unwrap_or(FieldType::String));
        }
    }
    // Keyword and transaction SQL quote their profile-owned body columns, so
    // the generated-SQL pass above declares exactly the bodies that query can
    // read. Do not add `message` and `raw_data` to every transforming query:
    // those wide columns would defeat Parquet projection and make a narrow
    // stats query look like a full-event scan to the admission controller.
    // Every generated log query is fenced by its requested time range, even
    // when the analyst's transforming pipeline does not mention event time.
    // The object worker projects only this declared input set for Iceberg, so
    // leaving the profile timestamp out produces a stage-0 predicate against a
    // column that was never exposed.
    let timestamp = profile.timestamp_expr();
    if let FieldResolution::ExplicitColumn(column) = profile.resolve(timestamp) {
        columns.entry(column).or_insert_with(|| {
            profile
                .field_type(timestamp)
                .unwrap_or(FieldType::Timestamp)
        });
    }
    columns
        .into_iter()
        .map(|(name, field_type)| RequiredColumn { name, field_type })
        .collect()
}

fn insert_physical_field(field: &str, profile: &dyn SchemaProfile, columns: &mut BTreeSet<String>) {
    if let Some((_, inputs)) = profile.source_computed_column(field) {
        columns.extend(inputs.into_iter().map(str::to_string));
        return;
    }

    let canonical = profile.canonicalize(field);
    if let Some((primary, fallback)) = profile.class_split_source_fields(canonical.as_ref()) {
        insert_physical_field(primary, profile, columns);
        insert_physical_field(fallback, profile, columns);
        return;
    }
    match profile.resolve(canonical.as_ref()) {
        FieldResolution::ExplicitColumn(column) => {
            columns.insert(column);
        }
        FieldResolution::JsonPath { col, path }
            if matches!(col.as_str(), "unmapped" | "ext" | "event") && !path.is_empty() =>
        {
            columns.insert(format!("{col}.{}", path.join(".")));
        }
        _ => {}
    }
}

fn expression_has_keyword(expression: &SearchExpr) -> bool {
    match expression {
        SearchExpr::Keyword(value) => !value.trim().is_empty() && value.trim() != "*",
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            expression_has_keyword(left) || expression_has_keyword(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => expression_has_keyword(inner),
        _ => false,
    }
}

fn query_needs_message(query: &Query) -> bool {
    match query {
        Query::Search(expression) => expression_has_keyword(expression),
        Query::Piped { source, command } => {
            // The shared field analyzer does not retain `rex`'s input field.
            // Today the command's only supported storage input is the event
            // message, whether it was implicit or written as `field=message`.
            query_needs_message(source)
                || matches!(command, Command::Rex { .. } | Command::Transaction { .. })
                || matches!(
                    command,
                    Command::Transaction {
                        startswith: Some(expression),
                        ..
                    } | Command::Transaction {
                        endswith: Some(expression),
                        ..
                    } if expression_has_keyword(expression)
                )
        }
    }
}

fn query_needs_raw_data(query: &Query) -> bool {
    match query {
        Query::Search(expression) => expression_has_keyword(expression),
        Query::Piped { source, command } => {
            query_needs_raw_data(source)
                || matches!(
                    command,
                    Command::Transaction {
                        startswith: Some(expression),
                        ..
                    } | Command::Transaction {
                        endswith: Some(expression),
                        ..
                    } if expression_has_keyword(expression)
                )
        }
    }
}

fn projected_scan_columns(
    query: &Query,
    generator: &ClickHouseSqlGenerator,
    profile: &dyn SchemaProfile,
    transformed_rows: bool,
) -> Vec<String> {
    if !transformed_rows {
        return Vec::new();
    }
    let mut columns = BTreeSet::new();
    for field in generator.referenced_fields_for_query(query) {
        insert_physical_field(&field, profile, &mut columns);
    }
    if query_needs_message(query) {
        insert_physical_field("message", profile, &mut columns);
    }
    if query_needs_raw_data(query) {
        insert_physical_field("raw_data", profile, &mut columns);
    }
    insert_physical_field(profile.timestamp_expr(), profile, &mut columns);
    columns.into_iter().collect()
}

fn compile(request: CompileRequest) -> Result<CompileResponse> {
    if request.query.trim().is_empty() {
        bail!("query must be non-empty");
    }
    if request.limit == 0 || request.limit > MAX_COMPILE_RESULT_LIMIT {
        bail!("limit must be between 1 and {MAX_COMPILE_RESULT_LIMIT}");
    }
    let start = parse_timestamp(&request.start, "start")?;
    let end = parse_timestamp(&request.end, "end")?;
    if start >= end {
        bail!("start must be earlier than end");
    }
    let mut query = parse_query(&request.query).context("invalid nPL query")?;
    let (dataset, source_placeholder, profile): (
        &'static str,
        &'static str,
        std::sync::Arc<dyn SchemaProfile>,
    ) = match request.dataset.trim().to_ascii_lowercase().as_str() {
        "logs" | "log" => {
            if !request.lowercased_fields.is_empty() && request.event_contract != "ocsf-1.9" {
                bail!("lowercased_fields requires the ocsf-1.9 lake contract");
            }
            let profile: std::sync::Arc<dyn SchemaProfile> = match request.event_contract.as_str() {
                "legacy-flat-ocsf-1.8" => profile_for_id(SchemaId::Ocsf),
                "ocsf-1.9" => std::sync::Arc::new(
                    OcsfProfile::try_lake_1_9_with_snapshot_field_types(
                        if request.snapshot_field_types.is_empty() {
                            request.unmapped_field_types.clone()
                        } else {
                            request.snapshot_field_types.clone()
                        },
                    )
                    .and_then(|profile| profile.with_lake_lowercased_at_rest(&request.lowercased_fields))
                    .map_err(anyhow::Error::msg)?,
                ),

                other => bail!("unsupported lake event contract: {other}"),
            };
            ("logs", SOURCE_PLACEHOLDER, profile)
        }
        "risk" => (
            "risk",
            RISK_SOURCE_PLACEHOLDER,
            std::sync::Arc::new(RiskProfile::new()),
        ),
        other => bail!("unsupported lake dataset: {other}"),
    };
    apply_profile_product_semantics(&mut query, profile.as_ref());
    if dataset == "logs" && contains_lake_post_processing_anywhere(&query) {
        bail!(
            "lake compiler cannot execute Nano-side lookup, prevalence, inputlookup, identity, or AI stages"
        );
    }
    let field_errors = validate_query_fields_with_profile(&query, Some(profile.as_ref()));
    if !field_errors.is_empty() {
        // NAN-3451: every `prevalence_*` scalar is derived from the same
        // stamp arrays, so an unstamped snapshot rejects all of them alike.
        let is_prevalence_scalar = |name: &str| PREVALENCE_SCALARS.contains(&name);
        if request.event_contract == "ocsf-1.9"
            && field_errors
                .iter()
                .any(|error| is_prevalence_scalar(&error.field_name))
        {
            let mut unstamped = field_errors
                .iter()
                .filter(|error| is_prevalence_scalar(&error.field_name))
                .map(|error| error.field_name.as_str())
                .collect::<Vec<_>>();
            unstamped.sort_unstable();
            unstamped.dedup();
            let other_errors = field_errors
                .iter()
                .filter(|error| !is_prevalence_scalar(&error.field_name))
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            bail!(
                "query field validation failed: {}: field not searchable on this lake yet (snapshot lacks the prevalence stamp arrays){}",
                unstamped.join(", "),
                if other_errors.is_empty() {
                    String::new()
                } else {
                    format!("; {}", other_errors.join("; "))
                }
            );
        }
        bail!(
            "query field validation failed: {}",
            field_errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let candidate_hints = candidate_hints(&query, dataset, profile.as_ref());
    let internal_distinct_state = has_internal_distinct_state(&query);
    // NAN-2961: progressive newest-first paging fences each chunk in time; a
    // subsearch must see the whole range, so nested scans never page.
    let mut newest_first_event_rows = dataset == "logs"
        && is_newest_first_event_projection(&query)
        && !query_has_nested_scan(&query);
    // A newest-first timeline with `head N` returns at most N rows. The worker
    // pages it by running the SQL once per disjoint time chunk and
    // concatenating newest-first, so the global top-N is the first N rows it
    // sees -- but only if it can read N off the statement's trailing
    // `ORDER BY time DESC … LIMIT N`. Clamp the outer LIMIT to N so staged
    // shapes (`| sort -time | head N`) carry it; a shape that still does not
    // end that way is executed over the whole window instead (below).
    let head_cap = if newest_first_event_rows {
        newest_first_head_cap(&query)
    } else {
        None
    };
    let output_limit = head_cap.map_or(request.limit, |cap| cap.min(request.limit));
    // Match SearchService: raw event timelines are newest-first and grouped
    // aggregations receive their deterministic implicit top-value sort.
    let (query, _) = apply_auto_sort(query);
    // NAN-3162: the event-UID tie-break on every window, so a `head N`
    // timeline over more than 24 h still ends in the cursor order and pages
    // progressively (the worker bounds that sort; see the builder's docs).
    let mut generator = ClickHouseSqlGenerator::with_table(source_placeholder)
        .with_profile(profile.clone())
        .with_uid_tiebreak_any_window(true);
    if internal_distinct_state {
        // SearchService merges these exact, bounded values states across
        // scan-budgeted slices. The normal user-facing values() cap of 100
        // would silently undercount dc() after the merge.
        generator = generator.with_max_group_array_size(INTERNAL_DISTINCT_VALUES_LIMIT);
    }
    let stats_page = request.stats_page && dataset == "logs" && !query_has_nested_scan(&query)
        && nanosiem_core::query::stats_page::eligible(&query);
    let options = QueryOptions {
        use_cache: false,
        table_view: request.table_view,
        limit: if stats_page { None } else { Some(output_limit) },
        unordered: false,
    };
    let mut sql = generator
        .generate_with_options(&query, &TimeRange::new(start, end), &options)
        .context("failed to generate OCSF lake SQL")?;
    if stats_page {
        // The window runs AFTER the entire user pipeline (including head),
        // BEFORE the display limit. It counts groups, never source events.
        // Generated grouped pipelines always have a final SELECT * FROM CTE.
        let (body, settings) = sql.rsplit_once(" SETTINGS ")
            .context("grouped page SQL omitted settings")?;
        let (stages, final_select) = body.rsplit_once("\nSELECT * FROM ")
            .context("grouped page SQL omitted final projection")?;
        // Repeat the last stage's exact generated ordering at the window
        // projection. A window operator must not rely on inherited CTE order.
        let statements =
            parse_generated_sql(&sql).context("failed to parse generated grouped page SQL")?;
        let sqlparser::ast::Statement::Query(statement) = &statements[0] else {
            bail!("grouped page SQL is not a query");
        };
        let ordering = statement.with.as_ref().and_then(|with| {
            with.cte_tables.iter().rev().find_map(|cte| cte.query.order_by.as_ref())
        }).map(|order| format!("{order} ")).unwrap_or_default();
        let offset = request.stats_page_offset;
        if offset >= output_limit {
            bail!("stats page offset must be below the compiler bound");
        }
        // Retain the first ranked group as a cardinality carrier even when
        // the requested offset is beyond the final group. No second scan and
        // no transfer of the preceding offset groups is needed. The worker
        // removes the carrier and ordinal before returning the display page.
        let end = output_limit;
        let row_limit = output_limit - offset + usize::from(offset > 0);
        sql = format!("{stages},\n__nano_stats_ranked AS (\n  SELECT *, {}, row_number() OVER ({ordering}) AS __nano_stats_ordinal FROM {final_select}\n)\nSELECT * FROM __nano_stats_ranked WHERE __nano_stats_ordinal = 1 OR (__nano_stats_ordinal > {offset} AND __nano_stats_ordinal <= {end}) ORDER BY __nano_stats_ordinal LIMIT {row_limit} SETTINGS {settings}",
            nanosiem_core::query::stats_page::TOTAL_EXPRESSION);
    }
    // NAN-3060: "newest-first event rows" is a promise about the SQL's
    // output order: the (time, metadata.uid) cursor of a page's last row
    // continues the result, and progressive chunks concatenate newest first.
    // Only a statement that ENDS in that order keeps it. `| table`, `| fields`,
    // `| rename` and `| sort -time` shapes compiled to an unordered outer
    // `SELECT … LIMIT n`: cursor pages over it repeated and skipped rows
    // (6,377 rows returned for a 5,981-row result).
    if newest_first_event_rows && !ends_in_event_cursor_order(&sql) {
        newest_first_event_rows = false;
    }
    if head_cap.is_some() && trailing_newest_first_limit(&sql) != Some(output_limit) {
        // Per-chunk execution would return up to N rows per chunk.
        newest_first_event_rows = false;
    }
    let required_columns = required_columns(
        &query,
        &sql,
        request.table_view,
        &generator,
        profile.as_ref(),
    );
    let mut required_columns = required_columns;
    if dataset == "logs"
        && query_needs_message(&query)
        && !required_columns
            .iter()
            .any(|column| column.name == "message")
    {
        required_columns.push(RequiredColumn {
            name: "message".to_string(),
            field_type: profile.field_type("message").unwrap_or(FieldType::String),
        });
        required_columns.sort_by(|left, right| left.name.cmp(&right.name));
    }
    if dataset == "logs"
        && query_needs_raw_data(&query)
        && !required_columns
            .iter()
            .any(|column| column.name == "raw_data")
    {
        required_columns.push(RequiredColumn {
            name: "raw_data".to_string(),
            field_type: profile.field_type("raw_data").unwrap_or(FieldType::String),
        });
        required_columns.sort_by(|left, right| left.name.cmp(&right.name));
    }
    let transformed_rows = !is_full_event_sql(&sql);
    let projected_scan_columns =
        projected_scan_columns(&query, &generator, profile.as_ref(), transformed_rows);
    if !sql.contains(source_placeholder) {
        bail!("query does not target the tenant lake source");
    }
    for forbidden in [
        "nanosiem.",
        "FROM logs",
        "FROM ocsf_logs",
        "FROM otel_",
        "FROM risk_findings",
        "FROM identity_observations",
    ] {
        if sql.contains(forbidden) {
            bail!("query requires an unsupported non-lake dataset: {forbidden}");
        }
    }
    let query_sha256 = hex::encode(Sha256::digest(request.query.as_bytes()));
    Ok(CompileResponse {
        schema_version: 1,
        profile: if dataset == "risk" { "risk" } else { "ocsf" },
        dataset,
        source_placeholder,
        query_sha256,
        start,
        end,
        limit: request.limit,
        table_view: request.table_view,
        newest_first_event_rows,
        stats_page,
        candidate_hints,
        required_columns,
        projected_scan_columns,
        sql,
    })
}

/// NAN-3276: generated SQL nests as deep as the user's expression does, and
/// a filter over many values is legitimately deep. sqlparser's default depth
/// (50) refused a 50-artifact prevalence read; ClickHouse itself accepts up to
/// its `max_parser_depth` (1000), and sqlparser's recursion protection grows
/// the stack, so the compiler accepts what the engine accepts.
const GENERATED_SQL_PARSER_DEPTH: usize = 1_000;

fn parse_generated_sql(
    sql: &str,
) -> Result<Vec<sqlparser::ast::Statement>, sqlparser::parser::ParserError> {
    sqlparser::parser::Parser::new(&sqlparser::dialect::ClickHouseDialect {})
        .with_recursion_limit(GENERATED_SQL_PARSER_DEPTH)
        .try_with_sql(sql)?
        .parse_statements()
}

fn is_full_event_sql(sql: &str) -> bool {
    let selects = regex::Regex::new(r"(?i)\bSELECT\b")
        .expect("static regex")
        .find_iter(sql)
        .count();
    let full_rows = regex::Regex::new(r"(?i)\bSELECT\s+\*\s+FROM\b")
        .expect("static regex")
        .find_iter(sql)
        .count();
    selects > 0 && selects == full_rows
}

fn has_internal_distinct_state(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            let current = match command {
                Command::Stats { aggregations, .. } => aggregations.iter().any(|aggregation| {
                    aggregation.func == nanosiem_core::query::AggFunc::Values
                        && aggregation.alias.as_deref() == Some(INTERNAL_DISTINCT_VALUES_ALIAS)
                }),
                _ => false,
            };
            current || has_internal_distinct_state(source)
        }
    }
}

/// Row-preserving projections retain the implicit newest-first event order.
/// Membership-changing and stateful commands deliberately fail this proof.
/// The smallest `head N` (or `sort … N`) bound in a newest-first timeline.
fn newest_first_head_cap(query: &Query) -> Option<usize> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            let current = match command {
                Command::Head { count } => Some(*count),
                Command::Sort { limit, .. } => *limit,
                _ => None,
            };
            match (newest_first_head_cap(source), current) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            }
        }
    }
}

/// `N` when the statement ends `ORDER BY time DESC [, "metadata.uid" DESC]
/// LIMIT N` (an optional trailing `SETTINGS …` aside). Mirrors the lake
/// worker's `newest_first_row_cap`, which is what actually stops the walk.
fn trailing_newest_first_limit(sql: &str) -> Option<usize> {
    let body = sql.rfind(" SETTINGS ").map_or(sql, |at| &sql[..at]);
    let (head, limit) = body.trim_end().rsplit_once(" LIMIT ")?;
    let limit = limit.trim().parse::<usize>().ok()?;
    let order = head.trim_end();
    let order = order
        .strip_suffix(", \"metadata.uid\" DESC")
        .unwrap_or(order)
        .trim_end();
    (order.ends_with("ORDER BY time DESC") || order.ends_with("ORDER BY \"time\" DESC"))
        .then_some(limit)
}

/// The statement's outer order is exactly the event cursor order,
/// `ORDER BY time DESC, "metadata.uid" DESC LIMIT n`.
fn ends_in_event_cursor_order(sql: &str) -> bool {
    let body = sql.rfind(" SETTINGS ").map_or(sql, |at| &sql[..at]);
    let Some((head, limit)) = body.trim_end().rsplit_once(" LIMIT ") else { return false };
    if limit.trim().parse::<usize>().is_err() {
        return false;
    }
    let head = head.trim_end();
    head.ends_with("ORDER BY time DESC, \"metadata.uid\" DESC")
        || head.ends_with("ORDER BY \"time\" DESC, \"metadata.uid\" DESC")
}

fn is_newest_first_event_projection(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            is_newest_first_event_projection(source)
                && (matches!(
                    command,
                    Command::Table { .. }
                        | Command::Fields { .. }
                        | Command::Head { .. }
                        | Command::Rename { .. }
                        | Command::Fillnull { .. }
                        | Command::Eval { .. }
                        | Command::Rex { .. }
                )
                    // NAN-2869: an explicit `sort -time` restates the
                    // default newest-first event order, so a timeline
                    // (`… | sort -time | head N`) pages newest-first too.
                    || matches!(
                        command,
                        Command::Sort { fields, .. }
                            if fields.len() == 1
                                && fields[0].descending
                                && matches!(fields[0].field.as_str(), "time" | "timestamp" | "_time")
                    ))
        }
    }
}

fn run() -> Result<()> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("failed to read compile request from stdin")?;
    let request: CompileRequest =
        serde_json::from_str(&input).context("compile request must be JSON")?;
    let response = compile(request)?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lake query compile failed: {error:#}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_pages_count_the_complete_pipeline_before_the_display_limit() {
        for query in [
            "* | stats count by src_endpoint.ip, actor.process.name",
            "* | stats count, max(timestamp) as last_seen by src_endpoint.ip | sort -count | head 500",
            "* | stats count by src_endpoint.ip | head 20",
        ] {
            let mut input = request(query);
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(output.stats_page, "{query}");
            assert!(output.sql.contains("SELECT *, count() OVER () AS __nano_stats_total"), "{}", output.sql);
            let final_sql = output.sql.rsplit_once("\nSELECT ").unwrap().1;
            assert!(output.sql.contains("OVER (ORDER BY count DESC"), "{}", output.sql);
            assert!(final_sql.contains("ORDER BY __nano_stats_ordinal"), "{final_sql}");
            assert!(final_sql.contains("LIMIT 100 SETTINGS"), "{final_sql}");
            // User head is in an earlier CTE, so cardinality counts its output.
            if query.ends_with("head 20") {
                assert!(output.sql.contains("\n  LIMIT 20"));
            }
        }
        for query in [
            "* | stats count by src_endpoint.ip | where count > 10",
            "* | stats count by src_endpoint.ip | eventstats sum(count) as total",
            "* | stats count by src_endpoint.ip | stats count",
            "* | timechart span=1h count",
        ] {
            let mut input = request(query);
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(!output.stats_page, "{query}");
            assert!(!output.sql.contains("__nano_stats_total"), "{query}");
        }
    }

    /// NAN-3276: the Asset dossier's global prevalence read (a grouped
    /// `stats` over an OR of per-artifact groups) compiled to SQL nested one
    /// parenthesis level per OR node, and the stats-page parse refused it at
    /// 50 artifacts: "failed to parse generated grouped page SQL: sql parser
    /// error: recursion limit exceeded". OR chains now compile flat, so that
    /// shape and a many-thousand-value list both page.
    #[test]
    fn grouped_pages_compile_for_long_or_chains_and_value_lists() {
        let group = |i: usize| {
            format!(
                "(query.hostname=\"d{i}.example\" OR http_request.url.hostname=\"d{i}.example\" \
                 OR url.hostname=\"d{i}.example\" OR dst_endpoint.hostname=\"d{i}.example\")"
            )
        };
        let groups = (0..50).map(group).collect::<Vec<_>>().join(" OR ");
        let values = (0..8_000)
            .map(|i| format!("\"d{i}.ex\""))
            .collect::<Vec<_>>()
            .join(", ");
        for predicate in [
            format!("({groups})"),
            format!("(query.hostname IN ({values}) OR file.hashes.value IN ({values}) OR dst_endpoint.hostname IN ({values}))"),
        ] {
            let mut input = request(&format!(
                "{predicate} | stats count() by query.hostname, file.hashes.value, device.hostname, src_endpoint.ip"
            ));
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(output.stats_page);
            assert!(output.sql.contains("__nano_stats_ordinal"), "{}", &output.sql[..300]);
            assert!(!output.sql.contains("(((("), "OR chains must not nest per node");
            // The same parser, at its default depth, accepts the result.
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::ClickHouseDialect {}, &output.sql)
                .expect("generated grouped page SQL parses at the default depth");
        }
    }

    /// NAN-3325: `stats sparkline` compiled to `sumMap(…).2`, which the
    /// grouped-page rewrite could not re-parse ("Expected: ), found: .2").
    #[test]
    fn grouped_sparkline_page_compiles() {
        let mut input = request("class_uid=4002 | stats sparkline by metadata.log_source");
        input.stats_page = true;
        let output = compile(input).expect("sparkline grouped page must compile");
        assert!(output.sql.contains("tupleElement(sumMap("), "{}", output.sql);
    }

    /// NAN-3385: `timechart bins=N` compiles on the lake against the request
    /// window (24 h / 10 → 3 h buckets), identical to the explicit span.
    #[test]
    fn timechart_bins_compiles_to_the_round_span() {
        let bins = compile(request("metadata.log_source=windows_event | timechart bins=10 count"))
            .expect("timechart bins= must compile");
        let span = compile(request("metadata.log_source=windows_event | timechart span=3h count"))
            .expect("timechart span= must compile");
        assert_eq!(bins.sql, span.sql);
    }

    #[test]
    fn lake_compile_uses_splunk_search_precedence() {
        let query = "class_uid=3002 activity_id=1 OR activity_id=2";
        let parsed = parse_query(query).unwrap();
        assert!(matches!(source_search_expression(&parsed), SearchExpr::And(_, right) if matches!(&**right, SearchExpr::Or(_, _))));
        let output = compile(request(query)).unwrap();
        assert!(output.sql.contains(" OR ") && output.sql.contains(" AND "), "{}", output.sql);
    }

    /// NAN-3150: the search service's lake timechart wrapper (`… | timechart
    /// … | sort time_bucket`) resolved the bucket as `ext.time_bucket` in
    /// stage_0 (`Code: 47. Unknown … identifier ext.time_bucket`).
    #[test]
    fn timechart_bucket_is_a_pipeline_output_not_an_ext_path() {
        for query in [
            "metadata.log_source=conduit_proxy src_endpoint.ip=10.1.5.242 | timechart span=1h sum(traffic.bytes_out) as bytes_out_total | sort time_bucket",
            "metadata.log_source=conduit_proxy | timechart span=1h count | sort time_bucket",
            "metadata.log_source=conduit_proxy | timechart span=10m count | where time_bucket > 0 | sort -time_bucket",
        ] {
            let mut input = request(query);
            input.stats_page = true;
            let output = compile(input).unwrap();
            assert!(!output.sql.contains("ext."), "{query}: {}", output.sql);
            assert!(!output.required_columns.iter().any(|column| column.name.contains("time_bucket")), "{query}");
            assert!(output.sql.contains("AS time_bucket"), "{}", output.sql);
        }
    }

    fn request(query: &str) -> CompileRequest {
        CompileRequest {
            query: query.to_string(),
            stats_page: false,
            stats_page_offset: 0,
            dataset: default_dataset(),
            start: "2026-08-07T00:00:00Z".to_string(),
            end: "2026-08-08T00:00:00Z".to_string(),
            limit: 100,
            table_view: true,
            event_contract: default_event_contract(),
            unmapped_field_types: BTreeMap::new(),
            snapshot_field_types: BTreeMap::new(),
            lowercased_fields: Vec::new(),
        }
    }

    /// NAN-3059: `event_type=<label>` compares the class-scoped enum's label
    /// column (`lower(activity_name) = …`). A projected plan such as the
    /// documented process tree must declare that column, or stage 0 fails on
    /// the lean cell with `Unknown expression identifier activity_name`.
    #[test]
    fn enum_label_filter_declares_its_label_column() {
        for query in [
            r#"src_host="ws-1" event_type=process_start | tree parent=parent_process_guid child=process_guid label=process_name"#,
            "event_type=logon | stats count() by device.hostname",
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.sql.contains("activity_name"), "{}", output.sql);
            assert!(
                output.required_columns.iter().any(|c| c.name == "activity_name"),
                "{query}: {:?}",
                output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
    }

    /// NAN-2869: raw equality only for paths the window proves lowercased at
    /// rest; the literal is lowered at compile time. Everything else keeps
    /// `lower(col)` (mixed-case producers, e.g. `WINDOWS_EVENT`).
    #[test]
    fn lowercased_at_rest_paths_compare_raw_with_a_lowered_literal() {
        let query = r#"metadata.log_source="WinEvent_Security" | stats count by user.name"#;
        let unproven = compile(request(query)).expect("compiles");
        assert!(unproven.sql.contains(r#"lower("metadata.log_source") = 'winevent_security'"#), "{}", unproven.sql);
        let mut proven = request(query);
        proven.snapshot_field_types = BTreeMap::from([
            ("metadata.log_source".to_string(), FieldType::String),
            ("user.name".to_string(), FieldType::String),
            ("time".to_string(), FieldType::Timestamp),
        ]);
        proven.lowercased_fields = vec!["metadata.log_source".to_string()];
        let proven = compile(proven).expect("compiles");
        assert!(proven.sql.contains(r#""metadata.log_source" = 'winevent_security'"#), "{}", proven.sql);
        assert!(!proven.sql.contains(r#"lower("metadata.log_source")"#), "{}", proven.sql);
        // A path outside the snapshot's string leaves is refused, and the
        // hint needs the lake contract.
        let mut bad = request(query);
        bad.lowercased_fields = vec!["user.name".to_string()];
        assert!(compile(bad).is_err());
        let mut legacy = request(query);
        legacy.event_contract = "legacy-flat-ocsf-1.8".to_string();
        legacy.lowercased_fields = vec!["metadata.log_source".to_string()];
        assert!(compile(legacy).is_err());
    }

    /// NAN-3154: ingest-lowercased identity paths compare RAW against the
    /// lowered literal on the lake -- including both legs of the dotless
    /// hostname expansion -- so chDB's Parquet bloom/min-max push-down can
    /// prune. Every other string field keeps `lower(col)`, and negations keep
    /// `lower()` (an uppercase row must stay excluded).
    #[test]
    fn lowercased_identity_paths_compare_raw_and_others_keep_lower() {
        let where_of = |query: &str| {
            let sql = compile(request(query)).expect("compiles").sql;
            sql[sql.find(" WHERE ").expect("where")..].to_string()
        };
        for (query, raw) in [
            (r#"device.hostname="WS-1.Corp.Local" | head 5"#, r#""device.hostname" = 'ws-1.corp.local'"#),
            (
                r#"device.hostname="WS-1" | head 5"#,
                r#"("device.hostname" = 'ws-1' OR startsWith("device.hostname", 'ws-1.'))"#,
            ),
            (
                r#"src_endpoint.hostname IN ("WS-1", "db.corp") | head 5"#,
                r#"("src_endpoint.hostname" IN ('ws-1', 'db.corp') OR startsWith("src_endpoint.hostname", 'ws-1.'))"#,
            ),
            (r#"src_endpoint.ip="10.1.1.46" | head 5"#, r#""src_endpoint.ip" = '10.1.1.46'"#),
            (r#"dst_endpoint.mac="AA:BB:CC:DD:EE:FF" | head 5"#, r#""dst_endpoint.mac" = 'aa:bb:cc:dd:ee:ff'"#),
        ] {
            let clause = where_of(query);
            assert!(clause.contains(raw), "{query}: {clause}");
            assert!(!clause.contains("lower(\""), "{query}: {clause}");
        }
        for (query, lowered) in [
            (r#"user.name="Bob" | head 5"#, r#"lower("user.name") = 'bob'"#),
            (r#"process.name="CMD.exe" | head 5"#, r#"lower("process.name") = 'cmd.exe'"#),
            (
                r#"device.hostname!="WS-1" | head 5"#,
                r#"(lower("device.hostname") != 'ws-1' AND NOT startsWith(lower("device.hostname"), 'ws-1.'))"#,
            ),
            (r#"src_endpoint.hostname NOT IN ("WS-1") | head 5"#, r#"NOT startsWith(lower("src_endpoint.hostname"), 'ws-1.')"#),
        ] {
            let clause = where_of(query);
            assert!(clause.contains(lowered), "{query}: {clause}");
        }
    }

    /// NAN-2994: the whole gen1 k6 realistic corpus (94 queries, also driven
    /// by `benchmarks/k6/lean_gate_search.js`) passes BOTH lean validation
    /// hops: the Search front door, whose cell-tenant profile has no snapshot
    /// inventory, and query[T]'s compile against a stored lake schema (the
    /// live read-schema fixture plus the NAN-2915 lean prevalence column).
    #[test]
    fn nan2994_k6_corpus_passes_front_door_and_cell_compile() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../benchmarks/results/soc_ir_corpus.json"
        ))
        .unwrap();
        let queries: Vec<&str> = corpus["domains"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|domain| domain["queries"].as_array().unwrap())
            .map(|query| query["query"].as_str().unwrap())
            .collect();
        assert_eq!(queries.len(), 94);
        assert!(queries
            .iter()
            .any(|query| query.contains("metadata.event_code")));
        assert!(queries.iter().any(|query| query.contains("action_id")));

        let front_door = nanosiem_core::schema::tenant_lake_schema::canonical_shared_lake_profile();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../nanosiem-lake-worker/tests/fixtures/nan2469-live-tail-read-schema.json"
        ))
        .unwrap();
        let mut stored: BTreeMap<String, FieldType> =
            serde_json::from_value::<Vec<String>>(fixture["available_paths"].clone())
                .unwrap()
                .into_iter()
                .map(|path| (path, FieldType::String))
                .collect();
        stored.insert("prevalence_dest_ip".into(), FieldType::Integer);

        let mut front_door_rejects = Vec::new();
        let mut compile_failures = Vec::new();
        for query in &queries {
            let parsed = parse_query(query).unwrap();
            for error in validate_query_fields_with_profile(&parsed, Some(front_door.as_ref())) {
                front_door_rejects.push(format!("{}: {query}", error.field_name));
            }
            let mut input = request(query);
            input.snapshot_field_types = stored.clone();
            if let Err(error) = compile(input) {
                compile_failures.push(format!("{error:#}: {query}"));
            }
        }
        assert!(compile_failures.is_empty(), "{compile_failures:#?}");
        // `prevalence_dest_ip` is not an OCSF path: only a tenant inventory can
        // vouch for the NAN-2915 stamp column, and the front door has none.
        assert!(
            front_door_rejects
                .iter()
                .all(|reject| reject.starts_with("prevalence_dest_ip: ")),
            "{front_door_rejects:#?}"
        );
    }

    #[test]
    fn nan2912_unstamped_prevalence_queries_fail_instead_of_injecting_a_constant() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!(
            "../../../benchmarks/results/soc_ir_corpus.json"
        ))
        .unwrap();
        let query = corpus["domains"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|domain| domain["queries"].as_array().unwrap())
            .nth(88)
            .unwrap()["query"]
            .as_str()
            .unwrap();
        assert!(query.contains("prevalence_dest_ip<50"));
        for query in [query, "prevalence_dest_ip<50 | stats count"] {
            let error = compile(request(query)).unwrap_err().to_string();
            assert!(error.contains("prevalence_dest_ip"), "{error}");
            assert!(error.contains("field not searchable on this lake yet"), "{error}");
            assert!(!error.contains("Unknown canonical OCSF field"), "{error}");
        }
        let mut partial = request("prevalence_dest_ip<50 | stats count");
        partial.snapshot_field_types.insert("enrichments.data.host_count".into(), FieldType::Array);
        assert!(compile(partial).unwrap_err().to_string().contains("field not searchable on this lake yet"));
        // NAN-2915: lean signed parts carry a physical ingest-time stamp column.
        let mut lean = request("prevalence_dest_ip<50 | stats count");
        lean.snapshot_field_types.insert("prevalence_dest_ip".into(), FieldType::Integer);
        let sql = compile(lean).unwrap().sql;
        assert!(sql.contains("prevalence_dest_ip"), "{sql}");
    }

    /// NAN-3188: a mandatory `class_uid = N` becomes a whole-file class
    /// hint; under OR or NOT it must not (another branch / the complement
    /// can match rows of any class).
    #[test]
    fn class_uid_equality_under_and_is_a_class_hint_only() {
        let classes = |query: &str| {
            compile(request(query))
                .unwrap_or_else(|error| panic!("{query}: {error:#}"))
                .candidate_hints
                .into_iter()
                .filter(|hint| matches!(hint, CandidateHint::Class { .. }))
                .collect::<Vec<_>>()
        };
        let class = |value| vec![CandidateHint::Class { value }];
        // The two NAN-3188 7d hunts.
        assert_eq!(
            classes("metadata.log_source=windows_sysmon (class_uid=201002 activity_id=2) CurrentVersion Run | stats count() by device.hostname"),
            class(201002)
        );
        assert_eq!(classes("(class_uid=4001 activity_id=1) dst_endpoint.port=445 | stats count() by device.hostname"), class(4001));
        assert_eq!(classes("class_uid=4001"), class(4001));
        assert_eq!(classes(r#"class_uid="4001" activity_id=1"#), class(4001));
        assert_eq!(classes("class_uid=4001 class_uid=4001"), class(4001), "deduplicated");
        for query in [
            "class_uid=4001 OR class_uid=1001",
            "(class_uid=4001 OR dst_endpoint.port=445) activity_id=1",
            "class_uid=4001 OR metadata.log_source=windows_sysmon",
            "NOT class_uid=4001",
            "NOT (class_uid=4001 activity_id=1)",
            "class_uid!=4001",
            "class_uid>4000",
            r#"class_uid="04001""#,
            r#"class_uid="4001x""#,
            "class_uid=4001.5",
            "class_uid IN (4001, 1001)",
            // A post-search where is not a search-term conjunct.
            "dst_endpoint.port=445 | where class_uid=4001",
        ] {
            assert!(classes(query).is_empty(), "{query}");
        }
        let output = compile(request("class_uid=4001 dst_endpoint.port=445")).unwrap();
        assert!(output.sql.contains("4001"), "the SQL still filters rows: {}", output.sql);
        let wire = serde_json::to_value(&output.candidate_hints).unwrap();
        assert!(wire.as_array().unwrap().contains(&serde_json::json!({"kind": "class", "value": 4001})), "{wire}");
    }

    #[test]
    fn non_equality_entity_literals_have_no_candidate_hints() {
        for npl in [
            "user.name=jsm*",
            "user.name=*",
            r#"user.name="""#,
            "user.name=jsm?th",
            "src_endpoint.ip=10.0.0.0/8",
            "dst_endpoint.ip=10.0.0.0/8",
        ] {
            for query in [npl.to_string(), format!(r#"({npl} OR user.name="bob")"#)] {
                let output = compile(request(&query)).unwrap();
                assert!(output.candidate_hints.is_empty(), "{query}: {:?}", output.candidate_hints);
            }
        }
        // A slash in a non-IP identity remains literal equality.
        assert!(matches!(
            compile(request(r#"user.name="domain/jsmith""#)).unwrap().candidate_hints.as_slice(),
            [CandidateHint::Entity { .. }]
        ));
    }

    /// NAN-2961: a correlation query binds one candidate part set for every
    /// scan, so outer-search hints (which would hide subsearch-only parts)
    /// and progressive time-fenced paging are both off for it.
    #[test]
    fn correlation_queries_are_never_pruned_or_paged_by_the_outer_search() {
        let plain = compile(request(r#"user.name="bob""#)).unwrap();
        assert!(!plain.candidate_hints.is_empty());
        assert!(plain.newest_first_event_rows);
        for query in [
            r#"user.name="bob" | join device.hostname [search user.name="alice"]"#,
            r#"user.name="bob" | append [search user.name="alice"]"#,
            r#"user.name="bob" device.hostname IN [search user.name="alice" | return device.hostname]"#,
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.candidate_hints.is_empty(), "{query}: {:?}", output.candidate_hints);
            assert!(!output.newest_first_event_rows, "{query}");
        }
    }

    #[test]
    fn disjunction_requires_every_branch_and_preserves_boolean_groups() {
        let wide_or = (0..8).map(|i| format!("user.name=\"user{i}\"")).collect::<Vec<_>>().join(" OR ");
        let bounded = compile(request(&format!("user.uid=\"mandatory\" ({wide_or})"))).unwrap();
        assert!(matches!(bounded.candidate_hints.as_slice(), [CandidateHint::Entity { source_path, .. }] if source_path == "user.uid"));
        let uid = compile(request(r#"actor.user.uid="S-1-5-21""#)).unwrap();
        assert!(matches!(uid.candidate_hints.as_slice(), [CandidateHint::Entity { source_path, .. }] if source_path == "actor.user.uid"));
        let q = compile(request(r#"(actor.user.name="jsmith" OR user.name="jsmith")"#)).unwrap();
        assert!(matches!(q.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));
        for npl in [r#"user.name="jsmith" OR class_uid=3002"#, r#"NOT user.name="jsmith""#, r#"user.name="jsmith" OR class_uid!=3002"#] {
            assert!(compile(request(npl)).unwrap().candidate_hints.is_empty(), "{npl}");
        }
    }

    #[test]
    fn nan2455_corpus_compile_and_sidecar_hints() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!("../../../benchmarks/results/soc_ir_corpus.json")).unwrap();
        for (prefix, hint) in [
            ("Registry Run-key", "currentversion"),
            ("Single-host egress", "10.1.5.242"),
            ("Encoded-PowerShell", "enc"),
            ("Triage: any new scheduled-task", ""),
            ("Hunt: process_create invoking PowerShell with -ExecutionPolicy", "xecution"),
            ("Retro IR: rare external destinations", ""),
            ("AD account & group enumeration", "net"),
        ] {
            let query = corpus["domains"].as_array().unwrap().iter()
                .flat_map(|d| d["queries"].as_array().unwrap())
                .find(|q| q["use_case"].as_str().unwrap().starts_with(prefix)).unwrap();
            let mut input = request(query["query"].as_str().unwrap());
            for field in ["enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
                input.snapshot_field_types.insert(field.into(), FieldType::Array);
            }
            let output = compile(input).unwrap_or_else(|e| panic!("{prefix}: {e:#}"));
            if !hint.is_empty() {
                assert!(output.candidate_hints.iter().any(|h| match h {
                    CandidateHint::Entity { value, .. } | CandidateHint::Keyword { value, .. } | CandidateHint::SourceFamily { value } => value.eq_ignore_ascii_case(hint),
                    CandidateHint::Any { .. } | CandidateHint::Class { .. } => false,
                }), "{prefix}: {:?}", output.candidate_hints);
            }
            println!("NAN2455_COMPILE {}", serde_json::to_string(&output).unwrap());
        }
    }

    #[test]
    fn stored_enrichment_selectors_correlate_and_preserve_unknown() {
        for field in ["enriched_src_country", "src_is_tor", "ioc_src_ip_threat_type", "synthient_src_vpn"] {
            let query = format!("* | stats count by {field} | sort -count | head 10");
            let old = compile(request(&query)).unwrap();
            assert!(old.sql.contains("CAST(NULL AS Nullable("), "{}", old.sql);
            assert!(!old.sql.contains("JOIN"));
            let mut input = request(&query);
            for name in ["enrichments.name", "enrichments.provider", "enrichments.data.status", "enrichments.data.country_name", "enrichments.data.owned_fields", "enrichments.data.is_tor", "enrichments.data.threat_type", "enrichments.data.vpn"] {
                input.snapshot_field_types.insert(name.into(), FieldType::Array);
            }
            let output = compile(input).unwrap();
            assert!(output.sql.contains("arrayFirstIndex((n, p, s"), "{}", output.sql);
            assert!(!output.sql.contains("JOIN"));
            assert!(!output.required_columns.iter().any(|c| c.name == field));
        }
        assert!(compile(request("synthient_src_vpp=true | stats count")).is_err());
        let country = compile(request("* | table enriched_src_country, enriched_src_country_code, enriched_src_asn")).unwrap();
        assert!(country.sql.contains("src_endpoint.location.country"));
        assert!(country.sql.contains("src_endpoint.autonomous_system.number"));
    }

    #[test]
    fn ipinfo_lite_text_arrays_use_case_insensitive_membership() {
        for (field, value, lowered) in [
            ("enrichments.data.country_name", "United States", "united states"),
            ("enrichments.data.continent_code", "NA", "na"),
            ("enrichments.data.as_domain", "Fixture.Example", "fixture.example"),
        ] {
            for op in ["=", "!="] {
                let mut input = request(&format!("{field}{op}\"{value}\" | stats count"));
                input.snapshot_field_types.insert(field.into(), FieldType::Array);
                let output = compile(input).unwrap();
                let predicate = format!("arrayExists(x -> lower(toString(x)) = '{lowered}', \"{field}\")");
                assert!(output.sql.contains(&predicate), "{}", output.sql);
                if op == "!=" { assert!(output.sql.contains(&format!("NOT {predicate}"))); }
                assert!(output.required_columns.iter().any(|column| column.name == field));
            }
        }
    }

    #[test]
    fn nan2455_prevalence_declares_derivative_stamp_inputs_not_a_phantom_column() {
        let mut input = request("prevalence_dest_ip<50 | stats count by dst_endpoint.ip,prevalence_dest_ip");
        for name in ["enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
            input.snapshot_field_types.insert(name.into(), FieldType::Array);
        }
        let output = compile(input).unwrap();
        assert!(output.sql.contains("arrayFirstIndex"), "{}", output.sql);
        for name in ["dst_endpoint.ip", "enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
            assert!(output.required_columns.iter().any(|c| c.name == name), "missing {name}");
            assert!(output.projected_scan_columns.iter().any(|c| c == name), "missing scan {name}");
        }
        assert!(!output.required_columns.iter().any(|c| c.name == "prevalence_dest_ip"));
        assert!(!output.projected_scan_columns.iter().any(|c| c == "prevalence_dest_ip"));
        assert!(compile(request("prevalence_dest_ip<50 | stats count")).is_err());
    }

    /// NAN-3451: the same prevalence nPL compiles on an open-core lake (derived
    /// from the stamp arrays, reading only real columns) and on lean (the
    /// physical stamp columns), and fails clearly on an unstamped snapshot.
    #[test]
    fn nan3451_prevalence_scalars_compile_on_open_core_and_lean() {
        let open_core = |query: &str| {
            let mut input = request(query);
            for name in [
                "enrichments.name",
                "enrichments.provider",
                "enrichments.value",
                "enrichments.data.host_count",
                "enrichments.data.host_count_saturated",
                "file.hashes.value",
                "process.file.hashes.value",
            ] {
                input.snapshot_field_types.insert(name.into(), FieldType::Array);
            }
            compile(input)
        };
        for query in [
            "* | where prevalence_min <= 3 | stats count",
            "prevalence_file_hash<5 | stats count by file.hashes.value",
            "prevalence_process_hash=1 OR prevalence_dest_domain<10 | stats count",
            "* | stats min(prevalence_min) as rarest by device.hostname",
        ] {
            let output = open_core(query).unwrap_or_else(|error| panic!("{query}: {error:#}"));
            assert!(output.sql.contains("arrayFirstIndex"), "{query}: {}", output.sql);
            for phantom in super::PREVALENCE_SCALARS {
                assert!(!output.required_columns.iter().any(|c| c.name == phantom), "{query}: {phantom}");
                assert!(!output.projected_scan_columns.iter().any(|c| c == phantom), "{query}: {phantom}");
            }
            assert!(output.required_columns.iter().any(|c| c.name == "enrichments.value"), "{query}");
        }
        let min = open_core("* | where prevalence_min <= 3 | stats count").unwrap();
        for input in ["file.hashes.value", "process.file.hashes.value", "dst_endpoint.ip"] {
            assert!(min.required_columns.iter().any(|c| c.name == input), "missing {input}");
        }

        let mut lean = request("* | where prevalence_min <= 3 | stats count");
        for name in super::PREVALENCE_SCALARS {
            lean.snapshot_field_types.insert(name.into(), FieldType::Integer);
        }
        lean.snapshot_field_types.insert("enrichments.value".into(), FieldType::Array);
        let lean = compile(lean).unwrap();
        assert!(!lean.sql.contains("arrayFirstIndex"), "{}", lean.sql);
        assert!(lean.required_columns.iter().any(|c| c.name == "prevalence_min"));

        let error = compile(request("* | where prevalence_min <= 3 | stats count"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("prevalence_min: field not searchable on this lake yet"), "{error}");
    }

    /// NAN-2707: `field=*` on a typed non-string scalar emitted `col != ''`,
    /// which chDB rejects (`converting '' to UInt16`); the worker 500 then
    /// surfaced as a 503 "search service unavailable" on every attempt.
    #[test]
    fn nan2707_existence_on_typed_scalars_never_compares_with_empty_string() {
        let stamped = |query: &str| {
            let mut input = request(query);
            for name in ["enrichments.name", "enrichments.provider", "enrichments.value", "enrichments.data.host_count", "enrichments.data.host_count_saturated"] {
                input.snapshot_field_types.insert(name.into(), FieldType::Array);
            }
            compile(input).unwrap().sql
        };
        for sql in [
            stamped("prevalence_dest_ip=* | stats count"),
        ] {
            assert!(
                sql.contains("(prevalence_dest_ip IS NOT NULL AND prevalence_dest_ip != 65535)"),
                "prevalence existence must exclude the N/A sentinel: {sql}"
            );
            assert!(!sql.contains("prevalence_dest_ip != ''"), "{sql}");
        }
        let absent = stamped("prevalence_dest_ip!=* | stats count");
        assert!(
            absent.contains("NOT (prevalence_dest_ip IS NOT NULL AND prevalence_dest_ip != 65535)"),
            "{absent}"
        );
        for (query, column) in [
            ("dst_endpoint.port=* | stats count", "\"dst_endpoint.port\""),
            ("time=* | stats count", "time"),
        ] {
            let sql = compile(request(query)).unwrap().sql;
            assert!(
                sql.contains(&format!("({column} IS NOT NULL AND toString({column}) != '')")),
                "{query}: {sql}"
            );
            assert!(!sql.contains(&format!("{column} != ''")), "{query}: {sql}");
        }
        // String leaves keep the unchanged (index-neutral) form.
        let ip = compile(request("src_endpoint.ip=* | stats count")).unwrap().sql;
        assert!(ip.contains("\"src_endpoint.ip\" != ''"), "{ip}");
        // The post-pipe `where` arm agrees on the sentinel.
        let piped = stamped("* | where prevalence_dest_ip=* | stats count");
        assert!(piped.contains("prevalence_dest_ip != 65535"), "{piped}");
    }

    #[test]
    fn lake_udm_aliases_validate_and_compile_to_physical_columns() {
        let mut queries = vec![
            "user=* | stats count by user".to_string(),
            "src_ip=10.0.0.1 | stats count by src_ip".to_string(),
            "source_type=windows_sysmon process_name=powershell.exe | table command_line, parent_command_line, src_host".to_string(),
            "file_hash=abc OR process_hash=abc | stats count by dest_ip".to_string(),
            "process_hash IN (\"abc\", \"def\") | stats count by user".to_string(),
            "* | stats count by uri | append [search * | stats count by src_ip]".to_string(),
        ];
        #[cfg(feature = "enterprise")]
        {
            let settings =
                nanosiem_core::enterprise_shared_identity_sync::TenantIdentitySyncSettings::default(
                );
            queries.push(settings.observed_users_query());
            queries.push(settings.last_sign_in_query());
        }
        for query in queries {
            let profile = OcsfProfile::lake_1_9();
            let parsed = parse_query(&query).unwrap();
            let errors = validate_query_fields_with_profile(&parsed, Some(&profile));
            assert!(errors.is_empty(), "{query}: {errors:?}");
            let output = compile(request(&query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(!output.sql.contains("JSONExtract"), "{}", output.sql);
            assert!(!output.sql.contains("_unified"), "{}", output.sql);
            if query.starts_with("user=") {
                assert!(output.sql.contains("\"user.name\""), "{}", output.sql);
                assert!(output.sql.contains("\"actor.user.name\""), "{}", output.sql);
                for name in ["user.name", "actor.user.name"] {
                    assert!(
                        output.required_columns.iter().any(|c| c.name == name),
                        "missing {name}: {}",
                        output.sql
                    );
                    assert!(
                        output.projected_scan_columns.iter().any(|c| c == name),
                        "missing scan {name}"
                    );
                }
            }
            for column in &output.required_columns {
                assert_ne!(column.name, "user");
                assert_ne!(column.name, "timestamp");
                assert_ne!(column.name, "src_ip");
            }
            if query.starts_with("src_ip=") {
                assert!(output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
            }
            if query.starts_with("process_hash IN") {
                assert!(output.sql.contains("arrayExists("), "{}", output.sql);
                assert!(output.sql.contains("\"actor.process.file.hashes.value\""), "{}", output.sql);
            }
            if query.contains("append") {
                assert!(!output.sql.contains("\"url\""), "output alias uri must not become url: {}", output.sql);
            }
        }
    }

    #[test]
    fn lake_unknown_alias_keeps_suggestions() {
        let profile = OcsfProfile::lake_1_9();
        let parsed = parse_query("src_ipp=10.0.0.1").unwrap();
        let errors = validate_query_fields_with_profile(&parsed, Some(&profile));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].suggestions.contains(&"src_ip".to_string()));
        assert!(compile(request("src_ipp=10.0.0.1")).is_err());
        assert!(compile(request("user_identity_emali=x")).is_err());
    }

    #[test]
    fn legacy_contract_remains_explicit_during_migration() {
        let mut legacy = request(
            r#"source_type="windows_sysmon" process.name="powershell.exe" | table process.name, device.hostname"#,
        );
        legacy.event_contract = "legacy-flat-ocsf-1.8".to_string();
        let output = compile(legacy).expect("explicit legacy query should compile");

        assert_eq!(output.profile, "ocsf");
        assert!(output.sql.contains("FROM __nano_lake_source__"));
        assert!(output.sql.contains("\"process.name\""));
        assert!(output.sql.contains("\"device.hostname\""));
        assert!(!output.sql.contains("nanosiem."));
    }

    #[test]
    fn rejects_invalid_window_and_limit() {
        let mut invalid_window = request("error");
        invalid_window.end = invalid_window.start.clone();
        assert!(compile(invalid_window).is_err());

        let mut invalid_limit = request("error");
        invalid_limit.limit = 0;
        assert!(compile(invalid_limit).is_err());

        let mut truncation_sentinel = request("error");
        truncation_sentinel.limit = 1_000_001;
        assert!(compile(truncation_sentinel).is_ok());

        let mut above_internal_limit = request("error");
        above_internal_limit.limit = 1_000_002;
        assert!(compile(above_internal_limit).is_err());
    }

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity { source_path: path.to_string(), value: value.to_string() }
    }

    /// NAN-3162: analysts type barewords. A bareword the generator reads as a
    /// VALUE compiles to exactly the SQL of its quoted spelling, so it must
    /// carry exactly the same candidate hints -- without them the query
    /// skipped the bloom sidecar, entity locators, density-seeded progressive
    /// and raw-equality pushdown.
    #[test]
    fn bareword_entity_values_hint_exactly_like_quoted() {
        for (bare, quoted, expected) in [
            ("device.hostname=web1.corp.local", r#"device.hostname="web1.corp.local""#,
             vec![entity("device.hostname", "web1.corp.local")]),
            ("user.name=alice", r#"user.name="alice""#, vec![entity("user.name", "alice")]),
            ("src_endpoint.ip=10.1.2.3", r#"src_endpoint.ip="10.1.2.3""#,
             vec![entity("src_endpoint.ip", "10.1.2.3")]),
            ("file.hashes.value=d41d8cd98f00b204e9800998ecf8427e",
             r#"file.hashes.value="d41d8cd98f00b204e9800998ecf8427e""#,
             vec![entity("file.hashes.value", "d41d8cd98f00b204e9800998ecf8427e")]),
            ("process.name=cmd.exe", r#"process.name="cmd.exe""#, vec![entity("process.name", "cmd.exe")]),
            // Product aliases resolve exactly as the SQL generator resolves them.
            ("host=web1.corp.local", r#"host="web1.corp.local""#,
             vec![entity("device.hostname", "web1.corp.local")]),
            ("src_ip=10.1.2.3", r#"src_ip="10.1.2.3""#, vec![entity("src_endpoint.ip", "10.1.2.3")]),
            ("dest_host=web1.corp.local", r#"dest_host="web1.corp.local""#,
             vec![entity("dst_endpoint.hostname", "web1.corp.local")]),
            // A class-split alias lowers to `if(a != '', a, b) = v`: the
            // union of both exact lookups is a superset of its rows.
            ("user=alice", r#"user="alice""#, vec![CandidateHint::Any {
                alternatives: vec![entity("user.name", "alice"), entity("actor.user.name", "alice")],
            }]),
            ("process_name=cmd.exe", r#"process_name="cmd.exe""#, vec![CandidateHint::Any {
                alternatives: vec![entity("process.name", "cmd.exe"), entity("actor.process.name", "cmd.exe")],
            }]),
        ] {
            for shape in [" | head 20", " | sort -time | head 50", ""] {
                let bare_out = compile(request(&format!("{bare}{shape}"))).expect(bare);
                let quoted_out = compile(request(&format!("{quoted}{shape}"))).expect(quoted);
                assert_eq!(bare_out.sql, quoted_out.sql, "{bare}{shape}: identical SQL");
                assert_eq!(bare_out.candidate_hints, quoted_out.candidate_hints, "{bare}{shape}");
                assert_eq!(bare_out.candidate_hints, expected, "{bare}{shape}");
                assert_eq!(bare_out.newest_first_event_rows, quoted_out.newest_first_event_rows, "{bare}{shape}");
            }
        }
    }

    /// NAN-3162: what must still get NO exact entity hint.
    #[test]
    fn bareword_non_values_get_no_entity_hint() {
        let no_entity = |hints: &[CandidateHint]| !hints.iter().any(|hint| matches!(hint,
            CandidateHint::Entity { .. } | CandidateHint::Any { .. }));
        for query in [
            // Field references (NAN-2380): a column NAME is not a value.
            "user.name=actor.user.name",
            "user.name=user",
            // Wildcards and regexes are not exact equality.
            "user.name=web*",
            "host=web*",
            "user.name=/adm.*/",
            "user=/adm.*/",
            // Dotless host names expand to an FQDN prefix match (NAN-2361).
            "device.hostname=ws1",
            "host=ws1",
            "src_host=ws1",
            // Numeric barewords are typed literals, never entity values.
            "src_endpoint.port=443",
            "process.uid=1234",
            "user.uid=1001",
            // CIDR membership is a range, not equality.
            "src_ip=10.0.0.0/8",
        ] {
            let output = compile(request(&format!("{query} | head 5"))).expect(query);
            assert!(no_entity(&output.candidate_hints), "{query}: {:?}", output.candidate_hints);
        }
    }

    /// A class-split alias inside an OR contributes its alternatives to the
    /// OR's one flat union.
    #[test]
    fn class_split_alias_flattens_into_or_union() {
        let output = compile(request("user=alice OR src_ip=10.1.2.3 | head 5")).unwrap();
        assert_eq!(output.candidate_hints, vec![CandidateHint::Any {
            alternatives: vec![
                entity("user.name", "alice"),
                entity("actor.user.name", "alice"),
                entity("src_endpoint.ip", "10.1.2.3"),
            ],
        }]);
    }

    /// NAN-3162: windows over 24 h keep the event-UID tie-break on the lake,
    /// so `head N` timelines page newest first (progressive + cursor).
    #[test]
    fn long_window_timelines_keep_cursor_order_on_the_lake() {
        for query in [
            "src_endpoint.ip=10.1.2.3 | head 50",
            "host=web1.corp.local | sort -time | head 50",
            "* | sort -time | head 20",
            "user.name=alice",
        ] {
            for end in ["2026-08-08T00:00:00Z", "2026-08-14T00:00:00Z", "2026-09-06T00:00:00Z"] {
                let mut input = request(query);
                input.end = end.to_string();
                let output = compile(input).expect(query);
                assert!(output.newest_first_event_rows, "{query} to {end}: {}", output.sql);
                assert!(ends_in_event_cursor_order(&output.sql), "{query} to {end}: {}", output.sql);
            }
        }
        // ClickHouse generators keep the 24 h cap byte-identically.
        let query = parse_query("* | head 5").unwrap();
        let range = TimeRange::new(
            parse_timestamp("2026-08-07T00:00:00Z", "start").unwrap(),
            parse_timestamp("2026-08-14T00:00:00Z", "end").unwrap(),
        );
        let options = QueryOptions { use_cache: false, table_view: true, limit: Some(5), unordered: false };
        let profile = std::sync::Arc::new(OcsfProfile::lake_1_9());
        let default = ClickHouseSqlGenerator::with_table(SOURCE_PLACEHOLDER)
            .with_profile(profile.clone())
            .generate_with_options(&query, &range, &options)
            .unwrap();
        assert!(!default.contains("\"metadata.uid\" DESC"), "{default}");
        let lake = ClickHouseSqlGenerator::with_table(SOURCE_PLACEHOLDER)
            .with_profile(profile)
            .with_uid_tiebreak_any_window(true)
            .generate_with_options(&query, &range, &options)
            .unwrap();
        assert!(lake.contains("ORDER BY time DESC, \"metadata.uid\" DESC"), "{lake}");
    }

    /// NAN-2361: a candidate hint must never be NARROWER than the SQL it ships
    /// with — candidates prune the source, so anything the hint excludes is a
    /// row the query can no longer return.
    ///
    /// A dotless hostname compiles to `= v OR startsWith(col, 'v.')`, but the
    /// entity hint carried the bare literal. Objects holding only
    /// `ws-fin-011.corp.local` were pruned before the SQL ran, so
    /// `device.hostname="ws-fin-011"` returned zero rows on promoted data while
    /// the same query worked against the hot tail, which has no entity sidecar
    /// to prune with.
    #[test]
    fn dotless_hostname_equality_emits_no_entity_hint() {
        let short = compile(request(r#"device.hostname="ws-fin-011" | head 5"#))
            .expect("short hostname query should compile");
        assert!(
            short.sql.contains("startsWith"),
            "the dotless form must still expand to the FQDN-prefix match: {}",
            short.sql
        );
        // It degrades to the substring lane rather than losing pruning
        // entirely: `ws-fin-011.corp.local` CONTAINS `ws-fin-011`, so a
        // contains-hint stays a superset of the expanded predicate. Only the
        // exact-value entity hint is unsound here.
        assert!(
            !short
                .candidate_hints
                .iter()
                .any(|hint| matches!(hint, CandidateHint::Entity { .. })),
            "an exact-value entity hint cannot accompany an expanded predicate: {:?}",
            short.candidate_hints
        );
        assert_eq!(
            short.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "contains",
                value: "ws-fin-011".to_string(),
            }]
        );

        // An FQDN is genuine exact equality, so it keeps its (sound) hint.
        let fqdn = compile(request(r#"device.hostname="ws-fin-011.corp.local" | head 5"#))
            .expect("fqdn hostname query should compile");
        assert!(!fqdn.sql.contains("startsWith"), "fqdn must not expand");
        assert_eq!(
            fqdn.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "device.hostname".to_string(),
                value: "ws-fin-011.corp.local".to_string(),
            }]
        );
    }

    #[test]
    fn emits_only_compiler_proven_sidecar_hints() {
        let event_uid = compile(request(
            r#"metadata.uid="scale03-ramp-1tb-0000000000000042" | head 1"#,
        ))
        .expect("event uid query should compile");
        assert_eq!(
            event_uid.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "metadata.uid".to_string(),
                value: "scale03-ramp-1tb-0000000000000042".to_string(),
            }]
        );

        let entity = compile(request(
            r#"src_endpoint.ip="198.51.100.25" | stats count() as events"#,
        ))
        .expect("entity query should compile");
        assert_eq!(
            entity.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "src_endpoint.ip".to_string(),
                value: "198.51.100.25".to_string(),
            }]
        );

        let signal_resource = compile(request(
            r#"resources.ip="45.155.205.233" | table metadata.uid, risk_score"#,
        ))
        .expect("Signal resource query should compile");
        assert_eq!(
            signal_resource.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "resources.ip".to_string(),
                value: "45.155.205.233".to_string(),
            }]
        );

        let keyword = compile(request("gpupdate | head 20")).expect("keyword query should compile");
        assert_eq!(
            keyword.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "token",
                value: "gpupdate".to_string(),
            }]
        );

        let unsafe_or = compile(request(
            r#"src_endpoint.ip="198.51.100.25" OR user.name="alice""#,
        ))
        .expect("OR query should still compile through the broad path");
        assert!(matches!(unsafe_or.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));

        // NAN-3694: the asset IP pivot keeps its pruning once `device.ip`
        // joins the OR.
        let ip_pivot = compile(request(
            r#"(src_endpoint.ip="10.1.4.63" OR dst_endpoint.ip="10.1.4.63" OR device.ip="10.1.4.63") | stats count"#,
        ))
        .expect("IP pivot should compile");
        assert!(
            matches!(ip_pivot.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }]
                if alternatives.len() == 3 && alternatives.contains(&CandidateHint::Entity {
                    source_path: "device.ip".to_string(),
                    value: "10.1.4.63".to_string(),
                })),
            "{:?}",
            ip_pivot.candidate_hints
        );
        for path in ["device.uid", "user.email_addr", "actor.user.email_addr", "actor.process.user.name"] {
            let compiled = compile(request(&format!(r#"{path}="Alice@Example.com" | head 1"#)))
                .expect("asset identity should compile");
            assert_eq!(
                compiled.candidate_hints,
                vec![CandidateHint::Entity { source_path: path.to_string(), value: "Alice@Example.com".to_string() }],
                "{path}"
            );
        }

        let event_uid_or = compile(request(
            r#"metadata.uid="scale03-a" OR metadata.uid="scale03-b""#,
        ))
        .expect("event uid OR query should still compile through the broad path");
        assert!(matches!(event_uid_or.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));

        let negated_event_uid = compile(request(r#"NOT metadata.uid="scale03-a""#))
            .expect("negated event uid query should still compile through the broad path");
        assert!(negated_event_uid.candidate_hints.is_empty());

        let structured_contains = compile(request(r#"process.cmd_line contains "gpupdate""#))
            .expect("structured contains should use the canonical text sidecar");
        assert_eq!(
            structured_contains.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "contains",
                value: "gpupdate".to_string(),
            }]
        );

        let mut trace = request(r#"unmapped.trace_id="4bf92f3577b34da6a3ce929d0e0e4736""#);
        trace
            .unmapped_field_types
            .insert("unmapped.trace_id".to_string(), FieldType::String);
        let trace = compile(trace).expect("generic OCSF trace fallback should compile");
        assert_eq!(
            trace.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "unmapped.trace_id".to_string(),
                value: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            }]
        );
    }

    /// NAN-3041: the eval/`if()` predicates rule authors need compile through
    /// the whole lean front door (validation included), with where/search
    /// semantics, and a post-pipe `where` resolves the `user` alias.
    #[test]
    fn eval_predicates_and_post_pipe_aliases_compile_on_the_lake() {
        let output = compile(request(
            r#"actor.process.name=* | eval a=if(actor.process.name CONTAINS "EDGE", 1, 0), b=if(actor.process.name=/edge.*update/i, 1, 0), c=if(actor.process.name IN ("MicrosoftEdgeUpdate.exe", "x"), 1, 0), d=if(in(actor.process.name, "svchost.exe"), 1, 0), e=if(NOT actor.process.name IN ("a"), 1, 0) | stats sum(a) as a, sum(b) as b, sum(c) as c, sum(d) as d, sum(e) as e"#,
        ))
        .expect("eval predicates compile on the lake");
        for needle in [
            r#"positionCaseInsensitiveUTF8(toString("actor.process.name"), toString('EDGE'))"#,
            r#"match(toString("actor.process.name"), '(?i)edge.*update')"#,
            r#"(lower(toString("actor.process.name")) IN ('microsoftedgeupdate.exe', 'x'))"#,
            r#"(lower(toString("actor.process.name")) IN ('svchost.exe'))"#,
        ] {
            assert!(output.sql.contains(needle), "{needle}\n{}", output.sql);
        }
        let output = compile(request(r#"user.name=* | where NOT user="x" | stats count"#)).expect("compiles");
        assert!(
            output.sql.contains(r#"NOT ifNull((lower(toString(if("user.name" != '', "user.name", "actor.user.name"))) = 'x'), false)"#),
            "{}",
            output.sql
        );
        assert!(!output.sql.contains(r#"toString("user")"#), "{}", output.sql);
    }

    /// NAN-3034: `*kw*` searches message AND raw_data (sysmon parts carry no
    /// message), projects both, and its hint is a substring (`contains`) hint:
    /// `*svchost*` must never make an index require the whole token.
    #[test]
    fn wildcard_keywords_search_every_body_column_with_substring_hints() {
        for (query, body_predicate) in [
            (
                "*svchost* | head 20",
                "(lower(message) iLike '%svchost%' OR lower(raw_data) iLike '%svchost%')".to_string(),
            ),
            // NAN-3041: `svch*` is a TERM prefix (any word starting `svch`),
            // not a body prefix. The substring guard stays, so its `contains`
            // hint below remains a superset and never prunes a match.
            (
                "svch* | head 20",
                ["message", "raw_data"]
                    .map(|col| {
                        format!(
                            "(lower({col}) iLike '%svch%' AND match({col}, '(?i)(?:^|[^a-z0-9])svch'))"
                        )
                    })
                    .join(" OR "),
            ),
        ] {
            let output = compile(request(query)).expect("wildcard keyword should compile");
            assert!(
                output.sql.contains(&format!("({body_predicate})")),
                "{query}: both body columns, got:\n{}",
                output.sql
            );
            assert!(!output.sql.contains("iLike 'svch%'"), "{query}: {}", output.sql);
            assert!(output.projected_scan_columns.iter().any(|c| c == "raw_data"), "{query}");
            assert!(output.projected_scan_columns.iter().any(|c| c == "message"), "{query}");
            let [CandidateHint::Keyword { mode, value }] = output.candidate_hints.as_slice() else {
                panic!("{query}: expected one keyword hint, got {:?}", output.candidate_hints);
            };
            assert_eq!(*mode, "contains", "{query}: a partial token is never a token hint");
            assert_eq!(value, query.split(' ').next().unwrap());
        }
    }

    /// NAN-3037: keyword NOT over nullable Parquet columns keeps rows whose
    /// `message` (or `raw_data`) is NULL, and a negated term adds no hint.
    #[test]
    fn keyword_not_is_null_safe_on_the_lake() {
        let kw = |t: &str| {
            format!("(hasAllTokens(lower(message), '{t}') OR hasAllTokens(lower(raw_data), '{t}'))")
        };
        let output = compile(request("svchost NOT zzqq | stats count")).expect("compiles");
        assert!(
            output.sql.contains(&format!("{} AND NOT ifNull(({}), false)", kw("svchost"), kw("zzqq"))),
            "got:\n{}",
            output.sql
        );
        assert_eq!(
            output.candidate_hints,
            vec![CandidateHint::Keyword { mode: "token", value: "svchost".to_string() }]
        );

        let output = compile(request("svchost NOT (aa OR (bb NOT cc)) | stats count")).expect("compiles");
        assert_eq!(output.sql.matches("NOT ifNull(").count(), 2, "got:\n{}", output.sql);
        assert!(!output.sql.contains("NOT (("), "got:\n{}", output.sql);
    }

    /// NAN-3221: `source_type` / `sourcetype` lower to the same
    /// `metadata.log_source` predicate, so they carry the same source-family
    /// hint (file pruning by the signed family label); other fields never do.
    #[test]
    fn source_type_aliases_carry_the_log_source_family_hint() {
        let canonical = compile(request("metadata.log_source=audit")).expect("compiles");
        for alias in [
            "source_type=audit",
            "sourcetype=audit",
            r#"source_type="audit""#,
        ] {
            let output = compile(request(alias)).expect("compiles");
            assert_eq!(output.sql, canonical.sql, "{alias}");
            assert_eq!(
                output.candidate_hints,
                vec![CandidateHint::SourceFamily {
                    value: "audit".to_string()
                }],
                "{alias}"
            );
        }
        for other in [
            "metadata.product.name=audit",
            "source_type=aud*",
            "source_type!=audit",
        ] {
            let output = compile(request(other)).expect("compiles");
            assert!(
                !output
                    .candidate_hints
                    .iter()
                    .any(|hint| matches!(hint, CandidateHint::SourceFamily { .. })),
                "{other}: {:?}",
                output.candidate_hints
            );
        }
    }

    /// NAN-3224: `risk` is a query-time alias of the findings that added
    /// risk. It compiles to exactly the findings predicate plus
    /// `risk_score > 0`, prunes by the real `findings` family, and never
    /// emits a `risk` family hint (no part carries that label).
    #[test]
    fn risk_source_alias_compiles_to_scored_findings() {
        let canonical = compile(request(r#"(metadata.log_source="findings" AND risk_score>0)"#))
            .expect("compiles");
        assert!(canonical.sql.contains("'findings'"), "{}", canonical.sql);
        assert!(canonical.sql.contains("risk_score"), "{}", canonical.sql);
        for alias in [
            "metadata.log_source=risk",
            "source_type=risk",
            "sourcetype=risk",
            r#"metadata.log_source="risk""#,
            "metadata.log_source IN (risk)",
        ] {
            let output = compile(request(alias)).expect("compiles");
            assert_eq!(output.sql, canonical.sql, "{alias}");
            assert_eq!(
                output.candidate_hints,
                vec![CandidateHint::SourceFamily { value: "findings".to_string() }],
                "{alias}"
            );
            assert!(!output.sql.contains("'risk'"), "{alias}: {}", output.sql);
        }
        let rba = compile(request(
            "metadata.log_source=risk | stats sum(risk_score) as risk_score by resources.type, resources.name",
        ))
        .expect("the RBA starter search compiles");
        assert!(rba.sql.contains("'findings'"), "{}", rba.sql);
    }

    /// NAN-3224: the "Risk by entity (RBA)" starter search seeded by
    /// enterprise migration 9011150 compiles against the lake.
    #[test]
    fn risk_by_entity_starter_search_compiles() {
        // Read at runtime, not `include_str!`: the open-core mirror strips
        // the enterprise migrations , and a compile-time include there
        // breaks every test target in this crate (NAN-2169, NAN-3307). Skip
        // only when the file is genuinely absent; any other IO error fails.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../migrations/postgres-enterprise/9011150_risk_by_entity_saved_search.sql"
        );
        let migration = match std::fs::read_to_string(path) {
            Ok(migration) => migration,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping: {path} is absent (open-core tree)");
                return;
            }
            Err(err) => panic!("read {path}: {err}"),
        };
        let query = migration
            .split("$rba$")
            .nth(1)
            .expect("the starter query is $rba$-quoted");
        let output = compile(request(query)).expect("the RBA starter search compiles");
        assert!(output.sql.contains("'findings'"), "{}", output.sql);
        assert!(output.sql.contains("risk_score"), "{}", output.sql);
        assert!(!output.sql.contains("'risk'"), "{}", output.sql);
    }

    #[test]
    fn extracts_process_name_from_safe_conjunctions_only() {
        let compound = compile(request(
            r#"metadata.log_source="windows_sysmon" actor.process.name="ngen.exe""#,
        ))
        .expect("compound process query should compile");
        assert!(compound.newest_first_event_rows);
        assert_eq!(
            compound.candidate_hints,
            vec![
                CandidateHint::SourceFamily { value: "windows_sysmon".to_string() },
                CandidateHint::Entity {
                    source_path: "actor.process.name".to_string(),
                    value: "ngen.exe".to_string(),
                },
            ]
        );

        let two_entities = compile(request(
            r#"device.hostname="lt-hr-023.corp.local" actor.process.name="ngen.exe""#,
        ))
        .expect("two-entity conjunction should compile");
        assert_eq!(
            two_entities.candidate_hints,
            vec![
                CandidateHint::Entity {
                    source_path: "device.hostname".to_string(),
                    value: "lt-hr-023.corp.local".to_string(),
                },
                CandidateHint::Entity {
                    source_path: "actor.process.name".to_string(),
                    value: "ngen.exe".to_string(),
                },
            ]
        );

        let unsafe_or = compile(request(
            r#"actor.process.name="ngen.exe" OR actor.process.name="powershell.exe""#,
        ))
        .expect("OR query should compile through the broad path");
        assert!(matches!(unsafe_or.candidate_hints.as_slice(), [CandidateHint::Any { alternatives }] if alternatives.len() == 2));

        let required_outer = compile(request(
            r#"device.hostname="lt-hr-023.corp.local" (actor.process.name="ngen.exe" OR actor.process.name="powershell.exe")"#,
        ))
        .expect("outer conjunct should remain safe");
        assert_eq!(
            required_outer.candidate_hints[..1],
            vec![CandidateHint::Entity {
                source_path: "device.hostname".to_string(),
                value: "lt-hr-023.corp.local".to_string(),
            }]
        );

        let negated = compile(request(r#"NOT actor.process.name="ngen.exe""#))
            .expect("negated query should compile through the broad path");
        assert!(negated.candidate_hints.is_empty());

        let explicitly_oldest_first =
            compile(request(r#"actor.process.name="ngen.exe" | sort +time"#))
                .expect("explicit ordering should compile");
        assert!(!explicitly_oldest_first.newest_first_event_rows);
    }

    #[test]
    fn row_preserving_ocsf_projection_retains_newest_first_proof() {
        // NAN-3060: these compile to an UNORDERED outer `SELECT … LIMIT n`,
        // so they never claim a cursor-continuable newest-first order (cursor
        // pages over them repeated and skipped rows).
        for query in [
            "* | table time, src_endpoint.ip, process.cmd_line",
            "* | fields time, metadata.uid",
            "* | rename raw_data AS r",
            "* | sort -time",
            "* | table time, metadata.uid | sort -time",
        ] {
            let output = compile(request(query)).expect("projection should compile");
            assert!(!ends_in_event_cursor_order(&output.sql), "{query}: {}", output.sql);
            assert!(!output.newest_first_event_rows, "{query}: {}", output.sql);
        }
        for query in ["*", "* | eval x=1", "* | sort -time | head 50", "* | head 5"] {
            let output = compile(request(query)).expect("event query should compile");
            assert!(ends_in_event_cursor_order(&output.sql) && output.newest_first_event_rows, "{query}: {}", output.sql);
        }

        let filtered = compile(request("* | where isnotnull(src_endpoint.ip)"))
            .expect("filtered event query should compile");
        assert!(!filtered.newest_first_event_rows);

        let headed = compile(request(
            r#"metadata.log_source="windows_sysmon" | head 3"#,
        ))
        .expect("head preserves the implicit newest-first event order");
        assert!(headed.newest_first_event_rows);
        for (query, newest_first) in [
            ("device.hostname=\"h\" | sort -time | head 100", true),
            ("device.hostname=\"h\" | sort time | head 100", false),
            ("device.hostname=\"h\" | sort -count | head 100", false),
        ] {
            let parsed = nanosiem_core::query::parse_query(query).unwrap();
            assert_eq!(is_newest_first_event_projection(&parsed), newest_first, "{query}");
        }
        assert!(
            headed
                .sql
                .contains("ORDER BY time DESC, \"metadata.uid\" DESC LIMIT 3"),
            "{}",
            headed.sql
        );
    }

    /// Audit #3: `| sort -time | head N` compiled to a staged statement whose
    /// outer LIMIT was the page limit, so the worker ran `head N` per
    /// progressive chunk and concatenated k*N rows. The outer LIMIT now
    /// carries N, which is what the worker reads to stop the walk.
    #[test]
    fn newest_first_head_caps_the_trailing_limit_the_worker_reads() {
        for (query, cap) in [
            ("device.hostname=\"h\" | sort -time | head 7", 7),
            ("device.hostname=\"h\" | head 7", 7),
            ("device.hostname=\"h\" | sort -time | head 500", 100),
        ] {
            let output = compile(request(query)).unwrap();
            assert!(output.newest_first_event_rows, "{query}");
            assert_eq!(trailing_newest_first_limit(&output.sql), Some(cap), "{query}: {}", output.sql);
            assert_eq!(output.limit, 100, "{query}");
        }
        // A head the worker cannot read off the statement is never paged
        // (these stage an unordered `LIMIT` before the final projection).
        for (query, cap) in [
            ("device.hostname=\"h\" | head 7 | sort -time", 7),
            ("device.hostname=\"h\" | head 9 | table time | head 4", 4),
        ] {
            let output = compile(request(query)).unwrap();
            assert!(
                !output.newest_first_event_rows || trailing_newest_first_limit(&output.sql) == Some(cap),
                "{query}: {}",
                output.sql
            );
        }
        // Without a head the page limit is unchanged.
        let plain = compile(request("device.hostname=\"h\"")).unwrap();
        assert!(plain.newest_first_event_rows);
        assert_eq!(trailing_newest_first_limit(&plain.sql), Some(100));
    }

    #[test]
    fn internal_distinct_merge_state_is_not_truncated_to_user_values_cap() {
        let output = compile(request(
            "* | stats values(dst_endpoint.ip) as __nano_distinct_values by src_endpoint.ip",
        ))
        .expect("internal distinct state should compile");

        assert!(output.sql.contains("groupUniqArray(10001)"));

        let ordinary = compile(request(
            "* | stats values(dst_endpoint.ip) by src_endpoint.ip",
        ))
        .expect("ordinary values query should compile");
        assert!(ordinary.sql.contains("groupUniqArray(100)"));
    }

    #[test]
    fn regex_hints_require_a_literal_present_in_every_match() {
        let guarded = compile(request("message=/rundll3[0-9].*/ | head 20"))
            .expect("guarded regex should compile");
        assert_eq!(
            guarded.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "regex_guard",
                value: "rundll3".to_string(),
            }]
        );

        let structured = compile(request(
            "process.cmd_line=/(?i).*powershell.*encodedcommand/ | head 20",
        ))
        .expect("structured regex should compile");
        assert_eq!(
            structured.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "regex_guard",
                value: "encodedcommand".to_string(),
            }]
        );

        let common = compile(request("message=/(foo.*admin|bar.*admin)/ | head 20"))
            .expect("common-literal alternation should compile");
        assert_eq!(
            common.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "regex_guard",
                value: "admin".to_string(),
            }]
        );

        for query in [
            "message=/(rundll32|powershell)/ | head 20",
            "message=/(admin)?.*/ | head 20",
            "message=/.*/ | head 20",
            "message!=/rundll3[0-9].*/ | head 20",
        ] {
            let output = compile(request(query)).expect("regex should still compile");
            assert!(
                output.candidate_hints.is_empty(),
                "unsafe guard for {query}"
            );
        }
    }

    #[test]
    fn canonical_hash_arrays_use_entity_and_fragment_accelerators() {
        let exact = compile(request(
            r#"file.hashes.value="175f1e89ea77f991487f7932be495aa777d53d6e6a934aee5b9c7066750b93c2""#,
        ))
        .expect("exact hash query should compile");
        assert_eq!(
            exact.candidate_hints,
            vec![CandidateHint::Entity {
                source_path: "file.hashes.value".to_string(),
                value: "175f1e89ea77f991487f7932be495aa777d53d6e6a934aee5b9c7066750b93c2"
                    .to_string(),
            }]
        );

        let fragment = compile(request("file.hashes.value contains 175f1e89"))
            .expect("hash fragment query should compile");
        assert_eq!(
            fragment.candidate_hints,
            vec![CandidateHint::Keyword {
                mode: "contains",
                value: "175f1e89".to_string(),
            }]
        );
    }

    #[test]
    fn rejects_request_supplied_storage_fields() {
        let input = r#"{
            "query":"error",
            "start":"2026-08-07T00:00:00Z",
            "end":"2026-08-08T00:00:00Z",
            "source":"s3://attacker-controlled/**"
        }"#;
        assert!(serde_json::from_str::<CompileRequest>(input).is_err());
    }

    #[test]
    fn canonical_ocsf_1_9_fields_compile_only_for_lake_contract() {
        let mut lake =
            request("metadata.log_source=edr | table metadata.uid, time, metadata.log_source");
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("canonical OCSF 1.9 query should compile");
        assert!(output.sql.contains("\"metadata.log_source\""));
        assert!(output.sql.contains("\"metadata.uid\""));
        assert!(!output.sql.contains("unmapped.\"metadata\".\"log_source\""));

        let mut unsupported = request("*");
        unsupported.event_contract = "vendor-schema".to_string();
        assert!(compile(unsupported).is_err());
    }

    #[test]
    fn reports_only_referenced_canonical_ocsf_columns() {
        let mut lake = request(
            r#"metadata.log_source=proxy http_request.url.url_string="/downloads/example.zip" dst_endpoint.autonomous_system.name=example"#,
        );
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake query should compile");
        let columns: BTreeMap<_, _> = output
            .required_columns
            .iter()
            .map(|column| (column.name.as_str(), column.field_type))
            .collect();

        assert_eq!(
            columns.get("http_request.url.url_string"),
            Some(&FieldType::String)
        );
        assert_eq!(columns.get("url.url_string"), None);
        assert_eq!(columns.get("prevalence_file_hash"), None);
        assert_eq!(
            columns.get("unmapped.parent_process_name"),
            None,
            "unreferenced JSON-tail fields must not be added"
        );
        assert_eq!(
            columns.get("dst_endpoint.autonomous_system.name"),
            Some(&FieldType::String)
        );
        assert_eq!(columns.get("time"), Some(&FieldType::Timestamp));
    }

    #[test]
    fn transaction_declares_quoted_canonical_row_identity_for_worker_projection() {
        let output = compile(request(
            r#"metadata.log_source="proxy" | transaction session.uid startswith="login" endswith="logout" maxspan=8h | table session.uid, user.name"#,
        ))
        .expect("canonical transaction should compile");
        let columns: BTreeMap<_, _> = output
            .required_columns
            .iter()
            .map(|column| (column.name.as_str(), column.field_type))
            .collect();

        assert_eq!(columns.get("metadata.uid"), Some(&FieldType::String));
        assert!(
            output
                .sql
                .contains(r#""metadata.uid" AS __nano_txn_row_identity"#)
        );
        assert!(
            output
                .sql
                .contains("ORDER BY __nano_txn_time, __nano_txn_row_identity")
        );
    }

    #[test]
    fn reports_typed_struct_paths_for_explicit_unmapped_tail() {
        let mut lake = request(r#"unmapped.parent_process_name="wscript.exe""#);
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake tail query should compile");
        let columns: BTreeMap<_, _> = output
            .required_columns
            .iter()
            .map(|column| (column.name.as_str(), column.field_type))
            .collect();

        assert_eq!(
            columns.get("unmapped.parent_process_name"),
            Some(&FieldType::String)
        );
        assert_eq!(columns.get("unmapped.^parent_process_name"), None);
        assert!(!output.sql.contains(".^"));
    }

    #[test]
    fn compiles_standard_ocsf_ioc_enrichment_arrays_from_snapshot_schema() {
        let mut lake = request(
            r#"enrichments.type=threat_intelligence enrichments.provider=tenant_feed | table time, enrichments.name, enrichments.value, enrichments.data.confidence"#,
        );
        lake.table_view = false;
        for field in [
            "enrichments.type",
            "enrichments.provider",
            "enrichments.name",
            "enrichments.value",
            "enrichments.data.confidence",
        ] {
            lake.snapshot_field_types
                .insert(field.to_string(), FieldType::Array);
        }

        let output = compile(lake).expect("canonical OCSF IOC enrichment should compile");

        assert!(
            output
                .sql
                .contains("has(\"enrichments.type\", 'threat_intelligence')")
        );
        assert!(
            output
                .sql
                .contains("has(\"enrichments.provider\", 'tenant_feed')")
        );
        assert!(output.sql.contains("\"enrichments.data.confidence\""));
        assert!(!output.sql.contains("ioc_src_ip_threat_type"));
        assert!(!output.sql.contains("custom_src_ip"));
    }

    #[test]
    fn compiles_manifest_typed_unmapped_numeric_leaf_without_json_probe() {
        let mut lake = request(r#"unmapped.threat_score>0.5 | stats max(unmapped.threat_score)"#);
        lake.event_contract = "ocsf-1.9".to_string();
        lake.unmapped_field_types
            .insert("unmapped.threat_score".to_string(), FieldType::Float);
        let output = compile(lake).expect("typed OCSF lake tail should compile");

        assert!(output.sql.contains("\"unmapped.threat_score\" > 0.5"));
        assert!(output.sql.contains("max(\"unmapped.threat_score\")"));
        assert!(!output.sql.contains(".^"));
        assert_eq!(
            output
                .required_columns
                .iter()
                .find(|column| column.name == "unmapped.threat_score")
                .map(|column| column.field_type),
            Some(FieldType::Float)
        );
    }

    #[test]
    fn preserves_canonical_sequence_group_for_outer_stages() {
        let mut lake = request(
            r#"metadata.log_source=proxy OR metadata.log_source=windows_sysmon | sequence by user.name maxspan=5m [metadata.log_source=proxy] [metadata.log_source=windows_sysmon] | table user.name, step1_time, step2_time"#,
        );
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake sequence should compile");

        assert!(
            output.sql.contains("SELECT \"user.name\", step1_time"),
            "outer sequence stages must address the grouped value by alias: {}",
            output.sql
        );
    }

    #[test]
    fn canonical_tree_preset_compiles_without_udm_aliases() {
        let mut lake = request("metadata.log_source=sysmon | tree process");
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("canonical tree preset should compile");
        assert!(!output.sql.contains("parent_process_guid"));
        assert!(!output.sql.contains("process_guid"));
        // NAN-2361: the tree fields are real lake columns already inside
        // `SELECT *` — naming them again next to `*` is a duplicate column
        // chDB rejects with ILLEGAL_COLUMN ("Cannot add column …").
        assert!(
            !output.sql.contains("*, \"actor.process.uid\""),
            "tree must not re-add columns already carried by SELECT *: {}",
            output.sql
        );
        // They still have to be REQUESTED from the source so the tree builder
        // can read them off result rows.
        assert!(
            output
                .required_columns
                .iter()
                .any(|column| column.name == "actor.process.uid"),
            "tree parent column must stay a required column"
        );
        assert!(
            output
                .required_columns
                .iter()
                .any(|column| column.name == "process.uid"),
            "tree child column must stay a required column"
        );
    }

    /// NAN-3257 repro + fix. The worker used to receive `… | tree process`
    /// and ran `SELECT *` of full-width events: every column of every matching
    /// event, ~360k wide rows for an hour of endpoint data, mostly with no
    /// parent/child edge. Search now sends the narrow, edge-only candidate.
    #[test]
    fn lean_tree_candidate_compiles_to_a_narrow_edge_scan() {
        let lake_profile = OcsfProfile::lake_1_9();
        for (query, child, parent_paths) in [
            // Non-Sysmon endpoint shapes: EDR / osquery, keyed on fields only.
            (
                r#"device.hostname="ws1" | tree process"#,
                "process.uid",
                &["actor.process.uid", "process.parent_process.uid"][..],
            ),
            // Non-proxy HTTP shape: web server / WAF / CDN.
            (
                "http_request.http_method=GET | tree web",
                "http_request.url.url_string",
                &["http_request.referrer"][..],
            ),
        ] {
            let mut old = request(query);
            old.event_contract = "ocsf-1.9".to_string();
            old.limit = 10_000;
            old.table_view = false;
            let old_output = compile(old).expect("pass-through tree compiles");
            assert!(old_output.sql.contains("SELECT * FROM __nano_lake_source__"), "repro: {}", old_output.sql);

            let mut parsed = parse_query(query).unwrap();
            apply_profile_product_semantics(&mut parsed, &lake_profile);
            let candidate = nanosiem_core::search::query_processing::lake_tree_candidate_query(
                &parsed,
                &lake_profile,
            )
            .expect("lean tree projects");
            use nanosiem_core::query::PrettyPrint;
            let mut lake = request(&candidate.pretty_print());
            lake.event_contract = "ocsf-1.9".to_string();
            lake.limit = 10_000;
            lake.table_view = false;
            let output = compile(lake).expect("narrow tree candidate compiles");
            assert!(!output.sql.contains("SELECT *, "), "{}", output.sql);
            assert!(
                !output.sql.contains("SELECT * FROM __nano_lake_source__"),
                "stage_0 must read only the tree columns: {}",
                output.sql
            );
            assert!(output.sql.contains(&format!("\"{child}\") != ''")), "{}", output.sql);
            for parent in parent_paths {
                assert!(output.sql.contains(&format!("\"{parent}\"")), "{parent}: {}", output.sql);
            }
            assert!(output.sql.contains("LIMIT 10000"), "{}", output.sql);
            assert!(
                output.required_columns.len() < 20,
                "projection must stay narrow: {:?}",
                output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
            // NAN-3261: an access log with only `http_request.url.path` set
            // (no url_string, no hostname) is still an edge for `tree web`.
            if child == "http_request.url.url_string" {
                assert!(output.sql.contains("\"http_request.url.path\") != ''"), "{}", output.sql);
                assert!(
                    output.required_columns.iter().any(|c| c.name == "http_request.url.path"),
                    "{:?}",
                    output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>()
                );
                assert!(!output.sql.contains("http_request.url.hostname+"), "{}", output.sql);
            }
        }
    }

    /// NAN-3451 follow-up: the narrow tree candidate now names the
    /// prevalence scalars (and, with `prevalence=`, that field plus the
    /// stamp arrays). On an open-core lake they compile to the
    /// `enrichments[]` derivation over real columns only; on lean they read
    /// the physical stamp columns. Neither duplicates a column.
    #[test]
    fn nan3451_tree_candidate_prevalence_compiles_on_open_core_and_lean() {
        let query = "nanosmoke | tree parent=actor.user.name child=device.hostname \
                     label=device.hostname prevalence=file.hashes.value";
        let compile_candidate = |snapshot: BTreeMap<String, FieldType>| {
            let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(snapshot.clone()).unwrap();
            let mut parsed = parse_query(query).unwrap();
            apply_profile_product_semantics(&mut parsed, &profile);
            let candidate =
                nanosiem_core::search::query_processing::lake_tree_candidate_query(&parsed, &profile)
                    .expect("lake tree projects");
            use nanosiem_core::query::PrettyPrint;
            let mut lake = request(&candidate.pretty_print());
            lake.event_contract = "ocsf-1.9".to_string();
            lake.limit = 10_000;
            lake.table_view = false;
            lake.snapshot_field_types = snapshot;
            let text = candidate.pretty_print();
            (text, compile(lake).expect("tree candidate compiles"))
        };
        let mut open_core = BTreeMap::new();
        for name in [
            "enrichments.name",
            "enrichments.provider",
            "enrichments.value",
            "enrichments.data.host_count",
            "enrichments.data.host_count_saturated",
            "file.hashes.value",
            "process.file.hashes.value",
        ] {
            open_core.insert(name.to_string(), FieldType::Array);
        }
        let (text, output) = compile_candidate(open_core.clone());
        assert!(text.contains("prevalence_min"), "{text}");
        assert!(output.sql.contains("arrayFirstIndex"), "{}", output.sql);
        for phantom in super::PREVALENCE_SCALARS {
            assert!(!output.required_columns.iter().any(|c| c.name == phantom), "{phantom}");
            assert!(!output.projected_scan_columns.iter().any(|c| c == phantom), "{phantom}");
        }
        for input in ["enrichments.value", "file.hashes.value", "device.hostname", "actor.user.name"] {
            assert!(output.required_columns.iter().any(|c| c.name == input), "missing {input}");
        }
        let mut names = output.required_columns.iter().map(|c| &c.name).collect::<Vec<_>>();
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate required column");
        assert!(total < 20, "projection must stay narrow: {names:?}");

        let mut lean = open_core;
        for name in super::PREVALENCE_SCALARS {
            lean.insert(name.to_string(), FieldType::Integer);
        }
        let (_, output) = compile_candidate(lean);
        assert!(!output.sql.contains("arrayFirstIndex"), "{}", output.sql);
        for name in super::PREVALENCE_SCALARS {
            assert!(output.required_columns.iter().any(|c| c.name == name), "lean {name}");
        }
    }

    /// NAN-3257 part 2: every requested column comes back under the name the
    /// analyst typed, including UDM concepts the lake resolves to another
    /// expression.
    #[test]
    fn table_columns_keep_the_typed_names() {
        let mut lake = request(
            r#"device.hostname="ws1" | table process_guid, parent_process_guid, process_name, process.uid"#,
        );
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("UDM-named table compiles on the lake");
        for alias in ["process_guid", "parent_process_guid", "process_name"] {
            assert!(
                output.sql.contains(&format!(" AS {alias},"))
                    || output.sql.contains(&format!(" AS \"{alias}\"")),
                "{alias} must be aliased back: {}",
                output.sql
            );
        }
        assert!(!output.sql.contains("AS \"process.uid\""), "{}", output.sql);
        assert!(!output.sql.contains(") AS if("), "{}", output.sql);
    }

    #[test]
    fn canonical_contract_rejects_unknown_fields_and_post_processing() {
        for query in [
            "parent_process_name=wscript.exe",
            "error | resolve_identity field=src_ip",
        ] {
            let mut lake = request(query);
            lake.event_contract = "ocsf-1.9".to_string();
            assert!(compile(lake).is_err(), "strict OCSF accepted {query}");
        }
    }

    #[test]
    fn canonical_contract_rejects_nano_side_post_processing() {
        for query in [
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence"#,
            r#"metadata.log_source="windows_sysmon" | prevalence hash_prevalence < 5"#,
            r#"metadata.log_source="windows_sysmon" | resolve_identity field=src_endpoint.ip"#,
            r#"metadata.log_source="windows_sysmon" | inputlookup url="https://example.test/{src_endpoint.ip}" key=src_endpoint.ip"#,
            r#"metadata.log_source="windows_sysmon" | ai "classify these events""#,
            r#"* | append [* | lookup iocs src_endpoint.ip OUTPUT confidence]"#,
            r#"* | join src_endpoint.ip [* | prevalence enrich=true]"#,
            r#"* | where src_endpoint.ip IN [* | resolve_identity field=src_endpoint.ip | return src_endpoint.ip]"#,
        ] {
            let mut lake = request(query);
            lake.event_contract = "ocsf-1.9".to_string();
            let error = compile(lake).expect_err("Nano-side command reached lake compiler");
            assert!(error.to_string().contains("Nano-side"), "{query}: {error}");
        }
    }

    #[test]
    fn legacy_contract_also_rejects_nano_side_post_processing() {
        let mut lake = request(
            r#"* | append [* | lookup iocs src_endpoint.ip OUTPUT confidence]"#,
        );
        lake.event_contract = "legacy-flat-ocsf-1.8".to_string();
        let error = compile(lake).expect_err("legacy contract must not bypass SQL-only guard");
        assert!(error.to_string().contains("Nano-side"));
    }

    #[test]
    fn compiles_derived_risk_dataset_against_pinned_placeholder() {
        let mut lake = request(
            "* | where score_24h > 500 or score_7d > 1000 | table entity, entity_type, score_24h, score_7d, distinct_rules_7d, last_rule_name",
        );
        lake.dataset = "risk".to_string();
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("risk nPL should compile");
        assert_eq!(output.profile, "risk");
        assert_eq!(output.dataset, "risk");
        assert_eq!(output.source_placeholder, RISK_SOURCE_PLACEHOLDER);
        assert!(output.sql.contains(RISK_SOURCE_PLACEHOLDER));
        assert!(output.sql.contains("score_24h > 500"));
        assert!(!output.sql.contains("risk_findings"));
    }

    /// NAN-3059: the derived risk grain (one row per entity) has no event
    /// UID and no pipeline outputs. `* | head 5` must not tie-break on
    /// `metadata.uid`, and `stats … by entity_type` must not project its own
    /// `count` output from the source; both failed with Code 47/215 on lean.
    #[test]
    fn risk_dataset_event_pages_and_stats_read_only_real_risk_columns() {
        let risk = |query: &str| {
            let mut input = request(query);
            input.dataset = "risk".to_string();
            input.event_contract = "ocsf-1.9".to_string();
            compile(input).unwrap_or_else(|error| panic!("{query}: {error:#}"))
        };
        let head = risk("* | head 5");
        assert!(!head.sql.contains("metadata.uid"), "{}", head.sql);
        assert!(!head.required_columns.iter().any(|c| c.name == "metadata.uid"));

        let stats = risk("* | stats count() by entity_type");
        let stage_0 = stats.sql.split("stage_1 AS").next().unwrap();
        assert!(!stage_0.contains(" count,") && !stage_0.contains("SELECT count"), "{}", stats.sql);
        assert!(!stats.required_columns.iter().any(|c| c.name == "count"));

        let top = risk("* | where score_24h > 0 | stats max(score_24h) as top by entity | sort -top | head 10");
        let stage_0 = top.sql.split("stage_1 AS").next().unwrap();
        assert!(!stage_0.contains("top,") && !stage_0.contains(", top"), "{}", top.sql);
    }

    #[test]
    fn declares_profile_keyword_body() {
        let mut lake = request("powershell");
        lake.event_contract = "ocsf-1.9".to_string();
        let output = compile(lake).expect("OCSF lake keyword should compile");

        assert!(
            output.required_columns.iter().any(|column| {
                column.name == "message" && column.field_type == FieldType::String
            })
        );
        assert!(
            output
                .projected_scan_columns
                .iter()
                .any(|column| column == "message")
        );
        assert!(
            output
                .required_columns
                .iter()
                .any(|column| column.name == "raw_data")
        );
        assert!(
            output
                .projected_scan_columns
                .iter()
                .any(|column| column == "raw_data")
        );
    }

    #[test]
    fn narrow_aggregation_does_not_project_keyword_bodies() {
        let output = compile(request(
            r#"metadata.log_source="windows_sysmon" | stats count() by src_endpoint.ip"#,
        ))
        .expect("narrow aggregation should compile");
        let columns = output
            .projected_scan_columns
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();

        assert!(columns.contains("metadata.log_source"));
        assert!(columns.contains("src_endpoint.ip"));
        assert!(columns.contains("time"));
        assert!(!columns.contains("message"));
        assert!(!columns.contains("raw_data"));
    }

    #[test]
    fn source_family_where_hint_requires_row_and_field_preservation() {
        let direct = compile(request(r#"* | eval command=process.cmd_line | where metadata.log_source=windows_sysmon | stats count by device.hostname"#)).unwrap();
        assert!(direct.candidate_hints.iter().any(|hint| matches!(hint,
            CandidateHint::SourceFamily { value } if value == "windows_sysmon")));

        let union = compile(request(r#"* | where (metadata.log_source=aws_cloudtrail OR metadata.log_source=windows_event) | stats count by user.name"#)).unwrap();
        assert!(union.candidate_hints.iter().any(|hint| matches!(hint,
            CandidateHint::Any { alternatives } if alternatives.len() == 2
                && alternatives.iter().all(|child| matches!(child, CandidateHint::SourceFamily { .. })))));

        let limited = compile(request(r#"* | head 10 | where metadata.log_source=windows_sysmon | stats count by device.hostname"#)).unwrap();
        assert!(limited.candidate_hints.is_empty());
    }

    #[test]
    fn message_commands_keep_their_physical_input() {
        for query in [
            r#"metadata.log_source="windows_sysmon" | rex "(?P<level>INFO|ERROR)" | stats count() by level"#,
            r#"metadata.log_source="windows_sysmon" | rex field=message "(?P<level>INFO|ERROR)" | stats count() by level"#,
            r#"metadata.log_source="windows_sysmon" | transaction user.name maxspan=30m | stats count()"#,
            r#"metadata.log_source="windows_sysmon" | transaction session.uid startswith="login" endswith="logout" | stats count()"#,
        ] {
            let output = compile(request(query)).expect("message command should compile");
            assert!(
                output
                    .required_columns
                    .iter()
                    .any(|column| column.name == "message")
            );
            assert!(
                output
                    .projected_scan_columns
                    .iter()
                    .any(|column| column == "message")
            );
            if query.contains("startswith") {
                assert!(
                    output
                        .required_columns
                        .iter()
                        .any(|column| column.name == "raw_data")
                );
                assert!(
                    output
                        .projected_scan_columns
                        .iter()
                        .any(|column| column == "raw_data")
                );
            }
        }
    }

    /// NAN-3328: every documented output column of a command is a real
    /// column of the later stages -- never rejected as an unknown OCSF field,
    /// never read from a bogus `ext.<name>`.
    #[test]
    fn nan3328_command_created_columns_flow_to_later_stages() {
        for (query, column) in [
            ("* | bin span=1h hop=30m | stats count by time_bucket_end", "time_bucket_end"),
            ("* | bin time span=1h hop=30m | stats count by time_end", "time_end"),
            ("* | anomaly field=traffic.bytes_out | table expected, avg_val, stddev_val", "expected"),
            ("* | anomaly field=traffic.bytes_out method=mad | table median_val, mad_val", "mad_val"),
            (
                "* | funnel by user.name window=1h [class_uid=3002] [class_uid=1007] | table funnel_level, step_name",
                "funnel_level",
            ),
            ("* | risk score=10 entity=user.name | table risk_entity, raw_risk_score", "risk_entity"),
        ] {
            let output = compile(request(query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(!output.sql.contains("ext."), "{query}: {}", output.sql);
            assert!(!output.sql.contains("unmapped."), "{query}: {}", output.sql);
            assert!(
                !output.required_columns.iter().any(|c| c.name == column),
                "{query}: stage output {column} declared as a source column"
            );
        }
    }

    /// NAN-3314: a `table` alias is usable downstream.
    #[test]
    fn nan3314_table_alias_is_a_later_stage_column() {
        for query in [
            "metadata.log_source=windows_event | table user.name as u, time | sort u",
            "metadata.log_source=windows_event | table user.name as u, time | where isnotnull(u)",
            "* | table user.name as u, time | stats count by u",
        ] {
            let output = compile(request(query)).unwrap_or_else(|e| panic!("{query}: {e:#}"));
            assert!(output.sql.contains("\"user.name\" AS u"), "{query}: {}", output.sql);
            assert!(!output.sql.contains("ext."), "{query}: {}", output.sql);
        }
    }

    /// NAN-3336: `rename a as b` onto an existing OCSF column replaces it.
    #[test]
    fn nan3336_rename_onto_existing_column_replaces_it() {
        let output = compile(request(
            "class_uid=1007 actor.user.name=* | rename actor.user.name as user.name | table user.name",
        ))
        .unwrap();
        assert!(
            output
                .sql
                .contains("SELECT * EXCEPT (\"user.name\"), \"actor.user.name\" AS \"user.name\""),
            "{}",
            output.sql
        );
        // A swap keeps both inputs visible to the projection.
        let swap = compile(request("* | rename src_endpoint.ip as dst_endpoint.ip, dst_endpoint.ip as src_endpoint.ip")).unwrap();
        assert!(!swap.sql.contains("EXCEPT"), "{}", swap.sql);
    }

    /// NAN-3316: wildcards expand against OCSF 1.9 paths.
    #[test]
    fn nan3316_wildcards_expand_against_ocsf_paths() {
        let output = compile(request("* | fields src_endpoint.*")).unwrap();
        assert!(output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
        assert!(output.sql.contains("\"src_endpoint.port\""), "{}", output.sql);

        let output = compile(request("* | table src_*")).unwrap();
        assert!(output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
        assert!(!output.sql.contains("AS src_ip"), "{}", output.sql);
        assert!(!output.sql.contains("unmapped.src_"), "{}", output.sql);

        let output = compile(request("* | fields *.ip")).unwrap();
        assert!(output.sql.contains("\"dst_endpoint.ip\""), "{}", output.sql);
        assert!(!output.sql.contains("prevalence_dest_ip"), "{}", output.sql);
        assert!(!output.sql.contains("dvc_ip"), "{}", output.sql);

        let output = compile(request("* | fields - src_endpoint.*")).unwrap();
        assert!(output.sql.contains("EXCEPT (") && output.sql.contains("\"src_endpoint.ip\""), "{}", output.sql);
    }
}
