// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lake candidate hints: the compiler-proven sidecar pruning hints that
//! `lake_query_compile` sends to the lake worker, and the NAN-4163 bare-`*`
//! classifier built on the same hint logic.
//!
//! The hint logic lived inside the `lake_query_compile` binary until NAN-4163;
//! it moved here unchanged so the search service can classify a query with
//! exactly the scope the compiler would hint (and not a drifting copy).

use crate::query::{Command, Comparator, Query, RhsSyntax, SearchExpr, Value};
use crate::schema::{FieldResolution, SchemaProfile};
use crate::search::query_processing::query_has_nested_scan;
use serde::Serialize;
use std::collections::BTreeSet;

/// A compiler-proven safe superset lookup for the immutable serving sidecars.
///
/// This is deliberately only a hint. The worker always runs the complete
/// compiled query against the candidate blocks, so the sidecar never becomes
/// an event truth source and cannot introduce false-positive results.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CandidateHint {
    Entity { source_path: String, value: String },
    SourceFamily { value: String },
    /// NAN-3188: `class_uid = value`, emitted only as a top-level-AND
    /// conjunct (never inside OR / NOT). It lets the worker skip a whole
    /// source/class family file whose signed class is another value.
    Class { value: i64 },
    Keyword { mode: &'static str, value: String },
    Any { alternatives: Vec<CandidateHint> },
}

pub const ENTITY_SIDECAR_PATHS: &[&str] = &[
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

// The contract lives in `crate::search::keyword_sidecar` so the lake
// worker that builds the index asserts against the same list. See that module
// for why a hinted-but-unindexed path is a silent zero-result, not a missed
// optimization.
use crate::search::keyword_sidecar::KEYWORD_SIDECAR_PATHS;

const MAX_CANDIDATE_HINTS: usize = 8;

pub fn source_search_expression(query: &Query) -> &SearchExpr {
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

/// NAN-4186: for a regex with no token common to every match whose
/// top-level form is an alternation (`psexec|paexec|admin\$`), one required
/// token per branch: every match holds at least one of them, so their union
/// is a candidate superset. `None` when any branch has no required token or
/// the union would exceed the probe bound.
fn alternation_regex_tokens(pattern: &str) -> Option<Vec<String>> {
    use regex_syntax::hir::{Hir, HirKind};
    fn branches(hir: &Hir) -> Option<&[Hir]> {
        match hir.kind() {
            HirKind::Alternation(expressions) => Some(expressions),
            HirKind::Capture(capture) => branches(&capture.sub),
            _ => None,
        }
    }
    let stripped = pattern.strip_prefix("(?i)").unwrap_or(pattern);
    let hir = regex_syntax::Parser::new().parse(stripped).ok()?;
    let branches = branches(&hir)?;
    if branches.len() > MAX_CANDIDATE_HINTS {
        return None;
    }
    let mut tokens = Vec::with_capacity(branches.len());
    for branch in branches {
        // Each branch re-enters the single-token proof as its own pattern.
        let token = mandatory_regex_token(&branch.to_string())?;
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    (tokens.len() > 1).then_some(tokens)
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
                && crate::query::rhs_compiles_as_value(profile, field, op, value, *rhs)
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
                && !crate::query::hostname_equality_expands(
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
                profile.entity_type(path) == Some(crate::schema::EntityType::Ip)
                    || profile.field_type(path) == Some(crate::schema::FieldType::IpAddress)
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
            if crate::query::rhs_compiles_as_value(profile, field, op, value, *rhs)
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
        SearchExpr::FieldFilter { field, op, value: Value::Regex(pattern), .. }
            if *op == Comparator::Regex && KEYWORD_SIDECAR_PATHS.contains(&field.as_str()) =>
        {
            if let Some(token) = mandatory_regex_token(pattern) {
                return Some(CandidateHint::Keyword { mode: "regex_guard", value: token });
            }
            let alternatives = alternation_regex_tokens(pattern)?
                .into_iter()
                .map(|value| CandidateHint::Keyword { mode: "regex_guard", value })
                .collect();
            Some(CandidateHint::Any { alternatives })
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
        || !crate::query::rhs_compiles_as_value(profile, field, &Comparator::Eq, value, *rhs)
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
            // NAN-4186: keyword guards carry no path, so the legs of an
            // eval-alias union share them; a repeat adds no probe.
            other => match candidate_hint_for_expression(other, profile)? {
                CandidateHint::Any { alternatives } => {
                    for alternative in alternatives {
                        if !out.contains(&alternative) { out.push(alternative); }
                    }
                }
                hint => if !out.contains(&hint) { out.push(hint) },
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
                    // Legs that deduplicate to one hint (NAN-4186) need no union.
                    let hint = match <[CandidateHint; 1]>::try_from(alternatives) {
                        Ok([single]) => single,
                        Err(alternatives) => CandidateHint::Any { alternatives },
                    };
                    if !hints.contains(&hint) { hints.push(hint); }
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

pub fn candidate_hints(
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
    collect_where_hints(query, profile, &mut hints);
    hints
}

/// A post-search `where` may be moved to file selection only while every
/// preceding command preserves the original row set and the hinted column.
/// In particular, `head`, aggregation, and an eval that replaces the hinted
/// field make the pushdown unsound.
///
/// NAN-4155: this used to push only source-family hints, so the common
/// `* | where device.hostname="h"` (or a hash / IP / user / class_uid where)
/// pruned no part by its entity sidecar and read every part in the window,
/// while the identical filter form read only the parts holding the entity.
/// A where predicate lowers to the same (or a narrower) comparison as its
/// search-filter spelling, so the hint the search form would get is a sound
/// candidate superset for it too. Keyword hints stay search-only.
fn collect_where_hints(
    query: &Query,
    profile: &dyn SchemaProfile,
    hints: &mut Vec<CandidateHint>,
) {
    let mut scope = EvalScope::default();
    collect_where_hints_inner(query, profile, hints, &mut scope);
}

/// What the evals before a `where` did to the event's fields.
#[derive(Default)]
struct EvalScope {
    /// Every physical path an eval may have overwritten.
    assigned: BTreeSet<String>,
    /// NAN-4186: eval'd names whose value is always one of these unmodified
    /// physical fields (or NULL/empty): `x = f`, `x = coalesce(a, b, ...)`,
    /// `x = coalesce(nullif(a, ""), b)`.
    aliases: std::collections::BTreeMap<String, Vec<String>>,
}

/// The unmodified physical fields an eval expression's value always comes
/// from, or `None` when it can produce any other value. `nullif(f, "")`
/// yields `f` or NULL; `coalesce` yields one of its arguments (or NULL).
/// A literal argument, any other function or an already-assigned field is
/// opaque.
fn eval_source_fields(expression: &crate::query::EvalExpression, assigned: &BTreeSet<String>) -> Option<Vec<String>> {
    use crate::query::EvalExpression;
    match expression {
        EvalExpression::Field(field) if !field.is_empty() && !assigned.contains(field) => Some(vec![field.clone()]),
        EvalExpression::FunctionCall { name, args } if name.eq_ignore_ascii_case("coalesce") && !args.is_empty() => {
            let mut fields = Vec::new();
            for arg in args {
                for field in eval_source_fields(arg, assigned)? {
                    if !fields.contains(&field) {
                        fields.push(field);
                    }
                }
            }
            Some(fields)
        }
        EvalExpression::FunctionCall { name, args } if name.eq_ignore_ascii_case("nullif") => match args.as_slice() {
            [inner, EvalExpression::Literal(Value::String(empty))] if empty.is_empty() => eval_source_fields(inner, assigned),
            _ => None,
        },
        _ => None,
    }
}

impl EvalScope {
    fn is_assigned(&self, field: &str, profile: &dyn SchemaProfile) -> bool {
        self.assigned.contains(field) || self.assigned.contains(profile.canonicalize(field).as_ref())
    }

    /// `condition` with every predicate on an eval alias replaced by the
    /// union of the same predicate on each of its source fields, and every
    /// other term the evals may have changed (or a bare keyword, whose
    /// where-semantics differ from search) made opaque. A positive predicate
    /// on `coalesce(a, b)` holds only when it holds for `a` or for `b`, so
    /// the union's hints are a candidate superset of the where; the full
    /// where is still evaluated on every selected row.
    fn substitute(&self, condition: &SearchExpr, profile: &dyn SchemaProfile) -> SearchExpr {
        let opaque = |expression: &SearchExpr| SearchExpr::Not(Box::new(SearchExpr::Not(Box::new(expression.clone()))));
        match condition {
            SearchExpr::And(left, right) => SearchExpr::And(Box::new(self.substitute(left, profile)), Box::new(self.substitute(right, profile))),
            SearchExpr::Or(left, right) => SearchExpr::Or(Box::new(self.substitute(left, profile)), Box::new(self.substitute(right, profile))),
            SearchExpr::Group(inner) => SearchExpr::Group(Box::new(self.substitute(inner, profile))),
            SearchExpr::FieldFilter { field, op, value, rhs } => {
                if let Some(sources) = self.aliases.get(field) {
                    let mut legs = sources.iter().map(|source| SearchExpr::FieldFilter {
                        field: source.clone(), op: *op, value: value.clone(), rhs: *rhs,
                    });
                    let first = legs.next().expect("an alias has a source");
                    SearchExpr::Group(Box::new(legs.fold(first, |union, leg| SearchExpr::Or(Box::new(union), Box::new(leg)))))
                } else if self.is_assigned(field, profile) {
                    opaque(condition)
                } else {
                    condition.clone()
                }
            }
            SearchExpr::Keyword(_) => opaque(condition),
            other => other.clone(),
        }
    }

    /// Whether a hint from a (substituted) where may select files: its paths
    /// are unmodified, and keywords only as substring/regex guards of field
    /// predicates (bare keywords were made opaque above).
    fn admits(&self, hint: &CandidateHint) -> bool {
        match hint {
            CandidateHint::Keyword { mode, .. } => *mode != "token",
            CandidateHint::Any { alternatives } => alternatives.iter().all(|alternative| {
                !matches!(alternative, CandidateHint::Any { .. }) && self.admits(alternative)
            }),
            other => where_hint_paths(other).is_some_and(|paths| !paths.iter().any(|path| self.assigned.contains(*path))),
        }
    }
}

/// Every physical path an eval assignment to `field` may overwrite: the
/// spelling itself, its canonical name, its resolved column, and both sides
/// of a class-split alias.
fn insert_assigned_paths(field: &str, profile: &dyn SchemaProfile, assigned: &mut BTreeSet<String>) {
    assigned.insert(field.to_string());
    let canonical = profile.canonicalize(field).to_string();
    for name in [field, canonical.as_str()] {
        if let Some((primary, fallback)) = profile.class_split_source_fields(name) {
            assigned.insert(primary.to_string());
            assigned.insert(fallback.to_string());
        }
        if let FieldResolution::ExplicitColumn(column) = profile.resolve(name) {
            assigned.insert(column);
        }
    }
    assigned.insert(canonical);
}

/// The physical paths a pushed-down hint relies on, or `None` for a hint
/// kind that must never come from a `where`.
fn where_hint_paths(hint: &CandidateHint) -> Option<Vec<&str>> {
    match hint {
        CandidateHint::SourceFamily { .. } => Some(vec!["metadata.log_source"]),
        CandidateHint::Class { .. } => Some(vec!["class_uid"]),
        CandidateHint::Entity { source_path, .. } => Some(vec![source_path.as_str()]),
        CandidateHint::Keyword { .. } => None,
        CandidateHint::Any { alternatives } => {
            let mut paths = Vec::new();
            for alternative in alternatives {
                match alternative {
                    CandidateHint::Any { .. } => return None,
                    other => paths.extend(where_hint_paths(other)?),
                }
            }
            Some(paths)
        }
    }
}

fn hint_probe_cost(hint: &CandidateHint) -> usize {
    match hint {
        CandidateHint::Any { alternatives } => alternatives.len(),
        _ => 1,
    }
}

fn collect_where_hints_inner(
    query: &Query,
    profile: &dyn SchemaProfile,
    hints: &mut Vec<CandidateHint>,
    scope: &mut EvalScope,
) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            if !collect_where_hints_inner(source, profile, hints, scope) {
                return false;
            }
            match command {
                Command::Eval { assignments } => {
                    for assignment in assignments {
                        // Sources are judged before this assignment lands.
                        let sources = eval_source_fields(&assignment.expression, &scope.assigned)
                            .filter(|sources| !sources.is_empty());
                        insert_assigned_paths(&assignment.field, profile, &mut scope.assigned);
                        match sources {
                            Some(sources) => { scope.aliases.insert(assignment.field.clone(), sources); }
                            None => { scope.aliases.remove(&assignment.field); }
                        }
                    }
                    true
                }
                Command::Where { condition } => {
                    let mut candidates = Vec::new();
                    collect_conjunctive_hints(&scope.substitute(condition, profile), profile, &mut candidates);
                    for candidate in candidates {
                        if !scope.admits(&candidate) {
                            continue;
                        }
                        let probes = hints.iter().map(hint_probe_cost).sum::<usize>();
                        if probes + hint_probe_cost(&candidate) <= MAX_CANDIDATE_HINTS
                            && !hints.contains(&candidate)
                        {
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

/// NAN-4163: the longest window a bare `*` search runs interactively on a
/// lean cell. A longer one goes straight to the durable background job.
pub const BARE_STAR_INTERACTIVE_MAX_WINDOW: chrono::Duration = chrono::Duration::hours(4);

/// NAN-4163: whether `query` is a **bare `*`** search, one that names nothing
/// the lake can prune the window's parts by. It is bare when, after the
/// compiler's where-hoist (NAN-4155):
///
/// - the search stage has no search term: it is only `*` or empty (a query
///   that starts with `|` parses to `*`), so it has no keyword, no
///   source/class scope (`metadata.log_source`, `source_type`, `class_uid`,
///   ...) and no entity term (host / user / IP / hash / process fields); and
/// - no `| where` directly after the search stage (before any other command)
///   carries a source-family, class or entity predicate. Such a where is
///   hoisted into file selection exactly as the filter form would be, so
///   `* | where metadata.log_source=x` is scoped. The predicates are judged
///   by the compiler's own hint logic ([`collect_conjunctive_hints`] +
///   [`where_hint_paths`]), so the two cannot drift.
///
/// Every other command (eval, stats, table, sort, a where after an eval, ...)
/// leaves the classification unchanged: `* | eval a=b | where
/// metadata.log_source=x` and `* | stats count by metadata.log_source` are
/// bare. The classification deliberately does not look past the first
/// non-where command even where the compiler's hoist would.
pub fn is_bare_star(query: &Query, profile: &dyn SchemaProfile) -> bool {
    fn match_all(expression: &SearchExpr) -> bool {
        match expression {
            SearchExpr::Keyword(term) => matches!(term.trim(), "" | "*"),
            SearchExpr::Group(inner) => match_all(inner),
            _ => false,
        }
    }
    fn commands_in_order<'a>(query: &'a Query, out: &mut Vec<&'a Command>) {
        if let Query::Piped { source, command } = query {
            commands_in_order(source, out);
            out.push(command);
        }
    }
    if !match_all(source_search_expression(query)) {
        return false;
    }
    let mut commands = Vec::new();
    commands_in_order(query, &mut commands);
    for command in commands {
        let Command::Where { condition } = command else {
            break;
        };
        let mut hints = Vec::new();
        collect_conjunctive_hints(condition, profile, &mut hints);
        if hints.iter().any(|hint| where_hint_paths(hint).is_some()) {
            return false;
        }
    }
    true
}

/// NAN-4163: whether `query` only lists events: its pipeline is empty or
/// uses only `head`, `table`, `fields`, `rename` and a newest-first
/// `sort -time`. These shapes are served by the newest-first paged `head`
/// path (NAN-4148/#7194: a 7 d `* | head 10` answers in about a second), so
/// a bare `*` listing stays interactive at any window. An allowlist: any
/// other command (stats, eval, where, timechart, dedup, top, rare,
/// transaction, join, ...) makes the query a non-listing shape.
pub fn is_listing_shape(query: &Query) -> bool {
    fn newest_first_time(fields: &[crate::query::SortField]) -> bool {
        matches!(fields, [field] if field.descending
            && matches!(field.field.as_str(), "time" | "_time" | "timestamp"))
    }
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            is_listing_shape(source)
                && match command {
                    Command::Head { .. }
                    | Command::Table { .. }
                    | Command::Fields { .. }
                    | Command::Rename { .. } => true,
                    Command::Sort { fields, .. } => newest_first_time(fields),
                    _ => false,
                }
        }
    }
}

/// NAN-4163 (Dan's rule): a bare `*` search ([`is_bare_star`]) over a window
/// longer than [`BARE_STAR_INTERACTIVE_MAX_WINDOW`] goes straight to the
/// durable background job on a lean cell, with no interactive attempt.
/// Exactly four hours still runs interactively, and so does a pure listing
/// ([`is_listing_shape`]) at any window. NAN-4184: so does an aggregate the
/// 5-minute count rollups answer without a scan
/// ([`crate::search::service::lake_count_rollup_answers`]), for example
/// `* | stats count by metadata.log_source`. `query` is classified under the
/// lean lake's OCSF 1.9 profile with the compiler's product semantics
/// applied; a query that does not parse is never routed (the interactive
/// path reports the parse error).
pub fn bare_star_routes_to_background_job(query: &str, window: chrono::Duration) -> bool {
    if window <= BARE_STAR_INTERACTIVE_MAX_WINDOW {
        return false;
    }
    let Ok(mut parsed) = crate::query::parse_query(query) else {
        return false;
    };
    let profile = crate::schema::OcsfProfile::lake_1_9();
    crate::search::query_processing::apply_profile_product_semantics(&mut parsed, &profile);
    !is_listing_shape(&parsed)
        && !crate::search::service::lake_count_rollup_answers(&profile, &parsed)
        && is_bare_star(&parsed, &profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(query: &str) -> bool {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let mut parsed = crate::query::parse_query(query).expect(query);
        crate::search::query_processing::apply_profile_product_semantics(&mut parsed, &profile);
        is_bare_star(&parsed, &profile)
    }

    fn hints(query: &str) -> Vec<CandidateHint> {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let mut parsed = crate::query::parse_query(query).expect(query);
        crate::search::query_processing::apply_profile_product_semantics(&mut parsed, &profile);
        candidate_hints(&parsed, "logs", &profile)
    }

    fn guard(value: &str) -> CandidateHint {
        CandidateHint::Keyword { mode: "regex_guard", value: value.to_string() }
    }

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity { source_path: path.to_string(), value: value.to_string() }
    }

    const CORPUS_EVAL: &str = r#"* | eval corpus_process_name=coalesce(nullif(process.name,""),actor.process.name), corpus_command_line=coalesce(nullif(process.cmd_line,""),actor.process.cmd_line)"#;

    /// NAN-4186: a where on an eval'd coalesce hints the union of the same
    /// predicate on each source field; a regex alternation hints one guard
    /// per branch. (lateral_movement:1/5, defense_evasion:5 had none.)
    #[test]
    fn where_on_an_eval_coalesce_hints_its_source_fields() {
        let any = |alternatives: Vec<CandidateHint>| CandidateHint::Any { alternatives };
        assert_eq!(
            hints(&format!(r#"{CORPUS_EVAL} | where corpus_command_line=/node:|psexec|paexec|admin\$|ipc\$/i | stats count by corpus_process_name,device.hostname | sort -count"#)),
            vec![any(vec![guard("node"), guard("psexec"), guard("paexec"), guard("admin"), guard("ipc")])],
        );
        assert_eq!(
            hints(&format!("{CORPUS_EVAL} | where corpus_process_name=WMIC.exe corpus_command_line=/node:/i | stats count as execs by device.hostname")),
            vec![any(vec![entity("process.name", "WMIC.exe"), entity("actor.process.name", "WMIC.exe")]), guard("node")],
        );
        assert_eq!(
            hints(r#"* | eval corpus_command_line=coalesce(nullif(process.cmd_line,""),actor.process.cmd_line) | where metadata.log_source=windows_sysmon corpus_command_line=/wevtutil|Clear-EventLog|Set-MpPreference|DisableRealtimeMonitoring|bitsadmin|MsMpEng|WinDefend/i | stats count by device.hostname,corpus_command_line"#),
            vec![
                CandidateHint::SourceFamily { value: "windows_sysmon".into() },
                any(["wevtutil", "eventlog", "mppreference", "disablerealtimemonitoring", "bitsadmin", "msmpeng", "windefend"].into_iter().map(guard).collect()),
            ],
        );
        // The search form gets the same alternation guards.
        assert_eq!(hints("process.cmd_line=/psexec|paexec/i"), vec![any(vec![guard("psexec"), guard("paexec")])]);
    }

    #[test]
    fn eval_pushdown_stays_sound() {
        for query in [
            // A transformed value, a literal fallback, a negation, a bare keyword.
            "* | eval x=lower(process.name) | where x=wmic.exe",
            r#"* | eval x=coalesce(process.name, "cmd.exe") | where x="cmd.exe""#,
            r#"* | eval x=coalesce(nullif(process.name,"-"),actor.process.name) | where x="cmd.exe""#,
            "* | eval x=process.name | where NOT x=cmd.exe",
            "* | eval x=process.name | where cmd.exe",
            // A source overwritten before the alias, or the alias reassigned.
            r#"* | eval process.name="a" | eval x=process.name | where x=a"#,
            r#"* | eval x=process.name | eval x=lower(user.name) | where x=a"#,
            // An OR leg without a hint leaves the union unhintable.
            "* | eval x=process.name | where x=a OR metadata.event_code=4624",
            // A where after an aggregation is not pushed down.
            "* | eval x=process.name | stats count by x | where x=a",
            // A branch with no required token.
            "process.cmd_line=/ab|psexec/i",
        ] {
            assert!(hints(query).is_empty(), "{query}: {:?}", hints(query));
        }
        // Aliases chain through a plain rename; a source rewritten AFTER the
        // alias is no longer trusted.
        assert_eq!(hints("* | eval y=process.name | eval x=y | where x=a"), Vec::<CandidateHint>::new(), "y is not physical");
        assert_eq!(hints("* | eval x=process.name | where x=a"), vec![entity("process.name", "a")]);
        assert!(hints(r#"* | eval x=process.name | eval process.name="b" | where x=a"#).is_empty());
        // The bare-* classifier is unchanged by the pushdown.
        assert!(bare(&format!("{CORPUS_EVAL} | where corpus_command_line=/psexec|paexec/i | stats count")));
        assert!(bare("* | where process.cmd_line=/psexec|paexec/i | stats count"));
    }

    #[test]
    fn bare_star_queries() {
        for query in [
            "*",
            "* | stats count",
            "* | stats count by metadata.log_source",
            r#"* | eval corpus_process_name=coalesce(nullif(process.name,""),actor.process.name) | where corpus_process_name="svchost.exe" | stats count by corpus_process_name"#,
            "* | eval a=b | where metadata.log_source=x",
            "* | eval a=1 | where device.hostname=h",
            "* | table device.hostname, user.name",
            // A leading where on a field with no source/class/entity hint.
            "* | where severity_id > 3",
            r#"* | where message="svchost""#,
            "| stats count",
        ] {
            assert!(bare(query), "{query} must be bare");
        }
    }

    #[test]
    fn scoped_queries_are_not_bare() {
        for query in [
            "error",
            "metadata.log_source=x",
            "class_uid=4001",
            "device.hostname=h",
            "src_endpoint.ip=1.2.3.4",
            "user=x",
            "* error",
            "metadata.log_source=x | stats count",
            // The where-hoist (NAN-4155) moves these into file selection.
            "* | where metadata.log_source=x",
            "* | where class_uid=4001 | stats count",
            r#"* | where device.hostname="ws-1.corp.local" | stats count"#,
            r#"* | where metadata.log_source=x | where severity_id > 3"#,
        ] {
            assert!(!bare(query), "{query} must not be bare");
        }
    }

    #[test]
    fn routes_only_past_four_hours() {
        let four = chrono::Duration::hours(4);
        let over = four + chrono::Duration::seconds(1);
        for query in ["* | stats dc(device.hostname)", r#"* | eval a=coalesce(process.name,"") | where a="x""#, "* | timechart span=1m count"] {
            assert!(!bare_star_routes_to_background_job(query, four), "{query}: exactly 4h stays interactive");
            assert!(bare_star_routes_to_background_job(query, over), "{query}: 4h + 1s goes to the job");
        }
        assert!(bare_star_routes_to_background_job("* | stats dc(device.hostname) by metadata.log_source", chrono::Duration::days(7)));
        assert!(!bare_star_routes_to_background_job("device.hostname=h", chrono::Duration::days(7)));
        assert!(!bare_star_routes_to_background_job("* | where metadata.log_source=x", chrono::Duration::days(7)));
        assert!(!bare_star_routes_to_background_job("* | (", chrono::Duration::days(7)));
    }

    /// Coordinator review of #7215: pure listings ride the newest-first
    /// paged `head` path (#7194) and stay interactive at any window.
    #[test]
    fn bare_star_listings_stay_interactive_at_any_window() {
        let week = chrono::Duration::days(7);
        for query in [
            "*",
            "* | head 50",
            "* | head 10",
            "* | table time, message",
            "* | fields device.hostname, user.name",
            "* | sort -time | head 100",
            "* | rename message as msg | table msg",
        ] {
            assert!(!bare_star_routes_to_background_job(query, week), "{query} is a listing: interactive");
        }
        for query in [
            "* | stats dc(device.hostname) by metadata.log_source",
            "* | eval a=1 | where a=1",
            "* | timechart span=1m count",
            "* | dedup device.hostname",
            "* | top device.hostname",
            "* | rare device.hostname",
            "* | sort device.hostname",
            "* | sort time",
            "* | head 10 | stats count",
            "* | where severity_id > 3",
        ] {
            assert!(bare_star_routes_to_background_job(query, week), "{query} transforms: background job");
        }
    }

    /// NAN-4184: an aggregate the 5-minute count rollups answer without a
    /// scan stays interactive at any window. This includes the literal
    /// inventory queries the system callers send, so a future change cannot
    /// silently route them to a job.
    #[test]
    fn rollup_answered_aggregates_stay_interactive() {
        let week = chrono::Duration::days(7);
        for query in [
            "* | stats count by metadata.log_source",
            "* | stats count by metadata.log_source | sort -count",
            "* | stats count by metadata.log_source | sort -count | head 10",
            "* | stats count by metadata.log_source | where count > 100",
            "* | stats count() as n by source_type",
            "* | timechart span=1h count by metadata.log_source",
            "* | timechart span=5m count",
            // The AI briefing's source breakdown
            "* | stats count() as cnt by metadata.log_source | sort -cnt | head 1000",
            // The AI source-type listing (both forms)
            "* | stats count() as event_count by metadata.log_source | sort -event_count",
            "* | stats count() as event_count by metadata.log_source | sort -event_count | head 50",
            // nanosiem-api handlers/fields.rs and the detection editor
            "* | stats count() as count by metadata.log_source | sort -count",
            // nano-desktop SearchEmptyState "Count events by source"
            "* | stats count by metadata.log_source",
        ] {
            assert!(!bare_star_routes_to_background_job(query, week), "{query}: rollup-answered, interactive");
        }
        for query in [
            "* | stats dc(device.hostname) by metadata.log_source",
            "* | stats sum(severity_id) by metadata.log_source",
            "* | stats count by actor.process.user.name",
            // A 1-minute span is not whole rollup buckets: the worker refuses
            // it and the service scans (web DemoHints).
            "* | timechart span=1m count by metadata.log_source",
            "* | eval s=metadata.log_source | stats count by s",
        ] {
            assert!(bare_star_routes_to_background_job(query, week), "{query}: needs a scan, background job");
        }
    }
}
