// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source pinning for hosted-shared detection rules, including correlation
//! rules (NAN-2961, lean parity gap #9).
//!
//! A shared detection claim is bound to ONE source route (the rule's
//! `shared_detection_rule_sources` row). Before NAN-2961 the
//! runtime pinned the top-level scan to that source and refused every query
//! with a nested scan (`IN [ … ]`, `join`, `append`, or a subsearch inside a
//! `where` / `transaction` / `sequence` / `funnel` condition). This module
//! replaces that refusal with an explicit, verifiable pin on EVERY scan:
//!
//! * A scan that does not name a source reads the rule's bound source.
//! * A scan may name its sources with ONE top-level condition,
//!   `metadata.log_source="okta"`, `metadata.log_source IN ("okta", "sysmon")`
//!   or `(metadata.log_source="okta" OR metadata.log_source="sysmon")`. It then
//!   reads exactly those sources. The top-level scan must include the bound
//!   source; nested scans may name any other source of the same tenant (the
//!   "companion" sources). The runtime proves each companion is one of the
//!   tenant's own routes and the authoring path proves the author can see it.
//! * The pin is ANDed at the top level of every scan
//!   (`(<scan>) AND metadata.log_source = …`), the serialized query is
//!   re-parsed and every scan is re-verified, exactly like the source-scope
//!   gate (NAN-2006). A crafted query that dislodges a pin is refused.
//!
//! Genuinely unsupported shapes are refused with a reason: cross-dataset
//! subsearches (the shared runtime evaluates the `logs` dataset only), a scan
//! that mentions the source field anywhere but a top-level condition (its
//! meaning would change under the pin), invalid source identities and
//! unbounded fan-out.

use std::collections::BTreeSet;

use crate::query::{Command, Comparator, Query, RhsSyntax, SearchExpr, Value};

/// Largest number of distinct sources one detection rule may read.
pub const MAX_DETECTION_RULE_SOURCES: usize = 16;
/// Largest number of nested scans (subsearches) one detection rule may run.
pub const MAX_DETECTION_NESTED_SCANS: usize = 16;

/// A detection query with every scan pinned to an explicit source set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedDetectionQuery {
    /// The query to run: every scan ANDed with its source pin.
    pub query: String,
    /// Sources other than the bound one that some scan reads (canonical
    /// lowercase). Empty for a single-source rule.
    pub companions: BTreeSet<String>,
    /// Number of nested scans (0 for a plain rule).
    pub nested_scans: usize,
}

/// What an authoring-time analysis learned about a rule query.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DetectionSourcePlan {
    /// Sources the top-level scan names, if it names any.
    pub top_level: Option<BTreeSet<String>>,
    /// Every source any scan names (top-level and nested).
    pub named: BTreeSet<String>,
    /// Number of nested scans.
    pub nested_scans: usize,
}

/// Why a detection query cannot be pinned. The message is safe to return to
/// the rule author.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectionShapeError {
    #[error("invalid query: {0}")]
    Parse(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("detection source pinning could not be verified for this query")]
    Unverified,
}

/// Analyse a rule query for authoring. Every scan, the top-level one
/// included, must either name no source or name it with one top-level
/// condition.
pub fn analyze_detection_sources(
    query: &str,
    source_field: &str,
) -> Result<DetectionSourcePlan, DetectionShapeError> {
    let parsed = crate::query::parse_query(query)
        .map_err(|error| DetectionShapeError::Parse(error.to_string()))?;
    let mut walker = Walker::new(source_field, None, true);
    walker.query(&parsed, true)?;
    Ok(DetectionSourcePlan {
        top_level: walker.top_level,
        named: walker.named,
        nested_scans: walker.nested_scans,
    })
}

/// Pin every scan of a detection query (NAN-2961). `bound_source` is the
/// claim's route slug. The top-level scan keeps the pre-NAN-2961 leniency
/// (a stray mention of the source field there is ANDed with the bound
/// source rather than refused) so existing single-source rules run exactly
/// as before; nested scans are strict.
pub fn pin_detection_query(
    query: &str,
    bound_source: &str,
    source_field: &str,
) -> Result<PinnedDetectionQuery, DetectionShapeError> {
    use crate::query::{extract_time_modifier_tokens, parse_query, PrettyPrint};
    if !matches!(source_field, "source_type" | "metadata.log_source") {
        return Err(DetectionShapeError::Unsupported(
            "detection source pinning has an invalid profile field".to_string(),
        ));
    }
    let bound = canonical_source(bound_source).ok_or_else(|| {
        DetectionShapeError::Unsupported("the rule's bound source has an invalid identity".to_string())
    })?;
    let parsed = parse_query(query).map_err(|error| DetectionShapeError::Parse(error.to_string()))?;
    let mut walker = Walker::new(source_field, Some(&bound), false);
    let pinned = walker.query(&parsed, true)?;
    let companions: BTreeSet<String> =
        walker.named.iter().filter(|source| **source != bound).cloned().collect();
    let mut allowed = companions.clone();
    allowed.insert(bound.clone());
    let mut enforced = pinned.pretty_print();

    // Fail closed on the serialized form, exactly as the callers will parse it.
    let reparsed = parse_query(&enforced).map_err(|_| DetectionShapeError::Unverified)?;
    let mut verified_scans = 0usize;
    if !verify_query(&reparsed, true, source_field, &bound, &allowed, &mut verified_scans)
        || verified_scans != walker.nested_scans + 1
    {
        return Err(DetectionShapeError::Unverified);
    }
    for token in extract_time_modifier_tokens(query) {
        enforced.push(' ');
        enforced.push_str(&token);
    }
    Ok(PinnedDetectionQuery {
        query: enforced,
        companions,
        nested_scans: walker.nested_scans,
    })
}

/// A route slug in canonical form, or `None` when it is not a valid identity.
fn canonical_source(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    .then_some(value)
}

struct Walker<'a> {
    field: &'a str,
    /// `None`: analysis only (no pins are emitted for unnamed scans).
    bound: Option<&'a str>,
    strict_top: bool,
    nested_scans: usize,
    named: BTreeSet<String>,
    top_level: Option<BTreeSet<String>>,
}

impl<'a> Walker<'a> {
    fn new(field: &'a str, bound: Option<&'a str>, strict_top: bool) -> Self {
        Self { field, bound, strict_top, nested_scans: 0, named: BTreeSet::new(), top_level: None }
    }

    fn unsupported(message: impl Into<String>) -> DetectionShapeError {
        DetectionShapeError::Unsupported(message.into())
    }

    /// Pin one pipeline. Its leftmost `Search` leaf is the pipeline's scan.
    fn query(&mut self, query: &Query, top: bool) -> Result<Query, DetectionShapeError> {
        match query {
            Query::Search(expr) => self.scan(expr, top),
            Query::Piped { source, command } => Ok(Query::Piped {
                source: Box::new(self.query(source, top)?),
                command: self.command(command)?,
            }),
        }
    }

    fn scan(&mut self, expr: &SearchExpr, top: bool) -> Result<Query, DetectionShapeError> {
        let strict = !top || self.strict_top;
        let named = scan_sources(expr, self.field, strict)?;
        if let Some(sources) = &named {
            if top {
                if let Some(bound) = self.bound {
                    if !sources.contains(bound) {
                        return Err(Self::unsupported(format!(
                            "the rule's top-level search names {} but not the rule's own source \"{bound}\"; \
                             include it, or name the other sources in a subsearch",
                            describe(sources)
                        )));
                    }
                }
                self.top_level = Some(sources.clone());
            }
            self.named.extend(sources.iter().cloned());
            if self.named.len() > MAX_DETECTION_RULE_SOURCES {
                return Err(Self::unsupported(format!(
                    "a detection rule may read at most {MAX_DETECTION_RULE_SOURCES} sources"
                )));
            }
        }
        let inner = self.expr(expr)?;
        let pin = match (named, self.bound) {
            (Some(sources), _) => sources,
            (None, Some(bound)) => BTreeSet::from([bound.to_string()]),
            (None, None) => return Ok(Query::Search(inner)),
        };
        Ok(Query::Search(SearchExpr::And(
            Box::new(SearchExpr::Group(Box::new(inner))),
            Box::new(pin_conjunct(self.field, &pin)),
        )))
    }

    fn nested(&mut self, subsearch: &Query, dataset_named: bool) -> Result<Query, DetectionShapeError> {
        if dataset_named {
            return Err(Self::unsupported(
                "cross-dataset subsearches are not supported in detection rules; \
                 hosted detections evaluate the logs dataset",
            ));
        }
        self.nested_scans += 1;
        if self.nested_scans > MAX_DETECTION_NESTED_SCANS {
            return Err(Self::unsupported(format!(
                "a detection rule may contain at most {MAX_DETECTION_NESTED_SCANS} subsearches"
            )));
        }
        self.query(subsearch, false)
    }

    /// Exhaustive (no `_` arm): a new `Query`-carrying variant is a compile
    /// error here, never an unpinned scan.
    fn expr(&mut self, expr: &SearchExpr) -> Result<SearchExpr, DetectionShapeError> {
        Ok(match expr {
            SearchExpr::InSubsearch { field, subsearch, negated, subsearch_dataset } => {
                SearchExpr::InSubsearch {
                    field: field.clone(),
                    subsearch: Box::new(self.nested(subsearch, subsearch_dataset.is_some())?),
                    negated: *negated,
                    subsearch_dataset: *subsearch_dataset,
                }
            }
            SearchExpr::And(left, right) => {
                SearchExpr::And(Box::new(self.expr(left)?), Box::new(self.expr(right)?))
            }
            SearchExpr::Or(left, right) => {
                SearchExpr::Or(Box::new(self.expr(left)?), Box::new(self.expr(right)?))
            }
            SearchExpr::Not(inner) => SearchExpr::Not(Box::new(self.expr(inner)?)),
            SearchExpr::Group(inner) => SearchExpr::Group(Box::new(self.expr(inner)?)),
            SearchExpr::Keyword(_)
            | SearchExpr::FieldFilter { .. }
            | SearchExpr::FunctionFilter { .. }
            | SearchExpr::FieldFunctionFilter { .. }
            | SearchExpr::InList { .. }
            | SearchExpr::BooleanFunction(_)
            | SearchExpr::EvalPredicate(_)
            | SearchExpr::LiteralComparison { .. }
            | SearchExpr::IocMatch { .. } => expr.clone(),
        })
    }

    /// Exhaustive (no `_` arm), mirroring `gate_command`.
    fn command(&mut self, command: &Command) -> Result<Command, DetectionShapeError> {
        let mut pinned = command.clone();
        match &mut pinned {
            Command::Join { subsearch, subsearch_dataset, .. } => {
                **subsearch = self.nested(subsearch, subsearch_dataset.is_some())?;
            }
            Command::Append { subsearch, .. } => {
                **subsearch = self.nested(subsearch, false)?;
            }
            Command::Where { condition } => *condition = self.expr(condition)?,
            Command::Transaction { startswith, endswith, .. } => {
                if let Some(expr) = startswith {
                    *expr = self.expr(expr)?;
                }
                if let Some(expr) = endswith {
                    *expr = self.expr(expr)?;
                }
            }
            Command::Sequence { conditions, .. } => {
                for condition in conditions.iter_mut() {
                    *condition = self.expr(condition)?;
                }
            }
            Command::Funnel { steps, .. } => {
                for (_, condition) in steps.iter_mut() {
                    *condition = self.expr(condition)?;
                }
            }
            Command::Stats { .. }
            | Command::Chart { .. }
            | Command::StreamStats { .. }
            | Command::Sort { .. }
            | Command::Head { .. }
            | Command::Tail { .. }
            | Command::Timechart { .. }
            | Command::Table { .. }
            | Command::Rename { .. }
            | Command::Lookup { .. }
            | Command::Eval { .. }
            | Command::Dedup { .. }
            | Command::Bin { .. }
            | Command::Rex { .. }
            | Command::Fields { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
            | Command::Fillnull { .. }
            | Command::Mvexpand { .. }
            | Command::Spath { .. }
            | Command::Format { .. }
            | Command::Return { .. }
            | Command::Risk { .. }
            | Command::Prevalence { .. }
            | Command::Sample { .. }
            | Command::Reverse
            | Command::EventStats { .. }
            | Command::Anomaly { .. }
            | Command::InputLookup { .. }
            | Command::Tree { .. }
            | Command::ResolveIdentity { .. }
            | Command::Asset { .. }
            | Command::Cloud { .. }
            | Command::Lateral { .. }
            | Command::Ai { .. }
            | Command::Output { .. }
            | Command::Services
            | Command::Service { .. }
            | Command::Trace { .. }
            | Command::Metric { .. }
            | Command::Retro { .. }
            | Command::Baseline { .. } => {}
        }
        Ok(pinned)
    }
}

fn describe(sources: &BTreeSet<String>) -> String {
    sources.iter().map(|source| format!("\"{source}\"")).collect::<Vec<_>>().join(", ")
}

fn pin_conjunct(field: &str, sources: &BTreeSet<String>) -> SearchExpr {
    if sources.len() == 1 {
        SearchExpr::FieldFilter {
            field: field.to_string(),
            op: Comparator::Eq,
            value: Value::String(sources.iter().next().cloned().unwrap_or_default()),
            rhs: RhsSyntax::Literal,
        }
    } else {
        SearchExpr::InList {
            field: field.to_string(),
            values: sources.iter().cloned().map(Value::String).collect(),
            negated: false,
        }
    }
}

/// The source set a scan names, from its top-level conjuncts.
///
/// `strict`: any other mention of the source field in the scan (under an
/// `OR`, a `NOT`, a non-equality comparison, a second naming condition) is
/// refused, because ANDing the pin would silently change what the author
/// wrote. Lenient (the legacy top-level scan): such a scan is simply pinned
/// to the bound source, as before NAN-2961.
fn scan_sources(
    expr: &SearchExpr,
    field: &str,
    strict: bool,
) -> Result<Option<BTreeSet<String>>, DetectionShapeError> {
    let mut conjuncts = Vec::new();
    top_level_conjuncts(expr, &mut conjuncts);
    let mut naming = Vec::new();
    let mut naming_mentions = 0usize;
    for conjunct in conjuncts {
        if let Some(values) = naming_condition(conjunct, field) {
            naming_mentions += field_mentions(conjunct, field);
            naming.push(values);
        }
    }
    let total_mentions = field_mentions(expr, field);
    let well_formed = naming.len() <= 1 && total_mentions == naming_mentions;
    if !well_formed {
        if strict {
            return Err(DetectionShapeError::Unsupported(format!(
                "{field} may appear in a detection search only once, as a top-level condition \
                 ({field}=\"<source>\" or {field} IN (\"<source>\", …))"
            )));
        }
        return Ok(None);
    }
    let Some(values) = naming.pop() else { return Ok(None) };
    let mut sources = BTreeSet::new();
    for value in values {
        let source = canonical_source(&value).ok_or_else(|| {
            DetectionShapeError::Unsupported(format!(
                "\"{value}\" is not a valid source identity in {field}"
            ))
        })?;
        sources.insert(source);
    }
    if sources.is_empty() {
        return Err(DetectionShapeError::Unsupported(format!("{field} names no source")));
    }
    Ok(Some(sources))
}

fn top_level_conjuncts<'e>(expr: &'e SearchExpr, out: &mut Vec<&'e SearchExpr>) {
    match expr {
        SearchExpr::And(left, right) => {
            top_level_conjuncts(left, out);
            top_level_conjuncts(right, out);
        }
        SearchExpr::Group(inner) if matches!(inner.as_ref(), SearchExpr::And(..) | SearchExpr::Group(_)) => {
            top_level_conjuncts(inner, out);
        }
        other => out.push(other),
    }
}

/// `F = "x"`, `F IN ("x", …)` or a parenthesised OR of `F = "x"` terms.
fn naming_condition(expr: &SearchExpr, field: &str) -> Option<Vec<String>> {
    match expr {
        SearchExpr::FieldFilter { field: name, op: Comparator::Eq, value: Value::String(value), .. }
            if name.eq_ignore_ascii_case(field) =>
        {
            Some(vec![value.clone()])
        }
        SearchExpr::InList { field: name, values, negated: false } if name.eq_ignore_ascii_case(field) => values
            .iter()
            .map(|value| match value {
                Value::String(value) => Some(value.clone()),
                _ => None,
            })
            .collect(),
        SearchExpr::Group(inner) => naming_condition(inner, field),
        SearchExpr::Or(left, right) => {
            let mut values = naming_condition(left, field)?;
            values.extend(naming_condition(right, field)?);
            Some(values)
        }
        _ => None,
    }
}

/// How many leaves of THIS scan's expression reference the source field.
/// Subsearches are separate scans and are not descended into.
fn field_mentions(expr: &SearchExpr, field: &str) -> usize {
    match expr {
        SearchExpr::FieldFilter { field: name, .. }
        | SearchExpr::FieldFunctionFilter { field: name, .. }
        | SearchExpr::InList { field: name, .. }
        | SearchExpr::InSubsearch { field: name, .. } => usize::from(name.eq_ignore_ascii_case(field)),
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            field_mentions(left, field) + field_mentions(right, field)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => field_mentions(inner, field),
        SearchExpr::Keyword(_)
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => 0,
    }
}

/// The pin conjunct's source set, when `expr` is exactly a pin.
fn pin_values(expr: &SearchExpr, field: &str) -> Option<BTreeSet<String>> {
    match expr {
        SearchExpr::FieldFilter { field: name, op: Comparator::Eq, value: Value::String(value), .. }
            if name.eq_ignore_ascii_case(field) =>
        {
            Some(BTreeSet::from([value.clone()]))
        }
        SearchExpr::InList { field: name, values, negated: false } if name.eq_ignore_ascii_case(field) => {
            let got: BTreeSet<String> = values
                .iter()
                .filter_map(|value| match value {
                    Value::String(value) => Some(value.clone()),
                    _ => None,
                })
                .collect();
            (got.len() == values.len() && !got.is_empty()).then_some(got)
        }
        _ => None,
    }
}

/// FAIL-CLOSED proof on the re-parsed query: every scan is
/// `And(<scan>, <pin>)` with the pin's sources inside `allowed`, and the
/// top-level pin includes the bound source.
fn verify_query(
    query: &Query,
    top: bool,
    field: &str,
    bound: &str,
    allowed: &BTreeSet<String>,
    scans: &mut usize,
) -> bool {
    match query {
        Query::Search(SearchExpr::And(left, right)) => {
            let Some(pin) = pin_values(right, field) else { return false };
            *scans += 1;
            pin.is_subset(allowed)
                && (!top || pin.contains(bound))
                && verify_expr(left, field, bound, allowed, scans)
        }
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            verify_query(source, top, field, bound, allowed, scans)
                && verify_command(command, field, bound, allowed, scans)
        }
    }
}

fn verify_expr(
    expr: &SearchExpr,
    field: &str,
    bound: &str,
    allowed: &BTreeSet<String>,
    scans: &mut usize,
) -> bool {
    match expr {
        SearchExpr::InSubsearch { subsearch, subsearch_dataset, .. } => {
            subsearch_dataset.is_none() && verify_query(subsearch, false, field, bound, allowed, scans)
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            verify_expr(left, field, bound, allowed, scans) && verify_expr(right, field, bound, allowed, scans)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => verify_expr(inner, field, bound, allowed, scans),
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. }
        | SearchExpr::IocMatch { .. } => true,
    }
}

fn verify_command(
    command: &Command,
    field: &str,
    bound: &str,
    allowed: &BTreeSet<String>,
    scans: &mut usize,
) -> bool {
    match command {
        Command::Join { subsearch, subsearch_dataset, .. } => {
            subsearch_dataset.is_none() && verify_query(subsearch, false, field, bound, allowed, scans)
        }
        Command::Append { subsearch, .. } => verify_query(subsearch, false, field, bound, allowed, scans),
        Command::Where { condition } => verify_expr(condition, field, bound, allowed, scans),
        Command::Transaction { startswith, endswith, .. } => {
            startswith.as_ref().is_none_or(|expr| verify_expr(expr, field, bound, allowed, scans))
                && endswith.as_ref().is_none_or(|expr| verify_expr(expr, field, bound, allowed, scans))
        }
        Command::Sequence { conditions, .. } => {
            conditions.iter().all(|expr| verify_expr(expr, field, bound, allowed, scans))
        }
        Command::Funnel { steps, .. } => {
            steps.iter().all(|(_, expr)| verify_expr(expr, field, bound, allowed, scans))
        }
        _ => true,
    }
}

#[cfg(test)]
#[path = "detection_sources_tests.rs"]
mod tests;
