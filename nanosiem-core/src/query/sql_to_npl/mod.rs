// SPDX-License-Identifier: AGPL-3.0-or-later

//! SQL → nPL conversion (NAN-5575).
//!
//! Machines run SQL; people read nPL. Hunt agents sometimes query Agent Lane
//! with raw ClickHouse SQL (the investigator's `sql` tool, `dataset: signals`
//! pivots). When an analyst wants to keep investigating, they need that query
//! as nPL so it opens in Search. This module is the STATIC converter: it
//! translates the guarded Agent Lane subset (one SELECT over the events table,
//! or over the detections as `dataset=signals` (NAN-5612), WHERE / GROUP BY /
//! HAVING / ORDER BY / LIMIT) and never guesses. Anything outside the subset is
//! a structured [`Unsupported`].
//!
//! Every conversion is then PROVEN: the nPL is compiled with the production
//! generator ([`ClickHouseSqlGenerator`]) and the compiled SQL is compared
//! with the original on a normalized signature (table, predicates,
//! aggregates, group-by, post-aggregation filters, order, limit). `exact` is
//! true only when the signatures match; otherwise every mismatch is listed in
//! `differences`. [`compare_npl_with_sql`] runs the same proof for nPL that
//! came from somewhere else (the AI fallback in enterprise).
//!
//! The time window is NOT an nPL term: the bounds on `timestamp` are lifted
//! out and returned as [`TimeBound`]s for the Search time range. The Agent
//! Lane window placeholders (`{earliest:DateTime64(6, 'UTC')}` /
//! `{latest:…}`) come back as [`TimeBound::WindowStart`] / [`TimeBound::WindowEnd`], which the caller binds
//! to the run's window. Conversion never executes anything.

mod canon;
mod convert;

#[cfg(test)]
mod corpus_tests;
#[cfg(test)]
mod template_sql_fixtures;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::query::Dataset;
use crate::schema::SchemaProfile;

pub use canon::Difference;
pub use canon::DifferenceKind;

/// The Agent Lane window parameters (the literals `guard_sql` requires and
/// the hunts playbook pins). Kept here so core does not depend on the
/// enterprise lane module; a test pins them to the playbook constants.
pub const WINDOW_START_PARAM: &str = "{earliest:DateTime64(6, 'UTC')}";
pub const WINDOW_END_PARAM: &str = "{latest:DateTime64(6, 'UTC')}";
/// The playbook's table placeholders (`dataset: signals` pivots).
pub const EVENTS_TABLE_PLACEHOLDER: &str = "{events}";
pub const SIGNALS_TABLE_PLACEHOLDER: &str = "{signals}";

/// Longest SQL the converter reads (the guard's own cap).
pub const MAX_SQL_BYTES: usize = 16 * 1024;

/// One end of the Search time range a query was bounded by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeBound {
    /// `{earliest:…}`: the caller binds it to the run's window start.
    WindowStart,
    /// `{latest:…}`: the caller binds it to the run's window end.
    WindowEnd,
    /// A literal instant in the SQL.
    At(DateTime<Utc>),
}

/// Where in the SQL a construct sits (1-based line / column, as sqlparser
/// reports them). Absent when the parser kept no location for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[schema(as = SqlToNplSpan)]
pub struct SqlSpan {
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
}

/// Why a query is outside the convertible subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub reason: String,
    pub span: Option<SqlSpan>,
    /// No nPL, AI-written or not, can express the query exactly: it reads a
    /// table Search cannot read (a system table), or it correlates events
    /// with signals in one statement (Search reads one dataset per query).
    pub no_search_dataset: bool,
}

impl Unsupported {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self { reason: reason.into(), span: None, no_search_dataset: false }
    }

    pub(crate) fn at(reason: impl Into<String>, span: sqlparser::tokenizer::Span) -> Self {
        Self { reason: reason.into(), span: span_of(span), no_search_dataset: false }
    }

    pub(crate) fn no_dataset(mut self) -> Self {
        self.no_search_dataset = true;
        self
    }
}

pub(crate) fn span_of(span: sqlparser::tokenizer::Span) -> Option<SqlSpan> {
    if span.start.line == 0 {
        return None;
    }
    Some(SqlSpan {
        start_line: span.start.line,
        start_column: span.start.column,
        end_line: span.end.line,
        end_column: span.end.column,
    })
}

/// What the converter is converting against: the deployment's schema
/// profile. The events table it reads is the profile's (`ocsf_logs` /
/// `logs`); Search reads only that table.
#[derive(Clone)]
pub struct ConvertContext {
    pub profile: Arc<dyn SchemaProfile>,
}

impl ConvertContext {
    pub fn new(profile: Arc<dyn SchemaProfile>) -> Self {
        Self { profile }
    }

    pub fn events_table(&self) -> &'static str {
        crate::schema::logs_table_for(self.profile.id())
    }
}

/// A conversion's outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct SqlToNpl {
    /// The nPL. `None` when the SQL is outside the subset.
    pub npl: Option<String>,
    /// The Search dataset the nPL runs on: `Logs` for SQL over the events
    /// table, `Signals` for SQL over the detections (NAN-5612).
    pub dataset: Dataset,
    pub earliest: Option<TimeBound>,
    pub latest: Option<TimeBound>,
    /// The compiled nPL matches the SQL on every compared dimension.
    pub exact: bool,
    /// Every way the compiled nPL differs from the SQL. Empty when exact.
    pub differences: Vec<Difference>,
    pub unsupported: Option<Unsupported>,
}

impl SqlToNpl {
    fn unsupported(u: Unsupported) -> Self {
        Self {
            npl: None,
            dataset: Dataset::Logs,
            earliest: None,
            latest: None,
            exact: false,
            differences: Vec::new(),
            unsupported: Some(u),
        }
    }
}

/// Convert one guarded Agent Lane SQL query to nPL, statically, and prove it.
pub fn convert_sql_to_npl(sql: &str, ctx: &ConvertContext) -> SqlToNpl {
    let converted = match convert::convert(sql, ctx).and_then(searchable) {
        Ok(c) => c,
        Err(u) => {
            let mut out = SqlToNpl::unsupported(u);
            out.dataset = sql_dataset(sql, ctx);
            return out;
        }
    };
    let (exact, differences) = match compare_npl_with_sql(sql, &converted.npl, ctx) {
        Ok(differences) => (differences.is_empty(), differences),
        Err(e) => (
            false,
            vec![Difference { kind: DifferenceKind::Different, detail: format!("the nPL could not be verified: {e}") }],
        ),
    };
    SqlToNpl {
        npl: Some(converted.npl),
        dataset: converted.dataset,
        earliest: converted.earliest,
        latest: converted.latest,
        exact,
        differences,
        unsupported: None,
    }
}

/// NAN-5614: never hand out nPL that Search refuses before running it (the
/// memory guard on an unfiltered `values()`, `dedup`, high-cardinality
/// group-by, …): the SQL ran, the nPL would not.
fn searchable(c: convert::Converted) -> Result<convert::Converted, Unsupported> {
    let query = crate::query::parse_query(&c.npl)
        .map_err(|e| Unsupported::new(format!("the converted nPL does not parse: {e}")))?;
    match crate::search::query_processing::detect_oom_risk(&query) {
        Some(risk) => Err(Unsupported::new(format!(
            "the nPL form ({}) is refused by Search's memory guard: {}",
            c.npl,
            risk.message()
        ))),
        None => Ok(c),
    }
}

/// The Search dataset a SQL query's outer SELECT reads (NAN-5612):
/// `Signals` when it reads the detections, else `Logs` (also when the SQL
/// cannot be read at all).
pub fn sql_dataset(sql: &str, ctx: &ConvertContext) -> Dataset {
    convert::preprocess(sql)
        .ok()
        .and_then(|pre| canon::signature_of_sql(&pre, ctx).ok())
        .filter(canon::reads_signals)
        .map_or(Dataset::Logs, |_| Dataset::Signals)
}

/// Compile `npl` with the production generator and compare it with `sql`.
/// `Ok(vec![])` means the two are equivalent on every compared dimension.
/// `Err` when either side cannot be read at all (the nPL does not parse or
/// compile, or the SQL is not a query the comparator understands).
///
/// The nPL runs on the dataset the SQL reads (NAN-5612): `dataset=signals`
/// when the SQL reads the detections, else the events table.
pub fn compare_npl_with_sql(sql: &str, npl: &str, ctx: &ConvertContext) -> Result<Vec<Difference>, String> {
    let original = canon::signature_of_sql(&convert::preprocess(sql).map_err(|u| u.reason)?, ctx)?;
    let dataset = if canon::reads_signals(&original) { Dataset::Signals } else { Dataset::Logs };
    let compiled = canon::compile_npl(npl, ctx, dataset)?;
    let generated = canon::signature_of_sql(&compiled, ctx)?;
    Ok(canon::compare(&original, &generated))
}

/// Bind the window placeholders to the run's window.
pub fn resolve_bound(
    bound: Option<&TimeBound>,
    window_start: Option<DateTime<Utc>>,
    window_end: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match bound {
        Some(TimeBound::At(at)) => Some(*at),
        Some(TimeBound::WindowStart) => window_start,
        Some(TimeBound::WindowEnd) => window_end,
        None => None,
    }
}

/// Most queries one batch request converts.
pub const MAX_BATCH: usize = 50;

/// One conversion request: the SQL and the run window its placeholders bind.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct SqlToNplRequest {
    /// The Agent Lane SQL (placeholders and all). At most 16 KiB.
    pub sql: String,
    /// What `{earliest:DateTime64(6, 'UTC')}` stands for (the run's window
    /// start). Without it a placeholder bound comes back as `null`.
    #[serde(default)]
    pub window_start: Option<DateTime<Utc>>,
    /// What `{latest:DateTime64(6, 'UTC')}` stands for.
    #[serde(default)]
    pub window_end: Option<DateTime<Utc>>,
}

/// A batch of conversions (one view's worth of SQL steps).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct SqlToNplBatchRequest {
    /// At most 50.
    pub items: Vec<SqlToNplRequest>,
}

/// One conversion, as the API returns it.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SqlToNplResponse {
    /// The nPL; `null` when the SQL is outside the convertible subset.
    pub npl: Option<String>,
    /// The Search dataset the nPL runs on (`logs`, or `signals` for SQL over
    /// the detections that fired). Search takes it as its `dataset`
    /// parameter, not as nPL text.
    pub dataset: String,
    /// The Search time range: the SQL's lower bound on `timestamp`, with the
    /// window placeholder bound to `window_start`.
    pub earliest: Option<DateTime<Utc>>,
    pub latest: Option<DateTime<Utc>>,
    /// The compiled nPL matches the SQL on table, predicates, aggregates,
    /// group-by, order and limit.
    pub exact: bool,
    /// The nPL came from the AI fallback, not the static converter.
    pub approximate: bool,
    /// Every way the compiled nPL departs from the SQL.
    pub differences: Vec<Difference>,
    /// Why the SQL could not be converted.
    pub unsupported_reason: Option<String>,
    /// Where in the SQL the unsupported construct sits.
    pub unsupported_span: Option<SqlSpan>,
    /// No nPL can express the SQL exactly (a table Search has no dataset
    /// for, or events and signals correlated in one statement): an AI
    /// translation cannot help either.
    pub no_search_dataset: bool,
}

/// A batch's results, in request order.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SqlToNplBatchResponse {
    pub results: Vec<SqlToNplResponse>,
}

impl SqlToNpl {
    /// The wire form, with the window placeholders bound.
    pub fn into_response(self, request: &SqlToNplRequest, approximate: bool) -> SqlToNplResponse {
        SqlToNplResponse {
            earliest: resolve_bound(self.earliest.as_ref(), request.window_start, request.window_end),
            latest: resolve_bound(self.latest.as_ref(), request.window_start, request.window_end),
            npl: self.npl,
            dataset: self.dataset.selector().to_string(),
            exact: self.exact,
            approximate,
            differences: self.differences,
            unsupported_reason: self.unsupported.as_ref().map(|u| u.reason.clone()),
            no_search_dataset: self.unsupported.as_ref().is_some_and(|u| u.no_search_dataset),
            unsupported_span: self.unsupported.and_then(|u| u.span),
        }
    }
}

/// Convert a request statically (the open-core path; executes nothing).
pub fn convert_request(request: &SqlToNplRequest, ctx: &ConvertContext) -> SqlToNplResponse {
    convert_sql_to_npl(&request.sql, ctx).into_response(request, false)
}

/// The time bounds the SQL names, without converting the rest (the AI path
/// keeps the static converter's reading of the window).
pub fn time_bounds(sql: &str, ctx: &ConvertContext) -> (Option<TimeBound>, Option<TimeBound>) {
    convert::window_only(sql, ctx)
}
