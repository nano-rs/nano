// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cost-based admission for the unfiltered-search memory guards (NAN-5635).
//!
//! [`detect_oom_risk`](super::detect_oom_risk) used to refuse `* | dedup …`,
//! `* | transaction …`, `* | eventstats …`, `* | anomaly …`, `* | reverse`,
//! `values()`/`list()` and `stats … by <high-cardinality field>` on any
//! unfiltered search, whatever the time range or data volume. Every one of
//! those commands runs inside ClickHouse under the per-query
//! `max_memory_usage` ceiling (40% of the server limit, NAN-4957), so the
//! worst case of running one alone is a clean Code 241 for that query, not a
//! server OOM. The budget below is half that ceiling, so a few admitted
//! queries at once still fit the server. The guard now decides per site:
//!
//! * **Spillable** — ClickHouse bounds it on its own: GROUP BY and ORDER BY
//!   spill to disk (`max_bytes_ratio_before_external_group_by/sort` = 0.3 in
//!   the Compose and Helm profiles; the legacy `deploy/k8s/aws-db`,
//!   `deploy/k8s/rackspace-db` and `ludus` shapes set absolute thresholds at
//!   half their per-query `max_memory_usage`, which also spill before the
//!   ceiling), `values()`/`list()` are capped at
//!   `max_group_array_size` per group, and `reverse` is a plain ORDER BY with
//!   the executor's top-N LIMIT (the same shape as `| sort timestamp`, which
//!   was never guarded). Admitted with no estimate.
//! * **Cost-gated** — state ClickHouse cannot spill: window partitions
//!   (`transaction`, `streamstats`, `anomaly`), the `LIMIT 1 BY` key set of
//!   `dedup`, the per-group lookup arrays of `eventstats`, and the executor's
//!   `count(*) OVER ()` pagination wrapper, which buffers every output row of
//!   a row-preserving pipeline. Admitted when a row estimate over the same
//!   window and filters fits the per-command row budget derived from the
//!   query's memory ceiling, refused with the estimate otherwise.
//!
//! This module is pure (no I/O); the service runs the estimate count.

use super::command_extraction::{query_has_per_row_filters, OomRisk, OomRiskSite};
use crate::query::{Command, Query};

/// Deployment override for the memory budget the row thresholds derive from.
/// `0` disables cost-based admission: every cost-gated site is refused as
/// before NAN-5635. Unset: half the query's effective memory ceiling.
pub const COST_GUARD_BUDGET_ENV: &str = "SEARCH_COST_GUARD_BUDGET_BYTES";

/// Budget used when neither the request nor the deployment reports a memory
/// ceiling (the ClickHouse server limit could not be read at boot).
pub const DEFAULT_COST_GUARD_BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// No install admits fewer rows than this for any cost-gated command, so a
/// tiny box can still run them over a short window.
pub const MIN_ROW_BUDGET: u64 = 100_000;

/// What the guard does with one structural site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionClass {
    /// ClickHouse spills or caps the state: admit without an estimate.
    Spillable,
    /// Non-spillable state: admit only when the estimate fits. The value is
    /// the assumed peak bytes of ClickHouse memory per input row.
    CostGated { bytes_per_row: u64 },
}

/// Peak ClickHouse memory per input row, measured on a throwaway OCSF stack
/// (ClickHouse 26.10, ~285k wide rows, NAN-5635) and rounded up with margin.
///
/// `streamstats` / `eventstats` keep every row (`SELECT *` plus the new
/// columns), and the executor's `count(*) OVER ()` wrapper buffers all of
/// them: 2.5–2.8 KiB per row measured. `transaction`, `anomaly` and `dedup`
/// collapse their output; measured 30–180 B per row, budgeted at 1 KiB for
/// partition skew.
///
/// `dedup` is the exception when its output reaches the result as is: on a
/// near-unique key it keeps almost every row, and the `count(*) OVER ()`
/// wrapper then buffers them all, so it is budgeted as row-preserving unless
/// a later aggregation or `head` / `tail` bounds what it feeds (NAN-5657).
pub(crate) const ROW_PRESERVING_BYTES_PER_ROW: u64 = 4096;
pub(crate) const COLLAPSING_BYTES_PER_ROW: u64 = 1024;

/// Classify one structural site.
pub fn admission_class(site: &OomRiskSite<'_>) -> AdmissionClass {
    match (&site.risk, site.command) {
        (OomRisk::HighCardinalityGroupBy { .. }, _)
        | (OomRisk::UnboundedCollectAggregation, _)
        | (OomRisk::UnboundedReverse, _) => AdmissionClass::Spillable,
        // eventstats / streamstats, and the prevalence pushdown's newest-1M
        // full-width sort (NAN-5660): both keep every input row.
        (OomRisk::UnboundedWindowFunction, _) | (OomRisk::UnboundedPrevalenceScan, _) => AdmissionClass::CostGated {
            bytes_per_row: ROW_PRESERVING_BYTES_PER_ROW,
        },
        (OomRisk::UnboundedDedup, _) if !output_is_bounded_after(site) => AdmissionClass::CostGated {
            bytes_per_row: ROW_PRESERVING_BYTES_PER_ROW,
        },
        (OomRisk::UnboundedDedup, _)
        | (OomRisk::UnboundedTransaction, _)
        | (OomRisk::UnboundedAnomaly, _) => AdmissionClass::CostGated {
            bytes_per_row: COLLAPSING_BYTES_PER_ROW,
        },
    }
}

/// Whether a later stage of the site's pipeline bounds the rows the site
/// feeds to the result (an aggregation, or `head` / `tail`), so the
/// pagination wrapper never buffers the site's whole output.
fn output_is_bounded_after(site: &OomRiskSite<'_>) -> bool {
    let mut commands = Vec::new();
    split_pipeline(site.scope, &mut commands);
    commands
        .get(site.command_index + 1..)
        .is_some_and(|after| {
            after
                .iter()
                .any(|cmd| is_aggregation(cmd) || matches!(cmd, Command::Head { .. } | Command::Tail { .. }))
        })
}

/// Rows a cost-gated command may see under `budget_bytes` of query memory.
pub fn row_budget(bytes_per_row: u64, budget_bytes: u64) -> u64 {
    (budget_bytes / bytes_per_row.max(1)).max(MIN_ROW_BUDGET)
}

/// Share of the query's memory ceiling the cost-gated commands may plan for.
/// The ceiling is per query (40% of the server limit), so a full-ceiling
/// budget would let three admitted queries at once exceed the server limit
/// and fail inserts with Code 241 (NAN-4957). Half leaves room for that and
/// for the scan the command sits on.
pub const BUDGET_SHARE_PCT: u64 = 50;

/// The memory budget the thresholds derive from: [`BUDGET_SHARE_PCT`] of the
/// smallest ceiling that applies to this query (the request's priority
/// settings, the deployment's per-query ceiling), else of the default. The
/// override replaces the share but is clamped to the ceiling; `Some(0)` from
/// it means cost-based admission is off.
pub fn resolve_budget_bytes(
    override_bytes: Option<u64>,
    request_max_memory: Option<u64>,
    deployment_ceiling: Option<u64>,
) -> u64 {
    let ceiling = match (request_max_memory, deployment_ceiling) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        (None, None) => DEFAULT_COST_GUARD_BUDGET_BYTES,
    }
    .max(1);
    match override_bytes {
        Some(0) => 0,
        Some(bytes) => bytes.min(ceiling),
        None => (ceiling / 100 * BUDGET_SHARE_PCT).max(1),
    }
}

/// Parse [`COST_GUARD_BUDGET_ENV`]. Invalid values are ignored (None).
pub fn budget_override_from_env() -> Option<u64> {
    std::env::var(COST_GUARD_BUDGET_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
}

/// The query whose row count bounds what reaches the site's command, or
/// `None` when no cheap upper bound exists (the guard then refuses, as before).
///
/// The estimate is the site's search stage plus the leading run of row
/// filters (`where`, with the `eval`/`rex`/`rename`/… it may depend on), so
/// `* | where isnotnull(user.name) | dedup …` is estimated on the rows the
/// `where` keeps. Every other command before the site must only keep or drop
/// rows (aggregations, `head`, `dedup`, …): their output is at most the
/// estimate. After an aggregation the estimate is the pipeline through the
/// last aggregation, so it counts groups exactly (including a group per
/// element of an array key, NAN-4295). A command that can multiply rows
/// (`mvexpand`, `join`, `append`, `lookup`, a hop `bin`, a gap-filled
/// `timechart`, …) or a subsearch over another dataset has no cheap bound.
pub fn estimate_query(site: &OomRiskSite<'_>) -> Option<Query> {
    if site.foreign_dataset {
        return None;
    }
    let mut commands = Vec::new();
    let base = split_pipeline(site.scope, &mut commands);
    let before = commands.get(..site.command_index)?;
    if !before.iter().all(|cmd| keeps_or_drops_rows(cmd)) {
        return None;
    }
    // After an aggregation the command sees groups, not events: count the
    // pipeline through the last aggregation (`* | stats count by ip |
    // eventstats …` sees one row per ip). Later stages only drop rows. The
    // count runs that aggregation once more; aggregations spill.
    if let Some(last_agg) = before.iter().rposition(|cmd| is_aggregation(cmd)) {
        let mut estimate = Query::Search(base.clone());
        for cmd in &before[..=last_agg] {
            estimate = Query::Piped {
                source: Box::new(estimate),
                command: (*cmd).clone(),
            };
        }
        return Some(estimate);
    }
    // Leading run of commands that only filter or annotate rows; stop at the
    // first one that reshapes the row set.
    let run: Vec<&Command> = before
        .iter()
        .copied()
        .take_while(|cmd| is_row_filter_stage(cmd))
        .collect();
    // Keep it through its last `where`: a trailing eval/rex changes nothing
    // the count sees.
    let last_where = run
        .iter()
        .rposition(|cmd| matches!(cmd, Command::Where { .. }));
    let mut estimate = Query::Search(base.clone());
    if let Some(last) = last_where {
        for cmd in &run[..=last] {
            if matches!(cmd, Command::Sort { .. }) {
                continue; // reorders only
            }
            estimate = Query::Piped {
                source: Box::new(estimate),
                command: (*cmd).clone(),
            };
        }
    }
    Some(estimate)
}

/// Whether the estimate count may stop at `budget + 1` rows (it carries
/// per-row filters, so ClickHouse reads rows) or should run unbounded (a
/// filter-free count is served from part metadata, NAN-1635).
pub fn estimate_is_bounded(estimate: &Query) -> bool {
    query_has_per_row_filters(estimate)
}

fn split_pipeline<'a>(query: &'a Query, commands: &mut Vec<&'a Command>) -> &'a crate::query::SearchExpr {
    match query {
        Query::Search(expr) => expr,
        Query::Piped { source, command } => {
            let base = split_pipeline(source, commands);
            commands.push(command);
            base
        }
    }
}

/// Stages the estimate may carry: row filters and the per-row annotators a
/// later filter can reference.
fn is_row_filter_stage(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Where { .. }
            | Command::Eval { .. }
            | Command::Rex { .. }
            | Command::Fillnull { .. }
            | Command::Spath { .. }
            | Command::Rename { .. }
            | Command::Sort { .. }
    ) || is_one_row_bin(cmd)
}

/// Grouping stages whose output is one row per group.
fn is_aggregation(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Stats { .. }
            | Command::Chart { .. }
            | Command::Timechart { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
    )
}

/// A tumbling or sliding `bin` labels each row once; a hop `bin` emits one
/// row per overlapping window (`ARRAY JOIN` over span/advance).
fn is_one_row_bin(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Bin { window_type, .. } if !matches!(window_type, crate::query::WindowType::Hop { .. })
    )
}

/// Commands whose output has at most as many rows as their input.
fn keeps_or_drops_rows(cmd: &Command) -> bool {
    is_one_row_bin(cmd)
        || matches!(cmd, Command::Timechart { cont: false, .. })
        || matches!(
        cmd,
        Command::Where { .. }
            | Command::Eval { .. }
            | Command::Rex { .. }
            | Command::Fillnull { .. }
            | Command::Spath { .. }
            | Command::Rename { .. }
            | Command::Sort { .. }
            | Command::Fields { .. }
            | Command::Table { .. }
            | Command::Head { .. }
            | Command::Tail { .. }
            | Command::Sample { .. }
            | Command::Reverse
            | Command::Dedup { .. }
            | Command::Stats { .. }
            | Command::Chart { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
            | Command::EventStats { .. }
            | Command::StreamStats { .. }
            | Command::Transaction { .. }
            | Command::Anomaly { .. }
            | Command::Risk { .. }
    )
}

/// Outcome of the admission check for one cost-gated site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estimate {
    /// Exact count (unbounded estimate).
    Exact(u64),
    /// A bounded count reached its cap: more than this many rows.
    MoreThan(u64),
}

/// Admit or refuse a cost-gated site given its counted rows. A `bounded`
/// count stops at `budget_rows + 1`, so anything over the budget only proves
/// "more than the budget".
pub fn decide(risk: &OomRisk, counted: u64, bounded: bool, budget_rows: u64) -> Result<(), String> {
    if counted <= budget_rows {
        return Ok(());
    }
    let seen = if bounded {
        Estimate::MoreThan(budget_rows)
    } else {
        Estimate::Exact(counted)
    };
    Err(refusal_message(risk, &seen, budget_rows))
}

/// The guard's message plus the number (NAN-5635).
pub fn refusal_message(risk: &OomRisk, estimate: &Estimate, budget_rows: u64) -> String {
    let scanned = match estimate {
        Estimate::Exact(n) => format!("~{}", group_thousands(*n)),
        Estimate::MoreThan(n) => format!("more than {}", group_thousands(*n)),
    };
    format!(
        "{} This search would feed {scanned} events into it; this install admits up to {} \
         for this command. Narrow the time range or add filters.",
        risk.message(),
        group_thousands(budget_rows)
    )
}

fn group_thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
#[path = "oom_admission_tests.rs"]
mod tests;
