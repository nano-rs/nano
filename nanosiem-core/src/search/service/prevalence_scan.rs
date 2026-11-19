// SPDX-License-Identifier: AGPL-3.0-or-later

//! How much of the base scan the prevalence pushdown materializes (NAN-5660).
//!
//! The enrich-only pushdown is per-row decoration (dictGet lookups), so its
//! `raw_logs` CTE keeps the newest rows: `ORDER BY timestamp DESC LIMIT n`.
//! With `n` = the 1M safety cap and the base's `SELECT *`, an unfiltered
//! `* | prevalence src_endpoint.ip` sorted up to 1M FULL-WIDTH OCSF rows and
//! hit the per-query memory ceiling (Code 241), though the analyst sees 50.
//!
//! Three plans, in order:
//!
//! * **Result window pushed.** Decoration commutes with `ORDER BY timestamp
//!   DESC LIMIT n`, so when nothing after the prevalence stage(s) filters,
//!   reorders or aggregates, `raw_logs` keeps only the rows the caller can
//!   read (`offset + min(limit, head)`): the same cost as `* | head 50`.
//! * **Projected.** Otherwise, when the output is a `table`/`fields` of
//!   promoted columns, the final SELECT names those columns instead of `l.*`;
//!   ClickHouse then carries only them (plus what the lookups and filters
//!   read) through the newest-1M sort.
//! * **Wide newest-1M scan.** Neither applies: the cost-based admission guard
//!   (NAN-5635) gates it like the other row-preserving buffers.
//!
//! The aggregation and filter forms keep their unbounded `raw_logs` (an
//! aggregation needs every row; the dictGet filter must see the whole window).

use std::collections::BTreeSet;
use std::collections::HashSet;

use crate::query::{ClickHouseSqlGenerator, Command, Query};
use crate::schema::{FieldResolution, SchemaProfile};
use crate::search::query_processing::PrevalenceCommandInfo;

/// The rows of the final result a caller reads: the page size and offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResultWindow {
    pub limit: usize,
    pub offset: usize,
}

/// How the pushdown bounds and projects its base scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrevalenceScanPlan {
    /// `ORDER BY timestamp DESC LIMIT n` on `raw_logs`; `None` keeps the base
    /// unbounded (aggregation / filter form).
    pub raw_logs_limit: Option<usize>,
    /// `raw_logs_limit` is the caller's result window, not the safety cap.
    pub window_pushed: bool,
    /// Promoted columns the final SELECT names instead of `l.*`.
    pub output_columns: Option<Vec<String>>,
}

impl PrevalenceScanPlan {
    /// The newest-1M sort of full-width rows: the shape the cost guard gates.
    pub(crate) fn is_wide_newest_scan(&self) -> bool {
        self.raw_logs_limit.is_some() && !self.window_pushed && self.output_columns.is_none()
    }
}

/// Decide the plan for one pushdown. `window` is `None` when the caller has
/// no result window (the plan then never pushes one).
pub(crate) fn plan_prevalence_scan(
    query: &Query,
    prevalence_commands: &[PrevalenceCommandInfo],
    post_prevalence_commands: &[Command],
    window: Option<ResultWindow>,
    profile: &dyn SchemaProfile,
) -> PrevalenceScanPlan {
    let base = BaseShape::of(query);
    let has_downstream_aggregation = post_prevalence_commands.iter().any(|cmd| {
        matches!(
            cmd,
            Command::Stats { .. } | Command::Top { .. } | Command::Rare { .. } | Command::Timechart { .. }
        )
    });
    let has_prevalence_filter = prevalence_commands.iter().any(|cmd| !cmd.conditions.is_empty());
    if has_downstream_aggregation || has_prevalence_filter {
        return PrevalenceScanPlan {
            raw_logs_limit: None,
            window_pushed: false,
            output_columns: None,
        };
    }
    let cap = ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT;
    if let Some(window) = window.filter(|_| base.keeps_time_order) {
        if post_prevalence_commands.iter().all(is_row_wise) {
            return PrevalenceScanPlan {
                raw_logs_limit: Some(rows_read(post_prevalence_commands, window).clamp(1, cap)),
                window_pushed: true,
                output_columns: None,
            };
        }
    }
    PrevalenceScanPlan {
        raw_logs_limit: Some(cap),
        window_pushed: false,
        output_columns: base
            .keeps_every_column
            .then(|| projected_output_columns(post_prevalence_commands, profile))
            .flatten(),
    }
}

/// Commands that keep each row's position in the `timestamp DESC` order and
/// drop none except from the end. Every one of them runs on the executor's
/// page (Rust post-processing) or is a per-row SQL column (`eval`), so the
/// page is the same whether `raw_logs` holds 1M rows or just the window.
/// Anything else (`where`, `sort`, `dedup`, `tail`, `risk`, aggregations, …)
/// blocks the pushdown.
fn is_row_wise(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Eval { .. }
            | Command::Table { .. }
            | Command::Fields { .. }
            | Command::Rename { .. }
            | Command::Head { .. }
            | Command::Rex { .. }
            | Command::Fillnull { .. }
    )
}

/// What the commands before the first `prevalence` leave of the base.
#[derive(Debug, Clone, Copy)]
struct BaseShape {
    /// Natural newest-first order and no LIMIT of their own, so the generator
    /// ends the base in `ORDER BY timestamp DESC` and a result window can go
    /// there. An explicit order (`sort`, `tail`, `reverse`), a limit (`head`,
    /// `sample`) or anything else keeps the unpushed plan.
    keeps_time_order: bool,
    /// Every table column is still in the base (only filters and added
    /// columns before prevalence), so the final SELECT may name any of them.
    keeps_every_column: bool,
}

impl BaseShape {
    fn of(query: &Query) -> Self {
        let mut commands = Vec::new();
        let mut node = query;
        while let Query::Piped { source, command } = node {
            commands.push(command);
            node = source;
        }
        commands.reverse();
        let before: Vec<&Command> = commands
            .into_iter()
            .take_while(|cmd| !matches!(cmd, Command::Prevalence { .. }))
            .collect();
        let adds_or_filters = |cmd: &&Command| {
            matches!(
                cmd,
                Command::Where { .. } | Command::Eval { .. } | Command::Rex { .. } | Command::Fillnull { .. }
            )
        };
        Self {
            keeps_time_order: before.iter().all(|cmd| {
                adds_or_filters(cmd)
                    || matches!(cmd, Command::Rename { .. } | Command::Fields { .. } | Command::Table { .. })
            }),
            keeps_every_column: before.iter().all(adds_or_filters),
        }
    }
}

/// Rows of the `timestamp DESC` result the caller reads: the executor slices
/// `[offset, offset + limit)` and a `| head N` keeps the first N of that page.
fn rows_read(post_prevalence_commands: &[Command], window: ResultWindow) -> usize {
    let head = post_prevalence_commands
        .iter()
        .filter_map(|cmd| match cmd {
            Command::Head { count } => Some(*count),
            _ => None,
        })
        .min();
    let page = head.map_or(window.limit, |head| head.min(window.limit));
    window.offset.saturating_add(page)
}

/// Columns the pushdown's final SELECT reads instead of `l.*`, or `None` when
/// the output needs every column.
///
/// Only when the output is shaped by `table` / `fields` (keep) and every
/// command after prevalence is one whose field references are known: each
/// row key the post-processing reads is a decoration, an eval output, or a
/// promoted column of that exact name (`table` reads the
/// `normalize_field_alias` key, `fields`/`sort`/`dedup` the name as written),
/// so the projected row carries every key `l.*` gave those commands. The
/// filters (`where`) and lookups read `l` directly in ClickHouse, so they need
/// no entry here; `timestamp` stays for the final ORDER BY.
fn projected_output_columns(post_prevalence_commands: &[Command], profile: &dyn SchemaProfile) -> Option<Vec<String>> {
    let shapes_output = post_prevalence_commands
        .iter()
        .any(|cmd| matches!(cmd, Command::Table { .. } | Command::Fields { keep: true, .. }));
    if !shapes_output {
        return None;
    }
    let mut eval_outputs: HashSet<&str> = HashSet::new();
    let mut referenced: Vec<&str> = Vec::new();
    for cmd in post_prevalence_commands {
        match cmd {
            // A `where` on `_prevalence.*` runs in Rust post-processing on the
            // row (`condition_references_prevalence_nested_fields`), so its
            // other fields would need projecting too: keep `l.*`. (Matching
            // the name anywhere in the condition only over-rejects.)
            Command::Where { condition } if format!("{condition:?}").contains("_prevalence") => return None,
            Command::Where { .. } | Command::Head { .. } => {}
            Command::Eval { assignments } => {
                eval_outputs.extend(assignments.iter().map(|a| a.field.as_str()));
            }
            Command::Table { fields } => referenced.extend(
                fields
                    .iter()
                    .map(|f| crate::search::field_utils::normalize_field_alias(&f.name)),
            ),
            Command::Fields { fields, keep: true } => referenced.extend(fields.iter().map(String::as_str)),
            Command::Sort { fields, .. } => referenced.extend(fields.iter().map(|f| f.field.as_str())),
            Command::Dedup { fields, .. } => referenced.extend(fields.iter().map(String::as_str)),
            _ => return None,
        }
    }
    let mut columns: BTreeSet<String> = BTreeSet::new();
    columns.insert("timestamp".to_string());
    for field in referenced {
        if eval_outputs.contains(field) || is_decoration(field) {
            continue;
        }
        if field.contains('*') {
            return None;
        }
        match profile.resolve(&profile.canonicalize(field)) {
            FieldResolution::ExplicitColumn(column) if column == field => {
                columns.insert(column);
            }
            _ => return None,
        }
    }
    Some(columns.into_iter().collect())
}

/// Columns the pushdown itself adds to every row (and the names the
/// post-query restructure derives from them).
fn is_decoration(field: &str) -> bool {
    super::prevalence_join::PREVALENCE_RESULT_COLUMNS.contains(&field)
        || matches!(field, "first_seen" | "last_seen")
        || field == "_prevalence"
        || field.starts_with("_prevalence.")
}

/// The final SELECT's row columns: `l.*`, or the projected columns under
/// their own names.
pub(crate) fn output_row_columns_sql(plan: &PrevalenceScanPlan) -> String {
    match &plan.output_columns {
        None => "l.*".to_string(),
        Some(columns) => columns
            .iter()
            .map(|column| {
                crate::sql_hygiene::alias_expr(&crate::sql_hygiene::qualified_column("l", column), column)
            })
            .collect::<Vec<_>>()
            .join(",\n    "),
    }
}

#[cfg(test)]
#[path = "prevalence_scan_tests.rs"]
mod tests;
