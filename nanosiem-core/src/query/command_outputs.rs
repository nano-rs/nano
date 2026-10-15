// SPDX-License-Identifier: AGPL-3.0-or-later

//! The single registry of output columns a pipeline command CREATES.
//!
//! Two collectors need this list: the field validator
//! (`validation::derived_fields`, which decides what a later stage may name)
//! and the SQL generator (`clickhouse_sql_gen::field_analysis`, which decides
//! that a later reference is a real stage column rather than a base/ext
//! field). They used to keep separate hand-written lists, and they drifted:
//! `bin … hop=` `_end` columns, the anomaly helper columns, funnel/lateral
//! outputs, `risk_entity` and `table … as alias` were missing from one side or
//! both. A later stage that named one was rejected as an unknown OCSF field or
//! compiled to a bogus `ext.<name>` read (NAN-3328, NAN-3314).
//!
//! Every command arm here must match what the generator (or the Nano-side
//! post-processing view) actually emits. Both collectors add these names on
//! top of their own context-specific entries (group-by passthroughs,
//! aggregation aliases, rex/spath outputs).

use super::ast::{AnomalyMethod, BinSpan, Command, WindowType};

/// Columns the anomaly scoring wrapper projects for `method`
/// (`zscore_outer_sql_with_alias` / `mad_outer_sql_with_alias`).
fn anomaly_columns(method: &AnomalyMethod) -> &'static [&'static str] {
    match method {
        AnomalyMethod::ZScore => &[
            "anomaly_score",
            "is_anomaly",
            "expected",
            "avg_val",
            "stddev_val",
        ],
        AnomalyMethod::Mad => &[
            "anomaly_score",
            "is_anomaly",
            "expected",
            "median_val",
            "mad_val",
        ],
    }
}

/// The `{func}_{field}` column the aggregation-first anomaly form exposes
/// (`anomaly sum(traffic.bytes) by …` → `sum_traffic_bytes`).
fn anomaly_aggregate_alias(field: &str) -> Option<String> {
    let (open, close) = (field.find('(')?, field.rfind(')')?);
    if close <= open {
        return None;
    }
    let function = field[..open].trim().to_ascii_lowercase();
    let inner = field[open + 1..close].trim();
    Some(if inner.is_empty() || inner == "*" {
        function
    } else {
        format!("{}_{}", function, inner.replace('.', "_"))
    })
}

/// Rows the lateral-movement view emits (`search::service::lateral`, both the
/// ClickHouse and the lake builder). Post-lateral commands run over these.
const LATERAL_OUTPUT_COLUMNS: &[&str] = &[
    "timestamp",
    "user",
    "src_host",
    "dest_host",
    "src_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "method",
    "method_detail",
    "hop_number",
    "process_name",
    "auth_type",
    "auth_result",
    "source_type",
    "log_source",
];

/// Fixed columns of the funnel result (`generate_funnel_sql`).
const FUNNEL_OUTPUT_COLUMNS: &[&str] = &[
    "funnel_level",
    "step_name",
    "count",
    "dropper_count",
    "dropper_median_idle_s",
];

/// Columns of a `| risk` stage (SQL generator and Rust post-processing).
const RISK_OUTPUT_COLUMNS: &[&str] = &[
    "risk_score",
    "raw_risk_score",
    "risk_entity",
    "risk_factors",
];

/// Columns the `| ai` pipe writes onto each row (NAN-3190).
const AI_PIPE_OUTPUT_FIELDS: &[&str] = &["ai_verdict", "ai_confidence", "ai_reasoning"];

/// The output column names `command` creates, in their query-facing spelling.
///
/// Group-by passthroughs and aggregation aliases are NOT listed here: their
/// handling legitimately differs between the validator and the generator.
pub(crate) fn command_created_columns(command: &Command) -> Vec<String> {
    let owned = |names: &[&str]| names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
    match command {
        Command::Bin {
            span,
            field,
            alias,
            window_type,
        } => {
            // Mirrors the Bin generator: explicit alias, else the binned field
            // (an in-place rewrite — not a new name), else `time_bucket`.
            let output = match (alias, field) {
                (Some(alias), _) => alias.clone(),
                (None, Some(field)) => field.clone(),
                (None, None) => "time_bucket".to_string(),
            };
            let mut out = Vec::new();
            if alias.is_some() || field.is_none() {
                out.push(output.clone());
            }
            // Hop and sliding time windows also project `<output>_end`.
            if matches!(span, BinSpan::Time(_))
                && matches!(window_type, WindowType::Hop { .. } | WindowType::Sliding)
            {
                out.push(format!("{output}_end"));
            }
            out
        }
        Command::Anomaly { field, method, .. } => {
            let mut out = owned(anomaly_columns(method));
            out.extend(anomaly_aggregate_alias(field));
            out
        }
        Command::Funnel { .. } => owned(FUNNEL_OUTPUT_COLUMNS),
        Command::Risk { .. } => owned(RISK_OUTPUT_COLUMNS),
        Command::Lateral { .. } => owned(LATERAL_OUTPUT_COLUMNS),
        Command::Ai { .. } => owned(AI_PIPE_OUTPUT_FIELDS),
        // `table f as alias` projects `f AS alias`: the alias is a real column
        // of every later stage (NAN-3314).
        Command::Table { fields } => fields.iter().filter_map(|f| f.alias.clone()).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    fn last_command(query: &str) -> Command {
        match parse_query(query).unwrap() {
            crate::query::Query::Piped { command, .. } => command,
            other => panic!("not piped: {other:?}"),
        }
    }

    #[test]
    fn bin_windows_register_end_columns() {
        assert_eq!(
            command_created_columns(&last_command("* | bin span=1h hop=30m")),
            vec!["time_bucket", "time_bucket_end"]
        );
        assert_eq!(
            command_created_columns(&last_command("* | bin time span=1h hop=30m")),
            vec!["time_end"]
        );
        assert_eq!(
            command_created_columns(&last_command("* | bin span=1h")),
            vec!["time_bucket"]
        );
    }

    #[test]
    fn anomaly_field_form_registers_helper_columns() {
        let cols = command_created_columns(&last_command("* | anomaly field=traffic.bytes_out"));
        for c in [
            "expected",
            "avg_val",
            "stddev_val",
            "anomaly_score",
            "is_anomaly",
        ] {
            assert!(cols.iter().any(|x| x == c), "missing {c}: {cols:?}");
        }
    }

    #[test]
    fn table_aliases_are_created_columns() {
        assert_eq!(
            command_created_columns(&last_command("* | table user.name as u, time")),
            vec!["u"]
        );
    }
}
