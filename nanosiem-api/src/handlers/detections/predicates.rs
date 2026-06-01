// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parse a detection rule's nPL query into a flat predicate list + pipe stages.
//!
//! NAN-501 — surfaces the structured AST so the Matches detail pane can render
//! "Rule conditions" as one row per predicate (field / op / value) instead of
//! the raw query string.
//!
//! The output is intentionally **lossy**: complex nested expressions
//! (And/Or trees, sub-searches, function-filters) are flattened into a flat
//! list of leaf predicates. We tag each predicate with `negated` (set when the
//! leaf is wrapped in a `NOT`) and a `connector` field describing how the
//! predicate joins to its neighbour ("AND" / "OR" / "NOT"). UI gets enough
//! signal to render meaningfully without us shipping the full AST.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::query::{parse_query, Aggregation, Command, Query, SearchExpr, Value};
use nanosiem_core::typeid::TypeIdParam;
use serde::Serialize;
use utoipa::ToSchema;

use crate::middleware::{check_permission, AuthContext};
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Flattened nPL parse result for the Rule conditions card.
#[derive(Debug, Serialize, ToSchema)]
pub struct RulePredicatesResponse {
    /// Original raw query (echoed back so the UI can show a "raw" toggle).
    pub raw_query: String,
    /// Whether the parser succeeded. If false, only `raw_query` and `parse_error` are populated.
    pub parsed: bool,
    /// Parser error message if parsing failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
    /// Leaf predicates from the search-term root, in source order.
    pub predicates: Vec<Predicate>,
    /// Pipe stages downstream of the search term (stats, where, sort, etc.).
    pub pipe_stages: Vec<PipeStage>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Predicate {
    /// Predicate kind. Determines which other fields are populated.
    pub kind: PredicateKind,
    /// Field name (when applicable). May be empty for keyword searches.
    pub field: Option<String>,
    /// Comparison operator string (e.g. "=", "!=", ">=", "LIKE", "IN").
    pub operator: Option<String>,
    /// Value rendered as a string (quoted if it would have been quoted in source).
    pub value: Option<String>,
    /// Multi-valued operands for IN-list and similar.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// Whether the predicate is negated (e.g. inside a NOT).
    pub negated: bool,
    /// How this predicate joins to the previous one: "AND", "OR" — or null if first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PredicateKind {
    /// Free-text keyword search (BM25).
    Keyword,
    /// `field op value` simple comparison.
    FieldFilter,
    /// `field IN (a, b, c)`.
    InList,
    /// `field IN [search ...]` subsearch — the subsearch isn't expanded here.
    InSubsearch,
    /// `function(args) op value` or `field op function(args)`.
    Function,
    /// Boolean function predicate (e.g. `isnull(field)`, `cidrmatch(...)`).
    BooleanFunction,
    /// Literal-vs-literal comparison (parameter expansion checks).
    Literal,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PipeStage {
    /// Command name for chip display ("stats", "where", "sort", etc.).
    pub command: String,
    /// Brief one-line argument summary (group-by fields, sort field, etc.).
    pub args: String,
}

/// Parse a detection rule's query into structured predicates + pipe stages.
#[utoipa::path(
    get,
    path = "/api/rules/{id}/predicates",
    tag = "detections",
    params(("id" = String, Path, description = "Detection rule ID")),
    responses(
        (status = 200, description = "Parsed predicate tree", body = RulePredicatesResponse),
        (status = 403, description = "Missing permission: detections:view", body = ErrorResponse),
        (status = 404, description = "Rule not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_rule_predicates(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<RulePredicatesResponse>, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:view".to_string()))?;

    let rule = state.detection_service.get_rule(*id).await?;

    // Try to parse. If parsing fails, return the raw query with a parse_error
    // so the UI can fall back to showing the raw text without breaking.
    let parsed_query = match parse_query(&rule.query) {
        Ok(q) => q,
        Err(err) => {
            return Ok(Json(RulePredicatesResponse {
                raw_query: rule.query,
                parsed: false,
                parse_error: Some(err.to_string()),
                predicates: vec![],
                pipe_stages: vec![],
            }));
        }
    };

    let mut predicates: Vec<Predicate> = Vec::new();
    let mut pipe_stages: Vec<PipeStage> = Vec::new();
    walk_query(&parsed_query, &mut predicates, &mut pipe_stages, false, None);

    Ok(Json(RulePredicatesResponse {
        raw_query: rule.query,
        parsed: true,
        parse_error: None,
        predicates,
        pipe_stages,
    }))
}

/// Walk a query AST, appending search predicates and pipe stages in source order.
fn walk_query(
    q: &Query,
    predicates: &mut Vec<Predicate>,
    pipe_stages: &mut Vec<PipeStage>,
    negated: bool,
    connector: Option<&str>,
) {
    match q {
        Query::Search(expr) => {
            walk_search_expr(expr, predicates, negated, connector);
        }
        Query::Piped { source, command } => {
            walk_query(source, predicates, pipe_stages, negated, connector);
            pipe_stages.push(summarise_command(command));
        }
    }
}

/// Walk a search expression, appending leaf predicates with appropriate connector tags.
fn walk_search_expr(
    expr: &SearchExpr,
    out: &mut Vec<Predicate>,
    negated: bool,
    connector: Option<&str>,
) {
    match expr {
        SearchExpr::And(a, b) => {
            walk_search_expr(a, out, negated, connector);
            walk_search_expr(b, out, negated, Some("AND"));
        }
        SearchExpr::Or(a, b) => {
            walk_search_expr(a, out, negated, connector);
            walk_search_expr(b, out, negated, Some("OR"));
        }
        SearchExpr::Not(inner) => {
            // Flip negation; preserve the connector this NOT was joined with.
            walk_search_expr(inner, out, !negated, connector);
        }
        SearchExpr::Group(inner) => {
            walk_search_expr(inner, out, negated, connector);
        }
        SearchExpr::Keyword(kw) => out.push(Predicate {
            kind: PredicateKind::Keyword,
            field: None,
            operator: None,
            value: Some(kw.clone()),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::FieldFilter { field, op, value } => out.push(Predicate {
            kind: PredicateKind::FieldFilter,
            field: Some(field.clone()),
            operator: Some(op.as_str().to_string()),
            value: Some(format_value(value)),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::FunctionFilter { function, op, value } => out.push(Predicate {
            kind: PredicateKind::Function,
            field: Some(format!("{:?}", function)),
            operator: Some(op.as_str().to_string()),
            value: Some(format_value(value)),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::FieldFunctionFilter { field, op, function } => out.push(Predicate {
            kind: PredicateKind::Function,
            field: Some(field.clone()),
            operator: Some(op.as_str().to_string()),
            value: Some(format!("{:?}", function)),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::InList {
            field,
            values,
            negated: list_negated,
        } => out.push(Predicate {
            kind: PredicateKind::InList,
            field: Some(field.clone()),
            operator: Some(if *list_negated { "NOT IN" } else { "IN" }.to_string()),
            value: None,
            values: values.iter().map(format_value).collect(),
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::InSubsearch {
            field,
            negated: sub_negated,
            ..
        } => out.push(Predicate {
            kind: PredicateKind::InSubsearch,
            field: Some(field.clone()),
            operator: Some(if *sub_negated { "NOT IN" } else { "IN" }.to_string()),
            value: Some("[subsearch]".to_string()),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::BooleanFunction(function) => out.push(Predicate {
            kind: PredicateKind::BooleanFunction,
            field: None,
            operator: None,
            value: Some(format!("{:?}", function)),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
        SearchExpr::LiteralComparison { left, op, right } => out.push(Predicate {
            kind: PredicateKind::Literal,
            field: Some(left.clone()),
            operator: Some(op.as_str().to_string()),
            value: Some(format_value(right)),
            values: vec![],
            negated,
            connector: connector.map(String::from),
        }),
    }
}

/// One-line summary of a pipe command for chip display.
fn summarise_command(cmd: &Command) -> PipeStage {
    match cmd {
        Command::Stats {
            aggregations,
            group_by,
        } => PipeStage {
            command: "stats".to_string(),
            args: stats_args(aggregations, group_by),
        },
        Command::Chart {
            aggregations,
            group_by,
        } => PipeStage {
            command: "chart".to_string(),
            args: stats_args(aggregations, group_by),
        },
        Command::StreamStats {
            aggregations,
            group_by,
            ..
        } => PipeStage {
            command: "streamstats".to_string(),
            args: stats_args(aggregations, group_by),
        },
        Command::Where { .. } => PipeStage {
            command: "where".to_string(),
            args: String::new(),
        },
        Command::Sort { fields, limit } => {
            let names: Vec<String> = fields.iter().map(|f| f.field.clone()).collect();
            let mut args = names.join(", ");
            if let Some(l) = limit {
                args.push_str(&format!(" limit={}", l));
            }
            PipeStage {
                command: "sort".to_string(),
                args,
            }
        }
        Command::Head { count } => PipeStage {
            command: "head".to_string(),
            args: count.to_string(),
        },
        Command::Tail { count } => PipeStage {
            command: "tail".to_string(),
            args: count.to_string(),
        },
        Command::Timechart { span, .. } => PipeStage {
            command: "timechart".to_string(),
            args: format!("span={}s", span.as_secs()),
        },
        Command::Table { fields } => PipeStage {
            command: "table".to_string(),
            args: fields
                .iter()
                .map(|f| f.name.clone())
                .collect::<Vec<_>>()
                .join(", "),
        },
        Command::Rename { mappings } => PipeStage {
            command: "rename".to_string(),
            args: mappings
                .iter()
                .map(|m| format!("{} → {}", m.from, m.to))
                .collect::<Vec<_>>()
                .join(", "),
        },
        // Default-debug rendering for the long tail of commands. We don't need
        // bespoke summaries for every command — analysts can hover for the raw
        // query if they need detail.
        other => PipeStage {
            command: command_name(other),
            args: String::new(),
        },
    }
}

fn stats_args(aggs: &[Aggregation], group_by: &Option<Vec<String>>) -> String {
    let agg_names: Vec<String> = aggs
        .iter()
        .map(|a| {
            a.alias
                .clone()
                .unwrap_or_else(|| format!("{:?}", a.func).to_lowercase())
        })
        .collect();
    let mut s = agg_names.join(", ");
    if let Some(g) = group_by {
        if !g.is_empty() {
            s.push_str(" by ");
            s.push_str(&g.join(", "));
        }
    }
    s
}

/// Human-readable command name for the chip label.
///
/// Covers the common verbs analysts care about; everything else falls back to
/// a lowercased Debug-derived name (e.g. `Command::Mvexpand` → "mvexpand").
fn command_name(cmd: &Command) -> String {
    let s = match cmd {
        Command::Stats { .. } => "stats",
        Command::Chart { .. } => "chart",
        Command::StreamStats { .. } => "streamstats",
        Command::Where { .. } => "where",
        Command::Sort { .. } => "sort",
        Command::Head { .. } => "head",
        Command::Tail { .. } => "tail",
        Command::Timechart { .. } => "timechart",
        Command::Table { .. } => "table",
        Command::Rename { .. } => "rename",
        Command::Eval { .. } => "eval",
        Command::Lookup { .. } => "lookup",
        Command::InputLookup { .. } => "inputlookup",
        Command::Dedup { .. } => "dedup",
        Command::Fields { .. } => "fields",
        Command::Bin { .. } => "bin",
        Command::Top { .. } => "top",
        Command::Rare { .. } => "rare",
        Command::Rex { .. } => "rex",
        Command::Spath { .. } => "spath",
        Command::Asset { .. } => "asset",
        Command::Cloud { .. } => "cloud",
        Command::Risk { .. } => "risk",
        Command::Lateral { .. } => "lateral",
        Command::Prevalence { .. } => "prevalence",
        Command::Append { .. } => "append",
        Command::Join { .. } => "join",
        Command::Fillnull { .. } => "fillnull",
        Command::Reverse => "reverse",
        // Catch-all: lower-case the variant name. This covers Mvexpand, Sample,
        // EventStats, Sequence, Funnel, Anomaly, Format, Return, Transaction,
        // Tree, ResolveIdentity, Ai, Output, ZScore, Mad, etc.
        other => return format!("{:?}", other)
            .split_whitespace()
            .next()
            .unwrap_or("command")
            .to_lowercase(),
    };
    s.to_string()
}

/// Format a Value into a UI-friendly string (preserves quoting hints).
fn format_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => {
            if n.fract() == 0.0 {
                format!("{}", *n as i64)
            } else {
                format!("{}", n)
            }
        }
        Value::Bool(b) => b.to_string(),
        Value::Ip(ip) => ip.to_string(),
        Value::Regex(p) => format!("/{}/", p),
        Value::Interval(d, _) => format!("{}s", d.as_secs()),
    }
}
