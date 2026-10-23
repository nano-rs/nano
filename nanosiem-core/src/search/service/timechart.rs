// SPDX-License-Identifier: AGPL-3.0-or-later
//! Complete, bounded timechart presentation shared by the storage backends.
use super::*;
use crate::auth::ScopeSet;
use crate::query::{
    Aggregation, BinaryOperator, Comparator, EvalAssignment, EvalExpression, SearchExpr, SortField,
    Value,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const MAX_BUCKETS: i64 = 1440;
const MAX_SERIES: usize = 100;

fn pipe(source: Query, command: Command) -> Query {
    Query::Piped {
        source: Box::new(source),
        command,
    }
}

fn widened_span(span: Duration, range: &TimeRange) -> Result<Duration, SearchError> {
    let seconds = i64::try_from(span.as_secs()).unwrap_or(i64::MAX);
    if seconds == 0 {
        return Err(SearchError::SqlValidationError(
            "timechart span must be greater than 0".into(),
        ));
    }
    let start = range.start.timestamp();
    let end = range.end.timestamp();
    // NAN-4276: count the buckets the half-open window actually fills (the
    // same `last_bucket_start` the fill uses). `floor(end) + 1` counted one
    // extra bucket on aligned ends, so 24 h at 1m (exactly 1,440 buckets)
    // was widened to 5m.
    if bucket_count(range, seconds) <= MAX_BUCKETS {
        return Ok(span);
    }
    let minimum = ((end - start) / (MAX_BUCKETS - 1) + 1).max(seconds);
    let nice = [1, 5, 10, 30, 60, 300, 900, 1800, 3600, 21600, 86400];
    let seconds = nice
        .into_iter()
        .find(|s| *s >= minimum)
        .unwrap_or_else(|| ((minimum + 86399) / 86400) * 86400);
    Ok(Duration::from_secs(seconds as u64))
}

/// Use exact, case-sensitive, null-safe comparisons for selected group keys.
/// Search field filters deliberately have different (case-insensitive) semantics.
fn selected_condition(
    keys: &[serde_json::Value],
    fields: &[String],
) -> Result<EvalExpression, SearchError> {
    let mut alternatives = Vec::new();
    for row in keys {
        let mut terms = Vec::new();
        for field in fields {
            let value = row.get(field).unwrap_or(&serde_json::Value::Null);
            let field_expr = EvalExpression::Field(field.clone());
            let isnull = EvalExpression::FunctionCall {
                name: "isnull".into(),
                args: vec![field_expr.clone()],
            };
            let expr = if value.is_null() {
                isnull
            } else {
                let literal = match value {
                    serde_json::Value::String(s) => Value::String(s.clone()),
                    serde_json::Value::Number(n) => Value::Number(n.as_f64().ok_or_else(|| {
                        SearchError::SqlValidationError("invalid timechart key".into())
                    })?),
                    serde_json::Value::Bool(b) => Value::Bool(*b),
                    _ => {
                        return Err(SearchError::SqlValidationError(
                            "timechart split keys must be scalar".into(),
                        ))
                    }
                };
                EvalExpression::FunctionCall {
                    name: "coalesce".into(),
                    args: vec![
                        EvalExpression::BinaryOp {
                            left: Box::new(field_expr),
                            op: BinaryOperator::Eq,
                            right: Box::new(EvalExpression::Literal(literal)),
                        },
                        EvalExpression::Literal(Value::Bool(false)),
                    ],
                }
            };
            terms.push(expr);
        }
        alternatives.push(
            terms
                .into_iter()
                .reduce(|a, b| EvalExpression::BinaryOp {
                    left: Box::new(a),
                    op: BinaryOperator::And,
                    right: Box::new(b),
                })
                .unwrap(),
        );
    }
    Ok(alternatives
        .into_iter()
        .reduce(|a, b| EvalExpression::BinaryOp {
            left: Box::new(a),
            op: BinaryOperator::Or,
            right: Box::new(b),
        })
        .unwrap_or(EvalExpression::Literal(Value::Bool(false))))
}

fn filter_selected(source: Query, condition: EvalExpression, other: bool) -> Query {
    // Eval parses full boolean expressions and preserves exact key equality.
    // A fresh temporary name cannot shadow a source or aggregation field.
    let field = format!(
        "__nano_timechart_selected_{}",
        uuid::Uuid::new_v4().simple()
    );
    let source = pipe(
        source,
        Command::Eval {
            assignments: vec![EvalAssignment {
                field: field.clone(),
                expression: EvalExpression::FunctionCall {
                    name: "if".into(),
                    args: vec![
                        condition,
                        EvalExpression::Literal(Value::Number(1.0)),
                        EvalExpression::Literal(Value::Number(0.0)),
                    ],
                },
            }],
        },
    );
    pipe(
        source,
        Command::Where {
            condition: SearchExpr::FieldFilter {
                field,
                op: Comparator::Eq,
                value: Value::Number(if other { 0.0 } else { 1.0 }),
                rhs: Default::default(),
            },
        },
    )
}

fn bucket_query(
    source: Query,
    span: Duration,
    aggregations: &[Aggregation],
    fields: &[String],
) -> Query {
    if fields.is_empty() {
        // Preserve the existing histogram/count-rollup path. The explicit sort
        // keeps this internal long-form fetch out of the presentation wrapper.
        return pipe(
            pipe(
                source,
                Command::Timechart {
                    span,
                    bins: None,
                    aggregations: aggregations.to_vec(),
                    split_by: Vec::new(),
                    limit: None,
                    cont: false,
                    useother: true,
                },
            ),
            Command::Sort {
                fields: vec![SortField {
                    field: "time_bucket".into(),
                    descending: false,
                }],
                limit: None,
            },
        );
    }
    let source = pipe(
        source,
        Command::Bin {
            span: BinSpan::Time(span),
            field: None,
            alias: Some("time_bucket".into()),
            window_type: WindowType::Tumbling,
        },
    );
    let mut groups = vec!["time_bucket".into()];
    groups.extend_from_slice(fields);
    pipe(
        source,
        Command::Stats {
            aggregations: aggregations.to_vec(),
            group_by: Some(groups),
        },
    )
}

fn series_name(
    row: &serde_json::Value,
    fields: &[String],
    agg: &Aggregation,
    multiple: bool,
) -> String {
    if fields.is_empty() {
        return agg.output_alias();
    }
    let values = fields
        .iter()
        .map(|f| row.get(f).cloned().unwrap_or(serde_json::Value::Null))
        .collect::<Vec<_>>();
    if values.len() == 1 && !multiple {
        if let Some(s) = values[0].as_str() {
            if ![
                "time_bucket",
                "timestamp",
                "_timechart",
                "OTHER",
                "__proto__",
                "constructor",
                "prototype",
            ]
            .contains(&s)
                && !s.starts_with("series ")
            {
                return s.to_string();
            }
            return format!("series {}", serde_json::to_string(s).unwrap());
        }
        return format!("series {}", values[0]);
    }
    if multiple {
        format!("series {}", serde_json::json!([agg.output_alias(), values]))
    } else {
        format!("series {}", serde_json::json!(values))
    }
}

/// NAN-4276: start of the last bucket the window covers. The window end is
/// EXCLUSIVE (the search range is `[start, end)`), so a range ending exactly on
/// a span boundary (22:00..23:00 at 5m) has no 23:00 bucket. The old
/// `floor(end)` fill emitted that bucket as a synthetic trailing zero (13
/// buckets for a 12-bucket hour). A sub-second end (23:00:00.5) still covers
/// part of the 23:00 bucket, so it stays.
fn last_bucket_start(range: &TimeRange, seconds: i64) -> i64 {
    let end = range.end.timestamp();
    let last_covered_second = if range.end.timestamp_subsec_nanos() == 0 {
        end - 1
    } else {
        end
    };
    last_covered_second.div_euclid(seconds) * seconds
}

/// Buckets of width `seconds` the half-open `range` fills (at least one).
fn bucket_count(range: &TimeRange, seconds: i64) -> i64 {
    let first = range.start.timestamp().div_euclid(seconds) * seconds;
    let last = last_bucket_start(range, seconds).max(first);
    (last - first) / seconds + 1
}

fn pivot(
    rows: &[serde_json::Value],
    other: &[serde_json::Value],
    fields: &[String],
    aggregations: &[Aggregation],
    span: Duration,
    range: &TimeRange,
) -> Result<Vec<serde_json::Value>, SearchError> {
    let seconds = span.as_secs() as i64;
    let mut buckets: BTreeMap<i64, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();
    let mut columns = BTreeSet::new();
    for (input, is_other) in [(rows, false), (other, true)] {
        for row in input {
            let text = row
                .get("time_bucket")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SearchError::SqlValidationError("timechart returned an invalid bucket".into())
                })?;
            let ts = chrono::DateTime::parse_from_rfc3339(text)
                .map(|d| d.timestamp())
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f")
                        .map(|d| d.and_utc().timestamp())
                })
                .map_err(|_| {
                    SearchError::SqlValidationError("timechart returned an invalid bucket".into())
                })?;
            let bucket = buckets.entry(ts).or_default();
            for agg in aggregations {
                let key = if is_other {
                    if aggregations.len() == 1 {
                        "OTHER".into()
                    } else {
                        format!("{}: OTHER", agg.output_alias())
                    }
                } else {
                    series_name(row, fields, agg, aggregations.len() > 1)
                };
                columns.insert(key.clone());
                bucket.insert(
                    key,
                    row.get(agg.output_alias())
                        .cloned()
                        .unwrap_or(serde_json::json!(0)),
                );
            }
        }
    }
    if fields.is_empty() {
        columns.extend(aggregations.iter().map(Aggregation::output_alias));
    }
    let start = range.start.timestamp().div_euclid(seconds) * seconds;
    let end = last_bucket_start(range, seconds).max(start);
    for ts in (start..=end).step_by(seconds as usize) {
        buckets.entry(ts).or_default();
    }
    Ok(buckets
        .into_iter()
        .map(|(ts, mut row)| {
            for col in &columns {
                row.entry(col.clone()).or_insert(serde_json::json!(0));
            }
            row.insert(
                "time_bucket".into(),
                serde_json::json!(chrono::DateTime::from_timestamp(ts, 0)
                    .unwrap()
                    .to_rfc3339()),
            );
            row.insert(
                "_timechart".into(),
                serde_json::json!({"span_seconds": seconds}),
            );
            serde_json::Value::Object(row)
        })
        .collect())
}

/// NAN-4289 (searchfuzz F25): split `… | timechart … by f | <tail>` when the
/// tail addresses a PIVOT column (`| where GET > 7000`, `| fields time_bucket, GET`).
///
/// The SQL form of a split timechart is long-form (`time_bucket, f, count`); the
/// pivot into one column per series happens in [`SearchService::complete_timechart`],
/// which only ran when the timechart was the last command. A tail that names a
/// series therefore reached the compiler and was refused as an unknown field.
///
/// Only a tail that references a name the long-form rows do NOT carry is
/// diverted, and only when every tail command runs in memory. A tail that reads
/// the long-form columns (`| where f="GET"`, `| head 100`) keeps its existing
/// SQL shape and results.
pub(super) fn split_pivot_tail(query: &Query) -> Option<(&Query, &Command, Vec<Command>)> {
    let mut tail = Vec::new();
    let mut current = query;
    let (source, chart) = loop {
        let Query::Piped { source, command } = current else {
            return None;
        };
        match command {
            Command::Timechart { split_by, .. } if !split_by.is_empty() => break (source.as_ref(), command),
            _ => {
                tail.push(command.clone());
                current = source;
            }
        }
    };
    if tail.is_empty() {
        return None;
    }
    tail.reverse();
    if !tail.iter().all(crate::search::processing::post_processing::is_supported_post_processing_command) {
        return None;
    }
    let long_form = crate::query::collect_derived_fields(current);
    let printed = std::iter::once("*".to_string())
        .chain(tail.iter().map(|command| command.pretty_print()))
        .collect::<Vec<_>>()
        .join(" | ");
    let addresses_pivot = crate::search::field_usage::extract_query_fields(&printed)
        .iter()
        .any(|field| !long_form.contains(&field.to_lowercase()));
    addresses_pivot.then_some((source, chart, tail))
}

const RANK_ALIAS: &str = "__nano_timechart_rank";

/// The ranking stage of a split timechart (`| sort -rank, <fields> | head n`).
fn rank_commands(fields: &[String], n: usize) -> [Command; 2] {
    let mut sort_fields = vec![SortField {
        field: RANK_ALIAS.into(),
        descending: true,
    }];
    sort_fields.extend(fields.iter().map(|f| SortField {
        field: f.clone(),
        descending: false,
    }));
    [
        Command::Sort {
            fields: sort_fields,
            limit: None,
        },
        Command::Head { count: n },
    ]
}

/// NAN-3173/NAN-3386: split the complete long-form count rows of a split
/// timechart (one row per `time_bucket` × series, as the count rollup or the
/// single bucketed scan returns them)
/// into the top-`n` series rows and the per-bucket OTHER rows, exactly as
/// the ranking fetch + selected/OTHER bucket fetches would: series are
/// ranked by their window total with the same `sort -rank, <fields> | head
/// n` stage, keys compare exactly (null is its own key), and OTHER sums
/// every unselected series per bucket. Counts come back as numbers.
fn split_long_form_series(
    rows: Vec<serde_json::Value>,
    fields: &[String],
    alias: &str,
    n: usize,
    useother: bool,
) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), SearchError> {
    let key_of = |row: &serde_json::Value| {
        let key = fields
            .iter()
            .map(|f| row.get(f).cloned().unwrap_or(serde_json::Value::Null))
            .collect::<Vec<_>>();
        (serde_json::to_string(&key).unwrap_or_default(), key)
    };
    let invalid =
        || SearchError::SqlValidationError("timechart count rollup returned an invalid row".into());
    let mut totals: BTreeMap<String, (Vec<serde_json::Value>, u64)> = BTreeMap::new();
    let mut keyed = Vec::with_capacity(rows.len());
    for mut row in rows {
        let count = row
            .get(alias)
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            })
            .ok_or_else(invalid)?;
        let bucket = row
            .get("time_bucket")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)?
            .to_string();
        row.as_object_mut()
            .ok_or_else(invalid)?
            .insert(alias.to_string(), serde_json::json!(count));
        let (key, values) = key_of(&row);
        let total = &mut totals.entry(key.clone()).or_insert((values, 0)).1;
        *total = total.checked_add(count).ok_or_else(invalid)?;
        keyed.push((key, bucket, count, row));
    }
    let ranking = totals
        .into_values()
        .map(|(values, total)| {
            let mut row = serde_json::Map::new();
            for (field, value) in fields.iter().zip(values) {
                row.insert(field.clone(), value);
            }
            row.insert(RANK_ALIAS.into(), serde_json::json!(total));
            serde_json::Value::Object(row)
        })
        .collect::<Vec<_>>();
    let ranked =
        apply_post_prevalence_commands_with_limit(ranking, &rank_commands(fields, n), usize::MAX)?
            .results;
    let selected = ranked
        .iter()
        .map(|row| key_of(row).0)
        .collect::<BTreeSet<_>>();
    let mut series = Vec::new();
    let mut other: BTreeMap<String, u64> = BTreeMap::new();
    for (key, bucket, count, row) in keyed {
        if selected.contains(&key) {
            series.push(row);
        } else if useother {
            let sum = other.entry(bucket).or_default();
            *sum = sum.checked_add(count).ok_or_else(invalid)?;
        }
    }
    let other = other
        .into_iter()
        .map(|(bucket, count)| {
            let mut row = serde_json::Map::new();
            row.insert("time_bucket".into(), serde_json::json!(bucket));
            row.insert(alias.to_string(), serde_json::json!(count));
            serde_json::Value::Object(row)
        })
        .collect();
    Ok((series, other))
}

/// Upper bound on long-form rows the single-pass split fetch accepts
/// (NAN-3386): room for ~1000 series per bucket, at most 100k rows. A larger
/// series set falls back to the ranking + selected + OTHER scans.
const SINGLE_PASS_MAX_ROWS: usize = 100_000;
const SINGLE_PASS_SERIES_PER_BUCKET: usize = 1000;

/// A split timechart can be ranked and folded in memory from its long-form
/// rows only when its single aggregation is additive across series and
/// buckets: `count` (bare, of a field, or conditional). `dc`, `avg`, etc.
/// cannot derive OTHER from per-series values and keep the scans.
fn single_pass_eligible(aggregations: &[Aggregation], fields: &[String]) -> bool {
    !fields.is_empty() && matches!(aggregations, [agg] if agg.func == AggFunc::Count)
}

fn single_pass_row_cap(span: Duration, range: &TimeRange) -> usize {
    let seconds = (span.as_secs() as i64).max(1);
    let buckets = bucket_count(range, seconds);
    (buckets.max(1) as usize)
        .saturating_mul(SINGLE_PASS_SERIES_PER_BUCKET)
        .min(SINGLE_PASS_MAX_ROWS)
}

fn require_complete_buckets(response: &SearchResponse) -> Result<(), SearchError> {
    if !response.total_count_exact || response.total_count > response.results.len() as u64 {
        return Err(SearchError::ResourceExhausted("timechart aggregation did not return the complete bucket set; narrow the range or reduce limit".into()));
    }
    Ok(())
}

impl SearchService {
    pub(super) async fn complete_timechart(
        &self,
        mut request: SearchRequest,
        scope: &ScopeSet,
        source: &Query,
        span: Duration,
        aggregations: &[Aggregation],
        fields: &[String],
        limit: Option<usize>,
        useother: bool,
    ) -> Result<SearchResponse, SearchError> {
        let started = Instant::now();
        let skip_field_stats = request.skip_field_stats;
        // Keep timechart's established field-derived names, while the Stats
        // rewrite would otherwise name each column after its function.
        let named_aggregations = aggregations
            .iter()
            .map(|agg| {
                let mut agg = agg.clone();
                agg.alias = Some(
                    agg.alias
                        .clone()
                        .or_else(|| agg.field.clone())
                        .unwrap_or_else(|| agg.output_alias()),
                );
                agg
            })
            .collect::<Vec<_>>();
        let aggregations = named_aggregations.as_slice();
        if aggregations.iter().any(|a| {
            matches!(
                a.output_alias().as_str(),
                "time_bucket" | "timestamp" | "_timechart"
            )
        }) {
            return Err(SearchError::SqlValidationError(
                "timechart aggregation alias conflicts with a reserved time column".into(),
            ));
        }
        let n = limit.unwrap_or(10);
        if n == 0 || n > MAX_SERIES {
            return Err(SearchError::SqlValidationError(format!(
                "timechart limit must be between 1 and {MAX_SERIES}"
            )));
        }
        let range = TimeRange::new(request.time_range.start, request.time_range.end);
        let widened = widened_span(span, &range)?;
        request.offset = Some(0);
        request.skip_histogram = true;
        request.skip_field_stats = true;
        let mut warnings = Vec::new();
        // NAN-3173: every inner fetch below goes back through `search`, which
        // re-injects the caller's source gate; build them from the gate-free
        // base so each carries it once and stays rollup-plannable.
        let inner_source = self.lake_timechart_inner_source(source, &request, scope);
        let inner_source = inner_source.as_ref().unwrap_or(source);
        let rollup_rows = match aggregations {
            [aggregation] if !fields.is_empty() => {
                Box::pin(self.lake_timechart_rollup_rows(
                    &request,
                    scope,
                    inner_source,
                    source,
                    widened,
                    aggregation,
                    fields,
                ))
                .await
            }
            _ => None,
        };
        let source = inner_source;
        // NAN-3386: without an exact rollup (e.g. a host-scoped split), fetch
        // the complete long-form series set with ONE bucketed, grouped scan
        // and rank/fold OTHER in memory; the ranking + selected + OTHER
        // fetches below are three full scans of the window.
        let rollup_rows = match rollup_rows {
            Some(rows) => Some(rows),
            None if single_pass_eligible(aggregations, fields) => {
                let mut single = request.clone();
                single.query =
                    bucket_query(source.clone(), widened, aggregations, fields).pretty_print();
                single.limit = Some(single_pass_row_cap(widened, &range));
                match Box::pin(self.search(single, scope)).await {
                    Ok(response) if require_complete_buckets(&response).is_ok() => {
                        warnings.extend(response.warnings.unwrap_or_default());
                        Some(response.results)
                    }
                    Ok(response) => {
                        tracing::debug!(
                            returned = response.results.len(),
                            total = response.total_count,
                            "split timechart series set exceeds the single-pass cap; running the series scans"
                        );
                        None
                    }
                    // A series set too large for the worker's group budget
                    // can still chart through the bounded ranking scans.
                    Err(SearchError::ResourceExhausted(error)) => {
                        tracing::debug!(%error, "split timechart single pass exhausted; running the series scans");
                        None
                    }
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        let (mut response, other) = if let Some(rows) = rollup_rows {
            // The rollup or the single scan answered the complete series
            // set: rank and fold OTHER in memory instead of three scans.
            let (selected, other) =
                split_long_form_series(rows, fields, &aggregations[0].output_alias(), n, useother)?;
            let mut response = SearchResponse::empty();
            response.results = selected;
            (response, other)
        } else {
            let mut base = source.clone();
            let mut other_source = None;
            if !fields.is_empty() {
                let mut rank = aggregations.first().cloned().ok_or_else(|| {
                    SearchError::SqlValidationError("timechart requires an aggregation".into())
                })?;
                rank.alias = Some(RANK_ALIAS.into());
                let ranking = pipe(
                    source.clone(),
                    Command::Stats {
                        aggregations: vec![rank],
                        group_by: Some(fields.to_vec()),
                    },
                );
                request.query = rank_commands(fields, n)
                    .into_iter()
                    .fold(ranking, pipe)
                    .pretty_print();
                request.limit = Some(n);
                let ranked = Box::pin(self.search(request.clone(), scope)).await?;
                warnings.extend(ranked.warnings.unwrap_or_default());
                let condition = selected_condition(&ranked.results, fields)?;
                base = filter_selected(source.clone(), condition.clone(), false);
                if useother {
                    other_source = Some(filter_selected(source.clone(), condition, true));
                }
            }
            request.limit = Some((MAX_BUCKETS as usize) * n.max(1) + 1);
            request.query = bucket_query(base, widened, aggregations, fields).pretty_print();
            let mut response = Box::pin(self.search(request.clone(), scope)).await?;
            require_complete_buckets(&response)?;
            warnings.extend(response.warnings.take().unwrap_or_default());
            let other = if let Some(source) = other_source {
                request.query = bucket_query(source, widened, aggregations, &[]).pretty_print();
                request.limit = Some(MAX_BUCKETS as usize + 1);
                let other = Box::pin(self.search(request.clone(), scope)).await?;
                require_complete_buckets(&other)?;
                warnings.extend(other.warnings.unwrap_or_default());
                other.results
            } else {
                Vec::new()
            };
            (response, other)
        };
        response.results = pivot(
            &response.results,
            &other,
            fields,
            aggregations,
            widened,
            &range,
        )?;
        response.total_count = response.results.len() as u64;
        if !skip_field_stats {
            let mut statistics = FieldStatistics::new();
            for row in &response.results {
                let mut public_row = row.clone();
                if let Some(row) = public_row.as_object_mut() {
                    row.remove("_timechart");
                }
                statistics.process_row(&public_row);
            }
            response.fields = statistics.get_field_info(self.config.top_values_count);
        }
        response.display_type = Some(DisplayType::Timechart);
        response.column_order = response
            .results
            .first()
            .and_then(|r| r.as_object())
            .map(|r| {
                r.keys()
                    .filter(|k| k.as_str() != "_timechart")
                    .cloned()
                    .collect()
            });
        if widened != span {
            let secs = widened.as_secs();
            let label = if secs % 86400 == 0 {
                format!("{}d", secs / 86400)
            } else if secs % 3600 == 0 {
                format!("{}h", secs / 3600)
            } else if secs % 60 == 0 {
                format!("{}m", secs / 60)
            } else {
                format!("{secs}s")
            };
            warnings.push(QueryWarningOutput {
                severity: "info".into(),
                code: "TIMECHART_SPAN_WIDENED".into(),
                message: format!("span widened to {label} for this range"),
                suggestion: None,
                impact: None,
            });
        }
        response.warnings = (!warnings.is_empty()).then_some(warnings);
        response.execution_time_ms = started.elapsed().as_millis() as u64;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-3386: only additive single-count splits take the single scan.
    #[test]
    fn single_pass_covers_only_additive_count_splits() {
        let f = vec!["metadata.event_code".to_string()];
        let count = Aggregation::new(AggFunc::Count, None);
        let count_field = Aggregation::new(AggFunc::Count, Some("user".into()));
        assert!(single_pass_eligible(&[count.clone()], &f));
        assert!(single_pass_eligible(&[count_field], &f));
        assert!(!single_pass_eligible(&[count.clone()], &[]));
        assert!(!single_pass_eligible(&[count.clone(), count.clone()], &f));
        for func in [AggFunc::Dc, AggFunc::Avg] {
            assert!(!single_pass_eligible(
                &[Aggregation::new(func, Some("bytes".into()))],
                &f
            ));
        }
        let week = TimeRange::new(
            chrono::DateTime::parse_from_rfc3339("2026-10-01T19:11:00Z")
                .unwrap()
                .into(),
            chrono::DateTime::parse_from_rfc3339("2026-10-08T19:11:00Z")
                .unwrap()
                .into(),
        );
        assert_eq!(
            single_pass_row_cap(Duration::from_secs(3600), &week),
            100_000
        );
        let hour = TimeRange::new(week.start, week.start + chrono::Duration::minutes(59));
        assert_eq!(single_pass_row_cap(Duration::from_secs(3600), &hour), 2000);
    }

    /// NAN-3173: the in-memory ranking of rollup rows matches the ranking
    /// fetch: top `n` by window total, ties by key, null its own series,
    /// OTHER summed per bucket from the rest (and dropped without useother).
    #[test]
    fn rollup_series_rank_and_fold_other_like_the_scans() {
        let f = || vec!["metadata.log_source".to_string()];
        let row = |bucket: &str, source: serde_json::Value, count: serde_json::Value| serde_json::json!({"time_bucket": bucket, "metadata.log_source": source, "count": count});
        let rows = vec![
            row("2026-10-01T00:00:00Z", "b".into(), 4.into()),
            row("2026-10-01T00:00:00Z", "a".into(), "4".into()),
            row("2026-10-01T00:00:00Z", serde_json::Value::Null, 9.into()),
            row("2026-10-01T01:00:00Z", "c".into(), 3.into()),
            row("2026-10-01T01:00:00Z", "a".into(), 1.into()),
            row("2026-10-01T02:00:00Z", "c".into(), 2.into()),
        ];
        // Totals: null 9, a 5, c 5, b 4. Top 2: null, then a (ties by key).
        let (series, other) = split_long_form_series(rows.clone(), &f(), "count", 2, true).unwrap();
        let keys = series
            .iter()
            .map(|row| row["metadata.log_source"].clone())
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                serde_json::json!("a"),
                serde_json::Value::Null,
                serde_json::json!("a")
            ]
        );
        assert_eq!(series[0]["count"], 4, "string counts come back as numbers");
        assert_eq!(
            other,
            [
                serde_json::json!({"time_bucket": "2026-10-01T00:00:00Z", "count": 4}),
                serde_json::json!({"time_bucket": "2026-10-01T01:00:00Z", "count": 3}),
                serde_json::json!({"time_bucket": "2026-10-01T02:00:00Z", "count": 2}),
            ]
        );
        let (_, other) = split_long_form_series(rows.clone(), &f(), "count", 2, false).unwrap();
        assert!(other.is_empty());
        let (series, other) = split_long_form_series(rows, &f(), "count", 10, true).unwrap();
        assert_eq!(series.len(), 6);
        assert!(other.is_empty());

        // The pivot over the folded rows equals the pivot of the scans.
        let start = chrono::DateTime::parse_from_rfc3339("2026-10-01T00:20:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let range = TimeRange::new(start, start + chrono::Duration::hours(3));
        let agg = Aggregation::new(AggFunc::Count, None);
        let rows = vec![
            row("2026-10-01T00:00:00Z", "a".into(), 2.into()),
            row("2026-10-01T03:00:00Z", "b".into(), 1.into()),
        ];
        let (series, other) = split_long_form_series(rows, &f(), "count", 1, true).unwrap();
        let chart = pivot(
            &series,
            &other,
            &f(),
            &[agg],
            Duration::from_secs(3600),
            &range,
        )
        .unwrap();
        assert_eq!(chart.len(), 4, "both ragged edge hours and the empty ones");
        assert_eq!(
            (chart[0]["a"].clone(), chart[0]["OTHER"].clone()),
            (2.into(), 0.into())
        );
        assert_eq!(
            (chart[1]["a"].clone(), chart[1]["OTHER"].clone()),
            (0.into(), 0.into())
        );
        assert_eq!(
            (chart[3]["a"].clone(), chart[3]["OTHER"].clone()),
            (0.into(), 1.into())
        );

        assert!(split_long_form_series(
            vec![serde_json::json!({"metadata.log_source": "a", "count": 1})],
            &f(),
            "count",
            1,
            true
        )
        .is_err());
    }

    #[test]
    fn full_day_is_widened_and_pivoted_with_real_other() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-10-01T11:20:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // NAN-4276: exactly a day at 1m is 1,440 buckets and is NOT widened;
        // one minute more is.
        let day = TimeRange::new(start, start + chrono::Duration::days(1));
        assert_eq!(widened_span(Duration::from_secs(60), &day).unwrap().as_secs(), 60);
        assert_eq!(bucket_count(&day, 60), 1_440);
        let range = TimeRange::new(start, start + chrono::Duration::days(1) + chrono::Duration::minutes(1));
        assert_eq!(bucket_count(&range, 60), 1_441);
        let span = widened_span(Duration::from_secs(60), &range).unwrap();
        assert_eq!(span.as_secs(), 300);
        let rows = vec![
            serde_json::json!({"time_bucket":"2026-10-01T11:20:00Z","ip":"a","count":60}),
            serde_json::json!({"time_bucket":"2026-10-02T11:20:00Z","ip":"b","count":7}),
        ];
        let other = vec![serde_json::json!({"time_bucket":"2026-10-01T11:20:00Z","count":40})];
        let result = pivot(
            &rows,
            &other,
            &["ip".into()],
            &[Aggregation::new(AggFunc::Count, None)],
            span,
            &range,
        )
        .unwrap();
        assert_eq!(result.len(), 289);
        assert_eq!(result[0]["OTHER"], 40);
        assert_eq!(result[1]["a"], 0);
        assert_eq!(result.last().unwrap()["b"], 7);
        assert_eq!(
            result
                .iter()
                .map(|r| r["a"].as_u64().unwrap()
                    + r["b"].as_u64().unwrap()
                    + r["OTHER"].as_u64().unwrap())
                .sum::<u64>(),
            107
        );
    }
    /// NAN-4276: the window end is exclusive. `* | timechart span=5m count`
    /// over 22:00..23:00 is 12 buckets, not 13 with a synthetic 23:00 zero.
    #[test]
    fn fill_stops_before_an_exclusive_end_boundary() {
        let at = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        let count = [Aggregation::new(AggFunc::Count, None)];
        let rows = vec![
            serde_json::json!({"time_bucket":"2026-10-20 22:00:00","count":5}),
            serde_json::json!({"time_bucket":"2026-10-20 22:55:00","count":3}),
        ];
        let span = Duration::from_secs(300);
        let hour = TimeRange::new(at("2026-10-20T22:00:00Z"), at("2026-10-20T23:00:00Z"));
        let chart = pivot(&rows, &[], &[], &count, span, &hour).unwrap();
        assert_eq!(chart.len(), 12);
        assert_eq!(chart[0]["time_bucket"], "2026-10-20T22:00:00+00:00");
        assert_eq!(chart[11]["time_bucket"], "2026-10-20T22:55:00+00:00");
        assert_eq!(chart[11]["count"], 3);
        // Split charts take the same fill (61 -> 60 rows at 1m).
        let split = pivot(
            &[serde_json::json!({"time_bucket":"2026-10-20 22:00:00","src":"a","count":1})],
            &[],
            &["src".into()],
            &count,
            Duration::from_secs(60),
            &hour,
        )
        .unwrap();
        assert_eq!(split.len(), 60);
        assert_eq!(
            split.last().unwrap()["time_bucket"],
            "2026-10-20T22:59:00+00:00"
        );
        // An end inside a bucket still covers part of it.
        let ragged = TimeRange::new(
            at("2026-10-20T22:00:00Z"),
            at("2026-10-20T23:00:00Z") + chrono::Duration::milliseconds(500),
        );
        let chart = pivot(&rows, &[], &[], &count, span, &ragged).unwrap();
        assert_eq!(chart.len(), 13);
        let unaligned = TimeRange::new(at("2026-10-20T22:02:00Z"), at("2026-10-20T23:02:00Z"));
        let chart = pivot(&rows, &[], &[], &count, span, &unaligned).unwrap();
        assert_eq!(chart.len(), 13);
        assert_eq!(chart[12]["time_bucket"], "2026-10-20T23:00:00+00:00");
        // A real row in the end bucket is never dropped (the SQL time bound
        // is inclusive, so an event at exactly `end` is counted).
        let edge = vec![serde_json::json!({"time_bucket":"2026-10-20 23:00:00","count":1})];
        let chart = pivot(&edge, &[], &[], &count, span, &hour).unwrap();
        assert_eq!(chart.len(), 13);
        assert_eq!(chart[12]["count"], 1);
        // A window shorter than one span still yields its bucket.
        let tiny = TimeRange::new(at("2026-10-20T22:00:00Z"), at("2026-10-20T22:00:01Z"));
        assert_eq!(pivot(&[], &[], &[], &count, span, &tiny).unwrap().len(), 1);
    }

    #[test]
    fn generated_queries_roundtrip_and_reuse_stats_pages() {
        let parsed =
            parse_query("* | timechart useother=false limit=3 span=1m count by src_endpoint.ip")
                .unwrap();
        assert!(parsed.pretty_print().contains("useother=false"));
        let Query::Piped {
            source,
            command:
                Command::Timechart {
                    span,
                    aggregations,
                    split_by,
                    ..
                },
        } = parsed
        else {
            panic!()
        };
        let condition = selected_condition(
            &[
                serde_json::json!({"src_endpoint.ip": "a\"\\b"}),
                serde_json::json!({"src_endpoint.ip":null}),
            ],
            &split_by,
        )
        .unwrap();
        let q = bucket_query(
            filter_selected(*source, condition, false),
            span,
            &aggregations,
            &split_by,
        );
        let text = q.pretty_print();
        parse_query(&text).unwrap_or_else(|e| panic!("{text}: {e:?}"));
        let range = TimeRange::new(
            chrono::Utc::now() - chrono::Duration::hours(1),
            chrono::Utc::now(),
        );
        let sql = ClickHouseSqlGenerator::new()
            .generate(&parse_query(&text).unwrap(), &range)
            .unwrap();
        assert!(sql.contains("coalesce") || sql.contains("ifNull"), "{sql}");
        assert!(sql.contains("GROUP BY"), "{sql}");
        assert!(crate::query::stats_page::eligible(
            &parse_query("* | stats count by src_endpoint.ip | sort -count | head 10").unwrap()
        ));
    }
    #[test]
    fn incomplete_aggregates_are_never_plotted_as_complete() {
        let mut response = SearchResponse::empty();
        response.total_count = 1;
        assert!(require_complete_buckets(&response).is_err());
        response.total_count = 0;
        response.total_count_exact = false;
        assert!(require_complete_buckets(&response).is_err());
    }

    #[test]
    fn series_labels_preserve_null_and_reserved_keys_without_collisions() {
        let agg = Aggregation::new(AggFunc::Count, None);
        let keys = [
            serde_json::json!(null),
            serde_json::json!("unknown"),
            serde_json::json!("OTHER"),
            serde_json::json!("series null"),
            serde_json::json!("__proto__"),
            serde_json::json!("timestamp"),
        ];
        let labels = keys
            .iter()
            .map(|key| series_name(&serde_json::json!({"ip":key}), &["ip".into()], &agg, false))
            .collect::<BTreeSet<_>>();
        assert_eq!(labels.len(), keys.len());
        assert!(!labels.contains("OTHER"));
        assert!(!labels.contains("__proto__"));
    }

    #[test]
    fn unsplit_fetch_preserves_the_existing_timechart_rollup_shape() {
        let parsed = parse_query("* | timechart span=1h count").unwrap();
        let Query::Piped {
            source,
            command: Command::Timechart {
                span, aggregations, ..
            },
        } = parsed
        else {
            panic!()
        };
        let query = bucket_query(*source, span, &aggregations, &[]);
        assert!(matches!(
            get_semantic_terminal_command(&query),
            Some(Command::Timechart { .. })
        ));
        assert!(parse_query(&query.pretty_print()).is_ok());
    }
}
