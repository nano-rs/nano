// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complete, bounded timechart presentation for ClickHouse search results.

use super::*;
use crate::auth::ScopeSet;
use crate::query::{
    Aggregation, BinaryOperator, Comparator, EvalAssignment, EvalExpression, PrettyPrint,
    SearchExpr, SortField, Value,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const MAX_BUCKETS: i64 = 1440;
const MAX_SERIES: usize = 100;
const RANK_ALIAS: &str = "__nano_timechart_rank";
const CARDINALITY_ALIAS: &str = "__nano_timechart_cardinality";
const SINGLE_PASS_MAX_ROWS: usize = 100_000;
const SINGLE_PASS_SERIES_PER_BUCKET: usize = 1000;
const CARDINALITY_ESTIMATE_MIN_BUCKETS: i64 = 32;

fn pipe(source: Query, command: Command) -> Query {
    Query::Piped {
        source: Box::new(source),
        command,
    }
}

fn last_bucket_start(range: &TimeRange, seconds: i64) -> i64 {
    let last = (range.end - chrono::Duration::milliseconds(1)).max(range.start);
    last.timestamp().div_euclid(seconds) * seconds
}

fn bucket_count(range: &TimeRange, seconds: i64) -> i64 {
    let first = range.start.timestamp().div_euclid(seconds) * seconds;
    let last = last_bucket_start(range, seconds).max(first);
    (last - first) / seconds + 1
}

fn widened_span(span: Duration, range: &TimeRange) -> Result<Duration, SearchError> {
    let seconds = i64::try_from(span.as_secs()).unwrap_or(i64::MAX);
    if seconds == 0 {
        return Err(SearchError::SqlValidationError(
            "timechart span must be greater than 0".into(),
        ));
    }
    if bucket_count(range, seconds) <= MAX_BUCKETS {
        return Ok(span);
    }

    // Reuse the bins ladder introduced by NAN-3385 rather than maintaining a
    // second list of round spans. The requested span remains a lower bound.
    Ok(crate::query::round_span_for_bins(range, MAX_BUCKETS as u32).max(span))
}

fn series_limit(limit: Option<usize>) -> Result<usize, SearchError> {
    let limit = limit.unwrap_or(10);
    if limit == 0 || limit > MAX_SERIES {
        return Err(SearchError::SqlValidationError(format!(
            "timechart limit must be between 1 and {MAX_SERIES}"
        )));
    }
    Ok(limit)
}

/// Build exact, case-sensitive, null-safe comparisons for selected group keys.
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
            let expression = if value.is_null() {
                isnull
            } else {
                let literal = match value {
                    serde_json::Value::String(value) => Value::String(value.clone()),
                    serde_json::Value::Number(value) => {
                        Value::Number(value.as_f64().ok_or_else(|| {
                            SearchError::SqlValidationError("invalid timechart key".into())
                        })?)
                    }
                    serde_json::Value::Bool(value) => Value::Bool(*value),
                    _ => {
                        return Err(SearchError::SqlValidationError(
                            "timechart split keys must be scalar".into(),
                        ));
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
            terms.push(expression);
        }
        alternatives.push(
            terms
                .into_iter()
                .reduce(|left, right| EvalExpression::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOperator::And,
                    right: Box::new(right),
                })
                .unwrap(),
        );
    }

    Ok(alternatives
        .into_iter()
        .reduce(|left, right| EvalExpression::BinaryOp {
            left: Box::new(left),
            op: BinaryOperator::Or,
            right: Box::new(right),
        })
        .unwrap_or(EvalExpression::Literal(Value::Bool(false))))
}

fn filter_selected(source: Query, condition: EvalExpression, other: bool) -> Query {
    // A fresh temporary field cannot shadow a source or aggregation field.
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
        // Preserve the established unsplit timechart SQL and rollup routing.
        return pipe(
            pipe(
                source,
                Command::Timechart {
                    span,
                    bins: None,
                    aggregations: aggregations.to_vec(),
                    split_by: Vec::new(),
                    limit: None,
                    useother: true,
                    cont: false,
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
    aggregation: &Aggregation,
    multiple_aggregations: bool,
) -> String {
    if fields.is_empty() {
        return aggregation.output_alias();
    }
    let values = fields
        .iter()
        .map(|field| row.get(field).cloned().unwrap_or(serde_json::Value::Null))
        .collect::<Vec<_>>();
    if values.len() == 1 && !multiple_aggregations {
        if let Some(value) = values[0].as_str() {
            if ![
                "time_bucket",
                "timestamp",
                "_timechart",
                "OTHER",
                "__proto__",
                "constructor",
                "prototype",
            ]
            .contains(&value)
                && !value.starts_with("series ")
            {
                return value.to_string();
            }
            return format!("series {}", serde_json::to_string(value).unwrap());
        }
        return format!("series {}", values[0]);
    }
    if multiple_aggregations {
        format!(
            "series {}",
            serde_json::json!([aggregation.output_alias(), values])
        )
    } else {
        format!("series {}", serde_json::json!(values))
    }
}

fn empty_aggregation_value(aggregation: &Aggregation) -> serde_json::Value {
    if matches!(
        aggregation.func,
        AggFunc::Count | AggFunc::Sum | AggFunc::Dc | AggFunc::EstDc
    ) {
        serde_json::json!(0)
    } else {
        serde_json::Value::Null
    }
}

fn pivot(
    rows: &[serde_json::Value],
    other: &[serde_json::Value],
    fields: &[String],
    aggregations: &[Aggregation],
    span: Duration,
    range: &TimeRange,
    cont: bool,
) -> Result<Vec<serde_json::Value>, SearchError> {
    let seconds = span.as_secs() as i64;
    let mut buckets: BTreeMap<i64, serde_json::Map<String, serde_json::Value>> = BTreeMap::new();
    let mut columns = BTreeMap::new();
    for (input, is_other) in [(rows, false), (other, true)] {
        for row in input {
            let text = row
                .get("time_bucket")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    SearchError::SqlValidationError("timechart returned an invalid bucket".into())
                })?;
            let timestamp = chrono::DateTime::parse_from_rfc3339(text)
                .map(|date| date.timestamp())
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f")
                        .map(|date| date.and_utc().timestamp())
                })
                .map_err(|_| {
                    SearchError::SqlValidationError("timechart returned an invalid bucket".into())
                })?;
            let bucket = buckets.entry(timestamp).or_default();
            for aggregation in aggregations {
                let key = if is_other {
                    if aggregations.len() == 1 {
                        "OTHER".into()
                    } else {
                        format!("{}: OTHER", aggregation.output_alias())
                    }
                } else {
                    series_name(row, fields, aggregation, aggregations.len() > 1)
                };
                let empty = empty_aggregation_value(aggregation);
                columns.insert(key.clone(), empty.clone());
                bucket.insert(
                    key,
                    row.get(aggregation.output_alias())
                        .cloned()
                        .unwrap_or(empty),
                );
            }
        }
    }
    if fields.is_empty() {
        columns.extend(aggregations.iter().map(|aggregation| {
            (
                aggregation.output_alias(),
                empty_aggregation_value(aggregation),
            )
        }));
    }

    if cont {
        let start = range.start.timestamp().div_euclid(seconds) * seconds;
        let end = last_bucket_start(range, seconds).max(start);
        for timestamp in (start..=end).step_by(seconds as usize) {
            buckets.entry(timestamp).or_default();
        }
    }

    Ok(buckets
        .into_iter()
        .map(|(timestamp, mut row)| {
            for (column, empty) in &columns {
                row.entry(column.clone()).or_insert_with(|| empty.clone());
            }
            row.insert(
                "time_bucket".into(),
                serde_json::json!(chrono::DateTime::from_timestamp(timestamp, 0)
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

fn rank_commands(fields: &[String], limit: usize) -> [Command; 2] {
    let mut sort_fields = vec![SortField {
        field: RANK_ALIAS.into(),
        descending: true,
    }];
    sort_fields.extend(fields.iter().map(|field| SortField {
        field: field.clone(),
        descending: false,
    }));
    [
        Command::Sort {
            fields: sort_fields,
            limit: None,
        },
        Command::Head { count: limit },
    ]
}

/// Rank a complete long-form count set and fold unselected rows into OTHER.
fn split_long_form_series(
    rows: Vec<serde_json::Value>,
    fields: &[String],
    alias: &str,
    limit: usize,
    useother: bool,
) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>), SearchError> {
    let key_of = |row: &serde_json::Value| {
        let key = fields
            .iter()
            .map(|field| row.get(field).cloned().unwrap_or(serde_json::Value::Null))
            .collect::<Vec<_>>();
        (serde_json::to_string(&key).unwrap_or_default(), key)
    };
    let invalid =
        || SearchError::SqlValidationError("timechart count query returned an invalid row".into());
    let mut totals: BTreeMap<String, (Vec<serde_json::Value>, u64)> = BTreeMap::new();
    let mut keyed = Vec::with_capacity(rows.len());
    for mut row in rows {
        let count = row
            .get(alias)
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
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
    let ranked = apply_post_prevalence_commands_with_limit(
        ranking,
        &rank_commands(fields, limit),
        usize::MAX,
    )?
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

fn single_pass_eligible(aggregations: &[Aggregation], fields: &[String]) -> bool {
    !fields.is_empty()
        && matches!(aggregations, [aggregation] if aggregation.func == AggFunc::Count)
}

fn single_pass_row_cap(span: Duration, range: &TimeRange) -> usize {
    let seconds = (span.as_secs() as i64).max(1);
    (bucket_count(range, seconds).max(1) as usize)
        .saturating_mul(SINGLE_PASS_SERIES_PER_BUCKET)
        .min(SINGLE_PASS_MAX_ROWS)
}

fn cardinality_estimate_query(source: Query, field: &str) -> Query {
    pipe(
        source,
        Command::Stats {
            aggregations: vec![Aggregation::with_alias(
                AggFunc::EstDc,
                Some(field.to_string()),
                CARDINALITY_ALIAS.into(),
            )],
            group_by: None,
        },
    )
}

fn needs_cardinality_estimate(span: Duration, range: &TimeRange) -> bool {
    bucket_count(range, (span.as_secs() as i64).max(1)) >= CARDINALITY_ESTIMATE_MIN_BUCKETS
}

fn multi_field_split_requires_bounded_plan(fields: &[String]) -> bool {
    fields.len() > 1
}

fn estimate_requires_bounded_plan(cardinality: u64, span: Duration, range: &TimeRange) -> bool {
    let buckets =
        u64::try_from(bucket_count(range, (span.as_secs() as i64).max(1))).unwrap_or(u64::MAX);
    cardinality.saturating_mul(buckets)
        >= u64::try_from(single_pass_row_cap(span, range)).unwrap_or(u64::MAX)
}

fn response_cardinality(response: &SearchResponse) -> Option<u64> {
    response
        .results
        .first()
        .and_then(|row| row.get(CARDINALITY_ALIAS))
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
}

fn probe_error_uses_fallback(error: &SearchError) -> bool {
    if matches!(error, SearchError::Timeout(_)) {
        return true;
    }
    let message = error.to_string();
    [
        "Code: 241",
        "MEMORY_LIMIT_EXCEEDED",
        "memory limit",
        "Query exceeded memory limit",
        "Code: 159",
        "TIMEOUT_EXCEEDED",
        "Code: 160",
        "TOO_MANY_ROWS",
        "too many rows",
        "Query returned too many rows",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

fn require_complete_buckets(response: &SearchResponse) -> Result<(), SearchError> {
    if response.total_count > response.results.len() as u64 {
        return Err(SearchError::SqlValidationError(
            "timechart aggregation did not return the complete bucket set; narrow the range or reduce limit".into(),
        ));
    }
    Ok(())
}

impl SearchService {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn complete_timechart(
        &self,
        mut request: SearchRequest,
        source: &Query,
        span: Duration,
        aggregations: &[Aggregation],
        fields: &[String],
        limit: Option<usize>,
        useother: bool,
        cont: bool,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        let started = Instant::now();
        let skip_field_stats = request.skip_field_stats;
        let named_aggregations = aggregations
            .iter()
            .map(|aggregation| {
                let mut aggregation = aggregation.clone();
                aggregation.alias = Some(
                    aggregation
                        .alias
                        .clone()
                        .or_else(|| aggregation.field.clone())
                        .unwrap_or_else(|| aggregation.output_alias()),
                );
                aggregation
            })
            .collect::<Vec<_>>();
        let aggregations = named_aggregations.as_slice();
        if aggregations.iter().any(|aggregation| {
            matches!(
                aggregation.output_alias().as_str(),
                "time_bucket" | "timestamp" | "_timechart"
            )
        }) {
            return Err(SearchError::SqlValidationError(
                "timechart aggregation alias conflicts with a reserved time column".into(),
            ));
        }
        let limit = series_limit(limit)?;
        let range = TimeRange::new(request.time_range.start, request.time_range.end);
        let widened = widened_span(span, &range)?;
        request.offset = Some(0);
        request.skip_histogram = true;
        request.skip_field_stats = true;
        let mut warnings = Vec::new();

        // NAN-5021 (C-S7): re-enter under the CALLER's scope. `source` already
        // carries the structurally injected gate, but the re-entry queries are
        // pretty-printed, re-parsed and extended with filters built from RESULT
        // values, so the gate must be re-proven rather than trusted to survive
        // serialization. Re-gating an already-gated scan only repeats the
        // predicate; it cannot change which rows match.
        let inner_scope = scope.clone();
        // Estimating only the leading field is unsafe for tuple splits such as
        // `by low_card, high_card`. Until the query AST supports a tuple-valued
        // uniq expression, all multi-field splits start with the bounded
        // rank/selected/OTHER plan and never materialize the probe.
        let prefer_bounded_plan = if multi_field_split_requires_bounded_plan(fields) {
            true
        } else if single_pass_eligible(aggregations, fields)
            && needs_cardinality_estimate(widened, &range)
        {
            let mut estimate = request.clone();
            estimate.query = cardinality_estimate_query(source.clone(), &fields[0]).pretty_print();
            estimate.limit = Some(1);
            let response = Box::pin(self.search(estimate, &inner_scope)).await?;
            warnings.extend(response.warnings.clone().unwrap_or_default());
            response_cardinality(&response).is_some_and(|cardinality| {
                estimate_requires_bounded_plan(cardinality, widened, &range)
            })
        } else {
            false
        };
        let single_pass_rows = if single_pass_eligible(aggregations, fields) && !prefer_bounded_plan
        {
            let mut single = request.clone();
            single.query =
                bucket_query(source.clone(), widened, aggregations, fields).pretty_print();
            single.limit = Some(single_pass_row_cap(widened, &range));
            match Box::pin(self.search(single, &inner_scope)).await {
                Ok(response) if require_complete_buckets(&response).is_ok() => {
                    warnings.extend(response.warnings.unwrap_or_default());
                    Some(response.results)
                }
                Ok(response) => {
                    tracing::debug!(
                        returned = response.results.len(),
                        total = response.total_count,
                        "split timechart exceeds the single-pass cap; running bounded series scans"
                    );
                    None
                }
                Err(error) if probe_error_uses_fallback(&error) => {
                    tracing::debug!(
                        error = %error,
                        "split timechart probe exceeded a ClickHouse resource bound; running bounded series scans"
                    );
                    None
                }
                Err(error) => return Err(error),
            }
        } else {
            None
        };

        let (mut response, other) = if let Some(rows) = single_pass_rows {
            let (selected, other) = split_long_form_series(
                rows,
                fields,
                &aggregations[0].output_alias(),
                limit,
                useother,
            )?;
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
                request.query = rank_commands(fields, limit)
                    .into_iter()
                    .fold(ranking, pipe)
                    .pretty_print();
                request.limit = Some(limit);
                let ranked = Box::pin(self.search(request.clone(), &inner_scope)).await?;
                warnings.extend(ranked.warnings.unwrap_or_default());
                let condition = selected_condition(&ranked.results, fields)?;
                base = filter_selected(source.clone(), condition.clone(), false);
                if useother {
                    other_source = Some(filter_selected(source.clone(), condition, true));
                }
            }

            request.limit = Some((MAX_BUCKETS as usize) * limit.max(1) + 1);
            request.query = bucket_query(base, widened, aggregations, fields).pretty_print();
            let mut response = Box::pin(self.search(request.clone(), &inner_scope)).await?;
            require_complete_buckets(&response)?;
            warnings.extend(response.warnings.take().unwrap_or_default());
            let other = if let Some(source) = other_source {
                request.query = bucket_query(source, widened, aggregations, &[]).pretty_print();
                request.limit = Some(MAX_BUCKETS as usize + 1);
                let other = Box::pin(self.search(request.clone(), &inner_scope)).await?;
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
            cont,
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
            .and_then(serde_json::Value::as_object)
            .map(|row| {
                row.keys()
                    .filter(|key| key.as_str() != "_timechart")
                    .cloned()
                    .collect()
            });
        if widened != span {
            let seconds = widened.as_secs();
            let label = if seconds % 86400 == 0 {
                format!("{}d", seconds / 86400)
            } else if seconds % 3600 == 0 {
                format!("{}h", seconds / 3600)
            } else if seconds % 60 == 0 {
                format!("{}m", seconds / 60)
            } else {
                format!("{seconds}s")
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
#[path = "timechart_tests.rs"]
mod tests;
