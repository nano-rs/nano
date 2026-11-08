// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn parser_roundtrips_useother_with_bins_and_option_order() {
    for query in [
        "* | timechart useother=false limit=3 bins=24 count by user",
        "* | timechart bins=24 count by user limit=3 useother=false",
    ] {
        let parsed = parse_query(query).unwrap_or_else(|error| panic!("{query}: {error}"));
        let printed = parsed.pretty_print();
        assert!(printed.contains("bins=24"), "{printed}");
        assert!(printed.contains("limit=3"), "{printed}");
        assert!(printed.contains("useother=false"), "{printed}");
        parse_query(&printed).unwrap_or_else(|error| panic!("{printed}: {error}"));
    }

    let default = parse_query("* | timechart span=10m count by user").unwrap();
    let Query::Piped {
        command: Command::Timechart { useother, .. },
        ..
    } = default
    else {
        panic!("expected timechart")
    };
    assert!(useother);
}

#[test]
fn series_limit_is_bounded_and_zero_is_rejected() {
    assert_eq!(series_limit(None).unwrap(), 10);
    assert_eq!(series_limit(Some(1)).unwrap(), 1);
    assert_eq!(series_limit(Some(MAX_SERIES)).unwrap(), MAX_SERIES);
    assert!(series_limit(Some(0)).is_err());
    assert!(series_limit(Some(MAX_SERIES + 1)).is_err());
}

#[test]
fn single_pass_covers_only_additive_count_splits() {
    let fields = vec!["metadata.event_code".to_string()];
    let count = Aggregation::new(AggFunc::Count, None);
    let count_field = Aggregation::new(AggFunc::Count, Some("user".into()));
    assert!(single_pass_eligible(&[count.clone()], &fields));
    assert!(single_pass_eligible(&[count_field], &fields));
    assert!(!single_pass_eligible(&[count.clone()], &[]));
    assert!(!single_pass_eligible(
        &[count.clone(), count.clone()],
        &fields
    ));
    for function in [AggFunc::Dc, AggFunc::Avg] {
        assert!(!single_pass_eligible(
            &[Aggregation::new(function, Some("bytes".into()))],
            &fields
        ));
    }

    let week = TimeRange::new(
        "2026-10-01T19:11:00Z".parse().unwrap(),
        "2026-10-08T19:11:00Z".parse().unwrap(),
    );
    assert_eq!(
        single_pass_row_cap(Duration::from_secs(3600), &week),
        100_000
    );
    let hour = TimeRange::new(week.start, week.start + chrono::Duration::minutes(59));
    assert_eq!(single_pass_row_cap(Duration::from_secs(3600), &hour), 2000);
}

#[test]
fn long_form_count_ranks_and_folds_other_per_bucket() {
    let fields = || vec!["metadata.log_source".to_string()];
    let row = |bucket: &str, source: serde_json::Value, count: serde_json::Value| {
        serde_json::json!({
            "time_bucket": bucket,
            "metadata.log_source": source,
            "count": count
        })
    };
    let rows = vec![
        row("2026-10-01T00:00:00Z", "b".into(), 4.into()),
        row("2026-10-01T00:00:00Z", "a".into(), "4".into()),
        row("2026-10-01T00:00:00Z", serde_json::Value::Null, 9.into()),
        row("2026-10-01T01:00:00Z", "c".into(), 3.into()),
        row("2026-10-01T01:00:00Z", "a".into(), 1.into()),
        row("2026-10-01T02:00:00Z", "c".into(), 2.into()),
    ];

    let (series, other) =
        split_long_form_series(rows.clone(), &fields(), "count", 2, true).unwrap();
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
    assert_eq!(series[0]["count"], 4, "string counts become numbers");
    assert_eq!(
        other,
        [
            serde_json::json!({"time_bucket": "2026-10-01T00:00:00Z", "count": 4}),
            serde_json::json!({"time_bucket": "2026-10-01T01:00:00Z", "count": 3}),
            serde_json::json!({"time_bucket": "2026-10-01T02:00:00Z", "count": 2}),
        ]
    );

    let (_, other) = split_long_form_series(rows.clone(), &fields(), "count", 2, false).unwrap();
    assert!(other.is_empty());
    let (series, other) = split_long_form_series(rows, &fields(), "count", 10, true).unwrap();
    assert_eq!(series.len(), 6);
    assert!(other.is_empty());
}

#[test]
fn pivot_with_cont_zero_fills_half_open_window_and_preserves_total() {
    let start: chrono::DateTime<chrono::Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
    let range = TimeRange::new(start, start + chrono::Duration::hours(4));
    let aggregation = Aggregation::new(AggFunc::Count, None);
    let rows = vec![
        serde_json::json!({"time_bucket":"2026-10-01T00:00:00Z","user":"a","count":5}),
        serde_json::json!({"time_bucket":"2026-10-01T01:00:00Z","user":"b","count":4}),
    ];
    let other = vec![serde_json::json!({"time_bucket":"2026-10-01T03:00:00Z","count":3})];
    let chart = pivot(
        &rows,
        &other,
        &["user".into()],
        &[aggregation],
        Duration::from_secs(3600),
        &range,
        true,
    )
    .unwrap();

    assert_eq!(chart.len(), 4, "the exclusive end is not an extra bucket");
    assert_eq!(chart[0]["a"], 5);
    assert_eq!(chart[1]["b"], 4);
    assert_eq!(chart[2]["a"], 0);
    assert_eq!(chart[2]["b"], 0);
    assert_eq!(chart[2]["OTHER"], 0);
    assert_eq!(chart[3]["OTHER"], 3);
    let total = chart
        .iter()
        .map(|row| {
            row["a"].as_u64().unwrap() + row["b"].as_u64().unwrap() + row["OTHER"].as_u64().unwrap()
        })
        .sum::<u64>();
    assert_eq!(total, 12);
}

#[test]
fn pivot_without_cont_keeps_gaps() {
    let start: chrono::DateTime<chrono::Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
    let range = TimeRange::new(start, start + chrono::Duration::hours(4));
    let rows = vec![
        serde_json::json!({"time_bucket":"2026-10-01T00:00:00Z","user":"a","count":5}),
        serde_json::json!({"time_bucket":"2026-10-01T02:00:00Z","user":"b","count":4}),
    ];
    let chart = pivot(
        &rows,
        &[],
        &["user".into()],
        &[Aggregation::new(AggFunc::Count, None)],
        Duration::from_secs(3600),
        &range,
        false,
    )
    .unwrap();

    assert_eq!(chart.len(), 2);
    assert_eq!(chart[0]["time_bucket"], "2026-10-01T00:00:00+00:00");
    assert_eq!(chart[1]["time_bucket"], "2026-10-01T02:00:00+00:00");
    assert_eq!(chart[0]["b"], 0);
    assert_eq!(chart[1]["a"], 0);
}

#[test]
fn empty_cells_follow_aggregation_semantics() {
    let start: chrono::DateTime<chrono::Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
    let range = TimeRange::new(start, start + chrono::Duration::hours(2));
    let zero_functions = [AggFunc::Count, AggFunc::Sum, AggFunc::Dc];
    for function in zero_functions {
        let aggregation = Aggregation::with_alias(function, Some("metric".into()), "metric".into());
        let rows = vec![serde_json::json!({
            "time_bucket":"2026-10-01T00:00:00Z", "user":"a", "metric":7
        })];
        let chart = pivot(
            &rows,
            &[],
            &["user".into()],
            &[aggregation],
            Duration::from_secs(3600),
            &range,
            true,
        )
        .unwrap();
        assert_eq!(chart[1]["a"], 0, "{function:?}");
    }

    let null_functions = [
        AggFunc::Avg,
        AggFunc::Min,
        AggFunc::Max,
        AggFunc::Perc95,
        AggFunc::Percentile(90),
        AggFunc::Median,
        AggFunc::Stdev,
        AggFunc::Values,
        AggFunc::List,
    ];
    for function in null_functions {
        let aggregation = Aggregation::with_alias(function, Some("metric".into()), "metric".into());
        let rows = vec![serde_json::json!({
            "time_bucket":"2026-10-01T00:00:00Z", "user":"a", "metric":7
        })];
        let other = vec![serde_json::json!({
            "time_bucket":"2026-10-01T00:00:00Z", "metric":3
        })];
        let chart = pivot(
            &rows,
            &other,
            &["user".into()],
            &[aggregation],
            Duration::from_secs(3600),
            &range,
            true,
        )
        .unwrap();
        assert!(chart[1]["a"].is_null(), "{function:?}");
        assert_eq!(chart[0]["OTHER"], 3, "real OTHER stays exact: {function:?}");
        assert!(chart[1]["OTHER"].is_null(), "missing OTHER: {function:?}");
    }
}

#[test]
fn large_high_cardinality_windows_select_the_bounded_plan() {
    let start: chrono::DateTime<chrono::Utc> = "2026-10-01T00:00:00Z".parse().unwrap();
    let range = TimeRange::new(start, start + chrono::Duration::hours(100));
    let span = Duration::from_secs(3600);
    assert!(needs_cardinality_estimate(span, &range));
    assert!(estimate_requires_bounded_plan(20_000, span, &range));
    assert!(!estimate_requires_bounded_plan(10, span, &range));

    let short = TimeRange::new(start, start + chrono::Duration::hours(4));
    assert!(!needs_cardinality_estimate(span, &short));
    assert!(multi_field_split_requires_bounded_plan(&[
        "low_card".into(),
        "high_card".into(),
    ]));
    assert!(!multi_field_split_requires_bounded_plan(&[
        "high_card".into()
    ]));
}

#[test]
fn clickhouse_probe_resource_errors_use_the_fallback() {
    for message in [
        "Code: 241. DB::Exception: Memory limit exceeded (MEMORY_LIMIT_EXCEEDED)",
        "Code: 159. DB::Exception: Timeout exceeded (TIMEOUT_EXCEEDED)",
        "Code: 160. DB::Exception: Limit for rows exceeded (TOO_MANY_ROWS)",
    ] {
        let error = crate::search::parse_clickhouse_error(message);
        assert!(probe_error_uses_fallback(&error), "{error:?}");
    }
    assert!(!probe_error_uses_fallback(&SearchError::Cancelled));
}

#[test]
fn widening_reuses_bins_ladder_and_caps_bucket_count() {
    let start: chrono::DateTime<chrono::Utc> = "2026-10-01T11:20:00Z".parse().unwrap();
    let day = TimeRange::new(start, start + chrono::Duration::days(1));
    assert_eq!(
        widened_span(Duration::from_secs(60), &day)
            .unwrap()
            .as_secs(),
        60
    );
    let too_many = TimeRange::new(
        start,
        start + chrono::Duration::days(1) + chrono::Duration::minutes(1),
    );
    let span = widened_span(Duration::from_secs(60), &too_many).unwrap();
    assert_eq!(span.as_secs(), 120);
    assert!(bucket_count(&too_many, span.as_secs() as i64) <= MAX_BUCKETS);
}

#[test]
fn series_labels_preserve_reserved_and_null_keys_without_collisions() {
    let aggregation = Aggregation::new(AggFunc::Count, None);
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
        .map(|key| {
            series_name(
                &serde_json::json!({"ip":key}),
                &["ip".into()],
                &aggregation,
                false,
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(labels.len(), keys.len());
    assert!(!labels.contains("OTHER"));
    assert!(!labels.contains("__proto__"));
}

#[test]
fn generated_selected_bucket_query_roundtrips_for_ocsf_field() {
    let parsed =
        parse_query("* | timechart useother=false limit=3 span=1m count by src_endpoint.ip")
            .unwrap();
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
        panic!("expected timechart")
    };
    let condition = selected_condition(
        &[
            serde_json::json!({"src_endpoint.ip": "a\"\\b"}),
            serde_json::json!({"src_endpoint.ip":null}),
        ],
        &split_by,
    )
    .unwrap();
    let query = bucket_query(
        filter_selected(*source, condition, false),
        span,
        &aggregations,
        &split_by,
    );
    let text = query.pretty_print();
    let parsed = parse_query(&text).unwrap_or_else(|error| panic!("{text}: {error:?}"));
    let range = TimeRange::new(
        chrono::Utc::now() - chrono::Duration::hours(1),
        chrono::Utc::now(),
    );
    let sql = ClickHouseSqlGenerator::new()
        .generate(&parsed, &range)
        .unwrap();
    assert!(sql.contains("coalesce") || sql.contains("ifNull"), "{sql}");
    assert!(sql.contains("GROUP BY"), "{sql}");
}

#[test]
fn incomplete_aggregate_is_not_plotted_as_complete() {
    let mut response = SearchResponse::empty();
    response.total_count = 1;
    assert!(require_complete_buckets(&response).is_err());
    response.results.push(serde_json::json!({"count": 1}));
    assert!(require_complete_buckets(&response).is_ok());
}
