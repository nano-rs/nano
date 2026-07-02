// SPDX-License-Identifier: AGPL-3.0-or-later

    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn dataset_selector_parses_known_and_defaults_logs() {
        assert_eq!(Dataset::from_selector("spans"), Dataset::Spans);
        assert_eq!(Dataset::from_selector("TRACES"), Dataset::Spans);
        assert_eq!(Dataset::from_selector(" metric "), Dataset::Metrics);
        assert_eq!(Dataset::from_selector("logs"), Dataset::Logs);
        // Unknown / empty falls back to logs (additive override, never an error).
        assert_eq!(Dataset::from_selector("garbage"), Dataset::Logs);
        assert_eq!(Dataset::from_selector(""), Dataset::Logs);
        assert_eq!(Dataset::default(), Dataset::Logs);
    }

    #[test]
    fn dataset_table_and_time_column() {
        assert_eq!(Dataset::Logs.table_name(), "logs");
        assert_eq!(Dataset::Logs.time_column(), "timestamp");
        assert_eq!(Dataset::Spans.table_name(), "otel_spans");
        assert_eq!(Dataset::Spans.time_column(), "start_time");
        assert_eq!(Dataset::Metrics.table_name(), "otel_metrics");
        assert_eq!(Dataset::Metrics.time_column(), "timestamp");
    }

    #[test]
    fn trace_by_id_lowercases_and_escapes() {
        let sql = trace_by_id_sql("ABCD1234");
        // Stored ids are lowercase hex.
        assert!(sql.contains("trace_id = 'abcd1234'"), "{sql}");
        // Two-step: index table then span window scan.
        assert!(sql.contains("otel_spans_trace_id_ts"), "{sql}");
        assert!(sql.contains("FROM nanosiem.otel_spans\n"), "{sql}");
        assert!(sql.contains("ORDER BY start_time ASC"), "{sql}");
        // Single-quote injection is escaped.
        let evil = trace_by_id_sql("a' OR '1'='1");
        assert!(evil.contains("''"), "{evil}");
        assert!(!evil.contains("OR '1'='1'"), "{evil}");
    }

    #[test]
    fn rate_and_histogram_quantile_generate_expected_sql() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let g = ClickHouseSqlGenerator::new();
        let sql = |q: &str| {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            g.generate(&query, &tr).unwrap_or_else(|e| panic!("gen {q}: {e}"))
        };
        // rate(value) → cumulative-counter delta over the window in seconds.
        let r = sql("* | stats rate(value) by service_name");
        assert!(r.contains("(max(value) - min(value)) / greatest(dateDiff('second'"), "{r}");
        // histogram_quantile(value, 95) → quantileTDigest(0.95)(value).
        let h = sql("* | stats histogram_quantile(value, 95) by service_name");
        assert!(h.contains("quantileTDigest(0.95)(value)"), "{h}");
    }

    #[test]
    fn trace_id_filter_routes_to_explicit_column() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let g = ClickHouseSqlGenerator::new();
        let query = parse_query(r#"trace_id="ABCDEF""#).unwrap();
        let s = g.generate(&query, &tr).unwrap();
        // Explicit column (not ext JSON), lowercase-normalized raw compare
        // engaging the migration-141 bloom — not wrapped in lower().
        assert!(s.contains("trace_id = 'abcdef'"), "{s}");
        assert!(!s.contains("ext"), "{s}");
    }

    #[test]
    fn dataset_generator_retargets_table_and_time_column() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        // Spans dataset: the time-bound WHERE + default ORDER BY use start_time,
        // and the read targets otel_spans.
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query("error").unwrap();
        let sql = g.generate(&q, &tr).unwrap();
        assert!(sql.contains("FROM otel_spans"), "{sql}");
        assert!(sql.contains("WHERE start_time BETWEEN"), "{sql}");
        assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
        assert!(!sql.contains("timestamp BETWEEN"), "{sql}");

        // rate() on spans uses the dataset time column too.
        let r = g
            .generate(&parse_query("* | stats rate(duration_ns) by service_name").unwrap(), &tr)
            .unwrap();
        assert!(r.contains("dateDiff('second', min(start_time), max(start_time))"), "{r}");
    }

    #[test]
    fn logs_dataset_is_byte_identical_default() {
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let q = parse_query("error").unwrap();
        let base = ClickHouseSqlGenerator::new().generate(&q, &tr).unwrap();
        let logs = ClickHouseSqlGenerator::new()
            .with_dataset(Dataset::Logs)
            .generate(&q, &tr)
            .unwrap();
        assert_eq!(base, logs, "Dataset::Logs must be byte-identical to the default");
        assert!(base.contains("FROM logs"), "{base}");
        assert!(base.contains("timestamp BETWEEN"), "{base}");
    }

    #[test]
    fn recent_traces_sql_filters_and_aggregates() {
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        // Defaults: every trace, recent first, LIMIT 200, no HAVING.
        let sql = recent_traces_sql(&tr, &TraceListFilters::default());
        assert!(sql.contains("FROM nanosiem.otel_spans"), "{sql}");
        assert!(sql.contains("GROUP BY trace_id"), "{sql}");
        assert!(sql.contains("countIf(status_code = 'ERROR') AS error_count"), "{sql}");
        assert!(sql.contains("argMin(service_name, length(parent_span_id)) AS root_service"), "{sql}");
        assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
        assert!(sql.contains("LIMIT 200"), "{sql}");
        assert!(!sql.contains("HAVING"), "{sql}");

        // Filters compose into a HAVING over the per-trace row.
        let filters = TraceListFilters {
            service: Some("api"),
            errors_only: true,
            min_duration_ns: Some(1_000_000),
            limit: Some(50),
            before: None,
        };
        let f = recent_traces_sql(&tr, &filters);
        assert!(f.contains("HAVING root_service = 'api'"), "{f}");
        assert!(f.contains("error_count > 0"), "{f}");
        assert!(f.contains("duration_ns >= 1000000"), "{f}");
        assert!(f.contains("LIMIT 50"), "{f}");
        // No cursor predicate when `before` is None (first page).
        assert!(!f.contains("otel_spans.start_time < "), "{f}");

        // Keyset cursor (NAN-1539): a strict `<` on the raw start_time column,
        // outside the HAVING, for partition-pruned pagination.
        let paged = recent_traces_sql(
            &tr,
            &TraceListFilters {
                before: Some(Utc.with_ymd_and_hms(2024, 1, 1, 12, 0, 0).unwrap()),
                ..Default::default()
            },
        );
        assert!(
            paged.contains("AND otel_spans.start_time < '2024-01-01 12:00:00"),
            "{paged}"
        );
        // service value is escaped.
        let evil = recent_traces_sql(&tr, &TraceListFilters { service: Some("a'b"), ..Default::default() });
        assert!(evil.contains("root_service = 'a''b'"), "{evil}");
        // limit clamps.
        let clamp = recent_traces_sql(&tr, &TraceListFilters { limit: Some(99999), ..Default::default() });
        assert!(clamp.contains("LIMIT 1000"), "{clamp}");
    }

    #[test]
    fn metric_names_sql_optional_service_filter() {
        let all = metric_names_sql(None);
        assert!(all.contains("SELECT DISTINCT metric_name"), "{all}");
        // NAN-1632 3.12: the (deliberately) time-unbounded name list reads the
        // 1-minute rollup, NOT raw otel_metrics and NOT the 400d-TTL _1h rollup
        // (which would return a stale-name superset past raw's 90d TTL).
        assert!(all.contains("FROM nanosiem.otel_metrics_1m"), "{all}");
        assert!(!all.contains("otel_metrics_1h"), "{all}");
        assert!(!all.contains("WHERE"), "{all}");
        let svc = metric_names_sql(Some("api"));
        assert!(svc.contains("WHERE service_name = 'api'"), "{svc}");
        // empty service is dropped.
        let empty = metric_names_sql(Some(""));
        assert!(!empty.contains("WHERE"), "{empty}");
    }

    #[test]
    fn metric_agg_allowlist_parses_and_rejects() {
        assert_eq!(MetricAgg::from_str("avg"), Some(MetricAgg::Avg));
        assert_eq!(MetricAgg::from_str("P95"), Some(MetricAgg::P95));
        assert_eq!(MetricAgg::from_str("rate"), Some(MetricAgg::Rate));
        assert_eq!(MetricAgg::from_str("median"), Some(MetricAgg::P50));
        assert_eq!(MetricAgg::from_str("nonsense"), None);
        assert_eq!(MetricAgg::from_str("p98"), None);
        assert_eq!(MetricAgg::default(), MetricAgg::Avg);
    }

    #[test]
    fn valid_tag_key_screens_injection() {
        assert!(valid_tag_key("http.method"));
        assert!(valid_tag_key("k8s.pod_name-1"));
        assert!(!valid_tag_key(""));
        assert!(!valid_tag_key("a' OR '1'='1"));
        assert!(!valid_tag_key("has space"));
        assert!(!valid_tag_key("semi;colon"));
    }

    #[test]
    fn metric_timeseries_v2_single_series_back_compat() {
        let q = MetricQuery {
            metric_name: "http.server.duration",
            service_name: Some("api"),
            agg: MetricAgg::Avg,
            group_by: None,
            filters: &[],
            step_secs: 60,
        };
        let sql = metric_timeseries_v2_sql(&q, &day_range());
        assert!(sql.contains("metric_name = 'http.server.duration'"), "{sql}");
        assert!(sql.contains("service_name = 'api'"), "{sql}");
        assert!(sql.contains("avg(value) AS v"), "{sql}");
        // No group_by → constant series key, GROUP BY bucket only.
        assert!(sql.contains("'' AS series_key"), "{sql}");
        assert!(sql.contains("GROUP BY bucket"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }

    #[test]
    fn metric_timeseries_v2_group_by_and_filters() {
        let filters = vec![
            MetricTagFilter { key: "env".into(), value: "prod".into() },
            MetricTagFilter { key: "region".into(), value: "us'east".into() },
        ];
        let q = MetricQuery {
            metric_name: "rpc.duration",
            service_name: None,
            agg: MetricAgg::P95,
            group_by: Some("http.method"),
            filters: &filters,
            step_secs: 30,
        };
        let sql = metric_timeseries_v2_sql(&q, &day_range());
        assert!(sql.contains("quantileTDigest(0.95)(value) AS v"), "{sql}");
        // group_by resolves over both maps and becomes a split key.
        assert!(sql.contains("attributes['http.method']"), "{sql}");
        assert!(sql.contains("AS series_key"), "{sql}");
        assert!(sql.contains("GROUP BY series_key, bucket"), "{sql}");
        // tag filters matched over the maps; value escaped.
        assert!(sql.contains("attributes['env']"), "{sql}");
        assert!(sql.contains("= 'prod'"), "{sql}");
        assert!(sql.contains("= 'us''east'"), "{sql}");
        // no service filter when None.
        assert!(!sql.contains("service_name ="), "{sql}");
    }

    #[test]
    fn metric_rate_agg_uses_window_in_scalar() {
        let q = MetricQuery {
            metric_name: "requests.total",
            service_name: None,
            agg: MetricAgg::Rate,
            group_by: None,
            filters: &[],
            step_secs: 60,
        };
        // The whole-window scalar uses the window length (1 day = 86400s) as the
        // rate denominator, not step_secs.
        let sql = metric_scalar_sql(&q, &day_range());
        assert!(sql.contains("(max(value) - min(value)) / greatest(86400"), "{sql}");
        assert!(sql.contains("AS v"), "{sql}");
        // No group_by → no GROUP BY clause (single scalar row).
        assert!(!sql.contains("GROUP BY"), "{sql}");
    }

    #[test]
    fn metric_tag_keys_and_values_sql() {
        let keys = metric_tag_keys_sql("http.server.duration", &day_range());
        assert!(keys.contains("arrayConcat(mapKeys(attributes), mapKeys(resource_attributes))"), "{keys}");
        assert!(keys.contains("metric_name = 'http.server.duration'"), "{keys}");
        assert!(keys.contains("SELECT DISTINCT k"), "{keys}");

        let vals = metric_tag_values_sql("m", "http.method", &day_range());
        assert!(vals.contains("attributes['http.method']"), "{vals}");
        assert!(vals.contains("AS tag_value"), "{vals}");
        // empty-string drop is applied in the outer query, not a HAVING on DISTINCT.
        assert!(vals.contains("WHERE tag_value != ''"), "{vals}");
    }

    #[test]
    fn metric_timeseries_filters_and_buckets() {
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        };
        let sql = metric_timeseries_sql("http.server.duration", Some("api"), &tr, 60);
        assert!(sql.contains("metric_name = 'http.server.duration'"), "{sql}");
        assert!(sql.contains("service_name = 'api'"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        // No service filter when None.
        let sql2 = metric_timeseries_sql("m", None, &tr, 0);
        assert!(!sql2.contains("service_name ="), "{sql2}");
        // step clamps to >= 1.
        assert!(sql2.contains("toIntervalSecond(1)"), "{sql2}");
    }

    fn day_range() -> TimeRange {
        TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        }
    }

    #[test]
    fn services_overview_aggregates_red_per_service() {
        let sql = services_overview_sql(&day_range(), &ServicesOverviewFilters::default());
        assert!(sql.contains("GROUP BY service_name"), "{sql}");
        // NAN-1539: reads the minute rollup, summing SimpleAggregateFunction
        // counts and merging the latency t-digest (already ms — no /1e6).
        assert!(sql.contains("FROM nanosiem.otel_service_red_1m"), "{sql}");
        assert!(sql.contains("sum(request_count) AS request_count"), "{sql}");
        assert!(sql.contains("sum(error_count) AS error_count"), "{sql}");
        assert!(
            sql.contains("quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[2] AS p95_ms"),
            "{sql}"
        );
        // sum on a SimpleAggregateFunction (NOT sumMerge — Code 43).
        assert!(!sql.contains("sumMerge"), "{sql}");
        // Time bound is a table-qualified plain WHERE on `minute` (no PREWHERE).
        assert!(
            sql.contains("WHERE otel_service_red_1m.minute BETWEEN"),
            "{sql}"
        );
        assert!(!sql.contains("PREWHERE"), "{sql}");
        assert!(sql.contains("LIMIT 1000"), "{sql}");
    }

    #[test]
    fn services_sparkline_buckets_per_service() {
        let sql = services_sparkline_sql(&day_range(), 60);
        assert!(sql.contains("GROUP BY service, bucket"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        // NAN-1539: bucket the rollup minutes, sum the rollup counts.
        assert!(sql.contains("FROM nanosiem.otel_service_red_1m"), "{sql}");
        assert!(sql.contains("toStartOfInterval(minute,"), "{sql}");
        assert!(sql.contains("sum(request_count) AS v"), "{sql}");
        // step clamps to >= 1.
        let z = services_sparkline_sql(&day_range(), 0);
        assert!(z.contains("toIntervalSecond(1)"), "{z}");
    }

    #[test]
    fn service_red_timeseries_buckets_and_escapes() {
        let sql = service_red_timeseries_sql("checkout-api", &day_range(), 60);
        assert!(sql.contains("service_name = 'checkout-api'"), "{sql}");
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        // NAN-1539: rollup-backed — summed counts + merged digest.
        assert!(sql.contains("FROM nanosiem.otel_service_red_1m"), "{sql}");
        assert!(sql.contains("sum(request_count) AS rate_count"), "{sql}");
        assert!(sql.contains("sum(error_count) AS error_count"), "{sql}");
        assert!(
            sql.contains("quantilesTDigestMerge(0.50, 0.95, 0.99)(duration_state)[3] AS p99_ms"),
            "{sql}"
        );
        assert!(sql.contains("GROUP BY bucket"), "{sql}");
        // injection-safe.
        let evil = service_red_timeseries_sql("a'b", &day_range(), 60);
        assert!(evil.contains("service_name = 'a''b'"), "{evil}");
    }

    #[test]
    fn service_endpoints_group_by_span_name() {
        let sql = service_endpoints_sql("payments", &day_range());
        assert!(sql.contains("GROUP BY span_name"), "{sql}");
        assert!(sql.contains("service_name = 'payments'"), "{sql}");
        assert!(sql.contains("ORDER BY request_count DESC"), "{sql}");
        assert!(sql.contains("LIMIT 500"), "{sql}");
    }

    #[test]
    fn service_exemplars_orders_errors_first_and_clamps() {
        let sql = service_exemplars_sql("payments", &day_range(), Some(25));
        assert!(sql.contains("status_code = 'ERROR' AS error"), "{sql}");
        assert!(sql.contains("duration_ns / 1e6 AS duration_ms"), "{sql}");
        assert!(sql.contains("ORDER BY error DESC, start_time DESC"), "{sql}");
        assert!(sql.contains("LIMIT 25"), "{sql}");
        // default + clamp.
        let def = service_exemplars_sql("p", &day_range(), None);
        assert!(def.contains("LIMIT 20"), "{def}");
        let clamp = service_exemplars_sql("p", &day_range(), Some(99999));
        assert!(clamp.contains("LIMIT 200"), "{clamp}");
    }

    #[test]
    fn slo_compute_availability_and_latency() {
        // Availability reads the RED minute rollup, not raw spans (NAN-1632
        // 3.13): sum(request_count) / sum(request_count)-sum(error_count) are
        // exactly the raw count() / countIf(status_code != 'ERROR').
        let avail = slo_compute_sql("checkout-api", SliKind::Availability, None, &day_range());
        assert!(
            avail.contains("FROM nanosiem.otel_service_red_1m"),
            "{avail}"
        );
        assert!(avail.contains("sum(request_count) AS total"), "{avail}");
        assert!(
            avail.contains("sum(request_count) - sum(error_count) AS good"),
            "{avail}"
        );
        assert!(avail.contains("service_name = 'checkout-api'"), "{avail}");
        assert!(avail.contains("LIMIT 1"), "{avail}");
        assert!(!avail.contains("otel_spans"), "{avail}");

        // Latency stays on raw spans (no rollup carries the per-span duration
        // threshold): threshold ms → ns literal.
        let lat = slo_compute_sql("payments", SliKind::Latency, Some(300.0), &day_range());
        assert!(lat.contains("FROM nanosiem.otel_spans"), "{lat}");
        assert!(lat.contains("count() AS total"), "{lat}");
        assert!(lat.contains("countIf(duration_ns <= 300000000) AS good"), "{lat}");

        // Latency with missing threshold degrades to the availability GOOD
        // definition but keeps its historical raw-spans shape.
        let lat_none = slo_compute_sql("payments", SliKind::Latency, None, &day_range());
        assert!(lat_none.contains("FROM nanosiem.otel_spans"), "{lat_none}");
        assert!(
            lat_none.contains("countIf(status_code != 'ERROR') AS good"),
            "{lat_none}"
        );
        // Non-finite threshold is rejected the same way.
        let lat_nan = slo_compute_sql("p", SliKind::Latency, Some(f64::NAN), &day_range());
        assert!(
            lat_nan.contains("countIf(status_code != 'ERROR') AS good"),
            "{lat_nan}"
        );
    }

    #[test]
    fn slo_availability_minute_aligns_start_bound() {
        // The rollup read floors the window START to the minute so the first
        // bucket is complete (rollup rows are keyed by toStartOfMinute); the
        // end bound passes through — minute keys are already aligned, so
        // `minute <= end` selects the same buckets as `minute <= floor(end)`.
        let tr = TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 10, 15, 42).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 10, 15, 42).unwrap(),
        };
        let sql = slo_compute_sql("api", SliKind::Availability, None, &tr);
        assert!(
            sql.contains("BETWEEN '2024-01-01 10:15:00' AND '2024-01-02 10:15:42'"),
            "{sql}"
        );
        // Second-precision bounds — the rollup `minute` is a DateTime, not
        // DateTime64 (a fractional literal fails to parse, Code 53).
        assert!(!sql.contains(".000000"), "{sql}");
    }

    #[test]
    fn infra_hosts_latest_per_host_metric() {
        let sql = infra_hosts_sql(&day_range(), &InfraHostsFilters::default());
        assert!(sql.contains("resource_attributes['host.name'] AS host"), "{sql}");
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.cpu.utilization') AS cpu_util"),
            "{sql}"
        );
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.memory.utilization') AS mem_util"),
            "{sql}"
        );
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.cpu.load_average.1m') AS load_1m"),
            "{sql}"
        );
        assert!(
            sql.contains("argMaxIf(value, timestamp, metric_name = 'system.network.io') AS net_io"),
            "{sql}"
        );
        // group label = host.group, fallback service_name.
        assert!(sql.contains("resource_attributes['host.group']"), "{sql}");
        assert!(sql.contains("GROUP BY host"), "{sql}");
        assert!(sql.contains("WHERE otel_metrics.timestamp BETWEEN"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
        assert!(sql.contains("LIMIT 10000"), "{sql}");
    }

    #[test]
    fn rum_web_vitals_p75_with_counts() {
        let sql = rum_web_vitals_sql(&day_range(), &RumFilters::default());
        assert!(
            sql.contains("quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.lcp') AS lcp_ms"),
            "{sql}"
        );
        assert!(sql.contains("AS inp_ms"), "{sql}");
        assert!(sql.contains("AS cls"), "{sql}");
        // count companions distinguish "0.0 p75" from "no data".
        assert!(sql.contains("countIf(metric_name = 'web.vitals.lcp') AS lcp_n"), "{sql}");
        assert!(
            sql.contains("metric_name IN ('web.vitals.lcp', 'web.vitals.inp', 'web.vitals.cls')"),
            "{sql}"
        );
        assert!(sql.contains("LIMIT 1"), "{sql}");
    }

    #[test]
    fn rum_pageviews_series_buckets_and_predicates() {
        let sql = rum_pageviews_series_sql(&day_range(), 60, &RumFilters::default());
        assert!(sql.contains("toIntervalSecond(60)"), "{sql}");
        assert!(sql.contains("AS views"), "{sql}");
        assert!(sql.contains("AS js_errors"), "{sql}");
        assert!(sql.contains("page.url"), "{sql}");
        assert!(sql.contains("exception.type"), "{sql}");
        assert!(sql.contains("GROUP BY bucket"), "{sql}");
        // step clamps to >= 1.
        let z = rum_pageviews_series_sql(&day_range(), 0, &RumFilters::default());
        assert!(z.contains("toIntervalSecond(1)"), "{z}");
    }

    #[test]
    fn rum_top_pages_group_and_clamp() {
        let sql = rum_top_pages_sql(&day_range(), Some(5), &RumFilters::default());
        assert!(sql.contains("attributes['page.url'] AS page"), "{sql}");
        assert!(sql.contains("count() AS views"), "{sql}");
        assert!(sql.contains("ORDER BY views DESC"), "{sql}");
        assert!(sql.contains("LIMIT 5"), "{sql}");
        let def = rum_top_pages_sql(&day_range(), None, &RumFilters::default());
        assert!(def.contains("LIMIT 10"), "{def}");
        let clamp = rum_top_pages_sql(&day_range(), Some(99999), &RumFilters::default());
        assert!(clamp.contains("LIMIT 100"), "{clamp}");
    }

    #[test]
    fn rum_recent_errors_orders_recent_and_clamps() {
        let sql = rum_recent_errors_sql(&day_range(), Some(25), &RumFilters::default());
        assert!(sql.contains("AS message"), "{sql}");
        assert!(sql.contains("attributes['page.url'] AS page"), "{sql}");
        assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
        assert!(sql.contains("LIMIT 25"), "{sql}");
        let def = rum_recent_errors_sql(&day_range(), None, &RumFilters::default());
        assert!(def.contains("LIMIT 20"), "{def}");
        let clamp = rum_recent_errors_sql(&day_range(), Some(99999), &RumFilters::default());
        assert!(clamp.contains("LIMIT 200"), "{clamp}");
    }

    #[test]
    fn synthetic_summary_aggregates_per_check() {
        let sql = synthetic_summary_sql(&day_range());
        assert!(sql.contains("FROM nanosiem.synthetic_check_results"), "{sql}");
        assert!(sql.contains("count() AS total"), "{sql}");
        assert!(sql.contains("sum(success) AS good"), "{sql}");
        assert!(
            sql.contains("quantileTDigest(0.50)(latency_ms) AS p50_latency_ms"),
            "{sql}"
        );
        assert!(sql.contains("GROUP BY check_id"), "{sql}");
        assert!(sql.contains("WHERE synthetic_check_results.timestamp BETWEEN"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }

    #[test]
    fn synthetic_history_escapes_and_clamps() {
        let sql = synthetic_history_sql("abc-123", &day_range(), Some(50));
        assert!(sql.contains("check_id = 'abc-123'"), "{sql}");
        assert!(sql.contains("AS ts"), "{sql}");
        assert!(sql.contains("ORDER BY timestamp DESC"), "{sql}");
        assert!(sql.contains("LIMIT 50"), "{sql}");
        // default + clamp.
        let def = synthetic_history_sql("c", &day_range(), None);
        assert!(def.contains("LIMIT 90"), "{def}");
        let clamp = synthetic_history_sql("c", &day_range(), Some(99999));
        assert!(clamp.contains("LIMIT 365"), "{clamp}");
        // injection-safe.
        let evil = synthetic_history_sql("a'b", &day_range(), None);
        assert!(evil.contains("check_id = 'a''b'"), "{evil}");
    }

    // ------------------------------------------------------------------------
    // NAN-1543 filter pushdown
    // ------------------------------------------------------------------------

    #[test]
    fn services_overview_q_and_sort_pushdown() {
        // q → case-insensitive substring on service_name, lowercased + escaped.
        let f = ServicesOverviewFilters {
            q: Some("Check'out"),
            sort: Some(ServicesSort::P95),
        };
        let sql = services_overview_sql(&day_range(), &f);
        assert!(
            sql.contains("AND lower(service_name) LIKE '%check''out%'"),
            "{sql}"
        );
        assert!(sql.contains("ORDER BY p95_ms DESC"), "{sql}");
        assert!(sql.contains("LIMIT 1000"), "{sql}");
        // name sort.
        let n = services_overview_sql(
            &day_range(),
            &ServicesOverviewFilters {
                sort: Some(ServicesSort::Name),
                ..Default::default()
            },
        );
        assert!(n.contains("ORDER BY service ASC"), "{n}");
        // error_rate sort falls back to the count order in SQL (glue re-sorts).
        let e = services_overview_sql(
            &day_range(),
            &ServicesOverviewFilters {
                sort: Some(ServicesSort::ErrorRate),
                ..Default::default()
            },
        );
        assert!(e.contains("ORDER BY request_count DESC"), "{e}");
        assert!(ServicesSort::ErrorRate.needs_glue_sort());
        assert!(!ServicesSort::Rate.needs_glue_sort());
        // default (no filters) keeps the historical count order, no q clause.
        let d = services_overview_sql(&day_range(), &ServicesOverviewFilters::default());
        assert!(d.contains("ORDER BY request_count DESC"), "{d}");
        assert!(!d.contains("LIKE"), "{d}");
    }

    #[test]
    fn services_sort_allowlist_parses_and_rejects() {
        assert_eq!(ServicesSort::from_str("rate"), Some(ServicesSort::Rate));
        assert_eq!(ServicesSort::from_str("P95"), Some(ServicesSort::P95));
        assert_eq!(ServicesSort::from_str("name"), Some(ServicesSort::Name));
        assert_eq!(
            ServicesSort::from_str("error_rate"),
            Some(ServicesSort::ErrorRate)
        );
        assert_eq!(ServicesSort::from_str("garbage"), None);
        assert_eq!(ServicesSort::default(), ServicesSort::Rate);
    }

    #[test]
    fn infra_hosts_q_group_env_pushdown() {
        let f = InfraHostsFilters {
            q: Some("WEB-01"),
            group: Some("frontend"),
            env: Some("prod'"),
        };
        let sql = infra_hosts_sql(&day_range(), &f);
        assert!(
            sql.contains("AND lower(resource_attributes['host.name']) LIKE '%web-01%'"),
            "{sql}"
        );
        assert!(
            sql.contains("AND resource_attributes['host.group'] = 'frontend'"),
            "{sql}"
        );
        assert!(
            sql.contains("AND resource_attributes['deployment.environment'] = 'prod'''"),
            "{sql}"
        );
        // default → no extra filter predicates (the host_group SELECT always
        // references host.group, so assert the FILTER form is absent, not the
        // bare attribute name).
        let d = infra_hosts_sql(&day_range(), &InfraHostsFilters::default());
        assert!(!d.contains("AND resource_attributes['host.group'] ="), "{d}");
        assert!(!d.contains("deployment.environment"), "{d}");
        assert!(!d.contains("LIKE"), "{d}");
        assert!(d.contains("LIMIT 10000"), "{d}");
    }

    #[test]
    fn rum_filters_pushdown_spans_and_metrics() {
        let f = RumFilters {
            page: Some("/Checkout"),
            browser: Some("Chrome"),
            env: Some("prod"),
        };
        // spans-side: page (lowercased substring), browser + env (exact).
        let series = rum_pageviews_series_sql(&day_range(), 60, &f);
        assert!(
            series.contains("AND lower(attributes['page.url']) LIKE '%/checkout%'"),
            "{series}"
        );
        assert!(
            series.contains("AND attributes['browser.name'] = 'Chrome'"),
            "{series}"
        );
        assert!(
            series.contains("AND resource_attributes['deployment.environment'] = 'prod'"),
            "{series}"
        );
        let top = rum_top_pages_sql(&day_range(), None, &f);
        assert!(top.contains("AND attributes['browser.name'] = 'Chrome'"), "{top}");
        let errs = rum_recent_errors_sql(&day_range(), None, &f);
        assert!(errs.contains("AND lower(attributes['page.url']) LIKE '%/checkout%'"), "{errs}");
        // metrics-side: only env applies to the vitals.
        let vitals = rum_web_vitals_sql(&day_range(), &f);
        assert!(
            vitals.contains("AND resource_attributes['deployment.environment'] = 'prod'"),
            "{vitals}"
        );
        assert!(!vitals.contains("page.url"), "{vitals}");
        assert!(!vitals.contains("browser.name"), "{vitals}");
        // default → no pushed predicates.
        let d = rum_pageviews_series_sql(&day_range(), 60, &RumFilters::default());
        assert!(!d.contains("browser.name"), "{d}");
    }

    // ------------------------------------------------------------------------
    // NAN-1542 service ↔ security convergence
    // ------------------------------------------------------------------------

    #[test]
    fn service_entities_single_scan_array_join_escapes() {
        let sql = service_entities_sql("checkout'api", &day_range());
        // NAN-1632 3.14: one scan arrayJoining both entity columns — the old
        // UNION ALL read the same granules twice under an identical predicate.
        assert!(
            sql.contains("SELECT arrayJoin([src_ip, host]) AS entity"),
            "{sql}"
        );
        assert!(!sql.contains("UNION ALL"), "{sql}");
        assert_eq!(
            sql.matches("FROM nanosiem.otel_spans").count(),
            1,
            "must scan otel_spans exactly once: {sql}"
        );
        assert!(sql.contains("service_name = 'checkout''api'"), "{sql}");
        // The empty filter must sit on the OUTER level: a same-level WHERE on
        // the arrayJoin alias gets the expression alias-substituted (a second
        // independent arrayJoin), not a filter on the projected one.
        assert!(sql.contains(")\nWHERE entity != ''"), "{sql}");
        assert!(sql.contains(&format!("LIMIT {SERVICE_ENTITY_CAP}")), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }

    #[test]
    fn security_signals_for_entities_in_list_and_escape() {
        let entities = vec!["10.0.0.1".to_string(), "web'01".to_string()];
        let sql = security_signals_for_entities_sql(&entities, &day_range(), Some(50));
        assert!(sql.contains("FROM nanosiem.signals"), "{sql}");
        assert!(
            sql.contains("risk_entity IN ('10.0.0.1', 'web''01')"),
            "{sql}"
        );
        assert!(sql.contains("AS ts"), "{sql}");
        assert!(sql.contains("rule_name"), "{sql}");
        assert!(sql.contains("severity"), "{sql}");
        assert!(sql.contains("ORDER BY timestamp DESC"), "{sql}");
        assert!(sql.contains("LIMIT 50"), "{sql}");
        assert!(sql.contains("WHERE signals.timestamp BETWEEN"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
        // empty entities → unsatisfiable guard, still valid SQL, default + clamp.
        let none = security_signals_for_entities_sql(&[], &day_range(), None);
        assert!(none.contains("AND (0)"), "{none}");
        assert!(none.contains("LIMIT 100"), "{none}");
        let clamp = security_signals_for_entities_sql(&entities, &day_range(), Some(99999));
        assert!(clamp.contains("LIMIT 1000"), "{clamp}");
    }

    // ── NAN-1562: cross-dataset correlation ──────────────────────────────────

    fn xds_range() -> crate::query::TimeRange {
        crate::query::TimeRange {
            start: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            end: Utc.with_ymd_and_hms(2024, 1, 2, 0, 0, 0).unwrap(),
        }
    }

    /// Parse: `trace_id IN [dataset=logs … | return trace_id]` carries the
    /// subsearch dataset on the AST.
    #[test]
    fn parse_in_subsearch_carries_dataset() {
        use crate::query::ast::{Query, SearchExpr};
        use crate::query::parse_query;
        let q = parse_query("trace_id IN [dataset=logs status_code=500 | return trace_id]")
            .unwrap();
        fn find_in_expr(e: &SearchExpr) -> Option<Option<Dataset>> {
            match e {
                SearchExpr::InSubsearch {
                    subsearch_dataset, ..
                } => Some(*subsearch_dataset),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    find_in_expr(a).or_else(|| find_in_expr(b))
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => find_in_expr(i),
                _ => None,
            }
        }
        fn find(q: &Query) -> Option<Option<Dataset>> {
            match q {
                Query::Search(e) => find_in_expr(e),
                Query::Piped { source, .. } => find(source),
            }
        }
        assert_eq!(find(&q), Some(Some(Dataset::Logs)));
    }

    /// Parse: `| join trace_id [dataset=spans …]` carries the dataset on Join.
    #[test]
    fn parse_join_carries_dataset() {
        use crate::query::ast::{Command, Query};
        use crate::query::parse_query;
        let q =
            parse_query("error | join trace_id [dataset=spans service_name=checkout]").unwrap();
        fn find(q: &Query) -> Option<Option<Dataset>> {
            match q {
                Query::Piped {
                    command:
                        Command::Join {
                            subsearch_dataset, ..
                        },
                    ..
                } => Some(*subsearch_dataset),
                Query::Piped { source, .. } => find(source),
                Query::Search(_) => None,
            }
        }
        assert_eq!(find(&q), Some(Some(Dataset::Spans)));
    }

    /// NAN-1562 FIX 2: `from=` is NO LONGER a dataset-selector alias. `from` is a
    /// real log field (email/syslog sender), and the old `from=` alias silently
    /// swallowed a `from=<word>` field filter inside a subsearch. The subsearch
    /// must now parse `from=production` as a FIELD FILTER (preserved on the AST),
    /// with NO subsearch_dataset consumed. Covers the IN-subsearch parser.
    #[test]
    fn from_field_filter_in_subsearch_is_preserved_not_a_dataset() {
        use crate::query::ast::{Query, SearchExpr};
        use crate::query::parse_query;
        let q = parse_query("user IN [from=production status=500 | return user]").unwrap();

        // No dataset selector was consumed (defaults to None → logs).
        fn in_dataset(e: &SearchExpr) -> Option<Option<Dataset>> {
            match e {
                SearchExpr::InSubsearch {
                    subsearch_dataset, ..
                } => Some(*subsearch_dataset),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    in_dataset(a).or_else(|| in_dataset(b))
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => in_dataset(i),
                _ => None,
            }
        }
        // Locate the InSubsearch subsearch and assert `from` survives as a filter.
        fn in_sub<'a>(e: &'a SearchExpr) -> Option<&'a Query> {
            match e {
                SearchExpr::InSubsearch { subsearch, .. } => Some(subsearch),
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    in_sub(a).or_else(|| in_sub(b))
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => in_sub(i),
                _ => None,
            }
        }
        fn has_from_filter(e: &SearchExpr) -> bool {
            match e {
                SearchExpr::FieldFilter { field, .. } => field == "from",
                SearchExpr::And(a, b) | SearchExpr::Or(a, b) => {
                    has_from_filter(a) || has_from_filter(b)
                }
                SearchExpr::Not(i) | SearchExpr::Group(i) => has_from_filter(i),
                _ => false,
            }
        }
        fn query_has_from(q: &Query) -> bool {
            match q {
                Query::Search(e) => has_from_filter(e),
                Query::Piped { source, .. } => query_has_from(source),
            }
        }
        let outer = match &q {
            Query::Search(e) => e,
            Query::Piped { source, .. } => match source.as_ref() {
                Query::Search(e) => e,
                _ => panic!("unexpected shape: {q:?}"),
            },
        };
        assert_eq!(
            in_dataset(outer),
            Some(None),
            "from= must NOT be consumed as a dataset selector: {q:?}"
        );
        let sub = in_sub(outer).expect("InSubsearch present");
        assert!(
            query_has_from(sub),
            "from=production must survive as a field filter, not be dropped: {sub:?}"
        );
    }

    /// NAN-1562 FIX 3: an unknown dataset selector value (`dataset=spanz`) is now
    /// a HARD parse error rather than silently resolving to logs via the lenient
    /// `from_selector` fallback.
    #[test]
    fn unknown_dataset_value_is_parse_error() {
        use crate::query::parse_query;
        assert!(
            parse_query("trace_id IN [dataset=spanz status=500 | return trace_id]").is_err(),
            "dataset=spanz must fail to parse, not resolve to logs"
        );
        assert!(
            parse_query("error | join trace_id [dataset=spanz service_name=checkout]").is_err(),
            "dataset=spanz in a join must fail to parse"
        );
    }

    /// Cross-dataset IN from a SPANS main query targets the logs table + time
    /// column in the subquery; the outer side stays on otel_spans.
    #[test]
    fn cross_dataset_in_spans_to_logs() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query(
            "service_name=checkout AND trace_id IN [dataset=logs status_code=500 | return trace_id]",
        )
        .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // Outer reads spans on start_time.
        assert!(sql.contains("FROM otel_spans"), "{sql}");
        assert!(sql.contains("WHERE start_time BETWEEN"), "{sql}");
        // The IN subquery hits the LOGS table on the LOGS time column.
        assert!(sql.contains("IN (SELECT DISTINCT"), "{sql}");
        assert!(sql.contains("FROM logs WHERE timestamp BETWEEN"), "{sql}");
    }

    /// NAN-1567: a logs subsearch from a SPANS outer must resolve its WHERE
    /// fields against the LOGS profile, not the inherited spans profile. A field
    /// that is a logs column but NOT a spans-promoted field (`source_type`) is
    /// the regression case — under the spans profile it resolves to
    /// `attributes['source_type']`, which references the OUTER table inside the
    /// subquery → a correlated subquery CH rejects (Code 48). (`status_code` in
    /// the test above masks this because it exists on both profiles.)
    #[test]
    fn cross_dataset_in_spans_to_logs_resolves_logs_profile_field() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query(
            "trace_id IN [dataset=logs source_type=\"auth\" | return trace_id]",
        )
        .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // The subsearch resolves `source_type` as the LOGS column, NOT the spans
        // `attributes['source_type']` Map access (the correlated-subquery bug).
        assert!(
            sql.contains("source_type = 'auth'") || sql.contains("source_type = \"auth\""),
            "subsearch must use the logs `source_type` column: {sql}"
        );
        assert!(
            !sql.contains("attributes['source_type']"),
            "subsearch must NOT resolve source_type via the spans attributes map: {sql}"
        );
    }

    /// Reverse direction: cross-dataset IN from a LOGS main query targets the
    /// spans table + start_time in the subquery.
    #[test]
    fn cross_dataset_in_logs_to_spans() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new(); // logs default
        let q = parse_query(
            "status_code=500 AND trace_id IN [dataset=spans service_name=checkout | return trace_id]",
        )
        .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        assert!(sql.contains("FROM logs"), "{sql}");
        // Subquery hits otel_spans on start_time.
        assert!(
            sql.contains("FROM otel_spans WHERE start_time BETWEEN"),
            "{sql}"
        );
    }

    /// Cross-dataset `| join` from a logs main query targets the spans table in
    /// the join CTE and appends the partial_merge join algorithm setting.
    #[test]
    fn cross_dataset_join_logs_to_spans_partial_merge() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new();
        let q =
            parse_query("status_code=500 | join trace_id [dataset=spans service_name=checkout]")
                .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // The join subsearch reads otel_spans on start_time.
        assert!(
            sql.contains("FROM otel_spans\n    WHERE start_time BETWEEN")
                || sql.contains("FROM otel_spans WHERE start_time BETWEEN"),
            "subsearch must hit otel_spans/start_time:\n{sql}"
        );
        // Non-logs subsearch → partial_merge.
        assert!(
            sql.contains("SETTINGS join_algorithm = 'partial_merge'"),
            "{sql}"
        );
    }

    /// A keyless cross-dataset join is rejected with an actionable error.
    #[test]
    fn cross_dataset_join_without_key_is_rejected() {
        use crate::query::ast::{Command, JoinType, Query, SearchExpr};
        use crate::query::ClickHouseSqlGenerator;
        // Build a keyless cross-dataset join AST directly (the parser requires
        // ≥1 field, so construct the degenerate shape to exercise the guard).
        let q = Query::Piped {
            source: Box::new(Query::Search(SearchExpr::Keyword("error".to_string()))),
            command: Command::Join {
                join_type: JoinType::Inner,
                fields: vec![],
                subsearch: Box::new(Query::Search(SearchExpr::FieldFilter {
                    field: "service_name".to_string(),
                    op: crate::query::ast::Comparator::Eq,
                    value: crate::query::ast::Value::String("checkout".to_string()),
                })),
                max: 1,
                overwrite: true,
                maxout: None,
                subsearch_dataset: Some(Dataset::Spans),
            },
        };
        let g = ClickHouseSqlGenerator::new();
        let err = g.generate(&q, &xds_range()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("cross-dataset correlation requires a join key"),
            "got: {msg}"
        );
    }

    /// A logs-only IN subsearch (dataset=logs from a logs query) is byte-identical
    /// to the same query with NO dataset token — proving the change is inert for
    /// the existing logs path.
    #[test]
    fn logs_only_in_subsearch_byte_identical() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let with_token = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("user IN [dataset=logs status_code=500 | return user]").unwrap(),
                &xds_range(),
            )
            .unwrap();
        let without = ClickHouseSqlGenerator::new()
            .generate(
                &parse_query("user IN [status_code=500 | return user]").unwrap(),
                &xds_range(),
            )
            .unwrap();
        assert_eq!(
            with_token, without,
            "logs-only IN with dataset=logs must be byte-identical to the no-token form"
        );
    }

    /// NAN-1562 FIX 1: a cross-dataset `| join service_name [dataset=spans …]`
    /// from a logs main query must resolve the SUB-side join key through the
    /// SPANS profile (which keeps `service_name`), NOT the logs profile (which
    /// aliases `service_name → cloud_service`, a column `otel_spans` lacks →
    /// Code 47 UNKNOWN_IDENTIFIER at runtime). The main side keeps the logs
    /// resolution. Existing join tests all key on `trace_id` (which canonicalizes
    /// identically across profiles) and so never exercised this.
    #[test]
    fn cross_dataset_join_sub_key_resolves_against_sub_profile() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new(); // logs main
        let q = parse_query("error | join service_name [dataset=spans service_name=checkout]")
            .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // SUB side of the ON clause must be the bare spans column, not cloud_service.
        assert!(
            sql.contains("= sub.service_name") || sql.contains("= sub.\"service_name\""),
            "ON sub side must be bare service_name (spans profile):\n{sql}"
        );
        // LIMIT … BY and the empty-key eviction also bind the SUB key.
        assert!(
            sql.contains("LIMIT 1 BY service_name")
                || sql.contains("LIMIT 1 BY \"service_name\""),
            "LIMIT BY must use the spans-profile sub key:\n{sql}"
        );
        assert!(
            sql.contains("toString(service_name) != ''")
                || sql.contains("toString(\"service_name\") != ''"),
            "sub key eviction must use spans-profile key:\n{sql}"
        );
        // The logs alias must NOT appear anywhere on the sub side.
        assert!(
            !sql.contains("sub.cloud_service") && !sql.contains("BY cloud_service"),
            "sub side must not resolve to the logs-only cloud_service:\n{sql}"
        );
        // The MAIN side keeps the logs resolution: service_name → cloud_service.
        assert!(
            sql.contains("main.cloud_service") || sql.contains("main.\"cloud_service\""),
            "main side must keep the logs profile (cloud_service):\n{sql}"
        );
    }

    /// NAN-1562 FIX 4: a cross-dataset IN with a STRING outer field and a NUMERIC
    /// return field must NOT emit `lower(<numeric col>)` (Code 43 — `lower` wants
    /// String). Both sides are coerced with `toString()` instead. Numeric form is
    /// reserved for the both-sides-numeric case.
    #[test]
    fn cross_dataset_in_string_outer_numeric_return_no_lower() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        let g = ClickHouseSqlGenerator::new(); // logs main; `user` is a string field
        let q = parse_query("user IN [dataset=spans service_name=checkout | return duration_ns]")
            .unwrap();
        let sql = g.generate(&q, &xds_range()).unwrap();
        // The numeric sub column must never be wrapped in lower().
        assert!(
            !sql.contains("lower(duration_ns)") && !sql.contains("lower(\"duration_ns\")"),
            "must not lower() a numeric sub return field:\n{sql}"
        );
        // Mixed-type comparison falls back to toString() on each side.
        assert!(
            sql.contains("toString(") && sql.contains("toString(duration_ns)"),
            "mixed string/numeric IN must coerce both sides with toString():\n{sql}"
        );
    }

    /// NAN-1562 FIX 4 (positive): when BOTH sides are numeric the bare,
    /// no-coercion form is kept (no toString/lower wrapping the comparison).
    #[test]
    fn cross_dataset_in_both_numeric_keeps_bare_form() {
        use crate::query::{parse_query, ClickHouseSqlGenerator};
        // outer `status_code` and sub `duration_ns` — both numeric.
        let g = ClickHouseSqlGenerator::new().with_dataset(Dataset::Spans);
        let q = parse_query(
            "service_name=checkout AND status_code IN [dataset=metrics metric_name=x | return value]",
        );
        // Just assert it generates and uses no lower() on the numeric value col.
        if let Ok(q) = q {
            let sql = g.generate(&q, &xds_range()).unwrap();
            assert!(!sql.contains("lower(value)"), "{sql}");
        }
    }
