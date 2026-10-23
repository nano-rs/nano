//! Execute generated metrics-v2 SQL against chDB, without a database container.
use nanosiem_core::query::{
    metric_scalar_sql, metric_timeseries_v2_sql, MetricAgg, MetricQuery, TimeRange,
};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
#[ignore = "requires python3 with chdb; run on the integration train"]
fn canonical_counter_series_runtime_golden() {
    let range = TimeRange {
        start: "2026-10-17T00:00:00Z".parse().unwrap(),
        end: "2026-10-17T01:00:00Z".parse().unwrap(),
    };
    let mut cases = Vec::new();
    for (name, replicas, expected) in [
        ("idle", 2, 0.0),
        ("active", 2, 3.0),
        ("single", 1, 1.0),
        ("reordered", 1, 1.0),
    ] {
        let mut selects = Vec::new();
        for tick in 0..3 {
            for replica in 0..replicas {
                let value = if name == "idle" {
                    100 * replica + 10
                } else {
                    tick * 60 * (replica + 1)
                };
                let tags = if name == "reordered" && tick == 1 {
                    "map('zone','a','device','0')"
                } else {
                    "map('device','0','zone','a')"
                };
                selects.push(format!("SELECT 'axum_http_requests_total' AS metric_name, 'api' AS service_name, toDateTime('2026-10-17 00:00:00') + toIntervalSecond({}) AS timestamp, toFloat64({value}) AS value, toUInt8(2) AS aggregation_temporality, {tags} AS attributes, map('deployment.environment','prod','service.instance.id','{replica}') AS resource_attributes", tick * 60));
            }
        }
        let table = format!("({})", selects.join(" UNION ALL "));
        for group_by in [None, Some("deployment.environment")] {
            let query = MetricQuery {
                metric_name: "axum_http_requests_total",
                service_name: Some("api"),
                agg: MetricAgg::Rate,
                group_by,
                filters: &[],
                step_secs: 3600,
            };
            for sql in [
                metric_scalar_sql(&query, &range, false),
                metric_timeseries_v2_sql(&query, &range, false),
            ] {
                cases.push(serde_json::json!({"name":name,"sql":sql.replace("FROM otel_metrics", &format!("FROM {table}")),"expected":expected}));
            }
        }
    }
    let script = r#"
import json,sys,chdb
for case in json.load(sys.stdin):
    rows=[json.loads(line) for line in str(chdb.query(case['sql'] + ' SETTINGS max_threads=6, max_memory_usage=1000000000', 'JSONEachRow')).splitlines()]
    assert len(rows)==1, (case['name'],rows)
    assert abs(rows[0]['v']-case['expected'])<1e-9, (case['name'], rows)
print('16 canonical counter-series SQL goldens passed')
"#;
    let mut child = Command::new("python3")
        .args(["-c", script])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&cases).unwrap().as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}
