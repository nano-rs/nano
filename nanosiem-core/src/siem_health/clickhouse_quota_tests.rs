// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5470: nano's ClickHouse users meeting their hourly quota.

use super::*;
use crate::siem_health::analyzer::fallback_report;
use crate::siem_health::analyzer::tests::base_zero_metrics_fixture;

fn analysis() -> AnalysisResult {
    fallback_report(&base_zero_metrics_fixture())
}

/// A usage row with only `queries` and `execution_time` set.
fn usage(user: &str, quota: &str, queries: u64, max_queries: u64, et: f64, max_et: f64) -> QuotaUsage {
    usage_with(user, quota, &[("queries", queries as f64, max_queries as f64), ("execution_time", et, max_et)])
}

/// A usage row with the given `(limit, used, max)`; every other limit 0/0.
fn usage_with(user: &str, quota: &str, set: &[(&str, f64, f64)]) -> QuotaUsage {
    QuotaUsage {
        user: user.into(),
        quota: quota.into(),
        limits: QUOTA_LIMITS
            .iter()
            .map(|(col, _)| set.iter().find(|(c, _, _)| c == col).map_or((0.0, 0.0), |(_, u, m)| (*u, *m)))
            .collect(),
    }
}

fn found(refusals: Vec<QuotaRefusal>, usage: Vec<QuotaUsage>) -> QuotaFindings {
    QuotaFindings { refusals, usage, window_minutes: 720, connected_node_only: false }
}

#[test]
fn nothing_to_report_adds_nothing() {
    let mut a = analysis();
    let before = (a.overall_score, a.recommendations.len());
    ensure_clickhouse_quota_findings(&mut a, &QuotaFindings::default());
    let quiet = found(vec![], vec![usage("nanosiem_search", "nano_search", 10, 1_000_000, 5.0, 360_000.0)]);
    ensure_clickhouse_quota_findings(&mut a, &quiet);
    assert_eq!((a.overall_score, a.recommendations.len()), before);
}

#[test]
fn a_refusal_is_high_and_caps_the_score() {
    let mut a = analysis();
    let found = found(
        vec![
            QuotaRefusal { user: "nanosiem_search".into(), refused: 7 },
            QuotaRefusal { user: "nanosiem_search".into(), refused: 3 },
        ],
        vec![usage("nanosiem_search", "nano_search", 1_000_000, 1_000_000, 1.0, 360_000.0)],
    );
    ensure_clickhouse_quota_findings(&mut a, &found);
    assert!(a.overall_score <= 79);
    let r = &a.recommendations[0];
    assert_eq!(r.title, CLICKHOUSE_QUOTA_TITLE);
    assert_eq!(r.priority, "high");
    assert!(
        r.description.contains("nanosiem_search: 10 queries refused with QUOTA_EXCEEDED in the last 12 hours"),
        "{}",
        r.description
    );
    assert!(!r.description.contains("only the connected"), "{}", r.description);
    // The refused user is not reported a second time as "near".
    assert_eq!(r.description.matches("nanosiem_search:").count(), 1, "{}", r.description);
    // Idempotent.
    ensure_clickhouse_quota_findings(&mut a, &found);
    assert_eq!(a.recommendations.iter().filter(|r| r.title == CLICKHOUSE_QUOTA_TITLE).count(), 1);
}

#[test]
fn near_a_capped_limit_is_a_medium_warning() {
    let mut a = analysis();
    let score = a.overall_score;
    let found = found(
        vec![],
        vec![
            usage("nanosiem_rawsql", "default", 10, 100_000, 30_000.0, 36_000.0),
            usage("nanosiem_search", "nano_search", 799_999, 1_000_000, 0.0, 360_000.0),
        ],
    );
    ensure_clickhouse_quota_findings(&mut a, &found);
    assert_eq!(a.overall_score, score, "a warning does not cap the score");
    let r = &a.recommendations[0];
    assert_eq!(r.priority, "medium");
    assert!(r.description.contains("nanosiem_rawsql: 83 % of its hourly execution time cap used this hour (quota default)"), "{}", r.description);
    assert!(!r.description.contains("nanosiem_search:"), "79.9 % is below the threshold: {}", r.description);
}

#[test]
fn probe_sql_reads_only_nano_users_and_fans_out_on_clusters() {
    let local = refusals_sql(None, 720);
    assert!(local.contains("event_time > now() - INTERVAL 720 MINUTE"), "{local}");
    assert!(local.contains("event_date >= toDate(now() - INTERVAL 720 MINUTE)"), "{local}");
    assert!(local.contains("FROM system.query_log"));
    assert!(local.contains("exception_code = 201"));
    assert!(local.contains("(startsWith(user, 'nanosiem') OR user = 'nano_backup')"));
    assert!(!local.contains("agentlane"));
    let clustered = usage_sql(Some("default"));
    assert!(clustered.contains("FROM clusterAllReplicas('default', system.quotas_usage)"), "{clustered}");
    assert!(clustered.contains("(startsWith(quota_key, 'nanosiem') OR quota_key = 'nano_backup')"));
}

#[test]
fn refusal_window_covers_the_run_interval() {
    assert_eq!(refusal_window_minutes(None), 12 * 60, "default: the 12 h SIEM Health interval");
    assert_eq!(refusal_window_minutes(Some(24 * 3600)), 24 * 60);
    assert_eq!(refusal_window_minutes(Some(90)), 60, "never shorter than one quota interval");
    assert_eq!(refusal_window_minutes(Some(3601)), 61, "rounded up, never a gap");
}

#[test]
fn a_rows_only_cap_near_its_limit_is_reported() {
    let mut a = analysis();
    let rawsql = usage_with("nanosiem_rawsql", "default", &[
        ("queries", 50.0, 100_000.0),
        ("read_rows", 92_000_000_000.0, 100_000_000_000.0),
        ("result_rows", 10.0, 1_000_000_000.0),
    ]);
    ensure_clickhouse_quota_findings(&mut a, &found(vec![], vec![rawsql]));
    let r = &a.recommendations[0];
    assert!(r.description.contains("nanosiem_rawsql: 92 % of its hourly read rows cap used this hour"), "{}", r.description);
    // The SQL keeps a quota capped only on rows.
    let sql = usage_sql(None);
    for col in ["read_rows", "result_rows", "errors", "read_bytes", "written_bytes", "result_bytes"] {
        assert!(sql.contains(&format!("ifNull(max_{col}, 0) > 0")), "{col}: {sql}");
    }
}

#[test]
fn uncapped_high_counts_are_no_finding() {
    let mut a = analysis();
    let before = a.recommendations.len();
    let service = usage_with("nanosiem", "nano_service", &[
        ("queries", 5_000_000.0, 0.0),
        ("read_rows", 9e12, 0.0),
        ("errors", 1e6, 0.0),
        ("execution_time", 1e6, 0.0),
    ]);
    ensure_clickhouse_quota_findings(&mut a, &found(vec![], vec![service]));
    assert_eq!(a.recommendations.len(), before);
}

#[test]
fn partial_coverage_is_said_in_the_finding() {
    let mut a = analysis();
    let mut f = found(vec![QuotaRefusal { user: "nanosiem_rawsql".into(), refused: 2 }], vec![]);
    f.connected_node_only = true;
    ensure_clickhouse_quota_findings(&mut a, &f);
    assert!(a.recommendations[0].description.contains("only the connected ClickHouse node was checked"));
}
