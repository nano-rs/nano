// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5342: shard skew math, thresholds and fixture-row collection.

use std::cell::RefCell;

use super::*;

// ---------------------------------------------------------------------------
// Fixture source
// ---------------------------------------------------------------------------

/// Fixture `system.*` rows, keyed by the probe that would read them. Records
/// every call so tests can assert how many queries ran. `deny` makes the
/// probes whose SQL contains one of its strings fail like ClickHouse does.
#[derive(Default)]
struct Fixture {
    shard_count: u32,
    part_log: Vec<BucketRow>,
    async_metric_log: Vec<BucketRow>,
    metric_log: Vec<MergeBucketRow>,
    replication_queue: Vec<QueuedMergesRow>,
    parts: Vec<HotPartitionRow>,
    deny: Vec<&'static str>,
    calls: RefCell<Vec<String>>,
}

const DENIED: &str = "Code: 497. DB::Exception: nanosiem: Not enough privileges. \
     To execute this query, it's necessary to have the grant SELECT(rows) ON system.part_log. \
     (ACCESS_DENIED)";

impl Fixture {
    fn check(&self, sql: &str) -> Result<(), String> {
        self.calls.borrow_mut().push(sql.to_string());
        if self.deny.iter().any(|d| sql.contains(d)) {
            return Err(DENIED.to_string());
        }
        Ok(())
    }
}

impl ShardSkewSource for Fixture {
    async fn shard_count(&self, cluster: &str) -> Result<u32, String> {
        self.check(&format!("clusters:{cluster}"))?;
        Ok(self.shard_count)
    }
    async fn rows(&self, sql: &str) -> Result<Vec<BucketRow>, String> {
        self.check(sql)?;
        if sql.contains("system.part_log") {
            Ok(self.part_log.clone())
        } else if sql.contains("system.asynchronous_metric_log") {
            Ok(self.async_metric_log.clone())
        } else {
            Err(format!("unexpected sql {sql}"))
        }
    }
    async fn merges(&self, sql: &str) -> Result<Vec<MergeBucketRow>, String> {
        self.check(sql)?;
        Ok(self.metric_log.clone())
    }
    async fn queued(&self, sql: &str) -> Result<Vec<QueuedMergesRow>, String> {
        self.check(sql)?;
        Ok(self.replication_queue.clone())
    }
    async fn hot(&self, sql: &str) -> Result<Vec<HotPartitionRow>, String> {
        self.check(sql)?;
        Ok(self.parts.clone())
    }
}

const NOW: i64 = 1_763_035_000; // arbitrary, mid-bucket
const DB: &str = "nanosiem";

/// `part_log` rows: `rows_per_sec` for each shard in each of the 6 buckets.
fn part_log(per_shard: &[(u32, f64)]) -> Vec<BucketRow> {
    let mut out = Vec::new();
    for (shard, rps) in per_shard {
        for ago in 0..6 {
            out.push(BucketRow {
                shard: *shard,
                ago,
                value: rps * f64::from(BUCKET_SECS),
            });
        }
    }
    out
}

fn async_parts(per_shard: &[(u32, f64)]) -> Vec<BucketRow> {
    let mut out = Vec::new();
    for (shard, parts) in per_shard {
        for ago in 0..6 {
            out.push(BucketRow {
                shard: *shard,
                ago,
                value: *parts,
            });
        }
    }
    out
}

fn merge_rows(per_shard: &[(u32, f64, f64)]) -> Vec<MergeBucketRow> {
    let mut out = Vec::new();
    for (shard, share, tasks) in per_shard {
        for ago in 0..3 {
            out.push(MergeBucketRow {
                shard: *shard,
                ago,
                saturated_share: *share,
                tasks: *tasks,
                pool: 32.0,
            });
        }
    }
    out
}

fn hot(per_shard: &[(u32, &str, u64)]) -> Vec<HotPartitionRow> {
    per_shard
        .iter()
        .map(|(shard, table, parts)| HotPartitionRow {
            shard: *shard,
            table: (*table).into(),
            partition: "20261113".into(),
            parts: *parts,
        })
        .collect()
}

fn run(fixture: &Fixture, cluster: Option<&str>) -> Option<ShardSkewMetrics> {
    futures::executor::block_on(collect_shard_skew(fixture, cluster, DB, NOW))
}

fn titles(recs: &[Recommendation]) -> Vec<&str> {
    recs.iter().map(|r| r.title.as_str()).collect()
}

fn skew(recs: &[Recommendation]) -> Option<&Recommendation> {
    recs.iter().find(|r| r.title == SHARD_SKEW_TITLE)
}

// ---------------------------------------------------------------------------
// Acceptance: balanced / skewed / single shard
// ---------------------------------------------------------------------------

#[test]
fn balanced_cluster_has_no_finding() {
    let fixture = Fixture {
        shard_count: 3,
        part_log: part_log(&[(1, 20_000.0), (2, 21_500.0), (3, 19_000.0)]),
        async_metric_log: async_parts(&[(1, 300.0), (2, 330.0), (3, 280.0)]),
        metric_log: merge_rows(&[(1, 0.2, 12.0), (2, 0.3, 14.0), (3, 0.1, 10.0)]),
        parts: hot(&[(1, "ocsf_logs", 300), (2, "ocsf_logs", 330), (3, "ocsf_logs", 280)]),
        ..Default::default()
    };
    let metrics = run(&fixture, Some("nanosiem_cluster")).expect("multi-shard collects");
    assert_eq!(fixture.calls.borrow().len(), 6, "count + five probes");
    assert!(metrics.probe_failures.is_empty());
    assert!(shard_skew_recommendations(&metrics).is_empty());
}

/// The NAN-5342 field report: shard 2 took 6.7 TiB/day against 5.1, held
/// 1,690 parts against 530 and had all 32 merge slots busy.
#[test]
fn skewed_cluster_names_the_shard_and_metric() {
    let fixture = Fixture {
        shard_count: 3,
        part_log: part_log(&[(1, 40_000.0), (2, 80_000.0), (3, 41_000.0)]),
        async_metric_log: async_parts(&[(1, 530.0), (2, 1_690.0), (3, 560.0)]),
        metric_log: merge_rows(&[(1, 0.1, 10.0), (2, 1.0, 32.0), (3, 0.2, 12.0)]),
        replication_queue: vec![QueuedMergesRow { shard: 2, queued: 140 }],
        parts: hot(&[(1, "ocsf_logs", 530), (2, "ocsf_logs", 1_690), (3, "ocsf_logs", 560)]),
        ..Default::default()
    };
    let metrics = run(&fixture, Some("nanosiem_cluster")).unwrap();
    let recs = shard_skew_recommendations(&metrics);
    assert_eq!(titles(&recs), vec![SHARD_SKEW_TITLE]);
    let rec = &recs[0];
    assert_eq!(rec.priority, "medium");
    let d = &rec.description;
    assert!(d.contains("Shard 2: writes 80000 rows/s against a cluster median of 41000 (+95%)"), "{d}");
    assert!(
        d.contains("Shard 2: ocsf_logs partition 20261113 holds 1690 active parts against a cluster median of 560 (+202%)"),
        "{d}"
    );
    assert!(d.contains("Shard 2: merge pool saturated for the last 15 minutes (32.0 of 32.0 slots busy on average, 140 merges queued)"), "{d}");
    assert!(d.contains("sizing guide"), "{d}");
    assert!(!d.contains("Shard 1"), "{d}");
    assert!(!d.contains("Shard 3"), "{d}");
}

#[test]
fn single_node_runs_no_queries() {
    let fixture = Fixture::default();
    assert!(run(&fixture, None).is_none());
    assert!(fixture.calls.borrow().is_empty());
}

#[test]
fn single_shard_cluster_stops_after_the_shard_count() {
    // 1 shard x 2 replicas: clustered, but nothing to compare.
    let fixture = Fixture {
        shard_count: 1,
        ..Default::default()
    };
    assert!(run(&fixture, Some("nanosiem_cluster")).is_none());
    assert_eq!(*fixture.calls.borrow(), vec!["clusters:nanosiem_cluster".to_string()]);
}

// ---------------------------------------------------------------------------
// Review fix 1: a probe that cannot run raises a notice, never silence
// ---------------------------------------------------------------------------

#[test]
fn access_denied_raises_a_notice_instead_of_staying_silent() {
    let fixture = Fixture {
        shard_count: 2,
        metric_log: merge_rows(&[(1, 0.0, 1.0), (2, 0.0, 1.0)]),
        deny: vec!["system.part_log", "system.asynchronous_metric_log"],
        ..Default::default()
    };
    let metrics = run(&fixture, Some("c")).unwrap();
    let probes: Vec<_> = metrics.probe_failures.iter().map(|f| f.probe.as_str()).collect();
    assert_eq!(probes, vec!["system.part_log", "system.asynchronous_metric_log"]);
    let recs = shard_skew_recommendations(&metrics);
    assert_eq!(titles(&recs), vec![SHARD_SKEW_UNAVAILABLE_TITLE]);
    assert_eq!(recs[0].priority, "low");
    let d = &recs[0].description;
    assert!(d.contains("system.part_log, system.asynchronous_metric_log"), "{d}");
    assert!(d.contains("ACCESS_DENIED"), "{d}");
    assert!(d.contains("nanosiem-users.xml"), "{d}");
}

#[test]
fn shard_count_failure_raises_the_notice() {
    let fixture = Fixture {
        deny: vec!["clusters:"],
        ..Default::default()
    };
    let metrics = run(&fixture, Some("c")).expect("failure is reported");
    assert_eq!(fixture.calls.borrow().len(), 1, "no fan-out after the count failed");
    assert_eq!(
        titles(&shard_skew_recommendations(&metrics)),
        vec![SHARD_SKEW_UNAVAILABLE_TITLE]
    );
}

#[test]
fn notice_and_finding_can_coexist() {
    // replication_queue denied, but the merge pool evidence still fires.
    let fixture = Fixture {
        shard_count: 2,
        metric_log: merge_rows(&[(1, 1.0, 32.0), (2, 0.0, 1.0)]),
        deny: vec!["system.replication_queue"],
        ..Default::default()
    };
    let metrics = run(&fixture, Some("c")).unwrap();
    assert_eq!(
        titles(&shard_skew_recommendations(&metrics)),
        vec![SHARD_SKEW_UNAVAILABLE_TITLE, SHARD_SKEW_TITLE]
    );
}

// ---------------------------------------------------------------------------
// Review fix 2: partial history is unknown, not zero ingestion
// ---------------------------------------------------------------------------

#[test]
fn restarted_shard_with_one_bucket_is_not_read_as_silent() {
    // Shard 3 restarted 4 minutes ago: part_log has only the newest bucket.
    let mut rows = part_log(&[(1, 5_000.0), (2, 5_100.0)]);
    rows.push(BucketRow {
        shard: 3,
        ago: 0,
        value: 5_050.0 * 300.0,
    });
    let metrics = assemble(3, Some(rows), None, None, None, None, Vec::new());
    assert_eq!(metrics.rows_per_sec[&3][0], Some(5_050.0));
    assert_eq!(metrics.rows_per_sec[&3][1..], [None; 5]);
    assert!(shard_skew_recommendations(&metrics).is_empty());
}

#[test]
fn part_log_probe_skipping_one_shard_is_not_read_as_silent() {
    // skip_unavailable_shards dropped shard 3 from the part_log read only;
    // the other probes reached it. It must not read as 0 rows/s.
    let fixture = Fixture {
        shard_count: 3,
        part_log: part_log(&[(1, 5_000.0), (2, 5_100.0)]),
        async_metric_log: async_parts(&[(1, 100.0), (2, 100.0), (3, 100.0)]),
        metric_log: merge_rows(&[(1, 0.0, 1.0), (2, 0.0, 1.0), (3, 0.0, 1.0)]),
        ..Default::default()
    };
    let metrics = run(&fixture, Some("c")).unwrap();
    assert!(!metrics.rows_per_sec.contains_key(&3));
    assert!(shard_skew_recommendations(&metrics).is_empty());
}

#[test]
fn shard_that_answered_but_wrote_nothing_reads_zero() {
    // Shard 3 returned rows for every bucket (system-log flush parts prove
    // it was up) but none of them were hot-table inserts: value 0.
    let metrics = assemble(
        3,
        Some(part_log(&[(1, 5_000.0), (2, 5_100.0), (3, 0.0)])),
        None,
        None,
        None,
        None,
        Vec::new(),
    );
    let rec = skew(&shard_skew_recommendations(&metrics)).cloned().expect("finding");
    assert!(rec.description.contains("Shard 3: writes 0.0 rows/s"), "{}", rec.description);
}

// ---------------------------------------------------------------------------
// Review fix 3: parts skew is hot-table skew, not node-wide
// ---------------------------------------------------------------------------

#[test]
fn unrelated_table_outlier_does_not_fire() {
    // Node-wide MaxPartCountForPartition is skewed on shard 2 for 30 minutes
    // (some other table), but the hot tables are balanced.
    let metrics = assemble(
        3,
        None,
        Some(async_parts(&[(1, 100.0), (2, 2_000.0), (3, 110.0)])),
        None,
        None,
        Some(hot(&[(1, "ocsf_logs", 100), (2, "ocsf_logs", 105), (3, "ocsf_logs", 98)])),
        Vec::new(),
    );
    assert!(hot_parts_deviations(&metrics).is_empty());
    assert!(shard_skew_recommendations(&metrics).is_empty());
}

#[test]
fn hot_table_snapshot_alone_is_not_sustained() {
    // Hot table skewed now, but the node history was balanced: a burst.
    let metrics = assemble(
        3,
        None,
        Some(async_parts(&[(1, 100.0), (2, 105.0), (3, 98.0)])),
        None,
        None,
        Some(hot(&[(1, "logs", 100), (2, "logs", 900), (3, "logs", 98)])),
        Vec::new(),
    );
    assert!(shard_skew_recommendations(&metrics).is_empty());
}

#[test]
fn hot_and_history_must_agree_on_the_side() {
    // Shard 2 high on the hot table now, but low node-wide: no finding.
    let metrics = assemble(
        3,
        None,
        Some(async_parts(&[(1, 300.0), (2, 50.0), (3, 310.0)])),
        None,
        None,
        Some(hot(&[(1, "logs", 100), (2, "logs", 900), (3, "logs", 98)])),
        Vec::new(),
    );
    assert!(hot_parts_deviations(&metrics).is_empty());
}

// ---------------------------------------------------------------------------
// Skew math
// ---------------------------------------------------------------------------

fn series(rows: &[(u32, &[Option<f64>])]) -> BTreeMap<u32, Vec<Option<f64>>> {
    rows.iter().map(|(s, v)| (*s, v.to_vec())).collect()
}

#[test]
fn median_odd_and_even() {
    assert_eq!(median(&[3.0, 1.0, 2.0]), Some(2.0));
    assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), Some(2.5));
    assert_eq!(median(&[]), None);
}

#[test]
fn deviation_must_exceed_25_percent() {
    // median 100; 125 is exactly 25% (not more), 126 is over.
    let at = series(&[(1, &[Some(100.0)]), (2, &[Some(100.0)]), (3, &[Some(125.0)])]);
    assert!(sustained_deviations(&at, 1, 0.0, SkewMetric::RowsPerSec).is_empty());
    let over = series(&[(1, &[Some(100.0)]), (2, &[Some(100.0)]), (3, &[Some(126.0)])]);
    let d = sustained_deviations(&over, 1, 0.0, SkewMetric::RowsPerSec);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].shard, 3);
    assert!((d[0].deviation - 0.26).abs() < 1e-9);
}

#[test]
fn a_shard_below_the_median_is_named_too() {
    let s = series(&[(1, &[Some(100.0)]), (2, &[Some(100.0)]), (3, &[Some(50.0)])]);
    let d = sustained_deviations(&s, 1, 0.0, SkewMetric::RowsPerSec);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].shard, 3);
    assert!(d[0].deviation < 0.0);
}

#[test]
fn one_calm_bucket_breaks_the_30_minute_window() {
    let hot = [Some(200.0); 6];
    let mut flapping = [Some(200.0); 6];
    flapping[3] = Some(100.0);
    let even = [Some(100.0); 6];
    let s = series(&[(1, &even), (2, &even), (3, &flapping)]);
    assert!(sustained_deviations(&s, 6, 0.0, SkewMetric::RowsPerSec).is_empty());
    let s = series(&[(1, &even), (2, &even), (3, &hot)]);
    assert_eq!(sustained_deviations(&s, 6, 0.0, SkewMetric::RowsPerSec).len(), 1);
}

#[test]
fn switching_sides_is_not_sustained() {
    let even = [Some(100.0); 6];
    let mut swing = [Some(200.0); 6];
    swing[2] = Some(10.0);
    let s = series(&[(1, &even), (2, &even), (3, &swing)]);
    assert!(sustained_deviations(&s, 6, 0.0, SkewMetric::RowsPerSec).is_empty());
}

#[test]
fn quiet_clusters_are_below_the_floor() {
    let s = series(&[(1, &[Some(10.0)]), (2, &[Some(10.0)]), (3, &[Some(30.0)])]);
    assert!(sustained_deviations(&s, 1, MIN_MEDIAN_ROWS_PER_SEC, SkewMetric::RowsPerSec).is_empty());
}

#[test]
fn missing_history_never_fires() {
    let full = [Some(100.0); 6];
    let mut gap = [Some(400.0); 6];
    gap[5] = None;
    let s = series(&[(1, &full), (2, &full), (3, &gap)]);
    assert!(sustained_deviations(&s, 6, 0.0, SkewMetric::ActiveParts).is_empty());
}

#[test]
fn two_shards_name_both_sides() {
    // With two shards the median is their mean; 1,690 vs 530 parts.
    let s = series(&[(1, &[Some(530.0)]), (2, &[Some(1_690.0)])]);
    let d = sustained_deviations(&s, 1, MIN_MEDIAN_PARTS, SkewMetric::ActiveParts);
    assert_eq!(d.iter().map(|d| d.shard).collect::<Vec<_>>(), vec![1, 2]);
}

#[test]
fn merge_pool_must_stay_saturated_for_15_minutes() {
    let mut rows = merge_rows(&[(1, 1.0, 32.0), (2, 0.1, 5.0)]);
    let m = |rows: Vec<MergeBucketRow>| assemble(2, None, None, Some(rows), None, None, Vec::new());
    assert_eq!(saturated_merge_pools(&m(rows.clone()).merges, 3).len(), 1);
    // One bucket at 80% saturation breaks the window.
    rows.iter_mut()
        .find(|r| r.shard == 1 && r.ago == 1)
        .unwrap()
        .saturated_share = 0.8;
    assert!(saturated_merge_pools(&m(rows).merges, 3).is_empty());
    // A missing bucket (metric_log gap) also breaks it.
    let gap: Vec<_> = merge_rows(&[(1, 1.0, 32.0)])
        .into_iter()
        .filter(|r| r.ago != 2)
        .collect();
    assert!(saturated_merge_pools(&m(gap).merges, 3).is_empty());
}

#[test]
fn ensure_adds_the_finding_once_on_every_path() {
    use crate::siem_health::analyzer::{ensure_shard_skew_findings, fallback_report};
    let mut collected = crate::siem_health::analyzer::tests::base_zero_metrics_fixture();
    collected.shard_skew = Some(assemble(
        2,
        None,
        None,
        Some(merge_rows(&[(1, 1.0, 32.0), (2, 0.0, 2.0)])),
        None,
        None,
        Vec::new(),
    ));
    let mut analysis = fallback_report(&collected);
    ensure_shard_skew_findings(&mut analysis, &collected);
    ensure_shard_skew_findings(&mut analysis, &collected);
    let found: Vec<_> = analysis
        .recommendations
        .iter()
        .filter(|r| r.title == SHARD_SKEW_TITLE)
        .collect();
    assert_eq!(found.len(), 1);
    assert!(found[0].description.contains("Shard 1: merge pool saturated"));
    // No skew data (single shard, or a report from before NAN-5342): nothing.
    collected.shard_skew = None;
    let mut analysis = fallback_report(&collected);
    ensure_shard_skew_findings(&mut analysis, &collected);
    assert!(!analysis.recommendations.iter().any(|r| r.title == SHARD_SKEW_TITLE));
}

#[test]
fn metrics_round_trip_through_report_json() {
    let metrics = assemble(
        2,
        Some(part_log(&[(1, 100.0), (2, 100.0)])),
        Some(async_parts(&[(1, 10.0), (2, 10.0)])),
        Some(merge_rows(&[(1, 0.0, 1.0), (2, 0.0, 1.0)])),
        Some(vec![QueuedMergesRow { shard: 1, queued: 3 }]),
        Some(hot(&[(1, "logs", 4)])),
        vec![ProbeFailure {
            probe: "system.parts".into(),
            error: "x".into(),
        }],
    );
    let json = serde_json::to_value(&metrics).unwrap();
    let back: ShardSkewMetrics = serde_json::from_value(json).unwrap();
    assert_eq!(back, metrics);
    // Reports stored by the first NAN-5342 build (no probe_failures) load.
    let old: ShardSkewMetrics =
        serde_json::from_value(serde_json::json!({"shard_count": 2})).unwrap();
    assert!(old.probe_failures.is_empty());
}

// ---------------------------------------------------------------------------
// SQL shape
// ---------------------------------------------------------------------------

#[test]
fn sql_reads_system_tables_only_through_cluster() {
    let anchor = bucket_anchor(NOW);
    assert_eq!(anchor % 300, 0);
    assert!(anchor <= NOW && NOW - anchor < 300);
    for sql in [
        rows_sql("c", DB, anchor),
        parts_sql("c", anchor),
        merges_sql("c", anchor),
        queued_merges_sql("c", DB),
        hot_partitions_sql("c", DB),
    ] {
        assert!(sql.contains("FROM cluster('c', system."), "{sql}");
        assert!(sql.contains("shardNum()"), "{sql}");
        assert!(!sql.contains("FROM nanosiem."), "{sql}");
    }
    let rows = rows_sql("c", DB, anchor);
    assert!(rows.contains(&format!("event_time >= toDateTime({})", anchor - 1800)), "{rows}");
    assert!(rows.contains(&format!("event_time < toDateTime({anchor})")), "{rows}");
    assert!(rows.contains(&format!("intDiv({} - ", anchor - 1)), "{rows}");
    // Liveness: the WHERE covers every part_log row; the hot filter is inside sumIf.
    assert!(rows.contains("sumIf(rows, database = 'nanosiem'"), "{rows}");
    let merges = merges_sql("c", anchor);
    assert!(merges.contains(&format!("event_time >= toDateTime({})", anchor - 900)), "{merges}");
}

#[test]
fn configured_database_reaches_every_database_filter() {
    let rows = rows_sql("c", "tenant_db", 0);
    let queued = queued_merges_sql("c", "tenant_db");
    let hot = hot_partitions_sql("c", "tenant_db");
    for sql in [&rows, &queued, &hot] {
        assert!(sql.contains("database = 'tenant_db'"), "{sql}");
        assert!(!sql.contains("'nanosiem'"), "{sql}");
    }
    assert!(queued_merges_sql("c", "o'b").contains("database = 'o''b'"));
    let fixture = Fixture {
        shard_count: 2,
        ..Default::default()
    };
    futures::executor::block_on(collect_shard_skew(&fixture, Some("c"), "tenant_db", NOW));
    let calls = fixture.calls.borrow();
    assert!(calls.iter().skip(1).filter(|c| c.contains("database")).all(|c| c.contains("'tenant_db'")));
    assert_eq!(calls.iter().filter(|c| c.contains("'tenant_db'")).count(), 3);
}

#[test]
fn cluster_name_is_escaped() {
    assert!(rows_sql("o'b", DB, 0).contains("cluster('o''b', system.part_log)"));
}

