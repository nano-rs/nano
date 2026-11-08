// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4982: disk-pressure eviction covers the OCSF stores.

use super::*;

#[test]
fn daily_tables_include_the_ocsf_store_and_the_legacy_store() {
    assert!(DAILY_TABLES.contains(&"logs"));
    assert!(DAILY_TABLES.contains(&"ocsf_logs"));
    assert!(DAILY_TABLES.contains(&crate::db::clickhouse_migrate::OCSF_LEGACY_TABLE));
}

#[test]
fn daily_tables_are_local_tables_never_distributed_wrappers() {
    for t in DAILY_TABLES {
        assert!(!t.ends_with("_distributed"), "{t}: wrappers hold no parts; drops run ON CLUSTER on the local table");
        assert!(!t.contains('.'), "{t}: unqualified, resolved in the admin client's database");
    }
}

#[test]
fn partition_reads_cover_every_daily_table_scoped_to_the_database() {
    for sql in [
        partition_snapshot_sql("system.parts", "nanosiem", "20261104").unwrap(),
        avg_partition_bytes_sql("system.parts", "nanosiem"),
        tables_with_partition_sql("system.parts", "nanosiem"),
    ] {
        assert!(sql.contains("database = 'nanosiem'"), "{sql}");
        assert!(sql.contains("'ocsf_logs'"), "{sql}");
        assert!(sql.contains("'ocsf_logs_legacy_v179'"), "{sql}");
        assert!(sql.contains("'logs'"), "{sql}");
        assert!(sql.contains("active = 1"), "{sql}");
        assert!(!sql.contains("PREWHERE"), "{sql}");
    }
}

#[test]
fn cluster_reads_use_the_cluster_sources() {
    let sql = tables_with_partition_sql("clusterAllReplicas('nano', system.parts)", "nanosiem");
    assert!(sql.starts_with("SELECT DISTINCT table FROM clusterAllReplicas('nano', system.parts) WHERE"), "{sql}");
    assert!(sql.ends_with("AND partition = ? ORDER BY table"), "{sql}");
}

#[test]
fn drop_statement_targets_the_local_table_on_cluster() {
    assert_eq!(
        drop_partition_sql("ocsf_logs", "", "20261001").unwrap(),
        "ALTER TABLE ocsf_logs DROP PARTITION '20261001'"
    );
    assert_eq!(
        drop_partition_sql("ocsf_logs", " ON CLUSTER 'nano'", "20261001").unwrap(),
        "ALTER TABLE ocsf_logs ON CLUSTER 'nano' DROP PARTITION '20261001'"
    );
}

#[test]
fn drop_statement_refuses_unknown_tables_and_non_date_partitions() {
    assert!(drop_partition_sql("ocsf_logs_distributed", "", "20261001").is_err());
    assert!(drop_partition_sql("users", "", "20261001").is_err());
    assert!(drop_partition_sql("ocsf_logs", "", "2026-10-01").is_err());
    assert!(drop_partition_sql("ocsf_logs", "", "20261001' OR 1").is_err());
    assert!(drop_partition_sql("ocsf_logs", "", "202610").is_err());
}

#[test]
fn audit_details_name_the_tables_actually_dropped() {
    let d = drop_audit_details("20261001", &["ocsf_logs".to_string(), "signals".to_string()]);
    assert_eq!(d["partition_date"], "20261001");
    assert_eq!(d["tables"], serde_json::json!(["ocsf_logs", "signals"]));
    assert!(d["candidate_tables"].as_array().unwrap().iter().any(|t| t == "ocsf_logs"));
}

#[test]
fn database_literal_is_escaped() {
    assert!(daily_tables_filter("a'b").starts_with("database = 'a\\'b' AND"));
}

#[test]
fn warm_ttl_never_rewrites_the_ocsf_store() {
    assert!(!WARM_TTL_TABLES.iter().any(|(t, _)| t.starts_with("ocsf_logs")));
}

fn policy(name: &str, priority: u64, disks: &[&str]) -> (String, u64, Vec<String>) {
    (name.to_string(), priority, disks.iter().map(|d| d.to_string()).collect())
}

/// The Compose config ships an unused local `tiered` policy: it must not
/// switch eviction off.
#[test]
fn an_unused_multi_volume_policy_is_not_tiering() {
    let policies = [policy("default", 1, &["default"]), policy("tiered", 1, &["default"]), policy("tiered", 2, &["warm_disk"])];
    assert!(!tiering_applies(&["default".to_string()], &policies, &[]));
}

#[test]
fn a_used_multi_volume_or_object_storage_policy_is_tiering() {
    let policies = [policy("default", 1, &["default"]), policy("default", 2, &["s3"])];
    assert!(tiering_applies(&["default".to_string()], &policies, &[]));
    let single = [policy("s3only", 1, &["s3"])];
    assert!(tiering_applies(&["s3only".to_string()], &single, &["s3".to_string()]));
    assert!(!tiering_applies(&["default".to_string()], &single, &["s3".to_string()]));
}

#[test]
fn used_policies_read_the_daily_tables() {
    let sql = used_policies_sql("clusterAllReplicas('nano', system.tables)", "nanosiem");
    assert!(sql.contains("FROM clusterAllReplicas('nano', system.tables) WHERE database = 'nanosiem'"), "{sql}");
    assert!(sql.contains("'ocsf_logs'") && sql.contains("'ocsf_logs_legacy_v179'") && sql.contains("'logs'"), "{sql}");
}

// ---------------------------------------------------------------- floor (review P1s)

const TODAY: &str = "20261104";

fn snap(oldest: Option<&str>, newest: Option<&str>) -> PartitionSnapshot {
    PartitionSnapshot { oldest_before_today: oldest.map(str::to_string), newest: newest.map(str::to_string) }
}

#[test]
fn snapshot_reads_oldest_before_today_and_newest_in_one_query() {
    let sql = partition_snapshot_sql("system.parts", "nanosiem", TODAY).unwrap();
    assert!(sql.starts_with("SELECT minIf(partition, partition < '20261104') AS oldest, max(partition) AS newest FROM system.parts WHERE"), "{sql}");
    assert!(partition_snapshot_sql("system.parts", "nanosiem", "2026-11-04").is_err());
}

#[test]
fn a_future_partition_never_makes_today_evictable() {
    // Today + one 2099 event: the old floor (protect max) would drop today.
    assert_eq!(evictable_partition(&snap(None, Some("20991231")), TODAY), None);
    // An old partition is still evictable beside a future one.
    assert_eq!(evictable_partition(&snap(Some("20261001"), Some("20991231")), TODAY).as_deref(), Some("20261001"));
}

#[test]
fn today_and_later_are_never_candidates() {
    assert_eq!(evictable_partition(&snap(Some(TODAY), Some("20991231")), TODAY), None);
    assert_eq!(evictable_partition(&snap(Some("20261105"), Some("20261105")), TODAY), None);
    assert_eq!(evictable_partition(&snap(Some("2026110"), Some(TODAY)), TODAY), None);
}

#[test]
fn the_newest_partition_is_never_a_candidate() {
    // Only an old partition is left (today has no data yet): it is the newest.
    assert_eq!(evictable_partition(&snap(Some("20261001"), Some("20261001")), TODAY), None);
    assert_eq!(evictable_partition(&snap(None, None), TODAY), None);
}

/// Fake partitions: `parts` is the live set. A partition can vanish either
/// right before the snapshot or after the snapshot but before table discovery.
struct Fake {
    parts: std::sync::Mutex<Vec<String>>,
    vanish_on_snapshot: std::sync::Mutex<Option<String>>,
    vanish_on_drop: std::sync::Mutex<Option<String>>,
    drop_attempts: std::sync::Mutex<Vec<String>>,
    reported_drops: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl PartitionDropper for Fake {
    async fn partition_snapshot(&self, today: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        let mut parts = self.parts.lock().unwrap();
        if let Some(v) = self.vanish_on_snapshot.lock().unwrap().take() {
            parts.retain(|p| *p != v);
        }
        Ok(PartitionSnapshot {
            oldest_before_today: parts.iter().filter(|p| p.as_str() < today).min().cloned(),
            newest: parts.iter().max().cloned(),
        })
    }
    async fn usage(&self) -> Result<f64, DiskPressureError> {
        Ok(0.99)
    }
    async fn drop_partition(&self, date: &str) -> Result<Vec<String>, DiskPressureError> {
        self.drop_attempts.lock().unwrap().push(date.to_string());
        self.parts.lock().unwrap().retain(|p| p != date);
        if self.vanish_on_drop.lock().unwrap().take().as_deref() == Some(date) {
            return Ok(Vec::new());
        }
        Ok(vec!["ocsf_logs".to_string()])
    }
    async fn dropped(&self, date: &str, _tables: &[String]) {
        self.reported_drops.lock().unwrap().push(date.to_string());
    }
}

fn fake(parts: &[&str], vanish_on_snapshot: Option<&str>, vanish_on_drop: Option<&str>) -> Fake {
    Fake {
        parts: std::sync::Mutex::new(parts.iter().map(|p| p.to_string()).collect()),
        vanish_on_snapshot: std::sync::Mutex::new(vanish_on_snapshot.map(str::to_string)),
        vanish_on_drop: std::sync::Mutex::new(vanish_on_drop.map(str::to_string)),
        drop_attempts: std::sync::Mutex::new(Vec::new()),
        reported_drops: std::sync::Mutex::new(Vec::new()),
    }
}

async fn run(f: &Fake) -> DropLoopOutcome {
    // A disabled fence never touches the pool.
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap();
    fifo_drop_loop(f, &crate::leader::LeaderFence::disabled(), &pool, 0.70, 10, std::time::Duration::ZERO, TODAY).await
}

#[tokio::test]
async fn the_loop_keeps_today_when_a_future_partition_exists() {
    let f = fake(&["20261001", "20261002", TODAY, "20991231"], None, None);
    assert_eq!(run(&f).await, DropLoopOutcome::Floor);
    assert_eq!(
        *f.reported_drops.lock().unwrap(),
        vec!["20261001", "20261002"]
    );
    assert_eq!(*f.parts.lock().unwrap(), vec![TODAY, "20991231"]);
}

#[tokio::test]
async fn a_partition_vanishing_before_the_snapshot_never_exposes_the_last_one() {
    // Two dates; the old one disappears (TTL) right before the read: the
    // remaining one is today's and is never dropped.
    let f = fake(&["20261001", TODAY], Some("20261001"), None);
    assert_eq!(run(&f).await, DropLoopOutcome::Floor);
    assert!(f.reported_drops.lock().unwrap().is_empty());
    // Same race when the last partition is an old date (no data today yet).
    let f = fake(&["20261001", "20261002"], Some("20261001"), None);
    assert_eq!(run(&f).await, DropLoopOutcome::Floor);
    assert!(
        f.reported_drops.lock().unwrap().is_empty(),
        "the sole remaining partition is the newest"
    );
}

#[tokio::test]
async fn a_candidate_vanishing_after_the_snapshot_is_skipped_not_reported_as_dropped() {
    let f = fake(&["20261001", "20261002", TODAY], None, Some("20261001"));
    assert_eq!(run(&f).await, DropLoopOutcome::Floor);
    assert_eq!(
        *f.drop_attempts.lock().unwrap(),
        vec!["20261001", "20261002"]
    );
    assert_eq!(
        *f.reported_drops.lock().unwrap(),
        vec!["20261002"],
        "the dropped callback is the audit/notification seam; a vanished candidate must not reach it"
    );
    assert_eq!(*f.parts.lock().unwrap(), vec![TODAY]);
}
