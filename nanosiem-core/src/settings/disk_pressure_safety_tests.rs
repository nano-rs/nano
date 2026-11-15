// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5447: retention floor, ClickHouse attribution and audit protection of
//! the disk-pressure evictor.

use super::*;

const TODAY: &str = "20261114";

// ---------------------------------------------------------------- floor

#[test]
fn cutoff_is_today_minus_the_floor() {
    assert_eq!(retention_cutoff(TODAY, 7).as_deref(), Some("20261107"));
    assert_eq!(retention_cutoff(TODAY, 0).as_deref(), Some(TODAY));
    assert_eq!(retention_cutoff("20260103", 7).as_deref(), Some("20251227"));
    assert_eq!(retention_cutoff("20240301", 1).as_deref(), Some("20240229"));
}

#[test]
fn cutoff_clamps_the_floor_and_rejects_bad_dates() {
    assert_eq!(retention_cutoff(TODAY, u64::MAX), retention_cutoff(TODAY, MAX_MIN_RETENTION_DAYS));
    assert_eq!(retention_cutoff("2026-11-14", 7), None);
    assert_eq!(retention_cutoff("20261341", 7), None);
}

#[test]
fn default_floor_is_seven_days() {
    assert_eq!(DEFAULT_MIN_RETENTION_DAYS, 7);
}

/// The default floor is min(7, what the install holds): an install sized
/// for fewer days keeps evicting its oldest day instead of pausing; an
/// explicit floor is always honored.
#[test]
fn the_default_floor_never_exceeds_what_the_install_holds() {
    // Holds 30 days: the default 7 applies.
    assert_eq!(effective_floor_days(7, false, Some(30)), 7);
    assert_eq!(effective_floor_days(7, false, Some(8)), 7);
    // Holds 4 days (oldest partition is 4 days old): keep 3, the oldest
    // day stays evictable.
    assert_eq!(effective_floor_days(7, false, Some(4)), 3);
    let cutoff = retention_cutoff(TODAY, effective_floor_days(7, false, Some(4))).unwrap();
    assert_eq!(
        evictable_partition(&snap(Some("20261110"), Some(TODAY)), TODAY, &cutoff).as_deref(),
        Some("20261110")
    );
    // Never below one day (today and yesterday stay).
    assert_eq!(effective_floor_days(7, false, Some(1)), 1);
    assert_eq!(effective_floor_days(7, false, Some(0)), 1);
    // Unknown holdings: the configured floor.
    assert_eq!(effective_floor_days(7, false, None), 7);
    // Explicit: as configured, even above what is held.
    assert_eq!(effective_floor_days(7, true, Some(4)), 7);
    assert_eq!(effective_floor_days(0, true, Some(4)), 0);
    assert_eq!(effective_floor_days(u64::MAX, true, None), MAX_MIN_RETENTION_DAYS);
}

#[test]
fn partition_age_is_whole_days() {
    assert_eq!(partition_age_days("20261110", TODAY), Some(4));
    assert_eq!(partition_age_days(TODAY, TODAY), Some(0));
    assert_eq!(partition_age_days("20991231", TODAY), None, "a future partition has no age");
    assert_eq!(partition_age_days("bad", TODAY), None);
}

#[test]
fn oldest_partition_sql_ignores_future_partitions() {
    let sql = oldest_partition_sql("system.parts", "nanosiem", TODAY).unwrap();
    assert!(sql.starts_with("SELECT minIf(partition, partition <= '20261114') FROM system.parts WHERE"), "{sql}");
    assert!(oldest_partition_sql("system.parts", "nanosiem", "2026' OR 1").is_err());
}

fn snap(oldest: Option<&str>, newest: Option<&str>) -> PartitionSnapshot {
    PartitionSnapshot { oldest_before_cutoff: oldest.map(str::to_string), newest: newest.map(str::to_string) }
}

#[test]
fn nothing_at_or_after_the_cutoff_is_evictable() {
    let cutoff = retention_cutoff(TODAY, 7).unwrap();
    assert_eq!(evictable_partition(&snap(Some("20261106"), Some(TODAY)), TODAY, &cutoff).as_deref(), Some("20261106"));
    assert_eq!(evictable_partition(&snap(Some("20261107"), Some(TODAY)), TODAY, &cutoff), None);
    assert_eq!(evictable_partition(&snap(Some("20261110"), Some(TODAY)), TODAY, &cutoff), None);
    // A cutoff after today is never honored.
    assert_eq!(evictable_partition(&snap(Some(TODAY), Some("20991231")), TODAY, "20261120"), None);
    assert_eq!(evictable_partition(&snap(Some("20261001"), Some(TODAY)), TODAY, "bad"), None);
}

#[test]
fn snapshot_sql_filters_on_the_cutoff() {
    let sql = partition_snapshot_sql("system.parts", "nanosiem", "20261107").unwrap();
    assert!(
        sql.starts_with("SELECT minIf(partition, partition < '20261107') AS oldest, max(partition) AS newest FROM system.parts WHERE"),
        "{sql}"
    );
    assert!(partition_snapshot_sql("system.parts", "nanosiem", "2026' OR 1").is_err());
}

// ---------------------------------------------------------------- the loop

#[derive(Default)]
struct Fake {
    parts: std::sync::Mutex<Vec<String>>,
    /// Dates already gone when the drop runs.
    gone: Vec<String>,
    /// A date whose audit rows cannot be archived.
    blocked: Option<String>,
    reported: std::sync::Mutex<Vec<String>>,
    attempts: std::sync::Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl PartitionDropper for Fake {
    async fn partition_snapshot(&self, cutoff: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        let parts = self.parts.lock().unwrap();
        Ok(PartitionSnapshot {
            oldest_before_cutoff: parts.iter().filter(|p| p.as_str() < cutoff).min().cloned(),
            newest: parts.iter().max().cloned(),
        })
    }
    async fn usage(&self) -> Result<f64, DiskPressureError> {
        Ok(0.99)
    }
    async fn drop_partition(&self, date: &str) -> Result<Evicted, DiskPressureError> {
        self.attempts.lock().unwrap().push(date.to_string());
        if self.blocked.as_deref() == Some(date) {
            return Err(DiskPressureError::AuditArchiveFailed("3 of 10 rows missing".into()));
        }
        self.parts.lock().unwrap().retain(|p| p != date);
        if self.gone.iter().any(|d| d == date) {
            return Ok(Evicted::default());
        }
        Ok(Evicted { dropped: vec!["ocsf_logs".into(), "signals".into()], archived_from: vec!["ocsf_logs".into()], archived_rows: 10 })
    }
    async fn dropped(&self, date: &str, _evicted: &Evicted) {
        self.reported.lock().unwrap().push(date.to_string());
    }
}

fn fake(parts: &[&str]) -> Fake {
    Fake { parts: std::sync::Mutex::new(parts.iter().map(|p| p.to_string()).collect()), ..Default::default() }
}

async fn run(f: &Fake, max_drops: usize, cutoff: &str) -> DropLoopOutcome {
    let pool = sqlx::postgres::PgPoolOptions::new().connect_lazy("postgres://unused@127.0.0.1:1/unused").unwrap();
    fifo_drop_loop(f, &crate::leader::LeaderFence::disabled(), &pool, 0.70, max_drops, std::time::Duration::ZERO, TODAY, cutoff).await
}

#[tokio::test]
async fn the_loop_never_drops_inside_the_floor_even_at_99_percent() {
    let cutoff = retention_cutoff(TODAY, 7).unwrap();
    let f = fake(&["20261105", "20261106", "20261107", "20261110", "20261113", TODAY]);
    assert_eq!(run(&f, 10, &cutoff).await, DropLoopOutcome::Floor);
    assert_eq!(*f.reported.lock().unwrap(), vec!["20261105", "20261106"]);
    assert_eq!(*f.parts.lock().unwrap(), vec!["20261107", "20261110", "20261113", TODAY]);
}

#[tokio::test]
async fn a_box_holding_only_floor_data_drops_nothing() {
    let cutoff = retention_cutoff(TODAY, 7).unwrap();
    let f = fake(&["20261108", "20261112", TODAY]);
    assert_eq!(run(&f, 10, &cutoff).await, DropLoopOutcome::Floor);
    assert!(f.attempts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn gone_dates_are_stepped_over_without_using_the_drop_budget() {
    let f = Fake {
        gone: vec!["20261001".into(), "20261002".into(), "20261003".into()],
        ..fake(&["20261001", "20261002", "20261003", "20261004", "20261005", "20261006", TODAY])
    };
    assert_eq!(run(&f, 2, TODAY).await, DropLoopOutcome::MaxDrops);
    assert_eq!(*f.reported.lock().unwrap(), vec!["20261004", "20261005"], "skips are not reported as drops");
}

#[tokio::test]
async fn a_failed_archive_stops_the_loop_without_dropping() {
    let f = Fake { blocked: Some("20261001".into()), ..fake(&["20261001", "20261002", TODAY]) };
    assert_eq!(run(&f, 5, TODAY).await, DropLoopOutcome::AuditBlocked);
    assert!(f.reported.lock().unwrap().is_empty());
    assert_eq!(f.parts.lock().unwrap().len(), 3, "the blocked date and everything after it stay");
}

// ---------------------------------------------------------------- audit

#[test]
fn the_audit_bearing_tables_are_the_event_stores() {
    for t in ["logs", "ocsf_logs", "ocsf_logs_legacy_v179"] {
        assert!(AUDIT_BEARING_TABLES.contains(&t));
        assert!(DAILY_TABLES.contains(&t));
    }
    assert!(!AUDIT_BEARING_TABLES.contains(&"signals"));
}

#[test]
fn audit_counts_read_one_partition() {
    let sql = audit_counts_sql("ocsf_logs", "ocsf_logs", "20261001").unwrap();
    assert!(sql.contains("countIf(source_type = 'audit')"), "{sql}");
    assert!(sql.contains("countIf(source_type != 'audit')"), "{sql}");
    assert!(sql.ends_with("FROM ocsf_logs WHERE toYYYYMMDD(timestamp) = 20261001"), "{sql}");
    assert!(!sql.contains("PREWHERE"));
    assert!(audit_counts_sql("signals", "signals", "20261001").is_err());
}

#[test]
fn notification_says_audit_rows_were_archived() {
    let evicted = Evicted { dropped: vec!["ocsf_logs".into(), "signals".into()], archived_from: vec!["ocsf_logs".into()], archived_rows: 42 };
    let msg = partition_dropped_message("20261001", &evicted);
    assert!(msg.contains("Dropped from: ocsf_logs, signals."), "{msg}");
    assert!(msg.contains("42 audit rows were moved to the audit archive"), "{msg}");
    let d = drop_audit_details("20261001", &evicted, 7);
    assert_eq!(d["audit_archived_from"], serde_json::json!(["ocsf_logs"]));
    assert_eq!(d["audit_archived_rows"], 42);
    assert_eq!(d["audit_archive_table"], "audit_archive");
    assert_eq!(d["dropped_tables"], serde_json::json!(["ocsf_logs", "signals"]));
}

// ---------------------------------------------------------------- attribution

const GIB: u64 = 1024 * 1024 * 1024;

fn sample(used: u64, ch: u64) -> DiskSample {
    DiskSample { host: "ch1".into(), disk: "default".into(), total: 100 * GIB, free: (100 - used) * GIB, ch_bytes: ch * GIB }
}

#[test]
fn a_non_clickhouse_file_filling_the_disk_drops_nothing() {
    // Normal at 60 % (50 GiB ClickHouse). A 25 GiB backup lands: 85 %.
    let baseline = sample(60, 50);
    let now = sample(85, 50);
    assert!(matches!(
        eviction_gate(&now, Some(&baseline), 0.80, 0.70),
        EvictionGate::NonClickHouse { non_clickhouse_growth_bytes: Some(g), .. } if g == 25 * GIB
    ));
}

#[test]
fn clickhouse_growth_is_evicted() {
    let baseline = sample(60, 50);
    assert_eq!(eviction_gate(&sample(85, 75), Some(&baseline), 0.80, 0.70), EvictionGate::Drop);
    // No baseline (started under pressure): ClickHouse holds most of it.
    assert_eq!(eviction_gate(&sample(85, 60), None, 0.80, 0.70), EvictionGate::Drop);
}

#[test]
fn dropping_is_futile_when_other_data_alone_exceeds_the_target() {
    // 75 % of the disk is not ClickHouse: even dropping every part leaves the
    // disk above the 70 % target.
    assert!(matches!(eviction_gate(&sample(85, 10), None, 0.80, 0.70), EvictionGate::NonClickHouse { .. }));
}

/// Non-ClickHouse growth stops eviction only when it is material AND larger
/// than ClickHouse's own growth.
#[test]
fn small_or_smaller_than_clickhouse_growth_never_stops_eviction() {
    // 100 GiB disk: 1 GiB is the materiality bar.
    assert_eq!(material_growth_bytes(100 * GIB), GIB);
    assert_eq!(material_growth_bytes(GIB), 256 * 1024 * 1024);
    let mib = 1024 * 1024;
    let base = DiskSample { host: "ch1".into(), disk: "default".into(), total: 100 * GIB, free: 21 * GIB, ch_bytes: 70 * GIB };
    // +512 MiB of logs crosses 80 %: immaterial, evict.
    let now = DiskSample { free: 21 * GIB - 512 * mib, ..base.clone() };
    assert_eq!(eviction_gate(&now, Some(&base), 0.80, 0.70), EvictionGate::Drop);
    // Other +3 GiB but ClickHouse +6 GiB: ClickHouse grew more, evict.
    let base = DiskSample { free: 30 * GIB, ch_bytes: 60 * GIB, ..base };
    let now = DiskSample { free: 21 * GIB, ch_bytes: 66 * GIB, ..base.clone() };
    assert_eq!(eviction_gate(&now, Some(&base), 0.80, 0.70), EvictionGate::Drop);
}

#[test]
fn mixed_growth_drops_only_when_clickhouse_alone_crossed_the_watermark() {
    let baseline = sample(75, 60); // 15 GiB other
    // Other +5, ClickHouse +5: without the other growth the disk is at 80 %.
    assert_eq!(eviction_gate(&sample(85, 65), Some(&baseline), 0.80, 0.70), EvictionGate::Drop);
    // Other +8, ClickHouse +2: without it the disk is at 77 %, under 80 %.
    assert!(matches!(eviction_gate(&sample(85, 62), Some(&baseline), 0.80, 0.70), EvictionGate::NonClickHouse { .. }));
}

#[test]
fn a_baseline_from_another_disk_is_ignored() {
    let mut baseline = sample(60, 50);
    baseline.host = "ch2".into();
    assert_eq!(eviction_gate(&sample(85, 50), Some(&baseline), 0.80, 0.70), EvictionGate::Drop);
}

#[test]
fn clickhouse_bytes_skip_hard_linked_mutation_copies() {
    let sql = clickhouse_bytes_sql("system.parts");
    assert!(sql.contains("if(max(active) = 1, sumIf(bytes_on_disk, active = 1), sum(bytes_on_disk))"), "{sql}");
    assert!(sql.contains("GROUP BY host, disk, database, table, partition_id, min_block_number, max_block_number, level, bytes_on_disk"), "{sql}");
}

// ---------------------------------------------------------------- filesystem

fn disk(host: &str, name: &str, total: u64, free: u64) -> (String, String, u64, u64) {
    (host.into(), name.into(), total, free)
}

/// Compose's storage.xml puts `default` and `warm_disk` on one filesystem:
/// same total and free. ClickHouse's bytes are summed over both, whichever
/// order ClickHouse lists them in.
#[test]
fn clickhouse_bytes_cover_every_disk_on_the_same_filesystem() {
    let parts = vec![
        ("ch1".to_string(), "default".to_string(), 40 * GIB),
        ("ch1".to_string(), "warm_disk".to_string(), 20 * GIB),
    ];
    let a = vec![disk("ch1", "default", 100 * GIB, 20 * GIB), disk("ch1", "warm_disk", 100 * GIB, 20 * GIB)];
    let b: Vec<_> = a.iter().rev().cloned().collect();
    for disks in [a, b] {
        let s = select_disk_sample(&disks, &parts, false).unwrap();
        assert_eq!(s.ch_bytes, 60 * GIB, "{disks:?}");
        assert_eq!(s.disk, "default", "the tie-break does not depend on row order");
        assert_eq!(s.non_clickhouse(), 20 * GIB);
        // The gate sees ClickHouse's growth as ClickHouse's.
        let baseline = DiskSample { free: 40 * GIB, ch_bytes: 40 * GIB, ..s.clone() };
        assert_eq!(eviction_gate(&s, Some(&baseline), 0.80, 0.70), EvictionGate::Drop);
    }
}

/// NAN-5463: Compose's `backups` disk (backups.xml, no reserve) shares the
/// filesystem with `default` / `warm_disk` (storage.xml, 1 GiB
/// `keep_free_space_bytes`). `system.disks` reports total/free NET of the
/// reserve, so the raw rows differ by exactly 1 GiB; the figures are the ones
/// a 26.10 Compose stack reported. Raw, `backups` won the "largest" pick and
/// ClickHouse's bytes read 0, so the gate held every tick. Physical figures
/// make the three siblings and the sample counts the parts.
#[test]
fn compose_backups_disk_with_no_reserve_still_counts_clickhouse_parts() {
    let keep = GIB;
    let rows = [
        ("backups", 1_962_694_664_192u64, 1_468_203_536_384u64, 0u64),
        ("default", 1_961_620_922_368, 1_467_129_794_560, keep),
        ("warm_disk", 1_961_620_922_368, 1_467_129_794_560, keep),
    ];
    let parts = vec![
        ("ch1".to_string(), "default".to_string(), 141_267_129u64),
        ("ch1".to_string(), "warm_disk".to_string(), 7 * GIB),
    ];
    let physical: Vec<_> = rows
        .iter()
        .map(|(name, total, free, keep)| physical_disk("ch1".into(), (*name).into(), *total, *free, *keep))
        .collect();
    for disks in [physical.clone(), physical.iter().rev().cloned().collect()] {
        let s = select_disk_sample(&disks, &parts, false).unwrap();
        assert_eq!(s.ch_bytes, 141_267_129 + 7 * GIB, "{disks:?}");
        assert_eq!(s.disk, "warm_disk", "the disk holding the most parts names the sample");
        assert_eq!(s.total, 1_962_694_664_192);
    }
    // The pre-fix shape (raw rows) is what produced ch_bytes = 0.
    let raw: Vec<_> = rows.iter().map(|(n, t, f, _)| disk("ch1", n, *t, *f)).collect();
    assert_eq!(select_disk_sample(&raw, &parts, false).unwrap().ch_bytes, 0);

    // A disk full of ClickHouse data is ClickHouse's pressure: the gate drops.
    let full = DiskSample {
        host: "ch1".into(),
        disk: "default".into(),
        total: 100 * GIB,
        free: 10 * GIB,
        ch_bytes: 80 * GIB,
    };
    assert_eq!(eviction_gate(&full, None, 0.80, 0.70), EvictionGate::Drop);
}

#[test]
fn a_separate_filesystem_and_another_host_are_not_summed() {
    let parts = vec![
        ("ch1".to_string(), "default".to_string(), 40 * GIB),
        ("ch1".to_string(), "hot_nvme".to_string(), 10 * GIB),
        ("ch2".to_string(), "default".to_string(), 30 * GIB),
    ];
    let disks = vec![
        disk("ch1", "default", 100 * GIB, 20 * GIB),
        disk("ch1", "hot_nvme", 50 * GIB, 40 * GIB),
    ];
    let s = select_disk_sample(&disks, &parts, false).unwrap();
    assert_eq!((s.disk.as_str(), s.ch_bytes), ("default", 40 * GIB));
    // Cluster: the worst used fraction wins.
    let disks = vec![disk("ch1", "default", 100 * GIB, 50 * GIB), disk("ch2", "default", 100 * GIB, 10 * GIB)];
    let s = select_disk_sample(&disks, &parts, true).unwrap();
    assert_eq!((s.host.as_str(), s.ch_bytes), ("ch2", 30 * GIB));
    assert!(select_disk_sample(&[], &parts, false).is_none());
}

// ---------------------------------------------------------------- holds

#[test]
fn hold_keys_are_distinct_and_match_their_descriptions() {
    let config = DiskPressureConfig { min_retention_days: 7, ..DiskPressureConfig::default() };
    let reasons = [
        HoldReason::RetentionFloor { cutoff: "20261107".into(), floor_days: 7 },
        HoldReason::NonClickHouse { sample: sample(85, 50), non_clickhouse_growth_bytes: None },
        HoldReason::AuditArchiveFailed,
    ];
    let mut seen = std::collections::HashSet::new();
    for (i, r) in reasons.iter().enumerate() {
        let (dedup, issue, title, detail) = r.describe(&config);
        assert_eq!((issue, dedup), HoldReason::KEYS[i]);
        assert!(seen.insert(dedup));
        assert!(!title.is_empty() && !detail.is_empty());
        assert!(dedup != "storage:clickhouse:disk_pressure", "holds must not overwrite the pressure event");
    }
    let (_, _, _, detail) = reasons[0].describe(&config);
    assert!(detail.contains("last 7 days"), "{detail}");
}
