// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use super::super::merge_quota::*;

fn plan(level: Level, hour: i32) -> PlannedMerge {
    PlannedMerge { output_level: level, event_hour: hour, inputs: Vec::new() }
}

#[test]
fn nan4826_role_shapes_drive_scheduler_and_backfill_entry_points() {
    const GIB: u64 = 1024 * 1024 * 1024;
    let _share = lock_backfill_share_for_test();
    for (bytes, cores, minute, history) in [
        (2 * GIB, 4, 2, 1), (3_413_114_880, 4, 2, 1),
        (4 * GIB, 4, 2, 1), (32 * GIB, 16, 8, 6), (64 * GIB, 32, 16, 12),
    ] {
        let root = tempfile::tempdir().unwrap();
        let role = root.path().join("tenant/ingest");
        std::fs::create_dir_all(&role).unwrap();
        std::fs::write(role.join("memory.max"), bytes.to_string()).unwrap();
        std::fs::write(role.join("cpu.max"), format!("{} 100000", cores * 100000)).unwrap();
        let cgroup = crate::cgroup_memory::resolve(root.path(), "0::/\n", "", Some(std::path::Path::new("tenant/ingest")));
        let role = crate::cgroup_memory::capacity_for(&cgroup, nanosiem_lake_cell::resources::CellCapacity {
            memory_bytes: 128 * GIB, cpu_millicores: 64000, memory_source: "host", cpu_source: "host",
        });
        let sizing = MergeCapacity::for_role(Some(role.memory_bytes), role.cpu_millicores);
        let _capacity = test_capacity(sizing);
        assert_eq!(capacity(Level::Minute), minute, "{bytes}/{cores}");
        assert_eq!(capacity(Level::Hour), history, "{bytes}/{cores}");
        assert!(sizing.minute_bytes * minute as u64 + sizing.history_bytes * history as u64 <= bytes * 80 / 100);
        let old = plan(Level::Hour, 1);
        let active = (0..history).map(|i| plan(Level::Hour, i as i32 + 10)).collect::<Vec<_>>();
        let active = active.iter().collect::<Vec<_>>();
        assert!(!available_at(&old, &active, i64::MAX), "full history lane");
        if bytes <= 4 * GIB {
            let fresh = plan(Level::Hour, 100);
            assert!(!available_at(&fresh, &active, 101 * 3_600_000), "reserved fresh slot cannot overrun a small role");
            assert!(!sizing.fits(Level::Hour, active.iter().copied()), "rewrites share history memory");
            assert!(sizing.fits(Level::Minute, active.iter().copied()), "minute compaction retains room");
        }
        let idle = Headroom { lag_ms: 0, utilization: Some(0.1), throttled: Some(0.0), r2_strain: Some(0.0),
            transfer_failures: 0, searching: false, prevalence_behind_ms: 0, l0_merge_overdue_ms: 0 };
        let mut share = 250;
        for _ in 0..40 { share = next_backfill_share(share, &idle); }
        assert_eq!(share, cores as u64 * 1000);
        set_backfill_share_for_test(share);
        assert_eq!(backfill_rewrite_slots(), history);
        assert_eq!(next_backfill_share(share, &Headroom { utilization: Some(0.95), ..idle }), share / 2);
        set_searching_for_test(true);
        assert_eq!(backfill_rewrite_slots(), 0);
        set_searching_for_test(false);
        set_ingest_behind_for_test(true);
        assert_eq!(backfill_rewrite_slots(), 0);
        set_ingest_behind_for_test(false);
        eprintln!("NAN4826 memory={bytes} cores={cores} minute={minute} history={history} minute_bytes={} history_bytes={} backfill_permille={share}", sizing.minute_bytes, sizing.history_bytes);
    }
    set_backfill_share_for_test(250);
}

#[test]
fn nan4826_cpu_and_memory_ancestors_and_resize_remain_authoritative() {
    let root = tempfile::tempdir().unwrap();
    let role = root.path().join("tenant/ingest");
    std::fs::create_dir_all(&role).unwrap();
    std::fs::write(role.join("cpu.max"), "3200000 100000").unwrap();
    std::fs::write(root.path().join("tenant/cpu.max"), "1600000 100000").unwrap();
    std::fs::write(role.join("memory.max"), "68719476736").unwrap();
    std::fs::write(root.path().join("tenant/memory.max"), "34359738368").unwrap();
    let cg = crate::cgroup_memory::resolve(root.path(), "0::/\n", "", Some(std::path::Path::new("tenant/ingest")));
    let host = nanosiem_lake_cell::resources::CellCapacity {
        memory_bytes: 128 * 1024 * 1024 * 1024, cpu_millicores: 64000,
        memory_source: "host", cpu_source: "host",
    };
    assert_eq!(crate::cgroup_memory::capacity_for(&cg, host.clone()).cpu_millicores, 16000);
    assert_eq!(cg.limit().unwrap().bytes, 34359738368);
    std::fs::write(role.join("cpu.max"), "150000 100000").unwrap();
    let role = crate::cgroup_memory::capacity_for(&cg, host);
    assert_eq!(role.cpu_millicores, 1500);
    let sizing = MergeCapacity::for_role(Some(role.memory_bytes), role.cpu_millicores);
    let _capacity = test_capacity(sizing);
    assert_eq!(capacity(Level::Hour), 1);
    assert_eq!(backfill_share_max_permille(), 1500);
    // The shared #8387 model also caps an oversized role quota to its
    // detected host. Merge and backfill must use that same CPU boundary.
    let role = crate::cgroup_memory::capacity_for(&cg, nanosiem_lake_cell::resources::CellCapacity {
        memory_bytes: 128 * 1024 * 1024 * 1024, cpu_millicores: 1000,
        memory_source: "host", cpu_source: "host",
    });
    let _host_capacity = test_capacity(MergeCapacity::for_role(Some(role.memory_bytes), role.cpu_millicores));
    assert_eq!(capacity(Level::Minute), 1);
    assert_eq!(backfill_share_max_permille(), 1000);
}

#[test]
fn nan4826_history_cannot_spend_the_last_minute_reservations() {
    let sizing = MergeCapacity::for_role(Some(15 * 1024 * 1024 * 1024), 16000);
    let active = (0..3).map(|hour| plan(Level::Hour, hour)).collect::<Vec<_>>();
    // Four 3-GiB history jobs would exactly fill the 80% pool. Count
    // rewrites and ordinary jobs can share it, so protect future minutes too.
    assert!(!sizing.fits(Level::Hour, active.iter()));
    assert!(sizing.fits(Level::Minute, active.iter()));
}
