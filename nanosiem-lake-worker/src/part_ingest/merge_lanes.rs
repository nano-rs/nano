// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent bounded merge lanes; overlapping event hours stay serialized.
use crate::parts::levels::{Level, PlannedMerge};

/// Concurrent merges per lane. History defaults to 2 (NAN-3187): after a
/// backlog, sealed hours healed one at a time (~15 min each). Beyond the
/// first, a history merge must be an `h` merge, run beside `h` merges only,
/// and fit the memory headroom ([`history_memory_admits`]).
pub fn capacity(level: Level) -> usize {
    let (name, default) = if level == Level::Minute {
        ("NANO_LAKE_MERGE_MINUTE_CONCURRENCY", 2)
    } else {
        ("NANO_LAKE_MERGE_HISTORY_CONCURRENCY", 2)
    };
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| (1..=4).contains(v))
        .unwrap_or(default)
}

/// The order one scheduling pass offers due merges to the lanes (NAN-3400).
///
/// * Minute lane first, newest hour first (unchanged): fresh L0s.
/// * History lane: `h` merges before day merges, then the merge with the
///   most inputs first, then the newest hour. Every input a merge removes is
///   one file fewer for every search over that hour, so a sealed hour left
///   as ~50 minute parts outranks an old hour that a late backfill gave one
///   extra part.
///
/// The history lane used to drain oldest hour first. On the load-test tenant
/// (2026-10-09) a backfill put one late part into ~100 old hours, each
/// rewrite took ~18 min on two lanes, and every hour sealed since then stayed
/// at ~50 parts behind that queue for 8+ hours: the 1d window read 349 files
/// instead of ~25, and 1d search p50 went from 1.2 s to 3.0 s.
pub fn launch_order(planned: &mut [PlannedMerge]) {
    use std::cmp::Reverse;
    planned.sort_by_key(|merge| match merge.output_level {
        Level::Minute => (0_u8, Reverse(0_usize), Reverse(merge.event_hour)),
        Level::Day => (2, Reverse(merge.inputs.len()), Reverse(merge.event_hour)),
        _ => (1, Reverse(merge.inputs.len()), Reverse(merge.event_hour)),
    });
}

pub fn overlaps(left: &PlannedMerge, right: &PlannedMerge) -> bool {
    let range = |merge: &PlannedMerge| {
        let first = merge.event_hour;
        let last = if merge.output_level == Level::Day {
            first.saturating_add(23)
        } else {
            first
        };
        (first, last)
    };
    let (a, b) = range(left);
    let (c, d) = range(right);
    a <= d && c <= b
        || left
            .inputs
            .iter()
            .any(|a| right.inputs.iter().any(|b| a.part_id == b.part_id))
}

pub fn available(merge: &PlannedMerge, active: &[&PlannedMerge]) -> bool {
    available_with(merge, active, capacity(merge.output_level), || {
        history_memory_admits(MemorySnapshot::read())
    })
}

/// [`available`] with the lane capacity and the memory probe supplied (the
/// probe runs only for a second-or-later concurrent history merge).
pub fn available_with(
    merge: &PlannedMerge,
    active: &[&PlannedMerge],
    capacity: usize,
    memory_admits: impl FnOnce() -> bool,
) -> bool {
    let minute = merge.output_level == Level::Minute;
    let same_lane = active
        .iter()
        .filter(|m| (m.output_level == Level::Minute) == minute)
        .collect::<Vec<_>>();
    if same_lane.len() >= capacity || active.iter().any(|m| overlaps(merge, m)) {
        return false;
    }
    if minute || same_lane.is_empty() {
        return true;
    }
    // A further history lane is only for sealed `h` merges side by side:
    // a day merge (24 hours of inputs) always runs alone.
    merge.output_level == Level::Hour
        && same_lane.iter().all(|m| m.output_level == Level::Hour)
        && memory_admits()
}

/// Resident memory one more history merge may add. The merge streams
/// (`merge::MAX_OPEN_INPUTS` readers over a decode window of at most
/// 32,768 rows x 10 KiB = 320 MiB) and NAN-3056 measured a background hour
/// merge plus a full admission-buffer flush under half of 4.5 GiB; 1 GiB
/// covers the window, reader page/dictionary state, the output row group and
/// token/partial building with margin.
pub const HISTORY_MERGE_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
/// A further history merge starts only while the cgroup working set plus
/// [`HISTORY_MERGE_MEMORY_BYTES`] stays under this share of memory.max.
pub const HISTORY_MEMORY_CEILING: f64 = 0.80;

/// This process's memory: working set (its cgroup's usage minus inactive
/// file cache, as container monitoring counts it; else VmRSS) and limit (the
/// lower of its own cgroup's memory.max and the assignment's memory cap);
/// `None` when unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySnapshot {
    pub working_set_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
}

impl MemorySnapshot {
    pub fn read() -> Self {
        let read = |path: &std::path::Path| std::fs::read_to_string(path).ok();
        let number = |s: Option<String>| s.and_then(|s| s.trim().parse::<u64>().ok());
        // The cell puts each role in a leaf cgroup (ingest[T]); without a
        // cgroup namespace /sys/fs/cgroup is the pod's, so resolve our own.
        let dir = read(std::path::Path::new("/proc/self/cgroup"))
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_owned()))
            })
            .map(|path| std::path::Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
            .unwrap_or_else(|| "/sys/fs/cgroup".into());
        let cgroup_limit = number(read(&dir.join("memory.max")))
            .filter(|limit| *limit > 0 && *limit < (1_u64 << 60));
        let limit_bytes = match (cgroup_limit, super::merge::memory_cap_bytes()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let inactive_file = read(&dir.join("memory.stat"))
            .and_then(|stat| {
                stat.lines()
                    .find_map(|l| l.strip_prefix("inactive_file ").map(str::to_owned))
            })
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let working_set_bytes = number(read(&dir.join("memory.current")))
            .map(|current| current.saturating_sub(inactive_file))
            .or_else(|| {
                read(std::path::Path::new("/proc/self/status")).and_then(|status| {
                    status
                        .lines()
                        .find_map(|l| l.strip_prefix("VmRSS:"))
                        .and_then(|kb| kb.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
                        .map(|kb| kb * 1024)
                })
            });
        Self {
            working_set_bytes,
            limit_bytes,
        }
    }
}

/// Whether one more history merge fits. No cgroup limit (lab, tests): there
/// is no budget to protect, so it fits. A limit with an unreadable usage
/// does not.
pub fn history_memory_admits(memory: MemorySnapshot) -> bool {
    let Some(limit) = memory.limit_bytes else {
        return true;
    };
    let Some(working_set) = memory.working_set_bytes else {
        return false;
    };
    let admits = (working_set.saturating_add(HISTORY_MERGE_MEMORY_BYTES) as f64)
        <= limit as f64 * HISTORY_MEMORY_CEILING;
    if !admits {
        tracing::debug!(
            working_set_bytes = working_set,
            limit_bytes = limit,
            "second history merge deferred: memory headroom"
        );
    }
    admits
}

/// Own OS thread: reducing its priority cannot affect Tokio's ingest threads.
pub async fn compute<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new().name("lake-merge".into()).spawn(move || {
        // SAFETY: Linux setpriority with pid 0 changes only this calling thread.
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 19) } != 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "could not lower merge thread priority");
        }
        let _ = tx.send(work());
    })?;
    rx.await
        .map_err(|_| anyhow::anyhow!("merge compute thread panicked"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::format::PartId;
    use crate::parts::levels::{plan_merges, MergePolicy};
    use crate::parts::part_log::PartRef;

    fn part(hour: i32, seq: i64, now: i64) -> PartRef {
        PartRef {
            part_id: PartId::parse(&format!("{:013}-{:016x}", now - 120_000, seq)).unwrap(),
            level: Level::L0,
            event_hour: hour,
            event_day: None,
            rows: 3_000,
            min_time_us: i64::from(hour) * 3_600_000_000,
            max_time_us: i64::from(hour) * 3_600_000_000 + 1,
            schema_fingerprint: "0".repeat(64),
            provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64),
            sorted: true,
            data_bytes: 450_000,
            row_groups: 1,
            data_files: 1,
        }
    }

    #[test]
    fn arrival_300_eps_with_250_part_backlog_drains_beside_history() {
        let start = 500_000_i64 * 3_600_000;
        let mut live = (0..250)
            .map(|i| part(499_999 + (i % 2) as i32, i, start))
            .collect::<Vec<_>>();
        let history = PlannedMerge {
            output_level: Level::Hour,
            event_hour: 499_997,
            inputs: vec![],
        };
        // Model a minute job taking 60 seconds, while the history job takes
        // the entire 15-minute run. Production scheduling/overlap logic is
        // used; this is a service-rate simulation, not a CPU benchmark.
        let mut active = vec![(history, i64::MAX)];
        let mut arrival = 250;
        let mut removed = 0;
        for tick in 0..90 {
            let now = start + tick * 10_000;
            for (merge, end) in &active {
                if *end <= now {
                    let ids = merge.inputs.iter().map(|p| &p.part_id).collect::<Vec<_>>();
                    live.retain(|p| !ids.contains(&&p.part_id));
                    removed += merge.inputs.len();
                }
            }
            active.retain(|(_, end)| *end > now);
            // Ingest advances each 10-second tick, independent of history.
            live.push(part(500_000, arrival, now + 120_000));
            arrival += 1;
            let mut planned = plan_merges(&live, now, &MergePolicy::default());
            planned.sort_by_key(|m| (m.output_level != Level::Minute, -i64::from(m.event_hour)));
            for merge in planned {
                if merge.output_level != Level::Minute {
                    continue;
                }
                let running = active.iter().map(|(m, _)| m).collect::<Vec<_>>();
                if available(&merge, &running) {
                    assert!(running.iter().all(|m| !overlaps(&merge, m)));
                    active.push((merge, now + 60_000));
                }
            }
            assert!(
                active
                    .iter()
                    .filter(|(m, _)| m.output_level == Level::Minute)
                    .count()
                    <= 2
            );
        }
        assert!(removed >= 250, "removed only {removed} backlog inputs");
        assert!(live.len() < 30, "{} L0s left after catch-up", live.len());
        assert_eq!(arrival - 250, 90, "every ingest tick ran");
    }

    #[test]
    fn day_range_and_same_hour_are_exclusive_across_lanes() {
        let day = PlannedMerge {
            output_level: Level::Day,
            event_hour: 48,
            inputs: vec![],
        };
        let mut minute = PlannedMerge {
            output_level: Level::Minute,
            event_hour: 71,
            inputs: vec![],
        };
        assert!(!available(&minute, &[&day]));
        minute.event_hour = 72;
        assert!(available(&minute, &[&day]));
        assert!(!available(&minute, &[&minute]));
    }

    /// NAN-3187: two backfilled sealed hours run two `h` merges at once
    /// when memory allows; a third waits, as does a day merge.
    #[test]
    fn two_sealed_backlog_hours_get_two_concurrent_hour_merges() {
        let now = 500_010_i64 * 3_600_000;
        // Parts created 120 s before `now - 600 s`: quiet (past the debounce).
        let live = (0..3)
            .flat_map(|h| {
                (0..30).map(move |i| part(500_000 + h, h as i64 * 100 + i, now - 600_000))
            })
            .collect::<Vec<_>>();
        let planned = plan_merges(&live, now, &MergePolicy::default());
        assert_eq!(planned.len(), 3, "{planned:?}");
        assert!(planned
            .iter()
            .all(|m| m.output_level == Level::Hour && m.inputs.len() == 30));
        let fits = || true;
        assert!(available_with(&planned[0], &[], 2, fits));
        assert!(
            available_with(&planned[1], &[&planned[0]], 2, fits),
            "second history lane"
        );
        assert!(
            !available_with(&planned[2], &[&planned[0], &planned[1]], 2, fits),
            "capacity 2"
        );
        // The second lane needs memory headroom; the first never waits on it.
        assert!(!available_with(&planned[1], &[&planned[0]], 2, || false));
        assert!(available_with(&planned[0], &[], 2, || false));
        // Same hour never twice; a day merge never beside another history job.
        assert!(!available_with(&planned[0], &[&planned[0]], 2, fits));
        let day = PlannedMerge {
            output_level: Level::Day,
            event_hour: 499_968,
            inputs: vec![],
        };
        assert!(!available_with(&day, &[&planned[0]], 2, fits));
        assert!(!available_with(&planned[0], &[&day], 2, fits));
        // Minute work is independent of the history lanes.
        let minute = PlannedMerge {
            output_level: Level::Minute,
            event_hour: 500_009,
            inputs: vec![],
        };
        assert!(available_with(
            &minute,
            &[&planned[0], &planned[1]],
            2,
            || false
        ));
        // Setting the knob to 1 restores one history merge at a time.
        assert!(!available_with(&planned[1], &[&planned[0]], 1, fits));
    }

    fn due(level: Level, hour: i32, inputs: usize) -> PlannedMerge {
        let now = 500_200_i64 * 3_600_000;
        PlannedMerge {
            output_level: level,
            event_hour: hour,
            // Part ids are unique per (hour, input): `overlaps` compares them.
            inputs: (0..inputs)
                .map(|i| part(hour, i64::from(hour) * 1_000 + i as i64, now))
                .collect(),
        }
    }

    /// Two-lane history service: one round is one hour merge per lane
    /// (~18 min each on the load-test tenant). Returns the round in which the last of
    /// the fragmented recent hours started.
    fn rounds_until_recent_hours_start(order: fn(&mut [PlannedMerge])) -> usize {
        // The 2026-10-09 load-test tenant backlog: 60 old hours that a backfill gave
        // one late part each (2 inputs), and 8 hours sealed since then that
        // still hold ~50 minute parts each.
        let mut waiting = (0..60)
            .map(|h| due(Level::Hour, 500_000 + h, 2))
            .chain((0..8).map(|h| due(Level::Hour, 500_100 + h, 50)))
            .collect::<Vec<_>>();
        for round in 1..=100 {
            order(&mut waiting);
            let mut started: Vec<PlannedMerge> = Vec::new();
            let mut index = 0;
            while index < waiting.len() {
                let running = started.iter().collect::<Vec<_>>();
                if available_with(&waiting[index], &running, 2, || true) {
                    started.push(waiting.remove(index));
                } else {
                    index += 1;
                }
            }
            assert_eq!(started.len(), 2, "both history lanes busy every round");
            if waiting.iter().all(|m| m.event_hour < 500_100) {
                return round;
            }
        }
        panic!("recent hours never started");
    }

    /// NAN-3400: the most fragmented sealed hours merge first; an old hour
    /// with one late part no longer holds a fresh 50-part hour for hours.
    #[test]
    fn fragmented_recent_hours_merge_before_old_backfill_rewrites() {
        let oldest_first: fn(&mut [PlannedMerge]) = |planned| {
            planned.sort_by_key(|m| {
                (
                    m.output_level != Level::Minute,
                    if m.output_level == Level::Minute {
                        -i64::from(m.event_hour)
                    } else {
                        i64::from(m.event_hour)
                    },
                )
            })
        };
        // Before: the recent hours waited behind all 60 old rewrites
        // (~30 rounds, ~9 h at 18 min a round).
        assert!(rounds_until_recent_hours_start(oldest_first) >= 30);
        // After: they take both lanes first (4 rounds, ~72 min).
        assert_eq!(rounds_until_recent_hours_start(launch_order), 4);
    }

    #[test]
    fn launch_order_keeps_minutes_first_and_days_after_hours() {
        let mut planned = vec![
            due(Level::Day, 499_968, 24),
            due(Level::Hour, 500_001, 2),
            due(Level::Minute, 500_009, 4),
            due(Level::Hour, 500_005, 2),
            due(Level::Hour, 500_003, 40),
            due(Level::Minute, 500_010, 4),
        ];
        launch_order(&mut planned);
        let order = planned
            .iter()
            .map(|m| (m.output_level, m.event_hour))
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                // Minute lane: newest first, ahead of every history job.
                (Level::Minute, 500_010),
                (Level::Minute, 500_009),
                // History: most inputs, then newest; a day merge (which runs
                // alone and holds both lanes) only after every hour merge.
                (Level::Hour, 500_003),
                (Level::Hour, 500_005),
                (Level::Hour, 500_001),
                (Level::Day, 499_968),
            ]
        );
    }

    #[test]
    fn history_memory_gate() {
        // This process always has a readable working set (cgroup or VmRSS).
        assert!(MemorySnapshot::read()
            .working_set_bytes
            .is_some_and(|b| b > 0));
        const GIB: u64 = 1024 * 1024 * 1024;
        let limit = 7 * GIB + 3 * GIB / 4; // ingest[T] memory.max on 10-07
        let at = |working_set| MemorySnapshot {
            working_set_bytes: Some(working_set),
            limit_bytes: Some(limit),
        };
        // The catch-up peak (6.1 GB) leaves no room for another merge...
        assert!(!history_memory_admits(at(6_100_000_000)));
        // ...steady ingest plus one running hour merge does.
        assert!(history_memory_admits(at(4 * GIB)));
        assert!(!history_memory_admits(MemorySnapshot {
            working_set_bytes: None,
            limit_bytes: Some(limit)
        }));
        assert!(history_memory_admits(MemorySnapshot {
            working_set_bytes: None,
            limit_bytes: None
        }));
    }

    #[tokio::test]
    async fn history_cpu_permit_does_not_block_minute_or_ingest() {
        let history = super::super::merge_quota::acquire_for(Level::Hour).unwrap();
        let (started, waiting) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let job = tokio::spawn(compute(move || {
            let _minute = super::super::merge_quota::acquire_for(Level::Minute).unwrap();
            started.send(()).unwrap();
            held.recv().unwrap();
        }));
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("minute waited behind history")
            .unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            tokio::task::yield_now(),
        )
        .await
        .expect("ingest executor must remain responsive");
        release.send(()).unwrap();
        job.await.unwrap().unwrap();
        drop(history);
    }
}
