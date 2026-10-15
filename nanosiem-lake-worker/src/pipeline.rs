// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded publication work and tenant-local snapshot cadence.

use anyhow::{bail, Result};
use futures::{stream, StreamExt};
use std::future::Future;

/// Tenant-local throughput model.
///
/// Symbols:
/// - `E` — row arrival rate (rows/sec) = configured EPS.
/// - `A` — staged-object arrival rate (objects/sec). Set by the tail packer's rotation, NOT
///   derivable from `E` alone (rows-per-object is not configured anywhere).
/// - `C` — `--cadence-seconds`, `N` — `--max-objects`, `R` — `--target-rows`, `B` — `--target-bytes`.
/// - `w` — mean compressed row bytes. `S` — serving bound in objects (`--hot-tail-max-objects`).
/// - `H` — headroom factor. Use `2`.
///
/// One cycle absorbs `n = min(N, R/p, B/(p*w))` objects where `p = E/A` is rows per staged
/// object. A cycle repeats every `T = max(C, work_time)`. Drain `D = n/T`.
///
/// Sustaining requires `D >= H*A`. Substituting `N = H*A*C` (the object-dimension requirement)
/// into the row and byte requirements eliminates both `p` and `A`:
///
/// ```text
/// N >= H * A * C          (object cap must cover H intervals of object arrival)
/// R >= H * E * C          (row target must cover H intervals of row arrival)
/// B >= H * E * w * C      (byte target must cover H intervals of compressed arrival)
/// ```
///
/// The second and third are **arrival-rate-free**: the row/byte targets must each cover at
/// least `H` cadence intervals of ingest. If they do not, they truncate the cycle below the
/// object cap and the object cap never binds — exactly measurement row 2.
///
/// Check against live (E=2000, w=143.8 B, A=25/min=0.4167/s, H=2):
/// - C=300: `R >= 1_200_000` (shipped 40_000 — **30x short**), `B >= 172.56 MB` (shipped 32 MiB —
///   **5.1x short**), `N >= 250` (shipped 32 — **8x short**).
/// - C=20: `R >= 80_000` (shipped 40_000 — 2x short), `B >= 11.504 MB` (32 MiB OK),
///   `N >= 16.7` (32 OK).
///
/// Memory dominates throughput: let `d = 10_240` peak decoded bytes/row,
/// `M` be the container limit, `O = 256 MiB` resident overhead and `Hm = 2`.
/// These constants come from the 2026-09-21 OOM at 221,895 rows in 2 GiB.
/// `R_mem = (M - O) / (Hm * d)`; `R <= R_mem`, hence `C_max = R_mem / (H * E)`.
/// At 2 GiB, R_mem = 91,750 rows; at E=2000, C_max = 22.9375 s (about 23 s).
/// The shipped cadence of 300 s was arithmetically unsatisfiable at 2000 EPS
/// in a 2 GiB container: 1.2M rows require 12.288 GB of decoded rows alone,
/// roughly six containers. Cadence 20 s works because it is below C_max.
/// Clamp cadence DOWN (floor to whole seconds), then raise rows only up to
/// R_mem. Keep B >= R_mem * w subject to the byte ceiling; N >= H*A*C remains
/// an object-arrival requirement, never a memory-derived increase.
///
/// The 20-second / 40k-row measurement (5 objects/min) improves on 2/min at
/// 300 seconds, but still loses to 25/min arrival. These are necessary sizing
/// constraints; work time and single-hour fragmentation can still limit drain.
///
/// **The three knobs are not independently settable.** They
/// must be derived, and because `E` and `A` are deployment properties they must be derived from
/// the tenant's own rate — measured, not guessed.
#[derive(Clone, Copy, Debug)]
pub struct CompactionCadence {
    pub target_rows: u64,
    pub target_bytes: u64,
    pub interval_seconds: u64,
}

impl CompactionCadence {
    pub fn ready(self, rows: u64, bytes: u64, oldest_epoch: i64, now_epoch: i64) -> bool {
        if rows == 0 {
            return false;
        }
        (self.target_rows > 0 && rows >= self.target_rows)
            || bytes >= self.target_bytes
            || u64::try_from(now_epoch.saturating_sub(oldest_epoch)).unwrap_or(0)
                >= self.interval_seconds
    }
}

/// Pressure starts at half the serving bound, using the WHOLE staged tail.
pub const COMPACTION_PRESSURE_FRACTION: u64 = 2;
pub const COMPACTION_HEADROOM: f64 = 2.0;

/// Enabled cadence always retains a one-second interval.
pub fn memory_bounded_cadence(cadence: u64, rows_per_sec: f64, rows_max: u64) -> u64 {
    if cadence == 0 { return 0; }
    if rows_per_sec > 0.0 {
        cadence.min((rows_max as f64 / (COMPACTION_HEADROOM * rows_per_sec)).floor() as u64).max(1)
    } else {
        cadence
    }
}

pub fn compaction_pressure(staged: u64, serving_bound: u64) -> bool {
    staged >= serving_bound.div_ceil(COMPACTION_PRESSURE_FRACTION)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactionSizing {
    pub rows: u64,
    pub bytes: u64,
    pub objects: u64,
}

impl CompactionSizing {
    /// Caller supplies the existing hard safety ceilings. Never shrink a valid
    /// operator floor or a previously raised bound when the window gets quiet.
    pub fn raised(
        self,
        objects_per_sec: f64,
        rows_per_sec: f64,
        row_bytes: f64,
        cadence_seconds: u64,
        ceiling: Self,
    ) -> Self {
        let intervals = COMPACTION_HEADROOM * cadence_seconds as f64;
        Self {
            rows: self
                .rows
                .max((intervals * rows_per_sec).ceil() as u64)
                .min(ceiling.rows),
            bytes: self
                .bytes
                .max((intervals * rows_per_sec * row_bytes).ceil() as u64)
                .min(ceiling.bytes),
            objects: self
                .objects
                .max((intervals * objects_per_sec).ceil() as u64)
                .min(ceiling.objects),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TailFlow {
    pub fill_objects_per_sec: f64,
    pub fill_rows_per_sec: f64,
    pub mean_compressed_row_bytes: f64,
    pub drain_objects_per_sec: f64,
    pub staged_objects: u64,
    pub seconds_since_last_commit: Option<f64>,
}

impl TailFlow {
    pub fn dead_drain(self, cadence_seconds: u64) -> bool {
        self.deficit_objects_per_sec() > 0.0
            && self.staged_objects > 0
            && self
                .seconds_since_last_commit
                .is_some_and(|s| s > 3.0 * cadence_seconds.max(1) as f64)
    }
    pub fn deficit_objects_per_sec(self) -> f64 {
        self.fill_objects_per_sec - self.drain_objects_per_sec
    }
    pub fn seconds_to_serving_bound(self, serving_bound: u64) -> Option<f64> {
        let deficit = self.deficit_objects_per_sec();
        (deficit > 0.0).then(|| serving_bound.saturating_sub(self.staged_objects) as f64 / deficit)
    }
}

/// Drain every started operation before returning an error. Dropping a sibling
/// upload on the first error can leave an ambiguous provider completion.
pub async fn publish_bounded<T, F>(
    work: impl IntoIterator<Item = F>,
    concurrency: usize,
) -> Result<Vec<T>>
where
    F: Future<Output = Result<T>>,
{
    if !(1..=16).contains(&concurrency) {
        bail!("publication concurrency must be within 1..=16");
    }
    let results = stream::iter(work)
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;
    results.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn memory_dominates_cadence_and_distinguishes_dead_from_slow() {
        assert_eq!(memory_bounded_cadence(300, 2000.0, 91_750), 22);
        assert_eq!(memory_bounded_cadence(20, 2000.0, 91_750), 20);
        let sizing = CompactionSizing {
            rows: 60_000,
            bytes: 64 << 20,
            objects: 32,
        }
        .raised(
            25.0 / 60.0,
            2000.0,
            143.8,
            22,
            CompactionSizing {
                rows: 91_750,
                bytes: 1 << 30,
                objects: 4096,
            },
        );
        assert_eq!(sizing.rows, 88_000);
        assert!(sizing.bytes >= 13_193_650);
        assert_eq!(sizing.objects, 32);
        assert_eq!(memory_bounded_cadence(300, 100_000.0, 91_750), 1);
        let flow = TailFlow {
            fill_objects_per_sec: 1.0,
            staged_objects: 100,
            seconds_since_last_commit: Some(61.0),
            ..Default::default()
        };
        assert!(flow.dead_drain(20));
        assert!(!TailFlow {
            seconds_since_last_commit: Some(59.0),
            ..flow
        }
        .dead_drain(20));
    }

    #[test]
    fn trickle_flushes_on_its_own_data_age() {
        let cadence = CompactionCadence {
            target_rows: 100_000,
            target_bytes: 64 << 20,
            interval_seconds: 300,
        };
        assert!(!cadence.ready(4, 100, 0, 299));
        assert!(cadence.ready(4, 100, 0, 300));
        assert!(cadence.ready(4, 100, 0, 301));
        assert!(cadence.ready(4, 100, 0, 600));
        assert!(!cadence.ready(0, 0, 0, 600));
        assert!(!cadence.ready(1, 1, 700, 600));
    }

    #[test]
    fn pressure_does_not_wait_for_timer() {
        let cadence = CompactionCadence {
            target_rows: 100_000,
            target_bytes: 64 << 20,
            interval_seconds: 300,
        };
        assert!(cadence.ready(100_000, 100, 100, 100));
        assert!(cadence.ready(1, 64 << 20, 100, 100));
    }

    #[test]
    fn fresh_commit_does_not_reset_staged_age_and_restart_is_identical() {
        let make = || CompactionCadence {
            target_rows: 100_000,
            target_bytes: 64 << 20,
            interval_seconds: 300,
        };
        // Data staged at 0, a commit at 300, observation at 301. A fresh
        // instance after restart has exactly the same durable inputs.
        assert!(make().ready(4, 100, 0, 301));
        assert_eq!(make().ready(4, 100, 0, 301), make().ready(4, 100, 0, 301));
    }

    #[test]
    fn deficit_reports_tonights_remaining_seconds() {
        let flow = TailFlow {
            staged_objects: 1500,
            fill_objects_per_sec: 25.0 / 60.0,
            drain_objects_per_sec: 2.0 / 60.0,
            ..Default::default()
        };
        assert!((flow.deficit_objects_per_sec() - 23.0 / 60.0).abs() < 1e-9);
        assert!((flow.seconds_to_serving_bound(4096).unwrap() - 6772.173913).abs() < 0.001);
        assert_eq!(flow.seconds_to_serving_bound(1000), Some(0.0));
        assert_eq!(
            TailFlow {
                drain_objects_per_sec: 1.0,
                ..flow
            }
            .seconds_to_serving_bound(4096),
            None
        );
    }

    #[test]
    fn pressure_override_bypasses_any_interval() {
        assert!(!compaction_pressure(2047, 4096));
        assert!(compaction_pressure(2048, 4096));
        assert!(compaction_pressure(5000, 4096));
    }

    #[test]
    fn derived_sizing_satisfies_all_dimensions_and_clamps() {
        let floor = CompactionSizing {
            rows: 40_000,
            bytes: 32 << 20,
            objects: 32,
        };
        let ceiling = CompactionSizing {
            rows: 1_000_000,
            bytes: 1 << 30,
            objects: 4096,
        };
        let raised = floor.raised(25.0 / 60.0, 2000.0, 248.0, 100, ceiling);
        assert!(raised.rows >= 400_000);
        assert!(raised.bytes >= 99_200_000);
        assert!(raised.objects >= 84);
        assert_eq!(raised.raised(0.0, 0.0, 0.0, 100, ceiling), raised);
        assert_eq!(floor.raised(1e9, 1e9, 1e9, 300, ceiling), ceiling);
    }

    #[tokio::test]
    async fn uploads_are_bounded_and_finish_after_a_sibling_failure() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let work = (0..12).map(|index| {
            let (active, peak, finished) = (active.clone(), peak.clone(), finished.clone());
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
                finished.fetch_add(1, Ordering::SeqCst);
                if index == 0 {
                    bail!("injected upload failure");
                }
                Ok(index)
            }
        });
        assert!(publish_bounded(work, 4).await.is_err());
        assert_eq!(finished.load(Ordering::SeqCst), 12);
        assert_eq!(peak.load(Ordering::SeqCst), 4);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
