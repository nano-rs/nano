// SPDX-License-Identifier: AGPL-3.0-or-later

//! ingest[T] edge-log stall watchdog.
//!
//! A lean test tenant (2026-09-29): the edge log's committed point stopped
//! at 30321 with the head at 30389. The process sat there, alive and
//! heartbeating, until someone noticed. This watchdog runs OUTSIDE the ingest
//! loop. When the committed point has not advanced for
//! [`EDGE_STALL_RESTART_AFTER`] while the edge holds data past it, and the loop
//! has made no other progress, it reports the stall and the caller restarts
//! the process. The supervisor respawns it with a fresh bootstrap, and unacked
//! edge segments replay.
//!
//! NAN-3387 (the load-test tenant, 2026-10-08): a loop that is still fetching from the
//! store for admission is not wedged, and restarting it only redoes the same
//! work. Progress the loop reports through [`note_progress`] defers the
//! restart, up to [`EDGE_STALL_HARD_AFTER`] without a committed advance. Past
//! that the watchdog fires anyway, so the deferral stays bounded.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::edge_log::EdgeLogStatus;

/// No committed progress and no loop progress, with data pending, for this
/// long: restart.
pub const EDGE_STALL_RESTART_AFTER: Duration = Duration::from_secs(15 * 60);

/// No committed progress with data pending for this long: restart, even if
/// the loop is still reporting progress.
pub const EDGE_STALL_HARD_AFTER: Duration = Duration::from_secs(45 * 60);

/// How often the watchdog samples the edge-log position.
pub const EDGE_STALL_SAMPLE_EVERY: Duration = Duration::from_secs(30);

/// Process-wide count of ingest-loop store progress (one ingest per process).
static PROGRESS: AtomicU64 = AtomicU64::new(0);

/// Record one unit of ingest-loop progress that does not move the committed
/// point yet (e.g. a part fetched to prepare the dedup window).
pub fn note_progress() {
    PROGRESS.fetch_add(1, Ordering::Relaxed);
}

/// The progress counter [`note_progress`] advances.
pub fn progress() -> u64 {
    PROGRESS.load(Ordering::Relaxed)
}

/// NAN-3522: process-wide count of ticks whose admission the over-commit
/// hold paused (its token bucket in debt).
static HOLD_PAUSES: AtomicU64 = AtomicU64::new(0);

/// Record one tick whose admission the over-commit hold paused. At a low
/// hold rate one large object is hours of debt, during which the committed
/// point cannot move: that time is the hold working, not a wedge, so it
/// never counts toward either bound. It does not reset the hard bound
/// either: un-paused stuck time before and after pauses still adds up to
/// [`EDGE_STALL_HARD_AFTER`]. A loop that stops ticking stops noting pauses,
/// and the watchdog runs as usual.
pub fn note_hold_pause() {
    HOLD_PAUSES.fetch_add(1, Ordering::Relaxed);
}

/// The counter [`note_hold_pause`] advances.
pub fn hold_pauses() -> u64 {
    HOLD_PAUSES.load(Ordering::Relaxed)
}

/// Committed-point progress tracking (pure; the caller samples).
#[derive(Debug)]
pub struct EdgeStallWatchdog {
    stall_after: Duration,
    hard_after: Duration,
    committed: Option<u64>,
    head: u64,
    progress: Option<u64>,
    /// Since when `committed` has not moved.
    since: Instant,
    /// Since when neither `committed` nor `progress` has moved.
    active_since: Instant,
    /// The last sample or pause, so a pause knows which interval it covers.
    last_seen: Instant,
}

impl EdgeStallWatchdog {
    pub fn new(stall_after: Duration, hard_after: Duration, now: Instant) -> Self {
        Self { stall_after, hard_after: hard_after.max(stall_after), committed: None, head: 0, progress: None, since: now, active_since: now, last_seen: now }
    }

    /// NAN-3522: the over-commit hold paused admission since the last
    /// sample. That interval is never a stall: it restarts the soft clock
    /// (the loop is doing its job) and is excluded from the hard clock,
    /// which is shifted forward by it rather than restarted, so the hard
    /// bound still holds across pauses.
    pub fn hold_paused(&mut self, now: Instant) {
        let paused = now.saturating_duration_since(self.last_seen);
        self.since = (self.since + paused).min(now);
        self.active_since = now;
        self.last_seen = now;
    }

    /// Feed one sample (`None`: the position could not be read without
    /// waiting, e.g. a pull in flight; it counts as no committed progress)
    /// together with the loop's progress counter. Returns the stall
    /// description once the committed point has been stuck while the head
    /// was past it, for `stall_after` with no loop progress either, or for
    /// `hard_after` regardless of it.
    pub fn observe(&mut self, sample: Option<(u64, u64)>, progress: u64, now: Instant) -> Option<String> {
        self.last_seen = now;
        if let Some((head, committed)) = sample {
            self.head = self.head.max(head);
            if self.committed != Some(committed) {
                self.committed = Some(committed);
                self.since = now;
                self.active_since = now;
            }
        }
        if self.progress.is_some_and(|seen| seen != progress) {
            self.active_since = now;
        }
        self.progress = Some(progress);
        let committed = self.committed?;
        if self.head <= committed {
            // Caught up (or idle): nothing is waiting.
            self.since = now;
            self.active_since = now;
            return None;
        }
        let stuck = now.saturating_duration_since(self.since);
        let idle = now.saturating_duration_since(self.active_since);
        let pending = self.head - committed;
        if stuck >= self.hard_after {
            return Some(format!(
                "edge log committed point stuck at {committed} for {}s with head {} ({pending} segments pending; loop progress did not commit)",
                stuck.as_secs(), self.head,
            ));
        }
        (idle >= self.stall_after).then(|| format!(
            "edge log committed point stuck at {committed} for {}s with head {} ({pending} segments pending)",
            stuck.as_secs(), self.head,
        ))
    }
}

/// `(head, committed_through)` of a status.
pub fn position(status: &EdgeLogStatus) -> (u64, u64) {
    (status.head, status.committed_through)
}

/// Sample `probe` (and `progress`) every `every` until the watchdog fires;
/// returns the stall.
pub async fn watch<F, Fut, P>(stall_after: Duration, hard_after: Duration, every: Duration, mut probe: F, progress: P) -> String
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<(u64, u64)>>,
    P: Fn() -> u64,
{
    let mut watchdog = EdgeStallWatchdog::new(stall_after, hard_after, Instant::now());
    let mut pauses = hold_pauses();
    loop {
        tokio::time::sleep(every).await;
        let now_pauses = hold_pauses();
        if now_pauses != pauses {
            pauses = now_pauses;
            watchdog.hold_paused(Instant::now());
        }
        let sample = probe().await;
        if let Some(stall) = watchdog.observe(sample, progress(), Instant::now()) {
            return stall;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_only_when_stuck_with_data_pending() {
        let t0 = Instant::now();
        let after = Duration::from_secs(600);
        let mut dog = EdgeStallWatchdog::new(after, after * 3, t0);
        assert!(dog.observe(None, 0, t0 + after * 2).is_none(), "no position known yet");
        assert!(dog.observe(Some((100, 100)), 0, t0).is_none());
        // Idle and caught up for a long time: fine.
        assert!(dog.observe(Some((100, 100)), 0, t0 + after * 3).is_none());
        // New data arrives and the consumer keeps committing: fine.
        let t1 = t0 + after * 3;
        assert!(dog.observe(Some((150, 120)), 0, t1 + Duration::from_secs(60)).is_none());
        assert!(dog.observe(Some((200, 180)), 0, t1 + Duration::from_secs(500)).is_none());
        // The live wedge: head 30389 vs committed 30321, then silence.
        let t2 = t1 + Duration::from_secs(600);
        assert!(dog.observe(Some((30_389, 30_321)), 0, t2).is_none());
        assert!(dog.observe(None, 0, t2 + after - Duration::from_secs(1)).is_none());
        let stall = dog.observe(None, 0, t2 + after).expect("fires after stall_after");
        assert!(stall.contains("30321") && stall.contains("30389"), "{stall}");
        // Progress resets it.
        assert!(dog.observe(Some((30_400, 30_389)), 0, t2 + after + Duration::from_secs(1)).is_none());
    }

    /// NAN-3387: the load-test tenant was killed at 900 s while it was still fetching
    /// parts for a backfill's dedup window, and every respawn redid the same
    /// fetches. Loop progress defers the restart, but only up to `hard_after`.
    #[test]
    fn loop_progress_defers_the_restart_but_only_up_to_the_hard_bound() {
        let t0 = Instant::now();
        let after = Duration::from_secs(900);
        let hard = Duration::from_secs(2_700);
        let mut dog = EdgeStallWatchdog::new(after, hard, t0);
        assert!(dog.observe(Some((130_863, 130_844)), 10, t0).is_none());
        // Fetching steadily: past `stall_after` without a commit, no restart.
        let mut progress = 10;
        let mut t = t0;
        while t < t0 + hard - Duration::from_secs(60) {
            t += Duration::from_secs(30);
            progress += 60;
            assert!(dog.observe(Some((130_863, 130_844)), progress, t).is_none(), "fired at {:?} while fetching", t - t0);
        }
        assert!(t - t0 > after, "the loop outlived the old 900 s kill");
        // Still fetching, but never committing: the hard bound fires.
        let stall = dog.observe(Some((130_863, 130_844)), progress + 60, t0 + hard).expect("hard bound");
        assert!(stall.contains("130844") && stall.contains("did not commit"), "{stall}");

        // Progress that stops is a stall again after `stall_after`.
        let mut dog = EdgeStallWatchdog::new(after, hard, t0);
        assert!(dog.observe(Some((50, 40)), 1, t0).is_none());
        assert!(dog.observe(Some((50, 40)), 2, t0 + Duration::from_secs(600)).is_none());
        assert!(dog.observe(Some((50, 40)), 2, t0 + Duration::from_secs(600) + after - Duration::from_secs(1)).is_none());
        assert!(dog.observe(Some((50, 40)), 2, t0 + Duration::from_secs(600) + after).is_some());
    }

    /// NAN-3522: a held tenant at 1.5 eps that admitted one 20k-row object is
    /// ~3.7 h in debt; the committed point cannot move meanwhile. Paused
    /// time never fires either bound; once the pauses stop, the bounds apply.
    #[test]
    fn hold_pauses_are_never_a_stall_but_the_bounds_resume_after() {
        let t0 = Instant::now();
        let (after, hard) = (Duration::from_secs(900), Duration::from_secs(2_700));
        let mut dog = EdgeStallWatchdog::new(after, hard, t0);
        assert!(dog.observe(Some((500, 400)), 0, t0).is_none());
        let mut t = t0;
        while t < t0 + Duration::from_secs(4 * 3_600) {
            t += Duration::from_secs(30);
            dog.hold_paused(t);
            assert!(dog.observe(Some((500, 400)), 0, t).is_none(), "fired at {:?} while held", t - t0);
        }
        // The pauses stop and nothing commits: the soft bound fires again.
        assert!(dog.observe(Some((500, 400)), 0, t + after - Duration::from_secs(1)).is_none());
        assert!(dog.observe(Some((500, 400)), 0, t + after).is_some());
    }

    /// The hard bound is not reset by pauses: 20 min stuck (with loop
    /// progress), 4 h held, then stuck again fires 25 min later, at 45 min of
    /// un-paused stuck time.
    #[test]
    fn hold_pauses_do_not_reset_the_hard_bound() {
        let t0 = Instant::now();
        let step = Duration::from_secs(30);
        let (after, hard) = (Duration::from_secs(900), Duration::from_secs(2_700));
        let mut dog = EdgeStallWatchdog::new(after, hard, t0);
        let (mut t, mut progress) = (t0, 0);
        assert!(dog.observe(Some((500, 400)), progress, t).is_none());
        let mut run = |dog: &mut EdgeStallWatchdog, t: &mut Instant, progress: &mut u64, until: Instant| {
            while *t + step <= until {
                *t += step;
                *progress += 1;
                assert!(dog.observe(Some((500, 400)), *progress, *t).is_none(), "fired at {:?}", *t - t0);
            }
        };
        run(&mut dog, &mut t, &mut progress, t0 + Duration::from_secs(20 * 60));
        let held_from = t;
        while t < held_from + Duration::from_secs(4 * 3_600) {
            t += step;
            dog.hold_paused(t);
            assert!(dog.observe(Some((500, 400)), progress, t).is_none(), "fired at {:?} while held", t - t0);
        }
        let resumed = t;
        run(&mut dog, &mut t, &mut progress, resumed + Duration::from_secs(25 * 60) - step);
        assert!(dog.observe(Some((500, 400)), progress + 1, resumed + Duration::from_secs(25 * 60)).is_some());
    }

    #[tokio::test]
    async fn the_watch_loop_fires_for_a_wedged_consumer() {
        let samples = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = samples.clone();
        let stall = tokio::time::timeout(Duration::from_secs(5), watch(Duration::from_millis(200), Duration::from_secs(60), Duration::from_millis(20), move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Some((30_389, 30_321)) }
        }, || 7)).await.expect("the watchdog fires");
        assert!(stall.contains("stuck at 30321"));
        assert!(samples.load(std::sync::atomic::Ordering::SeqCst) >= 10);
    }
}
