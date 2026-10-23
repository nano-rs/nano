// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3403: bounds on query[T]'s arrival (incremental) prewarm.
//!
//! Since NAN-3392 the part-log view is caught up every 500 ms in the
//! background, so every ingest flush and every merge commit became its own
//! advance and its own full prewarm pass (~5/min on the load-test tenant, against ~0.8 on
//! r11, when only requests and wakes caught up). Each pass re-walked every
//! hot-window data file: a writer-copy admission check, a producer-copy
//! check and a lease, i.e. 2-3 reader-cache hits per file per pass, which
//! drove the cache's per-hit bit-rot sample to re-hash the whole window every
//! few minutes inside the 4 GiB query role.
//!
//! - [`PrewarmLedger`]: digests a pass already leased; later passes skip
//!   them.
//! - [`PrewarmPacer`]: at most one incremental pass per
//!   [`PREWARM_MIN_INTERVAL_ENV`] (default 60 s); arrivals inside the
//!   interval coalesce into one trailing pass.
//!
//! Results never depend on either: a query over a part the prewarm has not
//! reached proves and leases its own files (NAN-2984).
//!
//! Kill switch: `NANO_LAKE_PREWARM_THROTTLE=0` restores the pre-NAN-3403
//! behavior (a pass per advance over every file). Both are read once.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The kill switch (see the module docs): `0` turns both bounds off.
pub const PREWARM_THROTTLE_ENV: &str = "NANO_LAKE_PREWARM_THROTTLE";
/// Minimum seconds between incremental prewarm passes (`0`: no gap, still
/// coalesced while one is pending).
pub const PREWARM_MIN_INTERVAL_ENV: &str = "NANO_LAKE_PREWARM_MIN_INTERVAL_SECONDS";
const DEFAULT_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Whether the NAN-3403 bounds apply (unset or anything but `0`: on).
pub fn throttle_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| parse_throttle(std::env::var(PREWARM_THROTTLE_ENV).ok().as_deref()))
}

fn parse_throttle(value: Option<&str>) -> bool {
    value.map(str::trim) != Some("0")
}

/// The configured gap between incremental passes.
pub fn min_interval() -> Duration {
    parse_min_interval(std::env::var(PREWARM_MIN_INTERVAL_ENV).ok().as_deref())
}

fn parse_min_interval(value: Option<&str>) -> Duration {
    value.and_then(|value| value.trim().parse::<u64>().ok()).map_or(DEFAULT_MIN_INTERVAL, Duration::from_secs)
}

/// Data/sidecar digests an earlier prewarm pass of this process already
/// leased.
#[derive(Debug, Default)]
pub struct PrewarmLedger {
    done: Mutex<HashSet<String>>,
}

impl PrewarmLedger {
    /// Must a pass touch `sha256`? Yes when no earlier pass finished it.
    pub fn needs(&self, sha256: &str) -> bool {
        !self.done.lock().unwrap_or_else(|e| e.into_inner()).contains(sha256)
    }

    /// A pass leased these digests.
    pub fn record<'a>(&self, digests: impl IntoIterator<Item = &'a str>) {
        self.done.lock().unwrap_or_else(|e| e.into_inner()).extend(digests.into_iter().map(str::to_owned));
    }

    /// Forget digests no longer in the live set (bounds the ledger).
    pub fn retain_live(&self, live: &HashSet<&str>) {
        self.done.lock().unwrap_or_else(|e| e.into_inner()).retain(|digest| live.contains(digest.as_str()));
    }

    pub fn len(&self) -> usize {
        self.done.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// At most one incremental prewarm pass per `min_interval`, coalescing
/// arrivals: while a pass is scheduled, further requests join it.
#[derive(Debug)]
pub struct PrewarmPacer {
    min_interval: Duration,
    state: Mutex<PacerState>,
}

#[derive(Debug, Default)]
struct PacerState {
    pending: bool,
    last_started: Option<Instant>,
}

impl PrewarmPacer {
    pub fn new(min_interval: Duration) -> Self {
        Self { min_interval, state: Mutex::default() }
    }

    /// A pass is wanted at `now`. `None`: one is already scheduled and will
    /// cover this request. `Some(delay)`: schedule a pass after `delay`
    /// (zero when the last pass started at least `min_interval` ago).
    pub fn request(&self, now: Instant) -> Option<Duration> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.pending {
            return None;
        }
        state.pending = true;
        Some(state.last_started.map_or(Duration::ZERO, |last| {
            (last + self.min_interval).saturating_duration_since(now)
        }))
    }

    /// The scheduled pass starts at `now`: later requests schedule the next.
    pub fn start(&self, now: Instant) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.pending = false;
        state.last_started = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_runs_the_first_pass_at_once_and_coalesces_while_pending() {
        let pacer = PrewarmPacer::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(pacer.request(t0), Some(Duration::ZERO));
        assert_eq!(pacer.request(t0 + Duration::from_secs(1)), None, "joins the scheduled pass");
        pacer.start(t0 + Duration::from_secs(1));
        // Arrivals every 14 s (the load-test tenant's flush + merge rate) during the
        // interval schedule ONE trailing pass, not one each.
        assert_eq!(pacer.request(t0 + Duration::from_secs(15)), Some(Duration::from_secs(46)));
        for at in [29, 43, 57] {
            assert_eq!(pacer.request(t0 + Duration::from_secs(at)), None);
        }
        pacer.start(t0 + Duration::from_secs(61));
        assert_eq!(pacer.request(t0 + Duration::from_secs(200)), Some(Duration::ZERO), "idle long enough: at once");
    }

    /// Before NAN-3403 every advance was its own pass: 14 s arrivals over
    /// 10 min were ~43 passes. With the pacer at most 1 + 10 run.
    #[test]
    fn pacer_bounds_passes_per_interval() {
        let pacer = PrewarmPacer::new(Duration::from_secs(60));
        let t0 = Instant::now();
        let mut next_run: Option<Instant> = None;
        let mut runs = 0;
        let mut at = t0;
        while at < t0 + Duration::from_secs(600) {
            if let Some(due) = next_run.filter(|due| *due <= at) {
                pacer.start(due);
                runs += 1;
                next_run = None;
            }
            if let Some(delay) = pacer.request(at) {
                next_run = Some(at + delay);
            }
            at += Duration::from_secs(14);
        }
        assert!(runs <= 11, "{runs} passes in 10 min");
        assert!(runs >= 9, "arrivals are still prewarmed about once a minute ({runs})");
    }

    #[test]
    fn zero_interval_still_coalesces_pending_requests() {
        let pacer = PrewarmPacer::new(Duration::ZERO);
        let t0 = Instant::now();
        assert_eq!(pacer.request(t0), Some(Duration::ZERO));
        assert_eq!(pacer.request(t0), None);
        pacer.start(t0);
        assert_eq!(pacer.request(t0), Some(Duration::ZERO));
    }

    #[test]
    fn ledger_skips_done_digests_until_their_proof_goes_stale() {
        let ledger = PrewarmLedger::default();
        assert!(ledger.needs("a"), "never prewarmed");
        ledger.record(["a", "b"]);
        assert!(!ledger.needs("a"), "leased by an earlier pass");
        ledger.retain_live(&HashSet::from(["b"]));
        assert!(ledger.needs("a"), "superseded digests are forgotten");
        assert!(!ledger.needs("b"));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn env_parsing() {
        assert!(parse_throttle(None));
        assert!(parse_throttle(Some("1")));
        assert!(!parse_throttle(Some("0")));
        assert!(!parse_throttle(Some(" 0 ")));
        assert_eq!(parse_min_interval(None), DEFAULT_MIN_INTERVAL);
        assert_eq!(parse_min_interval(Some("15")), Duration::from_secs(15));
        assert_eq!(parse_min_interval(Some("0")), Duration::ZERO);
        assert_eq!(parse_min_interval(Some("x")), DEFAULT_MIN_INTERVAL);
    }
}
