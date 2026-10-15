// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3522 over-commit hold: a token bucket on the rows `ingest[T]` admits.
//!
//! A tenant held at its abuse ceiling keeps ingesting at the hold rate; the
//! rest of what it sends stays in its edge log / Bronze (never dropped) and
//! drains at that rate. The bucket only pauses ADMISSION: due flushes,
//! acks, merges and GC run every tick as usual, so nothing admitted waits on
//! the hold and nothing unacknowledged is lost by it.
//!
//! Rows are known only after an admission decodes its objects, so the cell
//! turns the tokens into a source-byte budget with the observed bytes per
//! row: an admission takes its first object plus whatever fits the budget.
//! It may still overdraw the bucket (debt) by up to one object; admission
//! then stays paused until the debt is repaid at the hold rate. Over time
//! the admitted rate is the hold rate. One large object at a low rate is
//! hours of debt; the stall watchdog does not count that paused time
//! (`stall_watchdog::note_hold_pause`).

use std::time::{Duration, Instant};

/// Seconds of hold-rate rows the bucket holds when full (burst allowance).
/// the platform's design doc (NAN-3522 §4) quotes this value.
pub const HOLD_BURST_SECS: f64 = 10.0;

#[derive(Debug, Clone)]
pub struct IngestHold {
    eps: f64,
    capacity: f64,
    tokens: f64,
    at: Instant,
    /// Observed source bytes per admitted row (EWMA); None until measured.
    bytes_per_row: Option<f64>,
}

impl IngestHold {
    /// `None` for no hold, or a rate that would stall ingest (the placement
    /// validates `≥ 1`; a non-finite or non-positive value is ignored here
    /// too, so a hold can never stop ingest).
    pub fn new(eps: Option<f64>, now: Instant) -> Option<Self> {
        let eps = eps.filter(|e| e.is_finite() && *e > 0.0)?;
        let capacity = (eps * HOLD_BURST_SECS).max(1.0);
        Some(Self { eps, capacity, tokens: capacity, at: now, bytes_per_row: None })
    }

    pub fn eps(&self) -> f64 {
        self.eps
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.eps).min(self.capacity);
        self.at = now;
    }

    /// May the next tick admit? (No debt outstanding.)
    pub fn may_admit(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= 0.0
    }

    /// Charge an admission's rows (may go into debt) and learn its bytes per row.
    pub fn spend(&mut self, rows: u64, bytes: u64, now: Instant) {
        self.refill(now);
        self.tokens -= rows as f64;
        if rows > 0 && bytes > 0 {
            let sample = bytes as f64 / rows as f64;
            self.bytes_per_row = Some(self.bytes_per_row.map_or(sample, |prev| prev * 0.8 + sample * 0.2));
        }
    }

    /// The source bytes the next admission may take beyond its first object:
    /// the tokens at the observed bytes per row (0 until measured, so an
    /// admission takes one object until then).
    pub fn byte_budget(&mut self, now: Instant) -> u64 {
        self.refill(now);
        match self.bytes_per_row {
            Some(bpr) if self.tokens > 0.0 => (self.tokens * bpr) as u64,
            _ => 0,
        }
    }

    /// How long until admission may resume (zero when it may now).
    pub fn wait(&mut self, now: Instant) -> Duration {
        self.refill(now);
        if self.tokens >= 0.0 { Duration::ZERO } else { Duration::from_secs_f64(-self.tokens / self.eps) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_hold_or_a_stalling_rate_is_no_bucket() {
        let now = Instant::now();
        assert!(IngestHold::new(None, now).is_none());
        assert!(IngestHold::new(Some(0.0), now).is_none());
        assert!(IngestHold::new(Some(-5.0), now).is_none());
        assert!(IngestHold::new(Some(f64::NAN), now).is_none());
        assert!(IngestHold::new(Some(f64::INFINITY), now).is_none());
    }

    #[test]
    fn debt_pauses_admission_until_repaid_at_the_hold_rate() {
        let t0 = Instant::now();
        let mut h = IngestHold::new(Some(100.0), t0).unwrap();
        assert!(h.may_admit(t0));
        // One admission of 3,000 rows: 1,000 burst + 2,000 debt = 20 s.
        h.spend(3_000, 0, t0);
        assert!(!h.may_admit(t0));
        assert_eq!(h.wait(t0).as_secs(), 20);
        assert!(!h.may_admit(t0 + Duration::from_secs(19)));
        assert!(h.may_admit(t0 + Duration::from_secs(20)));
    }

    #[test]
    fn the_long_run_admitted_rate_is_the_hold_rate_and_never_zero() {
        // Simulate 1 s ticks admitting 5,000-row batches whenever allowed for
        // one hour at a 630 eps hold: admitted ≈ 630 × 3,600 (+ ≤ one batch + burst).
        let t0 = Instant::now();
        let mut h = IngestHold::new(Some(630.0), t0).unwrap();
        let mut admitted = 0_u64;
        for s in 0..3_600 {
            let now = t0 + Duration::from_secs(s);
            if h.may_admit(now) {
                h.spend(5_000, 0, now);
                admitted += 5_000;
            }
        }
        let target = 630.0 * 3_600.0;
        assert!(admitted as f64 >= target * 0.98, "admitted {admitted}: the backlog must keep draining");
        assert!(admitted as f64 <= target + 5_000.0 + 6_300.0, "admitted {admitted}: above the hold");
    }

    #[test]
    fn idle_time_does_not_bank_more_than_the_burst() {
        let t0 = Instant::now();
        let mut h = IngestHold::new(Some(10.0), t0).unwrap();
        // A day idle banks only 10 s of rows.
        let later = t0 + Duration::from_secs(86_400);
        h.spend(101, 0, later);
        assert!(!h.may_admit(later));
    }

    #[test]
    fn the_byte_budget_follows_the_tokens_at_the_observed_bytes_per_row() {
        let t0 = Instant::now();
        let mut h = IngestHold::new(Some(1_000.0), t0).unwrap();
        // Not measured yet: one object per admission.
        assert_eq!(h.byte_budget(t0), 0);
        // 2,000 rows from 400 kB: 200 B/row; 8,000 tokens left = 1.6 MB.
        h.spend(2_000, 400_000, t0);
        assert_eq!(h.byte_budget(t0), 1_600_000);
        // In debt: no budget (and admission pauses).
        h.spend(9_000, 1_800_000, t0);
        assert_eq!(h.byte_budget(t0), 0);
        assert!(!h.may_admit(t0));
    }
}
