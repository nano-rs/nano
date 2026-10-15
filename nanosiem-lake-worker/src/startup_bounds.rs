// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2823: named startup-bound checks for the lake-worker binaries.
//!
//! Every lake binary validates its CLI resource/poll bounds once at startup.
//! Those checks used to be one combined `if a || b || c { bail!("... bound is
//! invalid") }`, so a crash-looping pod said only that *something* was wrong
//! (the 2026-09-24 generation-publisher loop needed a source read to find
//! `--hot-tail-max-objects 4096 + --hot-tail-committed-max-objects 4096`).
//!
//! [`BoundChecks`] evaluates each bound as a separate named check and reports
//! EVERY failing one with its flag, value and allowed range:
//!
//! ```text
//! invalid bounds: --poll-seconds 0 is outside 0.1..=300; --max-objects 0 is outside 1..=4096
//! ```
//!
//! It only changes the message: a configuration is rejected exactly when at
//! least one check fails, which is exactly when the old combined predicate
//! was true. Each binary pins that equivalence with a table test against a
//! copy of its old predicate.

use crate::bounds::HOT_TAIL_OBJECT_FORMAT_CEILING;
use crate::generation::{COUNT_ROLLUP_LANE_MEMORY_BYTES, MAX_KEYWORD_PRODUCER_CEILING};
use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::RangeInclusive;

/// Accumulates named bound violations; see the module docs.
#[derive(Debug, Default)]
#[must_use = "call `finish()` or inspect `violations()`; dropping the checks ignores them"]
pub struct BoundChecks {
    violations: Vec<String>,
}

impl BoundChecks {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `describe()` as a violation when `ok` is false.
    pub fn require(&mut self, ok: bool, describe: impl FnOnce() -> String) -> &mut Self {
        if !ok {
            self.violations.push(describe());
        }
        self
    }

    /// `flag value` must lie in `range` (inclusive). Uses `RangeInclusive::
    /// contains`, so a NaN float is rejected, as it was by the old checks.
    pub fn in_range<T: PartialOrd + Display>(
        &mut self,
        flag: &str,
        value: T,
        range: RangeInclusive<T>,
    ) -> &mut Self {
        if !range.contains(&value) {
            self.violations.push(format!(
                "{flag} {value} is outside {}..={}",
                range.start(),
                range.end()
            ));
        }
        self
    }

    /// `flag value` must be at most `max` (for bounds with no lower limit).
    pub fn at_most<T: PartialOrd + Display>(&mut self, flag: &str, value: T, max: T) -> &mut Self {
        // `partial_cmp` so NaN (unordered) is rejected too.
        if !matches!(
            value.partial_cmp(&max),
            Some(Ordering::Less | Ordering::Equal)
        ) {
            self.violations
                .push(format!("{flag} {value} exceeds the maximum {max}"));
        }
        self
    }

    pub fn violations(&self) -> &[String] {
        &self.violations
    }

    pub fn into_violations(self) -> Vec<String> {
        self.violations
    }

    /// `Ok(())` when every check passed, else one error naming every failure.
    pub fn finish(self) -> anyhow::Result<()> {
        bounds_result(self.violations)
    }
}

/// Formats a violation list as the single startup error (or `Ok` if empty).
pub fn bounds_result(violations: Vec<String>) -> anyhow::Result<()> {
    if violations.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("invalid bounds: {}", violations.join("; "))
    }
}

/// Hot-tail tier partition (NAN-2361): the staged and committed object
/// budgets share one object-format ceiling. Rejects exactly when
/// `committed > ceiling || staged.saturating_add(committed) > ceiling`; the
/// sum is only reported when `committed` alone fits, so one cause yields one
/// message.
pub fn check_hot_tail_partition(
    checks: &mut BoundChecks,
    staged_flag: &str,
    staged: usize,
    committed_flag: &str,
    committed: usize,
) {
    let ceiling = HOT_TAIL_OBJECT_FORMAT_CEILING as usize;
    checks.at_most(committed_flag, committed, ceiling);
    checks.require(
        committed > ceiling || staged.saturating_add(committed) <= ceiling,
        || {
            format!(
                "{staged_flag} {staged} + {committed_flag} {committed} exceeds the \
                 {ceiling} object-format ceiling"
            )
        },
    );
}

/// Thread / heap / derivative-memory bounds shared by `lake_sidecar_build`
/// and `lake_generation_manage` (which spawns it with the same flags).
#[derive(Clone, Debug)]
pub struct DerivativeBuildBounds {
    pub threads: usize,
    pub count_rollup_threads: usize,
    pub keyword_producer_ceiling: usize,
    pub derivative_build_memory_bytes: u64,
    pub heap_bytes: usize,
}

impl DerivativeBuildBounds {
    /// Count-rollup lanes reserve `COUNT_ROLLUP_LANE_MEMORY_BYTES` each. The
    /// callers already reject an overflowing product with a `checked_mul`, so
    /// saturating here never changes a verdict.
    pub fn count_rollup_reservation(&self) -> u64 {
        (self.count_rollup_threads as u64).saturating_mul(COUNT_ROLLUP_LANE_MEMORY_BYTES)
    }

    pub fn check(&self, checks: &mut BoundChecks) {
        checks
            .in_range("--threads", self.threads, 1..=256)
            .require(self.count_rollup_threads >= 1, || {
                "--count-rollup-threads 0 must be at least 1".to_string()
            })
            .require(self.count_rollup_threads <= self.threads, || {
                format!(
                    "--count-rollup-threads {} exceeds --threads {}",
                    self.count_rollup_threads, self.threads
                )
            })
            .in_range(
                "--keyword-producer-ceiling",
                self.keyword_producer_ceiling,
                1..=MAX_KEYWORD_PRODUCER_CEILING,
            )
            .in_range(
                "--derivative-build-memory-bytes",
                self.derivative_build_memory_bytes,
                COUNT_ROLLUP_LANE_MEMORY_BYTES..=64_000_000_000,
            );
        let reservation = self.count_rollup_reservation();
        checks
            .require(reservation <= self.derivative_build_memory_bytes, || {
                format!(
                    "--count-rollup-threads {} reserves {reservation} bytes \
                     ({COUNT_ROLLUP_LANE_MEMORY_BYTES} per lane), exceeding \
                     --derivative-build-memory-bytes {}",
                    self.count_rollup_threads, self.derivative_build_memory_bytes
                )
            })
            .in_range("--heap-bytes", self.heap_bytes, 15_000_000..=64_000_000_000);
    }
}

/// Batch/poll bounds shared by the risk and event publishers.
#[derive(Clone, Debug)]
pub struct PublisherBatchBounds {
    pub batch_size: i64,
    pub poll_seconds: f64,
}

impl PublisherBatchBounds {
    pub fn check(&self) -> BoundChecks {
        let mut checks = BoundChecks::new();
        checks
            .in_range("--batch-size", self.batch_size, 1..=10_000)
            .in_range("--poll-seconds", self.poll_seconds, 0.1..=300.0);
        checks
    }
}

/// One named mutation of a bounds struct, for [`assert_same_accept_set`].
pub type BoundMutation<T> = (String, Box<dyn Fn(&mut T)>);

/// Builds `Vec<BoundMutation<T>>` from `field => [values...]` lists.
#[macro_export]
macro_rules! bound_mutations {
    ($ty:ty; $($field:ident => [$($value:expr),* $(,)?]),* $(,)?) => {{
        let mut out: Vec<$crate::startup_bounds::BoundMutation<$ty>> = Vec::new();
        $($({
            let value = $value;
            out.push((
                format!("{}={:?}", stringify!($field), value),
                Box::new(move |bounds: &mut $ty| bounds.$field = value.clone()),
            ));
        })*)*
        out
    }};
}

/// Test support (NAN-2823): proves a named-check rewrite accepts exactly the
/// configurations its old combined predicate accepted. Applies every single
/// mutation and every ordered pair of mutations to `base` and asserts both
/// verdicts agree; returns `(accepted, rejected)` case counts. Lives outside
/// `cfg(test)` because binary test modules link the non-test library.
#[doc(hidden)]
pub fn assert_same_accept_set<T: Clone>(
    base: &T,
    mutations: &[BoundMutation<T>],
    new_accepts: impl Fn(&T) -> bool,
    legacy_accepts: impl Fn(&T) -> bool,
) -> (usize, usize) {
    assert!(
        legacy_accepts(base),
        "base case must be valid under the legacy predicate"
    );
    assert!(
        new_accepts(base),
        "base case must be valid under the named checks"
    );
    let (mut accepted, mut rejected) = (0, 0);
    for (first_name, first) in mutations {
        for (second_name, second) in mutations {
            let mut case = base.clone();
            first(&mut case);
            second(&mut case);
            let legacy = legacy_accepts(&case);
            assert_eq!(
                new_accepts(&case),
                legacy,
                "verdict changed for {first_name}, {second_name}"
            );
            if legacy {
                accepted += 1;
            } else {
                rejected += 1;
            }
        }
    }
    assert!(
        accepted > 0 && rejected > 0,
        "table must cover both verdicts"
    );
    (accepted, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_when_every_check_passes() {
        let mut checks = BoundChecks::new();
        checks
            .in_range("--a", 5_u64, 1..=10)
            .in_range("--f", 0.1_f64, 0.1..=300.0)
            .at_most("--m", 4_u64, 4)
            .require(true, || "never".to_string());
        assert!(checks.violations().is_empty());
        checks.finish().expect("valid bounds");
    }

    #[test]
    fn names_every_failure_with_flag_value_and_range() {
        let mut checks = BoundChecks::new();
        checks
            .in_range("--poll-seconds", 0.0_f64, 0.1..=300.0)
            .in_range("--max-objects", 0_usize, 1..=4_096)
            .at_most("--committed", 5_000_usize, 4_096)
            .in_range("--ok", 3_u64, 1..=3)
            .require(false, || "--a 1 + --b 2 exceeds 2".to_string());
        let error = checks.finish().expect_err("invalid").to_string();
        assert_eq!(
            error,
            "invalid bounds: --poll-seconds 0 is outside 0.1..=300; \
             --max-objects 0 is outside 1..=4096; \
             --committed 5000 exceeds the maximum 4096; \
             --a 1 + --b 2 exceeds 2"
        );
    }

    #[test]
    fn nan_is_rejected() {
        let mut checks = BoundChecks::new();
        checks
            .in_range("--poll-seconds", f64::NAN, 0.1..=300.0)
            .at_most("--x", f64::NAN, 1.0);
        assert_eq!(checks.into_violations().len(), 2);
    }
}
