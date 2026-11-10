// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded execution of tenant-authored VRL for parser tests (security review
//! 2026-11-08, NAN-5040; process isolation NAN-5234).
//!
//! `test-vrl`, `test-live` and the AI parser loops run a draft program against
//! sample events. That used to call `Runtime::resolve` synchronously on a tokio
//! worker with no time bound: a nested `for_each` over a large split sample
//! pinned the worker until it finished, and about `nproc` such requests
//! stalled every other handler on the replica. Now:
//!
//! - execution runs in a one-shot, resource-limited worker process
//!   ([`crate::parsers::test_sandbox`], NAN-5234), never in the API process,
//!   so a program that allocates without limit is stopped by the worker's
//!   memory bound instead of exhausting the replica;
//! - every resolve carries an [`ExecutionBudget`]: VRL checks it between
//!   expressions (closure bodies included), and once the request's wall-clock
//!   budget is spent the program stops with a clear error;
//! - sample size, count and total size are capped ([`check_samples`]), which
//!   bounds the single non-preemptible function calls (one regex / grok over
//!   one sample) that a checkpoint cannot interrupt, and the worker request.
//!
//! Limits are far above real parser tests: the editor sends up to ~20 events
//! of a few KiB, and a production parser resolves one event in well under a
//! millisecond.

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use super::{humanize_runtime_spans, json_to_vrl_value, vrl_value_to_json, VrlValidatorError};

/// Largest single sample event (as the JSON text handed to the validator) a
/// parser test accepts. A real event, even a verbose Windows or CloudTrail
/// record, is tens of KiB; this leaves room for a 1 MiB raw line after JSON
/// wrapping and escaping.
pub const MAX_TEST_SAMPLE_BYTES: usize = 4 * 1024 * 1024;
/// Most sample events in one parser test request.
pub const MAX_TEST_SAMPLES: usize = 100;
/// Total bytes of every sample in one parser test request. Real requests are
/// far smaller (test-live sends at most 20 events; test-vrl's whole body is
/// under 2 MiB); this keeps the worker request, and so the worker's memory
/// need, bounded well inside its limits.
pub const MAX_TEST_TOTAL_SAMPLE_BYTES: usize = 16 * 1024 * 1024;
/// Wall-clock budget for executing every sample (and every stage) of one test
/// request.
pub const TEST_EXECUTION_BUDGET: Duration = Duration::from_secs(5);

/// How many checkpoints pass between clock reads (reading the clock on every
/// expression would dominate a tight loop).
const CHECKS_PER_CLOCK_READ: u32 = 256;

/// A per-request wall-clock budget, checked cooperatively by the VRL runtime.
pub struct ExecutionBudget {
    deadline: Instant,
    budget: Duration,
    ticks: u32,
    exhausted: bool,
}

impl ExecutionBudget {
    pub fn new(budget: Duration) -> Self {
        Self {
            deadline: Instant::now() + budget,
            budget,
            ticks: 0,
            exhausted: false,
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted || Instant::now() >= self.deadline
    }

    /// The user-facing message for a program stopped by this budget.
    pub fn exhausted_message(&self) -> String {
        format!(
            "Test execution exceeded its {}s time budget; reduce the sample or simplify \
             the program",
            self.budget.as_secs()
        )
    }
}

impl vrl::compiler::runtime::ExecutionControl for ExecutionBudget {
    fn checkpoint(&mut self) -> ControlFlow<()> {
        if self.exhausted {
            return ControlFlow::Break(());
        }
        self.ticks = self.ticks.wrapping_add(1);
        if self.ticks % CHECKS_PER_CLOCK_READ == 0 && Instant::now() >= self.deadline {
            self.exhausted = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Reject a request whose samples exceed the caps above.
pub fn check_samples<S: AsRef<str>>(samples: &[S]) -> Result<(), VrlValidatorError> {
    if samples.len() > MAX_TEST_SAMPLES {
        return Err(VrlValidatorError::InvalidInput(format!(
            "A parser test accepts at most {MAX_TEST_SAMPLES} sample events"
        )));
    }
    if let Some(big) = samples.iter().find(|s| s.as_ref().len() > MAX_TEST_SAMPLE_BYTES) {
        return Err(VrlValidatorError::InvalidInput(format!(
            "Sample event is {} bytes; a parser test accepts at most {} bytes per event",
            big.as_ref().len(),
            MAX_TEST_SAMPLE_BYTES
        )));
    }
    let total: usize = samples.iter().map(|s| s.as_ref().len()).sum();
    if total > MAX_TEST_TOTAL_SAMPLE_BYTES {
        return Err(VrlValidatorError::InvalidInput(format!(
            "Sample events total {total} bytes; a parser test accepts at most \
             {MAX_TEST_TOTAL_SAMPLE_BYTES} bytes in all"
        )));
    }
    Ok(())
}

/// Execute a compiled program against one event under `budget`.
pub fn run_program(
    vrl_code: &str,
    program: &vrl::compiler::Program,
    input: &serde_json::Value,
    budget: &mut ExecutionBudget,
) -> Result<serde_json::Value, String> {
    use vrl::compiler::runtime::Terminate;
    use vrl::compiler::TargetValue;
    use vrl::value::{Secrets, Value};

    if budget.is_exhausted() {
        return Err(budget.exhausted_message());
    }
    let mut target = TargetValue {
        value: json_to_vrl_value(input),
        metadata: Value::Object(BTreeMap::new()),
        secrets: Secrets::default(),
    };
    let timezone = vrl::compiler::TimeZone::Local;
    let mut runtime = vrl::compiler::runtime::Runtime::default();

    // NAN-4912 P3 (defense in depth): parser registries have no `log`,
    // but nothing a tested program does may reach the service logs.
    let resolved = tracing::subscriber::with_default(
        tracing::subscriber::NoSubscriber::default(),
        || runtime.resolve_with_control(&mut target, program, &timezone, budget),
    );
    match resolved {
        Ok(_) => Ok(vrl_value_to_json(&target.value)),
        Err(Terminate::Interrupted) => Err(budget.exhausted_message()),
        Err(e) => Err(format!(
            "VRL runtime error: {}",
            humanize_runtime_spans(vrl_code, &e.to_string())
        )),
    }
}

#[cfg(test)]
#[path = "validator_exec_bounds_tests.rs"]
mod tests;
