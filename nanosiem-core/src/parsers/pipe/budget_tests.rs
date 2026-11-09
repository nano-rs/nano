// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native-plan parser tests run under the same per-request budget as plain
//! VRL (security review 2026-11-08, NAN-5040 review follow-up).

use super::*;
use crate::parsers::VrlValidator;
use serde_json::json;
use std::time::{Duration, Instant};

const NESTED_LOOP: &str = r#"
parts = split(string!(.message), ",")
n = 0
for_each(parts) -> |_i, _a| {
  for_each(parts) -> |_j, _b| {
    n = n + 1
  }
}
.n = n
"#;

fn step(kind: &str, config: serde_json::Value) -> Step {
    Step {
        id: kind.into(),
        name: kind.into(),
        kind: kind.into(),
        enabled: true,
        condition: None,
        config: config.as_object().unwrap().clone(),
    }
}

fn native_plan_with(code: &str) -> String {
    Plan {
        version: 2,
        revision: 1,
        steps: vec![
            step("dedupe", json!({"fields":["message"]})),
            step("vrl", json!({ "code": code })),
        ],
    }
    .stored()
    .unwrap()
}

/// Exploit regression: a pipe header + native step + quadratic VRL used to run
/// on `Runtime::resolve` with no budget (64 KiB of commas = minutes of CPU).
#[tokio::test]
async fn native_plan_test_stops_at_the_budget() {
    let input = json!({ "message": ",".repeat(60 * 1024) }).to_string();
    let started = Instant::now();
    let rows = VrlValidator::new()
        .test_vrl_batch(&native_plan_with(NESTED_LOOP), &[input])
        .await
        .unwrap();
    let took = started.elapsed();
    assert!(!rows[0].success);
    assert!(
        rows[0].error.as_deref().unwrap_or("").contains("time budget"),
        "{:?}",
        rows[0].error
    );
    assert!(took < exec_bounds_budget() + Duration::from_secs(5), "{took:?}");
}

/// Legitimate path: the same plan on a small event finishes with its output.
#[tokio::test]
async fn native_plan_small_event_runs() {
    let rows = VrlValidator::new()
        .test_vrl_batch(&native_plan_with(NESTED_LOOP), &[json!({"message":"a,b,c"}).to_string()])
        .await
        .unwrap();
    assert!(rows[0].success, "{:?}", rows[0].error);
    assert_eq!(rows[0].output.as_ref().unwrap()["n"], 9);
}

fn exec_bounds_budget() -> Duration {
    crate::parsers::TEST_EXECUTION_BUDGET
}
