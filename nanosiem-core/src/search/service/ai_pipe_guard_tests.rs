// SPDX-License-Identifier: AGPL-3.0-or-later

//! `| ai` enrichment bounds (NAN-5277).
//!
//! The model is a fake injected at the `AiClient` trait, so no provider
//! config, `base_url` or env var can route these tests to a real model. Time
//! is paused: tokio advances the clock whenever every task is idle, so a
//! "60s" model call runs instantly and the timings are exact.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{AiPipeGuard, AiPipeLimits};
use crate::extensions::{
    AiClient, AiMessage, AiPipeCharge, AiUsageTally, AiUsageTotals, ExtensionError,
};

/// A model whose call takes `per_row` for every row it is sent (a slow model
/// is slow per row: it writes one verdict per row). It records the calls,
/// the rows per call and the most calls it saw in flight at once.
///
/// It meters like the enterprise `AiPipeAgent`: `enrich_rows` charges every
/// call (the single-call path), `charge_ai_pipe_command` charges a command,
/// and `enrich_chunk_uncharged` never charges and reports 100 prompt + 10
/// completion tokens per row into the command's tally.
struct FakeModel {
    per_row: Duration,
    fail: bool,
    /// `Some(reason)`: the command charge is refused (credit limit).
    refuse: Option<String>,
    charges: AtomicUsize,
    usage_events: std::sync::Mutex<Vec<AiUsageTotals>>,
    calls: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    biggest_call: AtomicUsize,
}

impl FakeModel {
    fn new(per_row: Duration) -> Self {
        Self {
            per_row,
            fail: false,
            refuse: None,
            charges: AtomicUsize::new(0),
            usage_events: std::sync::Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            biggest_call: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    fn charges(&self) -> usize {
        self.charges.load(Ordering::SeqCst)
    }
    fn usage_events(&self) -> Vec<AiUsageTotals> {
        self.usage_events.lock().unwrap().clone()
    }

    async fn model_call(&self, rows: Vec<Value>) -> Result<Vec<Value>, ExtensionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.biggest_call.fetch_max(rows.len(), Ordering::SeqCst);
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _guard = InFlight(&self.in_flight);
        tokio::time::sleep(self.per_row * rows.len() as u32).await;
        if self.fail {
            return Err(ExtensionError::AiProvider("upstream 503".into()));
        }
        Ok(rows
            .into_iter()
            .map(|mut r| {
                r["ai_verdict"] = json!("BENIGN");
                r
            })
            .collect())
    }
}

/// Decrements the in-flight count when a call ends or is cancelled.
struct InFlight<'a>(&'a AtomicUsize);
impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl AiClient for FakeModel {
    fn is_available(&self) -> bool {
        true
    }
    async fn complete(&self, _: Vec<AiMessage>, _: &str) -> Result<String, ExtensionError> {
        unimplemented!("`| ai` only calls enrich_rows")
    }
    async fn enrich_rows(
        &self,
        rows: Vec<Value>,
        _prompt: &str,
        _max_rows: usize,
    ) -> Result<Vec<Value>, ExtensionError> {
        // The single-call path meters every call.
        self.charges.fetch_add(1, Ordering::SeqCst);
        self.model_call(rows).await
    }
    async fn charge_ai_pipe_command(&self) -> Result<AiPipeCharge, ExtensionError> {
        if let Some(reason) = &self.refuse {
            return Ok(AiPipeCharge::Refused(reason.clone()));
        }
        self.charges.fetch_add(1, Ordering::SeqCst);
        Ok(AiPipeCharge::Charged)
    }
    async fn enrich_chunk_uncharged(
        &self,
        rows: Vec<Value>,
        _prompt: &str,
        usage: &AiUsageTally,
    ) -> Result<Vec<Value>, ExtensionError> {
        let n = rows.len() as u32;
        let out = self.model_call(rows).await?;
        usage.add(Some("ai_pipe".into()), "fake-model", "fake", n * 100, n * 10, 0, 0);
        Ok(out)
    }
    fn record_ai_pipe_usage(&self, totals: AiUsageTotals) {
        self.usage_events.lock().unwrap().push(totals);
    }
}

/// Defaults matching production (90s call, 180s budget, 10-row chunks,
/// 2 per command, 4 per process, 1 per user).
fn prod() -> AiPipeLimits {
    AiPipeLimits {
        call_timeout: Duration::from_secs(90),
        budget: Duration::from_secs(180),
        chunk_rows: 10,
        parallelism: 2,
        max_concurrent: 4,
        max_per_user: 1,
        slot_wait: Duration::from_millis(50),
    }
}

fn rows(n: usize) -> Vec<Value> {
    (0..n).map(|i| json!({ "id": i })).collect()
}

fn count(rows: &[Value], verdict: &str) -> usize {
    rows.iter().filter(|r| r["ai_verdict"] == verdict).count()
}

fn ids(rows: &[Value]) -> Vec<u64> {
    rows.iter().map(|r| r["id"].as_u64().unwrap()).collect()
}

/// The regression: a 100-row `| ai` on a model that needs 5s per row is 500s
/// as ONE call, far past the 90s per-call timeout, so every row came back
/// ERROR. Chunked at 10 rows (50s per call, 2 in flight) it finishes inside
/// the budget with every row classified and in order.
#[tokio::test(start_paused = true)]
async fn large_input_on_a_slow_model_completes_in_chunks() {
    let mut limits = prod();
    limits.budget = Duration::from_secs(280);
    let guard = AiPipeGuard::new(limits);
    let model = FakeModel::new(Duration::from_secs(5));
    let started = tokio::time::Instant::now();
    let out = guard.enrich(&model, rows(100), "p", 100, Some(Uuid::now_v7())).await;
    assert_eq!(out.len(), 100);
    assert_eq!(count(&out, "BENIGN"), 100, "{:?}", out[0]);
    assert_eq!(ids(&out), (0..100).collect::<Vec<_>>());
    assert_eq!(model.calls(), 10);
    assert_eq!(model.biggest_call.load(Ordering::SeqCst), 10);
    assert_eq!(model.max_in_flight.load(Ordering::SeqCst), 2);
    // 10 chunks x 50s at 2 in flight.
    assert_eq!(started.elapsed(), Duration::from_secs(250));
}

/// The overall budget: completed chunks keep their answers, the rest come
/// back SKIPPED with a reason, and the command returns at the budget.
#[tokio::test(start_paused = true)]
async fn budget_returns_partial_results() {
    let guard = AiPipeGuard::new(prod());
    let model = FakeModel::new(Duration::from_secs(5));
    let started = tokio::time::Instant::now();
    let out = guard.enrich(&model, rows(100), "p", 100, None).await;
    assert!(started.elapsed() <= Duration::from_secs(180), "{:?}", started.elapsed());
    assert_eq!(out.len(), 100);
    assert_eq!(ids(&out), (0..100).collect::<Vec<_>>());
    // 50s per chunk, 2 in flight: 3 rounds (150s) finish, the 4th is cut at 180s.
    assert_eq!(count(&out, "BENIGN"), 60);
    assert_eq!(count(&out, "SKIPPED"), 40);
    assert_eq!(count(&out, "ERROR"), 0);
    let reason = out[99]["ai_reasoning"].as_str().unwrap();
    assert!(reason.contains("budget of 180s"), "{reason}");
    assert!(reason.contains("60 of 100 rows classified"), "{reason}");
    // The answered rows come first, in order.
    assert!(out[..60].iter().all(|r| r["ai_verdict"] == "BENIGN"));
}

/// A chunk past the per-call timeout is ERROR and later chunks are not sent:
/// a model that slow would only burn the budget (and other users' slots).
#[tokio::test(start_paused = true)]
async fn chunk_timeout_stops_sending_more_chunks() {
    let mut limits = prod();
    limits.parallelism = 1;
    limits.budget = Duration::from_secs(600);
    let guard = AiPipeGuard::new(limits);
    let model = FakeModel::new(Duration::from_secs(60)); // 600s per 10-row chunk
    let started = tokio::time::Instant::now();
    let out = guard.enrich(&model, rows(30), "p", 100, None).await;
    assert_eq!(started.elapsed(), Duration::from_secs(90));
    assert_eq!(model.calls(), 1);
    assert_eq!(count(&out, "ERROR"), 10);
    assert_eq!(count(&out, "SKIPPED"), 20);
    assert!(out[0]["ai_reasoning"].as_str().unwrap().contains("timed out after 90s"));
    assert!(out[29]["ai_reasoning"].as_str().unwrap().contains("earlier chunk timed out"));
}

#[tokio::test(start_paused = true)]
async fn failing_model_tags_rows_error() {
    let guard = AiPipeGuard::new(prod());
    let mut model = FakeModel::new(Duration::ZERO);
    model.fail = true;
    let out = guard.enrich(&model, rows(15), "p", 100, None).await;
    assert_eq!(count(&out, "ERROR"), 15);
    assert!(out[0]["ai_reasoning"].as_str().unwrap().contains("upstream 503"));
}

/// Rows past `max_rows` never reach the model.
#[tokio::test(start_paused = true)]
async fn rows_past_max_rows_are_skipped() {
    let guard = AiPipeGuard::new(prod());
    let model = FakeModel::new(Duration::ZERO);
    let out = guard.enrich(&model, rows(30), "p", 12, None).await;
    assert_eq!(count(&out, "BENIGN"), 12);
    assert_eq!(count(&out, "SKIPPED"), 18);
    assert_eq!(model.calls(), 2); // 10 + 2
    assert!(out[29]["ai_reasoning"].as_str().unwrap().contains("max_rows limit of 12"));
}

/// One user cannot stack `| ai` commands: the second concurrent command is
/// skipped without reaching the model, and a different user still gets through.
#[tokio::test(start_paused = true)]
async fn per_user_cap_skips_the_second_command() {
    let guard = Arc::new(AiPipeGuard::new(prod()));
    let model = Arc::new(FakeModel::new(Duration::from_secs(1)));
    let alice = Uuid::now_v7();
    let first = {
        let (guard, model) = (guard.clone(), model.clone());
        tokio::spawn(async move { guard.enrich(model.as_ref(), rows(2), "p", 10, Some(alice)).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = guard.enrich(model.as_ref(), rows(2), "p", 10, Some(alice)).await;
    assert_eq!(count(&second, "SKIPPED"), 2);
    assert!(second[0]["ai_reasoning"].as_str().unwrap().contains("already have 1"));
    let bob = guard.enrich(model.as_ref(), rows(2), "p", 10, Some(Uuid::now_v7())).await;
    assert_eq!(count(&bob, "BENIGN"), 2);
    assert_eq!(count(&first.await.unwrap(), "BENIGN"), 2);
    assert_eq!(model.calls(), 2);
    // The slot is released: alice can run again.
    let again = guard.enrich(model.as_ref(), rows(2), "p", 10, Some(alice)).await;
    assert_eq!(count(&again, "BENIGN"), 2);
    assert!(guard.per_user.lock().unwrap().is_empty());
}

/// The process cap bounds model calls in flight across all commands: a large
/// command's parallel chunks never push it past the cap, and a command that
/// cannot get any slot is skipped (and gives its per-user count back).
#[tokio::test(start_paused = true)]
async fn process_cap_bounds_model_calls_across_commands() {
    let mut limits = prod();
    limits.max_concurrent = 3;
    limits.parallelism = 2;
    limits.budget = Duration::from_secs(1_000);
    let guard = Arc::new(AiPipeGuard::new(limits));
    let model = Arc::new(FakeModel::new(Duration::from_secs(1)));
    let spawn = |n: usize| {
        let (guard, model) = (guard.clone(), model.clone());
        tokio::spawn(async move {
            guard.enrich(model.as_ref(), rows(n), "p", 100, Some(Uuid::now_v7())).await
        })
    };
    // Two large commands: the first takes 2 slots, the second gets the 1 left.
    let a = spawn(40);
    tokio::time::sleep(Duration::from_millis(10)).await;
    let b = spawn(40);
    tokio::time::sleep(Duration::from_millis(10)).await;
    // No slot left for a third user.
    let c = guard.enrich(model.as_ref(), rows(5), "p", 100, Some(Uuid::now_v7())).await;
    assert_eq!(count(&c, "SKIPPED"), 5);
    assert!(c[0]["ai_reasoning"].as_str().unwrap().contains("already running"));
    assert_eq!(count(&a.await.unwrap(), "BENIGN"), 40);
    assert_eq!(count(&b.await.unwrap(), "BENIGN"), 40);
    assert_eq!(model.max_in_flight.load(Ordering::SeqCst), 3);
    assert!(guard.per_user.lock().unwrap().is_empty());
    assert_eq!(guard.slots.available_permits(), 3);
}

#[tokio::test(start_paused = true)]
async fn empty_rows_never_call_the_model() {
    let guard = AiPipeGuard::new(prod());
    let model = FakeModel::new(Duration::ZERO);
    assert!(guard.enrich(&model, Vec::new(), "p", 10, None).await.is_empty());
    assert_eq!(model.calls(), 0);
}

/// Dan's rule (NAN-5277): a 100-row `| ai` is ONE metered AI request and ONE
/// usage event with the tokens of all ten chunks, never one per chunk.
#[tokio::test(start_paused = true)]
async fn a_chunked_command_is_metered_once() {
    let guard = AiPipeGuard::new(prod());
    let model = FakeModel::new(Duration::from_millis(100));
    let out = guard.enrich(&model, rows(100), "p", 100, Some(Uuid::now_v7())).await;
    assert_eq!(count(&out, "BENIGN"), 100);
    assert_eq!(model.calls(), 10);
    assert_eq!(model.charges(), 1);
    let events = model.usage_events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].calls, 10);
    assert_eq!(events[0].prompt_tokens, 100 * 100);
    assert_eq!(events[0].completion_tokens, 100 * 10);
    assert_eq!(events[0].model_id, "fake-model");
    assert_eq!(events[0].agent_id.as_deref(), Some("ai_pipe"));
}

/// A command that never reaches the model is not charged: no rows, no free
/// slot, or a refused charge (no model call either).
#[tokio::test(start_paused = true)]
async fn a_command_that_never_calls_the_model_is_not_charged() {
    let guard = Arc::new(AiPipeGuard::new(prod()));
    let model = Arc::new(FakeModel::new(Duration::from_secs(1)));
    assert!(guard.enrich(model.as_ref(), Vec::new(), "p", 10, None).await.is_empty());
    assert_eq!(model.charges(), 0);

    // Per-user cap: the second command is skipped before any chunk runs.
    let alice = Uuid::now_v7();
    let first = {
        let (guard, model) = (guard.clone(), model.clone());
        tokio::spawn(async move { guard.enrich(model.as_ref(), rows(2), "p", 10, Some(alice)).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let skipped = guard.enrich(model.as_ref(), rows(2), "p", 10, Some(alice)).await;
    assert_eq!(count(&skipped, "SKIPPED"), 2);
    first.await.unwrap();
    assert_eq!(model.charges(), 1, "only the first command is charged");

    // Refused (credit limit): rows SKIPPED with the reason, no model call.
    let mut refused = FakeModel::new(Duration::ZERO);
    refused.refuse = Some("Monthly AI credit limit reached".into());
    let out = guard.enrich(&refused, rows(25), "p", 100, None).await;
    assert_eq!(count(&out, "SKIPPED"), 25);
    assert!(out[24]["ai_reasoning"].as_str().unwrap().contains("credit limit"));
    assert_eq!(refused.calls(), 0);
    assert_eq!(refused.charges(), 0);
    assert!(refused.usage_events().is_empty());
}

/// When every chunk times out the command IS charged its one request (the
/// model was called) and records no usage event (no call reported tokens).
#[tokio::test(start_paused = true)]
async fn all_chunks_timing_out_is_charged_once_without_usage() {
    let mut limits = prod();
    limits.parallelism = 1;
    let guard = AiPipeGuard::new(limits);
    let model = FakeModel::new(Duration::from_secs(60));
    let out = guard.enrich(&model, rows(30), "p", 100, None).await;
    assert_eq!(count(&out, "BENIGN"), 0);
    assert_eq!(model.charges(), 1);
    assert!(model.usage_events().is_empty());
}
