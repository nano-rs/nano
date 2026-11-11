// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounds on the nPL `| ai` row enrichment (NAN-5277).
//!
//! `| ai` runs LLM calls inside the search request, after the ClickHouse
//! fetch and while the request still holds its admission permit. Before this
//! guard nothing bounded those calls: the enterprise client retries a timed-out
//! request up to three times at the agent's 120s timeout (about six minutes),
//! and a 20-row call on the local stack took 102s. Two effects followed:
//!
//! - The interactive request outlived the 45s hand-off budget, was killed and
//!   re-ran as a background job, which made the LLM call again and held one of
//!   the TWO background workers per replica for minutes. A couple of `| ai`
//!   runs filled the pool, and every other user's long search queued behind
//!   them until the calls finished ("search down for a few minutes").
//! - Each call held a per-user admission slot (5 per user) for minutes, so an
//!   analyst or agent re-running `| ai` locked themselves out of search.
//!
//! The guard splits the rows into chunks small enough to finish well inside
//! the per-call timeout, runs them sequentially or with small bounded
//! parallelism, and gives the whole command an overall budget. Every model
//! call in flight holds a process slot, and a user runs one `| ai` command at
//! a time. The rows always come back, so the search itself always completes:
//!
//! - a chunk the model answered carries its verdicts;
//! - a chunk that failed or hit the per-call timeout is tagged
//!   `ai_verdict = "ERROR"` with the reason;
//! - a chunk never sent (budget used up, an earlier chunk timed out, no slot,
//!   past `max_rows`) is tagged `ai_verdict = "SKIPPED"` with the reason.
//!
//! `| ai` searches are never run as background jobs (see `nanosiem-search`
//! `handlers/search.rs` and `search::background::service`).
//!
//! Environment overrides (read once per process):
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `SEARCH_AI_PIPE_TIMEOUT_SECS` | 90 | Wall-clock cap on ONE model call (one chunk), retries included |
//! | `SEARCH_AI_PIPE_BUDGET_SECS` | 180 | Wall-clock cap on the whole `\| ai` command; unsent chunks come back SKIPPED |
//! | `SEARCH_AI_PIPE_CHUNK_ROWS` | 10 | Rows per model call (a 20-row call measured ~100s on a slow model) |
//! | `SEARCH_AI_PIPE_PARALLELISM` | 2 | Model calls one command may have in flight |
//! | `SEARCH_AI_PIPE_MAX_CONCURRENT` | 4 | Model calls in flight across the process |
//! | `SEARCH_AI_PIPE_MAX_PER_USER` | 1 | `\| ai` commands in flight per user |
//!
//! The budget default stays well under the 300s `/api/search` proxy read
//! timeout, leaving room for the ClickHouse fetch before the enrichment.
//! Metering: a command is ONE AI request however many chunks it is split
//! into. It is charged once, just before its first model call, and records
//! one usage event with the tokens summed over its chunks. A command that
//! never calls the model (no slot, empty input, credit limit, AI unavailable)
//! is not charged. A command whose every chunk timed out IS charged its one
//! request (the model was called), but records no usage event: a cancelled
//! call reports no tokens.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use futures::StreamExt;
use serde_json::Value;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

use crate::extensions::{skipped_rows, AiClient, AiPipeCharge, AiUsageTally};

/// The agent-side hard cap on rows sent to the model per command.
const MAX_AI_ROWS: usize = 500;

/// The limits one process applies to `| ai` enrichment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AiPipeLimits {
    /// Wall-clock cap on one model call (one chunk), retries included.
    pub call_timeout: Duration,
    /// Wall-clock cap on the whole command.
    pub budget: Duration,
    /// Rows per model call.
    pub chunk_rows: usize,
    /// Model calls one command may have in flight.
    pub parallelism: usize,
    /// Model calls in flight across the process.
    pub max_concurrent: usize,
    /// Commands in flight for one user.
    pub max_per_user: usize,
    /// How long a command waits for its first process slot before it is skipped.
    pub slot_wait: Duration,
}

impl AiPipeLimits {
    fn from_env() -> Self {
        fn env<T: std::str::FromStr>(name: &str) -> Option<T> {
            std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
        }
        fn positive(name: &str, default: usize) -> usize {
            env::<usize>(name).filter(|n| *n >= 1).unwrap_or(default)
        }
        Self {
            call_timeout: Duration::from_secs(positive("SEARCH_AI_PIPE_TIMEOUT_SECS", 90) as u64),
            budget: Duration::from_secs(positive("SEARCH_AI_PIPE_BUDGET_SECS", 180) as u64),
            chunk_rows: positive("SEARCH_AI_PIPE_CHUNK_ROWS", 10),
            parallelism: positive("SEARCH_AI_PIPE_PARALLELISM", 2),
            max_concurrent: positive("SEARCH_AI_PIPE_MAX_CONCURRENT", 4),
            max_per_user: positive("SEARCH_AI_PIPE_MAX_PER_USER", 1),
            slot_wait: Duration::from_secs(2),
        }
    }
}

/// Process-wide and per-user slots for `| ai` enrichment.
pub(crate) struct AiPipeGuard {
    limits: AiPipeLimits,
    slots: Arc<Semaphore>,
    per_user: Arc<Mutex<HashMap<Uuid, usize>>>,
}

/// Releases the per-user count when dropped.
struct UserSlot {
    per_user: Arc<Mutex<HashMap<Uuid, usize>>>,
    user: Option<Uuid>,
}

impl Drop for UserSlot {
    fn drop(&mut self) {
        if let Some(user) = self.user {
            let mut map = self.per_user.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(n) = map.get_mut(&user) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&user);
                }
            }
        }
    }
}

static GUARD: LazyLock<AiPipeGuard> = LazyLock::new(|| AiPipeGuard::new(AiPipeLimits::from_env()));

/// The process-wide guard.
pub(crate) fn guard() -> &'static AiPipeGuard {
    &GUARD
}

/// How one chunk ended.
enum ChunkOutcome {
    Done(Vec<Value>),
    Error(Vec<Value>),
    /// The per-call timeout fired: later chunks are not sent.
    TimedOut(Vec<Value>),
    Skipped(Vec<Value>),
    /// The command was not charged (credit limit, AI unavailable): rows are
    /// already tagged SKIPPED with the client's reason.
    Refused(Vec<Value>),
}

/// Records the command's ONE usage event when the command ends, including
/// when the search is cancelled mid-command (the future is dropped).
struct UsageFlush<'a> {
    client: &'a dyn AiClient,
    tally: AiUsageTally,
}

impl Drop for UsageFlush<'_> {
    fn drop(&mut self) {
        if let Some(totals) = self.tally.take() {
            self.client.record_ai_pipe_usage(totals);
        }
    }
}

impl AiPipeGuard {
    pub(crate) fn new(limits: AiPipeLimits) -> Self {
        Self {
            limits,
            slots: Arc::new(Semaphore::new(limits.max_concurrent)),
            per_user: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Take a user slot, then the command's first process slot. `Err` carries
    /// the reason shown on the skipped rows.
    async fn acquire(
        &self,
        user: Option<Uuid>,
    ) -> Result<(UserSlot, OwnedSemaphorePermit), String> {
        if let Some(user) = user {
            let mut map = self.per_user.lock().unwrap_or_else(|p| p.into_inner());
            let n = map.entry(user).or_insert(0);
            if *n >= self.limits.max_per_user {
                return Err(format!(
                    "AI enrichment skipped: you already have {} `| ai` search running. \
                     Wait for it to finish, then run this search again.",
                    self.limits.max_per_user
                ));
            }
            *n += 1;
        }
        // From here on, dropping `slot` gives the user count back.
        let slot = UserSlot {
            per_user: self.per_user.clone(),
            user,
        };
        match tokio::time::timeout(self.limits.slot_wait, self.slots.clone().acquire_owned()).await
        {
            Ok(Ok(permit)) => Ok((slot, permit)),
            _ => Err(format!(
                "AI enrichment skipped: {} `| ai` model calls are already running on this \
                 search service. Run this search again in a minute.",
                self.limits.max_concurrent
            )),
        }
    }

    /// Run `client.enrich_rows` over `rows` in chunks, inside the limits.
    /// Always returns every row, in order: enriched, or tagged SKIPPED / ERROR
    /// with the reason.
    pub(crate) async fn enrich(
        &self,
        client: &dyn AiClient,
        mut rows: Vec<Value>,
        prompt: &str,
        max_rows: usize,
        user: Option<Uuid>,
    ) -> Vec<Value> {
        if rows.is_empty() {
            return rows;
        }
        let started = Instant::now();
        let deadline = started + self.limits.budget;
        let (_user_slot, first_permit) = match self.acquire(user).await {
            Ok(slot) => slot,
            Err(reason) => {
                tracing::warn!(reason = %reason, "AI pipe enrichment skipped");
                return skipped_rows(rows, &reason);
            }
        };

        // Rows past max_rows never reach the model (the agent's contract).
        let cap = max_rows.clamp(1, MAX_AI_ROWS);
        let overflow = if rows.len() > cap {
            rows.split_off(cap)
        } else {
            Vec::new()
        };
        let total = rows.len();
        let chunk_rows = self.limits.chunk_rows.max(1);
        let chunks: Vec<Vec<Value>> = {
            let mut out = Vec::with_capacity(total.div_ceil(chunk_rows));
            let mut it = rows.into_iter().peekable();
            while it.peek().is_some() {
                out.push(it.by_ref().take(chunk_rows).collect());
            }
            out
        };

        // The first slot is held; extra parallel workers only use slots that
        // are free right now, so one command never queues behind others.
        let wanted_extra = self.limits.parallelism.min(chunks.len()).saturating_sub(1);
        let mut permits = vec![first_permit];
        for _ in 0..wanted_extra {
            match self.slots.clone().try_acquire_owned() {
                Ok(p) => permits.push(p),
                Err(_) => break,
            }
        }
        let workers = permits.len();

        // NAN-5277 metering: the command is ONE AI request however many chunks
        // it has. The first chunk that is about to call the model charges it
        // (parallel chunks wait on the same charge), so a command that never
        // reaches the model is never charged. Chunks then call the model
        // uncharged and report tokens into one tally, recorded once.
        let charge: tokio::sync::OnceCell<Result<AiPipeCharge, String>> =
            tokio::sync::OnceCell::new();
        let usage = UsageFlush {
            client,
            tally: AiUsageTally::default(),
        };
        let stop = AtomicBool::new(false);
        let call_timeout = self.limits.call_timeout;
        let budget_secs = self.limits.budget.as_secs();
        let run_chunk = |chunk: Vec<Value>| {
            let (stop, charge, tally) = (&stop, &charge, &usage.tally);
            async move {
                if stop.load(Ordering::SeqCst) {
                    return ChunkOutcome::Skipped(chunk);
                }
                let now = Instant::now();
                if now >= deadline {
                    return ChunkOutcome::Skipped(chunk);
                }
                let charged = charge
                    .get_or_init(|| async {
                        client.charge_ai_pipe_command().await.map_err(|e| e.to_string())
                    })
                    .await;
                match charged {
                    Ok(AiPipeCharge::Charged) => {}
                    Ok(AiPipeCharge::Refused(reason)) => {
                        return ChunkOutcome::Refused(skipped_rows(chunk, reason));
                    }
                    Err(e) => {
                        return ChunkOutcome::Error(error_rows(
                            chunk,
                            &format!("AI enrichment failed: {e}"),
                        ));
                    }
                }
                let now = Instant::now();
                if now >= deadline {
                    return ChunkOutcome::Skipped(chunk);
                }
                let budget_binds = deadline - now < call_timeout;
                let limit = call_timeout.min(deadline - now);
                let fallback = chunk.clone();
                let n = chunk.len();
                let call = client.enrich_chunk_uncharged(chunk, prompt, tally);
                match tokio::time::timeout(limit, call).await {
                    Ok(Ok(enriched)) => ChunkOutcome::Done(enriched),
                    Ok(Err(e)) => {
                        tracing::warn!("AI pipe chunk failed: {}", e);
                        ChunkOutcome::Error(error_rows(
                            fallback,
                            &format!("AI enrichment failed: {e}"),
                        ))
                    }
                    // Dropping the future cancels the in-flight HTTP request.
                    Err(_) if budget_binds => ChunkOutcome::Skipped(fallback),
                    Err(_) => {
                        stop.store(true, Ordering::SeqCst);
                        ChunkOutcome::TimedOut(error_rows(
                            fallback,
                            &format!(
                                "AI enrichment timed out after {}s on this chunk of {n} rows. \
                                 Try fewer rows (max_rows=) or a narrower search.",
                                call_timeout.as_secs()
                            ),
                        ))
                    }
                }
            }
        };
        // `buffered` keeps chunk order and caps chunks in flight at `workers`.
        let outcomes: Vec<ChunkOutcome> = futures::stream::iter(chunks)
            .map(run_chunk)
            .buffered(workers)
            .collect()
            .await;
        drop(permits);
        drop(usage);

        let classified: usize = outcomes
            .iter()
            .map(|o| match o {
                ChunkOutcome::Done(r) => r.len(),
                _ => 0,
            })
            .sum();
        let timed_out = outcomes.iter().any(|o| matches!(o, ChunkOutcome::TimedOut(_)));
        let skip_reason = if timed_out {
            format!(
                "AI enrichment stopped: an earlier chunk timed out, so this row was not \
                 sent to the model ({classified} of {total} rows classified). Try fewer rows (max_rows=) \
                 or a narrower search."
            )
        } else {
            format!(
                "AI enrichment budget of {budget_secs}s ran out before this row was \
                 classified ({classified} of {total} rows classified). Try fewer rows \
                 (max_rows=) or a narrower search."
            )
        };
        let mut out = Vec::with_capacity(total + overflow.len());
        let mut skipped = 0usize;
        for outcome in outcomes {
            match outcome {
                ChunkOutcome::Done(r)
                | ChunkOutcome::Error(r)
                | ChunkOutcome::TimedOut(r)
                | ChunkOutcome::Refused(r) => {
                    out.extend(r)
                }
                ChunkOutcome::Skipped(r) => {
                    skipped += r.len();
                    out.extend(skipped_rows(r, &skip_reason));
                }
            }
        }
        if !overflow.is_empty() {
            out.extend(skipped_rows(
                overflow,
                &format!("Row exceeded max_rows limit of {cap}"),
            ));
        }
        tracing::info!(
            rows = total,
            classified,
            skipped,
            workers,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "AI pipe enrichment finished"
        );
        out
    }
}

/// Tag every row `ai_verdict = "ERROR"` with `reason`.
fn error_rows(rows: Vec<Value>, reason: &str) -> Vec<Value> {
    rows.into_iter()
        .map(|mut row| {
            if let Some(obj) = row.as_object_mut() {
                obj.insert("ai_verdict".into(), Value::String("ERROR".into()));
                obj.insert(
                    "ai_confidence".into(),
                    Value::Number(serde_json::Number::from_f64(0.0).expect("finite")),
                );
                obj.insert("ai_reasoning".into(), Value::String(reason.to_string()));
            }
            row
        })
        .collect()
}

#[cfg(test)]
#[path = "ai_pipe_guard_tests.rs"]
mod tests;
