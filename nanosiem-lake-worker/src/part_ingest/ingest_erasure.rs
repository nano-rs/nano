// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3867: ingest[T] as the lean erasure executor (see
//! [`super::super::lean_erasure`]). A child of `ingest` so the step can use
//! the ingestor's log, part cache, merge lanes and prevalence state.
//!
//! One step at a time, at most one per maintenance tick:
//! - the tick claims an order (when idle and due), plans the next event hour
//!   and starts its probe/rewrite/publish in the background (or inline in
//!   the lab), exactly like a compaction merge;
//! - a later tick commits the finished step under the same fence as
//!   `commit_merge` (every input still live), then records it on the order.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;

use super::super::lean_erasure::{
    self as lean, execute_step, probe_part, ErasureLedger, ErasureLedgerSlot, LeanErasureOrder, LeanPhase, Probe, StepIo, StepKind,
    StepOutcome, StepRecord,
};
use super::super::merge::{merge_parts_filtered, FilteredMerge, MergeInput};
use super::{download_part_with_quota, hours_of, parts_dir, Ingestor};
use crate::erasure::ErasureIdentifierType;
use crate::parts::levels::Level;
use crate::parts::part_log::{AppendOutcome, LogOp, ObjectStore, PartRef, RetireReason};
use crate::parts::provenance::{PartSigner, TenantKeySet};

/// Backoff after a failed step or an unreachable ledger.
const RETRY_MS: i64 = 30_000;
/// Pause after every step: a history merge waiting for the lane takes it
/// first (erasure never holds the lane across steps).
const STEP_PAUSE_MS: i64 = 30_000;
/// Longest an erasure step yields (catch-up, busy history lanes, the
/// prevalence catch-up) before it runs beside them: both make progress.
const MAX_DEFERRAL_MS: i64 = 30 * 60_000;

/// The executor's state on the ingestor.
#[derive(Default)]
pub(crate) struct ErasureExec {
    slot: Option<ErasureLedgerSlot>,
    executor_node: String,
    /// The ledger and the credential URL it was built from.
    pool: Option<(String, Arc<dyn ErasureLedger>)>,
    /// Tests: an in-memory ledger instead of the exchange's login.
    fixed: Option<Arc<dyn ErasureLedger>>,
    order: Option<LeanErasureOrder>,
    flight: Option<ErasureFlight>,
    /// The next work-order write (a committed step's record, completion, a
    /// failure). Written by a spawned task: ingest never awaits the ledger.
    write: Option<LedgerWrite>,
    /// The ledger call in flight (one at a time).
    ledger_flight: Option<LedgerFlight>,
    /// Consecutive failed writes (the lease may be lost): past
    /// [`lean::MAX_CONSECUTIVE_FAILURES`] the order is dropped and re-taken
    /// from its recorded progress by a later claim.
    write_failures: u32,
    /// An IP order's prevalence wait renews its lease no more often than this.
    wait_record_due_ms: i64,
    next_poll_ms: i64,
    retry_not_before_ms: i64,
    /// No new step before this (the pause after the previous one).
    pause_until_ms: i64,
    /// A due step has been yielding since then.
    deferred_since_ms: Option<i64>,
}

struct ErasureFlight {
    hour: i32,
    handle: tokio::task::JoinHandle<Result<StepOutcome>>,
}

/// A work-order write, applied by a spawned task; its effect on the
/// executor (dropping a completed or failed order) waits for the reply.
#[derive(Clone)]
enum LedgerWrite {
    /// Progress (always) and a step's counters.
    Record(StepRecord),
    Complete,
    /// `code` fails the order; without one it is a counted retry.
    Fail { code: Option<&'static str>, message: String },
}

#[derive(Clone)]
enum LedgerCall {
    Claim,
    Write(LedgerWrite),
}

struct LedgerFlight {
    call: LedgerCall,
    handle: tokio::task::JoinHandle<Result<Option<LeanErasureOrder>>>,
}

/// What a step needs, owned (it may run on a background task).
#[derive(Clone)]
struct StepContext {
    tenant_id: String,
    trusted: TenantKeySet,
    work_dir: PathBuf,
    schema: arrow_schema::SchemaRef,
    fingerprint: String,
    key_id: String,
    build: String,
    now_ms: i64,
}

impl<'a> Ingestor<'a> {
    /// Install the exchange's `erasure_ledger` slot. Without it (an image
    /// whose platform does not declare it the tenant's executor) ingest never
    /// touches an erasure order.
    pub fn set_erasure_ledger(&mut self, slot: ErasureLedgerSlot, executor_node: String) {
        self.erasure.slot = Some(slot);
        self.erasure.executor_node = executor_node;
    }

    /// Tests / lab: execute against `ledger` instead of the exchange's login.
    pub fn set_erasure_ledger_fixed(&mut self, ledger: Arc<dyn ErasureLedger>, executor_node: String) {
        self.erasure.fixed = Some(ledger);
        self.erasure.executor_node = executor_node;
    }

    /// A step's probe/rewrite is running or awaiting its commit (tests).
    #[cfg(test)]
    pub(crate) fn erasure_step_in_flight(&self) -> bool {
        self.erasure.flight.is_some()
    }

    /// The order this executor holds (tests, health).
    pub fn erasure_order(&self) -> Option<&LeanErasureOrder> {
        self.erasure.order.as_ref()
    }

    /// One bounded erasure step. Failures are isolated like merges: logged,
    /// counted on the order, backed off.
    pub(super) async fn tick_erasure(&mut self, now_ms: i64, lag_ms: i64) {
        if (self.erasure.slot.is_none() && self.erasure.fixed.is_none()) || now_ms < self.erasure.retry_not_before_ms {
            return;
        }
        if let Err(error) = self.erasure_tick_inner(now_ms, lag_ms).await {
            tracing::warn!(tenant = %self.cfg.tenant_id, error = %format!("{error:#}"), "erasure step failed; retrying");
            self.erasure.retry_not_before_ms = now_ms + RETRY_MS;
        }
    }

    fn erasure_ledger(&mut self, now_ms: i64) -> Result<Option<Arc<dyn ErasureLedger>>> {
        if let Some(fixed) = &self.erasure.fixed {
            return Ok(Some(fixed.clone()));
        }
        let Some(credential) = self.erasure.slot.as_ref().and_then(ErasureLedgerSlot::get) else {
            self.erasure.pool = None;
            return Ok(None);
        };
        let now = chrono::DateTime::from_timestamp_millis(now_ms).unwrap_or_else(chrono::Utc::now);
        if credential.validate(&self.cfg.tenant_id, now).is_err() {
            self.erasure.pool = None;
            return Ok(None);
        }
        if let Some((url, pool)) = &self.erasure.pool {
            if *url == credential.database_url {
                return Ok(Some(pool.clone()));
            }
        }
        let pool: Arc<dyn ErasureLedger> = Arc::new(lean::PgErasureLedger(sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(15))
            .idle_timeout(std::time::Duration::from_secs(120))
            .connect_lazy(&credential.database_url)
            .context("erasure ledger URL")?));
        self.erasure.pool = Some((credential.database_url.clone(), pool.clone()));
        Ok(Some(pool))
    }

    async fn erasure_tick_inner(&mut self, now_ms: i64, lag_ms: i64) -> Result<()> {
        let running = |finished: Option<bool>| finished == Some(false);
        if running(self.erasure.flight.as_ref().map(|f| f.handle.is_finished()))
            || running(self.erasure.ledger_flight.as_ref().map(|f| f.handle.is_finished())) {
            return Ok(());
        }
        let Some(ledger) = self.erasure_ledger(now_ms)? else {
            // The grant was withdrawn: drop the order (its lease lapses and a
            // later grant re-takes it from its recorded progress).
            if let Some(flight) = self.erasure.flight.take() {
                flight.handle.abort();
            }
            self.erasure.ledger_flight = None;
            self.erasure.write = None;
            self.erasure.order = None;
            return Ok(());
        };
        if let Some(flight) = self.erasure.ledger_flight.take() {
            let reply = flight.handle.await.context("erasure ledger task panicked or was cancelled").and_then(|r| r);
            self.ledger_reply(flight.call, reply, now_ms)?;
        }
        if let Some(flight) = self.erasure.flight.take() {
            let outcome = flight.handle.await.context("erasure step task panicked or was cancelled").and_then(|r| r);
            self.finish_erasure_step(flight.hour, outcome, now_ms).await?;
        }
        if self.erasure.write.is_none() {
            if self.erasure.order.is_none() {
                if now_ms < self.erasure.next_poll_ms {
                    return Ok(());
                }
                self.erasure.next_poll_ms = now_ms + lean::POLL_INTERVAL_MS;
                self.spawn_ledger(ledger, LedgerCall::Claim);
                return Ok(());
            }
            let phase = self.erasure.order.as_ref().map(|order| order.progress.phase).context("order")?;
            match phase {
                LeanPhase::Scan | LeanPhase::Tail => self.start_erasure_step(now_ms, lag_ms).await?,
                LeanPhase::Prevalence => self.erase_prevalence(now_ms).await?,
                LeanPhase::Done => self.complete_erasure()?,
            }
        }
        if let Some(write) = self.erasure.write.take() {
            self.spawn_ledger(ledger, LedgerCall::Write(write));
        }
        Ok(())
    }

    /// Queue a work-order write (a record folds into a queued record).
    fn queue_write(&mut self, write: LedgerWrite) {
        match (&mut self.erasure.write, write) {
            (Some(LedgerWrite::Record(queued)), LedgerWrite::Record(next)) => queued.absorb(&next),
            (slot, write) => *slot = Some(write),
        }
    }

    /// Run one ledger call on its own task (the order as it is now).
    fn spawn_ledger(&mut self, ledger: Arc<dyn ErasureLedger>, call: LedgerCall) {
        let (tenant, node, order) = (self.cfg.tenant_id.clone(), self.erasure.executor_node.clone(), self.erasure.order.clone());
        let task = call.clone();
        let handle = tokio::spawn(async move {
            match task {
                LedgerCall::Claim => ledger.claim(&tenant, &node).await,
                LedgerCall::Write(write) => {
                    let order = order.context("erasure ledger write without an order")?;
                    match write {
                        LedgerWrite::Record(record) => ledger.record_step(&tenant, &node, &order, &record).await,
                        LedgerWrite::Complete => ledger.complete(&tenant, &node, &order).await,
                        LedgerWrite::Fail { code, message } => ledger.fail(&tenant, &node, &order, code, &message).await,
                    }
                    .map(|()| None)
                }
            }
        });
        self.erasure.ledger_flight = Some(LedgerFlight { call, handle });
    }

    /// Apply a finished ledger call.
    fn ledger_reply(&mut self, call: LedgerCall, reply: Result<Option<LeanErasureOrder>>, now_ms: i64) -> Result<()> {
        let tenant = self.cfg.tenant_id.clone();
        match call {
            LedgerCall::Claim => {
                let Some(mut order) = reply? else { return Ok(()) };
                // Zero cross-tenant: the database confines the login to this
                // tenant's rows; an order for any other tenant is never executed.
                anyhow::ensure!(order.tenant_id == tenant, "the erasure ledger returned another tenant's order; refusing it");
                if order.progress.sweep_started_ms.is_none() {
                    order.progress.sweep_started_ms = Some(now_ms);
                }
                if order.progress.pass_began_ms.is_none() {
                    order.progress.pass_began_ms = order.progress.sweep_started_ms;
                }
                tracing::info!(tenant = %tenant, order = %order.order_id, phase = ?order.progress.phase,
                    identifier_type = order.subject.identifier_type.as_str(), "erasure order claimed");
                self.erasure.order = Some(order);
            }
            LedgerCall::Write(write) => {
                if let Err(error) = reply {
                    self.erasure.write_failures += 1;
                    if self.erasure.write_failures >= lean::MAX_CONSECUTIVE_FAILURES {
                        // Probably a lost lease: drop the order; a later claim
                        // re-takes it from its recorded progress (log commits
                        // stand and replay clean).
                        tracing::warn!(tenant = %tenant, error = %format!("{error:#}"), "erasure ledger writes keep failing; releasing the order");
                        self.erasure.write = None;
                        self.erasure.order = None;
                        self.erasure.write_failures = 0;
                        self.erasure.next_poll_ms = now_ms + lean::POLL_INTERVAL_MS;
                        return Ok(());
                    }
                    self.queue_write(write);
                    return Err(error);
                }
                self.erasure.write_failures = 0;
                let order_id = self.erasure.order.as_ref().map(|order| order.order_id);
                match write {
                    LedgerWrite::Record(_) => {}
                    LedgerWrite::Complete => {
                        tracing::info!(tenant = %tenant, order = ?order_id, "erasure order completed");
                        self.erasure.order = None;
                        self.erasure.next_poll_ms = 0;
                    }
                    LedgerWrite::Fail { code: Some(code), message } => {
                        tracing::error!(tenant = %tenant, order = ?order_id, code, message, "erasure order failed");
                        self.erasure.order = None;
                    }
                    LedgerWrite::Fail { code: None, .. } => self.erasure.retry_not_before_ms = now_ms + RETRY_MS,
                }
            }
        }
        Ok(())
    }

    /// Why a due step should give way now: the backlog catch-up (no
    /// background rewrite then, as `run_merges`), the history lanes all busy,
    /// the prevalence replay behind (a rewrite merges L0 parts away; their
    /// observations go first, as for any merge), or the pause after the
    /// previous step. Bounded by [`MAX_DEFERRAL_MS`].
    fn erasure_yield(&self, now_ms: i64, lag_ms: i64) -> Option<&'static str> {
        let history = self.merge_in_flight.iter().filter(|flight| flight.merge.output_level != Level::Minute).count();
        if self.cfg.background_merges && self.catching_up(lag_ms) {
            Some("catching_up")
        } else if history >= super::super::merge_lanes::capacity(Level::Hour) {
            Some("history_lanes_busy")
        } else if self.prevalence_behind() {
            Some("prevalence_behind")
        } else if now_ms < self.erasure.pause_until_ms {
            Some("step_pause")
        } else {
            None
        }
    }

    async fn start_erasure_step(&mut self, now_ms: i64, lag_ms: i64) -> Result<()> {
        if let Some(reason) = self.erasure_yield(now_ms, lag_ms) {
            let since = *self.erasure.deferred_since_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) < MAX_DEFERRAL_MS {
                return Ok(());
            }
            tracing::info!(tenant = %self.cfg.tenant_id, reason, deferred_ms = now_ms - since,
                "erasure step deferral bound reached; running one step beside it");
        }
        self.erasure.deferred_since_ms = None;
        let planned = lean::plan_hour(self.log.live().parts(), self.erasure.order.as_ref().context("order")?);
        let Some((hour, candidates)) = planned else {
            let order = self.erasure.order.as_mut().context("order")?;
            lean::end_of_pass(&mut order.progress, now_ms);
            tracing::info!(tenant = %self.cfg.tenant_id, order = %order.order_id, phase = ?order.progress.phase,
                sweeps = order.progress.sweeps, "erasure pass finished");
            self.queue_write(LedgerWrite::Record(StepRecord::default()));
            return Ok(());
        };
        // A running compaction of the same parts would lose the fence (or
        // we would): let it finish first (it is bounded; the next tick
        // re-plans).
        if self.merge_in_flight.iter().any(|flight| flight.merge.inputs.iter().any(|p| candidates.iter().any(|c| c.part_id == p.part_id))) {
            return Ok(());
        }
        let truncated = candidates.len() >= lean::MAX_PROBES_PER_STEP;
        let context = StepContext {
            tenant_id: self.cfg.tenant_id.clone(),
            trusted: self.trusted.clone(),
            work_dir: self.cfg.work_dir.clone(),
            schema: self.schema.clone(),
            fingerprint: self.log.live().schema().context("log schema")?.fingerprint.clone(),
            key_id: self.signer.key_id().to_string(),
            build: self.cfg.build.clone(),
            now_ms,
        };
        let order = self.erasure.order.clone().context("order")?;
        let handle = match (self.background_parts, self.background_signer) {
            (Some(store), Some(signer)) => {
                tokio::spawn(async move { run_step(store, signer, context, order, hour, candidates, truncated).await })
            }
            _ => {
                // Lab / inline: the borrowed store and signer; run it here.
                let outcome = run_step(self.parts, self.signer, context, order, hour, candidates, truncated).await;
                tokio::spawn(async move { outcome })
            }
        };
        self.erasure.flight = Some(ErasureFlight { hour, handle });
        self.erasure.pause_until_ms = now_ms.saturating_add(STEP_PAUSE_MS);
        Ok(())
    }

    async fn finish_erasure_step(&mut self, hour: i32, outcome: Result<StepOutcome>, now_ms: i64) -> Result<()> {
        let tenant = self.cfg.tenant_id.clone();
        let step = match outcome {
            Ok(step) => step,
            Err(error) => {
                let order = self.erasure.order.as_mut().context("order")?;
                let code = lean::count_failure(&mut order.progress, None);
                tracing::warn!(tenant = %tenant, order = %order.order_id, error = %format!("{error:#}"), "erasure step failed");
                self.queue_write(LedgerWrite::Fail { code, message: format!("{error:#}") });
                return Ok(());
            }
        };
        let mut record = StepRecord { objects_scanned: step.probed, objects_pruned: step.pruned, ..StepRecord::default() };
        match step.kind {
            StepKind::Unsupported(code) => {
                let order = self.erasure.order.as_mut().context("order")?;
                let code = lean::count_failure(&mut order.progress, Some(code)).unwrap_or(code);
                self.queue_write(LedgerWrite::Fail { code: Some(code), message: "an adopted part may hold the subject".into() });
                return Ok(());
            }
            StepKind::Clean => {
                let order = self.erasure.order.as_mut().context("order")?;
                lean::clean(&mut order.progress, hour, step.resume_after.clone());
            }
            StepKind::Rewrite { .. } | StepKind::Retire { .. } => {
                // Same fence as `commit_merge`: an input that stopped being
                // live (a compaction committed first) drops this output for
                // orphan GC; the next step re-plans the hour.
                if !step.inputs.iter().all(|part| self.log.live().get(&part.part_id).is_some()) {
                    tracing::info!(tenant = %tenant, hour, "erasure inputs changed while the step ran; re-planning the hour");
                    return Ok(());
                }
                let order = self.erasure.order.as_ref().context("order")?;
                let deletion_unit = order.deletion_unit();
                let supersedes = step.inputs.iter().map(|part| part.part_id.clone()).collect::<Vec<_>>();
                let (op, output) = match step.kind {
                    StepKind::Rewrite { result, output } => {
                        record.rows_removed = result.filtered_out;
                        record.rows_redacted = result.filter_rewritten;
                        record.bytes_rewritten = output.data_bytes;
                        record.parts_superseded = supersedes.len() as u64;
                        (LogOp::Rewrite { output: output.clone(), supersedes, deletion_unit }, Some(output))
                    }
                    StepKind::Retire { rows_removed } => {
                        record.rows_removed = rows_removed;
                        record.parts_retired = supersedes.len() as u64;
                        (LogOp::Retire { parts: supersedes, reason: RetireReason::Erasure, deletion_unit }, None)
                    }
                    StepKind::Clean | StepKind::Unsupported(_) => unreachable!("handled above"),
                };
                let AppendOutcome::Committed { seq, .. } = self.log.append(op, now_ms).await?;
                if let Some(output) = &output {
                    // Window completeness, as `commit_merge`: the output holds
                    // a subset of its inputs' uids for each of its hours.
                    for out_hour in hours_of(output) {
                        let inputs = step.inputs.iter().filter(|p| hours_of(p).contains(&out_hour))
                            .map(|p| p.part_id.as_str()).collect::<Vec<_>>();
                        let tiered = self.late.inherit(out_hour, &inputs, output.part_id.as_str());
                        if inputs.iter().all(|p| self.window.has_loaded(out_hour, p) || (!tiered && self.late.covers(out_hour, p))) {
                            self.window.load_marker(out_hour, output.part_id.as_str(), now_ms);
                        }
                    }
                }
                record.objects_rewritten = step.inputs.len() as u64;
                record.part_log_first_seq = Some(seq);
                record.part_log_last_seq = Some(seq);
                let order = self.erasure.order.as_mut().context("order")?;
                lean::changed(&mut order.progress, seq, hour, step.resume_after.clone());
                tracing::info!(tenant = %tenant, order = %order.order_id, hour, seq, inputs = step.inputs.len(),
                    rows_removed = record.rows_removed, rows_redacted = record.rows_redacted, "erasure rewrite committed");
            }
        }
        // The log commit stands whatever happens to this write (retried).
        self.queue_write(LedgerWrite::Record(record));
        Ok(())
    }

    async fn erase_prevalence(&mut self, now_ms: i64) -> Result<()> {
        let order = self.erasure.order.as_ref().context("order")?;
        let ip = order.subject.identifier_type == ErasureIdentifierType::Ip;
        // The address stays in the tenant's SlateDB window until a held state
        // deletes it, after every `add` through the last rewrite is applied
        // (or a replay of a pre-erasure part would re-add it).
        let waiting = if !ip {
            None
        } else if self.cfg.prevalence_enabled && !self.prevalence_held() {
            Some("prevalence grant not held")
        } else if self.prevalence_held() && (self.prevalence_behind() || order.progress.last_commit_seq
            .is_some_and(|seq| self.prevalence_applied_seq.is_none_or(|applied| applied < seq))) {
            Some("prevalence replay behind the last rewrite")
        } else {
            None
        };
        if let Some(why) = waiting {
            let order = self.erasure.order.as_mut().context("order")?;
            let since = *order.progress.prevalence_wait_since_ms.get_or_insert(now_ms);
            if now_ms.saturating_sub(since) >= lean::PREVALENCE_GRANT_WAIT_MS {
                self.queue_write(LedgerWrite::Fail { code: Some(lean::PREVALENCE_UNAVAILABLE),
                    message: format!("{why} for {} h; the address could not be removed from prevalence", lean::PREVALENCE_GRANT_WAIT_MS / 3_600_000) });
            } else if now_ms >= self.erasure.wait_record_due_ms {
                // Keep the lease (and the wait's start) recorded.
                self.erasure.wait_record_due_ms = now_ms + lean::POLL_INTERVAL_MS;
                self.queue_write(LedgerWrite::Record(StepRecord::default()));
            }
            return Ok(());
        }
        if ip && self.prevalence_held() {
            let wait = self.ingest_wait();
            let value = order.subject.value().to_string();
            let order_id = order.order_id;
            let Some(prevalence) = self.prevalence.as_mut() else { return Ok(()) };
            let erased = tokio::time::timeout(wait, prevalence.erase_artifact("ip", &value)).await
                .context("prevalence erase overran the ingest wait")??;
            tracing::info!(tenant = %self.cfg.tenant_id, order = %order_id, erased, "erasure prevalence window removed");
        }
        // Not an IP subject (prevalence keys IPs only), or prevalence is not
        // configured for this tenant (no state exists to hold the address).
        self.complete_erasure()
    }

    fn complete_erasure(&mut self) -> Result<()> {
        let order = self.erasure.order.as_mut().context("order")?;
        order.progress.phase = LeanPhase::Done;
        tracing::info!(tenant = %self.cfg.tenant_id, order = %order.order_id, sweeps = order.progress.sweeps,
            last_seq = ?order.progress.last_commit_seq, "erasure order finished; completing it");
        self.queue_write(LedgerWrite::Complete);
        Ok(())
    }
}

/// The production step I/O: sidecar probes, then download, filtered merge
/// and publish (nothing here touches the log: the tick commits).
struct LakeStepIo<'s> {
    store: &'s dyn ObjectStore,
    signer: &'s dyn PartSigner,
    context: StepContext,
    order: LeanErasureOrder,
}

#[async_trait::async_trait]
impl StepIo for LakeStepIo<'_> {
    async fn probe(&self, part: &PartRef) -> Result<Probe> {
        probe_part(self.store, &self.context.tenant_id, &self.context.trusted, part, &self.order).await
    }

    async fn rewrite(&self, level: Level, event_hour: i32, inputs: &[PartRef]) -> Result<StepKind> {
        let context = &self.context;
        let mut local = Vec::with_capacity(inputs.len());
        for part in inputs {
            let dir = download_part_with_quota(self.store, &context.tenant_id, &context.trusted, &context.work_dir, part, true).await?;
            local.push(MergeInput { part: part.clone(), dir });
        }
        let filter = self.order.filter()?;
        let ctx = context.clone();
        let merged = super::super::merge_lanes::compute(move || {
            merge_parts_filtered(&parts_dir(&ctx.work_dir), &ctx.tenant_id, level, event_hour, &local, ctx.schema.clone(),
                &ctx.fingerprint, &ctx.key_id, &ctx.build, ctx.now_ms, filter)
        }).await??;
        Ok(match merged {
            FilteredMerge::Empty { rows_removed } => StepKind::Retire { rows_removed },
            FilteredMerge::Part(result) if result.filtered_out == 0 && result.filter_rewritten == 0 => {
                // The sidecars could not exclude the subject, but no row holds it.
                let _ = std::fs::remove_dir_all(&result.finished.dir);
                StepKind::Clean
            }
            FilteredMerge::Part(result) => {
                let output = super::super::writer::publish_compacted_parts(self.store, self.signer, &context.trusted,
                    std::slice::from_ref(&result.finished)).await?.remove(0);
                StepKind::Rewrite { result, output }
            }
        })
    }
}

/// One step over a slice of `hour` ([`execute_step`]).
async fn run_step(
    store: &dyn ObjectStore,
    signer: &dyn PartSigner,
    context: StepContext,
    order: LeanErasureOrder,
    hour: i32,
    candidates: Vec<PartRef>,
    truncated: bool,
) -> Result<StepOutcome> {
    let io = LakeStepIo { store, signer, context, order };
    execute_step(&io, hour, candidates, truncated).await
}
