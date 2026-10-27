// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4592: per-flush owner round trips for native part writes.
//!
//! The large tenant (FP, 10-26) committed ~480 rows/s, about its arrival rate, while its
//! backlog grew. Every object of a flush (data files, provenance, the log
//! entry) paid owner `lake-writers:authorize` (p50 0.98 s, p90 2.5 s) and
//! `lake-writers:complete` (p50 1.4 s, p90 4.1 s) one by one, and three of
//! those stages run back to back. Two changes, both on the native writer:
//!
//! * **Write-behind completion** ([`CompletionLane`]). A part object (any key
//!   of the `lake_part_file` family: `parts/…`) returns from its write once
//!   the PUT evidence (strong ETag) is journaled. Its owner completion runs
//!   in the background, coalesced with the objects beside it. A part-log
//!   entry or checkpoint (the only writes that make parts live) waits, while
//!   it authorizes, until every part completion begun before it has been
//!   registered. A failed completion makes that wait fail, so the log write
//!   fails closed and the journal replays the completion (exactly as a
//!   failed synchronous completion did). The invariant is unchanged: the
//!   part log never names an object the owner has not registered.
//! * **Coalescing** ([`AuthorizeCoalescer`], and the lane for completions).
//!   Part-object calls that arrive together go to the owner as one
//!   `lake-writers:authorize-native-batch` / `:complete-native-batch` call
//!   of at most [`NATIVE_BATCH_MAX_ITEMS`] objects (the hosted control plane #3118),
//!   each item byte-for-byte the single route's body. An owner that does not
//!   serve them yet (404/405/401/501, before its owner image and envoy roll)
//!   is remembered for [`UNSUPPORTED_REPROBE`] and the objects use the single
//!   routes, as before. Any other batch refusal is re-asked per object, so
//!   per-key outcomes (409, 422 reservation refused, …) stay exact; an owner
//!   still unavailable after the retry window fails every object of the call.
//!
//! Both are idempotent per `request_id` on the owner, so a coalesced call that
//! is cancelled, refused or partly applied is always safe to re-ask singly.
use super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Nano Main's native batch routes on the pooled-cell owner listener.
pub const NATIVE_AUTHORIZE_BATCH_PATH: &str = "/internal/v1/enterprise-shared/lake-writers:authorize-native-batch";
pub const NATIVE_COMPLETE_BATCH_PATH: &str = "/internal/v1/enterprise-shared/lake-writers:complete-native-batch";
/// Objects per batch call. The owner accepts up to 16 but runs 4 items at a
/// time, so a larger batch would answer in several waves (slower than the
/// singles it replaces, and a 16-item completion at p90 nears the cell
/// listener's 30 s route timeout). Four is one wave: a batch answers as fast
/// as one single call, and wider publications send several batches at once.
pub const NATIVE_BATCH_MAX_ITEMS: usize = 4;
/// 16 identities (~2.3 KiB each) or receipts fit with room to spare.
const BATCH_RESPONSE_CAP: usize = 256 * 1024;
/// How long calls that arrive together are gathered into one batch. A
/// publication starts its object writes together; this is far below one
/// owner round trip.
pub(super) const COALESCE_WINDOW: Duration = Duration::from_millis(5);
/// Re-ask an owner that did not serve the batch routes after this long.
const UNSUPPORTED_REPROBE: Duration = Duration::from_secs(600);
/// The only key family whose completion is write-behind: part objects.
pub(super) const DEFERRABLE_FAMILY: &str = "lake_part_file";

/// A batch call the owner does not serve (yet): its envoy has no route
/// (404), the route is not a POST route (405), the owner app refuses an
/// unknown path on the cell listener (401) or does not implement it (501).
/// The single routes then still decide the outcome, including a real 401.
fn batch_unserved(error: &anyhow::Error) -> bool {
    error.downcast_ref::<OwnerRefused>().is_some_and(|refused| matches!(refused.status, 401 | 404 | 405 | 501))
}
/// An owner that stayed unavailable through the whole retry window: asking
/// it again object by object would only multiply the load it is shedding.
fn unavailable_status(error: &anyhow::Error) -> Option<u16> {
    error.downcast_ref::<OwnerRefused>().map(|refused| refused.status).filter(|status| owner_unavailable(*status))
}

#[derive(Default)]
pub(super) struct BatchSupport {
    authorize: Mutex<Option<std::time::Instant>>,
    complete: Mutex<Option<std::time::Instant>>,
}
impl BatchSupport {
    fn usable(slot: &Mutex<Option<std::time::Instant>>) -> bool {
        slot.lock().expect("batch support").is_none_or(|until| std::time::Instant::now() >= until)
    }
    fn unserved(slot: &Mutex<Option<std::time::Instant>>) {
        *slot.lock().expect("batch support") = Some(std::time::Instant::now() + UNSUPPORTED_REPROBE);
    }
    pub(super) fn diagnostics(&self) -> Value {
        json!({"authorize_batch_usable": Self::usable(&self.authorize), "complete_batch_usable": Self::usable(&self.complete)})
    }
}

// ---------------------------------------------------------------- authorize

enum Authorized {
    Identity(Value),
    /// Ask the single route (alone in its window, or the batch was refused).
    Single,
    /// The owner stayed unavailable for the whole batch.
    Unavailable(u16),
}

#[derive(Default)]
pub(super) struct AuthorizeCoalescer {
    state: Mutex<Gathering<(Value, tokio::sync::oneshot::Sender<Authorized>)>>,
}

struct Gathering<T> {
    queued: Vec<T>,
    forming: bool,
}
impl<T> Default for Gathering<T> {
    fn default() -> Self { Self { queued: Vec::new(), forming: false } }
}
impl<T> Gathering<T> {
    /// Queue `item`; true when the caller must start a gatherer.
    fn push(&mut self, item: T) -> bool {
        self.queued.push(item);
        !std::mem::replace(&mut self.forming, true)
    }
    /// Take the next batch; `forming` stays set (and the caller starts
    /// another gatherer) while more remain.
    fn take(&mut self) -> (Vec<T>, bool) {
        let n = self.queued.len().min(NATIVE_BATCH_MAX_ITEMS);
        let batch = self.queued.drain(..n).collect();
        let more = !self.queued.is_empty();
        self.forming = more;
        (batch, more)
    }
}

impl AuthorizeCoalescer {
    /// The owner identity for one part object's `request`, authorized
    /// together with the part objects that arrive with it.
    pub(super) async fn authorize(writer: &Arc<NativePartWriter>, request: &Value) -> Result<Value> {
        #[cfg(test)]
        if writer.synchronous_completion {
            return writer.post(AUTHORIZE_PATH, request).await;
        }
        if !BatchSupport::usable(&writer.batch.authorize) {
            return writer.post(AUTHORIZE_PATH, request).await;
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let start = writer.authorizer.state.lock().expect("authorize coalescer").push((request.clone(), sender));
        if start {
            tokio::spawn(Self::gather(writer.clone()));
        }
        match receiver.await {
            Ok(Authorized::Identity(identity)) => Ok(identity),
            Ok(Authorized::Unavailable(status)) => Err(OwnerRefused { status }.into()),
            Ok(Authorized::Single) | Err(_) => writer.post(AUTHORIZE_PATH, request).await,
        }
    }

    /// Boxed: a gatherer may start the next one, so its future type must
    /// not name itself.
    fn gather(writer: Arc<NativePartWriter>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(Self::gather_once(writer))
    }
    async fn gather_once(writer: Arc<NativePartWriter>) {
        tokio::time::sleep(writer.coalesce_window).await;
        let (batch, more) = writer.authorizer.state.lock().expect("authorize coalescer").take();
        if more {
            tokio::spawn(Self::gather(writer.clone()));
        }
        if batch.len() < 2 {
            for (_, sender) in batch { let _ = sender.send(Authorized::Single); }
            return;
        }
        let requests = batch.iter().map(|(request, _)| request.clone()).collect::<Vec<_>>();
        let body = json!({"schema_version":1,"requests":requests});
        let answer = writer.post_paced(NATIVE_AUTHORIZE_BATCH_PATH, &body, batch.len() as u32, BATCH_RESPONSE_CAP).await
            .and_then(|response| {
                let identities = response["identities"].as_array().filter(|_| response["schema_version"] == 1)
                    .filter(|identities| identities.len() == batch.len())
                    .context("owner batch authorization answered a different inventory")?;
                Ok(identities.clone())
            });
        match answer {
            Ok(identities) => {
                // Each identity is validated against its own request by the
                // caller, exactly as a single answer is.
                for ((_, sender), identity) in batch.into_iter().zip(identities) {
                    let _ = sender.send(Authorized::Identity(identity));
                }
            }
            Err(error) => {
                let unavailable = unavailable_status(&error);
                if batch_unserved(&error) {
                    BatchSupport::unserved(&writer.batch.authorize);
                    tracing::info!("owner does not serve batch authorization yet; part objects authorize one by one");
                } else if unavailable.is_none() {
                    writer.counters.batch_fallbacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(error = %format!("{error:#}"), objects = batch.len(),
                        "owner refused a batch authorization; asking per object for exact outcomes");
                }
                for (_, sender) in batch {
                    let _ = sender.send(unavailable.map_or(Authorized::Single, Authorized::Unavailable));
                }
            }
        }
    }
}

// ---------------------------------------------------------------- complete

struct Queued {
    seq: u64,
    path: PathBuf,
    intent: Intent,
}

#[derive(Clone)]
struct LaneFailure {
    status: Option<u16>,
    message: String,
}

#[derive(Default)]
struct LaneState {
    next_seq: u64,
    /// Every write-behind completion not yet settled, by enqueue order.
    outstanding: BTreeMap<u64, String>,
    gathering: Gathering<Queued>,
    /// The first completion that failed since the last good replay.
    failure: Option<LaneFailure>,
}

/// Write-behind owner completions of part objects (see the module docs).
#[derive(Default)]
pub(super) struct CompletionLane {
    state: Mutex<LaneState>,
    changed: tokio::sync::Notify,
}

impl CompletionLane {
    pub(super) fn outstanding(&self) -> usize {
        self.state.lock().expect("completion lane").outstanding.len()
    }

    /// Start the owner completion of a journaled part-object PUT.
    pub(super) fn enqueue(&self, writer: &Arc<NativePartWriter>, path: PathBuf, intent: Intent) {
        let request_id = intent.request["request_id"].as_str().unwrap_or_default().to_string();
        let start = {
            let mut state = self.state.lock().expect("completion lane");
            let seq = state.next_seq;
            state.next_seq += 1;
            state.outstanding.insert(seq, request_id);
            state.gathering.push(Queued { seq, path, intent })
        };
        if start {
            tokio::spawn(Self::gather(writer.clone()));
        }
    }

    async fn wait_until(&self, done: impl Fn(&LaneState) -> bool) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if done(&self.state.lock().expect("completion lane")) {
                return;
            }
            notified.await;
        }
    }

    /// Every completion enqueued before this call is registered, or the
    /// first failure since the last good replay (fail closed).
    pub(super) async fn barrier(&self) -> Result<()> {
        let target = self.state.lock().expect("completion lane").next_seq;
        self.wait_until(|state| state.failure.is_some() || state.outstanding.range(..target).next().is_none()).await;
        match self.state.lock().expect("completion lane").failure.clone() {
            None => Ok(()),
            Some(failure) => {
                let error = match failure.status {
                    Some(status) => anyhow::Error::new(OwnerRefused { status }),
                    None => anyhow::anyhow!("{}", failure.message),
                };
                Err(error.context("a write-behind part completion failed; the journal replays it before the next write"))
            }
        }
    }

    /// No completion of `request_id` is running.
    pub(super) async fn settled(&self, request_id: &str) {
        self.wait_until(|state| !state.outstanding.values().any(|id| id == request_id)).await;
    }

    /// No completion is running.
    pub(super) async fn idle(&self) {
        self.wait_until(|state| state.outstanding.is_empty()).await;
    }

    pub(super) fn clear_failure(&self) {
        self.state.lock().expect("completion lane").failure = None;
    }

    fn settle(&self, seq: u64, result: &Result<()>) {
        {
            let mut state = self.state.lock().expect("completion lane");
            state.outstanding.remove(&seq);
            if let Err(error) = result {
                state.failure.get_or_insert_with(|| LaneFailure {
                    status: error.downcast_ref::<OwnerRefused>().map(|refused| refused.status),
                    message: format!("{error:#}"),
                });
            }
        }
        self.changed.notify_waiters();
    }

    /// Boxed for the same reason as [`AuthorizeCoalescer::gather`].
    fn gather(writer: Arc<NativePartWriter>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            tokio::time::sleep(writer.coalesce_window).await;
            let (batch, more) = writer.lane.state.lock().expect("completion lane").gathering.take();
            if more {
                tokio::spawn(Self::gather(writer.clone()));
            }
            writer.complete_queued(batch).await;
        })
    }
}

impl NativePartWriter {
    /// Complete write-behind part objects: one batch call when the owner
    /// serves it, else (or for objects the batch refused) one by one.
    async fn complete_queued(&self, batch: Vec<Queued>) {
        let mut remaining = batch;
        if remaining.len() > 1 && BatchSupport::usable(&self.batch.complete) {
            let completions = remaining.iter().map(|queued| Self::completion_body(&queued.intent)).collect::<Vec<_>>();
            let body = json!({"schema_version":1,"completions":completions});
            let answer = self.post_paced(NATIVE_COMPLETE_BATCH_PATH, &body, remaining.len() as u32, BATCH_RESPONSE_CAP).await
                .and_then(|response| {
                    let receipts = response["receipts"].as_array().filter(|_| response["schema_version"] == 1)
                        .filter(|receipts| receipts.len() == remaining.len())
                        .context("owner batch completion answered a different inventory")?;
                    Ok(receipts.clone())
                });
            match answer {
                Ok(receipts) => {
                    for (queued, receipt) in remaining.into_iter().zip(receipts) {
                        let Queued { seq, path, mut intent } = queued;
                        intent.registered = Some(receipt);
                        let result = Self::validate_registered(&intent)
                            .and_then(|()| self.save(&path, &intent))
                            .and_then(|()| self.archive_registered(&path, &intent));
                        self.settle_completion(seq, result);
                    }
                    return;
                }
                Err(error) => {
                    if batch_unserved(&error) {
                        BatchSupport::unserved(&self.batch.complete);
                        tracing::info!("owner does not serve batch completion yet; part objects complete one by one");
                    } else if let Some(status) = unavailable_status(&error) {
                        for queued in remaining {
                            self.settle_completion(queued.seq, Err(OwnerRefused { status }.into()));
                        }
                        return;
                    } else {
                        self.counters.batch_fallbacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::warn!(error = %format!("{error:#}"), objects = remaining.len(),
                            "owner refused a batch completion; completing per object for exact outcomes");
                    }
                }
            }
        }
        let singles = std::mem::take(&mut remaining).into_iter().map(|queued| async move {
            let result = self.complete_intent(&queued.path, queued.intent).await;
            self.settle_completion(queued.seq, result);
        });
        futures::future::join_all(singles).await;
    }

    fn settle_completion(&self, seq: u64, result: Result<()>) {
        if let Err(error) = &result {
            tracing::warn!(error = %format!("{error:#}"),
                "write-behind part completion failed; the next part-log write fails closed and the journal replays it");
            self.mark_needs_replay();
        }
        self.lane.settle(seq, &result);
    }
}

#[cfg(test)]
#[path = "native_lanes_tests.rs"]
mod tests;
