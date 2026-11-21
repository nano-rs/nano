// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group commit for log-source changes that re-render the Vector config
//! (NAN-5678).
//!
//! Every log-source delete re-renders the whole Vector config from the
//! surviving sources and reloads Vector once. A reload costs a full VRL
//! compile of every deployed parser (about 45 s for 41 OCSF parsers on one
//! fast core, more on a cloud vCPU, and the compile is single-threaded), so
//! deleting 36 sources one call at a time cost 36 reloads, each of which
//! could outlast the acknowledgement cap.
//!
//! [`ChangeBatcher`] turns concurrent changes into one render and one reload:
//!
//! * A caller [`submit`](ChangeBatcher::submit)s its keys and waits.
//! * The first caller starts a leader task. The leader waits `window` for
//!   other callers, takes EVERY pending key, and runs the batch once. Keys
//!   submitted while a batch runs (it holds the deploy lock for the whole
//!   reload) go into the next batch, so N concurrent changes cost at most two
//!   reloads, and N changes submitted together cost one.
//! * Each caller gets the result the batch recorded for ITS keys, so the
//!   answer stays truthful: a failed render fails every key in the batch, and
//!   a key the batch rejected on its own (not found) fails alone.
//! * The batch runs in its own task. A caller that stops waiting (the HTTP
//!   client disconnected or timed out) does not cancel the batch, so the
//!   render, the reload and the database writes after it are never cut off
//!   halfway (the half-applied delete of NAN-5678).

use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::sync::oneshot;

/// Runs one batch: every key pending when it started, deduplicated, in
/// submission order. Returns a result per key it judged.
pub type BatchRunner<K, R> = Arc<dyn Fn(Vec<K>) -> BoxFuture<'static, HashMap<K, R>> + Send + Sync>;

/// Why a caller got no result from its batch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BatchError {
    /// The batch task panicked or was cancelled (runtime shutdown).
    #[error("the batched change did not complete: {0}")]
    Aborted(String),
    /// The batch finished without recording a result for this key.
    #[error("the batched change recorded no result for this item")]
    NoResult,
}

struct Waiter<K, R> {
    keys: Vec<K>,
    runner: BatchRunner<K, R>,
    reply: oneshot::Sender<Result<HashMap<K, R>, BatchError>>,
}

struct Inner<K, R> {
    pending: Vec<Waiter<K, R>>,
    leader_running: bool,
    batches_run: u64,
}

/// See the module docs.
pub struct ChangeBatcher<K, R> {
    inner: Arc<Mutex<Inner<K, R>>>,
    window: Duration,
}

impl<K, R> ChangeBatcher<K, R>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    R: Clone + Send + 'static,
{
    /// `window`: how long the leader waits for more changes before it runs a
    /// batch. Zero still batches whatever is pending when the leader runs.
    pub fn new(window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner { pending: Vec::new(), leader_running: false, batches_run: 0 })),
            window,
        }
    }

    /// Batches run so far (tests and diagnostics).
    pub fn batches_run(&self) -> u64 {
        self.inner.lock().expect("change batcher poisoned").batches_run
    }

    /// Queue `keys` and wait for the batch that includes them. The result
    /// map holds an entry per submitted key: the batch's result, or
    /// [`BatchError`] when it recorded none.
    ///
    /// `runner` runs the batch when this caller's keys are the first pending
    /// ones; every caller of one batcher passes the same operation.
    pub async fn submit(&self, keys: Vec<K>, runner: BatchRunner<K, R>) -> HashMap<K, Result<R, BatchError>> {
        if keys.is_empty() {
            return HashMap::new();
        }
        let (reply, receive) = oneshot::channel();
        let start_leader = {
            let mut inner = self.inner.lock().expect("change batcher poisoned");
            inner.pending.push(Waiter { keys: keys.clone(), runner, reply });
            !std::mem::replace(&mut inner.leader_running, true)
        };
        if start_leader {
            tokio::spawn(lead(Arc::clone(&self.inner), self.window));
        }
        let outcome = receive
            .await
            .unwrap_or_else(|_| Err(BatchError::Aborted("the batch task stopped".to_string())));
        keys.into_iter()
            .map(|key| {
                let result = match &outcome {
                    Ok(results) => results.get(&key).cloned().ok_or(BatchError::NoResult),
                    Err(error) => Err(error.clone()),
                };
                (key, result)
            })
            .collect()
    }
}

/// The leader: run batches until nothing is pending.
async fn lead<K, R>(inner: Arc<Mutex<Inner<K, R>>>, window: Duration)
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    R: Clone + Send + 'static,
{
    loop {
        if !window.is_zero() {
            tokio::time::sleep(window).await;
        }
        let batch = {
            let mut inner = inner.lock().expect("change batcher poisoned");
            if inner.pending.is_empty() {
                inner.leader_running = false;
                return;
            }
            inner.batches_run += 1;
            std::mem::take(&mut inner.pending)
        };
        let runner = Arc::clone(&batch[0].runner);
        let mut seen = HashSet::new();
        let keys: Vec<K> = batch
            .iter()
            .flat_map(|waiter| waiter.keys.iter().cloned())
            .filter(|key| seen.insert(key.clone()))
            .collect();
        // Its own task, so a panic in the batch fails this batch's callers
        // and the leader carries on with the next one.
        let outcome = tokio::spawn(runner(keys))
            .await
            .map_err(|error| BatchError::Aborted(error.to_string()));
        for waiter in batch {
            let reply = match &outcome {
                Ok(results) => Ok(waiter
                    .keys
                    .iter()
                    .filter_map(|key| results.get(key).map(|result| (key.clone(), result.clone())))
                    .collect()),
                Err(error) => Err(error.clone()),
            };
            // A caller that stopped waiting is fine: the batch already ran.
            let _ = waiter.reply.send(reply);
        }
    }
}

#[cfg(test)]
#[path = "change_batch_tests.rs"]
mod tests;
