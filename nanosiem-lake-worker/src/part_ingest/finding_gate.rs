// SPDX-License-Identifier: AGPL-3.0-or-later

//! Finding appends from detect[T] never block the ingest loop.
//!
//! A lean test tenant (2026-09-29): a retried finding append found its
//! attempt marker and ran the replay proof — a genesis part-log scan of ~30k
//! entries — while HOLDING the ingestor lock. The ingest loop (edge-log pulls,
//! L0 flushes) and the credential swap (which also took the lock) waited ~20
//! min; detect's 60 s ack timeout fired, it retried, and the next retry
//! scanned again.
//!
//! The gate splits every append:
//! - admission: a bounded queue ([`FindingGateConfig::queue_depth`]); a full
//!   queue refuses at once ([`FindingRefused::QueueFull`]);
//! - one append at a time (the part log has one writer), each under one
//!   deadline ([`FindingGateConfig::deadline`], below detect's ack timeout);
//! - validation and the replay proof run WITHOUT the ingestor lock. A proof
//!   runs in the background, so a proof longer than the deadline completes
//!   for the retry instead of restarting each time;
//! - NAN-4656: one proof runs at a time, and a retry waits on the running
//!   one. The proof records durable floors as it goes
//!   ([`super::finding_floors`]), so a proof started later (a new receipt
//!   set, a restart, detect's own drain proof) resumes after them. The ops
//!   tenant (2026-10-26) lost its finished proofs to a TTL counted from the
//!   START of an 11-minute scan and re-read 57.8k entries every retry;
//! - every object of the finding parts is registered with the owner writer
//!   authority (NAN-3499) without the lock, before the commit;
//! - only the commit (schema, attempt markers, log `Add`) takes the lock, and
//!   waiting for it is bounded by the same deadline.
//!
//! A refused append leaves the outbox rows in place; detect's drain retries.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::finding_append::{FindingAppendRequest, FindingAppendResponse};
use super::ingest::{finding_replay_proof, register_finding_parts, validate_finding, FindingAppendContext, Ingestor};
use crate::parts::part_log::SourceRef;

#[derive(Debug, Clone)]
pub struct FindingGateConfig {
    /// Appends admitted (running + waiting) at once.
    pub queue_depth: usize,
    /// Per-append budget from admission to the commit taking the lock.
    /// Below detect's 60 s acknowledgement timeout.
    pub deadline: Duration,
    /// Replay proofs kept (running or finished, not yet consumed).
    pub max_proofs: usize,
    /// A finished proof that found its replay is dropped this long after it
    /// FINISHED if nobody consumed it. A finished "not committed" outcome is
    /// never reused: the next proof extends it from its floor to the head.
    pub proof_ttl: Duration,
}

impl Default for FindingGateConfig {
    fn default() -> Self {
        Self { queue_depth: 4, deadline: Duration::from_secs(40), max_proofs: 8, proof_ttl: Duration::from_secs(600) }
    }
}

/// Why an append was refused before it touched the log. The rows stay in
/// detect's outbox; its drain retries.
#[derive(Debug, thiserror::Error)]
pub enum FindingRefused {
    #[error("finding append queue is full ({0} admitted); retry later")]
    QueueFull(usize),
    #[error("finding append deadline elapsed while {0}; retry later")]
    Deadline(&'static str),
    #[error("too many finding replay proofs in flight; retry later")]
    ProofsBusy,
}

/// `(finished at, result)` once the proof ends.
type ProofOutcome = Option<(Instant, std::result::Result<Option<FindingAppendResponse>, String>)>;

struct Proof {
    outcome: tokio::sync::watch::Receiver<ProofOutcome>,
}

impl Proof {
    fn running(&self) -> bool {
        self.outcome.borrow().is_none()
    }

    /// A finished outcome worth handing to a later retry: a found replay
    /// (permanent, the log is append-only) still within its TTL. An error
    /// or "not committed" is re-proven from the durable floors instead, so
    /// a stale "absent" can never let a second `Add` through.
    fn reusable(&self, ttl: Duration) -> bool {
        matches!(&*self.outcome.borrow(), Some((finished, Ok(Some(_)))) if finished.elapsed() < ttl)
    }
}

pub struct FindingGate {
    config: FindingGateConfig,
    queue: Arc<tokio::sync::Semaphore>,
    exec: tokio::sync::Semaphore,
    proofs: Mutex<HashMap<String, Proof>>,
}

/// An admitted append (a queue slot); dropping it frees the slot.
pub struct Admitted(#[allow(dead_code)] tokio::sync::OwnedSemaphorePermit);

impl FindingGate {
    pub fn new(config: FindingGateConfig) -> Self {
        Self {
            queue: Arc::new(tokio::sync::Semaphore::new(config.queue_depth.max(1))),
            exec: tokio::sync::Semaphore::new(1),
            proofs: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Take a queue slot or refuse at once.
    pub fn admit(&self) -> std::result::Result<Admitted, FindingRefused> {
        self.queue.clone().try_acquire_owned().map(Admitted).map_err(|_| FindingRefused::QueueFull(self.config.queue_depth))
    }

    /// Validate, prove and commit one append (see the module docs). The
    /// ingestor lock is held only for the commit.
    pub async fn append(
        &self,
        _admitted: Admitted,
        ingestor: &tokio::sync::Mutex<Ingestor<'static>>,
        context: &FindingAppendContext<'static>,
        request: FindingAppendRequest,
        now_ms: impl Fn() -> i64,
    ) -> Result<FindingAppendResponse> {
        let deadline = tokio::time::Instant::now() + self.config.deadline;
        let _exec = tokio::time::timeout_at(deadline, self.exec.acquire())
            .await
            .map_err(|_| FindingRefused::Deadline("waiting for the previous append"))??;
        let mut validated = tokio::time::timeout_at(deadline, validate_finding(context, request))
            .await
            .map_err(|_| FindingRefused::Deadline("validating receipts and signed parts"))??;
        if validated.needs_replay_proof {
            let receipts = validated.request.receipts.clone();
            let attempted = validated.attempted.clone();
            if let Some(committed) = self.replay_proof(context, &receipts, &attempted, deadline).await? {
                return Ok(committed);
            }
        }
        // NAN-3499: the drain stored these parts outside the writer
        // authority; register them before the commit. Not under the deadline
        // (a native write must not be dropped midway); the commit refuses a
        // request whose own deadline passed meanwhile.
        register_finding_parts(context, &mut validated).await?;
        let mut ingestor = tokio::time::timeout_at(deadline, ingestor.lock())
            .await
            .map_err(|_| FindingRefused::Deadline("waiting for the ingest loop"))?;
        // From here the commit runs to completion (bounded by store timeouts):
        // the log append is not cancellation-safe.
        ingestor.commit_finding(validated, now_ms()).await
    }

    /// The background proof for `receipts`. Consumed (removed) once its
    /// outcome is returned; a proof still running at the deadline stays for
    /// the retry. NAN-4656: at most one proof runs; another receipt set
    /// waits for it (its floors then shorten the next one).
    async fn replay_proof(
        &self,
        context: &FindingAppendContext<'static>,
        receipts: &[SourceRef],
        attempted: &[SourceRef],
        deadline: tokio::time::Instant,
    ) -> Result<Option<FindingAppendResponse>> {
        let key = proof_key(receipts);
        let mut outcome = loop {
            let busy = {
                let mut proofs = self.proofs.lock().expect("proof lock");
                let ttl = self.config.proof_ttl;
                proofs.retain(|_, proof| proof.running() || proof.reusable(ttl));
                match proofs.get(&key) {
                    Some(proof) => break proof.outcome.clone(),
                    None => match proofs.values().find(|proof| proof.running()) {
                        Some(other) => other.outcome.clone(),
                        None => {
                            if proofs.len() >= self.config.max_proofs {
                                return Err(FindingRefused::ProofsBusy.into());
                            }
                            let (sender, receiver) = tokio::sync::watch::channel(None);
                            let context = context.clone();
                            let receipts = receipts.to_vec();
                            let attempted = attempted.to_vec();
                            tokio::spawn(async move {
                                let result = finding_replay_proof(&context, &receipts, &attempted).await
                                    .map_err(|error| format!("{error:#}"));
                                let _ = sender.send(Some((Instant::now(), result)));
                            });
                            proofs.insert(key.clone(), Proof { outcome: receiver.clone() });
                            break receiver;
                        }
                    },
                }
            };
            // Another receipt set's proof is reading the log: wait for it
            // rather than read the same entries twice.
            let mut busy = busy;
            tokio::time::timeout_at(deadline, busy.wait_for(Option::is_some)).await
                .map_err(|_| FindingRefused::Deadline("waiting for another replay proof (continues in the background)"))?
                .map_err(|_| anyhow::anyhow!("finding replay proof task ended without an outcome"))?;
        };
        let finished = tokio::time::timeout_at(deadline, outcome.wait_for(Option::is_some)).await;
        let result = match finished {
            Err(_) => return Err(FindingRefused::Deadline("proving a replay against the part log (continues in the background)").into()),
            Ok(Err(_)) => Err(anyhow::anyhow!("finding replay proof task ended without an outcome")),
            Ok(Ok(value)) => value.clone().expect("outcome is set").1.map_err(anyhow::Error::msg),
        };
        self.proofs.lock().expect("proof lock").remove(&key);
        result
    }

    /// Proofs held (tests, health).
    pub fn proofs_held(&self) -> usize {
        self.proofs.lock().expect("proof lock").len()
    }
}

fn proof_key(receipts: &[SourceRef]) -> String {
    let mut identities = receipts.iter().map(|r| format!("{}\0{}\0{}", r.key, r.version, r.sha256)).collect::<Vec<_>>();
    identities.sort();
    crate::parts::sha256_hex(identities.join("\n").as_bytes())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "finding_replay_tests.rs"]
mod replay_tests;
