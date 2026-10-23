// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4338: report quarantined edge segments to the tenant's landing ledger.
//!
//! **Why.** landing[T] commits each converted file to the hosted landing
//! ledger with its row count, and the ledger adds it to the source's `rows`.
//! When ingest[T] later refuses one of that file's edge segments whole and
//! quarantines it (NAN-3643: `admission_crashed`, `reserve_refused`, ...),
//! those rows were never stored, yet the bucket-drop card counted them.
//!
//! **Transport.** ingest[T]'s own edge-log consumer credential, on
//! `POST /edge-log/v1/quarantine` of the tenant Worker (tenant bound by the
//! credential). No new credential: the Worker forwards the report to the
//! landing ledger, which recorded at produce time which landed file (and
//! source, and epoch) each segment came from, and moves the rows from
//! `rows` to `rowsQuarantined`. An operator replay that committed reports
//! `replayed` and moves them back. Segments landing[T] did not produce
//! (HEC, Vector) match nothing.
//!
//! **Delivery.** Reports go to a small outbox file in the work dir, written
//! before the state change it describes is final (a replay's report is
//! queued before its quarantine entry is released), and are sent off the
//! tick, in order, at most [`MAX_PER_FLIGHT`] per flight, each bounded by
//! [`CALL_TIMEOUT`]; a failure keeps the rest and retries after
//! [`RETRY_MS`]. Every report is idempotent at the ledger, and on start
//! every kept quarantine entry is reported again (a crash between keeping
//! an object and queueing its report loses nothing).
//!
//! **Mixed versions.** A Worker from before this route answers 404 (the
//! `/edge-log` prefix is reserved), a tenant without a landing ledger 404,
//! a report the Worker cannot parse 400: the report is dropped, never
//! retried, and ingest is never held. A new Worker with an old ingest[T]
//! counts exactly as before.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The outbox, in ingest[T]'s work dir.
pub const OUTBOX_FILE: &str = "quarantine-ledger-outbox.json";
/// Most reports kept unsent (a quarantine holds at most a few hundred objects).
pub const MAX_OUTBOX: usize = 1024;
/// Reports sent per flight.
pub const MAX_PER_FLIGHT: usize = 16;
/// Wait after a failed send.
pub const RETRY_MS: i64 = 30_000;
/// One report's request bound.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportState {
    /// Refused whole and kept in the quarantine.
    Quarantined,
    /// An operator replay of it committed.
    Replayed,
}

/// One report, exactly the route's body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuarantineReport {
    pub segment_key: String,
    pub rows: u64,
    pub state: ReportState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportOutcome {
    /// The ledger has it (moved, already moved, or not a landing segment).
    Recorded,
    /// The Worker has no such route (older Worker, no landing ledger) or
    /// refuses the report's shape: drop it.
    Unsupported,
}

/// Where reports go (the tenant Worker; a fake in tests).
#[async_trait]
pub trait QuarantineLedgerSink: Send + Sync {
    async fn report(&self, report: &QuarantineReport) -> Result<ReportOutcome>;
}

struct Flight {
    /// The outcomes of the reports sent, in order, and the error that
    /// stopped the flight early.
    handle: tokio::task::JoinHandle<(Vec<ReportOutcome>, Option<anyhow::Error>)>,
}

/// The outbox and its sender.
pub struct QuarantineLedger {
    tenant_id: String,
    sink: Arc<dyn QuarantineLedgerSink>,
    outbox: VecDeque<QuarantineReport>,
    path: Option<PathBuf>,
    flight: Option<Flight>,
    next_send_ms: i64,
    /// Reports the ledger recorded / dropped as unsupported (health, tests).
    pub recorded: u64,
    pub unsupported: u64,
}

impl QuarantineLedger {
    /// Opens the outbox under `work_dir` (none: memory only, tests).
    pub fn open(tenant_id: &str, work_dir: Option<&Path>, sink: Arc<dyn QuarantineLedgerSink>) -> Self {
        let path = work_dir.map(|dir| dir.join(OUTBOX_FILE));
        let outbox = path.as_deref().map(load_outbox).unwrap_or_default();
        Self { tenant_id: tenant_id.to_string(), sink, outbox, path, flight: None, next_send_ms: 0, recorded: 0, unsupported: 0 }
    }

    /// Reports not yet delivered.
    pub fn pending(&self) -> usize {
        self.outbox.len()
    }

    /// Queue `report` (durably, when the outbox has a file). A report equal
    /// to the latest queued one for the same segment adds nothing.
    pub fn enqueue(&mut self, report: QuarantineReport) {
        if self.outbox.iter().rev().find(|queued| queued.segment_key == report.segment_key) == Some(&report) {
            return;
        }
        if self.outbox.len() >= MAX_OUTBOX {
            tracing::warn!(tenant = %self.tenant_id, key = %report.segment_key, bound = MAX_OUTBOX,
                "quarantine ledger outbox is full; this report is dropped (the landing rows count stays as it is)");
            return;
        }
        self.outbox.push_back(report);
        self.persist();
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let write = || -> Result<()> {
            let staged = path.with_extension("json.tmp");
            std::fs::write(&staged, serde_json::to_vec(&self.outbox)?)?;
            std::fs::rename(&staged, path)?;
            Ok(())
        };
        if let Err(error) = write() {
            tracing::warn!(tenant = %self.tenant_id, error = %format!("{error:#}"), "quarantine ledger outbox could not be written");
        }
    }

    /// One bounded step: collect a finished flight, then start the next one
    /// when due. Never waits on the Worker.
    pub async fn tick(&mut self, now_ms: i64) {
        if let Some(flight) = self.flight.take() {
            if !flight.handle.is_finished() {
                self.flight = Some(flight);
                return;
            }
            let (outcomes, error) = match flight.handle.await {
                Ok(result) => result,
                Err(error) => (Vec::new(), Some(anyhow::anyhow!("quarantine ledger report task: {error}"))),
            };
            for outcome in &outcomes {
                self.outbox.pop_front();
                match outcome {
                    ReportOutcome::Recorded => self.recorded += 1,
                    ReportOutcome::Unsupported => self.unsupported += 1,
                }
            }
            if !outcomes.is_empty() {
                self.persist();
            }
            if let Some(error) = error {
                tracing::warn!(tenant = %self.tenant_id, error = %format!("{error:#}"), pending = self.outbox.len(),
                    "quarantine ledger report failed; retrying");
                self.next_send_ms = now_ms + RETRY_MS;
            }
        }
        if self.outbox.is_empty() || now_ms < self.next_send_ms {
            return;
        }
        let batch = self.outbox.iter().take(MAX_PER_FLIGHT).cloned().collect::<Vec<_>>();
        let sink = self.sink.clone();
        let tenant = self.tenant_id.clone();
        let handle = tokio::spawn(async move {
            let mut outcomes = Vec::new();
            for report in &batch {
                let sent = tokio::time::timeout(CALL_TIMEOUT, sink.report(report))
                    .await
                    .map_err(|_| anyhow::anyhow!("quarantine ledger report timed out after {} s", CALL_TIMEOUT.as_secs()))
                    .and_then(|result| result);
                match sent {
                    Ok(outcome) => {
                        if outcome == ReportOutcome::Unsupported {
                            tracing::info!(tenant = %tenant, key = %report.segment_key,
                                "the tenant Worker takes no quarantine reports (older Worker or no landing ledger); report dropped");
                        }
                        outcomes.push(outcome);
                    }
                    Err(error) => return (outcomes, Some(error)),
                }
            }
            (outcomes, None)
        });
        self.flight = Some(Flight { handle });
    }

    /// Start a flight when one is due and wait for it to finish (tests).
    pub async fn settle(&mut self, now_ms: i64) {
        if self.flight.is_none() {
            self.tick(now_ms).await;
        }
        if let Some(flight) = &self.flight {
            while !flight.handle.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        // Collect it (this may start the next flight).
        self.tick(now_ms).await;
    }
}

fn load_outbox(path: &Path) -> VecDeque<QuarantineReport> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return VecDeque::new(),
        Err(error) => {
            tracing::warn!(error = %error, "quarantine ledger outbox unreadable; starting empty");
            return VecDeque::new();
        }
    };
    serde_json::from_slice::<VecDeque<QuarantineReport>>(&bytes)
        .context("quarantine ledger outbox does not parse")
        .unwrap_or_else(|error| {
            tracing::warn!(error = %format!("{error:#}"), "quarantine ledger outbox ignored; kept entries are reported again at start");
            VecDeque::new()
        })
}

/// ingest[T] in production: the tenant Worker, through the edge-log
/// consumer client (its credential rotates in place).
#[async_trait]
impl QuarantineLedgerSink for crate::edge_log::EdgeLogSource<crate::edge_log::HttpEdgeLogClient> {
    async fn report(&self, report: &QuarantineReport) -> Result<ReportOutcome> {
        self.transport().report_quarantine(report).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, http::{HeaderMap, StatusCode}, routing::post, Router};
    use std::sync::Mutex;

    const KEY: &str = "bronze-v2/shard=0/tenant_id=43380000-0000-4000-8000-000000000001/1700000000-00000000-0000-4000-8000-000000000017.parquet";

    fn report(state: ReportState) -> QuarantineReport {
        QuarantineReport { segment_key: KEY.into(), rows: 50_000, state }
    }

    /// A tenant Worker: answers each quarantine report with the next status.
    #[derive(Clone, Default)]
    struct Worker(Arc<Mutex<(Vec<u16>, Vec<(String, serde_json::Value)>)>>);

    async fn serve(statuses: Vec<u16>) -> (String, Worker) {
        async fn handle(State(worker): State<Worker>, headers: HeaderMap, body: axum::body::Bytes) -> StatusCode {
            let mut state = worker.0.lock().unwrap();
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
            state.1.push((auth, serde_json::from_slice(&body).unwrap()));
            let status = if state.0.is_empty() { 200 } else { state.0.remove(0) };
            StatusCode::from_u16(status).unwrap()
        }
        let worker = Worker(Arc::new(Mutex::new((statuses, Vec::new()))));
        let router = Router::new().route("/edge-log/v1/quarantine", post(handle)).with_state(worker.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://127.0.0.1:{}", address.port()), worker)
    }

    struct Client(crate::edge_log::HttpEdgeLogClient);

    #[async_trait]
    impl QuarantineLedgerSink for Client {
        async fn report(&self, report: &QuarantineReport) -> Result<ReportOutcome> {
            self.0.report_quarantine(report).await
        }
    }

    fn client(base: &str) -> Arc<Client> {
        Arc::new(Client(crate::edge_log::HttpEdgeLogClient::new(base, zeroize::Zeroizing::new("consumer-token-for-tests".into())).unwrap()))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_route_body_is_exact_on_the_consumer_credential() {
        let (base, worker) = serve(vec![200]).await;
        assert_eq!(client(&base).report(&report(ReportState::Quarantined)).await.unwrap(), ReportOutcome::Recorded);
        let calls = worker.0.lock().unwrap().1.clone();
        assert_eq!(calls, vec![("Bearer consumer-token-for-tests".to_string(),
            serde_json::json!({ "segmentKey": KEY, "rows": 50_000, "state": "quarantined" }))]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_old_worker_drops_reports_and_never_holds_ingest() {
        // A Worker from before NAN-4338 answers 404 (reserved /edge-log path);
        // a malformed report 400: dropped, not retried.
        let (base, worker) = serve(vec![404, 400]).await;
        let mut ledger = QuarantineLedger::open("t", None, client(&base));
        ledger.enqueue(report(ReportState::Quarantined));
        ledger.enqueue(report(ReportState::Replayed));
        ledger.settle(0).await;
        assert_eq!((ledger.pending(), ledger.unsupported, ledger.recorded), (0, 2, 0));
        assert_eq!(worker.0.lock().unwrap().1.len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failing_worker_keeps_the_report_in_order_and_retries_later() {
        let dir = tempfile::tempdir().unwrap();
        let (base, worker) = serve(vec![503, 200, 200]).await;
        let mut ledger = QuarantineLedger::open("t", Some(dir.path()), client(&base));
        ledger.enqueue(report(ReportState::Quarantined));
        ledger.enqueue(report(ReportState::Quarantined)); // the same report again adds nothing
        ledger.enqueue(report(ReportState::Replayed));
        assert_eq!(ledger.pending(), 2);
        ledger.settle(1_000).await;
        assert_eq!((ledger.pending(), ledger.recorded), (2, 0), "a 503 keeps both");
        // Not before the retry delay.
        ledger.settle(1_000 + RETRY_MS - 1).await;
        assert_eq!(worker.0.lock().unwrap().1.len(), 1);
        // A restart in between keeps the unsent outbox.
        drop(ledger);
        let mut reopened = QuarantineLedger::open("t", Some(dir.path()), client(&base));
        assert_eq!(reopened.pending(), 2);
        reopened.settle(1_000 + RETRY_MS).await;
        assert_eq!((reopened.pending(), reopened.recorded), (0, 2));
        let states = worker.0.lock().unwrap().1.iter().map(|(_, body)| body["state"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(states, ["quarantined", "quarantined", "replayed"], "retried in order");
        assert_eq!(QuarantineLedger::open("t", Some(dir.path()), client(&base)).pending(), 0);
    }
}
