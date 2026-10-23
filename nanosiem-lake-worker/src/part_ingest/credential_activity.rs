// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-credential ingest activity for lean tenants (NAN-3899).
//!
//! **Why.** The Credentials table (`GET /api/log-sources/ingest-credentials`)
//! shows each ingest credential's last seen time and 24 h event count from
//! `nano_shared.read_tenant_ingest_credential_edge_activity` (migration
//! 9001980). Its only writer was the gen1 shard-0 Bronze publisher, which
//! polled the Worker's `GET /internal/credential-activity`. A lean tenant
//! has no Bronze publisher (retired in NAN-3861), and its lake counters are
//! read from part rollups that carry no credential (NAN-3020), so every
//! credential stayed "waiting" with 0 events while the tenant ingested.
//!
//! **Writer.** ingest[T] is the one lean stage that sees every committed
//! row together with the credential the edge authorized it under
//! (`metadata.nano_credential_id`, stamped by the cell's Vector from the
//! Worker's attribution and never taken from the payload). It keeps a
//! bounded per-credential aggregate: first and last commit time and hourly
//! (flushes, events, bytes) buckets for the last 24 h. Rows are counted
//! when their flush committed (parts in the log, acks landed), so a crash
//! replay never counts a row twice: a replayed object is a duplicate and
//! is never tallied.
//!
//! **Flush.** At most every [`FLUSH_INTERVAL_MS`] (and only when the
//! snapshot changed), the aggregate is written as one
//! `nanosiem.edge-credential-activity.v1` snapshot through
//! `nano_shared.record_lake_credential_edge_activity`: one statement,
//! one row per credential updated in place, never a row per event or per
//! request. The write runs off the tick (bounded by [`CALL_TIMEOUT`]); a
//! failure keeps the aggregate and retries after [`RETRY_MS`].
//!
//! **Tenant isolation.** The login is the tenant's own `publish` data-path
//! login that the platform already hands ingest[T] for its erasure ledger
//! (`erasure_ledger`, NAN-3867), validated against this cell's tenant
//! before use. The database binds the tenant from that session: a snapshot
//! naming another tenant is refused, and a credential that is not the
//! bound tenant's is skipped, never stored.
//!
//! **Meaning of the numbers on lean.** `events_24h` / `bytes_24h` are the
//! rows ingest[T] committed for the credential (bytes: its share of the
//! source objects' stored bytes), `first_accepted_at` / `last_accepted_at`
//! the commit times, `requests_24h` the flushes that carried its rows. A
//! credential that never sent a row is never listed, so it stays "waiting".
//! Restarts keep the aggregate through a small state file
//! ([`STATE_FILE`]) in the cell's state directory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The snapshot contract `record_lake_credential_edge_activity` accepts.
pub const CONTRACT: &str = "nanosiem.edge-credential-activity.v1";
const HOUR_MS: i64 = 3_600_000;
/// The rolling window of the counts.
pub const WINDOW_MS: i64 = 24 * HOUR_MS;
/// Shortest gap between two writes (the bound on control-DB writes).
pub const FLUSH_INTERVAL_MS: i64 = 30_000;
/// Gap after a failed write.
pub const RETRY_MS: i64 = 60_000;
/// One write's timeout (the write never holds the tick).
pub const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// The writer's per-snapshot bound, and the most credentials tracked.
pub const MAX_CREDENTIALS: usize = 1024;
/// An idle credential stays listed this long, so its 24 h counts are
/// written back down to zero before it is forgotten.
pub const RETAIN_IDLE_MS: i64 = 2 * WINDOW_MS;
/// The aggregate's file in the cell's state directory.
pub const STATE_FILE: &str = "credential-activity-v1.json";

/// One flush's rows per credential (lowercase hyphenated UUID), built at
/// admission and absorbed only when the flush committed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlushTally(BTreeMap<String, (u64, u64)>);

impl FlushTally {
    /// One committed row of `credential`, `bytes` its stored share.
    pub fn note(&mut self, credential: &str, bytes: u64) {
        let entry = self.0.entry(credential.to_string()).or_default();
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(bytes);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Events per credential (tests).
    pub fn events(&self, credential: &str) -> u64 {
        self.0.get(credential).map_or(0, |(events, _)| *events)
    }
}

/// `metadata.nano_credential_id` of a source row, as the canonical
/// lowercase hyphenated UUID the writer accepts; `None` for anything else
/// (unattributed rows are not credential activity).
pub fn row_credential(row: &crate::iceberg::EventRow) -> Option<String> {
    if row.event_kind != crate::iceberg::EventKind::Source {
        return None;
    }
    crate::ingest_source_counters::credential_id(&row.ocsf_event)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CredentialState {
    first_ms: i64,
    last_ms: i64,
    /// Hour index (`ms / HOUR_MS`) -> `[flushes, events, bytes]`.
    hours: BTreeMap<i64, [u64; 3]>,
}

impl CredentialState {
    fn window(&self, now_ms: i64) -> [u64; 3] {
        let floor = (now_ms - WINDOW_MS).div_euclid(HOUR_MS);
        self.hours.range(floor + 1..).fold([0; 3], |mut sum, (_, counts)| {
            for (total, count) in sum.iter_mut().zip(counts) {
                *total = total.saturating_add(*count);
            }
            sum
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    tenant_id: String,
    credentials: BTreeMap<String, CredentialState>,
}

/// Where a snapshot goes.
#[async_trait::async_trait]
pub trait ActivitySink: Send + Sync {
    /// Record one snapshot; returns the credentials the database touched.
    async fn record(&self, snapshot: Value) -> Result<i32>;
}

/// `nano_shared.record_lake_credential_edge_activity` on the tenant's
/// `publish` data-path login.
pub struct PgActivitySink(pub sqlx::PgPool);

#[async_trait::async_trait]
impl ActivitySink for PgActivitySink {
    async fn record(&self, snapshot: Value) -> Result<i32> {
        sqlx::query_scalar::<_, i32>("SELECT nano_shared.record_lake_credential_edge_activity($1::jsonb)")
            .bind(snapshot)
            .fetch_one(&self.0)
            .await
            .context("record lean credential activity")
    }
}

struct Flight {
    handle: tokio::task::JoinHandle<Result<i32>>,
    credentials: Vec<Value>,
}

/// The bounded per-credential aggregate and its flush state.
pub struct CredentialActivity {
    tenant_id: String,
    credentials: BTreeMap<String, CredentialState>,
    /// Rows of credentials past [`MAX_CREDENTIALS`] (never tracked).
    dropped_rows: u64,
    /// The credentials array last written (a write is skipped when equal).
    last_written: Option<Vec<Value>>,
    next_flush_ms: i64,
    flight: Option<Flight>,
    state_path: Option<PathBuf>,
    dirty: bool,
    writes: u64,
}

impl CredentialActivity {
    /// `state_dir`: where the aggregate survives a restart (`None`: memory
    /// only). A state file of another tenant, or an unreadable one, is
    /// ignored.
    pub fn new(tenant_id: &str, state_dir: Option<&Path>) -> Self {
        let state_path = state_dir.map(|dir| dir.join(STATE_FILE));
        let credentials = state_path
            .as_deref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<Persisted>(&bytes).ok())
            .filter(|persisted| persisted.tenant_id == tenant_id)
            .map(|persisted| persisted.credentials)
            .unwrap_or_default()
            .into_iter()
            .take(MAX_CREDENTIALS)
            .collect();
        Self {
            tenant_id: tenant_id.to_string(),
            credentials,
            dropped_rows: 0,
            last_written: None,
            next_flush_ms: 0,
            flight: None,
            state_path,
            dirty: false,
            writes: 0,
        }
    }

    /// Fold one committed flush in at `now_ms`.
    pub fn absorb(&mut self, tally: FlushTally, now_ms: i64) {
        let hour = now_ms.div_euclid(HOUR_MS);
        for (credential, (events, bytes)) in tally.0 {
            if !self.credentials.contains_key(&credential) && self.credentials.len() >= MAX_CREDENTIALS {
                self.dropped_rows = self.dropped_rows.saturating_add(events);
                continue;
            }
            let state = self.credentials.entry(credential).or_insert_with(|| CredentialState {
                first_ms: now_ms,
                last_ms: now_ms,
                hours: BTreeMap::new(),
            });
            state.first_ms = state.first_ms.min(now_ms);
            state.last_ms = state.last_ms.max(now_ms);
            let bucket = state.hours.entry(hour).or_default();
            bucket[0] += 1;
            bucket[1] = bucket[1].saturating_add(events);
            bucket[2] = bucket[2].saturating_add(bytes);
            self.dirty = true;
        }
    }

    /// Drop buckets outside the window and credentials idle past
    /// [`RETAIN_IDLE_MS`].
    fn prune(&mut self, now_ms: i64) {
        let floor = (now_ms - WINDOW_MS).div_euclid(HOUR_MS);
        let before = self.credentials.len();
        self.credentials.retain(|_, state| {
            state.hours.retain(|hour, _| *hour > floor);
            state.last_ms >= now_ms - RETAIN_IDLE_MS
        });
        if self.credentials.len() != before {
            self.dirty = true;
        }
    }

    /// The snapshot's `credentials` array: most recently seen first, at most
    /// [`MAX_CREDENTIALS`].
    fn snapshot_credentials(&self, now_ms: i64) -> Vec<Value> {
        let mut states = self.credentials.iter().collect::<Vec<_>>();
        states.sort_by(|a, b| b.1.last_ms.cmp(&a.1.last_ms).then(a.0.cmp(b.0)));
        states
            .into_iter()
            .take(MAX_CREDENTIALS)
            .map(|(credential, state)| {
                let [requests, events, bytes] = state.window(now_ms);
                json!({
                    "credential_id": credential,
                    "first_accepted_at": rfc3339(state.first_ms),
                    "last_accepted_at": rfc3339(state.last_ms),
                    "requests_24h": requests,
                    "events_24h": events,
                    "bytes_24h": bytes,
                    "unknown_event_requests_24h": 0,
                })
            })
            .collect()
    }

    /// The full `nanosiem.edge-credential-activity.v1` document.
    pub fn snapshot(&self, now_ms: i64) -> Value {
        self.document(self.snapshot_credentials(now_ms), now_ms)
    }

    fn document(&self, credentials: Vec<Value>, now_ms: i64) -> Value {
        json!({
            "contract": CONTRACT,
            "tenant_uuid": self.tenant_id,
            "sampled_at": rfc3339(now_ms),
            "window_seconds": WINDOW_MS / 1_000,
            "truncated": self.credentials.len() > MAX_CREDENTIALS,
            "credentials": credentials,
        })
    }

    /// Credentials tracked (tests, health).
    pub fn tracked(&self) -> usize {
        self.credentials.len()
    }

    /// Writes started so far (tests, health).
    pub fn writes(&self) -> u64 {
        self.writes
    }

    /// A write is in flight (tests).
    pub fn in_flight(&self) -> bool {
        self.flight.is_some()
    }

    /// One bounded step: collect a finished write, then start the next one
    /// when due and changed. Never waits on the database.
    pub async fn tick(&mut self, sink: Option<Arc<dyn ActivitySink>>, now_ms: i64) {
        if let Some(flight) = self.flight.take() {
            if !flight.handle.is_finished() {
                self.flight = Some(flight);
                return;
            }
            match flight.handle.await.context("credential activity write task").and_then(|result| result) {
                Ok(touched) => {
                    tracing::debug!(tenant = %self.tenant_id, touched, "recorded lean credential activity");
                    self.last_written = Some(flight.credentials);
                    self.next_flush_ms = now_ms + FLUSH_INTERVAL_MS;
                }
                Err(error) => {
                    tracing::warn!(tenant = %self.tenant_id, error = %format!("{error:#}"),
                        "recording lean credential activity failed; retrying");
                    self.next_flush_ms = now_ms + RETRY_MS;
                }
            }
        }
        if now_ms < self.next_flush_ms {
            return;
        }
        self.next_flush_ms = now_ms + FLUSH_INTERVAL_MS;
        self.prune(now_ms);
        self.persist();
        if self.dropped_rows > 0 {
            tracing::warn!(tenant = %self.tenant_id, rows = self.dropped_rows, bound = MAX_CREDENTIALS,
                "credential activity bound reached; rows of untracked credentials were not attributed");
            self.dropped_rows = 0;
        }
        let credentials = self.snapshot_credentials(now_ms);
        let unchanged = match &self.last_written {
            Some(written) => *written == credentials,
            // Nothing ever ingested under a credential: nothing to write.
            None => credentials.is_empty(),
        };
        if unchanged {
            return;
        }
        let Some(sink) = sink else { return };
        let document = self.document(credentials.clone(), now_ms);
        self.writes += 1;
        let handle = tokio::spawn(async move {
            tokio::time::timeout(CALL_TIMEOUT, sink.record(document))
                .await
                .map_err(|_| anyhow::anyhow!("credential activity write timed out after {} s", CALL_TIMEOUT.as_secs()))?
        });
        self.flight = Some(Flight { handle, credentials });
    }

    /// Wait for the write in flight (tests, shutdown).
    pub async fn settle(&mut self, now_ms: i64) {
        if let Some(flight) = &mut self.flight {
            while !flight.handle.is_finished() {
                tokio::task::yield_now().await;
            }
        }
        let next = self.next_flush_ms;
        self.next_flush_ms = i64::MAX;
        self.tick(None, now_ms).await;
        if self.next_flush_ms == i64::MAX {
            self.next_flush_ms = next;
        }
    }

    fn persist(&mut self) {
        let Some(path) = &self.state_path else { return };
        if !self.dirty {
            return;
        }
        let persisted = Persisted { tenant_id: self.tenant_id.clone(), credentials: self.credentials.clone() };
        let write = || -> Result<()> {
            let bytes = serde_json::to_vec(&persisted)?;
            let temporary = path.with_extension("json.tmp");
            std::fs::write(&temporary, bytes)?;
            std::fs::rename(&temporary, path)?;
            Ok(())
        };
        match write() {
            Ok(()) => self.dirty = false,
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "saving credential activity state failed"),
        }
    }
}

/// ingest[T]'s writer: the aggregate plus where its login comes from.
pub struct ActivityExec {
    pub activity: CredentialActivity,
    /// The exchange's `erasure_ledger` (the tenant's own `publish` login),
    /// replaced on every credential refresh.
    slot: Option<super::lean_erasure::ErasureLedgerSlot>,
    /// Tests / lab: a fixed sink instead of the exchange's login.
    fixed: Option<Arc<dyn ActivitySink>>,
    /// The pool for the current login URL (one connection, lazy).
    pool: Option<(String, Arc<dyn ActivitySink>)>,
}

impl ActivityExec {
    /// Hosted lean ingest: write through the exchange's publish login.
    pub fn from_ledger(tenant_id: &str, state_dir: Option<&Path>, slot: super::lean_erasure::ErasureLedgerSlot) -> Self {
        Self { activity: CredentialActivity::new(tenant_id, state_dir), slot: Some(slot), fixed: None, pool: None }
    }

    /// Tests / lab: write to `sink`.
    pub fn fixed(tenant_id: &str, sink: Arc<dyn ActivitySink>) -> Self {
        Self { activity: CredentialActivity::new(tenant_id, None), slot: None, fixed: Some(sink), pool: None }
    }

    /// The sink for the current login: `None` while none is delivered, it
    /// is expired, or it names another tenant.
    fn sink(&mut self, tenant_id: &str, now_ms: i64) -> Option<Arc<dyn ActivitySink>> {
        if let Some(fixed) = &self.fixed {
            return Some(fixed.clone());
        }
        let now = DateTime::<Utc>::from_timestamp_millis(now_ms).unwrap_or_else(Utc::now);
        let Some(credential) = self
            .slot
            .as_ref()
            .and_then(super::lean_erasure::ErasureLedgerSlot::get)
            .filter(|credential| credential.validate(tenant_id, now).is_ok())
        else {
            self.pool = None;
            return None;
        };
        if let Some((url, sink)) = &self.pool {
            if *url == credential.database_url {
                return Some(sink.clone());
            }
        }
        let pool = match sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(CALL_TIMEOUT)
            .idle_timeout(Duration::from_secs(120))
            .connect_lazy(&credential.database_url)
        {
            Ok(pool) => pool,
            Err(error) => {
                tracing::warn!(error = %error, "credential activity login unusable");
                return None;
            }
        };
        let sink: Arc<dyn ActivitySink> = Arc::new(PgActivitySink(pool));
        self.pool = Some((credential.database_url, sink.clone()));
        Some(sink)
    }

    /// One bounded step (see [`CredentialActivity::tick`]).
    pub async fn tick(&mut self, tenant_id: &str, now_ms: i64) {
        let sink = self.sink(tenant_id, now_ms);
        self.activity.tick(sink, now_ms).await;
    }
}

fn rfc3339(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .unwrap_or_default()
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
#[path = "credential_activity_ingest_tests.rs"]
mod ingest_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const TENANT: &str = "11111111-2222-4333-8444-555555555555";
    const HEC_A: &str = "7d0b5c2e-4f1a-4c3e-9a6b-1e2f3a4b5c6d";
    const HEC_B: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    const T0: i64 = 1_760_000_000_000;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<Value>>);

    #[async_trait::async_trait]
    impl ActivitySink for Recorder {
        async fn record(&self, snapshot: Value) -> Result<i32> {
            let touched = snapshot["credentials"].as_array().map_or(0, Vec::len) as i32;
            self.0.lock().unwrap().push(snapshot);
            Ok(touched)
        }
    }

    struct Failing;

    #[async_trait::async_trait]
    impl ActivitySink for Failing {
        async fn record(&self, _: Value) -> Result<i32> {
            anyhow::bail!("database unavailable")
        }
    }

    fn tally(rows: &[(&str, u64)]) -> FlushTally {
        let mut tally = FlushTally::default();
        for (credential, bytes) in rows {
            tally.note(credential, *bytes);
        }
        tally
    }

    fn row(credential: Option<&str>, kind: crate::iceberg::EventKind) -> crate::iceberg::EventRow {
        let mut metadata = json!({"log_source": "windows_security"});
        if let Some(credential) = credential {
            metadata["nano_credential_id"] = json!(credential);
        }
        crate::iceberg::EventRow { event_uid: "uid".into(), event_kind: kind, ocsf_event: json!({"metadata": metadata}) }
    }

    fn entry<'v>(snapshot: &'v Value, credential: &str) -> Option<&'v Value> {
        snapshot["credentials"].as_array().unwrap().iter().find(|c| c["credential_id"] == credential)
    }

    #[test]
    fn rows_are_attributed_only_to_the_stamped_credential() {
        use crate::iceberg::EventKind;
        assert_eq!(row_credential(&row(Some(HEC_A), EventKind::Source)).as_deref(), Some(HEC_A));
        assert_eq!(row_credential(&row(Some(&HEC_A.to_uppercase()), EventKind::Source)).as_deref(), Some(HEC_A),
            "canonical lowercase, the form the writer's pattern accepts");
        assert_eq!(row_credential(&row(None, EventKind::Source)), None, "unattributed rows are not credential activity");
        assert_eq!(row_credential(&row(Some("pull:1234"), EventKind::Source)), None);
        assert_eq!(row_credential(&row(Some(HEC_A), EventKind::Signal)), None, "only tenant source rows count");
    }

    #[tokio::test]
    async fn activity_is_recorded_for_the_right_token_and_an_unused_token_stays_waiting() {
        let recorder = Arc::new(Recorder::default());
        let mut activity = CredentialActivity::new(TENANT, None);
        activity.absorb(tally(&[(HEC_A, 100), (HEC_A, 50), (HEC_A, 10)]), T0);
        activity.tick(Some(recorder.clone()), T0).await;
        activity.settle(T0).await;
        let written = recorder.0.lock().unwrap().clone();
        assert_eq!(written.len(), 1);
        let snapshot = &written[0];
        assert_eq!(snapshot["contract"], CONTRACT);
        assert_eq!(snapshot["tenant_uuid"], TENANT, "the snapshot names only this cell's tenant");
        assert_eq!(snapshot["window_seconds"], 86_400);
        let a = entry(snapshot, HEC_A).expect("the sending credential is listed");
        assert_eq!(a["events_24h"], 3);
        assert_eq!(a["bytes_24h"], 160);
        assert_eq!(a["requests_24h"], 1);
        assert_eq!(a["first_accepted_at"], rfc3339(T0));
        assert_eq!(a["last_accepted_at"], rfc3339(T0));
        assert!(entry(snapshot, HEC_B).is_none(), "a token that sent nothing is never listed: it stays waiting");
    }

    #[tokio::test]
    async fn nothing_is_written_for_a_tenant_whose_tokens_sent_nothing() {
        let recorder = Arc::new(Recorder::default());
        let mut activity = CredentialActivity::new(TENANT, None);
        activity.absorb(FlushTally::default(), T0);
        activity.tick(Some(recorder.clone()), T0).await;
        activity.settle(T0).await;
        assert!(recorder.0.lock().unwrap().is_empty());
        assert_eq!(activity.writes(), 0);
    }

    #[tokio::test]
    async fn writes_are_bounded_to_one_per_interval_and_skipped_when_unchanged() {
        let recorder = Arc::new(Recorder::default());
        let mut activity = CredentialActivity::new(TENANT, None);
        // A busy minute: a flush committed every 100 ms, a tick after each.
        let mut now = T0;
        while now < T0 + 60_000 {
            activity.absorb(tally(&[(HEC_A, 10), (HEC_B, 20)]), now);
            activity.tick(Some(recorder.clone()), now).await;
            activity.settle(now).await;
            now += 100;
        }
        let writes = recorder.0.lock().unwrap().len();
        assert!(writes <= (60_000 / FLUSH_INTERVAL_MS) as usize + 1, "{writes} writes in one minute");
        assert!(writes >= 2, "a busy credential is written at least every interval");
        // Idle: the snapshot no longer changes, so nothing more is written.
        let before = recorder.0.lock().unwrap().len();
        for step in 0..10 {
            let at = now + FLUSH_INTERVAL_MS * (step + 1);
            activity.tick(Some(recorder.clone()), at).await;
            activity.settle(at).await;
        }
        assert!(recorder.0.lock().unwrap().len() <= before + 1, "an unchanged snapshot is not rewritten");
    }

    #[tokio::test]
    async fn the_credential_count_is_bounded() {
        let recorder = Arc::new(Recorder::default());
        let mut activity = CredentialActivity::new(TENANT, None);
        let mut flush = FlushTally::default();
        for index in 0..(MAX_CREDENTIALS as u128 + 10) {
            flush.note(&uuid::Uuid::from_u128(index + 1).hyphenated().to_string(), 1);
        }
        activity.absorb(flush, T0);
        assert_eq!(activity.tracked(), MAX_CREDENTIALS);
        activity.tick(Some(recorder.clone()), T0).await;
        activity.settle(T0).await;
        let written = recorder.0.lock().unwrap();
        assert_eq!(written[0]["credentials"].as_array().unwrap().len(), MAX_CREDENTIALS);
    }

    #[tokio::test]
    async fn counts_decay_out_of_the_window_and_idle_tokens_are_forgotten() {
        let recorder = Arc::new(Recorder::default());
        let mut activity = CredentialActivity::new(TENANT, None);
        activity.absorb(tally(&[(HEC_A, 10)]), T0);
        activity.tick(Some(recorder.clone()), T0).await;
        activity.settle(T0).await;
        let later = T0 + WINDOW_MS + HOUR_MS;
        activity.tick(Some(recorder.clone()), later).await;
        activity.settle(later).await;
        let last = recorder.0.lock().unwrap().last().cloned().unwrap();
        let a = entry(&last, HEC_A).expect("still listed while its counts decay");
        assert_eq!(a["events_24h"], 0, "written back down to zero");
        assert_eq!(a["last_accepted_at"], rfc3339(T0), "last seen never moves without rows");
        let forgotten = T0 + RETAIN_IDLE_MS + HOUR_MS;
        activity.tick(Some(recorder.clone()), forgotten).await;
        activity.settle(forgotten).await;
        assert_eq!(activity.tracked(), 0);
    }

    #[tokio::test]
    async fn a_failed_write_keeps_the_aggregate_and_retries_later() {
        let mut activity = CredentialActivity::new(TENANT, None);
        activity.absorb(tally(&[(HEC_A, 10)]), T0);
        activity.tick(Some(Arc::new(Failing)), T0).await;
        activity.settle(T0).await;
        let recorder = Arc::new(Recorder::default());
        activity.tick(Some(recorder.clone()), T0 + FLUSH_INTERVAL_MS).await;
        assert!(recorder.0.lock().unwrap().is_empty(), "retry waits RETRY_MS");
        activity.tick(Some(recorder.clone()), T0 + RETRY_MS).await;
        activity.settle(T0 + RETRY_MS).await;
        let written = recorder.0.lock().unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(entry(&written[0], HEC_A).unwrap()["events_24h"], 1);
    }

    #[tokio::test]
    async fn no_login_means_no_write_but_the_aggregate_is_kept() {
        let mut activity = CredentialActivity::new(TENANT, None);
        activity.absorb(tally(&[(HEC_A, 10)]), T0);
        activity.tick(None, T0).await;
        assert_eq!(activity.writes(), 0);
        let recorder = Arc::new(Recorder::default());
        activity.tick(Some(recorder.clone()), T0 + FLUSH_INTERVAL_MS).await;
        activity.settle(T0 + FLUSH_INTERVAL_MS).await;
        assert_eq!(recorder.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn the_aggregate_survives_a_restart_but_never_crosses_tenants() {
        let dir = tempfile::tempdir().unwrap();
        let mut activity = CredentialActivity::new(TENANT, Some(dir.path()));
        activity.absorb(tally(&[(HEC_A, 10), (HEC_A, 10)]), T0);
        activity.tick(None, T0).await;
        let restarted = CredentialActivity::new(TENANT, Some(dir.path()));
        assert_eq!(entry(&restarted.snapshot(T0), HEC_A).unwrap()["events_24h"], 2);
        let other = CredentialActivity::new("99999999-2222-4333-8444-555555555555", Some(dir.path()));
        assert_eq!(other.tracked(), 0, "another tenant's state file is ignored");
        assert_eq!(other.snapshot(T0)["tenant_uuid"], "99999999-2222-4333-8444-555555555555");
    }
}
