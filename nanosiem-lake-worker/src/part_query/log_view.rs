// SPDX-License-Identifier: AGPL-3.0-or-later

//! The query process's view of one tenant's part log (contract section 5.3).
//!
//! The live set is folded only from verified entries. The read path never
//! LISTs: it starts from a trusted local position (the previous fold in this
//! process), or on a cold start from a checkpoint probed at the multiple of
//! `CHECKPOINT_EVERY` at or below the `HEAD` hint, and then GETs
//! `entries/{seq+1}` until "not found". A missing or stale `HEAD` only costs
//! GETs: the head is found by exponential probing plus bisection over the
//! dense entry sequence, so a cold start is O(log n) probes plus the entries
//! after the checkpoint.
//!
//! Entries are unsigned (contract r2, 5.1): integrity is the hash chain plus
//! the owner-signed record of every part. The view therefore verifies each
//! `merge`/`rewrite` eagerly before applying it (4.5): the output part's
//! `provenance.json` must hash to the entry's `provenance_sha256`, carry a
//! valid owner signature, equal the `PartRef` on every shared field, and
//! name exactly the superseded parts as its inputs. An entry that would
//! remove live parts on anything less is refused and the view fails closed.
//! Parts added by `add`/`adopt` are verified when first fetched.
//!
//! Besides the live set the view records, per catch-up, which event-time
//! ranges newly visible parts touched. Detections use that to skip a run when
//! nothing arrived and to re-run the windows late parts land in.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::parts::format::{LogKeys, PartKeys};
use crate::parts::part_log::{
    check_supersedes, Checkpoint, LiveSet, LogEntry, LogOp, LogSchema, ObjectStore, PartRef, CHECKPOINT_EVERY,
};
use crate::parts::provenance::{SignedProvenance, TenantKeySet};
use crate::parts::refusal_tally::RefusalWindow;
use crate::parts::sha256_hex;

/// How many checkpoint multiples below the head a cold start probes before
/// replaying from genesis.
const CHECKPOINT_PROBES: u64 = 3;
/// Upper bound on a probed sequence number (2^40 entries is ~35k years of
/// 1 s appends); keeps the exponential probe finite on a hostile store.
const MAX_PROBE_SEQ: u64 = 1 << 40;
/// Largest window of concurrent entry GETs in a catch-up (see
/// [`PartLogView::catch_up`]).
pub const CATCH_UP_MAX_WINDOW: u64 = 32;
/// NAN-3662: how far back (by append time) the refusal window reaches: the
/// 48 h the ingest counters serve at 5-minute precision plus the current hour.
pub const REFUSAL_RETAIN_MS: i64 = 49 * 3_600_000;
/// NAN-3662: most older entries one refusal backfill reads (~2.3 days of
/// 10 s flushes); past it the window is complete only from the oldest read.
pub const MAX_REFUSAL_BACKFILL_ENTRIES: u64 = 20_000;

#[derive(Debug, Deserialize)]
struct HeadHint {
    seq: u64,
}

/// Event-time footprint of newly visible data since the previous catch-up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Advance {
    /// Entries applied by this catch-up.
    pub entries: u64,
    /// `(min_time_us, max_time_us)` of every part that became live through an
    /// `add`, `adopt` or erasure `rewrite` (new rows). Merges only reshuffle
    /// rows that were already visible, so they are not new data.
    pub new_data: Vec<(i64, i64)>,
    /// Appended-at time (ms) of the newest applied entry.
    pub newest_appended_at_ms: Option<i64>,
}

impl Advance {
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Did new rows land with event time inside `[from_us, to_us]`?
    pub fn touches(&self, from_us: i64, to_us: i64) -> bool {
        self.new_data.iter().any(|(min, max)| *min <= to_us && *max >= from_us)
    }
}

/// A verified, incrementally maintained live set for one tenant.
pub struct PartLogView {
    tenant_id: String,
    keys: TenantKeySet,
    log_keys: LogKeys,
    set: LiveSet,
    schema_cache: Option<(String, std::sync::Arc<arrow_schema::Schema>)>,
    edge_logs: super::fetch::EdgeLogMap,
    /// NAN-3662: refused rows per source lane, from every applied `reject`.
    refusals: std::sync::Arc<std::sync::Mutex<RefusalWindow>>,
    /// NAN-3662: after a checkpoint start, the newest entry whose `reject`s
    /// are not in `refusals` yet, `(seq, sha256)`: the checkpoint's own
    /// entry. Taken by the first refusal read ([`backfill_refusals`]).
    refusal_history: Option<(u64, String)>,
}

impl PartLogView {
    /// Cold open: probe the head, start from the best verifiable checkpoint
    /// at a `CHECKPOINT_EVERY` multiple, then apply every later entry.
    pub async fn open(store: &dyn ObjectStore, tenant_id: &str, keys: TenantKeySet) -> Result<Self> {
        let log_keys = LogKeys::new(tenant_id)?;
        let head = probe_head(store, &log_keys).await?;
        let mut set = LiveSet::default();
        if let Some(head) = head {
            let base = head - head % CHECKPOINT_EVERY;
            for step in 0..CHECKPOINT_PROBES {
                let Some(seq) = base.checked_sub(step * CHECKPOINT_EVERY) else { break };
                if seq == 0 {
                    break;
                }
                match load_checkpoint(store, &log_keys, tenant_id, seq).await {
                    Ok(Some(loaded)) => {
                        set = loaded;
                        break;
                    }
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::warn!(tenant_id, seq, error = %error, "skipping unverifiable part-log checkpoint");
                    }
                }
            }
        }
        // NAN-3662: from a checkpoint, older `reject`s are read only on demand;
        // from genesis every entry is applied, so the window is complete.
        let refusal_history = set.head().map(|(seq, sha, _)| (seq, sha.to_string()));
        let mut refusals = RefusalWindow::new(REFUSAL_RETAIN_MS);
        if refusal_history.is_none() {
            refusals.mark_complete_since(i64::MIN);
        }
        let mut view = Self {
            tenant_id: tenant_id.to_string(),
            keys,
            log_keys,
            set,
            schema_cache: None,
            edge_logs: Default::default(),
            refusals: std::sync::Arc::new(std::sync::Mutex::new(refusals)),
            refusal_history,
        };
        view.catch_up(store).await?;
        Ok(view)
    }

    /// Apply every entry after the head. O(new entries).
    ///
    /// Entries are GET in windows that double while every GET in the window
    /// hits (1, 2, 4, … [`CATCH_UP_MAX_WINDOW`]), and the replacement
    /// records of a window's merges are verified concurrently too
    /// (NAN-2989). A warm catch-up (0–1 new entries) still costs one GET;
    /// a cold start after a reap no longer pays one R2 round trip per entry
    /// since the last checkpoint (up to 1,024 in series, tens of seconds).
    /// Entries still apply strictly in order, and a window stops at its
    /// first missing sequence number (a later hit from a racing append is
    /// discarded and fetched again by the next window).
    pub async fn catch_up(&mut self, store: &dyn ObjectStore) -> Result<Advance> {
        let mut advance = Advance::default();
        let mut window = 1_u64;
        loop {
            let first = self.set.head().map_or(0, |(seq, _, _)| seq + 1);
            let fetched = futures::future::join_all(
                (first..first.saturating_add(window)).map(|seq| {
                    let key = self.log_keys.entry(seq);
                    async move { store.get(&key).await }
                }),
            )
            .await;
            let mut entries = Vec::with_capacity(fetched.len());
            for (seq, result) in (first..).zip(fetched) {
                let Some(bytes) = result? else { break };
                let entry = LogEntry::parse_bytes(&bytes, &self.tenant_id)
                    .with_context(|| format!("part-log entry {seq} does not parse"))?;
                entries.push((seq, sha256_hex(&bytes), entry));
            }
            let (tenant_id, keys) = (&self.tenant_id, &self.keys);
            let checks = futures::future::join_all(entries.iter().filter_map(|(seq, _, entry)| match &entry.op {
                LogOp::Merge { output, supersedes } | LogOp::Rewrite { output, supersedes, .. } => Some(async move {
                    verify_replacement(store, tenant_id, keys, output, supersedes)
                        .await
                        .with_context(|| format!("part-log entry {seq} replaces parts without a matching signed record"))
                }),
                _ => None,
            }))
            .await;
            checks.into_iter().collect::<Result<Vec<()>>>()?;
            let complete = entries.len() as u64 == window;
            for (_, sha, entry) in &entries {
                self.set.apply(entry, sha)?;
                self.track_edge_logs(entry);
                record_advance(entry, &mut advance);
                if let LogOp::Reject { rejections } = &entry.op {
                    self.refusals.lock().unwrap_or_else(std::sync::PoisonError::into_inner).record(entry.appended_at_ms, rejections);
                }
            }
            if !complete {
                break;
            }
            window = (window * 2).min(CATCH_UP_MAX_WINDOW);
        }
        Ok(advance)
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// The shared `add` edge-log map the fetcher checks records against.
    pub fn edge_logs(&self) -> super::fetch::EdgeLogMap {
        self.edge_logs.clone()
    }

    fn track_edge_logs(&self, entry: &LogEntry) {
        let mut map = self.edge_logs.lock().expect("edge log map");
        match &entry.op {
            LogOp::Add { parts, edge_log, .. } => {
                for part in parts {
                    map.insert(part.part_id.clone(), edge_log.clone());
                }
            }
            LogOp::Merge { supersedes, .. } | LogOp::Rewrite { supersedes, .. } => supersedes.iter().for_each(|id| {
                map.remove(id);
            }),
            LogOp::Retire { parts, .. } => parts.iter().for_each(|id| {
                map.remove(id);
            }),
            LogOp::Genesis { .. } | LogOp::Schema { .. } | LogOp::Adopt { .. } | LogOp::EdgeFloor { .. } | LogOp::EdgeEnd { .. } | LogOp::Reject { .. } => {}
        }
    }

    pub fn live(&self) -> &LiveSet {
        &self.set
    }

    /// NAN-3662: the refusal window (shared with a running backfill).
    pub fn refusals(&self) -> std::sync::Arc<std::sync::Mutex<RefusalWindow>> {
        std::sync::Arc::clone(&self.refusals)
    }

    /// NAN-3662: the start of the refusal backfill this view still owes,
    /// once (see [`backfill_refusals`]).
    pub fn take_refusal_history(&mut self) -> Option<(u64, String)> {
        self.refusal_history.take()
    }

    /// `(seq, entry sha256)` of the verified head, `None` for an empty log.
    pub fn head(&self) -> Option<(u64, String)> {
        self.set.head().map(|(seq, sha, _)| (seq, sha.to_string()))
    }

    /// The schema bound by the verified part-log head.
    pub fn schema_fingerprint(&self) -> Option<&str> {
        self.set.schema().map(|schema| schema.fingerprint.as_str())
    }

    /// Live parts whose rows may intersect `[from_us, to_us]`, oldest first.
    pub fn parts_overlapping(&self, from_us: i64, to_us: i64) -> Vec<PartRef> {
        let mut parts = self
            .set
            .parts()
            .filter(|part| part.overlaps(from_us, to_us))
            .cloned()
            .collect::<Vec<_>>();
        parts.sort_by(|a, b| (a.min_time_us, a.part_id.as_str()).cmp(&(b.min_time_us, b.part_id.as_str())));
        parts
    }

    /// The read schema at the head (the newest `genesis`/`schema` entry).
    pub fn read_schema(&mut self) -> Result<std::sync::Arc<arrow_schema::Schema>> {
        let schema: &LogSchema = self.set.schema().context("part log has no schema")?;
        if let Some((fingerprint, arrow)) = &self.schema_cache {
            if fingerprint == &schema.fingerprint {
                return Ok(arrow.clone());
            }
        }
        let arrow = std::sync::Arc::new(schema.to_arrow()?);
        self.schema_cache = Some((schema.fingerprint.clone(), arrow.clone()));
        Ok(arrow)
    }

    /// Number of live parts per level code (status/metrics).
    pub fn level_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for part in self.set.parts() {
            *counts.entry(part.level.code()).or_default() += 1;
        }
        counts
    }
}

fn record_advance(entry: &LogEntry, advance: &mut Advance) {
    advance.entries += 1;
    advance.newest_appended_at_ms = Some(advance.newest_appended_at_ms.map_or(entry.appended_at_ms, |at| at.max(entry.appended_at_ms)));
    let mut push = |part: &PartRef| advance.new_data.push((part.min_time_us, part.max_time_us));
    match &entry.op {
        LogOp::Add { parts, .. } | LogOp::Adopt { parts } => parts.iter().for_each(&mut push),
        // An erasure rewrite removes rows; a detection window it touches
        // must be re-evaluated too.
        LogOp::Rewrite { output, .. } => push(output),
        LogOp::Genesis { .. }
        | LogOp::Schema { .. }
        | LogOp::Merge { .. }
        | LogOp::Retire { .. }
        | LogOp::EdgeFloor { .. }
        | LogOp::EdgeEnd { .. }
        | LogOp::Reject { .. } => {}
    }
}

/// Contract 4.5 for a `merge`/`rewrite`: the output's owner-signed record
/// matches the entry, and its inputs are exactly the superseded parts.
async fn verify_replacement(
    store: &dyn ObjectStore,
    tenant_id: &str,
    keys: &TenantKeySet,
    output: &PartRef,
    supersedes: &[crate::parts::format::PartId],
) -> Result<()> {
    let key = PartKeys::new(tenant_id, output.level, output.event_hour, &output.part_id)?.provenance();
    let bytes = store.get(&key).await?.context("merge output provenance is missing")?;
    let sha = sha256_hex(&bytes);
    if sha != output.provenance_sha256 {
        bail!("merge output provenance does not match its entry");
    }
    let signed = SignedProvenance::verify_bytes(&bytes, tenant_id, keys)?;
    output.check_record(&signed.record, &sha)?;
    check_supersedes(supersedes, &signed.record)
}

/// NAN-3662: fold the `reject` entries at and below `from` (`(seq,
/// sha256)`, newest first) into `window`, back to `horizon_ms` (append
/// time), at most `max_entries` of them. Each entry is verified against the
/// hash chain from `from` down (its sha256 is the next entry's
/// `prev_sha256`), so nothing outside the verified log is counted. Marks
/// the window complete from where the read stopped: `horizon_ms` (or the
/// log's start) when it got there; else the oldest entry read (a cap, a
/// reaped entry, or a failure).
pub async fn backfill_refusals(
    store: &dyn ObjectStore,
    tenant_id: &str,
    from: (u64, String),
    horizon_ms: i64,
    max_entries: u64,
    window: &std::sync::Mutex<RefusalWindow>,
) -> Result<()> {
    let log_keys = LogKeys::new(tenant_id)?;
    let lock = || window.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut top, mut expected) = (Some(from.0), from.1);
    let mut read = 0_u64;
    let mut oldest_ms: Option<i64> = None;
    let complete_from = |oldest_ms: Option<i64>| oldest_ms.unwrap_or(i64::MAX);
    while let Some(high) = top {
        if read >= max_entries {
            break;
        }
        let span = CATCH_UP_MAX_WINDOW.min(max_entries - read);
        let low = high.saturating_sub(span - 1);
        let fetched = futures::future::join_all((low..=high).rev().map(|seq| {
            let key = log_keys.entry(seq);
            async move { store.get(&key).await }
        }))
        .await;
        for (seq, result) in (low..=high).rev().zip(fetched) {
            let bytes = match result {
                Ok(Some(bytes)) => bytes,
                // Reaped (or never there): the log before it is gone.
                Ok(None) => {
                    lock().mark_complete_since(complete_from(oldest_ms));
                    return Ok(());
                }
                Err(error) => {
                    lock().mark_complete_since(complete_from(oldest_ms));
                    return Err(error.context(format!("part-log entry {seq} is unreadable")));
                }
            };
            if sha256_hex(&bytes) != expected {
                lock().mark_complete_since(complete_from(oldest_ms));
                bail!("part-log entry {seq} does not match the verified chain");
            }
            let entry = match LogEntry::parse_bytes(&bytes, tenant_id) {
                Ok(entry) => entry,
                Err(error) => {
                    lock().mark_complete_since(complete_from(oldest_ms));
                    return Err(error.context(format!("part-log entry {seq} does not parse")));
                }
            };
            read += 1;
            if entry.appended_at_ms < horizon_ms {
                lock().mark_complete_since(horizon_ms);
                return Ok(());
            }
            if let LogOp::Reject { rejections } = &entry.op {
                lock().record(entry.appended_at_ms, rejections);
            }
            oldest_ms = Some(entry.appended_at_ms);
            expected = entry.prev_sha256;
            if seq == 0 {
                lock().mark_complete_since(i64::MIN);
                return Ok(());
            }
        }
        top = low.checked_sub(1);
    }
    lock().mark_complete_since(complete_from(oldest_ms));
    Ok(())
}

async fn load_checkpoint(store: &dyn ObjectStore, log_keys: &LogKeys, tenant_id: &str, seq: u64) -> Result<Option<LiveSet>> {
    let Some(bytes) = store.get(&log_keys.checkpoint(seq)).await? else { return Ok(None) };
    let checkpoint = Checkpoint::parse_bytes(&bytes, tenant_id)?;
    if checkpoint.seq != seq {
        bail!("checkpoint {seq} names another sequence number");
    }
    // A checkpoint is usable only together with the entry it names (5.3);
    // its parts are verified like any other as they are fetched (4.5).
    let entry = store.get(&log_keys.entry(seq)).await?.context("checkpoint names a missing entry")?;
    if sha256_hex(&entry) != checkpoint.entry_sha256 {
        bail!("checkpoint does not match its entry");
    }
    LogEntry::parse_bytes(&entry, tenant_id)?;
    Ok(Some(LiveSet::from_checkpoint(&checkpoint)?))
}

/// The highest existing entry sequence number, without LIST: the `HEAD`
/// hint when it is exact, otherwise exponential probing plus bisection.
async fn probe_head(store: &dyn ObjectStore, log_keys: &LogKeys) -> Result<Option<u64>> {
    let exists = |seq: u64| async move { Ok::<bool, anyhow::Error>(store.get(&log_keys.entry(seq)).await?.is_some()) };
    let hint = match store.get(&log_keys.head()).await {
        Ok(Some(bytes)) => serde_json::from_slice::<HeadHint>(&bytes).ok().map(|hint| hint.seq),
        _ => None,
    };
    if let Some(seq) = hint.filter(|seq| *seq < MAX_PROBE_SEQ) {
        if exists(seq).await? && !exists(seq + 1).await? {
            return Ok(Some(seq));
        }
    }
    if !exists(0).await? {
        return Ok(None);
    }
    // Invariant: `low` exists; find a `high` that does not.
    let mut low = hint.filter(|seq| *seq < MAX_PROBE_SEQ).unwrap_or(0);
    if !exists(low).await? {
        low = 0;
    }
    let mut step = 1_u64;
    let mut high = low + 1;
    while exists(high).await? {
        low = high;
        step = step.saturating_mul(2);
        high = low.saturating_add(step);
        if high >= MAX_PROBE_SEQ {
            bail!("part log head probe exceeded its bound");
        }
    }
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if exists(mid).await? {
            low = mid;
        } else {
            high = mid;
        }
    }
    Ok(Some(low))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::parts::format::PartId;
    use crate::parts::levels::Level;
    use crate::parts::part_log::{LocalObjectStore, PartLogWriter, SourceRef};
    use crate::parts::provenance::tests::{sample_record, signer, TENANT};
    use crate::parts::provenance::{InputPart, PartInputs, PartSigner, ProvenanceRecord, SignedProvenance};
    use arrow_schema::{DataType, Field, Schema, TimeUnit};

    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
            Field::new("message", DataType::Utf8, true),
        ])
    }

    /// A signed record stored under its part's keys; returns the log ref.
    pub(crate) async fn stored_part(
        store: &dyn ObjectStore,
        n: u64,
        min: i64,
        max: i64,
        level: Level,
        inputs: Option<Vec<PartRef>>,
    ) -> PartRef {
        let mut record: ProvenanceRecord = sample_record();
        record.part_id = PartId::parse(&format!("{:013}-{:016x}", 1_790_330_400_000 + n, n)).unwrap();
        record.created_at_ms = record.part_id.created_unix_ms();
        record.level = level;
        record.min_time_us = min;
        record.max_time_us = max;
        record.hours[0].min_time_us = min;
        record.hours[0].max_time_us = max;
        record.files.data[0].min_time_us = min;
        record.files.data[0].max_time_us = max;
        if let Some(inputs) = inputs {
            record.admission = None;
            record.inputs = PartInputs::Parts {
                parts: inputs
                    .iter()
                    .map(|input| InputPart {
                        part_id: input.part_id.clone(),
                        level: input.level,
                        provenance_sha256: input.provenance_sha256.clone(),
                        rows: input.rows,
                        merkle_root: input.merkle_root.clone(),
                    })
                    .collect(),
            };
        }
        let signer = signer(3);
        let signature = signer.sign(TENANT, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let signed = SignedProvenance::assemble(record.clone(), signature, &signer.trusted()).unwrap();
        let bytes = signed.to_bytes().unwrap();
        let keys = PartKeys::new(TENANT, level, record.event_hour, &record.part_id).unwrap();
        store.put_if_absent(&keys.provenance(), &bytes).await.unwrap();
        PartRef::from_record(&record, &sha256_hex(&bytes), true)
    }

    pub(crate) fn trusted() -> TenantKeySet {
        signer(3).trusted()
    }

    fn source(n: u64) -> SourceRef {
        SourceRef { key: format!("bronze/{n}.parquet"), version: "1".into(), sha256: "d".repeat(64) }
    }

    fn now() -> i64 {
        1_790_330_500_000
    }

    /// Counts entry GETs (the only per-query cost of a warm catch-up).
    struct CountingStore<'a> {
        inner: &'a LocalObjectStore,
        entry_gets: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl ObjectStore for CountingStore<'_> {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            if key.contains("/log/entries/") {
                self.entry_gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.get(key).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
            self.inner.put_if_absent(key, bytes).await
        }
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
            self.inner.put(key, bytes).await
        }
        async fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<String>> {
            self.inner.list(prefix).await
        }
    }

    /// NAN-2989: a cold open over many entries (no checkpoint yet) applies
    /// them all, in order, with merges verified, through windowed GETs; a
    /// warm catch-up with nothing new costs exactly one GET.
    #[tokio::test]
    async fn windowed_catch_up_applies_every_entry_in_order_and_stays_cheap_when_warm() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&local, TENANT, 1, &schema(), now()).await.unwrap();
        let mut pending = Vec::new();
        let mut n = 0_u64;
        for round in 0..20_i64 {
            for _ in 0..4 {
                n += 1;
                let part = stored_part(&local, n, round * 100, round * 100 + 50, Level::L0, None).await;
                writer.append(LogOp::Add { parts: vec![part.clone()], consumed: vec![source(n)], edge_log: None }, now()).await.unwrap();
                pending.push(part);
            }
            n += 1;
            let merged = stored_part(&local, n, round * 100, round * 100 + 50, Level::Minute, Some(pending.clone())).await;
            let supersedes = pending.drain(..).map(|p| p.part_id).collect();
            writer.append(LogOp::Merge { output: merged, supersedes }, now()).await.unwrap();
        }
        // genesis + 20 × (4 adds + 1 merge)
        let head = 100_u64;
        let store = CountingStore { inner: &local, entry_gets: Default::default() };
        let mut view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        assert_eq!(view.head().unwrap().0, head);
        assert_eq!(view.live().parts().count(), 20, "one M part per round survives");
        assert!(view.live().parts().all(|p| p.level == Level::Minute));
        // Warm: one GET for `head + 1`, nothing applied.
        store.entry_gets.store(0, std::sync::atomic::Ordering::SeqCst);
        assert!(view.catch_up(&store).await.unwrap().is_empty());
        assert_eq!(store.entry_gets.load(std::sync::atomic::Ordering::SeqCst), 1);
        // One new entry: two GETs (the hit, then the miss that ends it).
        n += 1;
        let late = stored_part(&local, n, 5_000, 5_050, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![late], consumed: vec![source(n)], edge_log: None }, now()).await.unwrap();
        store.entry_gets.store(0, std::sync::atomic::Ordering::SeqCst);
        let advance = view.catch_up(&store).await.unwrap();
        assert_eq!((advance.entries, advance.new_data.clone()), (1, vec![(5_000, 5_050)]));
        assert_eq!(store.entry_gets.load(std::sync::atomic::Ordering::SeqCst), 3, "window 1 hits, window 2 misses twice");
        assert_eq!(view.head().unwrap().0, head + 1);
    }

    #[tokio::test]
    async fn view_follows_adds_and_verified_merges_and_reports_new_data_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), now()).await.unwrap();
        let first = stored_part(&store, 1, 10, 20, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![first.clone()], consumed: vec![source(1)], edge_log: None }, now()).await.unwrap();
        let mut view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        assert_eq!(view.head().unwrap().0, 1);
        assert_eq!(view.parts_overlapping(0, 100).len(), 1);
        assert!(view.catch_up(&store).await.unwrap().is_empty());

        let second = stored_part(&store, 2, 30, 40, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![second.clone()], consumed: vec![source(2)], edge_log: None }, now()).await.unwrap();
        let merged = stored_part(&store, 3, 10, 40, Level::Minute, Some(vec![first.clone(), second.clone()])).await;
        writer
            .append(LogOp::Merge { output: merged, supersedes: vec![first.part_id.clone(), second.part_id.clone()] }, now())
            .await
            .unwrap();
        let advance = view.catch_up(&store).await.unwrap();
        assert_eq!(advance.entries, 2);
        assert_eq!(advance.new_data, vec![(30, 40)]);
        assert!(advance.touches(35, 36) && !advance.touches(10, 20));
        let live = view.parts_overlapping(0, 100);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].level, Level::Minute);
        assert_eq!(view.read_schema().unwrap().fields().len(), 2);
    }

    #[tokio::test]
    async fn signed_late_part_is_offered_once_then_a_merge_does_not_replay_it() {
        use crate::part_query::detections::{CommitRequest, DetectionGate, PlanRequest};

        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), now()).await.unwrap();
        let first = stored_part(&store, 10, 120, 130, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![first.clone()], consumed: vec![source(10)], edge_log: None }, now()).await.unwrap();
        let mut view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        let gate = DetectionGate::new(None, view.head().unwrap().0).unwrap();
        gate.commit(&CommitRequest { rule_id: "rule".into(), log_seq: 1, evaluated_through_us: 99 }).unwrap();

        // The event-time window is already closed when this owner-signed L0
        // part is committed to the tenant's hash-chained log.
        let late = stored_part(&store, 11, 40, 45, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![late.clone()], consumed: vec![source(11)], edge_log: None }, now()).await.unwrap();
        let advance = view.catch_up(&store).await.unwrap();
        assert_eq!(advance.new_data, vec![(40, 45)]);
        gate.observe(view.head().unwrap().0, &advance);
        let request = |start, end| PlanRequest { rule_id: "rule".into(), window_start_us: start, window_end_us: end, grid_us: Some(100) };
        let plan = gate.plan(&request(100, 199));
        assert_eq!(plan.rerun_windows.len(), 1);
        assert_eq!((plan.rerun_windows[0].start_us, plan.rerun_windows[0].end_us), (0, 99));
        let replay_parts = view.parts_overlapping(0, 99);
        assert_eq!(replay_parts.len(), 1);
        assert_eq!(replay_parts[0].part_id, late.part_id);
        gate.commit(&CommitRequest { rule_id: "rule".into(), log_seq: plan.log_seq, evaluated_through_us: 199 }).unwrap();
        assert!(gate.plan(&request(200, 299)).rerun_windows.is_empty());

        // A signed merge only rearranges the two already visible L0 parts.
        let merged = stored_part(&store, 12, 40, 130, Level::Minute, Some(vec![first.clone(), late.clone()])).await;
        writer.append(LogOp::Merge { output: merged, supersedes: vec![first.part_id, late.part_id] }, now()).await.unwrap();
        let advance = view.catch_up(&store).await.unwrap();
        assert!(advance.new_data.is_empty());
        gate.observe(view.head().unwrap().0, &advance);
        assert!(gate.plan(&request(200, 299)).rerun_windows.is_empty());
    }

    #[tokio::test]
    async fn a_merge_that_supersedes_other_than_its_signed_inputs_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), now()).await.unwrap();
        let first = stored_part(&store, 1, 10, 20, Level::L0, None).await;
        let second = stored_part(&store, 2, 30, 40, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![first.clone(), second.clone()], consumed: vec![source(1)], edge_log: None }, now()).await.unwrap();
        // The signed record merges only `first`, but the entry also retires `second`.
        let merged = stored_part(&store, 3, 10, 20, Level::Minute, Some(vec![first.clone()])).await;
        writer
            .append(LogOp::Merge { output: merged, supersedes: vec![first.part_id.clone(), second.part_id.clone()] }, now())
            .await
            .unwrap();
        let error = PartLogView::open(&store, TENANT, trusted()).await.err().unwrap();
        assert!(format!("{error:#}").contains("without a matching signed record"), "{error:#}");
        // An untrusted signer key never verifies a merge either.
        let other = TenantKeySet::new([("other-key-01".to_string(), crate::parts::provenance::tests::test_key(9).verifying_key())]);
        assert!(PartLogView::open(&store, TENANT, other).await.is_err());
    }

    #[tokio::test]
    async fn cold_open_uses_a_checkpoint_without_listing_and_survives_a_stale_head() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), now()).await.unwrap();
        let part = stored_part(&store, 1, 1, 2, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![part], consumed: vec![source(0)], edge_log: None }, now()).await.unwrap();
        for n in 2..=CHECKPOINT_EVERY + 5 {
            writer.append(LogOp::Schema { schema: LogSchema::from_arrow(&schema()).unwrap() }, now()).await.unwrap();
            let _ = n;
        }
        let log_keys = LogKeys::new(TENANT).unwrap();
        assert!(store.get(&log_keys.checkpoint(CHECKPOINT_EVERY)).await.unwrap().is_some());
        // Stale hint: bisection still finds the true head.
        store.put(&log_keys.head(), br#"{"seq":3,"entry_sha256":"x"}"#).await.unwrap();
        let view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        assert_eq!(view.head().unwrap().0, CHECKPOINT_EVERY + 5);
        assert_eq!(view.live().parts().count(), 1);
        // Missing hint: same answer.
        store.delete(&log_keys.head()).await.unwrap();
        let view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        assert_eq!(view.head().unwrap().0, CHECKPOINT_EVERY + 5);
    }

    fn reject(n: u64, slug: &str, rows: u64) -> LogOp {
        LogOp::Reject {
            rejections: vec![crate::parts::part_log::Rejection {
                source: source(n),
                scope: "object".into(),
                rows_rejected: rows,
                reason: "admission_invalid".into(),
                detail: format!("nano_refusals=v1 {slug}:{rows}:ocsf_constraint_failed@device; bronze admission produced no canonical events"),
            }],
        }
    }

    fn refused_by_source(window: &std::sync::Mutex<RefusalWindow>) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for row in window.lock().unwrap().rows(i64::MIN, i64::MAX) {
            *out.entry(row.source).or_default() += row.rows;
        }
        out
    }

    /// NAN-3662: a view folds the `reject`s it applies; one started from a
    /// checkpoint owes the older ones, which the backfill reads once,
    /// verified against the hash chain, back to the horizon only.
    #[tokio::test]
    async fn refusals_fold_on_catch_up_and_a_checkpoint_start_backfills_to_the_horizon() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let t = |seq: u64| 1_790_330_000_000 + seq as i64 * 1_000;
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), t(0)).await.unwrap();
        for seq in 1..=CHECKPOINT_EVERY + 5 {
            let op = match seq {
                10 => reject(seq, "too_old", 1),
                500 => reject(seq, "azure_monitor", 100),
                s if s == CHECKPOINT_EVERY => reject(seq, "at_checkpoint", 3),
                s if s == CHECKPOINT_EVERY + 3 => reject(seq, "azure_monitor", 7),
                _ => LogOp::Schema { schema: LogSchema::from_arrow(&schema()).unwrap() },
            };
            writer.append(op, t(seq)).await.unwrap();
        }
        let mut view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        let window = view.refusals();
        // Only what the catch-up after the checkpoint applied, not complete yet.
        assert_eq!(refused_by_source(&window), BTreeMap::from([("azure_monitor".to_string(), 7)]));
        assert_eq!(window.lock().unwrap().complete_since_ms(), None);
        let from = view.take_refusal_history().expect("a checkpoint start owes a backfill");
        assert_eq!(from.0, CHECKPOINT_EVERY);
        assert!(view.take_refusal_history().is_none(), "taken once");

        // A capped read stops early and says from when it is complete.
        let capped = std::sync::Mutex::new(RefusalWindow::new(REFUSAL_RETAIN_MS));
        backfill_refusals(&store, TENANT, from.clone(), t(100), 50, &capped).await.unwrap();
        assert_eq!(capped.lock().unwrap().complete_since_ms(), Some(t(CHECKPOINT_EVERY - 49)));
        // A wrong chain anchor counts nothing and fails closed.
        let wrong = std::sync::Mutex::new(RefusalWindow::new(REFUSAL_RETAIN_MS));
        assert!(backfill_refusals(&store, TENANT, (from.0, "0".repeat(64)), t(100), 10_000, &wrong).await.is_err());
        assert!(refused_by_source(&wrong).is_empty());

        backfill_refusals(&store, TENANT, from, t(100), MAX_REFUSAL_BACKFILL_ENTRIES, &window).await.unwrap();
        assert_eq!(refused_by_source(&window), BTreeMap::from([
            ("at_checkpoint".to_string(), 3),
            ("azure_monitor".to_string(), 107),
        ]), "the entry before the horizon is not counted");
        assert_eq!(window.lock().unwrap().complete_since_ms(), Some(t(100)));
        // New refusals keep folding on catch-up.
        writer.append(reject(CHECKPOINT_EVERY + 6, "azure_monitor", 1), t(CHECKPOINT_EVERY + 6)).await.unwrap();
        view.catch_up(&store).await.unwrap();
        assert_eq!(refused_by_source(&window)["azure_monitor"], 108);
    }

    /// NAN-3662: a view replayed from genesis has every refusal already.
    #[tokio::test]
    async fn a_genesis_start_is_complete_without_a_backfill() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), now()).await.unwrap();
        writer.append(reject(1, "azure_monitor", 100), now()).await.unwrap();
        let mut view = PartLogView::open(&store, TENANT, trusted()).await.unwrap();
        assert!(view.take_refusal_history().is_none());
        let window = view.refusals();
        assert_eq!(window.lock().unwrap().complete_since_ms(), Some(i64::MIN));
        assert_eq!(refused_by_source(&window), BTreeMap::from([("azure_monitor".to_string(), 100)]));
    }

    #[tokio::test]
    async fn a_tampered_entry_fails_the_view_closed() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut writer = PartLogWriter::open(&store, TENANT, 1, &schema(), now()).await.unwrap();
        let part = stored_part(&store, 1, 1, 2, Level::L0, None).await;
        writer.append(LogOp::Add { parts: vec![part], consumed: vec![source(1)], edge_log: None }, now()).await.unwrap();
        writer.append(LogOp::Schema { schema: LogSchema::from_arrow(&schema()).unwrap() }, now()).await.unwrap();
        let log_keys = LogKeys::new(TENANT).unwrap();
        // Rewrite entry 1 with different (still canonical) content: the chain breaks at 2.
        let mut entry = LogEntry::parse_bytes(&store.get(&log_keys.entry(1)).await.unwrap().unwrap(), TENANT).unwrap();
        entry.appended_at_ms += 1;
        std::fs::remove_file(store.path(&log_keys.entry(1)).unwrap()).unwrap();
        store.put_if_absent(&log_keys.entry(1), &entry.to_bytes().unwrap()).await.unwrap();
        assert!(PartLogView::open(&store, TENANT, trusted()).await.is_err());
    }
}
