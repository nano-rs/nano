// SPDX-License-Identifier: AGPL-3.0-or-later

//! A part-log reader over an [`ObjectStore`], and the owner refusal code
//! parser part GC shares with the cell's own owner client.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

use super::index::{CheckpointClaim, PartLogReader, VerifiedEntryBytes};
use crate::parts::format::{LogKeys, PartKeys};
use crate::parts::part_log::{Checkpoint, LogEntry, ObjectStore, PartRef};
use crate::parts::provenance::{ProvenanceRecord, SignedProvenance, TenantKeySet};
use crate::parts::sha256_hex;

/// The owner's `{"error": code}` from a refusal body (or any text that
/// embeds it); `http_<status>` when there is none or it is not a stable code.
pub fn error_code(detail: &str, status: u16) -> String {
    detail
        .find('{')
        .and_then(|start| serde_json::from_str::<serde_json::Value>(&detail[start..]).ok())
        .and_then(|body| body.get("error").and_then(|code| code.as_str()).map(str::to_string))
        .filter(|code| code.len() <= 128 && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()))
        .unwrap_or_else(|| format!("http_{status}"))
}

/// A [`PartLogReader`] over the tenant's part store, verifying with the
/// contract's own parsers: canonical unsigned entries and checkpoints
/// (`LogEntry::parse_bytes`, `Checkpoint::parse_bytes`) and owner-signed
/// provenance (`SignedProvenance::verify_bytes` + `PartRef::check_record`).
pub struct StorePartLogReader {
    store: Arc<dyn ObjectStore>,
    tenant_uuid: String,
    keys: LogKeys,
    trusted: TenantKeySet,
    gc_private: bool,
    /// NAN-4160: continuation for checkpoint discovery, the seq of the
    /// newest checkpoint this reader verified. Discovery resumes there.
    checkpoint_cursor: std::sync::Mutex<Option<u64>>,
}

/// Keys per checkpoint listing page (the guarded store's page bound).
pub(crate) const CHECKPOINT_PAGE_KEYS: usize = 256;
/// Pages one discovery call may read. A larger backlog of numbered
/// checkpoints is walked across calls from the cursor, so each call is
/// bounded and discovery reaches the newest checkpoint after
/// `ceil(backlog / (CHECKPOINT_PAGE_KEYS * CHECKPOINT_PAGES_PER_CALL))` calls.
pub(crate) const CHECKPOINT_PAGES_PER_CALL: usize = 4;

impl StorePartLogReader {
    /// `trusted`: the owner release signer keys that sign part records.
    pub fn new(store: Arc<dyn ObjectStore>, tenant_uuid: &str, trusted: TenantKeySet) -> Result<Self> {
        Ok(Self { store, tenant_uuid: tenant_uuid.to_string(), keys: LogKeys::new(tenant_uuid)?, trusted,
            gc_private: false, checkpoint_cursor: std::sync::Mutex::new(None),
        })
    }
    pub(crate) fn gc_private(mut self) -> Self {
        self.gc_private = true;
        self
    }
}

#[async_trait]
impl PartLogReader for StorePartLogReader {
    async fn read_ahead_bytes(&self, seq: u64) -> Result<Option<Vec<u8>>> {
        self.store.get(&self.keys.entry(seq)).await
    }

    async fn verified_entry(&self, seq: u64) -> Result<Option<VerifiedEntryBytes>> {
        let Some(bytes) = self.store.get(&self.keys.entry(seq)).await? else { return Ok(None);
        };
        let entry = if self.gc_private {
            crate::part_ingest::part_gc_cell::gc_parse_entry(&bytes, &self.tenant_uuid)
        } else {
            LogEntry::parse_bytes(&bytes, &self.tenant_uuid)
        }
        .with_context(|| format!("part-log entry {seq} does not verify"))?;
        anyhow::ensure!(entry.seq == seq, "part-log entry {seq} names seq {}", entry.seq);
        Ok(Some(VerifiedEntryBytes { sha256: sha256_hex(&bytes), bytes, entry }))
    }

    async fn newest_checkpoint(&self) -> Result<Option<CheckpointClaim>> {
        // NAN-4160: never list the whole `log/checkpoints/` prefix. It also
        // holds ingest metadata (restamp snapshots, count-backfill records)
        // that grows without bound, and a guarded listing refuses more than
        // 256 keys, which stalled GC for good on busy tenants. Walk only the
        // numbered snapshots, a bounded number of pages per call, resuming
        // after the last verified checkpoint.
        let prefix = self.keys.checkpoints_prefix();
        let resume = *self.checkpoint_cursor.lock().expect("checkpoint cursor lock");
        // Start just before the remembered checkpoint so it stays a candidate.
        let mut after = resume.and_then(|seq| seq.checked_sub(1)).map(|seq| self.keys.checkpoint(seq));
        let mut numbered = Vec::new();
        for _ in 0..CHECKPOINT_PAGES_PER_CALL {
            let page = self.store.list_page(&prefix, after.as_deref(), CHECKPOINT_PAGE_KEYS).await?;
            let full = page.len() >= CHECKPOINT_PAGE_KEYS;
            // Numbered names are 20 digits and sort before every metadata
            // name (all start with a lowercase letter): the first other key
            // ends the numbered range.
            let mut past_numbered = false;
            for key in &page {
                anyhow::ensure!(key.starts_with(&prefix), "checkpoint listing escaped its prefix");
                if crate::parts::part_log::is_snapshot_checkpoint_key(key) {
                    numbered.push(key.clone());
                } else if !key[prefix.len()..].starts_with(|c: char| c.is_ascii_digit()) {
                    past_numbered = true;
                    break;
                }
            }
            after = page.last().cloned();
            if !full || past_numbered {
                break;
            }
        }
        let mut candidates = 0;
        // Filter before the cap: checkpoint-side writer metadata (finding
        // attempt marker, count-backfill admissions) sorts after the numbered
        // snapshots and must never crowd them out of the window.
        for key in numbered.iter().rev().take(32) {
            candidates += 1;
            anyhow::ensure!(
                !self.gc_private || candidates <= 16,
                "GC checkpoint candidate limit"
            );
            let Some(bytes) = self.store.get(key).await? else { continue;
            };
            if self.gc_private {
                crate::part_ingest::part_gc_cell::gc_parsed_preflight(&bytes)?;
            }
            let checkpoint = match Checkpoint::parse_bytes(&bytes, &self.tenant_uuid) {
                Ok(checkpoint) if *key == self.keys.checkpoint(checkpoint.seq) => checkpoint,
                Ok(_) => continue,
                Err(error) => {
                    tracing::warn!(%key, error = %error, "skipping unreadable part-log checkpoint");
                    continue;
                }
            };
            let Some(entry) = self.store.get(&self.keys.entry(checkpoint.seq)).await? else { continue;
            };
            let entry_sha256 = sha256_hex(&entry);
            if entry_sha256 != checkpoint.entry_sha256 {
                continue;
            }
            // Monotonic: a concurrent call that verified an older checkpoint
            // never moves the cursor back.
            let mut cursor = self.checkpoint_cursor.lock().expect("checkpoint cursor lock");
            *cursor = Some(cursor.map_or(checkpoint.seq, |seq| seq.max(checkpoint.seq)));
            drop(cursor);
            return Ok(Some(CheckpointClaim { seq: checkpoint.seq, checkpoint_sha256: sha256_hex(&bytes), entry_sha256 }));
        }
        // Nothing verifies from the cursor (e.g. a replaced log): rescan from
        // the start next time rather than trust a stale position.
        *self.checkpoint_cursor.lock().expect("checkpoint cursor lock") = None;
        Ok(None)
    }

    async fn verified_provenance(&self, part: &PartRef) -> Result<ProvenanceRecord> {
        let key = PartKeys::new(&self.tenant_uuid, part.level, part.event_hour, &part.part_id)?.provenance();
        let bytes = self.store.get(&key).await?.with_context(|| format!("part {} has no provenance", part.part_id))?;
        let sha256 = sha256_hex(&bytes);
        anyhow::ensure!(sha256 == part.provenance_sha256, "part {} provenance digest differs from the log", part.part_id);
        if self.gc_private {
            crate::part_ingest::part_gc_cell::gc_parsed_preflight(&bytes)?;
        }
        let signed = SignedProvenance::verify_bytes(&bytes, &self.tenant_uuid, &self.trusted)?;
        part.check_record(&signed.record, &sha256)?;
        Ok(signed.record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn store_reader_verifies_entries_and_signed_provenance() {
        use crate::lake_part_gc::planner::tests::{adopted_record, T0};
        use crate::lake_part_gc::request::tests::TENANT_UUID;
        use crate::parts::part_log::{LocalObjectStore, PartLogWriter};
        use crate::parts::provenance::{tests::signer, PartSigner};
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path()).unwrap());
        let schema = arrow_schema::Schema::new(vec![
            arrow_schema::Field::new(
                "time",
                arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("+00:00".into())),
                false,
            ),
            arrow_schema::Field::new("message", arrow_schema::DataType::Utf8, true),
        ]);
        PartLogWriter::open(store.as_ref(), TENANT_UUID, 1, &schema, T0).await.unwrap();

        let owner = signer(1);
        let record = adopted_record(10, "warehouse/nano/events/data/a.parquet", &"e".repeat(64));
        let signature = owner.sign(TENANT_UUID, std::slice::from_ref(&record)).await.unwrap().remove(0);
        let bytes = SignedProvenance::assemble(record.clone(), signature, &owner.trusted()).unwrap().to_bytes().unwrap();
        let part = PartRef::from_record(&record, &sha256_hex(&bytes), false);
        let keys = PartKeys::new(TENANT_UUID, part.level, part.event_hour, &part.part_id).unwrap();
        store.put(&keys.provenance(), &bytes).await.unwrap();

        let reader = StorePartLogReader::new(store.clone(), TENANT_UUID, owner.trusted()).unwrap();
        assert_eq!(reader.verified_entry(0).await.unwrap().unwrap().entry.seq, 0);
        assert!(reader.verified_entry(1).await.unwrap().is_none());
        assert_eq!(reader.verified_provenance(&part).await.unwrap(), record);
        let mut wrong = part.clone();
        wrong.provenance_sha256 = "f".repeat(64);
        assert!(reader.verified_provenance(&wrong).await.is_err());
        let untrusted = StorePartLogReader::new(store, TENANT_UUID, signer(2).trusted()).unwrap();
        assert!(untrusted.verified_provenance(&part).await.is_err());
    }

    /// NAN-4160: a store that serves only bounded pages. A full listing of
    /// `log/checkpoints/` is what stalled GC; it is refused here.
    struct PagedOnly {
        inner: crate::parts::part_log::LocalObjectStore,
        pages: std::sync::atomic::AtomicUsize,
        gets: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl ObjectStore for PagedOnly {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.get(key).await
        }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> { self.inner.put_if_absent(key, bytes).await }
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
        async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
        async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
            anyhow::bail!("checkpoint discovery must not list the whole prefix")
        }
        async fn list_page(&self, prefix: &str, start_after: Option<&str>, limit: usize) -> Result<Vec<String>> {
            assert!(limit <= CHECKPOINT_PAGE_KEYS, "page larger than the guarded bound");
            self.pages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.list_page(prefix, start_after, limit).await
        }
    }

    #[tokio::test]
    async fn checkpoint_discovery_converges_on_a_large_backlog_with_bounded_calls() {
        use crate::lake_part_gc::planner::tests::{Chain, T0};
        use crate::lake_part_gc::request::tests::TENANT_UUID;
        use crate::parts::part_log::{CHECKPOINT_EVERY, LocalObjectStore};
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PagedOnly {
            inner: LocalObjectStore::new(dir.path()).unwrap(),
            pages: Default::default(), gets: Default::default(),
        });
        let keys = LogKeys::new(TENANT_UUID).unwrap();
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        let base = chain.view().live().checkpoint(TENANT_UUID).unwrap();
        let write = |seq: u64| {
            let (store, keys, mut checkpoint) = (store.clone(), keys.clone(), base.clone());
            async move {
                let entry = format!("entry-{seq}").into_bytes();
                checkpoint.seq = seq;
                checkpoint.entry_sha256 = sha256_hex(&entry);
                store.put(&keys.entry(seq), &entry).await.unwrap();
                store.put(&keys.checkpoint(seq), &checkpoint.to_bytes().unwrap().unwrap()).await.unwrap();
            }
        };
        // Live shape that stalled two tenants (72 checkpoints + 222 restamp
        // snapshots), scaled up: the numbered backlog alone
        // spans several calls, and metadata alone exceeds one guarded page.
        let backlog: u64 = 2_500;
        for n in 1..=backlog {
            write(n * CHECKPOINT_EVERY).await;
        }
        let prefix = keys.checkpoints_prefix();
        for n in 0..300 {
            store.put(&format!("{prefix}prevalence-restamp-v1/{:013}-{:016x}.json", 1_800_000_000_000_u64 + n, n), b"[]").await.unwrap();
        }
        store.put(&format!("{prefix}count-backfill-v1/1800000000000-0123456789abcdef.json"), b"{}").await.unwrap();
        store.put(&format!("{prefix}finding-attempt-index-v1"), b"").await.unwrap();

        let reader = StorePartLogReader::new(store.clone(), TENANT_UUID, TenantKeySet::default()).unwrap();
        // Backlog x per-call cost: each call reads at most PAGES pages and
        // gains PAGES * PAGE - 1 new checkpoints (the cursor's own is re-read),
        // so the newest is reached within this many calls.
        let per_call = (CHECKPOINT_PAGE_KEYS * CHECKPOINT_PAGES_PER_CALL - 1) as u64;
        let bound = backlog.div_ceil(per_call);
        assert!(bound > 1, "the backlog must need more than one call");
        let (mut calls, mut last) = (0_u64, 0_u64);
        loop {
            let (pages, gets) = (store.pages.load(Ordering::SeqCst), store.gets.load(Ordering::SeqCst));
            let claim = reader.newest_checkpoint().await.unwrap().expect("a checkpoint verifies");
            calls += 1;
            assert!(store.pages.load(Ordering::SeqCst) - pages <= CHECKPOINT_PAGES_PER_CALL);
            assert!(store.gets.load(Ordering::SeqCst) - gets <= 2 * 32);
            assert!(claim.seq > last, "every call must make progress");
            last = claim.seq;
            if claim.seq == backlog * CHECKPOINT_EVERY {
                break;
            }
            assert!(calls < bound, "discovery did not converge within {bound} calls");
        }
        assert!(calls <= bound);
        // Steady state: one new checkpoint costs one page, whatever the
        // metadata beside it.
        write((backlog + 1) * CHECKPOINT_EVERY).await;
        let pages = store.pages.load(Ordering::SeqCst);
        assert_eq!(reader.newest_checkpoint().await.unwrap().unwrap().seq, (backlog + 1) * CHECKPOINT_EVERY);
        assert_eq!(store.pages.load(Ordering::SeqCst) - pages, 1);
        assert_eq!(reader.newest_checkpoint().await.unwrap().unwrap().seq, (backlog + 1) * CHECKPOINT_EVERY);
    }

    #[tokio::test]
    async fn checkpoint_discovery_ignores_metadata_beyond_one_page() {
        use crate::lake_part_gc::planner::tests::{Chain, T0};
        use crate::lake_part_gc::request::tests::TENANT_UUID;
        use crate::parts::part_log::LocalObjectStore;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PagedOnly {
            inner: LocalObjectStore::new(dir.path()).unwrap(),
            pages: Default::default(), gets: Default::default(),
        });
        let keys = LogKeys::new(TENANT_UUID).unwrap();
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        let mut checkpoint = chain.view().live().checkpoint(TENANT_UUID).unwrap();
        let (seq, entry_bytes) = (checkpoint.seq, b"entry".to_vec());
        checkpoint.entry_sha256 = sha256_hex(&entry_bytes);
        store.put(&keys.entry(seq), &entry_bytes).await.unwrap();
        store.put(&keys.checkpoint(seq), &checkpoint.to_bytes().unwrap().unwrap()).await.unwrap();
        let prefix = keys.checkpoints_prefix();
        for n in 0..600 {
            store.put(&format!("{prefix}prevalence-restamp-v1/{:013}-{:016x}.json", 1_800_000_000_000_u64 + n, n), b"[]").await.unwrap();
        }
        let reader = StorePartLogReader::new(store.clone(), TENANT_UUID, TenantKeySet::default()).unwrap();
        assert_eq!(reader.newest_checkpoint().await.unwrap().unwrap().seq, seq);
        assert_eq!(store.pages.load(std::sync::atomic::Ordering::SeqCst), 1, "metadata after the numbered range is never paged");
    }

}
