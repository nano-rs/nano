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
}

impl StorePartLogReader {
    /// `trusted`: the owner release signer keys that sign part records.
    pub fn new(store: Arc<dyn ObjectStore>, tenant_uuid: &str, trusted: TenantKeySet) -> Result<Self> {
        Ok(Self { store, tenant_uuid: tenant_uuid.to_string(), keys: LogKeys::new(tenant_uuid)?, trusted,
            gc_private: false,
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
        let keys = self.store.list(&self.keys.checkpoints_prefix()).await?;
        let mut candidates = 0;
        // Filter before the cap: checkpoint-side writer metadata (finding
        // attempt marker, count-backfill admissions) sorts after the numbered
        // snapshots and must never crowd them out of the window.
        for key in keys.iter().rev().filter(|key| crate::parts::part_log::is_snapshot_checkpoint_key(key)).take(32) {
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
            return Ok(Some(CheckpointClaim { seq: checkpoint.seq, checkpoint_sha256: sha256_hex(&bytes), entry_sha256 }));
        }
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
}
