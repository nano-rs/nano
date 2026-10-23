// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3643: quarantine for bronze objects admission refused whole.
//!
//! Before this, a refused object was logged (`reject` entry) and
//! acknowledged, then retention or the edge log dropped it: a parser or
//! admission bug lost the lane's data for good. Now ingest[T] keeps a copy
//! of every object it refuses whole, with the refusal reason, in its own
//! tenant's state directory:
//!
//! - **Tenant-scoped.** One ingest[T] per tenant, one directory under its
//!   work dir; every entry records the tenant and is read back only by that
//!   tenant's ingest. A replay request naming another tenant is refused.
//! - **Bounded.** An entry expires [`QUARANTINE_TTL_MS`] after it was first
//!   kept; the directory holds at most [`MAX_QUARANTINE_BYTES`] (oldest
//!   evicted first) and never an object over [`MAX_QUARANTINED_OBJECT_BYTES`].
//! - **Replay through normal admission.** An operator asks for a replay
//!   (`POST /v1/tenants/{tenant}/admin/bronze-quarantine/replay`, full
//!   operator token only). ingest[T] then admits the kept bytes alone, under
//!   the source identity [`quarantine_replay_key`] /
//!   [`QUARANTINE_REPLAY_VERSION`]: the same admission, uid dedupe (the
//!   in-memory window and the 72 h late tier) and exactly-once commit as any
//!   object. The entry is dropped once the replay's flush committed; a
//!   replay the log already consumed is acknowledged, never admitted twice;
//!   a replay refused again stays quarantined with the new reason.
//!
//! Admission rules are unchanged: this only keeps what they refuse.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use crate::parts::part_log::{quarantine_replay_key, QUARANTINE_REPLAY_VERSION};

/// How long a refused object is kept for a replay (7 days).
pub const QUARANTINE_TTL_MS: i64 = 7 * 86_400_000;
/// The most quarantined bytes one tenant's ingest keeps.
pub const MAX_QUARANTINE_BYTES: u64 = 1 << 30;
/// A larger refused object is not kept (its `reject` entry still is).
pub const MAX_QUARANTINED_OBJECT_BYTES: u64 = 128 << 20;
/// How often ingest sweeps expired entries.
pub const SWEEP_INTERVAL_MS: i64 = 10 * 60_000;

const ENTRY_KIND: &str = "nano.lake.bronze-quarantine.v1";
const DIR: &str = "bronze-quarantine";
/// Notice handles of replays carry this prefix; they are never acked to the
/// source queue (the queue never issued them).
pub const REPLAY_HANDLE_PREFIX: &str = "bronze-quarantine-replay:";

/// One quarantined object, as kept on disk and listed to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QuarantineEntry {
    pub kind: String,
    pub tenant_id: String,
    /// SHA-256 of the kept bytes (the object's id).
    pub id: String,
    /// The refused object's source key and version (edge segment or bronze).
    pub source_key: String,
    pub source_version: String,
    pub scope: String,
    pub reason: String,
    /// Value-free refusal detail (the `reject` entry's).
    pub detail: String,
    pub rows_rejected: u64,
    pub bytes: u64,
    pub quarantined_at_ms: i64,
    pub expires_at_ms: i64,
    /// Times admission refused these bytes (a failed replay adds one).
    pub refusals: u32,
    /// Set by an operator replay request; cleared when it is refused again.
    pub replay_requested_at_ms: Option<i64>,
}

/// Why an operator replay request was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayRefused {
    #[error("replay names another tenant's quarantine")]
    CrossTenant,
    #[error("quarantine id must be a lowercase SHA-256")]
    InvalidId,
    #[error("no quarantined object with that id")]
    NotFound,
}

/// What [`Quarantine::keep`] did with a refused object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kept {
    New,
    /// Already quarantined (a replay refused again): reason updated.
    Again,
    TooLarge,
}

/// The tenant's quarantine directory.
#[derive(Debug, Clone)]
pub struct Quarantine {
    dir: PathBuf,
    tenant: String,
    max_bytes: u64,
    max_object_bytes: u64,
}

/// The kept refusal: where it came from and why.
pub struct Refusal<'a> {
    pub source_key: &'a str,
    pub source_version: &'a str,
    pub scope: &'a str,
    pub reason: &'a str,
    pub detail: &'a str,
    pub rows_rejected: u64,
}

impl Quarantine {
    pub fn open(work_dir: &Path, tenant: &str) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(tenant)?;
        let dir = work_dir.join(DIR);
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self { dir, tenant: tenant.to_string(), max_bytes: MAX_QUARANTINE_BYTES, max_object_bytes: MAX_QUARANTINED_OBJECT_BYTES })
    }

    /// Smaller caps (tests).
    pub fn with_limits(mut self, max_bytes: u64, max_object_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self.max_object_bytes = max_object_bytes.min(max_bytes);
        self
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The notice handle a replay of `id` is admitted under.
    pub fn replay_handle(id: &str) -> String {
        format!("{REPLAY_HANDLE_PREFIX}{id}")
    }

    pub fn is_replay_handle(handle: &str) -> bool {
        handle.starts_with(REPLAY_HANDLE_PREFIX)
    }

    /// The id of this tenant's replay source `key`, if it is one.
    pub fn replay_id<'k>(&self, key: &'k str) -> Option<&'k str> {
        let id = key
            .strip_prefix("bronze-quarantine/tenant_id=")?
            .strip_prefix(self.tenant.as_str())?
            .strip_prefix('/')?
            .strip_suffix(".parquet")?;
        crate::parts::is_sha256_hex(id).then_some(id)
    }

    fn data_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.parquet"))
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// The kept bytes of `id`, for a replay admission.
    pub fn copy_to(&self, id: &str, target: &Path) -> Result<bool> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        match std::fs::copy(self.data_path(id), target) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Keep `file` (bytes with SHA-256 `id`) refused as `refusal`.
    pub fn keep(&self, file: &Path, id: &str, refusal: &Refusal<'_>, now_ms: i64) -> Result<Kept> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        let bytes = std::fs::metadata(file)?.len();
        if bytes > self.max_object_bytes {
            return Ok(Kept::TooLarge);
        }
        let detail = refusal.detail.chars().filter(|c| !c.is_control()).take(480).collect::<String>();
        if let Some(mut entry) = self.load(id)? {
            entry.reason = refusal.reason.to_string();
            entry.detail = detail;
            entry.refusals = entry.refusals.saturating_add(1);
            entry.replay_requested_at_ms = None;
            self.store(&entry)?;
            return Ok(Kept::Again);
        }
        let staged = self.dir.join(format!(".{id}.parquet.tmp"));
        std::fs::copy(file, &staged)?;
        std::fs::File::open(&staged)?.sync_all()?;
        std::fs::rename(&staged, self.data_path(id))?;
        self.store(&QuarantineEntry {
            kind: ENTRY_KIND.into(),
            tenant_id: self.tenant.clone(),
            id: id.into(),
            source_key: refusal.source_key.chars().take(1024).collect(),
            source_version: refusal.source_version.chars().take(256).collect(),
            scope: refusal.scope.into(),
            reason: refusal.reason.into(),
            detail,
            rows_rejected: refusal.rows_rejected,
            bytes,
            quarantined_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(QUARANTINE_TTL_MS),
            refusals: 1,
            replay_requested_at_ms: None,
        })?;
        self.enforce_cap(Some(id))?;
        Ok(Kept::New)
    }

    fn store(&self, entry: &QuarantineEntry) -> Result<()> {
        let staged = self.dir.join(format!(".{}.json.tmp", entry.id));
        std::fs::write(&staged, serde_json::to_vec(entry)?)?;
        std::fs::File::open(&staged)?.sync_all()?;
        std::fs::rename(&staged, self.entry_path(&entry.id))?;
        Ok(())
    }

    /// NAN-4338: this tenant's entry `id`, if kept.
    pub fn get(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        self.load(id)
    }

    /// This tenant's entry `id`. An entry that names another tenant, or
    /// another id than its file, is never returned.
    fn load(&self, id: &str) -> Result<Option<QuarantineEntry>> {
        let bytes = match std::fs::read(self.entry_path(id)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let entry: QuarantineEntry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(id, error = %error, "unreadable bronze quarantine entry ignored");
                return Ok(None);
            }
        };
        if entry.kind != ENTRY_KIND || entry.tenant_id != self.tenant || entry.id != id {
            tracing::warn!(id, "bronze quarantine entry for another scope ignored");
            return Ok(None);
        }
        Ok(Some(entry))
    }

    /// Every entry, oldest first.
    pub fn list(&self) -> Result<Vec<QuarantineEntry>> {
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&self.dir)? {
            let name = item?.file_name();
            let Some(id) = name.to_str().and_then(|name| name.strip_suffix(".json")) else { continue };
            if !crate::parts::is_sha256_hex(id) {
                continue;
            }
            if let Some(entry) = self.load(id)? {
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| (a.quarantined_at_ms, &a.id).cmp(&(b.quarantined_at_ms, &b.id)));
        Ok(entries)
    }

    /// An operator asks to replay `id`, scoped to `tenant`.
    pub fn request_replay(&self, tenant: &str, id: &str, now_ms: i64) -> Result<QuarantineEntry> {
        if tenant != self.tenant {
            return Err(ReplayRefused::CrossTenant.into());
        }
        if !crate::parts::is_sha256_hex(id) {
            return Err(ReplayRefused::InvalidId.into());
        }
        let Some(mut entry) = self.load(id)? else {
            return Err(ReplayRefused::NotFound.into());
        };
        if !self.data_path(id).exists() {
            return Err(ReplayRefused::NotFound.into());
        }
        entry.replay_requested_at_ms.get_or_insert(now_ms);
        self.store(&entry)?;
        Ok(entry)
    }

    /// The oldest entry an operator asked to replay.
    pub fn next_replay(&self) -> Result<Option<QuarantineEntry>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|entry| entry.replay_requested_at_ms.is_some())
            .min_by_key(|entry| (entry.replay_requested_at_ms, entry.quarantined_at_ms)))
    }

    /// Clear a replay request that cannot proceed (the replay was refused
    /// before admission ran, e.g. its bytes vanished); the entry stays
    /// until it expires or an operator asks again.
    pub fn clear_replay(&self, id: &str) -> Result<()> {
        if let Some(mut entry) = self.load(id)? {
            if entry.replay_requested_at_ms.take().is_some() {
                self.store(&entry)?;
            }
        }
        Ok(())
    }

    /// Drop `id` (its replay committed, or it expired).
    pub fn release(&self, id: &str) -> Result<()> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        for path in [self.entry_path(id), self.data_path(id)] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => bail!("remove {}: {error}", path.display()),
            }
        }
        Ok(())
    }

    /// Drop expired entries, stray staging files and orphaned bytes; then
    /// hold the size cap. Returns the entries dropped.
    pub fn sweep(&self, now_ms: i64) -> Result<usize> {
        let mut dropped = 0;
        for entry in self.list()? {
            if entry.expires_at_ms <= now_ms {
                self.release(&entry.id)?;
                dropped += 1;
            }
        }
        for item in std::fs::read_dir(&self.dir)? {
            let path = item?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue };
            let orphan = name
                .strip_suffix(".parquet")
                .is_some_and(|id| !self.entry_path(id).exists());
            if name.starts_with('.') || orphan {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(dropped + self.enforce_cap(None)?)
    }

    /// Evict the oldest entries (never `keep`) while over the size cap.
    fn enforce_cap(&self, keep: Option<&str>) -> Result<usize> {
        let entries = self.list()?;
        let mut total = entries.iter().map(|entry| entry.bytes).sum::<u64>();
        let mut evicted = 0;
        for entry in &entries {
            if total <= self.max_bytes {
                break;
            }
            if Some(entry.id.as_str()) == keep {
                continue;
            }
            tracing::warn!(tenant = %self.tenant, id = %entry.id, source = %entry.source_key, bytes = entry.bytes,
                "bronze quarantine over its size cap; evicting the oldest object");
            self.release(&entry.id)?;
            total = total.saturating_sub(entry.bytes);
            evicted += 1;
        }
        Ok(evicted)
    }

    /// (entries, bytes) held now.
    pub fn usage(&self) -> Result<(usize, u64)> {
        let entries = self.list()?;
        Ok((entries.len(), entries.iter().map(|entry| entry.bytes).sum()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "36430000-0000-4000-8000-000000000001";
    const OTHER: &str = "36430000-0000-4000-8000-000000000002";

    fn refusal() -> Refusal<'static> {
        Refusal {
            source_key: "edgelog/seg-7",
            source_version: "edge-seq:7",
            scope: "object",
            reason: "admission_invalid",
            detail: "no canonical events: first row time missing",
            rows_rejected: 12,
        }
    }

    fn object(dir: &Path, body: &[u8]) -> (PathBuf, String) {
        let path = dir.join(format!("{}.bin", crate::parts::sha256_hex(body)));
        std::fs::write(&path, body).unwrap();
        (path, crate::parts::sha256_hex(body))
    }

    #[test]
    fn refusal_is_kept_with_its_reason_and_expires_after_the_ttl() {
        let root = tempfile::tempdir().unwrap();
        let quarantine = Quarantine::open(root.path(), TENANT).unwrap();
        let (file, id) = object(root.path(), b"refused bytes");
        assert_eq!(quarantine.keep(&file, &id, &refusal(), 1_000).unwrap(), Kept::New);
        let entries = quarantine.list().unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!((entry.tenant_id.as_str(), entry.id.as_str(), entry.reason.as_str()), (TENANT, id.as_str(), "admission_invalid"));
        assert_eq!((entry.source_key.as_str(), entry.rows_rejected, entry.refusals), ("edgelog/seg-7", 12, 1));
        assert_eq!(entry.expires_at_ms, 1_000 + QUARANTINE_TTL_MS);
        let copy = root.path().join("copy");
        assert!(quarantine.copy_to(&id, &copy).unwrap());
        assert_eq!(std::fs::read(&copy).unwrap(), b"refused bytes");

        // Refused again (a failed replay): same entry, new reason, request cleared.
        quarantine.request_replay(TENANT, &id, 2_000).unwrap();
        let again = Refusal { reason: "shape_drift", ..refusal() };
        assert_eq!(quarantine.keep(&file, &id, &again, 3_000).unwrap(), Kept::Again);
        let entry = quarantine.list().unwrap().remove(0);
        assert_eq!((entry.reason.as_str(), entry.refusals, entry.replay_requested_at_ms), ("shape_drift", 2, None));
        assert_eq!(entry.quarantined_at_ms, 1_000, "the TTL runs from the first refusal");

        assert_eq!(quarantine.sweep(1_000 + QUARANTINE_TTL_MS - 1).unwrap(), 0);
        assert_eq!(quarantine.sweep(1_000 + QUARANTINE_TTL_MS).unwrap(), 1);
        assert!(quarantine.list().unwrap().is_empty());
        assert!(!quarantine.copy_to(&id, &copy).unwrap(), "expired bytes are gone");
    }

    #[test]
    fn replay_requests_are_tenant_scoped_and_validated() {
        let root = tempfile::tempdir().unwrap();
        let quarantine = Quarantine::open(&root.path().join(TENANT), TENANT).unwrap();
        let other = Quarantine::open(&root.path().join(OTHER), OTHER).unwrap();
        let (file, id) = object(root.path(), b"tenant a bytes");
        quarantine.keep(&file, &id, &refusal(), 1_000).unwrap();
        let refused = |result: Result<QuarantineEntry>| result.unwrap_err().downcast::<ReplayRefused>().unwrap();
        assert_eq!(refused(quarantine.request_replay(OTHER, &id, 2_000)), ReplayRefused::CrossTenant);
        assert_eq!(refused(other.request_replay(OTHER, &id, 2_000)), ReplayRefused::NotFound,
            "another tenant's quarantine never holds this object");
        assert_eq!(refused(quarantine.request_replay(TENANT, "../../etc/passwd", 2_000)), ReplayRefused::InvalidId);
        assert!(quarantine.next_replay().unwrap().is_none());
        quarantine.request_replay(TENANT, &id, 2_000).unwrap();
        assert_eq!(quarantine.next_replay().unwrap().unwrap().id, id);

        // An entry file copied in from another tenant is never served.
        let foreign = other.dir.join(format!("{id}.json"));
        std::fs::copy(quarantine.entry_path(&id), &foreign).unwrap();
        std::fs::copy(quarantine.data_path(&id), other.data_path(&id)).unwrap();
        assert!(other.list().unwrap().is_empty());
        assert_eq!(refused(other.request_replay(OTHER, &id, 2_000)), ReplayRefused::NotFound);

        // Replay keys name exactly this tenant.
        assert_eq!(quarantine.replay_id(&quarantine_replay_key(TENANT, &id)), Some(id.as_str()));
        assert_eq!(quarantine.replay_id(&quarantine_replay_key(OTHER, &id)), None);
        assert_eq!(other.replay_id(&quarantine_replay_key(TENANT, &id)), None);
    }

    #[test]
    fn oversized_objects_are_not_kept_and_the_cap_evicts_the_oldest() {
        assert!(MAX_QUARANTINED_OBJECT_BYTES < MAX_QUARANTINE_BYTES);
        let root = tempfile::tempdir().unwrap();
        let (max_bytes, per) = (1_000, 100);
        let quarantine = Quarantine::open(root.path(), TENANT).unwrap().with_limits(max_bytes, per);
        let big = root.path().join("big");
        std::fs::write(&big, vec![7_u8; per as usize + 1]).unwrap();
        assert_eq!(quarantine.keep(&big, &"a".repeat(64), &refusal(), 1).unwrap(), Kept::TooLarge);
        assert!(quarantine.list().unwrap().is_empty());
        // Fill past the cap with objects at the per-object maximum.
        let fits = (max_bytes / per) as usize;
        for n in 0..=fits {
            let file = root.path().join(format!("o{n}"));
            std::fs::write(&file, vec![n as u8; per as usize]).unwrap();
            let id = format!("{n:064x}");
            quarantine.keep(&file, &id, &refusal(), n as i64).unwrap();
        }
        let (count, bytes) = quarantine.usage().unwrap();
        assert_eq!(count, fits);
        assert!(bytes <= max_bytes);
        assert!(quarantine.list().unwrap().iter().all(|entry| entry.id != format!("{:064x}", 0)), "the oldest was evicted");
    }
}
