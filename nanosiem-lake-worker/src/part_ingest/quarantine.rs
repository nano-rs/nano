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
//!
//! NAN-4554: the directory is a working copy. Every change is queued in its
//! `outbox/` and mirrored into the tenant bucket
//! ([`super::quarantine_store`]), and a fresh work dir (a replaced pod) is
//! restored from there.

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
/// NAN-4554: ids whose change still has to reach the tenant bucket.
const OUTBOX: &str = "outbox";
/// NAN-4554: present once this work dir was restored from the bucket. It
/// holds the restore's low-water mark (see [`Quarantine::mark_restored`]).
const RESTORED_MARKER: &str = "restored-v1";
/// NAN-4554 (review P1): `released/{id}` holds when `id` was released (its
/// replay committed), for [`QUARANTINE_TTL_MS`]: an import of a released id
/// is refused, so its rows can never be admitted twice (uid dedupe sees only
/// the 72 h late tier; quarantined objects are often older).
const RELEASED: &str = "released";
/// NAN-4554 (review P3): an import's staging file younger than this is never
/// swept (the body streams without the quarantine lock).
const IMPORT_STAGING_MAX_AGE_MS: i64 = 60 * 60_000;
/// Clock skew allowed between the pod that wrote a bucket record and the
/// entry's `quarantined_at_ms` (the restore horizon's slack too).
const RECORD_SKEW_MS: i64 = 86_400_000;
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

/// NAN-4554: entries an operator import may bring the quarantine to (the
/// byte cap still applies on top).
pub const MAX_IMPORTED_ENTRIES: usize = 1_024;

/// What [`Quarantine::import`] did with one exported object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Imported {
    /// Kept and queued for the tenant-bucket mirror.
    New,
    /// The id is already kept with these bytes: a no-op.
    Exists,
}

/// Why an operator import of one exported object was refused (nothing was
/// written).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImportRefused {
    #[error("the entry names another tenant's quarantine")]
    CrossTenant,
    #[error("the entry is not a bronze quarantine entry")]
    Malformed,
    #[error("the bytes do not hash to the entry's id")]
    Digest,
    #[error("the bytes do not have the entry's size")]
    Size,
    #[error("the entry expired")]
    Expired,
    #[error("the object is over the per-object cap")]
    ObjectTooLarge,
    #[error("the quarantine would exceed its byte cap")]
    OverCap,
    #[error("the quarantine would exceed its entry cap")]
    TooManyEntries,
    #[error("the id is kept with different bytes")]
    Conflict,
    /// Its replay already committed (a release tombstone, local or restored
    /// from the bucket): importing it again could commit its rows twice.
    #[error("the id was already released (its replay committed)")]
    Released,
    /// This work dir has not been restored from the tenant bucket yet, so a
    /// release recorded there is not known here: retry once it is.
    #[error("the quarantine restore from the tenant bucket has not completed")]
    RestorePending,
    /// Older than the records the bounded restore read: a release of it
    /// may exist in the bucket unread.
    #[error("the entry is older than the restore's read bound")]
    BeyondRestoreBound,
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
        std::fs::create_dir_all(dir.join(OUTBOX)).with_context(|| format!("create {}", dir.display()))?;
        std::fs::create_dir_all(dir.join(RELEASED)).with_context(|| format!("create {}", dir.display()))?;
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

    /// NAN-4554: the caps a restore applies before it downloads anything.
    pub(crate) fn limits(&self) -> (u64, u64) {
        (self.max_bytes, self.max_object_bytes)
    }

    /// NAN-4554: the directory (its volume's free space bounds a restore).
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
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
            self.enqueue(id, now_ms)?;
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
        self.enqueue(id, now_ms)?;
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
        self.enqueue(id, now_ms)?;
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
    pub fn clear_replay(&self, id: &str, now_ms: i64) -> Result<()> {
        if let Some(mut entry) = self.load(id)? {
            if entry.replay_requested_at_ms.take().is_some() {
                self.store(&entry)?;
                self.enqueue(id, now_ms)?;
            }
        }
        Ok(())
    }

    /// Drop `id`: its replay committed. The release is mirrored, so a
    /// restored quarantine never offers it again.
    pub fn release(&self, id: &str, now_ms: i64) -> Result<()> {
        // The tombstone first: a crash after it never leaves the id
        // importable again.
        self.tombstone(id, now_ms)?;
        self.remove_local(id)?;
        self.enqueue(id, now_ms)
    }

    /// NAN-4554 (review P1): record that `id` was released at `at_ms` (kept
    /// for [`QUARANTINE_TTL_MS`] from then; an earlier time already kept wins).
    pub(crate) fn tombstone(&self, id: &str, at_ms: i64) -> Result<()> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        if self.released_at(id)?.is_some_and(|kept| kept <= at_ms) {
            return Ok(());
        }
        let staged = self.dir.join(RELEASED).join(format!(".{id}.tmp"));
        std::fs::write(&staged, at_ms.to_string())?;
        std::fs::File::open(&staged)?.sync_all()?;
        std::fs::rename(&staged, self.dir.join(RELEASED).join(id))?;
        Ok(())
    }

    /// NAN-4554: when `id` was released, if its tombstone is kept. An
    /// unreadable tombstone counts as released (fail closed).
    pub fn released_at(&self, id: &str) -> Result<Option<i64>> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        match std::fs::read_to_string(self.dir.join(RELEASED).join(id)) {
            Ok(at) => Ok(Some(at.trim().parse::<i64>().unwrap_or(i64::MAX))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Drop `id` here only (expiry, the cap, a restored release): every
    /// copy applies the same expiry and cap, so nothing is mirrored.
    pub(crate) fn remove_local(&self, id: &str) -> Result<()> {
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
                self.remove_local(&entry.id)?;
                dropped += 1;
            }
        }
        for item in std::fs::read_dir(&self.dir)? {
            let path = item?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue };
            let orphan = name
                .strip_suffix(".parquet")
                .is_some_and(|id| !self.entry_path(id).exists());
            // Review P3: an import still streaming its body is not swept.
            if name.starts_with(".import-") && young(&path, now_ms) {
                continue;
            }
            if name.starts_with('.') || orphan {
                let _ = std::fs::remove_file(&path);
            }
        }
        for item in std::fs::read_dir(self.dir.join(RELEASED))? {
            let path = item?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else { continue };
            let expired = crate::parts::is_sha256_hex(name)
                && self.released_at(name)?.is_some_and(|at| at != i64::MAX && at.saturating_add(QUARANTINE_TTL_MS) <= now_ms);
            if expired || name.starts_with('.') {
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
            self.remove_local(&entry.id)?;
            total = total.saturating_sub(entry.bytes);
            evicted += 1;
        }
        Ok(evicted)
    }

    // ---------------------------------------------------------- NAN-4554

    /// Queue `id` for the bucket mirror (an entry kept before mirroring).
    pub(crate) fn enqueue_mirror(&self, id: &str, now_ms: i64) -> Result<()> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        self.enqueue(id, now_ms)
    }

    /// Queue `id` for the bucket mirror (survives a process restart).
    fn enqueue(&self, id: &str, now_ms: i64) -> Result<()> {
        let path = self.dir.join(OUTBOX).join(id);
        if path.exists() {
            return Ok(());
        }
        let staged = self.dir.join(OUTBOX).join(format!(".{id}.tmp"));
        std::fs::write(&staged, now_ms.to_string())?;
        std::fs::File::open(&staged)?.sync_all()?;
        std::fs::rename(&staged, &path)?;
        Ok(())
    }

    /// Ids whose change has not reached the bucket yet, with when each was
    /// first queued, oldest first.
    pub fn outbox(&self) -> Result<Vec<(String, i64)>> {
        let mut queued = Vec::new();
        for item in std::fs::read_dir(self.dir.join(OUTBOX))? {
            let item = item?;
            let Some(id) = item.file_name().to_str().map(str::to_string) else { continue };
            if !crate::parts::is_sha256_hex(&id) {
                continue;
            }
            let at = std::fs::read_to_string(item.path()).ok().and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0);
            queued.push((id, at));
        }
        queued.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
        Ok(queued)
    }

    /// `id`'s change reached the bucket.
    pub fn outbox_done(&self, id: &str) -> Result<()> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        match std::fs::remove_file(self.dir.join(OUTBOX).join(id)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    /// The kept bytes of `id` and their length.
    pub fn data_file(&self, id: &str) -> Result<Option<(PathBuf, u64)>> {
        ensure!(crate::parts::is_sha256_hex(id), "invalid quarantine id");
        let path = self.data_path(id);
        match std::fs::metadata(&path) {
            Ok(meta) => Ok(Some((path, meta.len()))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// A scratch file in the directory (swept like any staging file).
    pub fn staging_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!(".{name}.tmp"))
    }

    /// Take a restored entry and its verified bytes (`staged`, moved in).
    pub fn adopt(&self, entry: &QuarantineEntry, staged: &Path) -> Result<()> {
        ensure!(entry.tenant_id == self.tenant && crate::parts::is_sha256_hex(&entry.id), "restored entry for another scope");
        std::fs::File::open(staged)?.sync_all()?;
        std::fs::rename(staged, self.data_path(&entry.id))?;
        self.store(entry)
    }

    /// NAN-4554: take one object exported from an earlier pod (`staged`, in
    /// this directory, moved in) with its entry, after verifying everything
    /// before any write: kind, tenant, id == sha256(bytes), size, expiry,
    /// the per-object, byte and entry caps. Idempotent per id: an id kept
    /// with the same bytes is a no-op; different bytes are refused. A kept
    /// import is queued for the tenant-bucket mirror (its replay request,
    /// if any, is cleared: the operator replays on this pod).
    pub fn import(&self, entry: &QuarantineEntry, staged: &Path, now_ms: i64) -> Result<Imported> {
        let refused = |reason: ImportRefused| -> Result<Imported> {
            let _ = std::fs::remove_file(staged);
            Err(reason.into())
        };
        if entry.tenant_id != self.tenant {
            return refused(ImportRefused::CrossTenant);
        }
        if entry.kind != ENTRY_KIND || !crate::parts::is_sha256_hex(&entry.id) {
            return refused(ImportRefused::Malformed);
        }
        // Review P1, fail closed: a released id (here or, via the restore,
        // in the bucket) is never kept again.
        if self.needs_restore() {
            return refused(ImportRefused::RestorePending);
        }
        if self.released_at(&entry.id)?.is_some() {
            return refused(ImportRefused::Released);
        }
        if self.restore_low_water_ms()?.is_some_and(|low| entry.quarantined_at_ms < low.saturating_add(RECORD_SKEW_MS)) {
            return refused(ImportRefused::BeyondRestoreBound);
        }
        let (bytes, digest) = super::writer::file_digest(staged)?;
        if digest != entry.id {
            return refused(ImportRefused::Digest);
        }
        if bytes != entry.bytes {
            return refused(ImportRefused::Size);
        }
        if entry.expires_at_ms <= now_ms {
            return refused(ImportRefused::Expired);
        }
        if bytes > self.max_object_bytes {
            return refused(ImportRefused::ObjectTooLarge);
        }
        if self.get(&entry.id)?.is_some() {
            return match self.data_file(&entry.id)? {
                Some((path, _)) if super::writer::file_digest(&path)?.1 == entry.id => {
                    let _ = std::fs::remove_file(staged);
                    Ok(Imported::Exists)
                }
                _ => refused(ImportRefused::Conflict),
            };
        }
        let (entries, used) = self.usage()?;
        if entries + 1 > MAX_IMPORTED_ENTRIES {
            return refused(ImportRefused::TooManyEntries);
        }
        if used.saturating_add(bytes) > self.max_bytes {
            return refused(ImportRefused::OverCap);
        }
        let entry = QuarantineEntry { replay_requested_at_ms: None, ..entry.clone() };
        self.adopt(&entry, staged)?;
        self.enqueue_mirror(&entry.id, now_ms)?;
        Ok(Imported::New)
    }

    /// Whether this work dir still has to be restored from the bucket.
    pub fn needs_restore(&self) -> bool {
        !self.dir.join(RESTORED_MARKER).exists()
    }

    /// The restore completed. `low_water_ms`: the write time of the oldest
    /// bucket record it read when it read only the newest records (bounded);
    /// entries quarantined before that (less the clock skew) are not
    /// imported, as their release may be in an unread record.
    pub fn mark_restored(&self, low_water_ms: Option<i64>) -> Result<()> {
        let body = low_water_ms.map_or_else(|| "1".to_string(), |low| format!("low_water_ms={low}"));
        let staged = self.dir.join(format!(".{RESTORED_MARKER}.tmp"));
        std::fs::write(&staged, body)?;
        std::fs::File::open(&staged)?.sync_all()?;
        std::fs::rename(&staged, self.dir.join(RESTORED_MARKER))?;
        Ok(())
    }

    /// The low-water mark the restore recorded, if it was bounded.
    fn restore_low_water_ms(&self) -> Result<Option<i64>> {
        match std::fs::read_to_string(self.dir.join(RESTORED_MARKER)) {
            // Unparseable counts as everything beyond the bound (fail closed).
            Ok(body) => Ok(body.trim().strip_prefix("low_water_ms=").map(|low| low.parse::<i64>().unwrap_or(i64::MAX))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// (entries, bytes) held now.
    pub fn usage(&self) -> Result<(usize, u64)> {
        let entries = self.list()?;
        Ok((entries.len(), entries.iter().map(|entry| entry.bytes).sum()))
    }
}

/// Whether `path` was modified less than [`IMPORT_STAGING_MAX_AGE_MS`]
/// before `now_ms` (unknown: treated as young; a later sweep removes it).
fn young(path: &Path, now_ms: i64) -> bool {
    let modified_ms = std::fs::metadata(path).and_then(|meta| meta.modified()).ok()
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|at| at.as_millis() as i64);
    modified_ms.is_none_or(|at| now_ms.saturating_sub(at) < IMPORT_STAGING_MAX_AGE_MS)
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

    /// NAN-4554 review P1/P3: a release tombstone refuses a re-import and
    /// lasts the TTL; a bounded restore's low-water mark refuses older
    /// entries; an import still staging is not swept.
    #[test]
    fn released_ids_and_entries_beyond_the_restore_bound_are_never_imported() {
        let root = tempfile::tempdir().unwrap();
        let source = Quarantine::open(&root.path().join("old"), TENANT).unwrap();
        let (file, id) = object(root.path(), b"replayed bytes");
        source.keep(&file, &id, &refusal(), 1_000).unwrap();
        let entry = source.get(&id).unwrap().unwrap();
        let quarantine = Quarantine::open(&root.path().join("new"), TENANT).unwrap();
        let stage = |name: &str| {
            let path = quarantine.staging_path(name);
            std::fs::write(&path, b"replayed bytes").unwrap();
            path
        };
        let refused = |result: Result<Imported>| result.unwrap_err().downcast::<ImportRefused>().unwrap();
        assert_eq!(refused(quarantine.import(&entry, &stage("import-a"), 2_000)), ImportRefused::RestorePending);
        quarantine.mark_restored(None).unwrap();
        assert_eq!(quarantine.import(&entry, &stage("import-b"), 2_000).unwrap(), Imported::New);
        quarantine.release(&id, 3_000).unwrap();
        assert_eq!(quarantine.released_at(&id).unwrap(), Some(3_000));
        assert_eq!(refused(quarantine.import(&entry, &stage("import-c"), 4_000)), ImportRefused::Released);
        quarantine.sweep(3_000 + QUARANTINE_TTL_MS - 1).unwrap();
        assert!(quarantine.released_at(&id).unwrap().is_some(), "kept for the TTL");
        quarantine.sweep(3_000 + QUARANTINE_TTL_MS).unwrap();
        assert!(quarantine.released_at(&id).unwrap().is_none(), "then swept");

        // A bounded restore whose oldest read record is no older than the
        // entry (less the skew): its release may be unread, so it is refused.
        let bounded = Quarantine::open(&root.path().join("bounded"), TENANT).unwrap();
        bounded.mark_restored(Some(entry.quarantined_at_ms)).unwrap();
        let path = bounded.staging_path("import-d");
        std::fs::write(&path, b"replayed bytes").unwrap();
        assert_eq!(refused(bounded.import(&entry, &path, 4_000)), ImportRefused::BeyondRestoreBound);

        // A young import staging file survives a sweep; other dot-files do not.
        let staging = quarantine.staging_path("import-live");
        let stray = quarantine.staging_path("stray");
        std::fs::write(&staging, b"x").unwrap();
        std::fs::write(&stray, b"x").unwrap();
        let wall = chrono::Utc::now().timestamp_millis();
        quarantine.sweep(wall).unwrap();
        assert!(staging.exists() && !stray.exists());
        quarantine.sweep(wall + IMPORT_STAGING_MAX_AGE_MS + 1_000).unwrap();
        assert!(!staging.exists(), "an abandoned import staging file is swept once old");
    }
}
