// SPDX-License-Identifier: AGPL-3.0-or-later

//! SlateDB's physical mutation boundary. The owner endpoint owns the PG
//! reservation, conditional S3 mutation, trusted HEAD, and completion. Ingest
//! holds only a tenant-scoped read credential; no object-store mutation can
//! fall through to that credential.

use std::os::unix::{
    ffi::OsStrExt,
    fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
};
use std::{fmt, path::Path as FilePath, sync::Arc};

use base64::Engine;
use futures::{stream::BoxStream, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slatedb::object_store::{
    path::Path, CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
    ObjectStore, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult,
    Result as StoreResult,
};

use super::s3_store::S3Location;

const STORE: &str = "prevalence-owner";
const OWNER_CA_RECHECK: std::time::Duration = std::time::Duration::from_secs(60);

/// NAN-4445: how long an ingest create of a numbered WAL key keeps retrying
/// an owner 409 on an absent object in place. 9015130 lets a fresh ingest
/// request take over a WAL create reservation abandoned for five minutes (an
/// owner roll interrupted it and the old process's request id was lost with
/// its ephemeral journal). Six minutes covers that window from a reservation
/// made just before this process started, so one open heals instead of
/// failing and waiting out the ingest's open backoff (up to 10 min). Past it
/// the open fails as before and the backoff schedules the next one.
const INGEST_WAL_CONFLICT_RETRY: std::time::Duration = std::time::Duration::from_secs(6 * 60);
/// NAN-4445: the longest pause between those ingest retries (about 30 owner
/// calls per open instead of 70).
const INGEST_WAL_CONFLICT_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(15);

/// What an owner 409 on a still-absent object does for this writer class and
/// key family. A 409 means another request holds the key's reservation
/// (`authorize_object_state`) or a replay mismatched; it is never proof that
/// the conditional create landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbsentConflict {
    /// Return the error: the caller (SlateDB, the open) decides.
    Fail,
    /// NAN-3956: the standalone compactor retries in place until the 9013910
    /// takeover or the holder completes. Bounded by the compactor's own
    /// cancellation; returning would stop SlateDB's compactor.
    RetryUntilCancelled,
    /// NAN-4445: ingest WAL creates retry for at most this long (9015130).
    RetryFor(std::time::Duration),
}

fn absent_conflict(writer_class: WriterClass, key_family: &str) -> AbsentConflict {
    match (writer_class, key_family) {
        (WriterClass::Maintenance, _) => AbsentConflict::RetryUntilCancelled,
        // Only wal/ is a numbered family the ingest class creates alone.
        // manifest/ is SlateDB's writer/compactor fence (no takeover exists)
        // and compacted/ keys are fresh ULIDs per attempt.
        (WriterClass::Ingest, "wal") => AbsentConflict::RetryFor(INGEST_WAL_CONFLICT_RETRY),
        (WriterClass::Ingest, _) => AbsentConflict::Fail,
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerAccess {
    pub url: String,
    pub bearer: String,
    pub tenant_id: String,
    pub assignment_generation: i64,
    pub writer_epoch: i64,
    /// The bearer's expiry (RFC 3339), when the exchange states it. Absent:
    /// re-exchanged on the conservative schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl fmt::Debug for OwnerAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerAccess")
            .field("url", &self.url)
            .field("tenant_id", &self.tenant_id)
            .field("assignment_generation", &self.assignment_generation)
            .field("writer_epoch", &self.writer_epoch)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct PrevalenceAccess {
    pub read: S3Location,
    pub owner: OwnerAccess,
    /// The owner's private server CA (`part_signing.ca_file`: the same owner
    /// endpoint as part signing). Required for an https owner URL.
    pub owner_ca_file: Option<std::path::PathBuf>,
}

/// Supplied only to the standalone maintenance process. The ingest exchange
/// cannot deserialize this type or select its writer class.
pub struct MaintenanceAccess {
    pub read: S3Location,
    pub owner: OwnerAccess,
    /// The owner's private server CA; required for an https owner URL.
    pub owner_ca_file: Option<std::path::PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriterClass {
    Ingest,
    Maintenance,
}

impl WriterClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
            Self::Maintenance => "maintenance",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingMutation {
    request_id: uuid::Uuid,
    tenant_id: String,
    object_bucket: String,
    assignment_generation: i64,
    writer_epoch: i64,
    writer_class: String,
    operation: String,
    object_key: String,
    content_length: u64,
    content_sha256: String,
    expected_etag: Option<String>,
}

#[derive(Serialize)]
struct MutationRequest<'a> {
    schema_version: u8,
    request_id: uuid::Uuid,
    tenant_id: &'a str,
    assignment_generation: i64,
    writer_epoch: i64,
    writer_class: &'static str,
    object_bucket: &'a str,
    object_key: &'a str,
    key_family: &'static str,
    operation: &'static str,
    content_length: u64,
    content_sha256: &'a str,
    expected_etag: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationResponse {
    schema_version: u8,
    request_id: uuid::Uuid,
    tenant_id: String,
    assignment_generation: i64,
    writer_epoch: i64,
    writer_class: String,
    object_bucket: String,
    object_key: String,
    key_family: String,
    operation: String,
    content_length: u64,
    content_sha256: String,
    expected_etag: Option<String>,
    result_etag: String,
    result_version: Option<String>,
    completed: bool,
    head_verified: bool,
}

fn error(message: impl Into<String>) -> slatedb::object_store::Error {
    let message = message.into();
    slatedb::object_store::Error::Generic {
        store: STORE,
        source: std::io::Error::other(message).into(),
    }
}

fn family(suffix: &str) -> Option<(&'static str, u64)> {
    let (dir, name) = suffix.split_once('/')?;
    match dir {
        "wal" if name.len() == 24 && name.ends_with(".sst")
            && name[..20].bytes().all(|c| c.is_ascii_digit()) => Some(("wal", 134_217_728)),
        "manifest" if name.len() == 29 && name.ends_with(".manifest")
            && name[..20].bytes().all(|c| c.is_ascii_digit()) => Some(("manifest", 8_388_608)),
        "compactions" if name.len() == 32 && name.ends_with(".compactions")
            && name[..20].bytes().all(|c| c.is_ascii_digit()) => Some(("compactions", 8_388_608)),
        "compacted" if name.len() == 30 && name.ends_with(".sst")
            && name[..26].bytes().all(|c| matches!(c, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')) => Some(("compacted", 536_870_912)),
        "gc" if matches!(name, "manifest.boundary" | "compactions.boundary") => Some(("gc_boundary", 20)),
        _ => None,
    }
}

fn publish_pending(
    path: &FilePath,
    pending: &PendingMutation,
    fault: Option<&str>,
) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing journal directory"))?;
    let temp = dir.join(format!(".pending-{}", uuid::Uuid::now_v7()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        if fault == Some("create") {
            return Err(std::io::Error::other("injected create fault"));
        }
        serde_json::to_writer(&mut file, pending).map_err(std::io::Error::other)?;
        if fault == Some("write") {
            return Err(std::io::Error::other("injected write fault"));
        }
        file.sync_all()?;
        if fault == Some("sync") {
            return Err(std::io::Error::other("injected sync fault"));
        }
        let from =
            std::ffi::CString::new(temp.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
        let to =
            std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(std::io::Error::other)?;
        // Atomic publication without replacing another writer's pending ID.
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if fault == Some("rename") {
            return Err(std::io::Error::other("injected rename fault"));
        }
        Ok(())
    })();
    if temp.exists() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

// A published name is not proof of durable publication: rename can succeed
// before the parent directory sync fails. This must run for both new records
// and identical retries, immediately before any owner request is sent.
fn sync_pending_before_post(path: &FilePath, fault: Option<&str>) -> std::io::Result<()> {
    let file = std::fs::File::open(path)?;
    if fault == Some("journal_file_sync") {
        return Err(std::io::Error::other("injected journal file sync fault"));
    }
    file.sync_all()?;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("missing journal directory"))?;
    let directory = std::fs::File::open(dir)?;
    if fault == Some("journal_dir_sync") {
        return Err(std::io::Error::other(
            "injected journal directory sync fault",
        ));
    }
    directory.sync_all()
}

pub struct OwnerStore {
    /// The read side, swappable in place with the bearer
    /// ([`Self::refresh_in_place`], NAN-3849).
    reads: std::sync::RwLock<Arc<dyn ObjectStore>>,
    access: OwnerAccess,
    bucket: String,
    prefix: String,
    journal: std::path::PathBuf,
    tls: super::owner_tls::OwnerTlsClient,
    mutation_lock: tokio::sync::Mutex<()>,
    writer_class: WriterClass,
    /// The owner bearer, swappable in place ([`Self::set_bearer`]): a
    /// long-running compactor keeps its store across credential refreshes.
    bearer: std::sync::RwLock<String>,
    /// [`INGEST_WAL_CONFLICT_RETRY`]; shortened only by tests.
    ingest_wal_conflict_retry: std::time::Duration,
}

impl fmt::Debug for OwnerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnerStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}
impl fmt::Display for OwnerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prevalence-owner")
    }
}

impl OwnerStore {
    pub fn new(
        reads: Arc<dyn ObjectStore>,
        access: PrevalenceAccess,
        journal: &FilePath,
    ) -> anyhow::Result<Self> {
        Self::new_for_class(
            reads,
            access.read,
            access.owner,
            access.owner_ca_file.as_deref(),
            journal,
            WriterClass::Ingest,
        )
    }

    pub fn new_maintenance(
        reads: Arc<dyn ObjectStore>,
        access: MaintenanceAccess,
        journal: &FilePath,
    ) -> anyhow::Result<Self> {
        Self::new_for_class(
            reads,
            access.read,
            access.owner,
            access.owner_ca_file.as_deref(),
            journal,
            WriterClass::Maintenance,
        )
    }

    fn new_for_class(
        reads: Arc<dyn ObjectStore>,
        read: S3Location,
        owner: OwnerAccess,
        owner_ca_file: Option<&FilePath>,
        journal: &FilePath,
        writer_class: WriterClass,
    ) -> anyhow::Result<Self> {
        let tenant = uuid::Uuid::parse_str(&owner.tenant_id)?;
        anyhow::ensure!(
            tenant.to_string() == owner.tenant_id,
            "owner tenant must be a canonical UUID"
        );
        anyhow::ensure!(
            read.prefix == format!("lake/prevalence-state/v1/tenant={tenant}/"),
            "read prefix differs from owner tenant"
        );
        anyhow::ensure!(
            owner.url.starts_with("https://") || cfg!(test),
            "owner endpoint must use HTTPS"
        );
        anyhow::ensure!(
            owner.assignment_generation > 0 && owner.writer_epoch > 0 && !owner.bearer.is_empty(),
            "owner assignment or bearer missing"
        );
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(journal)?;
        // A directory this process owns but created with a looser mode (an
        // earlier create_dir_all under the umask) is tightened, not fatal:
        // only a journal someone else controls is refused.
        let meta = std::fs::metadata(journal)?;
        if meta.permissions().mode() & 0o077 != 0
            && std::os::unix::fs::MetadataExt::uid(&meta) == unsafe { libc::geteuid() }
        {
            std::fs::set_permissions(journal, std::fs::Permissions::from_mode(0o700))?;
        }
        anyhow::ensure!(
            std::fs::metadata(journal)?.permissions().mode() & 0o077 == 0,
            "owner request journal must be private"
        );
        // Private owner CA only, never system roots, hostname verified.
        let tls = super::owner_tls::OwnerTlsClient::new(
            &owner.url,
            owner_ca_file,
            std::time::Duration::from_secs(match writer_class {
                WriterClass::Ingest => 30,
                WriterClass::Maintenance => 300,
            }),
        )?;
        Ok(Self {
            reads: std::sync::RwLock::new(reads),
            bearer: std::sync::RwLock::new(owner.bearer.clone()),
            access: owner,
            bucket: read.bucket,
            prefix: read.prefix,
            journal: journal.to_path_buf(),
            tls,
            mutation_lock: tokio::sync::Mutex::new(()),
            writer_class,
            ingest_wal_conflict_retry: INGEST_WAL_CONFLICT_RETRY,
        })
    }

    fn bearer(&self) -> String {
        self.bearer.read().expect("bearer lock").clone()
    }

    fn reads(&self) -> Arc<dyn ObjectStore> {
        self.reads.read().expect("reads lock").clone()
    }

    /// NAN-3849: a refreshed grant for the same tenant, generation, epoch,
    /// owner and bucket/prefix swaps the bearer and the read side in place,
    /// so the state on top of this store stays open (its block, index and
    /// filter caches stay warm and nothing in flight is aborted). Requests
    /// already running finish on the previous credential, which is still
    /// valid; every later one uses the new one. Anything else refuses and
    /// the caller reopens as before.
    pub fn refresh_in_place(&self, read: &S3Location, owner: &OwnerAccess, reads: Arc<dyn ObjectStore>) -> anyhow::Result<()> {
        anyhow::ensure!(read.bucket == self.bucket && read.prefix == self.prefix,
            "refreshed read grant is bound to another bucket or prefix");
        self.set_bearer(owner)?;
        *self.reads.write().expect("reads lock") = reads;
        Ok(())
    }

    /// Swap in a refreshed owner bearer for the same tenant, generation,
    /// epoch and writer class (a changed generation or epoch needs a new
    /// store: its pending records are bound to the old one).
    pub fn set_bearer(&self, owner: &OwnerAccess) -> anyhow::Result<()> {
        anyhow::ensure!(owner.tenant_id == self.access.tenant_id
            && owner.assignment_generation == self.access.assignment_generation
            && owner.writer_epoch == self.access.writer_epoch
            && owner.url == self.access.url,
            "refreshed owner grant is bound to another tenant, generation, epoch or owner");
        *self.bearer.write().expect("bearer lock") = owner.bearer.clone();
        Ok(())
    }

    fn journal_path(&self, key: &str) -> std::path::PathBuf {
        self.journal
            .join(hex::encode(Sha256::digest(key.as_bytes())))
    }

    async fn mutate(
        &self,
        path: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> StoreResult<PutResult> {
        self.mutate_inner(path, payload, opts, None).await
    }

    async fn mutate_inner(
        &self,
        path: &Path,
        payload: PutPayload,
        opts: PutOptions,
        publication_fault: Option<&str>,
    ) -> StoreResult<PutResult> {
        let _guard = self.mutation_lock.lock().await;
        let key = format!("{}{}", self.prefix, path);
        let suffix = path
            .as_ref()
            .strip_prefix("db/")
            .ok_or_else(|| error("SlateDB path must start with db/"))?;
        let (key_family, max_bytes) = family(suffix).ok_or_else(|| {
            error(format!(
                "SlateDB object key is outside authorized families: {path}"
            ))
        })?;
        let (operation, expected_etag) = match opts.mode {
            PutMode::Create => ("create", None),
            PutMode::Update(version) if key_family == "gc_boundary" => (
                "update",
                Some(version.e_tag.ok_or_else(|| error("CAS needs ETag"))?),
            ),
            other => {
                return Err(error(format!(
                    "SlateDB mutation requires supported conditional mode: {path} {other:?}"
                )))
            }
        };
        let allowed = match self.writer_class {
            WriterClass::Ingest => matches!(key_family, "wal" | "manifest" | "compacted"),
            WriterClass::Maintenance => {
                matches!(key_family, "manifest" | "compacted" | "compactions")
            }
        };
        if !allowed || operation != "create" {
            return Err(error(
                "writer class cannot mutate this object family or operation",
            ));
        }
        if !opts.attributes.is_empty() || !opts.tags.is_empty() {
            // SlateDB's retrying store adds an optional ULID attribute to
            // conditional PUTs and retries without it on NotSupported.
            // The owner wire deliberately has no unbound metadata channel.
            return Err(slatedb::object_store::Error::NotSupported {
                source: std::io::Error::other("owner mutation does not accept object metadata")
                    .into(),
            });
        }
        let length = payload.content_length() as u64;
        if (length == 0 && key_family != "wal")
            || length > max_bytes
            || (self.writer_class == WriterClass::Ingest
                && key_family == "compacted"
                && length > 67_108_864)
        {
            return Err(error("SlateDB object size exceeds owner bound"));
        }
        let mut hasher = Sha256::new();
        for part in &payload {
            hasher.update(part);
        }
        let sha = hex::encode(hasher.finalize());
        let journal_path = self.journal_path(&key);
        // A stale local pending record (SlateDB now writes this key with
        // other bytes, or under a newer generation/epoch) must not wedge the
        // key. The owner's reconcile is NEVER used for this: 9007100
        // `prevalence_state_reconcile` quarantines the key, and authorize
        // then refuses every later create of it, which permanently kills a
        // numbered key (wal/manifest/compactions) SlateDB must still write.
        // Instead, by the key's own state (trusted read-only HEAD):
        // - present: the earlier create landed; answer AlreadyExists so
        //   SlateDB's sequenced protocol refreshes and advances;
        // - absent: nothing landed; drop the record and create afresh. If
        //   the owner still holds a pending row for the old request it
        //   refuses, except for abandoned maintenance compactions creates
        //   (9013910) and ingest WAL creates (9015130) idle for five
        //   minutes, which the retry below waits out. No key is quarantined. If the owner never
        //   authorized it (cell30: it crashed first), the create succeeds.
        if journal_path.exists() {
            let bytes = std::fs::read(&journal_path).map_err(|e| error(e.to_string()))?;
            let saved: PendingMutation =
                serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
            let same_request = saved.tenant_id == self.access.tenant_id
                && saved.object_bucket == self.bucket
                && saved.assignment_generation == self.access.assignment_generation
                && saved.writer_epoch == self.access.writer_epoch
                && saved.writer_class == self.writer_class.as_str()
                && saved.operation == operation
                && saved.object_key == key
                && saved.content_length == length
                && saved.content_sha256 == sha
                && saved.expected_etag == expected_etag;
            if !same_request {
                match slatedb::object_store::ObjectStoreExt::head(&self.reads(), path).await {
                    Ok(_) => {
                        return Err(slatedb::object_store::Error::AlreadyExists {
                            path: path.to_string(),
                            source: std::io::Error::other("an earlier owner create of this key landed").into(),
                        });
                    }
                    Err(slatedb::object_store::Error::NotFound { .. }) => {
                        tracing::warn!(key = %key, stale_request = %saved.request_id,
                            "stale local owner request for an absent key dropped; creating afresh");
                        let _ = std::fs::remove_file(&journal_path);
                        let _ = std::fs::File::open(&self.journal).and_then(|dir| dir.sync_all());
                    }
                    Err(other) => return Err(other),
                }
            }
        }
        let pending = if journal_path.exists() {
            let bytes = std::fs::read(&journal_path).map_err(|e| error(e.to_string()))?;
            let saved: PendingMutation =
                serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
            if saved.tenant_id != self.access.tenant_id
                || saved.object_bucket != self.bucket
                || saved.assignment_generation != self.access.assignment_generation
                || saved.writer_epoch != self.access.writer_epoch
                || saved.writer_class != self.writer_class.as_str()
                || saved.operation != operation
                || saved.object_key != key
                || saved.content_length != length
                || saved.content_sha256 != sha
                || saved.expected_etag != expected_etag
            {
                return Err(error(
                    "pending owner request differs; reconciliation required",
                ));
            }
            saved
        } else {
            let pending = PendingMutation {
                request_id: uuid::Uuid::now_v7(),
                tenant_id: self.access.tenant_id.clone(),
                object_bucket: self.bucket.clone(),
                assignment_generation: self.access.assignment_generation,
                writer_epoch: self.access.writer_epoch,
                writer_class: self.writer_class.as_str().into(),
                operation: operation.into(),
                object_key: key.clone(),
                content_length: length,
                content_sha256: sha.clone(),
                expected_etag: expected_etag.clone(),
            };
            publish_pending(&journal_path, &pending, publication_fault)
                .map_err(|e| error(e.to_string()))?;
            pending
        };
        sync_pending_before_post(&journal_path, publication_fault)
            .map_err(|e| error(e.to_string()))?;
        let request = MutationRequest {
            schema_version: 1,
            request_id: pending.request_id,
            tenant_id: &self.access.tenant_id,
            assignment_generation: self.access.assignment_generation,
            writer_epoch: self.access.writer_epoch,
            writer_class: self.writer_class.as_str(),
            object_bucket: &self.bucket,
            object_key: &key,
            key_family,
            operation,
            content_length: length,
            content_sha256: &sha,
            expected_etag: expected_etag.as_deref(),
        };
        let envelope = serde_json::to_vec(&request).map_err(|e| error(e.to_string()))?;
        let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(envelope);
        // Keep the request ID and bytes fixed while an owner reservation is
        // contested. A 409 is not proof that the conditional create landed.
        // In particular, never invent AlreadyExists for an absent numbered
        // compactions file: SlateDB would refresh the same version forever.
        let retry = match absent_conflict(self.writer_class, key_family) {
            AbsentConflict::RetryFor(_) => AbsentConflict::RetryFor(self.ingest_wal_conflict_retry),
            other => other,
        };
        let backoff_max = match retry {
            AbsentConflict::RetryFor(_) => INGEST_WAL_CONFLICT_BACKOFF_MAX,
            _ => std::time::Duration::from_secs(5),
        };
        let started = std::time::Instant::now();
        let mut conflict_backoff = std::time::Duration::from_millis(100);
        let response = loop {
            let body = reqwest::Body::wrap_stream(futures::stream::iter(
                payload.clone().into_iter().map(Ok::<_, std::io::Error>),
            ));
            self.tls.reload_ca_if_due(OWNER_CA_RECHECK, "prevalence owner");
            let response = self
                .tls
                .client()
                .post(&self.access.url)
                .bearer_auth(self.bearer())
                .header("x-nano-owner-request", &envelope)
                .header("content-type", "application/octet-stream")
                .header(reqwest::header::CONTENT_LENGTH, length)
                .body(body)
                .send()
                .await
                .map_err(|e| error(e.to_string()))?;
            if response.status() != reqwest::StatusCode::CONFLICT {
                break response;
            }
            match retry {
                AbsentConflict::Fail => break response,
                AbsentConflict::RetryFor(budget) if started.elapsed() + conflict_backoff > budget => {
                    tracing::warn!(key_family, waited_secs = started.elapsed().as_secs(),
                        "prevalence owner conflict on this key outlasted the in-place retry; failing the write");
                    break response;
                }
                AbsentConflict::RetryFor(_) | AbsentConflict::RetryUntilCancelled => {}
            }
            drop(response);
            match slatedb::object_store::ObjectStoreExt::head(&self.reads(), path).await {
                Ok(_) => {
                    // Another conditional writer won. Let SlateDB re-read
                    // its sequenced state and converge (or fence this writer).
                    return Err(slatedb::object_store::Error::AlreadyExists {
                        path: path.to_string(),
                        source: std::io::Error::other("owner conflict: object now exists").into(),
                    });
                }
                Err(slatedb::object_store::Error::NotFound { .. }) => {}
                Err(other) => return Err(other),
            }
            // The owner's conditional-create reservation recovery allows a
            // fresh current request to replace an abandoned maintenance
            // compactions (9013910) or ingest WAL (9015130) reservation.
            // Retry in place while it ages past five minutes or another
            // request is still completing. This future remains cancellable;
            // the role's credential refresh runs beside it and can refresh
            // the bearer without reopening the state.
            tracing::warn!(key_family, backoff_ms = conflict_backoff.as_millis() as u64,
                "prevalence owner conflict on absent object; re-reading and retrying");
            tokio::time::sleep(conflict_backoff).await;
            conflict_backoff = (conflict_backoff * 2).min(backoff_max);
        };
        if response.status() != reqwest::StatusCode::OK {
            if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
                // SlateDB's numbered manifest/compactions protocol must see
                // a sequenced create conflict so it can refresh and advance.
                // The pending record stays for owner reconciliation; no
                // completion is acknowledged here.
                return Err(slatedb::object_store::Error::AlreadyExists {
                    path: path.to_string(),
                    source: std::io::Error::other("owner conditional create conflict").into(),
                });
            }
            if matches!(response.status().as_u16(), 400 | 401 | 403) {
                // A definite refusal: the owner answers these before any PG
                // pending row or S3 call exists (authorize's refusals all
                // return before it records the request). Keeping the local
                // record would wedge the key once SlateDB retries it with
                // different bytes after the owner recovers.
                let _ = std::fs::remove_file(&journal_path);
                let _ = std::fs::File::open(&self.journal).and_then(|dir| dir.sync_all());
            }
            return Err(error(format!(
                "owner mutation status {}",
                response.status()
            )));
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| error(e.to_string()))? {
            if chunk.len() > 4096 - body.len() {
                return Err(error("owner response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let result: MutationResponse =
            serde_json::from_slice(&body).map_err(|e| error(e.to_string()))?;
        if result.schema_version != 1
            || result.request_id != pending.request_id
            || result.tenant_id != self.access.tenant_id
            || result.assignment_generation != self.access.assignment_generation
            || result.writer_epoch != self.access.writer_epoch
            || result.writer_class != self.writer_class.as_str()
            || result.object_bucket != self.bucket
            || result.object_key != key
            || result.key_family != key_family
            || result.operation != operation
            || result.content_length != length
            || result.content_sha256 != sha
            || result.expected_etag != expected_etag
            || !result.completed
            || !result.head_verified
            || result.result_etag.is_empty()
            || result.result_etag.len() > 512
        {
            return Err(error("owner completion binding or trusted HEAD differs"));
        }
        std::fs::remove_file(&journal_path).map_err(|e| error(e.to_string()))?;
        std::fs::File::open(&self.journal)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| error(e.to_string()))?;
        Ok(PutResult {
            e_tag: Some(result.result_etag),
            version: result.result_version,
            extensions: Default::default(),
        })
    }
}

#[async_trait::async_trait]
impl ObjectStore for OwnerStore {
    async fn put_opts(
        &self,
        path: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> StoreResult<PutResult> {
        self.mutate(path, payload, opts).await
    }
    async fn put_multipart_opts(
        &self,
        _: &Path,
        _: PutMultipartOptions,
    ) -> StoreResult<Box<dyn MultipartUpload>> {
        Err(error("multipart write has no owner protocol"))
    }
    async fn get_opts(&self, path: &Path, options: GetOptions) -> StoreResult<GetResult> {
        self.reads().get_opts(path, options).await
    }
    fn delete_stream(
        &self,
        locations: BoxStream<'static, StoreResult<Path>>,
    ) -> BoxStream<'static, StoreResult<Path>> {
        locations
            .map(|_| {
                Err(error(
                    "ingest GC delete lacks verified reachability authority",
                ))
            })
            .boxed()
    }
    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, StoreResult<ObjectMeta>> {
        self.reads().list(prefix)
    }
    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> StoreResult<ListResult> {
        self.reads().list_with_delimiter(prefix).await
    }
    async fn copy_opts(&self, _: &Path, _: &Path, _: CopyOptions) -> StoreResult<()> {
        Err(error("copy has no owner protocol"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use slatedb::object_store::{memory::InMemory, ObjectStoreExt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TENANT: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

    #[derive(Clone)]
    struct Fixture {
        objects: Arc<InMemory>,
        writes: Arc<AtomicUsize>,
        maintenance_ssts: Arc<AtomicUsize>,
        failure: Arc<AtomicUsize>,
        requests: Arc<std::sync::Mutex<Vec<uuid::Uuid>>>,
        pg: Option<(sqlx::PgPool, sqlx::PgPool)>,
        /// NAN-3849: owner writes made with the refreshed bearer.
        rotated_writes: Arc<AtomicUsize>,
    }


    async fn owner(
        State(state): State<Fixture>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<axum::Json<serde_json::Value>, StatusCode> {
        let writer_class = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
            Some("Bearer owner-token") => "ingest",
            Some("Bearer owner-token-2") => {
                state.rotated_writes.fetch_add(1, Ordering::SeqCst);
                "ingest"
            }
            Some("Bearer maintenance-token") => "maintenance",
            _ => return Err(StatusCode::UNAUTHORIZED),
        };
        let encoded = headers
            .get("x-nano-owner-request")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        let envelope = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let mut request: serde_json::Value =
            serde_json::from_slice(&envelope).map_err(|_| StatusCode::BAD_REQUEST)?;
        let key = request["object_key"]
            .as_str()
            .ok_or(StatusCode::BAD_REQUEST)?;
        let key_prefix = format!("lake/prevalence-state/v1/tenant={TENANT}/");
        if request["tenant_id"] != TENANT
            || request["assignment_generation"] != 2
            || request["writer_epoch"] != 3
            || request["writer_class"] != writer_class
            || request["object_bucket"] != "bucket"
            || !key.starts_with(&key_prefix)
            || request["operation"] != "create"
            || request["expected_etag"] != serde_json::Value::Null
            || request["content_length"] != body.len()
            || request["content_sha256"] != hex::encode(Sha256::digest(&body))
        {
            return Err(StatusCode::FORBIDDEN);
        }
        let relative = &key[key_prefix.len()..];
        let (fam, max) = family(relative.strip_prefix("db/").ok_or(StatusCode::FORBIDDEN)?)
            .ok_or(StatusCode::FORBIDDEN)?;
        if request["key_family"] != fam
            || !(match writer_class {
                "ingest" => matches!(fam, "wal" | "manifest" | "compacted"),
                _ => matches!(fam, "manifest" | "compacted" | "compactions"),
            })
            || (body.is_empty() && fam != "wal")
            || body.len() as u64 > max
            || (writer_class == "ingest" && fam == "compacted" && body.len() > 67_108_864)
        {
            return Err(StatusCode::FORBIDDEN);
        }
        let path = Path::from(relative);
        state.requests.lock().unwrap().push(
            uuid::Uuid::parse_str(
                request["request_id"]
                    .as_str()
                    .ok_or(StatusCode::BAD_REQUEST)?,
            )
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        );
        if state.failure.load(Ordering::SeqCst) == 1 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        if state.failure.load(Ordering::SeqCst) == 4 {
            return Err(StatusCode::CONFLICT);
        }
        if state.failure.load(Ordering::SeqCst) == 3 {
            // The owner's authorize refusal (e.g. authorize_stale_epoch).
            return Err(StatusCode::FORBIDDEN);
        }
        let request_id = uuid::Uuid::parse_str(request["request_id"].as_str().unwrap())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let pool = state.pg.as_ref().map(|(ingest, maintenance)| {
            if writer_class == "ingest" {
                ingest
            } else {
                maintenance
            }
        });
        if let Some(pool) = pool {
            let permit: serde_json::Value = sqlx::query_scalar(
                "SELECT nano_shared.prevalence_state_authorize($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(uuid::Uuid::parse_str(TENANT).unwrap())
            .bind(2_i64)
            .bind(3_i64)
            .bind(writer_class)
            .bind("create")
            .bind(key)
            .bind(body.len() as i64)
            .bind(Option::<String>::None)
            .bind(request_id)
            .fetch_one(pool)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if permit["ok"] != true {
                if permit["reason"] == "object_state" {
                    return Err(if state.objects.head(&path).await.is_ok() {
                        StatusCode::PRECONDITION_FAILED
                    } else {
                        StatusCode::CONFLICT
                    });
                }
                return Err(StatusCode::FORBIDDEN);
            }
        }
        let result = state
            .objects
            .put_opts(&path, body.to_vec().into(), PutMode::Create.into())
            .await
            .map_err(|_| StatusCode::PRECONDITION_FAILED)?;
        state.writes.fetch_add(1, Ordering::SeqCst);
        if writer_class == "maintenance" && fam == "compacted" {
            state.maintenance_ssts.fetch_add(1, Ordering::SeqCst);
        }
        if state.failure.load(Ordering::SeqCst) == 2 {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let head = state
            .objects
            .head(&path)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if head.size != body.len() as u64 || head.e_tag.is_none() || head.e_tag != result.e_tag {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        let verified_etag = head.e_tag.unwrap();
        if let Some(pool) = pool {
            let complete: serde_json::Value = sqlx::query_scalar(
                "SELECT nano_shared.prevalence_state_complete($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(uuid::Uuid::parse_str(TENANT).unwrap())
            .bind(2_i64)
            .bind(3_i64)
            .bind(key)
            .bind(request_id)
            .bind(&verified_etag)
            .bind(body.len() as i64)
            .bind(false)
            .fetch_one(pool)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            if complete["ok"] != true {
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
        }
        request["result_etag"] = serde_json::json!(verified_etag);
        request["result_version"] = serde_json::json!(result.version);
        request["completed"] = serde_json::json!(true);
        request["head_verified"] = serde_json::json!(true);
        Ok(axum::Json(request))
    }

    async fn setup(
        failure: usize,
    ) -> (Arc<InMemory>, PrevalenceAccess, Fixture, tempfile::TempDir) {
        let objects = Arc::new(InMemory::new());
        let pg = match (
            std::env::var("NAN2915_PG_INGEST_URL"),
            std::env::var("NAN2915_PG_MAINT_URL"),
        ) {
            (Ok(ingest), Ok(maintenance)) => Some((
                sqlx::PgPool::connect(&ingest).await.unwrap(),
                sqlx::PgPool::connect(&maintenance).await.unwrap(),
            )),
            _ => None,
        };
        let fixture = Fixture {
            objects: objects.clone(),
            writes: Arc::new(AtomicUsize::new(0)),
            maintenance_ssts: Arc::new(AtomicUsize::new(0)),
            failure: Arc::new(AtomicUsize::new(failure)),
            requests: Arc::new(std::sync::Mutex::new(Vec::new())),
            pg,
            rotated_writes: Arc::new(AtomicUsize::new(0)),
        };
        let app = Router::new()
            .route("/mutate", post(owner))
            // Compacted SSTs are MiBs; the owner accepts up to its family caps.
            .layer(axum::extract::DefaultBodyLimit::disable())
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let access = PrevalenceAccess {
            read: S3Location {
                endpoint: "http://127.0.0.1".into(),
                region: "auto".into(),
                bucket: "bucket".into(),
                prefix: format!("lake/prevalence-state/v1/tenant={TENANT}/"),
                access_key_id: "read".into(),
                secret_access_key: "read".into(),
                session_token: None,
            },
            owner: OwnerAccess {
                url: format!("http://{address}/mutate"),
                bearer: "owner-token".into(),
                tenant_id: TENANT.into(),
                assignment_generation: 2,
                writer_epoch: 3,
                expires_at: None,
            },
            owner_ca_file: None,
        };
        let tmp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        (objects, access, fixture, tmp)
    }

    #[tokio::test]
    async fn direct_prefix_store_bypassed_owner_but_owner_store_routes_create() {
        let (objects, access, fixture, tmp) = setup(0).await;
        // Regression witness: the former PrefixStore could PUT with no owner.
        let direct = slatedb::object_store::prefix::PrefixStore::new(
            objects.clone(),
            access.read.prefix.as_str(),
        );
        direct
            .put(
                &Path::from("db/wal/00000000000000000001.sst"),
                b"old bypass".to_vec().into(),
            )
            .await
            .unwrap();
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
        let store = OwnerStore::new(objects.clone(), access, tmp.path()).unwrap();
        let result = store
            .put_opts(
                &Path::from("db/wal/00000000000000000002.sst"),
                b"through owner".to_vec().into(),
                PutMode::Create.into(),
            )
            .await
            .unwrap();
        assert!(result.e_tag.is_some());
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        assert!(store
            .put_opts(
                &Path::from("db/wal/00000000000000000003.sst"),
                b"blind".to_vec().into(),
                PutMode::Overwrite.into()
            )
            .await
            .is_err());
        assert!(store
            .put_opts(
                &Path::from("db/compactions/00000000000000000001.compactions"),
                b"wrong class".to_vec().into(),
                PutMode::Create.into()
            )
            .await
            .is_err());
        assert!(store
            .delete(&Path::from("db/wal/00000000000000000002.sst"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn maintenance_owner_conflict_rereads_and_retries_without_stopping() {
        let (objects, access, fixture, tmp) = setup(4).await;
        let mut owner = access.owner;
        owner.bearer = "maintenance-token".into();
        let store = OwnerStore::new_maintenance(objects.clone(), MaintenanceAccess {
            read: access.read, owner, owner_ca_file: None,
        }, tmp.path()).unwrap();
        let path = Path::from("db/compactions/00000000000000000001.compactions");
        let write = store.put_opts(&path, b"new state".to_vec().into(), PutMode::Create.into());
        tokio::pin!(write);
        // Repeated 409 + absent HEAD must stay in this call, preserving the
        // journal/request ID, instead of stopping SlateDB's compactor.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::select! {
                result = &mut write => panic!("contested write returned before owner recovery: {result:?}"),
                _ = async {
                    while fixture.requests.lock().unwrap().len() < 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                } => {}
            }
        }).await.expect("owner did not receive repeated contested requests");
        fixture.failure.store(0, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut write).await.unwrap().unwrap();
        let requests = fixture.requests.lock().unwrap();
        assert!(requests.iter().all(|id| *id == requests[0]));
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
    }

    /// NAN-4445: which owner 409s on an absent object retry in place.
    #[test]
    fn absent_conflict_retry_classification() {
        for fam in ["wal", "manifest", "compacted", "compactions", "gc_boundary"] {
            assert_eq!(absent_conflict(WriterClass::Maintenance, fam), AbsentConflict::RetryUntilCancelled, "{fam}");
        }
        assert_eq!(absent_conflict(WriterClass::Ingest, "wal"), AbsentConflict::RetryFor(INGEST_WAL_CONFLICT_RETRY));
        // The bound covers 9015130's five-minute takeover window, and stays
        // under the ingest open's hard timeout (15 min).
        assert!(INGEST_WAL_CONFLICT_RETRY > std::time::Duration::from_secs(5 * 60));
        assert!(INGEST_WAL_CONFLICT_RETRY < super::super::ingest::PREVALENCE_OPEN_HARD_TIMEOUT);
        for fam in ["manifest", "compacted"] {
            assert_eq!(absent_conflict(WriterClass::Ingest, fam), AbsentConflict::Fail, "{fam}");
        }
    }

    /// NAN-4445 (the large tenant): an orphaned WAL create reservation answers 409 until
    /// the owner's five-minute takeover; the ingest write retries in place
    /// with one request id and lands once the owner lets it.
    #[tokio::test]
    async fn ingest_wal_owner_conflict_retries_in_place_until_the_takeover() {
        let (objects, access, fixture, tmp) = setup(4).await;
        let store = OwnerStore::new(objects.clone(), access, tmp.path()).unwrap();
        let path = Path::from("db/wal/00000000000000000007.sst");
        let write = store.put_opts(&path, b"wal".to_vec().into(), PutMode::Create.into());
        tokio::pin!(write);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::select! {
                result = &mut write => panic!("contested WAL write returned before the takeover: {result:?}"),
                _ = async {
                    while fixture.requests.lock().unwrap().len() < 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                } => {}
            }
        }).await.expect("owner did not receive repeated contested requests");
        fixture.failure.store(0, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut write).await.unwrap().unwrap();
        let requests = fixture.requests.lock().unwrap();
        assert!(requests.iter().all(|id| *id == requests[0]));
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
    }

    /// NAN-4445: the in-place WAL retry is bounded; past it the write fails
    /// (the open fails and the ingest's backoff schedules the next one).
    #[tokio::test]
    async fn ingest_wal_owner_conflict_retry_is_bounded() {
        let (objects, access, fixture, tmp) = setup(4).await;
        let mut store = OwnerStore::new(objects.clone(), access, tmp.path()).unwrap();
        store.ingest_wal_conflict_retry = std::time::Duration::from_millis(500);
        let path = Path::from("db/wal/00000000000000000007.sst");
        let result = tokio::time::timeout(std::time::Duration::from_secs(10),
            store.put_opts(&path, b"wal".to_vec().into(), PutMode::Create.into())).await.expect("retry was not bounded");
        assert!(result.is_err());
        assert!(fixture.requests.lock().unwrap().len() >= 2, "retried at least once");
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    }

    /// NAN-4445: an ingest manifest 409 (SlateDB's writer/compactor fence,
    /// no takeover exists) still fails at once.
    #[tokio::test]
    async fn ingest_manifest_owner_conflict_fails_without_retry() {
        let (objects, access, fixture, tmp) = setup(4).await;
        let store = OwnerStore::new(objects.clone(), access, tmp.path()).unwrap();
        let path = Path::from("db/manifest/00000000000000000003.manifest");
        assert!(store.put_opts(&path, b"m".to_vec().into(), PutMode::Create.into()).await.is_err());
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn maintenance_owner_conflict_with_present_object_refreshes_instead_of_overwriting() {
        let (objects, access, fixture, tmp) = setup(4).await;
        let mut owner = access.owner;
        owner.bearer = "maintenance-token".into();
        let store = OwnerStore::new_maintenance(objects.clone(), MaintenanceAccess {
            read: access.read, owner, owner_ca_file: None,
        }, tmp.path()).unwrap();
        let path = Path::from("db/compactions/00000000000000000001.compactions");
        objects.put(&path, b"winner".to_vec().into()).await.unwrap();
        let result = store.put_opts(&path, b"loser".to_vec().into(), PutMode::Create.into()).await;
        assert!(matches!(result, Err(slatedb::object_store::Error::AlreadyExists { .. })));
        assert_eq!(objects.get(&path).await.unwrap().bytes().await.unwrap().as_ref(), b"winner");
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn failed_owner_request_preserves_request_id_for_identical_retries() {
        let (objects, access, fixture, tmp) = setup(1).await;
        let path = Path::from("db/wal/00000000000000000001.sst");
        let store = OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap();
        assert!(store
            .put_opts(&path, b"original".to_vec().into(), PutMode::Create.into())
            .await
            .is_err());
        let key = format!("{}{}", access.read.prefix, path);
        let before = std::fs::read(store.journal_path(&key)).unwrap();
        drop(store);
        let restarted = OwnerStore::new(objects, access, tmp.path()).unwrap();
        // An identical retry (after a restart) reuses the same request id.
        assert!(restarted
            .put_opts(&path, b"original".to_vec().into(), PutMode::Create.into())
            .await
            .is_err());
        assert_eq!(before, std::fs::read(restarted.journal_path(&key)).unwrap());
        fixture.failure.store(0, Ordering::SeqCst);
        assert!(restarted
            .put_opts(&path, b"original".to_vec().into(), PutMode::Create.into())
            .await
            .is_ok());
        assert!(!restarted.journal_path(&key).exists());
    }

    /// A definite owner refusal (403 authorize_stale_epoch) is answered
    /// before any PG pending row or S3 call, so the local pending record is
    /// dropped: once the owner recovers, SlateDB's retry of the same key
    /// with different bytes must not wedge on "reconciliation required".
    #[tokio::test]
    async fn definite_owner_refusal_drops_the_pending_record() {
        let (objects, access, fixture, tmp) = setup(3).await;
        let path = Path::from("db/manifest/00000000000000000001.manifest");
        let key = format!("{}{}", access.read.prefix, path);
        let store = OwnerStore::new(objects.clone(), access, tmp.path()).unwrap();
        let refused = store
            .put_opts(&path, b"first".to_vec().into(), PutMode::Create.into())
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("owner mutation status 403"), "{refused}");
        assert!(!store.journal_path(&key).exists());
        fixture.failure.store(0, Ordering::SeqCst);
        store
            .put_opts(&path, b"re-encoded".to_vec().into(), PutMode::Create.into())
            .await
            .unwrap();
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        assert!(!store.journal_path(&key).exists());
    }

    #[test]
    fn pending_journal_publish_survives_each_pre_http_fault() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let pending = PendingMutation {
            request_id: uuid::Uuid::now_v7(),
            tenant_id: TENANT.into(),
            object_bucket: "bucket".into(),
            assignment_generation: 2,
            writer_epoch: 3,
            writer_class: "ingest".into(),
            operation: "create".into(),
            object_key: "key".into(),
            content_length: 1,
            content_sha256: "a".repeat(64),
            expected_etag: None,
        };
        for stage in ["create", "write", "sync", "rename"] {
            let path = tmp.path().join(stage);
            assert!(publish_pending(&path, &pending, Some(stage)).is_err());
            if path.exists() {
                let saved: PendingMutation =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                assert_eq!(saved.request_id, pending.request_id);
            } else {
                publish_pending(&path, &pending, None).unwrap();
            }
            let saved: PendingMutation =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(saved, pending);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn post_rename_retry_syncs_existing_journal_before_every_post() {
        let (objects, access, fixture, tmp) = setup(0).await;
        let path = Path::from("db/wal/00000000000000000010.sst");
        let key = format!("{}{}", access.read.prefix, path);
        let store = OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap();
        let payload = || b"durable retry".to_vec().into();
        let options = || PutMode::Create.into();

        // The rename published the final JSON, but the first call failed
        // before the directory was synced and before reaching HTTP.
        assert!(store
            .mutate_inner(&path, payload(), options(), Some("rename"))
            .await
            .is_err());
        let journal_path = store.journal_path(&key);
        let saved: PendingMutation =
            serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
        assert!(fixture.requests.lock().unwrap().is_empty());

        // The identical retry must fail closed if either durability sync
        // fails, even though the published JSON is valid and visible.
        drop(store);
        let retry = OwnerStore::new(objects, access, tmp.path()).unwrap();
        for fault in ["journal_file_sync", "journal_dir_sync"] {
            assert!(retry
                .mutate_inner(&path, payload(), options(), Some(fault))
                .await
                .is_err());
            assert!(fixture.requests.lock().unwrap().is_empty());
            let current: PendingMutation =
                serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
            assert_eq!(current, saved);
        }

        retry.put_opts(&path, payload(), options()).await.unwrap();
        assert_eq!(*fixture.requests.lock().unwrap(), vec![saved.request_id]);
        assert!(!journal_path.exists());
    }

    #[tokio::test]
    async fn new_journal_sync_failures_never_send_http() {
        let (objects, access, fixture, tmp) = setup(0).await;
        let store = OwnerStore::new(objects, access.clone(), tmp.path()).unwrap();
        for (sequence, fault) in ["journal_file_sync", "journal_dir_sync"]
            .into_iter()
            .enumerate()
        {
            let path = Path::from(format!("db/wal/{:020}.sst", sequence + 11));
            assert!(store
                .mutate_inner(
                    &path,
                    b"new record".to_vec().into(),
                    PutMode::Create.into(),
                    Some(fault),
                )
                .await
                .is_err());
            assert!(fixture.requests.lock().unwrap().is_empty());
            let key = format!("{}{}", access.read.prefix, path);
            let journal_path = store.journal_path(&key);
            let saved: PendingMutation =
                serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
            store
                .put_opts(&path, b"new record".to_vec().into(), PutMode::Create.into())
                .await
                .unwrap();
            assert_eq!(
                fixture.requests.lock().unwrap().last(),
                Some(&saved.request_id)
            );
            fixture.requests.lock().unwrap().clear();
        }
    }

    #[tokio::test]
    async fn tenant_key_class_generation_epoch_size_and_cas_are_fenced() {
        let (objects, access, fixture, tmp) = setup(0).await;
        let mut foreign = access.clone();
        foreign.owner.tenant_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb".into();
        assert!(OwnerStore::new(objects.clone(), foreign, tmp.path()).is_err());
        let store = OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap();
        for path in [
            "db/wal/../manifest/00000000000000000001.manifest",
            "db/foreign/file",
            "db/compactions/00000000000000000001.compactions",
        ] {
            assert!(store
                .put_opts(
                    &Path::from(path),
                    b"x".to_vec().into(),
                    PutMode::Create.into()
                )
                .await
                .is_err());
        }
        let path = Path::from("db/wal/00000000000000000009.sst");
        let update = slatedb::object_store::UpdateVersion {
            e_tag: Some("etag".into()),
            version: None,
        };
        assert!(store
            .put_opts(
                &path,
                b"cas".to_vec().into(),
                PutMode::Update(update).into()
            )
            .await
            .is_err());
        assert!(store
            .put_opts(
                &Path::from("db/manifest/00000000000000000009.manifest"),
                vec![0; 8_388_609].into(),
                PutMode::Create.into()
            )
            .await
            .is_err());
        let mut stale_generation = access.clone();
        stale_generation.owner.assignment_generation = 1;
        let stale = OwnerStore::new(
            objects.clone(),
            stale_generation,
            &tmp.path().join("stale-generation"),
        )
        .unwrap();
        assert!(stale
            .put_opts(&path, b"g".to_vec().into(), PutMode::Create.into())
            .await
            .is_err());
        let mut stale_epoch = access;
        stale_epoch.owner.writer_epoch = 2;
        let stale = OwnerStore::new(objects, stale_epoch, &tmp.path().join("stale-epoch")).unwrap();
        assert!(stale
            .put_opts(&path, b"e".to_vec().into(), PutMode::Create.into())
            .await
            .is_err());
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn lost_completion_response_never_acknowledges_a_real_create() {
        let (objects, access, fixture, tmp) = setup(2).await;
        let path = Path::from("db/wal/00000000000000000008.sst");
        let key = format!("{}{}", access.read.prefix, path);
        let store = OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap();
        assert!(store
            .put_opts(&path, b"written".to_vec().into(), PutMode::Create.into())
            .await
            .is_err());
        assert_eq!(fixture.writes.load(Ordering::SeqCst), 1);
        assert!(store.journal_path(&key).exists());
        drop(store);
        fixture.failure.store(0, Ordering::SeqCst);
        let restarted = OwnerStore::new(objects, access, tmp.path()).unwrap();
        assert!(restarted
            .put_opts(&path, b"written".to_vec().into(), PutMode::Create.into())
            .await
            .is_err());
        assert!(restarted.journal_path(&key).exists());
    }

    /// NAN-3849 (tenant-a 2026-10-14): every ~5 min credential refresh closed and
    /// reopened the tenant state (17-19 s, WAL replay, block/index/filter
    /// caches dropped, catch-up reads in flight aborted). A refresh for the
    /// same tenant, generation, epoch, owner and bucket now swaps the bearer
    /// and read side in place: the open state keeps working and its next
    /// writes carry the new bearer. A changed generation still refuses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refreshed_grant_swaps_in_place_without_reopening_the_state() {
        use super::super::prevalence::IngestPrevalence;
        let (objects, access, fixture, tmp) = setup(0).await;
        let mut state = IngestPrevalence::open_with_reads(TENANT, tmp.path(), Some(&access), Some(objects.clone())).await.unwrap();
        state.initialize_at(0, &"0".repeat(64)).await.unwrap();
        state.make_durable().await.unwrap();
        assert_eq!(fixture.rotated_writes.load(Ordering::SeqCst), 0);
        let mut refreshed = access.clone();
        refreshed.owner.bearer = "owner-token-2".into();
        refreshed.read.access_key_id = "read-2".into();
        assert!(state.refresh_credential_in_place(&refreshed, Some(objects.clone())).unwrap(), "swapped in place");
        // Same open state: its cursor is there, and a new write lands with
        // the refreshed bearer.
        assert_eq!(state.applied().await.unwrap().unwrap().seq, 0);
        state.write_test_wals(1).await.unwrap();
        assert!(fixture.rotated_writes.load(Ordering::SeqCst) >= 1, "later writes use the refreshed bearer");
        let mut moved = refreshed.clone();
        moved.owner.assignment_generation += 1;
        assert!(!state.refresh_credential_in_place(&moved, Some(objects.clone())).unwrap(), "another generation reopens");
        let mut other_bucket = refreshed.clone();
        other_bucket.read.bucket = "other".into();
        assert!(!state.refresh_credential_in_place(&other_bucket, Some(objects)).unwrap(), "another bucket reopens");
        state.close().await.unwrap();
    }

    #[tokio::test]
    async fn real_slatedb_wal_reopens_only_after_owner_mutations() {
        let (objects, access, fixture, tmp) = setup(0).await;
        let store: Arc<dyn ObjectStore> =
            Arc::new(OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap());
        let settings = slatedb::config::Settings {
            flush_interval: None,
            compactor_options: None,
            ..Default::default()
        };
        let db = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            slatedb::Db::builder("db", store)
                .with_settings(settings.clone())
                .build(),
        )
        .await
        .expect("SlateDB open timed out")
        .unwrap();
        let mut batch = slatedb::WriteBatch::new();
        batch.put(b"key", b"value");
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            db.write_with_options(
                batch,
                &slatedb::config::WriteOptions {
                    await_durable: false,
                    ..Default::default()
                },
            ),
        )
        .await
        .expect("SlateDB write timed out")
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(15), db.flush())
            .await
            .expect("SlateDB WAL flush timed out")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(15), db.close_wal_only())
            .await
            .expect("SlateDB close timed out")
            .unwrap();
        assert!(
            fixture.writes.load(Ordering::SeqCst) >= 2,
            "manifest and WAL must both pass owner"
        );
        let store: Arc<dyn ObjectStore> =
            Arc::new(OwnerStore::new(objects, access, tmp.path()).unwrap());
        let reopened = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            slatedb::Db::builder("db", store)
                .with_settings(settings)
                .build(),
        )
        .await
        .expect("SlateDB reopen timed out")
        .unwrap();
        assert_eq!(
            reopened.get(b"key").await.unwrap().unwrap().as_ref(),
            b"value"
        );
        reopened.close_wal_only().await.unwrap();
    }

    #[tokio::test]
    async fn real_slatedb_l0_flushes_continue_past_unflushed_limit() {
        let (objects, access, fixture, tmp) = setup(0).await;
        let settings = slatedb::config::Settings {
            flush_interval: None,
            compactor_options: None,
            l0_sst_size_bytes: 4096,
            max_unflushed_bytes: 16384,
            ..Default::default()
        };
        let store: Arc<dyn ObjectStore> =
            Arc::new(OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap());
        let db = slatedb::Db::builder("db", store)
            .with_settings(settings.clone())
            .build()
            .await
            .unwrap();
        for n in 0..10u32 {
            let key = format!("key-{n:03}");
            let value = vec![n as u8; 2048];
            let mut batch = slatedb::WriteBatch::new();
            batch.put(key.as_bytes(), &value);
            tokio::time::timeout(
                std::time::Duration::from_secs(20),
                db.write_with_options(
                    batch,
                    &slatedb::config::WriteOptions {
                        await_durable: false,
                        ..Default::default()
                    },
                ),
            )
            .await
            .expect("write blocked by unflushed memtables")
            .unwrap();
            if n % 2 == 1 {
                tokio::time::timeout(std::time::Duration::from_secs(20), db.flush())
                    .await
                    .unwrap_or_else(|_| panic!("WAL flush {n} timed out"))
                    .unwrap();
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(20), db.close_wal_only())
            .await
            .expect("close timed out")
            .unwrap();
        assert!(fixture.writes.load(Ordering::SeqCst) > 3);
        let l0_objects = objects
            .list(Some(&Path::from("db/compacted")))
            .collect::<Vec<_>>()
            .await;
        assert!(
            l0_objects.len() >= 2,
            "expected multiple owner-authorized L0 uploads"
        );
        let store: Arc<dyn ObjectStore> =
            Arc::new(OwnerStore::new(objects, access, tmp.path()).unwrap());
        let db = slatedb::Db::builder("db", store)
            .with_settings(settings)
            .build()
            .await
            .unwrap();
        for n in 0..10u32 {
            let key = format!("key-{n:03}");
            assert_eq!(
                db.get(key.as_bytes()).await.unwrap().unwrap().as_ref(),
                vec![n as u8; 2048]
            );
        }
        db.close_wal_only().await.unwrap();
    }

    #[tokio::test]
    async fn standalone_maintenance_compacts_real_ingest_l0_and_reopens() {
        run_standalone_maintenance_compaction(false, false).await;
    }

    /// Run by the disposable PG18 harness with tenant-specific logins.
    #[tokio::test]
    #[ignore]
    async fn standalone_maintenance_compaction_with_real_pg_owner() {
        run_standalone_maintenance_compaction(true, false).await;
    }

    #[tokio::test]
    async fn standalone_maintenance_compactor_survives_owner_conflicts_and_resumes() {
        run_standalone_maintenance_compaction(false, true).await;
    }

    async fn run_standalone_maintenance_compaction(expect_pg: bool, conflict: bool) {
        use slatedb::admin::AdminBuilder;
        use tokio_util::sync::CancellationToken;

        let (objects, access, fixture, tmp) = setup(0).await;
        assert_eq!(fixture.pg.is_some(), expect_pg);
        let settings = slatedb::config::Settings {
            flush_interval: None,
            compactor_options: None,
            garbage_collector_options: None,
            l0_sst_size_bytes: 4096,
            max_unflushed_bytes: 65536,
            l0_max_ssts: 4,
            l0_max_ssts_per_key: 4,
            ..Default::default()
        };
        let ingest: Arc<dyn ObjectStore> = Arc::new(
            OwnerStore::new(objects.clone(), access.clone(), &tmp.path().join("ingest")).unwrap(),
        );
        let db = slatedb::Db::builder("db", ingest)
            .with_settings(settings.clone())
            .build()
            .await
            .unwrap();
        let mut maintenance_owner = access.owner.clone();
        maintenance_owner.bearer = "maintenance-token".into();
        let maintenance: Arc<dyn ObjectStore> = Arc::new(
            OwnerStore::new_maintenance(
                objects.clone(),
                MaintenanceAccess {
                    read: access.read.clone(),
                    owner: maintenance_owner,
                    owner_ca_file: None,
                },
                &tmp.path().join("maintenance"),
            )
            .unwrap(),
        );
        // The maintenance bearer cannot be supplied to the ingest constructor
        // to make a compactions write, even with an otherwise valid envelope.
        let mut forged = access.clone();
        forged.owner.bearer = "maintenance-token".into();
        let forged_ingest =
            OwnerStore::new(objects.clone(), forged, &tmp.path().join("forged")).unwrap();
        assert!(forged_ingest
            .put_opts(
                &Path::from("db/compactions/00000000000000000001.compactions"),
                b"x".to_vec().into(),
                PutMode::Create.into()
            )
            .await
            .is_err());
        let forged_maintenance = OwnerStore::new_maintenance(
            objects.clone(),
            MaintenanceAccess {
                read: access.read.clone(),
                owner: access.owner.clone(),
                owner_ca_file: None,
            },
            &tmp.path().join("forged-maintenance"),
        )
        .unwrap();
        assert!(forged_maintenance
            .put_opts(
                &Path::from("db/compactions/00000000000000000099.compactions"),
                b"x".to_vec().into(),
                PutMode::Create.into(),
            )
            .await
            .is_err());
        assert!(maintenance
            .put_opts(
                &Path::from("db/wal/00000000000000000099.sst"),
                b"x".to_vec().into(),
                PutMode::Create.into()
            )
            .await
            .is_err());

        if conflict {
            fixture.failure.store(4, Ordering::SeqCst);
        }
        let requests_before = fixture.requests.lock().unwrap().len();
        let admin = AdminBuilder::new("db", maintenance).build();
        let cancel = CancellationToken::new();
        let options = slatedb::config::CompactorOptions {
            poll_interval: std::time::Duration::from_millis(100),
            commit_compacted_interval: std::time::Duration::from_millis(100),
            max_concurrent_compactions: 1,
            object_store_max_retries: Some(2),
            worker: Some(slatedb::config::CompactionWorkerOptions {
                max_concurrent_compactions: 1,
                compactions_poll_interval: std::time::Duration::from_millis(100),
                max_subcompactions: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        let worker_cancel = cancel.clone();
        let worker = tokio::spawn(async move {
            admin
                .run_compactor_with_options(worker_cancel, options)
                .await
        });
        if conflict {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if fixture.requests.lock().unwrap().len() >= requests_before + 3 {
                        break;
                    }
                    assert!(!worker.is_finished(), "409 stopped the real SlateDB compactor");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }).await.expect("compactor did not retry owner conflicts");
            assert!(!worker.is_finished(), "409 stopped the real SlateDB compactor");
            fixture.failure.store(0, Ordering::SeqCst);
        }
        for n in 0..24u32 {
            let artifact = format!("192.0.2.{n}");
            let key = crate::part_ingest::prevalence::key("ip", &artifact);
            let value = crate::part_ingest::prevalence::encode(
                &crate::part_ingest::prevalence::WindowState {
                    first_seen: 1_000_000,
                    last_seen: 2_000_000,
                    days: vec![(0, 100 + n as u64)],
                    hosts: (1..=300).map(|host| (host, 0)).collect(),
                },
            );
            let mut batch = slatedb::WriteBatch::new();
            batch.put(&key, &value);
            let write = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                db.write_with_options(
                    batch,
                    &slatedb::config::WriteOptions {
                        await_durable: false,
                        ..Default::default()
                    },
                ),
            )
            .await;
            if write.is_err() {
                let keys = objects.list(None).collect::<Vec<_>>().await;
                panic!(
                    "ingest blocked at L0 cap n={n}, keys={keys:?}, worker_finished={}",
                    worker.is_finished()
                );
            }
            write.unwrap().unwrap();
            if n % 2 == 1 {
                tokio::time::timeout(
                    std::time::Duration::from_secs(20),
                    db.flush_with_options(slatedb::config::FlushOptions {
                        flush_type: slatedb::config::FlushType::MemTable,
                    }),
                )
                .await
                .expect("L0 flush blocked")
                .unwrap();
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(20), db.close_wal_only())
            .await
            .expect("writer close blocked")
            .unwrap();
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(20), worker)
            .await
            .expect("compactor stop blocked")
            .unwrap()
            .unwrap();
        let compactions = objects
            .list(Some(&Path::from("db/compactions")))
            .collect::<Vec<_>>()
            .await;
        assert!(
            !compactions.is_empty(),
            "actual compactor wrote no state through owner"
        );
        assert!(
            fixture.maintenance_ssts.load(Ordering::SeqCst) > 0,
            "actual compactor produced no conditional SST through maintenance owner"
        );
        assert!(fixture.writes.load(Ordering::SeqCst) > 10);
        let ingest: Arc<dyn ObjectStore> =
            Arc::new(OwnerStore::new(objects, access, &tmp.path().join("ingest")).unwrap());
        let reopened = slatedb::Db::builder("db", ingest)
            .with_settings(settings)
            .build()
            .await
            .unwrap();
        for n in 0..24u32 {
            let artifact = format!("192.0.2.{n}");
            let key = crate::part_ingest::prevalence::key("ip", &artifact);
            let bytes = reopened.get(&key).await.unwrap().unwrap();
            let row = crate::part_ingest::prevalence::decode(&bytes).unwrap();
            assert_eq!(row.days, vec![(0, 100 + n as u64)]);
            assert_eq!(row.first_seen, 1_000_000);
            assert_eq!(row.last_seen, 2_000_000);
            assert_eq!(row.hosts.len(), 300);
        }
        reopened.close_wal_only().await.unwrap();
    }

    /// cell30 (2026-09-30): a local pending record for
    /// `compactions/...0009` outlived an owner crash that happened before
    /// authorize (no owner row). Every compaction then failed "stays
    /// blocked". A stale record for an ABSENT key is now dropped and the
    /// key created afresh; no reconcile (which would quarantine the key
    /// forever) is ever sent: this owner fixture has no /reconcile route.
    #[tokio::test]
    async fn a_stale_record_for_an_absent_numbered_key_is_dropped_and_created() {
        let (objects, access, fixture, tmp) = setup(1).await;
        let path = Path::from("db/compactions/00000000000000000009.compactions");
        let mut maintenance_owner = access.owner.clone();
        maintenance_owner.bearer = "maintenance-token".into();
        let store = OwnerStore::new_maintenance(objects.clone(),
            MaintenanceAccess { read: access.read.clone(), owner: maintenance_owner, owner_ca_file: None }, tmp.path()).unwrap();
        // The owner dies before authorize: the record stays (same-byte retries reuse it).
        assert!(store.put_opts(&path, b"state v1".to_vec().into(), PutMode::Create.into()).await.is_err());
        let key = format!("{}{}", access.read.prefix, path);
        assert!(store.journal_path(&key).exists());
        // SlateDB retries the key with new bytes after the owner is back.
        fixture.failure.store(0, Ordering::SeqCst);
        store.put_opts(&path, b"state v2".to_vec().into(), PutMode::Create.into()).await
            .expect("a stale record for an absent key never blocks the key");
        assert!(!store.journal_path(&key).exists());
        assert_eq!(objects.get(&path).await.unwrap().bytes().await.unwrap().as_ref(), b"state v2");
    }

    /// A stale record for a key whose earlier create DID land answers
    /// AlreadyExists (SlateDB refreshes and advances to the next id); the
    /// object is never overwritten.
    #[tokio::test]
    async fn a_stale_record_for_a_present_key_reports_already_exists() {
        let (objects, access, fixture, tmp) = setup(2).await;
        let path = Path::from("db/manifest/00000000000000000004.manifest");
        let store = OwnerStore::new(objects.clone(), access.clone(), tmp.path()).unwrap();
        // The create lands but the owner fails before completing (failure 2).
        assert!(store.put_opts(&path, b"m4".to_vec().into(), PutMode::Create.into()).await.is_err());
        fixture.failure.store(0, Ordering::SeqCst);
        let result = store.put_opts(&path, b"m4 regenerated".to_vec().into(), PutMode::Create.into()).await;
        assert!(matches!(result, Err(slatedb::object_store::Error::AlreadyExists { .. })), "{result:?}");
        assert_eq!(objects.get(&path).await.unwrap().bytes().await.unwrap().as_ref(), b"m4");
    }

    /// The lean test tenant's hang (2026-09-30): ingest's prevalence writes (write +
    /// WAL flush per chunk, memtables to L0 by size, no compactor) stop at
    /// SlateDB's L0 cap. A 47-part rebuild's worth of writes stalls
    /// without maintenance[T] and completes with it, L0 staying under the
    /// cap, every row readable afterwards.
    async fn rebuild_writes(with_maintenance: bool) -> (bool, Option<usize>) {
        let (objects, access, _fixture, tmp) = setup(0).await;
        let settings = slatedb::config::Settings {
            flush_interval: None,
            compactor_options: None,
            garbage_collector_options: None,
            l0_sst_size_bytes: 16 * 1024,
            max_unflushed_bytes: 64 * 1024,
            l0_max_ssts: 8,
            l0_max_ssts_per_key: 8,
            ..Default::default()
        };
        let ingest: Arc<dyn ObjectStore> = Arc::new(OwnerStore::new(objects.clone(), access.clone(), &tmp.path().join("ingest")).unwrap());
        let db = slatedb::Db::builder("db", ingest).with_settings(settings.clone()).build().await.unwrap();
        let cancel = tokio_util::sync::CancellationToken::new();
        let compactor = with_maintenance.then(|| {
            let mut owner = access.owner.clone();
            owner.bearer = "maintenance-token".into();
            let store: Arc<dyn ObjectStore> = Arc::new(OwnerStore::new_maintenance(objects.clone(),
                MaintenanceAccess { read: access.read.clone(), owner, owner_ca_file: None },
                &tmp.path().join("maintenance")).unwrap());
            let mut options = crate::part_ingest::maintenance::compactor_options();
            options.poll_interval = std::time::Duration::from_millis(100);
            options.commit_compacted_interval = std::time::Duration::from_millis(100);
            if let Some(worker) = options.worker.as_mut() {
                worker.compactions_poll_interval = std::time::Duration::from_millis(100);
                // Scaled down like the L0 size: outputs are split at it.
                worker.max_sst_size = 64 * 1024;
            }
            tokio::spawn(crate::part_ingest::maintenance::run_compactor(store, options, cancel.clone()))
        });
        let mut completed = true;
        'parts: for part in 0..47u32 {
            for chunk in 0..4u32 {
                let mut batch = slatedb::WriteBatch::new();
                for n in 0..64u32 {
                    batch.put(format!("p{part:02}-c{chunk}-k{n:03}").as_bytes(), vec![(part + n) as u8; 512]);
                }
                let commit = async {
                    db.write_with_options(batch, &slatedb::config::WriteOptions { await_durable: false, ..Default::default() }).await?;
                    db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::Wal }).await
                };
                match tokio::time::timeout(std::time::Duration::from_secs(if with_maintenance { 60 } else { 5 }), commit).await {
                    Ok(result) => result.unwrap(),
                    Err(_) => {
                        eprintln!("stalled at part {part} chunk {chunk}; l0={:?} compactor_finished={:?}",
                            crate::part_ingest::maintenance::l0_count(objects.clone()).await,
                            compactor.as_ref().map(|c| c.is_finished()));
                        completed = false;
                        break 'parts;
                    }
                }
            }
        }
        if completed {
            // Every memtable reaches L0 (the flusher is asynchronous), then
            // the compactor gets time to catch up with the last L0s.
            tokio::time::timeout(std::time::Duration::from_secs(60),
                db.flush_with_options(slatedb::config::FlushOptions { flush_type: slatedb::config::FlushType::MemTable }))
                .await.expect("final memtable flush blocked").unwrap();
            for _ in 0..300 {
                if crate::part_ingest::maintenance::l0_count(objects.clone()).await.unwrap().unwrap_or(0) < 8 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            for part in [0u32, 23, 46] {
                let value = db.get(format!("p{part:02}-c3-k063").as_bytes()).await.unwrap().expect("row readable");
                assert_eq!(value.as_ref(), vec![(part + 63) as u8; 512].as_slice());
            }
        }
        let l0 = crate::part_ingest::maintenance::l0_count(objects.clone()).await.unwrap();
        if with_maintenance {
            // Every compacted output is split at max_sst_size (plus one
            // block): each owner POST stays small and bounded in time.
            let outputs = objects.list(Some(&Path::from("db/compacted"))).collect::<Vec<_>>().await;
            let largest = outputs.iter().map(|meta| meta.as_ref().unwrap().size).max().unwrap_or(0);
            assert!(largest <= 64 * 1024 + 8 * 1024, "a compacted SST of {largest} bytes exceeds the split size");
        }
        cancel.cancel();
        if let Some(compactor) = compactor {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(20), compactor).await;
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), db.close_wal_only()).await;
        (completed, l0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_47_part_rebuild_stalls_without_maintenance_and_completes_with_it() {
        let (completed, _) = rebuild_writes(false).await;
        assert!(!completed, "without a compactor the writes must reach the L0 cap and stall");
        let (completed, l0) = rebuild_writes(true).await;
        assert!(completed, "with maintenance[T] compacting, every write completes");
        let l0 = l0.expect("a manifest exists");
        assert!(l0 < 8, "L0 stays under l0_max_ssts (was {l0})");
    }
}
