// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `lake_part` write path with a server-verified SHA-256 (NAN-2884).
//!
//! Every part file goes up as ONE SigV4-signed `PutObject` (never
//! multipart: R2's SHA-256 is composite-only for multipart) carrying
//! - `x-amz-checksum-sha256`: standard padded base64 of the raw 32-byte
//!   SHA-256 (44 chars), as a header, not a trailer; R2 rejects a mismatch
//!   with 400 BadDigest and writes nothing;
//! - `x-amz-content-sha256`: the lowercase hex of the same digest (signed);
//! - `If-None-Match: *`: create only (412 when the key exists).
//!
//! No other checksum (no SDK CRC) is sent. The body streams from disk. The
//! owner then trusts R2's stored `ChecksumSHA256` + size instead of
//! re-hashing (#1555). An overwrite without the header would DROP the stored
//! checksum, so every PUT here sends it; there is no unconditional PUT for
//! part files. Reads stay on opendal ([`super::s3_store::S3ObjectStore`]).

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::s3_store::{S3Location, S3ObjectStore};
use crate::parts::format::{MAX_OBJECT_BYTES, PARTS_ROOT};
use crate::parts::part_log::{ObjectStore, OwnerConflict, WriteHints, WriterClass};

/// A `lake_part` PUT the store refused for a reason no retry can fix
/// (403 credentials/scope, 400 BadDigest / InvalidArgument / other client
/// errors). Callers stop retrying and fail-stop (the supervisor restarts
/// the process with fresh credentials), instead of retrying for 30 minutes.
#[derive(Debug, thiserror::Error)]
#[error("lake_part PUT {key} refused: HTTP {status} {code}")]
pub struct TerminalPutError {
    pub key: String,
    pub status: u16,
    pub code: String,
}

/// A retryable PUT failure (5xx, 429, network).
#[derive(Debug, thiserror::Error)]
#[error("lake_part PUT {key} failed: HTTP {status} {code}")]
pub struct TransientPutError {
    pub key: String,
    pub status: u16,
    pub code: String,
}

type HmacSha256 = Hmac<Sha256>;

/// `x-amz-checksum-sha256` value for a lowercase-hex SHA-256.
pub fn checksum_header_value(sha256_hex: &str) -> Result<String> {
    let raw = hex::decode(sha256_hex).context("sha256 is not hex")?;
    ensure!(raw.len() == 32, "sha256 must be 32 bytes");
    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// S3 URI-encoding of one path (each segment; `/` kept). RFC 3986
/// unreserved characters stay; everything else is `%XX` uppercase.
pub fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 16);
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// A SigV4 request signer (header-based, no query signing).
#[derive(Clone)]
pub struct SigV4 {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: String,
    pub service: String,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

impl SigV4 {
    /// Sign `method canonical_uri` with `headers` (lowercase names; must
    /// include `host` and `x-amz-date`) and the hex payload hash. Returns the
    /// `Authorization` header value.
    pub fn authorization(
        &self,
        method: &str,
        canonical_uri: &str,
        headers: &[(String, String)],
        payload_sha256_hex: &str,
        amz_date: &str,
    ) -> Result<String> {
        ensure!(amz_date.len() == 16, "x-amz-date must be YYYYMMDDTHHMMSSZ");
        let mut sorted = headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())).collect::<Vec<_>>();
        sorted.sort();
        let canonical_headers = sorted.iter().map(|(k, v)| format!("{k}:{v}\n")).collect::<String>();
        let signed_headers = sorted.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        let canonical_request =
            format!("{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_sha256_hex}");
        let date = &amz_date[..8];
        let scope = format!("{date}/{}/{}/aws4_request", self.region, self.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let k_date = hmac(format!("AWS4{}", self.secret_access_key).as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, self.region.as_bytes());
        let k_service = hmac(&k_region, self.service.as_bytes());
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
        Ok(format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        ))
    }
}

/// The part store for a tenant bucket prefix: checksummed single-PUT writes,
/// opendal reads.
pub struct R2PartStore {
    native_writer: Option<std::sync::Arc<super::native_writer::NativePartWriter>>,
    producer_cache: Option<(PathBuf, u64)>,
    client: reqwest::Client,
    location: std::sync::RwLock<S3Location>,
    /// `lake_part_log` credentials for `log/entries/…` (None: same as
    /// `location`).
    log_location: std::sync::RwLock<Option<S3Location>>,
    reads: S3ObjectStore,
    /// Reads/lists of `log/entries/…` with the `lake_part_log` credential.
    /// the platform scopes `lake_part` to `parts/` + `log/checkpoints/` only,
    /// so a log-entry GET with it is a 403 whether or not the key exists.
    log_reads: Option<S3ObjectStore>,
    /// Every key must start with this (`lake/parts/v1/tenant={uuid}/`).
    tenant_prefix: String,
    /// Small-object spill files (the role's state dir, never `/tmp`).
    spill_dir: PathBuf,
}

impl R2PartStore {
    pub fn with_native_writer(mut self, writer: std::sync::Arc<super::native_writer::NativePartWriter>) -> Result<Self> {
        writer.check_store_binding(&self.tenant_prefix, &self.location.read().expect("location lock"))?;
        self.native_writer = Some(writer); Ok(self)
    }
    pub fn replace_write_permission(&self, permission: super::native_writer::WritePermission) -> Result<()> {
        self.native_writer.as_ref().context("store has no native writer")?.replace_permission(permission)
    }

    #[cfg(test)]
    pub(crate) fn gc_operator_snapshot(&self, key: &str) -> std::sync::Arc<opendal::Operator> {
        self.reader_for(key).gc_operator_snapshot()
    }

    /// Install only on the GC-owned store; credential replacement preserves it.
    pub(crate) fn guard_gc(&self, guard: std::sync::Arc<crate::r2_ops::GcHttpGuard>) -> Result<()> {
        self.reads
            .guard_gc(&self.location.read().expect("location lock"), guard.clone())?;
        if let Some(reads) = &self.log_reads {
            let location = self.log_location.read().expect("location lock");
            reads.guard_gc(location.as_ref().context("GC log location missing")?, guard)?;
        }
        Ok(())
    }

    pub fn with_producer_cache(mut self, parts: &Path, max_bytes: u64) -> Self {
        self.producer_cache = Some((parts.to_path_buf(), max_bytes));
        self
    }

    /// A store for one tenant's part keys; `spill_dir` holds the temp files
    /// of small checksummed PUTs (created 0700 if missing).
    pub fn new(location: &S3Location, tenant_id: &str, spill_dir: &Path) -> Result<Self> {
        ensure!(location.endpoint.starts_with("https://") || cfg!(test), "R2 endpoint must be https");
        ensure!(uuid::Uuid::parse_str(tenant_id).is_ok(), "part store tenant must be a uuid");
        std::fs::create_dir_all(spill_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(spill_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            native_writer: None,
            producer_cache: None,
            tenant_prefix: format!("{PARTS_ROOT}/tenant={tenant_id}/"),
            spill_dir: spill_dir.to_path_buf(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            location: std::sync::RwLock::new(location.clone()),
            log_location: std::sync::RwLock::new(None),
            reads: S3ObjectStore::new(location)?,
            log_reads: None,
        })
    }

    /// Separate `lake_part` (files, checkpoints, reads) and `lake_part_log`
    /// (log entries) credentials, as the cell exchange issues them.
    pub fn new_split(part: &S3Location, log: &S3Location, tenant_id: &str, spill_dir: &Path) -> Result<Self> {
        ensure!(part.bucket == log.bucket && part.endpoint == log.endpoint, "part and log credentials name different buckets");
        let mut store = Self::new(part, tenant_id, spill_dir)?;
        *store.log_location.write().expect("location lock") = Some(log.clone());
        store.log_reads = Some(S3ObjectStore::new(log)?);
        Ok(store)
    }

    /// Detect stages finding parts with a narrow write credential while all
    /// reads (including log checkpoints) use its tenant read-only credential.
    pub fn new_split_read(part: &S3Location, read: &S3Location, tenant_id: &str, spill_dir: &Path) -> Result<Self> {
        let mut store = Self::new_split(part, read, tenant_id, spill_dir)?;
        store.reads = S3ObjectStore::new(read)?;
        Ok(store)
    }

    pub fn replace_split(&self, part: &S3Location, log: &S3Location) -> Result<()> {
        ensure!(part.bucket == log.bucket && part.endpoint == log.endpoint, "part and log credentials name different buckets");
        self.replace(part)?;
        *self.log_location.write().expect("location lock") = Some(log.clone());
        match &self.log_reads {
            Some(reads) => reads.replace(log)?,
            None => bail!("store was built without a split log credential"),
        }
        Ok(())
    }

    /// Refresh a [`Self::new_split_read`] store: writes on `part`, every
    /// read (log entries and checkpoints included) on `read`.
    pub fn replace_split_read(&self, part: &S3Location, read: &S3Location) -> Result<()> {
        self.replace_split(part, read)?;
        self.reads.replace(read)
    }

    /// The tenant's part objects under `prefix` with etag, size and upload
    /// time, listed on the `lake_part` read credential (sanctioned GC input).
    pub async fn list_part_objects(&self, prefix: &str) -> Result<Vec<crate::lake_part_gc::ListedPartObject>> {
        self.check_key(&format!("{prefix}__list_probe__"))?;
        self.reads.list_with_metadata(prefix).await
    }

    pub(crate) async fn list_selected_part_objects(
        &self, prefix: &str,
        selection: &crate::lake_part_gc::planner::InventorySelection<'_>,
    ) -> Result<Vec<crate::lake_part_gc::ListedPartObject>> {
        self.check_key(&format!("{prefix}__list_probe__"))?;
        self.reads.list_selected_with_metadata(prefix, selection).await
    }

    pub fn part_inventory_scope(&self) -> String {
        self.reads.inventory_scope()
    }

    /// Swap in refreshed credentials.
    pub fn replace(&self, location: &S3Location) -> Result<()> {
        if let Some(writer) = &self.native_writer { writer.check_store_binding(&self.tenant_prefix, location)?; }
        self.reads.replace(location)?;
        *self.location.write().expect("location lock") = location.clone();
        Ok(())
    }

    fn object_key(location: &S3Location, key: &str) -> String {
        let prefix = location.prefix.trim_matches('/');
        if prefix.is_empty() {
            key.to_string()
        } else {
            format!("{prefix}/{key}")
        }
    }

    /// Refuse any key outside this tenant's part prefix.
    fn check_key(&self, key: &str) -> Result<()> {
        ensure!(
            key.starts_with(&self.tenant_prefix)
                && !key.chars().any(char::is_control)
                && !key.split('/').any(|segment| segment.is_empty() || segment == "." || segment == ".."),
            "key {key} is outside the tenant's part prefix"
        );
        Ok(())
    }

    /// One conditional, checksummed PutObject streaming `path`. `Ok(false)`
    /// on 412 (the key exists). `class` picks the credential: log entries
    /// use `lake_part_log`, everything else `lake_part`.
    pub async fn put_file_if_absent(&self, key: &str, path: &Path, sha256_hex: &str, bytes: u64, class: WriterClass) -> Result<bool> {
        self.put_file_inner(key, path, sha256_hex, bytes, class, None).await
    }

    async fn put_file_inner(&self, key: &str, path: &Path, sha256_hex: &str, bytes: u64, class: WriterClass, hints: Option<&WriteHints>) -> Result<bool> {
        self.check_key(key)?;
        ensure!(bytes > 0 && bytes <= MAX_OBJECT_BYTES, "part file size is outside the object cap");
        ensure!(
            (class == WriterClass::LakePartLog) == key.starts_with(&format!("{}log/entries/", self.tenant_prefix)),
            "writer class does not match key {key}"
        );
        let native_writer = self.native_writer_for(key);
        let _native_guard = match native_writer { Some(writer) => Some(writer.write_guard(key).await?), None => None };
        let mut replay = ReplayUnlessDone(native_writer.map(|writer| writer.as_ref()));
        let outcome = self.put_file_guarded(key, path, sha256_hex, bytes, class, hints, native_writer).await;
        if outcome.is_ok() {
            replay.0 = None;
        }
        outcome
    }

    async fn put_file_guarded(&self, key: &str, path: &Path, sha256_hex: &str, bytes: u64, class: WriterClass,
        hints: Option<&WriteHints>, native_writer: Option<&std::sync::Arc<super::native_writer::NativePartWriter>>) -> Result<bool> {
        let native_attempt = match native_writer {
            Some(writer) => {
                match writer.begin(key, sha256_hex, bytes, hints.context("native writes require exact event bounds")?).await? {
                Some(attempt) => Some(attempt), None => return Ok(true),
                }
            }, None => None,
        };
        let location = match class {
            WriterClass::LakePartLog => self
                .log_location
                .read()
                .expect("location lock")
                .clone()
                .unwrap_or_else(|| self.location.read().expect("location lock").clone()),
            WriterClass::LakePart => self.location.read().expect("location lock").clone(),
        };
        let url_path = format!("/{}/{}", location.bucket, Self::object_key(&location, key));
        let canonical_uri = uri_encode_path(&url_path);
        let host = location
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let mut headers = vec![
            ("host".to_string(), host),
            ("if-none-match".to_string(), "*".to_string()),
            ("x-amz-checksum-sha256".to_string(), checksum_header_value(sha256_hex)?),
            ("x-amz-content-sha256".to_string(), sha256_hex.to_string()),
            ("x-amz-date".to_string(), amz_date.clone()),
        ];
        if let Some(token) = &location.session_token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }
        let signer = SigV4 {
            access_key_id: location.access_key_id.clone(),
            secret_access_key: location.secret_access_key.clone(),
            session_token: location.session_token.clone(),
            region: location.region.clone(),
            service: "s3".to_string(),
        };
        let authorization = signer.authorization("PUT", &canonical_uri, &headers, sha256_hex, &amz_date)?;
        let file = tokio::fs::File::open(path).await?;
        ensure!(file.metadata().await?.len() == bytes, "local part file size changed before upload");
        let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file));
        let mut request = self
            .client
            .put(format!("{}{}", location.endpoint.trim_end_matches('/'), canonical_uri))
            .header(reqwest::header::AUTHORIZATION, authorization)
            .header(reqwest::header::CONTENT_LENGTH, bytes);
        for (name, value) in headers.iter().filter(|(name, _)| name != "host") {
            request = request.header(name.as_str(), value.as_str());
        }
        let response = request.body(body).send().await?;
        match response.status().as_u16() {
            200 => {
                if let (Some(writer), Some(attempt)) = (native_writer, native_attempt) {
                    let etag = response.headers().get(reqwest::header::ETAG).context("native PUT has no ETag")?.to_str()?;
                    writer.finish(attempt, etag).await?;
                }
                Ok(true)
            },
            412 => Ok(false),
            // A concurrent conditional write won (R2 ConditionalRequestConflict)
            // or the owner refused the writer: fenced, never retried.
            409 => Err(OwnerConflict { key: key.to_string() }.into()),
            status => {
                let text = response.text().await.unwrap_or_default();
                let code = text.split("<Code>").nth(1).and_then(|t| t.split("</Code>").next()).unwrap_or("").chars().take(64).collect::<String>();
                if (400..500).contains(&status) && status != 408 && status != 429 {
                    Err(TerminalPutError { key: key.to_string(), status, code }.into())
                } else {
                    Err(TransientPutError { key: key.to_string(), status, code }.into())
                }
            }
        }
    }
}

/// A failed OR cancelled native write (a merge transfer deadline drops it)
/// may leave a journaled intent: the next write replays first, as every
/// write did while they were serialized.
struct ReplayUnlessDone<'w>(Option<&'w super::native_writer::NativePartWriter>);
impl Drop for ReplayUnlessDone<'_> {
    fn drop(&mut self) { if let Some(writer) = self.0 { writer.mark_needs_replay(); } }
}

impl R2PartStore {
    /// The native writer that authorizes `key`. Finding receipts and the
    /// exact ingest index metadata marker retain their scoped conditional
    /// path, as do admitted count-backfill windows and owed prevalence
    /// restamp snapshots (writer state the owner's closed key grammar does not
    /// cover); numbered checkpoints still authorize.
    fn native_writer_for(&self, key: &str) -> Option<&std::sync::Arc<super::native_writer::NativePartWriter>> {
        self.native_writer.as_ref().filter(|_| !key.starts_with(
            &format!("{}finding-outbox/receipts/", self.tenant_prefix))
            && key != format!("{}log/checkpoints/{}", self.tenant_prefix, super::ingest::FINDING_ATTEMPT_INDEX_READY)
            && !key.starts_with(&format!("{}log/checkpoints/{}", self.tenant_prefix, super::ingest::COUNT_BACKFILL_DIR))
            && !key.starts_with(&format!("{}log/checkpoints/{}", self.tenant_prefix, super::ingest::PREVALENCE_RESTAMP_DIR)))
    }

    /// NAN-3499: authorize, HEAD, complete for an object already stored by
    /// another principal. The owner HEADs the provider itself and refuses a
    /// completion whose ETag, length or SHA-256 checksum differs, so the
    /// receipt binds exactly the stored bytes.
    async fn register_stored(&self, key: &str, sha256_hex: &str, bytes: u64, hints: &WriteHints) -> Result<bool> {
        self.check_key(key)?;
        ensure!(bytes > 0 && bytes <= MAX_OBJECT_BYTES, "part file size is outside the object cap");
        ensure!(hints.class == WriterClass::LakePart && !self.is_log_entry(key),
            "only lake_part objects are registered after the fact ({key})");
        let Some(writer) = self.native_writer_for(key) else { return Ok(false) };
        let _guard = writer.write_guard(key).await?;
        let mut replay = ReplayUnlessDone(Some(writer.as_ref()));
        if let Some(attempt) = writer.begin(key, sha256_hex, bytes, hints).await? {
            let (etag, length) = self.reads.stat_strong(key).await?
                .with_context(|| format!("object to register is absent: {key}"))?;
            ensure!(length == bytes, "stored object length {length} differs from {bytes}: {key}");
            writer.finish(attempt, &etag).await?;
        }
        replay.0 = None;
        Ok(true)
    }

    fn is_log_entry(&self, key: &str) -> bool {
        key.starts_with(&format!("{}log/entries/", self.tenant_prefix))
    }

    /// The credential that is scoped to `key`: `lake_part_log` for
    /// `log/entries/…` (when split), `lake_part` for everything else.
    fn reader_for(&self, key: &str) -> &S3ObjectStore {
        match &self.log_reads {
            Some(log) if self.is_log_entry(key) => log,
            _ => &self.reads,
        }
    }

    /// Small objects (log entries, checkpoints, provenance): the same
    /// checksummed single PUT through a spill file in the state dir, so no
    /// write ever lacks the checksum.
    async fn put_small(&self, key: &str, bytes: &[u8], class: WriterClass) -> Result<bool> {
        let sha = hex::encode(Sha256::digest(bytes));
        let temp = tempfile::NamedTempFile::new_in(&self.spill_dir)?;
        std::fs::write(temp.path(), bytes)?;
        self.put_file_if_absent(key, temp.path(), &sha, bytes.len() as u64, class).await
    }
}

#[async_trait]
impl ObjectStore for R2PartStore {
    async fn warm_signed_file(&self, key: &str, path: &Path, digest: &str, bytes: u64) -> Result<bool> {
        self.check_key(key)?;
        let Some((parts, max_bytes)) = &self.producer_cache else { return Ok(false) };
        let (parts, key, path, digest, max_bytes) = (parts.clone(), key.to_string(), path.to_path_buf(), digest.to_string(), *max_bytes);
        tokio::task::spawn_blocking(move || crate::producer_cache::warm(&parts, &key, &path, &digest, bytes, max_bytes)).await?
    }

    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        self.check_key(key)?;
        self.reader_for(key).get_range(key, range).await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        // Only NotFound is "absent"; a 403 stays an error (never a new log).
        self.check_key(key)?;
        self.reader_for(key).get(key).await
    }

    async fn get_to_file(&self, key: &str, path: &Path) -> Result<bool> {
        self.check_key(key)?;
        self.reader_for(key).get_to_file(key, path).await
    }

    async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
        let class = if key.starts_with(&format!("{}log/entries/", self.tenant_prefix)) { WriterClass::LakePartLog } else { WriterClass::LakePart };
        self.put_small(key, bytes, class).await
    }

    async fn put_if_absent_with(&self, key: &str, bytes: &[u8], hints: &WriteHints) -> Result<bool> {
        let sha = hex::encode(Sha256::digest(bytes));
        let temp = tempfile::NamedTempFile::new_in(&self.spill_dir)?;
        std::fs::write(temp.path(), bytes)?;
        self.put_file_inner(key, temp.path(), &sha, bytes.len() as u64, hints.class, Some(hints)).await
    }

    async fn put_file_if_absent_with(&self, key: &str, path: &Path, sha256_hex: &str, bytes: u64, hints: &WriteHints) -> Result<bool> {
        self.put_file_inner(key, path, sha256_hex, bytes, hints.class, Some(hints)).await
    }

    async fn register_existing_with(&self, key: &str, sha256_hex: &str, bytes: u64, hints: &WriteHints) -> Result<bool> {
        self.register_stored(key, sha256_hex, bytes, hints).await
    }

    async fn put(&self, key: &str, _bytes: &[u8]) -> Result<()> {
        // Every part-store write is a conditional create. The old `log/HEAD`
        // hint overwrite is gone: no credential scope covers it (least
        // privilege), and readers probe the entries without it.
        bail!("the R2 part store never overwrites ({key})")
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.check_key(key)?;
        self.reader_for(key).delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        // Fence lists to this tenant's prefix like every other access.
        self.check_key(&format!("{prefix}__list_probe__"))?;
        self.reader_for(prefix).list(prefix).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS SigV4 test suite `get-vanilla`.
    #[test]
    fn sigv4_matches_the_aws_get_vanilla_vector() {
        let signer = SigV4 {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            region: "us-east-1".into(),
            service: "service".into(),
        };
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let empty = hex::encode(Sha256::digest(b""));
        let auth = signer.authorization("GET", "/", &headers, &empty, "20150830T123600Z").unwrap();
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn checksum_header_is_padded_standard_base64_of_the_raw_digest() {
        let sha = hex::encode(Sha256::digest(b"part bytes"));
        let value = checksum_header_value(&sha).unwrap();
        assert_eq!(value.len(), 44);
        assert!(value.ends_with('='));
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(&value).unwrap(), hex::decode(&sha).unwrap());
        assert!(checksum_header_value("zz").is_err());
    }

    #[test]
    fn keys_are_uri_encoded_per_segment() {
        assert_eq!(
            uri_encode_path("/b/lake/parts/v1/tenant=x/parts/l0/2026/09/25/10/p/data-00000.parquet"),
            "/b/lake/parts/v1/tenant%3Dx/parts/l0/2026/09/25/10/p/data-00000.parquet"
        );
    }

    const T: &str = "00000000-0000-4000-8000-000000000001";

    async fn serve(status_for: fn(&str, usize) -> u16) -> (std::net::SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<(String, axum::http::HeaderMap, usize)>>>) {
        use axum::{extract::State, http::HeaderMap, routing::put, Router};
        use std::sync::{Arc, Mutex};
        type Seen = Arc<Mutex<Vec<(String, HeaderMap, usize)>>>;
        let seen: Seen = Arc::default();
        let app = Router::new()
            .route(
                "/{*path}",
                put(move |State(seen): State<Seen>, axum::extract::Path(path): axum::extract::Path<String>, headers: HeaderMap, body: axum::body::Bytes| async move {
                    let mut seen = seen.lock().unwrap();
                    let prior = seen.iter().filter(|(p, _, _)| *p == path).count();
                    seen.push((path.clone(), headers, body.len()));
                    let status = status_for(&path, prior);
                    (axum::http::StatusCode::from_u16(status).unwrap(), "<Error><Code>Code</Code></Error>")
                }),
            )
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, seen)
    }

    fn location(addr: std::net::SocketAddr, key: &str) -> S3Location {
        S3Location {
            endpoint: format!("http://{addr}"),
            region: "auto".into(),
            bucket: "nano-shared-r2-t".into(),
            prefix: String::new(),
            access_key_id: key.into(),
            secret_access_key: "s".into(),
            session_token: Some("t".into()),
        }
    }

    #[tokio::test]
    async fn split_store_reads_log_entries_with_log_credential() {
        use axum::{http::HeaderMap, routing::get, Router};
        let app = Router::new().route("/{*path}", get(|headers: HeaderMap| async move {
            if headers.get("authorization").and_then(|v| v.to_str().ok()).is_some_and(|v| v.contains("Credential=log/")) {
                (axum::http::StatusCode::OK, "log")
            } else {
                (axum::http::StatusCode::FORBIDDEN, "wrong class")
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let store = R2PartStore::new_split(&location(addr, "part"), &location(addr, "log"), T, &dir.path().join("spill")).unwrap();
        let key = format!("lake/parts/v1/tenant={T}/log/entries/00000000000000000001.json");
        assert_eq!(store.get(&key).await.unwrap().as_deref(), Some(b"log".as_slice()));
        assert!(store.get("lake/parts/v1/tenant=00000000-0000-4000-8000-000000000002/log/entries/x").await.is_err());
        assert!(store.list("lake/parts/v1/tenant=00000000-0000-4000-8000-000000000002/log/entries/").await.is_err());
        server.abort();
    }

    #[tokio::test]
    async fn put_sends_one_conditional_checksummed_request_and_maps_412() {
        let (addr, seen) = serve(|_, prior| if prior == 0 { 200 } else { 412 }).await;
        let dir = tempfile::tempdir().unwrap();
        let store = R2PartStore::new_split(&location(addr, "part"), &location(addr, "log"), T, &dir.path().join("spill")).unwrap();
        let file = dir.path().join("f");
        std::fs::write(&file, b"hello part").unwrap();
        let sha = hex::encode(Sha256::digest(b"hello part"));
        let key = format!("lake/parts/v1/tenant={T}/parts/l0/x");
        assert!(store.put_file_if_absent(&key, &file, &sha, 10, WriterClass::LakePart).await.unwrap());
        assert!(!store.put_file_if_absent(&key, &file, &sha, 10, WriterClass::LakePart).await.unwrap(), "412 = exists");
        let entry = format!("lake/parts/v1/tenant={T}/log/entries/00000000000000000001.json");
        let hints = WriteHints { class: WriterClass::LakePartLog, event_hour: 0, min_time_ms: 0, max_time_ms: 0 };
        assert!(store.put_if_absent_with(&entry, b"{}", &hints).await.unwrap());
        let seen = seen.lock().unwrap();
        let (path, headers, len) = &seen[0];
        assert_eq!(*path, format!("nano-shared-r2-t/{key}"));
        assert_eq!(*len, 10);
        assert_eq!(headers["x-amz-checksum-sha256"], checksum_header_value(&sha).unwrap().as_str());
        assert_eq!(headers["x-amz-content-sha256"], sha.as_str());
        assert_eq!(headers["if-none-match"], "*");
        assert_eq!(headers["x-amz-security-token"], "t");
        assert!(headers["authorization"].to_str().unwrap().contains("x-amz-checksum-sha256"));
        assert!(headers["authorization"].to_str().unwrap().contains("Credential=part/"));
        // One fixed-length body: never chunked (R2 needs the length for the checksum).
        assert_eq!(headers["content-length"], "10");
        assert!(!headers.contains_key("transfer-encoding"));
        // No other checksum algorithm, no trailer.
        assert!(!headers.contains_key("x-amz-sdk-checksum-algorithm"));
        assert!(!headers.contains_key("x-amz-trailer"));
        assert!(!headers.keys().any(|k| k.as_str().starts_with("x-amz-checksum-") && k.as_str() != "x-amz-checksum-sha256"));
        // Log entries go up with the lake_part_log credential, checksummed too.
        let (_, log_headers, _) = &seen[2];
        assert!(log_headers["authorization"].to_str().unwrap().contains("Credential=log/"));
        assert!(!log_headers.contains_key("transfer-encoding"));
        assert!(log_headers.contains_key("x-amz-checksum-sha256"));
        drop(seen);
        // A size mismatch never sends.
        assert!(store.put_file_if_absent(&key, &file, &sha, 11, WriterClass::LakePart).await.is_err());
        // Spill files live in the state dir and are cleaned up.
        assert_eq!(std::fs::read_dir(dir.path().join("spill")).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn keys_classes_and_statuses_are_enforced() {
        let (addr, _seen) = serve(|path, _| {
            if path.ends_with("/forbidden") {
                403
            } else if path.ends_with("/digest") {
                400
            } else if path.ends_with("/conflict") {
                409
            } else {
                503
            }
        })
        .await;
        let dir = tempfile::tempdir().unwrap();
        let store = R2PartStore::new(&location(addr, "part"), T, &dir.path().join("spill")).unwrap();
        let base = format!("lake/parts/v1/tenant={T}/parts");
        let put = |name: &str| {
            let key = format!("{base}/{name}");
            let store = &store;
            async move { store.put_if_absent(&key, b"x").await.unwrap_err() }
        };
        assert_eq!(put("forbidden").await.downcast_ref::<TerminalPutError>().unwrap().status, 403);
        assert_eq!(put("digest").await.downcast_ref::<TerminalPutError>().unwrap().status, 400);
        assert!(put("conflict").await.downcast_ref::<OwnerConflict>().is_some(), "409 fences");
        assert_eq!(put("busy").await.downcast_ref::<TransientPutError>().unwrap().status, 503);
        // Another tenant's key, traversal, or a wrong class never leave the process.
        let other = "lake/parts/v1/tenant=00000000-0000-4000-8000-000000000002/parts/x";
        assert!(store.put_if_absent(other, b"x").await.is_err());
        assert!(store.put_if_absent(&format!("{base}/../../tenant=x/y"), b"x").await.is_err());
        assert!(store.delete(other).await.is_err());
        assert!(store.put(&format!("{base}/x"), b"x").await.is_err(), "the part store never overwrites");
        let hints = WriteHints { class: WriterClass::LakePartLog, event_hour: 0, min_time_ms: 0, max_time_ms: 0 };
        assert!(store.put_if_absent_with(&format!("{base}/x"), b"x", &hints).await.is_err(), "class/key mismatch");
    }

    /// A fake R2 bucket enforcing prefix-scoped temporary credentials the way
    /// the platform mints them for ingest: access key `part` covers `parts/` +
    /// `log/checkpoints/`, `log` covers `log/entries/`; anything else is 403
    /// (GET, LIST and PUT). Missing in-scope keys are 404, as R2 answers.
    mod scoped_r2 {
        use axum::{
            body::Bytes,
            extract::{Path, Query, State},
            http::{HeaderMap, StatusCode},
            response::{IntoResponse, Response},
            routing::get,
            Router,
        };
        use std::collections::{BTreeMap, HashMap};
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        pub struct Bucket {
            pub objects: BTreeMap<String, Vec<u8>>,
            /// Access key -> key prefixes (relative to `tenant_root`).
            pub scopes: HashMap<String, Vec<String>>,
            pub tenant_root: String,
            /// Every (access key, method, key-or-prefix) seen.
            pub seen: Vec<(String, &'static str, String)>,
        }
        pub type Shared = Arc<Mutex<Bucket>>;

        fn access_of(headers: &HeaderMap) -> String {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
            auth.split("Credential=").nth(1).and_then(|c| c.split('/').next()).unwrap_or("").to_string()
        }

        fn in_scope(bucket: &Bucket, access: &str, key: &str) -> bool {
            bucket.scopes.get(access).is_some_and(|prefixes| prefixes.iter().any(|p| key.starts_with(&format!("{}{p}", bucket.tenant_root))))
        }

        fn denied() -> Response {
            (StatusCode::FORBIDDEN, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>").into_response()
        }

        async fn get_object(State(state): State<Shared>, Path((_b, key)): Path<(String, String)>, headers: HeaderMap) -> Response {
            let mut bucket = state.lock().unwrap();
            let access = access_of(&headers);
            bucket.seen.push((access.clone(), "GET", key.clone()));
            if !in_scope(&bucket, &access, &key) {
                return denied();
            }
            match bucket.objects.get(&key) {
                Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
                None => (StatusCode::NOT_FOUND, "<Error><Code>NoSuchKey</Code></Error>").into_response(),
            }
        }

        async fn list_objects(
            State(state): State<Shared>,
            Path(_b): Path<String>,
            Query(query): Query<HashMap<String, String>>,
            headers: HeaderMap,
        ) -> Response {
            let mut bucket = state.lock().unwrap();
            let access = access_of(&headers);
            let prefix = query.get("prefix").cloned().unwrap_or_default();
            bucket.seen.push((access.clone(), "LIST", prefix.clone()));
            if !in_scope(&bucket, &access, &prefix) {
                return denied();
            }
            let contents: String = bucket
                .objects
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, v)| format!("<Contents><Key>{k}</Key><Size>{}</Size><LastModified>2026-09-28T00:00:00.000Z</LastModified><ETag>\"e\"</ETag></Contents>", v.len()))
                .collect();
            let body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>b</Name><Prefix>{prefix}</Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>");
            (StatusCode::OK, [("content-type", "application/xml")], body).into_response()
        }

        async fn put_object(State(state): State<Shared>, Path((_b, key)): Path<(String, String)>, headers: HeaderMap, body: Bytes) -> Response {
            let mut bucket = state.lock().unwrap();
            let access = access_of(&headers);
            bucket.seen.push((access.clone(), "PUT", key.clone()));
            if !in_scope(&bucket, &access, &key) {
                return denied();
            }
            if headers.get("if-none-match").is_some_and(|v| v == "*") && bucket.objects.contains_key(&key) {
                return (StatusCode::PRECONDITION_FAILED, "<Error><Code>PreconditionFailed</Code></Error>").into_response();
            }
            bucket.objects.insert(key, body.to_vec());
            StatusCode::OK.into_response()
        }

        pub async fn serve(bucket: Bucket) -> (std::net::SocketAddr, Shared) {
            let state: Shared = Arc::new(Mutex::new(bucket));
            let app = Router::new()
                .route("/{bucket}", get(list_objects))
                .route("/{bucket}/", get(list_objects))
                .route("/{bucket}/{*key}", get(get_object).put(put_object))
                .with_state(state.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (addr, state)
        }
    }

    fn log_schema() -> arrow_schema::Schema {
        use arrow_schema::{DataType, Field, Schema, TimeUnit};
        Schema::new(vec![
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
            Field::new("message", DataType::Utf8, true),
        ])
    }

    /// the platform's ingest scopes; `log_scope` lets a test mis-scope the log credential.
    async fn scoped_store(log_scope: &str) -> (R2PartStore, scoped_r2::Shared, tempfile::TempDir) {
        let bucket = scoped_r2::Bucket {
            scopes: [
                ("part".to_string(), vec!["parts/".to_string(), "log/checkpoints/".to_string()]),
                ("log".to_string(), vec![log_scope.to_string()]),
            ]
            .into_iter()
            .collect(),
            tenant_root: format!("lake/parts/v1/tenant={T}/"),
            ..Default::default()
        };
        let (addr, state) = scoped_r2::serve(bucket).await;
        let dir = tempfile::tempdir().unwrap();
        let store = R2PartStore::new_split(&location(addr, "part"), &location(addr, "log"), T, &dir.path().join("spill")).unwrap();
        (store, state, dir)
    }

    /// The live failure on the first lean tenant: log-entry reads went out
    /// with the `lake_part` credential (403 on `log/entries/`). They must use
    /// `lake_part_log`; a missing entry (404) is absent, so genesis commits.
    #[tokio::test]
    async fn fresh_tenant_bootstraps_with_log_reads_on_the_log_credential() {
        use crate::parts::part_log::{load_log, PartLogWriter};
        let (store, state, _dir) = scoped_store("log/entries/").await;
        let writer = PartLogWriter::open(&store, T, 1, &log_schema(), 1_000).await.unwrap();
        assert_eq!(writer.live().head().map(|(seq, _, _)| seq), Some(0));
        {
            let bucket = state.lock().unwrap();
            let entries = format!("lake/parts/v1/tenant={T}/log/entries/");
            assert_eq!(bucket.objects.keys().collect::<Vec<_>>(), vec![&format!("{entries}00000000000000000000.json")], "genesis only; no log/HEAD");
            for (access, method, key) in &bucket.seen {
                let want = if key.starts_with(&entries) { "log" } else { "part" };
                assert_eq!(access, want, "{method} {key} used the wrong credential");
            }
            assert!(bucket.seen.iter().any(|(a, m, _)| a == "log" && *m == "GET"), "entries read via lake_part_log");
            assert!(bucket.seen.iter().any(|(a, m, _)| a == "part" && *m == "LIST"), "checkpoints listed via lake_part");
        }
        // Existing log: read back, not re-created.
        assert_eq!(load_log(&store, T).await.unwrap().head().map(|(seq, _, _)| seq), Some(0));
        let writer = PartLogWriter::open(&store, T, 1, &log_schema(), 2_000).await.unwrap();
        assert_eq!(writer.live().head().map(|(seq, _, _)| seq), Some(0));
        assert_eq!(state.lock().unwrap().objects.len(), 1);
        // Listing the entries prefix also routes to the log credential.
        assert_eq!(store.list(&format!("lake/parts/v1/tenant={T}/log/entries/")).await.unwrap().len(), 1);
        assert!(store.put(&format!("lake/parts/v1/tenant={T}/log/HEAD"), b"{}").await.is_err(), "no overwrites");
    }

    /// A 403 is never "absent": a denied log credential fails the open loudly
    /// and never writes a genesis over a log it could not read.
    #[tokio::test]
    async fn a_denied_log_read_fails_loudly_and_writes_nothing() {
        use crate::parts::part_log::PartLogWriter;
        let (store, state, _dir) = scoped_store("log/other/").await;
        let error = PartLogWriter::open(&store, T, 1, &log_schema(), 1_000).await.err().expect("must fail");
        let denied = error.chain().any(|c| c.downcast_ref::<opendal::Error>().is_some_and(|e| e.kind() == opendal::ErrorKind::PermissionDenied));
        assert!(denied, "{error:#}");
        let bucket = state.lock().unwrap();
        assert!(bucket.objects.is_empty());
        assert!(!bucket.seen.iter().any(|(_, m, _)| *m == "PUT"), "no genesis attempted");
    }
    async fn native_store(fail_complete: bool, put_status: u16) -> (R2PartStore, tempfile::TempDir,
        std::sync::Arc<std::sync::atomic::AtomicUsize>, std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use axum::{routing::put, Router};
        let (writer, dir, a, c, owner) = super::super::native_writer::tests::fixture_for(fail_complete, T, "nano-shared-r2-t").await;
        let puts = Arc::new(AtomicUsize::new(0)); let count = puts.clone(); let authorized = a.clone();
        let app = Router::new().route("/{*path}", put(move |axum::extract::Path(path): axum::extract::Path<String>, headers: axum::http::HeaderMap| {
            let count = count.clone(); let authorized = authorized.clone();
            async move {
                if !path.contains("/finding-outbox/receipts/") && !path.ends_with("/log/checkpoints/finding-attempt-index-v1") && !path.contains("/log/checkpoints/count-backfill-v1/") && !path.contains("/log/checkpoints/prevalence-restamp-v1/") { assert!(authorized.load(Ordering::SeqCst) > 0, "authorize must precede provider PUT"); }
                assert_eq!(headers["if-none-match"], "*");
                let expected = if path.contains("/log/entries/") { "Credential=log/" } else { "Credential=part/" };
                assert!(headers["authorization"].to_str().unwrap().contains(expected));
                count.fetch_add(1, Ordering::SeqCst);
                (axum::http::StatusCode::from_u16(put_status).unwrap(), [("etag", "\"actual-put-etag\"")], "")
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let addr = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let store = R2PartStore::new_split(&location(addr, "part"), &location(addr, "log"), T, &dir.path().join("spill")).unwrap()
            .with_native_writer(Arc::new(writer)).unwrap();
        (store, dir, a, c, puts, owner, provider)
    }

    #[tokio::test]
    async fn native_data_and_log_complete_503_replays_same_put_etag_without_put_or_authorize() {
        use std::sync::atomic::Ordering;
        for (family, class) in [("parts/l0/object", WriterClass::LakePart), ("log/entries/00000000000000000001.json", WriterClass::LakePartLog)] {
            let (store, dir, a, c, puts, owner, provider) = native_store(true, 200).await;
            let key = format!("lake/parts/v1/tenant={T}/{family}");
            let hints = WriteHints { class, event_hour: 1, min_time_ms: 3600000, max_time_ms: 3600001 };
            assert!(store.put_if_absent_with(&key, b"payload", &hints).await.is_err());
            let intent = std::fs::read_dir(dir.path().join("native-writer-receipts/pending")).unwrap().next().unwrap().unwrap().path();
            let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&intent).unwrap()).unwrap();
            assert_eq!(saved["object"]["etag"], "\"actual-put-etag\"");
            assert_eq!(saved["request"]["min_event_time"], "1970-01-01T01:00:00.000Z");
            assert_eq!(saved["request"]["max_event_time"], "1970-01-01T01:00:00.001Z");
            assert!(store.put_if_absent_with(&key, b"payload", &hints).await.unwrap());
            assert!(store.put_if_absent_with(&key, b"payload", &hints).await.unwrap());
            assert_eq!(a.load(Ordering::SeqCst), 1); assert_eq!(c.load(Ordering::SeqCst), 2); assert_eq!(puts.load(Ordering::SeqCst), 1);
            owner.abort(); provider.abort();
        }
    }

    #[tokio::test]
    async fn native_unknown_upload_and_412_never_complete_or_retry_put() {
        use std::sync::atomic::Ordering;
        for status in [503, 412] {
            let (store, _dir, a, c, puts, owner, provider) = native_store(false, status).await;
            let key = format!("lake/parts/v1/tenant={T}/parts/l0/object");
            let hints = WriteHints { class: WriterClass::LakePart, event_hour: 1, min_time_ms: 3600000, max_time_ms: 3600001 };
            let result = store.put_if_absent_with(&key, b"payload", &hints).await;
            if status == 412 { assert!(!result.unwrap()); } else { assert!(result.is_err()); }
            assert!(store.put_if_absent_with(&key, b"payload", &hints).await.unwrap_err().to_string().contains("unresolved"));
            assert_eq!(a.load(Ordering::SeqCst), 1); assert_eq!(c.load(Ordering::SeqCst), 0); assert_eq!(puts.load(Ordering::SeqCst), 1);
            owner.abort(); provider.abort();
        }
    }

    #[tokio::test]
    async fn native_missing_hints_fail_closed_but_finding_receipts_keep_exact_scoped_path() {
        use std::sync::atomic::Ordering;
        let (store, dir, a, c, puts, owner, provider) = native_store(false, 200).await;
        for family in ["parts/l0/object", "log/entries/00000000000000000001.json", "log/checkpoints/00000000000000000001.json"] {
            assert!(store.put_if_absent(&format!("lake/parts/v1/tenant={T}/{family}"), b"payload").await.is_err());
        }
        let file = dir.path().join("payload"); std::fs::write(&file, b"payload").unwrap();
        assert!(store.put_file_if_absent(&format!("lake/parts/v1/tenant={T}/parts/l0/object"), &file, &hex::encode(Sha256::digest(b"payload")), 7, WriterClass::LakePart).await.is_err());
        assert_eq!(puts.load(Ordering::SeqCst), 0);
        assert!(store.put_if_absent(&format!("lake/parts/v1/tenant={T}/finding-outbox/receipts/request.json"), b"payload").await.unwrap());
        assert!(store.put_if_absent(&format!("lake/parts/v1/tenant={T}/finding-outbox/receipts-foreign/request.json"), b"payload").await.is_err());
        let marker = format!("lake/parts/v1/tenant={T}/log/checkpoints/finding-attempt-index-v1");
        assert!(store.put_if_absent(&marker, super::super::ingest::FINDING_ATTEMPT_INDEX_READY.as_bytes()).await.unwrap());
        for suffix in ["finding-attempt-index-v1.json", "finding-attempt-index-v10", "finding-attempt-index-v1/child"] {
            assert!(store.put_if_absent(&format!("lake/parts/v1/tenant={T}/log/checkpoints/{suffix}"), b"payload").await.is_err());
        }
        assert_eq!(a.load(Ordering::SeqCst), 0); assert_eq!(c.load(Ordering::SeqCst), 0); assert_eq!(puts.load(Ordering::SeqCst), 2);
        // Count-backfill admissions take the same scoped direct path.
        let backfill = format!("lake/parts/v1/tenant={T}/log/checkpoints/{}1800000000000-0123456789abcdef.json",
            super::super::ingest::COUNT_BACKFILL_DIR);
        assert!(store.put_if_absent(&backfill, b"{}").await.unwrap());
        assert_eq!(a.load(Ordering::SeqCst), 0); assert_eq!(c.load(Ordering::SeqCst), 0); assert_eq!(puts.load(Ordering::SeqCst), 3);
        // NAN-3864: owed prevalence restamp snapshots too.
        let owed = format!("lake/parts/v1/tenant={T}/log/checkpoints/{}1800000000000-0123456789abcdef.json",
            super::super::ingest::PREVALENCE_RESTAMP_DIR);
        assert!(store.put_if_absent(&owed, b"[]").await.unwrap());
        assert_eq!(a.load(Ordering::SeqCst), 0); assert_eq!(c.load(Ordering::SeqCst), 0); assert_eq!(puts.load(Ordering::SeqCst), 4);
        let hints = WriteHints { class: WriterClass::LakePart, event_hour: 1, min_time_ms: 3600000, max_time_ms: 3600001 };
        assert!(store.put_if_absent_with(&format!("lake/parts/v1/tenant={T}/log/checkpoints/00000000000000000001.json"), b"payload", &hints).await.unwrap());
        assert_eq!(a.load(Ordering::SeqCst), 1); assert_eq!(c.load(Ordering::SeqCst), 1); assert_eq!(puts.load(Ordering::SeqCst), 5);
        owner.abort(); provider.abort();
    }

    /// NAN-3499: an object another principal already stored (the detect
    /// finding drain) is registered by authorize + provider HEAD + complete,
    /// never re-PUT; the completion carries the HEAD's strong ETag.
    #[tokio::test]
    async fn native_register_existing_authorizes_heads_and_completes_without_put() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use axum::{routing::get, Router};
        let (writer, dir, a, c, owner) = super::super::native_writer::tests::fixture_for(false, T, "nano-shared-r2-t").await;
        let puts = Arc::new(AtomicUsize::new(0));
        let count = puts.clone();
        let app = Router::new().route("/{*path}", get(|| async { ([("etag", "\"actual-put-etag\"")], "payload") })
            .put(move || { let count = count.clone(); async move { count.fetch_add(1, Ordering::SeqCst); axum::http::StatusCode::OK } }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let provider = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let store = R2PartStore::new_split(&location(addr, "part"), &location(addr, "log"), T, &dir.path().join("spill")).unwrap()
            .with_native_writer(Arc::new(writer)).unwrap();
        let sha = hex::encode(Sha256::digest(b"payload"));
        let hints = WriteHints { class: WriterClass::LakePart, event_hour: 1, min_time_ms: 3600000, max_time_ms: 3600001 };
        let key = format!("lake/parts/v1/tenant={T}/parts/l0/finding-object");
        assert!(store.register_existing_with(&key, &sha, 8, &hints).await.unwrap_err().to_string().contains("length 7 differs"));
        assert_eq!(c.load(Ordering::SeqCst), 0, "a length mismatch never completes");
        let other = format!("lake/parts/v1/tenant={T}/parts/l0/finding-object-2");
        assert!(store.register_existing_with(&other, &sha, 7, &hints).await.unwrap());
        assert_eq!(c.load(Ordering::SeqCst), 1, "HEAD-verified completion");
        assert_eq!(puts.load(Ordering::SeqCst), 0, "registration never PUTs");
        let log_hints = WriteHints { class: WriterClass::LakePartLog, ..hints };
        assert!(store.register_existing_with(&format!("lake/parts/v1/tenant={T}/log/entries/00000000000000000001.json"), &sha, 7, &log_hints).await.is_err());
        assert!(a.load(Ordering::SeqCst) >= 2);
        let plain = R2PartStore::new_split(&location(addr, "part"), &location(addr, "log"), T, &dir.path().join("spill2")).unwrap();
        assert!(!plain.register_existing_with(&other, &sha, 7, &hints).await.unwrap(), "no writer authority: nothing registered");
        owner.abort(); provider.abort();
    }

}
