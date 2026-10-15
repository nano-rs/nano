// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable search-job record signing (NAN-2361, hosted-shared review P1).
//!
//! Dragonfly holds every tenant's durable job hash in one shared keyspace.
//! Before this module the only thing binding a record to its tenant was the
//! key prefix, so any process with a Redis socket could forge a queued job for
//! another tenant (copying that tenant's `authority_json` / generation pin from
//! an existing hash) and that tenant's runner would execute it under the
//! tenant's own lake credentials.
//!
//! The search service now signs every durable record it enqueues with an
//! HMAC-SHA256 over a canonical, length-prefixed serialization of the
//! tenant-stamped identity and every field the runner trusts. The runner holds
//! only its own tenant's derived key and verifies the signature on claim,
//! before any credential or authority is touched.
//!
//! Key hierarchy:
//! - search holds a 32-byte master key (`NANO_SEARCH_JOB_SIGNING_KEY_FILE`);
//! - per-tenant key = HKDF-SHA256(master, salt = [`JOB_SIGNING_HKDF_SALT`],
//!   info = lowercase hyphenated tenant UUID), 32 bytes;
//! - a runner receives ONLY its tenant's derived key
//!   (`--job-signing-key-file` / `NANO_LAKE_JOB_SIGNING_KEY_FILE`).
//!
//! HKDF is written out by hand (RFC 5869 extract + one expand block) on top of
//! the workspace `hmac`/`sha2` pair so no extra crate is pulled in; the RFC
//! test vector lives in the test file.

use std::path::Path;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Provider-neutral transport envelope. JSON fields remain exact signed strings:
/// a storage adapter must not parse and re-serialize them before verification.
/// Callers derive `job_key` from trusted tenant/retention/assignment/epoch context,
/// never from the envelope itself. The existing Redis signing format is unchanged.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJobEnvelope {
    pub tenant_id: String,
    pub job_id: String,
    pub backend: String,
    pub user_id: String,
    pub priority: String,
    pub created_at_ms: String,
    pub request_json: String,
    pub task_json: String,
    pub generation_pin_json: String,
    pub authority_json: String,
    pub scope_deny: String,
    pub scope_artifact_deny: String,
    pub signature: String,
}

impl std::fmt::Debug for DurableJobEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableJobEnvelope").finish_non_exhaustive()
    }
}

impl DurableJobEnvelope {
    pub fn signed_record<'a>(&'a self, job_key: &'a str) -> DurableJobSignedRecord<'a> {
        DurableJobSignedRecord {
            job_key,
            tenant_id: &self.tenant_id,
            job_id: &self.job_id,
            backend: &self.backend,
            user_id: &self.user_id,
            priority: &self.priority,
            created_at_ms: &self.created_at_ms,
            request_json: &self.request_json,
            task_json: &self.task_json,
            generation_pin_json: &self.generation_pin_json,
            authority_json: &self.authority_json,
            scope_deny: &self.scope_deny,
            scope_artifact_deny: &self.scope_artifact_deny,
        }
    }

    /// Authenticate transport bytes before decoding any authority/request data.
    /// This is not semantic validation: the existing tenant, scope, generation,
    /// task and result-retention validators are still mandatory after this call.
    pub fn verify(
        &self,
        signer: &DurableJobSigningKey,
        expected_job_key: &str,
        expected_job_id: Uuid,
    ) -> Result<(), DurableJobSigningError> {
        if self.tenant_id != signer.tenant_id().to_string()
            || self.job_id != expected_job_id.to_string()
            || self.backend != "lake_durable"
            || expected_job_key.is_empty()
            || expected_job_key.len() > 1024
        {
            return Err(DurableJobSigningError::Mismatch);
        }
        let record = self.signed_record(expected_job_key);
        if record.canonical_bytes().len() > 65_536 {
            return Err(DurableJobSigningError::Malformed);
        }
        signer.verify(&record, &self.signature)
    }
}

/// HKDF salt for per-tenant key derivation. Bump the suffix on any change to
/// the canonical serialization below: the version is part of the key.
pub const JOB_SIGNING_HKDF_SALT: &[u8] = b"nano-search-job-signing-v1";
/// Domain-separation tag folded into every signed message.
const JOB_SIGNATURE_DOMAIN: &[u8] = b"nano-search-durable-job-record-v1";
/// Redis hash field that carries the hex-encoded signature.
pub const JOB_SIGNATURE_FIELD: &str = "signature";
/// Key material size in bytes (master and derived).
pub const JOB_SIGNING_KEY_BYTES: usize = 32;
const MAX_KEY_FILE_BYTES: u64 = 256;

#[derive(Debug, thiserror::Error)]
pub enum DurableJobSigningError {
    #[error("durable job signing key file {0}")]
    KeyFile(String),
    #[error("durable job signing key must be 32 raw bytes or 64 hex characters")]
    KeyLength,
    #[error("durable job record is unsigned")]
    Unsigned,
    #[error("durable job record signature is malformed")]
    Malformed,
    #[error("durable job record signature does not verify under this tenant's key")]
    Mismatch,
}

/// Master signing key held only by the search service.
pub struct DurableJobSigningMasterKey {
    key: [u8; JOB_SIGNING_KEY_BYTES],
}

impl std::fmt::Debug for DurableJobSigningMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableJobSigningMasterKey").finish()
    }
}

impl Drop for DurableJobSigningMasterKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DurableJobSigningMasterKey {
    pub fn from_bytes(key: [u8; JOB_SIGNING_KEY_BYTES]) -> Self {
        Self { key }
    }

    /// Load the master key from a private (mode `0400`/`0600`, owner-only)
    /// regular file containing 32 raw bytes or 64 hex characters.
    pub fn from_file(path: &Path) -> Result<Self, DurableJobSigningError> {
        Ok(Self::from_bytes(read_key_file(path)?))
    }

    /// Derive the tenant's signing key: HKDF-SHA256(master, salt, tenant UUID).
    pub fn derive_tenant_key(&self, tenant_id: Uuid) -> DurableJobSigningKey {
        let info = tenant_id.as_hyphenated().to_string().to_ascii_lowercase();
        let key = hkdf_sha256_32(&self.key, JOB_SIGNING_HKDF_SALT, info.as_bytes());
        DurableJobSigningKey { key, tenant_id }
    }
}

/// Per-tenant signing/verification key. The runner receives exactly one.
#[derive(Clone)]
pub struct DurableJobSigningKey {
    key: [u8; JOB_SIGNING_KEY_BYTES],
    tenant_id: Uuid,
}

impl std::fmt::Debug for DurableJobSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableJobSigningKey")
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

impl Drop for DurableJobSigningKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DurableJobSigningKey {
    pub fn from_bytes(key: [u8; JOB_SIGNING_KEY_BYTES], tenant_id: Uuid) -> Self {
        Self { key, tenant_id }
    }

    /// Load a derived tenant key from a private regular file (same format and
    /// mode rules as the master key).
    pub fn from_file(path: &Path, tenant_id: Uuid) -> Result<Self, DurableJobSigningError> {
        Ok(Self::from_bytes(read_key_file(path)?, tenant_id))
    }

    /// Hex-encode the derived key for delivery to a runner Secret. Only the
    /// materialization tooling should call this.
    pub fn to_hex(&self) -> String {
        hex::encode(self.key)
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Sign a durable job record. Returns lowercase hex of the 32-byte tag.
    pub fn sign(&self, record: &DurableJobSignedRecord<'_>) -> String {
        hex::encode(self.tag(record))
    }

    /// Verify a stored signature in constant time.
    pub fn verify(
        &self,
        record: &DurableJobSignedRecord<'_>,
        signature_hex: &str,
    ) -> Result<(), DurableJobSigningError> {
        if signature_hex.is_empty() {
            return Err(DurableJobSigningError::Unsigned);
        }
        if signature_hex.len() != 64 {
            return Err(DurableJobSigningError::Malformed);
        }
        let presented = hex::decode(signature_hex).map_err(|_| DurableJobSigningError::Malformed)?;
        let mut mac = self.mac();
        mac.update(&record.canonical_bytes());
        mac.verify_slice(&presented)
            .map_err(|_| DurableJobSigningError::Mismatch)
    }

    fn mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length")
    }

    fn tag(&self, record: &DurableJobSignedRecord<'_>) -> [u8; 32] {
        let mut mac = self.mac();
        mac.update(&record.canonical_bytes());
        mac.finalize().into_bytes().into()
    }
}

/// Every field the runner trusts from a claimed record, plus the physical
/// key the record lives under. The physical key binds tenant UUID, retention
/// identity and worker-assignment revision, so a hash copied into another
/// tenant's or another revision's namespace cannot verify.
///
/// Runner-owned mutable fields (`status`, `attempt`, `fence`, `lease_*`,
/// `error`, `progress_json`, `result_ref_json`, `resource_class`,
/// `execution_failures`, `lease_recoveries`, `completed_at_ms`,
/// `queue_position`) are deliberately NOT covered: they are fenced by the
/// claim CAS on `lease_owner`/`attempt`/`fence` and never re-read as
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableJobSignedRecord<'a> {
    /// Full Redis hash key, e.g. `search:{jobs:<uuid>:assignment:<rev>}:job:<id>`.
    pub job_key: &'a str,
    /// Tenant stamp stored in the record (`""` in the dedicated keyspace).
    pub tenant_id: &'a str,
    pub job_id: &'a str,
    pub backend: &'a str,
    pub user_id: &'a str,
    pub priority: &'a str,
    pub created_at_ms: &'a str,
    pub request_json: &'a str,
    pub task_json: &'a str,
    pub generation_pin_json: &'a str,
    /// Serialized [`super::DurableSearchJobAuthority`]; carries `access_jti`
    /// or the automation-key identity, roles, permissions and revisions.
    pub authority_json: &'a str,
    pub scope_deny: &'a str,
    pub scope_artifact_deny: &'a str,
}

impl DurableJobSignedRecord<'_> {
    /// Canonical serialization: domain tag, then each field as
    /// `u64 little-endian byte length || bytes`, in declaration order. Length
    /// prefixes make the encoding injective; no field boundary can be moved
    /// by choosing values that contain separators.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let fields: [&[u8]; 14] = [
            JOB_SIGNATURE_DOMAIN,
            self.job_key.as_bytes(),
            self.tenant_id.as_bytes(),
            self.job_id.as_bytes(),
            self.backend.as_bytes(),
            self.user_id.as_bytes(),
            self.priority.as_bytes(),
            self.created_at_ms.as_bytes(),
            self.request_json.as_bytes(),
            self.task_json.as_bytes(),
            self.generation_pin_json.as_bytes(),
            self.authority_json.as_bytes(),
            self.scope_deny.as_bytes(),
            self.scope_artifact_deny.as_bytes(),
        ];
        let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 8).sum());
        for field in fields {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());
            out.extend_from_slice(field);
        }
        out
    }
}

/// RFC 5869 HKDF-SHA256 producing exactly one 32-byte output block.
pub fn hkdf_sha256_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC(salt, IKM)
    let mut extract = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    // Expand (L = 32 = one block): T(1) = HMAC(PRK, info || 0x01)
    let mut expand = HmacSha256::new_from_slice(&prk).expect("HMAC accepts any key length");
    expand.update(info);
    expand.update(&[0x01]);
    let okm: [u8; 32] = expand.finalize().into_bytes().into();
    okm
}

/// Parse key material: 32 raw bytes, or 64 hex characters with optional
/// trailing whitespace.
pub fn parse_key_material(bytes: &[u8]) -> Result<[u8; JOB_SIGNING_KEY_BYTES], DurableJobSigningError> {
    if bytes.len() == JOB_SIGNING_KEY_BYTES {
        let mut key = [0_u8; JOB_SIGNING_KEY_BYTES];
        key.copy_from_slice(bytes);
        return Ok(key);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| DurableJobSigningError::KeyLength)?
        .trim();
    if text.len() != 2 * JOB_SIGNING_KEY_BYTES
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DurableJobSigningError::KeyLength);
    }
    let decoded = hex::decode(text).map_err(|_| DurableJobSigningError::KeyLength)?;
    decoded
        .try_into()
        .map_err(|_| DurableJobSigningError::KeyLength)
}

#[cfg(unix)]
fn read_key_file(path: &Path) -> Result<[u8; JOB_SIGNING_KEY_BYTES], DurableJobSigningError> {
    use std::os::unix::fs::PermissionsExt;

    let describe = |message: &str| DurableJobSigningError::KeyFile(format!("{}: {message}", path.display()));
    if !path.is_absolute() {
        return Err(describe("path is not absolute"));
    }
    // Same admission rule as the other private key files in this repository
    // (`generation_bundle_signer`, `shared_writer`): one bounded
    // regular file, no symlink, owner-only mode (0400 or 0600). Kubernetes
    // Secret items are symlinks; mount the key with `subPath` to get a
    // regular file.
    let metadata = std::fs::symlink_metadata(path).map_err(|error| describe(&error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(describe("is not a regular file"));
    }
    if metadata.len() == 0 || metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(describe("has an implausible size"));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o400 && mode != 0o600 {
        return Err(describe("mode must be 0400 or 0600"));
    }
    let mut bytes = std::fs::read(path).map_err(|error| describe(&error.to_string()))?;
    let key = parse_key_material(&bytes);
    bytes.zeroize();
    key
}

#[cfg(not(unix))]
fn read_key_file(path: &Path) -> Result<[u8; JOB_SIGNING_KEY_BYTES], DurableJobSigningError> {
    Err(DurableJobSigningError::KeyFile(format!(
        "{}: private key files require a unix filesystem",
        path.display()
    )))
}

#[cfg(test)]
#[path = "job_signing_tests.rs"]
mod tests;
