// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-owned enterprise-shared object-cache identity and namespace.
//!
//! This module deliberately does not accept HTTP request values. A lake worker
//! constructs one authority after loading its signed tenant assignment, then
//! derives every cache path from that authority plus an immutable object
//! identity proven by the signed serving manifest and object-store metadata.
//! Dedicated/open-core workers do not construct this type and retain their
//! historical cache layout.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const MARKER_SCHEMA_VERSION: u32 = 1;
const CACHE_KEY_DOMAIN: &[u8] = b"nano.enterprise_shared.r2.object-cache.v1";
const AUTHORITY_DOMAIN: &[u8] = b"nano.enterprise_shared.r2.cache-authority.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheEncryptionProvider {
    /// The cache is mounted from tmpfs and therefore has no at-rest bytes.
    /// The deployment must verify the filesystem type before starting the
    /// worker; this is the safe fallback when the node CSI layer cannot attest
    /// encryption at rest.
    MemoryEphemeral,
    CsiEncrypted,
    CephRbdEncrypted,
    DmCrypt,
    Luks2,
}

impl CacheEncryptionProvider {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "memory-ephemeral" => Ok(Self::MemoryEphemeral),
            "csi-encrypted" => Ok(Self::CsiEncrypted),
            "ceph-rbd-encrypted" => Ok(Self::CephRbdEncrypted),
            "dm-crypt" => Ok(Self::DmCrypt),
            "luks2" => Ok(Self::Luks2),
            _ => bail!("enterprise-shared cache encryption provider is unsupported"),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::MemoryEphemeral => "memory-ephemeral",
            Self::CsiEncrypted => "csi-encrypted",
            Self::CephRbdEncrypted => "ceph-rbd-encrypted",
            Self::DmCrypt => "dm-crypt",
            Self::Luks2 => "luks2",
        }
    }
}

/// Non-secret, server-derived authority for exactly one tenant cache.
///
/// `credential_id` is an opaque rotation identity, never credential material.
/// The separately injected runtime credential must be bucket-scoped and
/// read-only; the exact bucket and read-only assertion are repeated here so a
/// provisioning mismatch fails before any remote read or cache hit.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantObjectCacheAuthority {
    tenant_id: Uuid,
    bucket: String,
    credential_id: String,
    assignment_revision: u64,
    purge_epoch: u64,
    encryption_provider: CacheEncryptionProvider,
    encryption_key_id: String,
    encryption_key_revision: u64,
    tenant_max_bytes: u64,
    cell_max_bytes: u64,
}

impl std::fmt::Debug for TenantObjectCacheAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantObjectCacheAuthority")
            .field("tenant_id", &self.tenant_id)
            .field("bucket", &self.bucket)
            .field("assignment_revision", &self.assignment_revision)
            .field("purge_epoch", &self.purge_epoch)
            .field("encryption_provider", &self.encryption_provider)
            .field("encryption_key_revision", &self.encryption_key_revision)
            .field("tenant_max_bytes", &self.tenant_max_bytes)
            .field("cell_max_bytes", &self.cell_max_bytes)
            .finish_non_exhaustive()
    }
}

impl TenantObjectCacheAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: Uuid,
        bucket: String,
        credential_id: String,
        credential_bucket: &str,
        credential_is_read_only: bool,
        assignment_revision: u64,
        purge_epoch: u64,
        encryption_provider: CacheEncryptionProvider,
        encryption_key_id: String,
        encryption_key_revision: u64,
        tenant_max_bytes: u64,
        cell_max_bytes: u64,
    ) -> Result<Self> {
        if !valid_bucket(&bucket) || credential_bucket != bucket || !credential_is_read_only {
            bail!("enterprise-shared cache requires one exact bucket-scoped read-only credential");
        }
        if !valid_token(&credential_id, 256) || !valid_token(&encryption_key_id, 256) {
            bail!("enterprise-shared cache credential or encryption identity is invalid");
        }
        if assignment_revision == 0
            || purge_epoch == 0
            || encryption_key_revision == 0
            || tenant_max_bytes == 0
            || cell_max_bytes == 0
            || tenant_max_bytes > cell_max_bytes
            || cell_max_bytes > (1_u64 << 60)
        {
            bail!("enterprise-shared cache revision or byte quota is invalid");
        }
        Ok(Self {
            tenant_id,
            bucket,
            credential_id,
            assignment_revision,
            purge_epoch,
            encryption_provider,
            encryption_key_id,
            encryption_key_revision,
            tenant_max_bytes,
            cell_max_bytes,
        })
    }

    pub const fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub const fn tenant_max_bytes(&self) -> u64 {
        self.tenant_max_bytes
    }

    pub const fn cell_max_bytes(&self) -> u64 {
        self.cell_max_bytes
    }

    pub fn authority_digest(&self) -> String {
        let mut identity = Vec::new();
        push_field(&mut identity, AUTHORITY_DOMAIN);
        push_field(&mut identity, self.tenant_id.as_bytes());
        push_field(&mut identity, self.bucket.as_bytes());
        push_field(
            &mut identity,
            &Sha256::digest(self.credential_id.as_bytes()),
        );
        push_field(&mut identity, &self.assignment_revision.to_le_bytes());
        push_field(&mut identity, &self.purge_epoch.to_le_bytes());
        push_field(&mut identity, self.encryption_provider.as_str().as_bytes());
        push_field(
            &mut identity,
            &Sha256::digest(self.encryption_key_id.as_bytes()),
        );
        push_field(&mut identity, &self.encryption_key_revision.to_le_bytes());
        push_field(&mut identity, &self.tenant_max_bytes.to_le_bytes());
        push_field(&mut identity, &self.cell_max_bytes.to_le_bytes());
        hex::encode(Sha256::digest(identity))
    }

    fn marker(&self) -> TenantCacheMarker {
        TenantCacheMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            tenant_id: self.tenant_id,
            bucket: self.bucket.clone(),
            credential_id_sha256: hex::encode(Sha256::digest(self.credential_id.as_bytes())),
            assignment_revision: self.assignment_revision,
            purge_epoch: self.purge_epoch,
            encryption_provider: self.encryption_provider.clone(),
            encryption_key_id_sha256: hex::encode(Sha256::digest(
                self.encryption_key_id.as_bytes(),
            )),
            encryption_key_revision: self.encryption_key_revision,
            tenant_max_bytes: self.tenant_max_bytes,
            cell_max_bytes: self.cell_max_bytes,
            authority_sha256: self.authority_digest(),
        }
    }
}

/// Exact immutable identity used to derive one canonical cache filename.
/// The caller is trusted worker code, never a public request decoder.
pub(crate) struct TenantObjectCacheIdentity<'a> {
    pub(crate) tenant_id: Uuid,
    pub(crate) dataset: &'a str,
    pub(crate) bucket: &'a str,
    pub(crate) object_key: &'a str,
    /// Provider version where available (S3 version ID or R2 object version).
    pub(crate) version_id: Option<&'a str>,
    /// Provider ETag where available. At least one of version/ETag is required.
    pub(crate) etag: Option<&'a str>,
    pub(crate) content_sha256: &'a str,
    pub(crate) size_bytes: u64,
    pub(crate) query_generation: &'a str,
    pub(crate) schema_generation: &'a str,
    pub(crate) runtime_generation: &'a str,
}

#[derive(Clone, Debug)]
pub struct TenantObjectCacheNamespace {
    authority: TenantObjectCacheAuthority,
    cell_root: PathBuf,
    tenant_root: PathBuf,
    objects: PathBuf,
    pins: PathBuf,
    global_lock: PathBuf,
}

impl TenantObjectCacheNamespace {
    pub fn open(base_root: &Path, authority: TenantObjectCacheAuthority) -> Result<Self> {
        if !base_root.is_absolute() {
            bail!("enterprise-shared cache root must be absolute");
        }
        ensure_private_directory(base_root)?;
        let cell_root = base_root.join("enterprise-shared");
        ensure_private_directory(&cell_root)?;
        let tenant_root = cell_root.join(authority.tenant_id.to_string());
        let objects = tenant_root.join("objects");
        let pins = tenant_root.join("pins");
        let namespace = Self {
            authority,
            global_lock: cell_root.join(".cache.lock"),
            cell_root,
            tenant_root,
            objects,
            pins,
        };
        namespace.with_global_lock(|| {
            namespace.verify_or_initialize_cell_marker()?;
            namespace.reject_cross_tenant_bucket_or_credential_reuse()?;
            ensure_private_directory(&namespace.tenant_root)?;
            ensure_private_directory(&namespace.objects)?;
            ensure_private_directory(&namespace.pins)?;
            namespace.verify_or_initialize_marker()
        })?;
        namespace.ensure_cell_fits(0)?;
        Ok(namespace)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.tenant_root
    }

    pub(crate) const fn tenant_id(&self) -> Uuid {
        self.authority.tenant_id()
    }

    pub(crate) fn objects(&self) -> &Path {
        &self.objects
    }

    pub(crate) fn pins(&self) -> &Path {
        &self.pins
    }

    pub(crate) fn global_lock_path(&self) -> &Path {
        &self.global_lock
    }

    pub(crate) fn credential_id(&self) -> &str {
        self.authority.credential_id()
    }

    pub(crate) const fn tenant_max_bytes(&self) -> u64 {
        self.authority.tenant_max_bytes()
    }

    pub(crate) fn cache_key(&self, object: &TenantObjectCacheIdentity<'_>) -> Result<String> {
        if object.tenant_id != self.authority.tenant_id || object.bucket != self.authority.bucket {
            bail!("enterprise-shared cache object belongs to another tenant or bucket");
        }
        for (label, value) in [
            ("dataset", object.dataset),
            ("object key", object.object_key),
            ("query generation", object.query_generation),
            ("schema generation", object.schema_generation),
            ("runtime generation", object.runtime_generation),
        ] {
            if !valid_identity(value, 4_096) {
                bail!("enterprise-shared cache {label} is invalid");
            }
        }
        if object.object_key.split('/').any(|part| part == "..")
            || object.size_bytes == 0
            || !valid_sha256(object.content_sha256)
            || !valid_optional_provider_identity(object.version_id)
            || !valid_optional_provider_identity(object.etag)
            || (object.version_id.is_none() && object.etag.is_none())
        {
            bail!("enterprise-shared cache object identity is invalid");
        }

        let mut identity = Vec::new();
        push_field(&mut identity, CACHE_KEY_DOMAIN);
        push_field(&mut identity, self.authority.authority_digest().as_bytes());
        push_field(&mut identity, object.tenant_id.as_bytes());
        push_field(&mut identity, object.dataset.as_bytes());
        push_field(&mut identity, object.bucket.as_bytes());
        push_field(&mut identity, object.object_key.as_bytes());
        push_optional_field(&mut identity, object.version_id);
        push_optional_field(&mut identity, object.etag);
        push_field(&mut identity, object.content_sha256.as_bytes());
        push_field(&mut identity, &object.size_bytes.to_le_bytes());
        push_field(&mut identity, object.query_generation.as_bytes());
        push_field(&mut identity, object.schema_generation.as_bytes());
        push_field(&mut identity, object.runtime_generation.as_bytes());
        Ok(hex::encode(Sha256::digest(identity)))
    }

    /// Fail closed when the encrypted cache cell cannot fit an additional
    /// object. Eviction is tenant-local; one tenant never deletes another
    /// tenant's cache entry. Provisioning must keep the sum of tenant quotas
    /// within this cell ceiling.
    pub fn ensure_cell_fits(&self, additional_bytes: u64) -> Result<()> {
        let used = physical_parquet_bytes(&self.cell_root)?;
        if used.saturating_add(additional_bytes) > self.authority.cell_max_bytes {
            bail!(
                "enterprise-shared cache cell needs {} bytes above its {} byte bound",
                used.saturating_add(additional_bytes),
                self.authority.cell_max_bytes
            );
        }
        Ok(())
    }

    pub fn with_global_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&self.global_lock)
            .with_context(|| format!("open cache lock {}", self.global_lock.display()))?;
        lock.lock_exclusive()?;
        let result = operation();
        let unlock = FileExt::unlock(&lock);
        result.and_then(|value| {
            unlock?;
            Ok(value)
        })
    }

    fn verify_or_initialize_marker(&self) -> Result<()> {
        let marker_path = self.tenant_root.join("authority.json");
        let expected = self.authority.marker();
        if marker_path.exists() {
            let metadata = std::fs::symlink_metadata(&marker_path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("enterprise-shared cache authority marker is unsafe");
            }
            let observed: TenantCacheMarker = serde_json::from_slice(&std::fs::read(&marker_path)?)
                .context("decode enterprise-shared cache authority marker")?;
            if observed != expected {
                bail!(
                    "enterprise-shared cache authority changed; explicit tenant purge is required"
                );
            }
            return Ok(());
        }
        if std::fs::read_dir(&self.objects)?.next().is_some()
            || std::fs::read_dir(&self.pins)?.next().is_some()
        {
            bail!("enterprise-shared cache bytes exist without an authority marker");
        }
        let bytes = serde_json::to_vec(&expected)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&self.tenant_root)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&marker_path) {
            Ok(_) => File::open(&self.tenant_root)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let observed: TenantCacheMarker =
                    serde_json::from_slice(&std::fs::read(&marker_path)?)?;
                if observed != expected {
                    bail!("concurrent cache authority initialization conflicted");
                }
            }
            Err(error) => return Err(error.error.into()),
        }
        Ok(())
    }

    fn verify_or_initialize_cell_marker(&self) -> Result<()> {
        let marker_path = self.cell_root.join("authority.json");
        let expected = CellCacheMarker {
            schema_version: MARKER_SCHEMA_VERSION,
            cell_max_bytes: self.authority.cell_max_bytes,
        };
        if marker_path.exists() {
            let metadata = std::fs::symlink_metadata(&marker_path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("enterprise-shared cache cell marker is unsafe");
            }
            let observed: CellCacheMarker =
                serde_json::from_slice(&std::fs::read(&marker_path)?)
                    .context("decode enterprise-shared cache cell marker")?;
            if observed != expected {
                bail!("enterprise-shared cache cell byte ceiling is inconsistent");
            }
            return Ok(());
        }
        let bytes = serde_json::to_vec(&expected)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&self.cell_root)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(&marker_path) {
            Ok(_) => File::open(&self.cell_root)?.sync_all()?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                let observed: CellCacheMarker =
                    serde_json::from_slice(&std::fs::read(&marker_path)?)?;
                if observed != expected {
                    bail!("concurrent cache cell initialization conflicted");
                }
            }
            Err(error) => return Err(error.error.into()),
        }
        Ok(())
    }

    fn reject_cross_tenant_bucket_or_credential_reuse(&self) -> Result<()> {
        let expected_credential_sha256 =
            hex::encode(Sha256::digest(self.authority.credential_id.as_bytes()));
        let expected_tenant_directory = self.authority.tenant_id.to_string();
        for entry in std::fs::read_dir(&self.cell_root)? {
            let entry = entry?;
            let entry_name = entry.file_name();
            if !entry.file_type()?.is_dir()
                || entry_name.to_str() == Some(expected_tenant_directory.as_str())
            {
                continue;
            }
            let tenant_root = entry.path();
            reject_symlink(&tenant_root)?;
            let marker_path = tenant_root.join("authority.json");
            if !marker_path.exists() {
                bail!("enterprise-shared cache contains an unauthorised tenant directory");
            }
            let metadata = std::fs::symlink_metadata(&marker_path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("enterprise-shared cache tenant marker is unsafe");
            }
            let observed: TenantCacheMarker = serde_json::from_slice(&std::fs::read(&marker_path)?)
                .context("decode enterprise-shared cache tenant marker")?;
            if observed.tenant_id.to_string() != entry_name.to_string_lossy() {
                bail!("enterprise-shared cache tenant directory identity is inconsistent");
            }
            if observed.bucket == self.authority.bucket
                || observed.credential_id_sha256 == expected_credential_sha256
            {
                bail!("enterprise-shared tenants cannot reuse an object bucket or read credential");
            }
        }
        Ok(())
    }

    /// Purge exactly one stopped/revoked tenant namespace. The expected
    /// authority digest prevents a stale operator action from deleting a
    /// newly rotated assignment. Live hard-link leases refuse the purge.
    pub fn purge(base_root: &Path, expected: &TenantObjectCacheAuthority) -> Result<()> {
        if !base_root.is_absolute() {
            bail!("enterprise-shared cache purge root must be absolute");
        }
        let cell_root = base_root.join("enterprise-shared");
        if !cell_root.exists() {
            return Ok(());
        }
        reject_symlink(&cell_root)?;
        let tenant_root = cell_root.join(expected.tenant_id.to_string());
        let global_lock = cell_root.join(".cache.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&global_lock)?;
        lock.lock_exclusive()?;
        let result = (|| {
            if !tenant_root.exists() {
                return Ok(());
            }
            reject_symlink(&tenant_root)?;
            let marker_path = tenant_root.join("authority.json");
            let marker: TenantCacheMarker = serde_json::from_slice(&std::fs::read(&marker_path)?)?;
            if marker.tenant_id != expected.tenant_id
                || marker.authority_sha256 != expected.authority_digest()
            {
                bail!("refusing cache purge for a different tenant authority");
            }
            let pins = tenant_root.join("pins");
            if pins.exists() {
                for entry in std::fs::read_dir(&pins)? {
                    let lease_path = entry?.path().join(".lease");
                    let lease = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&lease_path)?;
                    match lease.try_lock_exclusive() {
                        Ok(()) => FileExt::unlock(&lease)?,
                        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                            bail!("refusing to purge a tenant cache with a live query lease")
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            std::fs::remove_dir_all(&tenant_root)?;
            File::open(&cell_root)?.sync_all()?;
            Ok(())
        })();
        let unlock = FileExt::unlock(&lock);
        result.and_then(|()| unlock.map_err(Into::into))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantCacheMarker {
    schema_version: u32,
    tenant_id: Uuid,
    bucket: String,
    credential_id_sha256: String,
    assignment_revision: u64,
    purge_epoch: u64,
    encryption_provider: CacheEncryptionProvider,
    encryption_key_id_sha256: String,
    encryption_key_revision: u64,
    tenant_max_bytes: u64,
    cell_max_bytes: u64,
    authority_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CellCacheMarker {
    schema_version: u32,
    cell_max_bytes: u64,
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path.exists() {
        reject_symlink(path)?;
        if !std::fs::metadata(path)?.is_dir() {
            bail!("enterprise-shared cache path is not a directory");
        }
    } else {
        std::fs::create_dir_all(path)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("enterprise-shared cache path cannot be a symbolic link");
    }
    Ok(())
}

fn physical_parquet_bytes(root: &Path) -> Result<u64> {
    fn visit(
        path: &Path,
        depth: usize,
        inodes: &mut BTreeSet<(u64, u64)>,
        bytes: &mut u64,
    ) -> Result<()> {
        if depth > 5 {
            bail!("enterprise-shared cache directory exceeded its expected depth");
        }
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_symlink() {
                bail!("enterprise-shared cache contains a symbolic link");
            }
            if file_type.is_dir() {
                visit(&path, depth + 1, inodes, bytes)?;
            } else if path.extension().and_then(|value| value.to_str()) == Some("parquet") {
                let metadata = entry.metadata()?;
                if inodes.insert((metadata.dev(), metadata.ino())) {
                    *bytes = bytes
                        .checked_add(metadata.len())
                        .context("enterprise-shared cache byte total overflow")?;
                }
            }
        }
        Ok(())
    }

    let mut inodes = BTreeSet::new();
    let mut bytes = 0_u64;
    if root.exists() {
        visit(root, 0, &mut inodes, &mut bytes)?;
    }
    Ok(bytes)
}

fn valid_bucket(value: &str) -> bool {
    (3..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !value.contains("..")
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_identity(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_optional_provider_identity(value: Option<&str>) -> bool {
    value.is_none_or(|value| valid_identity(value, 1_024))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
}

fn push_optional_field(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            output.push(1);
            push_field(output, value.as_bytes());
        }
        None => output.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(tenant: Uuid, bucket: &str, purge_epoch: u64) -> TenantObjectCacheAuthority {
        TenantObjectCacheAuthority::new(
            tenant,
            bucket.to_string(),
            format!("credential-{tenant}"),
            bucket,
            true,
            7,
            purge_epoch,
            CacheEncryptionProvider::CsiEncrypted,
            format!("key-{tenant}"),
            3,
            1_024,
            2_048,
        )
        .unwrap()
    }

    fn identity<'a>(tenant: Uuid, bucket: &'a str) -> TenantObjectCacheIdentity<'a> {
        TenantObjectCacheIdentity {
            tenant_id: tenant,
            dataset: "logs",
            bucket,
            object_key: "warehouse/nano/events/data/part.parquet",
            version_id: Some("version-1"),
            etag: Some("etag-1"),
            content_sha256: "a000000000000000000000000000000000000000000000000000000000000000",
            size_bytes: 100,
            query_generation: "snapshot-42-tail-7",
            schema_generation: "schema-9",
            runtime_generation: "lake-runtime-11",
        }
    }

    #[test]
    fn restart_accepts_only_the_exact_server_authority() {
        let root = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(1);
        let expected = authority(tenant, "nano-tenant-a", 1);
        let first = TenantObjectCacheNamespace::open(root.path(), expected.clone()).unwrap();
        let second = TenantObjectCacheNamespace::open(root.path(), expected).unwrap();
        assert_eq!(first.root(), second.root());
        let marker =
            String::from_utf8(std::fs::read(first.root().join("authority.json")).unwrap()).unwrap();
        assert!(!marker.contains(&format!("credential-{tenant}")));
        assert!(!marker.contains(&format!("key-{tenant}")));

        let rotated = authority(tenant, "nano-tenant-a", 2);
        assert!(TenantObjectCacheNamespace::open(root.path(), rotated).is_err());
    }

    #[test]
    fn authority_marker_tamper_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let expected = authority(Uuid::from_u128(1), "nano-tenant-a", 1);
        let namespace = TenantObjectCacheNamespace::open(root.path(), expected.clone()).unwrap();
        let marker = namespace.root().join("authority.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
        value["bucket"] = serde_json::json!("nano-tenant-b");
        std::fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(TenantObjectCacheNamespace::open(root.path(), expected).is_err());
    }

    #[test]
    fn equal_content_never_reuses_another_tenant_namespace() {
        let root = tempfile::tempdir().unwrap();
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let cache_a =
            TenantObjectCacheNamespace::open(root.path(), authority(tenant_a, "nano-tenant-a", 1))
                .unwrap();
        let cache_b =
            TenantObjectCacheNamespace::open(root.path(), authority(tenant_b, "nano-tenant-b", 1))
                .unwrap();
        let key_a = cache_a
            .cache_key(&identity(tenant_a, "nano-tenant-a"))
            .unwrap();
        let key_b = cache_b
            .cache_key(&identity(tenant_b, "nano-tenant-b"))
            .unwrap();
        let path_a = cache_a.objects().join(format!("{key_a}.parquet"));
        let path_b = cache_b.objects().join(format!("{key_b}.parquet"));
        std::fs::write(&path_a, b"tenant-a-bytes").unwrap();
        assert_ne!(key_a, key_b);
        assert_ne!(path_a, path_b);
        assert!(!path_b.exists());
        assert!(cache_b
            .cache_key(&identity(tenant_a, "nano-tenant-a"))
            .is_err());
    }

    #[test]
    fn every_provider_and_generation_identity_changes_the_cache_key() {
        let root = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(1);
        let cache =
            TenantObjectCacheNamespace::open(root.path(), authority(tenant, "nano-tenant-a", 1))
                .unwrap();
        let baseline = cache.cache_key(&identity(tenant, "nano-tenant-a")).unwrap();
        let mut variants = Vec::new();
        let mut version = identity(tenant, "nano-tenant-a");
        version.version_id = Some("version-2");
        variants.push(cache.cache_key(&version).unwrap());
        let mut etag = identity(tenant, "nano-tenant-a");
        etag.etag = Some("etag-2");
        variants.push(cache.cache_key(&etag).unwrap());
        let mut digest = identity(tenant, "nano-tenant-a");
        digest.content_sha256 = "b000000000000000000000000000000000000000000000000000000000000000";
        variants.push(cache.cache_key(&digest).unwrap());
        let mut query = identity(tenant, "nano-tenant-a");
        query.query_generation = "snapshot-43-tail-1";
        variants.push(cache.cache_key(&query).unwrap());
        let mut schema = identity(tenant, "nano-tenant-a");
        schema.schema_generation = "schema-10";
        variants.push(cache.cache_key(&schema).unwrap());
        let mut runtime = identity(tenant, "nano-tenant-a");
        runtime.runtime_generation = "lake-runtime-12";
        variants.push(cache.cache_key(&runtime).unwrap());
        assert!(variants.iter().all(|candidate| candidate != &baseline));
        assert_eq!(
            variants.iter().collect::<BTreeSet<_>>().len(),
            variants.len()
        );
    }

    #[test]
    fn credential_scope_encryption_and_quotas_fail_closed() {
        let tenant = Uuid::from_u128(1);
        assert!(TenantObjectCacheAuthority::new(
            tenant,
            "nano-tenant-a".to_string(),
            "credential".to_string(),
            "nano-tenant-b",
            true,
            1,
            1,
            CacheEncryptionProvider::CsiEncrypted,
            "key".to_string(),
            1,
            1,
            1,
        )
        .is_err());
        assert!(TenantObjectCacheAuthority::new(
            tenant,
            "nano-tenant-a".to_string(),
            "credential".to_string(),
            "nano-tenant-a",
            false,
            1,
            1,
            CacheEncryptionProvider::CsiEncrypted,
            "key".to_string(),
            1,
            1,
            1,
        )
        .is_err());
        assert_eq!(
            CacheEncryptionProvider::parse("memory-ephemeral").unwrap(),
            CacheEncryptionProvider::MemoryEphemeral
        );
        assert!(CacheEncryptionProvider::parse("plaintext").is_err());
    }

    #[test]
    fn cell_quota_counts_tenants_without_cross_tenant_eviction() {
        let root = tempfile::tempdir().unwrap();
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let cache_a =
            TenantObjectCacheNamespace::open(root.path(), authority(tenant_a, "nano-tenant-a", 1))
                .unwrap();
        let cache_b =
            TenantObjectCacheNamespace::open(root.path(), authority(tenant_b, "nano-tenant-b", 1))
                .unwrap();
        std::fs::write(
            cache_a
                .objects()
                .join(format!("{}.parquet", "a".repeat(64))),
            vec![0; 900],
        )
        .unwrap();
        std::fs::write(
            cache_b
                .objects()
                .join(format!("{}.parquet", "b".repeat(64))),
            vec![0; 900],
        )
        .unwrap();
        assert!(cache_a.ensure_cell_fits(200).is_ok());
        assert!(cache_a.ensure_cell_fits(300).is_err());
        assert_eq!(
            std::fs::metadata(
                cache_b
                    .objects()
                    .join(format!("{}.parquet", "b".repeat(64)))
            )
            .unwrap()
            .len(),
            900
        );
    }

    #[test]
    fn purge_requires_exact_authority_and_refuses_live_leases() {
        let root = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(1);
        let expected = authority(tenant, "nano-tenant-a", 1);
        let cache = TenantObjectCacheNamespace::open(root.path(), expected.clone()).unwrap();
        let lease_dir = cache.pins().join("live");
        std::fs::create_dir(&lease_dir).unwrap();
        let lease = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(lease_dir.join(".lease"))
            .unwrap();
        lease.lock_exclusive().unwrap();
        assert!(TenantObjectCacheNamespace::purge(root.path(), &expected).is_err());
        FileExt::unlock(&lease).unwrap();
        drop(lease);

        let wrong = authority(tenant, "nano-tenant-a", 2);
        assert!(TenantObjectCacheNamespace::purge(root.path(), &wrong).is_err());
        TenantObjectCacheNamespace::purge(root.path(), &expected).unwrap();
        assert!(!cache.root().exists());
        TenantObjectCacheNamespace::purge(root.path(), &expected).unwrap();
    }

    #[test]
    fn cell_ceiling_is_one_exact_server_owned_value() {
        let root = tempfile::tempdir().unwrap();
        TenantObjectCacheNamespace::open(
            root.path(),
            authority(Uuid::from_u128(1), "nano-tenant-a", 1),
        )
        .unwrap();
        let mismatched = TenantObjectCacheAuthority::new(
            Uuid::from_u128(2),
            "nano-tenant-b".to_string(),
            "credential-b".to_string(),
            "nano-tenant-b",
            true,
            7,
            1,
            CacheEncryptionProvider::CsiEncrypted,
            "key-b".to_string(),
            3,
            1_024,
            4_096,
        )
        .unwrap();
        assert!(TenantObjectCacheNamespace::open(root.path(), mismatched).is_err());
    }

    #[test]
    fn tenants_cannot_reuse_a_bucket_or_read_credential() {
        let root = tempfile::tempdir().unwrap();
        let tenant_a = Uuid::from_u128(1);
        let tenant_b = Uuid::from_u128(2);
        let first = authority(tenant_a, "nano-tenant-a", 1);
        TenantObjectCacheNamespace::open(root.path(), first.clone()).unwrap();

        let same_bucket = TenantObjectCacheAuthority::new(
            tenant_b,
            "nano-tenant-a".to_string(),
            "credential-b".to_string(),
            "nano-tenant-a",
            true,
            7,
            1,
            CacheEncryptionProvider::CsiEncrypted,
            "key-b".to_string(),
            3,
            1_024,
            2_048,
        )
        .unwrap();
        assert!(TenantObjectCacheNamespace::open(root.path(), same_bucket).is_err());

        let same_credential = TenantObjectCacheAuthority::new(
            tenant_b,
            "nano-tenant-b".to_string(),
            first.credential_id.clone(),
            "nano-tenant-b",
            true,
            7,
            1,
            CacheEncryptionProvider::CsiEncrypted,
            "key-b".to_string(),
            3,
            1_024,
            2_048,
        )
        .unwrap();
        assert!(TenantObjectCacheNamespace::open(root.path(), same_credential).is_err());
    }

    #[test]
    fn purge_is_idempotent_when_the_cache_cell_is_absent() {
        let root = tempfile::tempdir().unwrap();
        let absent_base = root.path().join("not-created");
        let expected = authority(Uuid::from_u128(1), "nano-tenant-a", 1);
        assert!(TenantObjectCacheNamespace::purge(&absent_base, &expected).is_ok());
        assert!(TenantObjectCacheNamespace::purge(Path::new("relative"), &expected).is_err());
    }
}
