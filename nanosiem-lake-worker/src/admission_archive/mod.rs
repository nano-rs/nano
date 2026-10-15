// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact archive protocol. This module never claims or executes a job.
//!
//! A descriptor is addressable only through the retention authority after all
//! objects have passed read-back verification. Reservations and references do
//! not expire: recovery must explicitly resolve abandoned publications.

#[cfg(feature = "enterprise")]
pub mod hosted;
pub mod inventory;
pub mod postgres;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use nanosiem_core::search::jobs::DurableLakeGenerationPin;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const CONTRACT: u32 = 1;
pub const MAX_DEPENDENCIES: usize = 100_000;
pub const MAX_DESCRIPTOR_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    /// Stable read identity (config JSON pointer, original file path or URI).
    /// Never used as a destination path by the resolver.
    pub locator: String,
    pub sha256: String,
    pub bytes: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    /// Deployment supplies the secret out of band; secret bytes are not objects.
    pub purpose: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub contract: u32,
    pub tenant_id: Uuid,
    pub logical_tenant_id: String,
    pub assignment_revision: u64,
    pub executor_abi: String,
    pub pin: DurableLakeGenerationPin,
    /// Sorted by locator. Contains exact config and exact signed tail bytes.
    pub dependencies: Vec<Dependency>,
    pub secrets: Vec<SecretReference>,
}

impl Descriptor {
    pub fn validate(&self) -> Result<()> {
        self.pin.validate()?;
        if self.contract != CONTRACT
            || self.tenant_id.is_nil()
            || self.logical_tenant_id.is_empty()
            || self.logical_tenant_id.len() > 256
            || self.assignment_revision == 0
            || self.executor_abi.is_empty()
            || self.executor_abi.len() > 256
            || self.dependencies.is_empty()
            || self.dependencies.len() > MAX_DEPENDENCIES
            || self.secrets.len() > 32
            || crate::config::event_generation_id(
                self.pin.snapshot_id,
                &self.pin.event_config_sha256,
            )? != self.pin.generation_id
        {
            bail!("invalid admission descriptor identity");
        }
        let mut previous = None;
        let mut total_bytes = 0_u64;
        for dependency in &self.dependencies {
            if !digest_valid(&dependency.sha256)
                || dependency.locator.is_empty()
                || dependency.locator.len() > 4096
                || dependency.locator.chars().any(char::is_control)
                || previous.is_some_and(|p: &str| p >= dependency.locator.as_str())
            {
                bail!("invalid or unordered admission dependency");
            }
            previous = Some(dependency.locator.as_str());
            total_bytes = total_bytes
                .checked_add(dependency.bytes)
                .context("archive byte count overflow")?;
            if total_bytes > 4 * 1024 * 1024 * 1024 * 1024 {
                bail!("archive exceeds its byte bound");
            }
        }
        let mut secrets = BTreeSet::new();
        for secret in &self.secrets {
            if !digest_valid(&secret.sha256)
                || secret.purpose.is_empty()
                || !secrets.insert(&secret.purpose)
            {
                bail!("invalid admission secret reference");
            }
        }
        if self.dependency("worker-config")?.bytes > MAX_DESCRIPTOR_BYTES as u64 {
            bail!("archived configuration exceeds its byte bound");
        }
        if self.dependency("compiler")?.sha256 != self.pin.compiler_sha256
            || self.dependency("native-library")?.sha256 != self.pin.native_artifact_sha256
            || !self.dependency("compiler")?.executable
        {
            bail!("descriptor changed compiler/native pin");
        }
        if let Some(tail) = &self.pin.hot_tail_manifest_sha256 {
            if &self.dependency("hot-tail-manifest")?.sha256 != tail
                || self.dependency("hot-tail-manifest")?.bytes > 4_194_304
            {
                bail!("descriptor changed exact tail pin");
            }
        } else if self
            .dependencies
            .iter()
            .any(|d| d.locator == "hot-tail-manifest")
        {
            bail!("descriptor invented an unpinned tail");
        }
        Ok(())
    }

    pub fn dependency(&self, locator: &str) -> Result<&Dependency> {
        self.dependencies
            .iter()
            .find(|d| d.locator == locator)
            .with_context(|| format!("admission dependency missing: {locator}"))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            bail!("admission descriptor exceeds limit");
        }
        Ok(bytes)
    }

    pub fn sha256(&self) -> Result<String> {
        Ok(digest(&self.encode()?))
    }

    /// Every object is scoped to one descriptor as well as one tenant. This
    /// avoids cross-descriptor deletion races without a global blob refcount.
    pub fn object_key(&self, descriptor: &str, dependency: &Dependency) -> Result<String> {
        if !digest_valid(descriptor) || !digest_valid(&dependency.sha256) {
            bail!("invalid archive object identity");
        }
        Ok(format!(
            "{}/retained-generation/v1/admission/{descriptor}/sha256/{}",
            self.tenant_id, dependency.sha256
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectReceipt {
    pub key: String,
    pub sha256: String,
    pub bytes: u64,
    /// Exact provider version or strong ETag, never a mutable discovery key.
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub descriptor: Descriptor,
    pub objects: BTreeMap<String, ObjectReceipt>,
}

impl Publication {
    pub fn validate(&self) -> Result<String> {
        let identity = self.descriptor.sha256()?;
        let expected: BTreeSet<_> = self
            .descriptor
            .dependencies
            .iter()
            .map(|d| self.descriptor.object_key(&identity, d))
            .collect::<Result<_>>()?;
        if expected != self.objects.keys().cloned().collect() {
            bail!("publication has a partial or surplus dependency set");
        }
        for dependency in &self.descriptor.dependencies {
            let key = self.descriptor.object_key(&identity, dependency)?;
            let receipt = &self.objects[&key];
            if receipt.key != key
                || receipt.sha256 != dependency.sha256
                || receipt.bytes != dependency.bytes
                || receipt.version.is_empty()
            {
                bail!("publication receipt differs from dependency");
            }
        }
        Ok(identity)
    }
}

/// Implementations MUST serialize reserve/publish/retain/retire durably on
/// (tenant, descriptor). A reservation pins its entire namespace before the
/// first PUT; publish is one atomic visibility transition. Retire must reject
/// reservations and held references; retired identities may never resurrect.
/// A GC deletion permit must also fence late object writers.
#[async_trait]
pub trait RetentionAuthority: Send + Sync {
    async fn reserve(&self, descriptor: &Descriptor) -> Result<()>;
    async fn publish(&self, publication: &Publication) -> Result<()>;
    /// Read and retain in ONE transaction. Reserved/retired/missing => error.
    /// Idempotency key cannot be rebound to another descriptor.
    async fn retain(&self, tenant: Uuid, descriptor: &str, reference: Uuid) -> Result<Publication>;
    async fn release(&self, tenant: Uuid, descriptor: &str, reference: Uuid) -> Result<()>;
}

/// Transport adapters must use the existing owner-authorized writer for hosted
/// R2. Implementations may not substitute direct provider PUTs or "latest" GETs.
#[async_trait]
pub trait ObjectReader: Send + Sync {
    async fn get_exact(&self, receipt: &ObjectReceipt, destination: &Path) -> Result<()>;
}

#[async_trait]
pub trait ObjectArchive: ObjectReader {
    async fn put_immutable(
        &self,
        key: &str,
        dependency: &Dependency,
        source: &Path,
    ) -> Result<ObjectReceipt>;
}

pub trait SecretProvider: Send + Sync {
    fn read(&self, reference: &SecretReference) -> Result<Vec<u8>>;

    fn verify(&self, reference: &SecretReference) -> Result<()> {
        let bytes = zeroize::Zeroizing::new(self.read(reference)?);
        if digest(&bytes) != reference.sha256 {
            bail!("runner secret version mismatch");
        }
        Ok(())
    }
}

/// `sources` is the result of a completeness inventory, not a directory walk
/// over the whole pod. The inventory must be held under its generation/cache
/// guards until this function finishes. All bytes are checked before AND after
/// upload; no descriptor becomes visible on any failure.
pub async fn publish(
    authority: &dyn RetentionAuthority,
    objects: &dyn ObjectArchive,
    descriptor: Descriptor,
    sources: &BTreeMap<String, PathBuf>,
) -> Result<String> {
    let identity = descriptor.sha256()?;
    if sources.keys().cloned().collect::<BTreeSet<_>>()
        != descriptor
            .dependencies
            .iter()
            .map(|d| d.locator.clone())
            .collect()
    {
        bail!("publication source set is incomplete");
    }
    authority.reserve(&descriptor).await?;
    let mut receipts = BTreeMap::new();
    let scratch = tempfile::tempdir()?;
    for dependency in &descriptor.dependencies {
        let source = &sources[&dependency.locator];
        verify_file(source, dependency)?;
        let key = descriptor.object_key(&identity, dependency)?;
        if receipts.contains_key(&key) {
            continue;
        }
        let receipt = objects.put_immutable(&key, dependency, source).await?;
        if receipt.key != key
            || receipt.sha256 != dependency.sha256
            || receipt.bytes != dependency.bytes
            || receipt.version.is_empty()
        {
            bail!("archive PUT receipt mismatch");
        }
        let readback = scratch.path().join("readback");
        objects.get_exact(&receipt, &readback).await?;
        verify_file(&readback, dependency)?;
        std::fs::remove_file(readback)?;
        receipts.insert(key, receipt);
    }
    let publication = Publication {
        descriptor,
        objects: receipts,
    };
    publication.validate()?;
    authority.publish(&publication).await?;
    Ok(identity)
}

/// Private hydration, with no writes to a caller-supplied path and no visible
/// receipt until the WHOLE closure has verified. Original path strings are
/// lookup keys only, never trusted filesystem paths. Phase 2 may translate
/// this mapping into an executor's isolated mount namespace.
pub struct ResolvedArchive {
    directory: tempfile::TempDir,
    pub descriptor: Descriptor,
    pub files: BTreeMap<String, PathBuf>,
    pub reference: Uuid,
}

impl ResolvedArchive {
    pub fn root(&self) -> &Path {
        self.directory.path()
    }
}

/// The reference remains held after success OR failure, including process
/// death. The lifecycle owner explicitly releases it after execution/recovery.
/// Dropping a Rust value is never permission to collect an accepted job.
pub async fn resolve(
    authority: &dyn RetentionAuthority,
    objects: &dyn ObjectReader,
    secrets: &dyn SecretProvider,
    tenant: Uuid,
    descriptor_sha256: &str,
    executor_abi: &str,
    reference: Uuid,
) -> Result<ResolvedArchive> {
    if !digest_valid(descriptor_sha256) || tenant.is_nil() || reference.is_nil() {
        bail!("invalid exact resolver request");
    }
    let publication = authority
        .retain(tenant, descriptor_sha256, reference)
        .await?;
    if publication.validate()? != descriptor_sha256
        || publication.descriptor.tenant_id != tenant
        || publication.descriptor.executor_abi != executor_abi
    {
        bail!("archive tenant, digest or executor ABI mismatch");
    }
    for secret in &publication.descriptor.secrets {
        secrets.verify(secret)?;
    }
    let directory = tempfile::tempdir()?;
    let mut files = BTreeMap::new();
    for (index, dependency) in publication.descriptor.dependencies.iter().enumerate() {
        let key = publication
            .descriptor
            .object_key(descriptor_sha256, dependency)?;
        let destination = directory.path().join(format!("{index:08}"));
        objects
            .get_exact(&publication.objects[&key], &destination)
            .await?;
        verify_file(&destination, dependency)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &destination,
                std::fs::Permissions::from_mode(if dependency.executable { 0o500 } else { 0o400 }),
            )?;
        }
        std::fs::File::open(&destination)?.sync_all()?;
        files.insert(dependency.locator.clone(), destination);
    }
    let config = std::fs::read(&files["worker-config"])?;
    if crate::config::event_config_sha256(&config)?
        != publication.descriptor.pin.event_config_sha256
    {
        bail!("resolved config differs from accepted semantic pin");
    }
    let config_value: serde_json::Value = serde_json::from_slice(&config)?;
    if config_value["assigned_tenant_id"].as_str()
        != Some(publication.descriptor.logical_tenant_id.as_str())
        || config_value["compiler"]["sha256"].as_str()
            != Some(publication.descriptor.pin.compiler_sha256.as_str())
        || config_value["native_library"]["sha256"].as_str()
            != Some(publication.descriptor.pin.native_artifact_sha256.as_str())
    {
        bail!("resolved configuration changed tenant or executable identity");
    }
    if let Some(path) = files.get("hot-tail-manifest") {
        let reference = publication
            .descriptor
            .secrets
            .iter()
            .find(|s| s.purpose == "entity-tail-hmac")
            .context("signed tail has no secret reference")?;
        let key = zeroize::Zeroizing::new(secrets.read(reference)?);
        if digest(&key) != reference.sha256 {
            bail!("runner secret changed during resolution");
        }
        let tail = crate::generation::verify_hot_tail_manifest(&std::fs::read(path)?, &key)?;
        let pin = &publication.descriptor.pin;
        if tail.tenant_id != publication.descriptor.logical_tenant_id
            || tail.base_snapshot_id != pin.snapshot_id
            || Some(tail.head_snapshot_id) != pin.hot_tail_snapshot_id
            || tail.tail_id != pin.hot_tail_id
        {
            bail!("resolved signed tail differs from accepted pin");
        }
    }
    let receipt = directory.path().join("verified-descriptor.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(receipt)?;
    file.write_all(&publication.descriptor.encode()?)?;
    file.sync_all()?;
    std::fs::File::open(directory.path())?.sync_all()?;
    Ok(ResolvedArchive {
        directory,
        descriptor: publication.descriptor,
        files,
        reference,
    })
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationReport {
    pub job_id: String,
    pub descriptor_sha256: Option<String>,
    pub expected_reads: usize,
    pub covered_reads: usize,
    pub gaps: Vec<String>,
}

/// Compare an independently observed read set with the descriptor. A successful
/// upload alone is not a completeness proof. Missing telemetry is itself a gap.
pub fn verify_observed_reads(
    job_id: String,
    descriptor: &Descriptor,
    observed: &[Dependency],
) -> Result<VerificationReport> {
    descriptor.validate()?;
    let mut gaps = Vec::new();
    let mut covered = 0;
    if observed.is_empty() {
        gaps.push("no observed execution reads".into());
    }
    for read in observed {
        if descriptor.dependencies.iter().any(|d| d == read) {
            covered += 1;
        } else {
            gaps.push(format!("uncovered execution read: {}", read.locator));
        }
    }
    Ok(VerificationReport {
        job_id,
        descriptor_sha256: Some(descriptor.sha256()?),
        expected_reads: observed.len(),
        covered_reads: covered,
        gaps,
    })
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(crate) fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(crate) fn verify_file(path: &Path, expected: &Dependency) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() != expected.bytes {
        bail!("archive dependency is not a regular file of the pinned size");
    }
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    if hex::encode(hasher.finalize()) != expected.sha256 {
        bail!("archive dependency digest mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
