// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signed, content-addressed derivative bundles for generation cold starts.
//!
//! Iceberg and PostgreSQL remain authoritative. A bundle is only a disposable
//! acceleration copy: the query-side consumer admits it into an unactivated
//! generation directory after verifying the PostgreSQL pointer, Ed25519
//! envelope, tenant/table/snapshot/retention identity, and every artifact's
//! strong ETag, byte length, and SHA-256. Optional consumers may rebuild from
//! the already-hydrated Iceberg snapshot after a cache miss. Required
//! enterprise-shared consumers instead fail the candidate and leave the prior
//! serving generation unchanged.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{BufReader, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::pin::Pin;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use opendal::Operator;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::generation::ObjectStampManifest;

pub const GENERATION_BUNDLE_SCHEMA_VERSION: u8 = 3;
pub const GENERATION_BUNDLE_SIGNATURE_DOMAIN: &str = "nano-lake-generation-bundle-v3";
pub const GENERATION_BUNDLE_CONTRACT_VERSION: &str = "nano-lake-generation-bundle-v3";
/// NAN-2361: ingest prevalence hand-offs reuse the bundle manifest format but
/// are signed under their own domain by a tenant-scoped hand-off key, never
/// by the Nano Main owner key. A hand-off therefore cannot be replayed as a
/// retained generation even if both keys were held by one party.
pub const PREVALENCE_HANDOFF_SIGNATURE_DOMAIN: &str = "nano-lake-prevalence-handoff-v1";
pub const MAX_GENERATION_BUNDLE_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// SHA-256 of the empty byte string: the only digest an empty file can have.
const EMPTY_FILE_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const GENERATION_BUNDLE_ARCHIVE_MAGIC: &[u8] = b"NANO-LAKE-BUNDLE-SHARD-V2\0";
/// Inline sign transport (manifest bytes base64-encoded in the owner request)
/// and the tenant-signed prevalence hand-off: the owner's original NAN-2690
/// bound on the decoded manifest.
pub const MAX_GENERATION_BUNDLE_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
/// Inline sign transport: the owner's artifact, per-artifact member, total
/// member and derivative-inventory count bound (each).
pub const MAX_GENERATION_BUNDLE_INLINE_COUNT: usize = 20_000;
/// NAN-2801 reference sign transport: the owner streams the unsigned manifest
/// from the tenant's own bucket (see [`GenerationBundleSignTransport::Reference`])
/// and bounds it by its streaming-validation memory instead of a request body.
/// Also the bound every reader applies to a published pointer, because a
/// reader cannot tell (and need not know) how the owner received the bytes it
/// signed. Pinned to Nano Main by
/// `tests/fixtures/generation-bundle-owner-ref-limits.json`.
pub const MAX_GENERATION_BUNDLE_REF_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;
/// NAN-2801 reference sign transport: the count bound (each), as above.
pub const MAX_GENERATION_BUNDLE_REF_COUNT: usize = 200_000;

/// How the Nano Main owner receives the manifest it signs. The signed bytes,
/// the signature and every reader check are identical in both; only the
/// owner's admission bounds and the copy-artifact set differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationBundleSignTransport {
    /// `manifest_bytes_base64` in the sign request (NAN-2690 bounds).
    Inline,
    /// NAN-2801: `manifest_ref {key, sha256, size_bytes}` naming the unsigned
    /// canonical manifest, uploaded beforehand as one extra retained-generation
    /// copy artifact of the bundle at [`unsigned_manifest_key`]. The bundle's
    /// copy-artifact set therefore holds that object too, so bundle lifecycle
    /// GC deletes it with the bundle; control migration 9002955 derives the
    /// transport from its presence.
    Reference,
}

impl GenerationBundleSignTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::Reference => "ref",
        }
    }
    pub fn max_manifest_bytes(self) -> u64 {
        match self {
            Self::Inline => MAX_GENERATION_BUNDLE_MANIFEST_BYTES,
            Self::Reference => MAX_GENERATION_BUNDLE_REF_MANIFEST_BYTES,
        }
    }
    pub fn max_count(self) -> usize {
        match self {
            Self::Inline => MAX_GENERATION_BUNDLE_INLINE_COUNT,
            Self::Reference => MAX_GENERATION_BUNDLE_REF_COUNT,
        }
    }
    /// Copy artifacts beyond the manifest's own artifacts: the signed manifest
    /// object, plus the unsigned manifest object in reference mode.
    pub fn extra_copy_artifacts(self) -> usize {
        match self {
            Self::Inline => 1,
            Self::Reference => 2,
        }
    }
}

/// The object-key directory every object naming one bundle's manifest lives
/// in: `<tenant>/retained-generation/v1/bundles/<table>/<snapshot>-<list16>/<bundle16>/`.
pub fn bundle_manifest_directory(
    tenant_id: Uuid,
    table_uuid: Uuid,
    snapshot_id: i64,
    manifest_list_sha256: &str,
    bundle_identity_sha256: &str,
) -> Result<String> {
    if snapshot_id <= 0
        || !lower_sha256(manifest_list_sha256)
        || !lower_sha256(bundle_identity_sha256)
    {
        bail!("generation bundle manifest directory identity is malformed");
    }
    Ok(format!(
        "{tenant_id}/retained-generation/v1/bundles/{table_uuid}/{snapshot_id}-{}/{}/",
        &manifest_list_sha256[..16],
        &bundle_identity_sha256[..16],
    ))
}

/// NAN-2801: where the publisher stages the UNSIGNED canonical manifest for
/// the owner to sign by reference:
/// `<bundle manifest directory>sha256/<unsigned sha>.unsigned-manifest.json`.
/// It sits under the signed `manifest-<sha>.json`'s directory in the existing
/// retained-generation writer class (and credential prefix), and uses the
/// content-addressed `/sha256/<sha>.<ext>` form that every key-grammar check
/// already admits (this crate's `named_artifact_key_matches`, the core copy
/// registrar's `writer_object_key_matches`, Nano Main's owner). Ordinary
/// derivative artifacts live in `.../bundles/<bundle16>/sha256/`, a different
/// directory, so the two can never collide.
pub fn unsigned_manifest_key(
    tenant_id: Uuid,
    table_uuid: Uuid,
    snapshot_id: i64,
    manifest_list_sha256: &str,
    bundle_identity_sha256: &str,
    unsigned_manifest_sha256: &str,
) -> Result<String> {
    if !lower_sha256(unsigned_manifest_sha256) {
        bail!("unsigned generation bundle manifest digest is malformed");
    }
    Ok(format!(
        "{}sha256/{unsigned_manifest_sha256}.unsigned-manifest.json",
        bundle_manifest_directory(
            tenant_id, table_uuid, snapshot_id, manifest_list_sha256, bundle_identity_sha256,
        )?
    ))
}
/// Bound on one portable derivative manifest (`*/manifest.json`) that
/// admission rebases in memory through `serde_json::Value`. Distinct from the
/// signed bundle manifest bound above, which also guards the tenant-signed
/// prevalence hand-off and stays at 16 MiB.
///
/// Measured (`manifest_memory_tests`, entity-sidecar-shaped manifest, glibc
/// malloc, release build): peak RSS growth of the Value rebase is 314 MiB for
/// a 62 MiB manifest (5.1x) and 1003 MiB for 250 MiB (4.0x). At this bound the
/// worst case is ~5.1 x 128 MiB = ~650 MiB, which fits the 3 GiB
/// generation-consumer container beside its 512 MiB derivative-build budget
/// (`--max-memory-bytes`, which contains the 64 MiB `--heap-bytes` keyword
/// writer heap) and the 32 x 2 MiB object-fetch channels. The live tenant1
/// entity sidecar manifest was 64,995,597 bytes when the old 16 MiB bound
/// refused activation (2026-09-22): this leaves ~2x growth headroom.
pub const MAX_PORTABLE_MANIFEST_IN_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
/// Sanity bound on one portable derivative manifest now that admission
/// rebases it by streaming (`rebase_manifest_stream`, memory independent of
/// file size). The in-memory bound above still applies to the two places that
/// cannot stream: a manifest whose object keys are not in canonical order
/// (the `Value` fallback), and signed re-verification, which holds the
/// signed manifest bytes (1x, no `Value`) because metadata archives are
/// fetched whole. 512 MiB is ~8x the live entity sidecar manifest.
pub const MAX_PORTABLE_MANIFEST_BYTES: u64 = 512 * 1024 * 1024;
const MAX_GENERATION_BUNDLE_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;
const DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES: u64 = 64 * 1024;
/// How many raw content-store objects may be in flight at once. R2 is a
/// high-latency, per-connection-bandwidth-limited store: with one GET at a
/// time a bundle's wall time is (files x round trip) + (bytes / stream
/// bandwidth), and the first term dominates as soon as the publisher emits one
/// object per derivative file. Concurrency hides the round trips without
/// raising peak memory: each stream still has an eight-slot 256 KiB channel.
pub const OBJECT_FETCH_CONCURRENCY_ENV: &str = "LAKE_GENERATION_BUNDLE_OBJECT_FETCH_CONCURRENCY";
/// 32 measured at parity with the legacy archive path at 2048 derivative
/// files and 1.95x faster at 512 (NAN-2532, 45 ms TTFB / 120 MB/s per stream);
/// one active GET was 17.8x SLOWER at 2048 files. Peak memory is bounded by
/// the per-stream eight-slot 256 KiB channels: 32 x 2 MiB.
const DEFAULT_OBJECT_FETCH_CONCURRENCY: usize = 32;
const MAX_OBJECT_FETCH_CONCURRENCY: usize = 64;

fn raw_object_fetch_concurrency() -> usize {
    std::env::var(OBJECT_FETCH_CONCURRENCY_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_OBJECT_FETCH_CONCURRENCY)
        .clamp(1, MAX_OBJECT_FETCH_CONCURRENCY)
}

/// A content-store receipt is a few hundred JSON bytes; charge one allocation
/// unit for it, the same conservative unit every other member is charged in.
const OBJECT_RECEIPT_ALLOCATION_BYTES: u64 = DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES;
const GENERATION_BUNDLE_ADMISSION_RECEIPT: &str = ".generation-bundle-admission-v1.json";
const MAX_GENERATION_BUNDLE_ADMISSION_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;

/// SlateDB emits one zero-byte writer-epoch fence even when WAL payloads are
/// disabled. It is part of the immutable checkpoint tree, not an incomplete
/// upload. Keep this exception deliberately narrower than a generic empty-file
/// allowance so a truncated derivative still fails closed.
///
/// The one predicate for the publisher's inventory build, the consumer's
/// admission walk and `validate_artifact`. The windows come from the
/// prevalence builder itself: any window can own a SlateDB database (the
/// builder only shares one between windows whose scans are identical, so 30d
/// reused 7d's until tenant1 held more than seven days of events). The Nano
/// Main owner mirrors this as `PREVALENCE_EMPTY_WAL_FILE`.
pub(crate) fn generation_bundle_allows_empty_file(relative_path: &str) -> bool {
    let parts = relative_path.split('/').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0] != "prevalence-snapshot-v2"
        || !crate::prevalence_build::PREVALENCE_WINDOWS
            .iter()
            .any(|(window, _)| *window == parts[1])
        || parts[2] != "slatedb"
        || parts[3] != "wal"
    {
        return false;
    }
    parts[4]
        .strip_suffix(".sst")
        .is_some_and(|stem| stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit()))
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationBundleArtifactFamily {
    RetainedGeneration,
    PrevalenceArtifact,
}

impl GenerationBundleArtifactFamily {
    fn key_token(self) -> &'static str {
        match self {
            Self::RetainedGeneration => "retained-generation",
            Self::PrevalenceArtifact => "prevalence-artifact",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleArtifact {
    pub family: GenerationBundleArtifactFamily,
    pub role: String,
    /// Exact immutable key in the tenant's dedicated R2 bucket.
    pub key: String,
    pub etag: String,
    pub sha256: String,
    /// Serialized archive bytes stored in R2.
    pub bytes: u64,
    /// Installed bytes after verified in-memory extraction. The archive is
    /// never persisted locally, so staging does not require a second copy.
    pub unpacked_bytes: u64,
    pub members: Vec<GenerationBundleArtifactMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_event_time: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_event_time: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleArtifactMember {
    /// Generation-root-relative installation path. Absolute paths are never
    /// serialized, which permits a bundle to hydrate on another Pod.
    pub relative_path: String,
    /// Byte offset of this archive member in the installed logical file.
    /// Large derivative files are split across bounded immutable R2 objects.
    pub offset: u64,
    /// Exact final byte length of the installed logical file.
    pub total_bytes: u64,
    /// SHA-256 of this exact chunk, not of the complete logical file.
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleBuilderProvenance {
    pub image_digest: String,
    pub compiler_sha256: String,
    pub libchdb_sha256: String,
    pub worker_identity: String,
    pub phase_timings_seconds: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleSourceObject {
    pub relative_path: String,
    pub source_uri: String,
    pub version_id: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleObjectStampManifest {
    /// Informational moving catalog head; excluded from the admission digest.
    pub metadata_location: String,
    pub snapshot_id: i64,
    pub table: String,
    pub objects: Vec<GenerationBundleSourceObject>,
}

impl From<&ObjectStampManifest> for GenerationBundleObjectStampManifest {
    fn from(value: &ObjectStampManifest) -> Self {
        Self {
            metadata_location: value.metadata_location.clone(),
            snapshot_id: value.snapshot_id,
            table: value.table.clone(),
            objects: value
                .objects
                .iter()
                .map(|object| GenerationBundleSourceObject {
                    relative_path: object.relative_path.clone(),
                    source_uri: object.source_uri.clone(),
                    version_id: object.version_id.clone(),
                    size_bytes: object.size_bytes,
                    sha256: object.sha256.clone(),
                })
                .collect(),
        }
    }
}

pub fn object_stamp_manifest_sha256(
    manifest: &GenerationBundleObjectStampManifest,
) -> Result<String> {
    #[derive(Serialize)]
    struct Identity<'a> {
        snapshot_id: i64,
        table: &'a str,
        objects: &'a [GenerationBundleSourceObject],
    }
    let identity = Identity {
        snapshot_id: manifest.snapshot_id,
        table: &manifest.table,
        objects: &manifest.objects,
    };
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&identity)?)))
}

/// Full portable file identity. Archives are transport only; this inventory is
/// the owner-signed authority for reuse in each newly admitted generation.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivativeMember {
    pub relative_path: String,
    pub sha256: String,
    pub bytes: u64,
    pub content_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleManifest {
    pub schema_version: u8,
    pub contract_version: String,
    pub tenant_id: Uuid,
    pub table_uuid: Uuid,
    pub table_location: String,
    pub snapshot_id: i64,
    pub manifest_list_sha256: String,
    pub iceberg_metadata_location: String,
    /// Digest/count bind the query Pod's independently hydrated authoritative
    /// stamp ledger. The potentially large ledger is a signed archive member,
    /// not inline manifest JSON.
    pub object_stamp_manifest_sha256: String,
    pub source_object_count: usize,
    pub ancestor_snapshot_ids: Vec<i64>,
    pub ancestor_snapshot_ids_sha256: String,
    pub derivative_contract_sha256: String,
    pub hmac_key_sha256: String,
    pub read_schema_sha256: String,
    pub min_event_time: DateTime<Utc>,
    pub max_event_time: DateTime<Utc>,
    pub bundle_identity_sha256: String,
    pub generation_id: String,
    pub event_config_sha256: String,
    /// NAN-2361 prevalence hand-off publication order: the manager's Unix
    /// millisecond clock at publish, signed with the rest of the manifest and
    /// mirrored into the manifest key. Consumers discover the newest hand-off
    /// by this sequence and refuse any manifest at or below the sequence in
    /// their receipt, so a same-tenant writer cannot roll ingest prevalence
    /// back by replaying an older signed manifest under a fresh Last-Modified.
    /// Absent on retained-generation bundles (canonical bytes unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_sequence: Option<u64>,
    pub builder: GenerationBundleBuilderProvenance,
    pub artifacts: Vec<GenerationBundleArtifact>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivative_inventory: Option<Vec<DerivativeMember>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBundleSignature {
    pub key_id: String,
    pub domain: String,
    pub signature_base64: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGenerationBundleManifest {
    pub manifest: GenerationBundleManifest,
    pub signature: GenerationBundleSignature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationBundleIdentity<'a> {
    pub tenant_id: Uuid,
    pub table_uuid: Uuid,
    pub snapshot_id: i64,
    pub manifest_list_sha256: &'a str,
    pub derivative_contract_sha256: &'a str,
    pub hmac_key_sha256: &'a str,
    pub read_schema_sha256: &'a str,
}

/// Fixed-width, field-boundary-safe identity. Runtime/compiler bytes and
/// capacity knobs deliberately do not participate; semantic format changes do.
pub fn bundle_identity(identity: &GenerationBundleIdentity<'_>) -> Result<String> {
    if identity.tenant_id.is_nil()
        || identity.table_uuid.is_nil()
        || identity.snapshot_id <= 0
        || !lower_sha256(identity.manifest_list_sha256)
        || !lower_sha256(identity.derivative_contract_sha256)
        || !lower_sha256(identity.hmac_key_sha256)
        || !lower_sha256(identity.read_schema_sha256)
    {
        bail!("generation bundle identity is invalid");
    }
    let mut digest = Sha256::new();
    digest.update(b"nano:lake-generation-bundle-identity:v1\0");
    for field in [
        identity.tenant_id.as_bytes().as_slice(),
        identity.table_uuid.as_bytes().as_slice(),
        &identity.snapshot_id.to_be_bytes(),
        &decode_sha256(identity.manifest_list_sha256)?,
        &decode_sha256(identity.derivative_contract_sha256)?,
        &decode_sha256(identity.hmac_key_sha256)?,
        &decode_sha256(identity.read_schema_sha256)?,
    ] {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn ancestor_snapshot_ids_sha256(ids: &[i64]) -> Result<String> {
    if ids.is_empty() || ids.len() > 100_000 || ids.iter().any(|id| *id <= 0) {
        bail!("generation bundle snapshot ancestry is invalid");
    }
    let mut digest = Sha256::new();
    digest.update(b"nano:lake-generation-bundle-ancestry:v1\0");
    for id in ids {
        digest.update(id.to_be_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

impl GenerationBundleManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("encode canonical generation bundle manifest")
    }

    pub fn signature_message(&self) -> Result<Vec<u8>> {
        self.signature_message_for_domain(GENERATION_BUNDLE_SIGNATURE_DOMAIN)
    }

    pub fn signature_message_for_domain(&self, domain: &str) -> Result<Vec<u8>> {
        let canonical = self.canonical_bytes()?;
        let mut message = Vec::with_capacity(domain.len() + 1 + 8 + canonical.len());
        message.extend_from_slice(domain.as_bytes());
        message.push(0);
        message.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        message.extend_from_slice(&canonical);
        Ok(message)
    }

    pub(crate) fn validate_structure(&self) -> Result<()> {
        if self.schema_version != GENERATION_BUNDLE_SCHEMA_VERSION
            || self.contract_version != GENERATION_BUNDLE_CONTRACT_VERSION
        {
            bail!(
                "unsupported generation bundle contract/schema: expected {}/{}, actual {}/{}",
                GENERATION_BUNDLE_CONTRACT_VERSION,
                GENERATION_BUNDLE_SCHEMA_VERSION,
                self.contract_version,
                self.schema_version
            );
        }
        if self.tenant_id.is_nil()
            || self.table_uuid.is_nil()
            || self.snapshot_id <= 0
            || self.min_event_time > self.max_event_time
            || self.ancestor_snapshot_ids.first().copied() != Some(self.snapshot_id)
            || ancestor_snapshot_ids_sha256(&self.ancestor_snapshot_ids)?
                != self.ancestor_snapshot_ids_sha256
            || !lower_sha256(&self.manifest_list_sha256)
            || !lower_sha256(&self.object_stamp_manifest_sha256)
            || self.source_object_count == 0
            || !lower_sha256(&self.derivative_contract_sha256)
            || !lower_sha256(&self.hmac_key_sha256)
            || !lower_sha256(&self.read_schema_sha256)
            || !lower_sha256(&self.bundle_identity_sha256)
            || !lower_sha256(&self.event_config_sha256)
            || !valid_generation_id(&self.generation_id, self.snapshot_id)
            || !valid_table_location(&self.table_location)
            || !self.iceberg_metadata_location.starts_with(&format!(
                "{}/metadata/",
                self.table_location.trim_end_matches('/')
            ))
            || self.artifacts.is_empty()
            || !valid_provenance(&self.builder)
        {
            bail!("generation bundle manifest identity is invalid");
        }
        let expected_identity = bundle_identity(&GenerationBundleIdentity {
            tenant_id: self.tenant_id,
            table_uuid: self.table_uuid,
            snapshot_id: self.snapshot_id,
            manifest_list_sha256: &self.manifest_list_sha256,
            derivative_contract_sha256: &self.derivative_contract_sha256,
            hmac_key_sha256: &self.hmac_key_sha256,
            read_schema_sha256: &self.read_schema_sha256,
        })?;
        if expected_identity != self.bundle_identity_sha256 {
            bail!("generation bundle content identity differs");
        }
        self.validate_artifacts()?;
        if let Some(inventory) = &self.derivative_inventory {
            let mut actual = BTreeMap::new();
            for artifact in self.artifacts.iter().filter(|a| a.role != "source-object-stamps") {
                if artifact.members.len() != 1 || !artifact.role.starts_with("inventory-object-") { bail!("inventory must use independent raw objects"); }
                for member in &artifact.members { actual.insert(member.relative_path.as_str(), member.total_bytes); }
            }
            let mut declared = BTreeMap::new();
            for member in inventory {
                if !safe_relative_path(&member.relative_path) || !lower_sha256(&member.sha256)
                    || member.content_id != format!("sha256:{}", member.sha256)
                    || declared.insert(member.relative_path.as_str(), member.bytes).is_some() {
                    bail!("invalid derivative content inventory");
                }
            }
            if actual != declared { bail!("derivative inventory is not complete"); }
            let identities: BTreeMap<_, _> = inventory.iter().map(|i| (i.relative_path.as_str(), i)).collect();
            for artifact in self.artifacts.iter().filter(|a| a.role != "source-object-stamps") {
                let file = &artifact.members[0];
                if !identities.get(file.relative_path.as_str()).is_some_and(|i| i.bytes == file.total_bytes
                    && (file.bytes != file.total_bytes || i.sha256 == file.sha256)) {
                    bail!("inventory content digest differs from transfer object");
                }
            }
        }
        Ok(())
    }

    /// True when every artifact belongs to the prevalence family: an
    /// ingest-stamping hand-off for the Bronze publishers. Such a manifest
    /// is never a complete retained generation.
    pub fn is_prevalence_handoff(&self) -> bool {
        !self.artifacts.is_empty()
            && self
                .artifacts
                .iter()
                .all(|artifact| artifact.family == GenerationBundleArtifactFamily::PrevalenceArtifact)
    }

    fn validate_artifacts(&self) -> Result<()> {
        let mut relative_paths = BTreeSet::new();
        let mut installed_files = BTreeMap::new();
        let mut object_keys = BTreeSet::new();
        let mut roles = BTreeSet::new();
        let mut packed_bytes = 0_u64;
        let mut unpacked_bytes = 0_u64;
        for artifact in &self.artifacts {
            validate_artifact(self, artifact)?;
            if !object_keys.insert(artifact.key.as_str()) || !roles.insert(artifact.role.as_str()) {
                bail!("generation bundle repeats an archive role or object key");
            }
            packed_bytes = packed_bytes
                .checked_add(artifact.bytes)
                .context("generation bundle packed-byte total overflow")?;
            unpacked_bytes = unpacked_bytes
                .checked_add(artifact.unpacked_bytes)
                .context("generation bundle unpacked-byte total overflow")?;
            if packed_bytes > MAX_GENERATION_BUNDLE_TOTAL_BYTES
                || unpacked_bytes > MAX_GENERATION_BUNDLE_TOTAL_BYTES
            {
                bail!("generation bundle exceeds its packed, unpacked, or member bound");
            }
            for member in &artifact.members {
                let end = member
                    .offset
                    .checked_add(member.bytes)
                    .context("generation bundle member extent overflow")?;
                if let Some((next_offset, total_bytes)) =
                    installed_files.get_mut(member.relative_path.as_str())
                {
                    if *next_offset != member.offset || *total_bytes != member.total_bytes {
                        bail!("generation bundle member chunks are missing, reordered, or inconsistent");
                    }
                    *next_offset = end;
                } else {
                    if member.offset != 0 {
                        bail!("generation bundle installed member does not begin at offset zero");
                    }
                    relative_paths.insert(member.relative_path.as_str());
                    installed_files
                        .insert(member.relative_path.as_str(), (end, member.total_bytes));
                }
            }
        }
        if installed_files
            .values()
            .any(|(next_offset, total_bytes)| next_offset != total_bytes)
        {
            bail!("generation bundle installed member is truncated");
        }

        // NAN-2361 prevalence hand-off: a manifest whose artifacts are ALL of the
        // prevalence family is an ingest-stamping hand-off, not a retained
        // generation. It never installs on a query Pod (exact admission checks
        // `is_prevalence_handoff` and refuses it), so the retained-generation
        // members are not required. The prevalence tree contract is unchanged.
        if self.is_prevalence_handoff() {
            if !relative_paths.contains("prevalence-snapshot-v2/manifest.json") {
                bail!("prevalence hand-off omits prevalence-snapshot-v2/manifest.json");
            }
            if relative_paths
                .iter()
                .any(|path| !path.starts_with("prevalence-snapshot-v2/"))
            {
                bail!("prevalence hand-off carries a member outside the prevalence tree");
            }
            if !relative_paths.iter().any(|path| {
                path.starts_with("prevalence-snapshot-v2/")
                    && *path != "prevalence-snapshot-v2/manifest.json"
            }) {
                bail!("prevalence hand-off omits mandatory prevalence files");
            }
            return Ok(());
        }
        for required in [
            "bundle-metadata/object-stamps.json",
            "entity-sidecar/manifest.json",
            "keyword-sidecar/manifest.json",
            "fragment-sidecar/manifest.json",
            "identity-snapshot/manifest.json",
            "identity-snapshot/by-ip.parquet",
            "count-rollup/manifest.json",
            "prevalence-snapshot-v2/manifest.json",
        ] {
            if !relative_paths.contains(required) {
                bail!("generation bundle omits mandatory derivative artifact {required}");
            }
        }
        for required_prefix in [
            "entity-sidecar/object-",
            "keyword-sidecar/index/",
            "fragment-sidecar/index/",
            "count-rollup/object-",
        ] {
            if !relative_paths
                .iter()
                .any(|path| path.starts_with(required_prefix))
            {
                bail!("generation bundle omits mandatory derivative tree {required_prefix}");
            }
        }
        if !relative_paths.iter().any(|path| {
            path.starts_with("prevalence-snapshot-v2/")
                && *path != "prevalence-snapshot-v2/manifest.json"
        }) {
            bail!("generation bundle omits mandatory prevalence files");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct GenerationBundleAdmission {
    pub tenant_id: Uuid,
    pub table_uuid: Uuid,
    pub table_location: String,
    pub snapshot_id: i64,
    pub manifest_list_sha256: String,
    pub derivative_contract_sha256: String,
    pub hmac_key_sha256: String,
    pub read_schema_sha256: String,
    pub object_stamp_manifest_sha256: String,
    pub assignment_revision: i64,
    pub irreversible_event_time_floor: DateTime<Utc>,
    pub signer_key_id: String,
    pub signer_public_key: [u8; 32],
}

/// Builder-only predecessor admission. The caller independently proves that
/// this snapshot is an ancestor and verifies its Iceberg manifest-list digest;
/// the owner signature then authenticates the exact object-stamp inventory
/// needed by the incremental derivative builders.
#[derive(Clone, Debug)]
pub struct PriorGenerationBundleAdmission {
    pub tenant_id: Uuid,
    pub table_uuid: Uuid,
    pub table_location: String,
    pub snapshot_id: i64,
    pub manifest_list_sha256: String,
    pub derivative_contract_sha256: String,
    pub hmac_key_sha256: String,
    pub read_schema_sha256: String,
    pub assignment_revision: i64,
    pub irreversible_event_time_floor: DateTime<Utc>,
    pub signer_key_id: String,
    pub signer_public_key: [u8; 32],
}

impl SignedGenerationBundleManifest {
    fn verify_admission_identity(&self, expected: &GenerationBundleAdmission) -> Result<()> {
        macro_rules! check {
            ($actual:expr, $expected:expr, $field:literal) => {
                if $actual != $expected {
                    bail!("{}: expected {:?}, actual {:?}", $field, $expected, $actual);
                }
            };
        }
        check!(
            self.signature.domain,
            GENERATION_BUNDLE_SIGNATURE_DOMAIN,
            "signature.domain"
        );
        check!(
            self.signature.key_id,
            expected.signer_key_id,
            "signature.key_id"
        );
        check!(self.manifest.tenant_id, expected.tenant_id, "tenant_id");
        check!(self.manifest.table_uuid, expected.table_uuid, "table_uuid");
        check!(
            self.manifest.snapshot_id,
            expected.snapshot_id,
            "snapshot_id"
        );
        check!(
            self.manifest.manifest_list_sha256,
            expected.manifest_list_sha256,
            "manifest_list_sha256"
        );
        check!(
            self.manifest.derivative_contract_sha256,
            expected.derivative_contract_sha256,
            "derivative_contract_sha256"
        );
        check!(
            self.manifest.hmac_key_sha256,
            expected.hmac_key_sha256,
            "hmac_key_sha256"
        );
        check!(
            self.manifest.read_schema_sha256,
            expected.read_schema_sha256,
            "read_schema_sha256"
        );
        check!(
            self.manifest.object_stamp_manifest_sha256,
            expected.object_stamp_manifest_sha256,
            "object_stamp_manifest_sha256"
        );
        check!(
            self.manifest.table_location.trim_end_matches('/'),
            expected.table_location.trim_end_matches('/'),
            "table_location"
        );
        if self.manifest.min_event_time < expected.irreversible_event_time_floor {
            bail!(
                "min_event_time: expected at least {}, actual {}",
                expected.irreversible_event_time_floor,
                self.manifest.min_event_time
            );
        }
        Ok(())
    }

    pub fn verify(&self, expected: &GenerationBundleAdmission) -> Result<()> {
        self.manifest.validate_structure()?;
        if self.manifest.is_prevalence_handoff() {
            bail!("prevalence hand-off manifest is not a retained generation bundle");
        }
        self.verify_admission_identity(expected)
            .context("generation bundle differs from its server-owned admission identity")?;
        let signature = BASE64_STANDARD
            .decode(&self.signature.signature_base64)
            .context("decode generation bundle Ed25519 signature")?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("generation bundle Ed25519 signature length differs"))?;
        let verifying_key = VerifyingKey::from_bytes(&expected.signer_public_key)
            .context("parse generation bundle Ed25519 public key")?;
        verifying_key
            .verify_strict(
                &self.manifest.signature_message()?,
                &Signature::from_bytes(&signature),
            )
            .context("verify generation bundle Ed25519 signature")
    }
}

/// Server-owned expectations a Bronze publisher holds before it adopts a
/// prevalence hand-off. There is no PostgreSQL pointer: the newest signed
/// manifest under the tenant's hand-off prefix is discovered by listing, so
/// the Ed25519 signature, tenant, table, and signer identity are the fence.
#[derive(Clone, Debug)]
pub struct PrevalenceHandoffAdmission {
    pub tenant_id: Uuid,
    pub table_uuid: Uuid,
    pub table_location: String,
    pub signer_key_id: String,
    pub signer_public_key: [u8; 32],
    /// Which trust root signed the hand-off: the tenant-scoped local seed
    /// under [`PREVALENCE_HANDOFF_SIGNATURE_DOMAIN`], or the Nano Main owner
    /// key under [`GENERATION_BUNDLE_SIGNATURE_DOMAIN`] once the owner's
    /// contract admits prevalence-only manifests. Either way a hand-off can
    /// never be admitted as a retained generation (`is_prevalence_handoff`).
    pub signature_domain: PrevalenceHandoffSignatureDomain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrevalenceHandoffSignatureDomain {
    /// Local per-tenant hand-off seed (`nano-lake-prevalence-handoff-v1`).
    Handoff,
    /// Nano Main owner signer (`nano-lake-generation-bundle-v3`).
    Bundle,
}

impl PrevalenceHandoffSignatureDomain {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "handoff" => Ok(Self::Handoff),
            "bundle" => Ok(Self::Bundle),
            _ => bail!("prevalence hand-off signature domain must be handoff or bundle"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handoff => PREVALENCE_HANDOFF_SIGNATURE_DOMAIN,
            Self::Bundle => GENERATION_BUNDLE_SIGNATURE_DOMAIN,
        }
    }
}

impl SignedGenerationBundleManifest {
    /// Verify an ingest prevalence hand-off. Unlike exact query admission this
    /// does not bind the manifest-list, derivative-contract, HMAC, or read
    /// schema digests up front: the consumer learns them from the signed
    /// manifest and then checks the ones it can (the HMAC key digest) itself.
    pub fn verify_prevalence_handoff(&self, expected: &PrevalenceHandoffAdmission) -> Result<()> {
        self.manifest.validate_structure()?;
        if !self.manifest.is_prevalence_handoff() {
            bail!("generation bundle is not a prevalence hand-off");
        }
        if self.manifest.published_sequence.is_none_or(|sequence| sequence == 0) {
            bail!("prevalence hand-off manifest carries no signed publication sequence");
        }
        if self.signature.domain != expected.signature_domain.as_str()
            || self.signature.key_id != expected.signer_key_id
            || self.manifest.tenant_id != expected.tenant_id
            || self.manifest.table_uuid != expected.table_uuid
            || self.manifest.table_location.trim_end_matches('/')
                != expected.table_location.trim_end_matches('/')
        {
            bail!("prevalence hand-off differs from its server-owned admission identity");
        }
        let signature = BASE64_STANDARD
            .decode(&self.signature.signature_base64)
            .context("decode prevalence hand-off Ed25519 signature")?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("prevalence hand-off Ed25519 signature length differs"))?;
        let verifying_key = VerifyingKey::from_bytes(&expected.signer_public_key)
            .context("parse prevalence hand-off Ed25519 public key")?;
        verifying_key
            .verify_strict(
                &self
                    .manifest
                    .signature_message_for_domain(expected.signature_domain.as_str())?,
                &Signature::from_bytes(&signature),
            )
            .context("verify prevalence hand-off Ed25519 signature")
    }
}

/// Listing prefix under which every prevalence hand-off manifest for one
/// tenant table is published. Immutable keys: a consumer lists and picks the
/// newest snapshot, it never overwrites a pointer.
pub fn prevalence_handoff_prefix(tenant_id: Uuid, table_uuid: Uuid) -> String {
    format!("{tenant_id}/prevalence-artifact/v1/handoff/{table_uuid}/")
}

/// Exact key of one signed hand-off manifest. The key stays inside the
/// `prevalence-artifact` writer family (so the existing owner permit class
/// covers it). Unlike the retained-generation family, that family's key
/// contract admits ONLY content-addressed `…/sha256/<sha256>…` names (no
/// `manifest-<sha>.json` form), so the manifest is addressed by its own
/// digest under a `sha256/` segment with a `.manifest` suffix. The signed
/// `published_sequence` is a key segment so a consumer can order hand-offs
/// from the listing alone and fetch only the newest.
pub fn prevalence_handoff_manifest_key(
    tenant_id: Uuid,
    table_uuid: Uuid,
    snapshot_id: i64,
    manifest_list_sha256: &str,
    bundle_identity_sha256: &str,
    published_sequence: u64,
    manifest_sha256: &str,
) -> Result<String> {
    if snapshot_id <= 0
        || published_sequence == 0
        || !lower_sha256(manifest_list_sha256)
        || !lower_sha256(bundle_identity_sha256)
        || !lower_sha256(manifest_sha256)
    {
        bail!("prevalence hand-off manifest key identity is malformed");
    }
    Ok(format!(
        "{}{}-{}/{}/{}/sha256/{}.manifest",
        prevalence_handoff_prefix(tenant_id, table_uuid),
        snapshot_id,
        &manifest_list_sha256[..16],
        &bundle_identity_sha256[..16],
        published_sequence,
        manifest_sha256
    ))
}

/// Parsed identity of one hand-off manifest key beneath
/// [`prevalence_handoff_prefix`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevalenceHandoffKey {
    pub snapshot_id: i64,
    pub manifest_list_sha256_prefix: String,
    pub bundle_identity_sha256_prefix: String,
    /// Publication order as carried in the key; must equal the signed
    /// manifest's `published_sequence` (the consumer checks the canonical key).
    pub published_sequence: u64,
    pub manifest_sha256: String,
}

pub fn parse_prevalence_handoff_manifest_key(
    tenant_id: Uuid,
    table_uuid: Uuid,
    key: &str,
) -> Option<PrevalenceHandoffKey> {
    let rest = key.strip_prefix(&prevalence_handoff_prefix(tenant_id, table_uuid))?;
    let mut parts = rest.split('/');
    let snapshot_and_list = parts.next()?;
    let bundle_prefix = parts.next()?;
    let sequence = parts.next()?;
    if parts.next()? != "sha256" {
        return None;
    }
    let file = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let (snapshot, list_prefix) = snapshot_and_list.split_once('-')?;
    let snapshot_id = snapshot.parse::<i64>().ok()?;
    let manifest_sha256 = file.strip_suffix(".manifest")?;
    let published_sequence = sequence.parse::<u64>().ok()?;
    let hex16 = |value: &str| value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if snapshot_id <= 0
        || snapshot != snapshot_id.to_string()
        || published_sequence == 0
        || sequence != published_sequence.to_string()
        || !hex16(list_prefix)
        || !hex16(bundle_prefix)
        || !lower_sha256(manifest_sha256)
    {
        return None;
    }
    Some(PrevalenceHandoffKey {
        snapshot_id,
        manifest_list_sha256_prefix: list_prefix.to_string(),
        bundle_identity_sha256_prefix: bundle_prefix.to_string(),
        published_sequence,
        manifest_sha256: manifest_sha256.to_string(),
    })
}

/// Install a verified prevalence hand-off into `target`, which must be absent.
/// The archive members are extracted exactly as published (the builder's
/// `prevalence-snapshot-v2/` tree); the consumer projects its own serving
/// config from the tree's `manifest.json`, so no local manifest rebase runs
/// here and no authoritative snapshot directory is required.
pub async fn hydrate_prevalence_handoff(
    reader: &dyn GenerationBundleObjectReader,
    signed: &SignedGenerationBundleManifest,
    target: &Path,
) -> Result<GenerationBundleHydration> {
    let started = Instant::now();
    if !target.is_absolute() {
        bail!("prevalence hand-off target must be an absolute directory");
    }
    if target.exists() {
        bail!("prevalence hand-off target must be absent");
    }
    if !signed.manifest.is_prevalence_handoff() {
        bail!("generation bundle is not a prevalence hand-off");
    }
    let parent = target
        .parent()
        .context("prevalence hand-off target has no parent")?;
    std::fs::create_dir_all(parent)?;
    let hydrated_bytes = signed
        .manifest
        .artifacts
        .iter()
        .try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.unpacked_bytes)
                .context("prevalence hand-off hydrated byte total overflow")
        })?;
    let candidate = tempfile::Builder::new()
        .prefix(".prevalence-handoff-")
        .tempdir_in(parent)
        .context("create prevalence hand-off hydration candidate")?;
    for artifact in &signed.manifest.artifacts {
        if artifact.family != GenerationBundleArtifactFamily::PrevalenceArtifact {
            bail!("prevalence hand-off carries a non-prevalence artifact");
        }
        let bytes = reader
            .read_exact(
                &artifact.key,
                artifact.bytes,
                &artifact.sha256,
                &artifact.etag,
            )
            .await
            .with_context(|| format!("download prevalence hand-off artifact {}", artifact.role))?;
        extract_archive(candidate.path(), artifact, &bytes)
            .with_context(|| format!("extract prevalence hand-off archive {}", artifact.role))?;
    }
    sync_tree(candidate.path())?;
    let candidate_path = candidate.keep();
    if let Err(error) = std::fs::rename(&candidate_path, target) {
        let _ = std::fs::remove_dir_all(&candidate_path);
        return Err(error).context("atomically admit prevalence hand-off");
    }
    File::open(parent)?.sync_all()?;
    Ok(GenerationBundleHydration {
        payload_hashed_bytes: 0, downloaded_payload_bytes: 0,
        bundle_identity_sha256: signed.manifest.bundle_identity_sha256.clone(),
        generation_id: signed.manifest.generation_id.clone(),
        artifacts: signed.manifest.artifacts.len(),
        bytes: hydrated_bytes,
        verify_seconds: started.elapsed().as_secs_f64(),
        disk: None,
    })
}

#[derive(Clone, Debug)]
pub struct PublishedGenerationBundlePointer {
    pub bundle_identity_sha256: String,
    pub manifest_key: String,
    pub manifest_sha256: String,
    pub manifest_bytes: u64,
    pub manifest_etag: String,
    pub assignment_revision: i64,
    pub irreversible_event_time_floor: DateTime<Utc>,
}

impl PublishedGenerationBundlePointer {
    pub fn validate(&self, expected_identity: &str) -> Result<()> {
        if self.bundle_identity_sha256 != expected_identity
            || !lower_sha256(&self.bundle_identity_sha256)
            || !lower_sha256(&self.manifest_sha256)
            || self.manifest_bytes == 0
            || self.manifest_bytes > MAX_GENERATION_BUNDLE_REF_MANIFEST_BYTES
            || self.assignment_revision <= 0
            || !strong_etag(&self.manifest_etag)
            || !safe_object_key(&self.manifest_key)
            || !self
                .manifest_key
                .contains("/retained-generation/v1/bundles/")
            || !self
                .manifest_key
                .ends_with(&format!("manifest-{}.json", self.manifest_sha256))
        {
            bail!("published generation bundle pointer is malformed");
        }
        Ok(())
    }
}

pub trait GenerationBundleObjectReader: Send + Sync {
    fn read_exact<'a>(
        &'a self,
        key: &'a str,
        expected_bytes: u64,
        expected_sha256: &'a str,
        expected_etag: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

    /// The default adapter is for bounded metadata/test readers. Production
    /// readers override this to apply channel backpressure to the GET body.
    fn read_to<'a>(
        &'a self,
        artifact: &'a GenerationBundleArtifact,
        sender: tokio::sync::mpsc::Sender<bytes::Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let bytes = self.read_exact(&artifact.key, artifact.bytes, &artifact.sha256, &artifact.etag).await?;
            for chunk in bytes.chunks(256 * 1024) {
                sender.send(bytes::Bytes::copy_from_slice(chunk)).await.context("archive receiver stopped")?;
            }
            Ok(())
        })
    }

}

#[derive(Clone)]
pub struct EnterpriseSharedR2BundleReader {
    operator: Operator,
}

impl EnterpriseSharedR2BundleReader {
    pub fn new(operator: Operator) -> Self {
        Self { operator }
    }

    pub fn operator(&self) -> &Operator {
        &self.operator
    }
}

impl GenerationBundleObjectReader for EnterpriseSharedR2BundleReader {
    fn read_exact<'a>(
        &'a self,
        key: &'a str,
        expected_bytes: u64,
        expected_sha256: &'a str,
        expected_etag: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            crate::object_identity::read_exact(
                &self.operator,
                key,
                expected_bytes,
                Some(expected_sha256),
                Some(expected_etag),
            )
            .await
            .map(|(bytes, _)| bytes)
        })
    }

    fn read_to<'a>(
        &'a self,
        artifact: &'a GenerationBundleArtifact,
        sender: tokio::sync::mpsc::Sender<bytes::Bytes>,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            crate::object_identity::read_exact_stream(
                &self.operator, &artifact.key, artifact.bytes, Some(&artifact.sha256), Some(&artifact.etag),
                |bytes| {
                    let sender = sender.clone();
                    async move {
                        for offset in (0..bytes.len()).step_by(256 * 1024) {
                            sender.send(bytes.slice(offset..(offset + 256 * 1024).min(bytes.len()))).await.context("archive receiver stopped")?;
                        }
                        Ok(())
                    }
                },
            ).await?;
            Ok(())
        })
    }

}

#[derive(Clone, Debug, PartialEq)]
pub struct GenerationBundleHydration {
    /// SHA input for transferred payloads and admission, excluding small signed metadata.
    pub payload_hashed_bytes: u64,
    pub downloaded_payload_bytes: u64,
    pub bundle_identity_sha256: String,
    pub generation_id: String,
    pub artifacts: usize,
    pub bytes: u64,
    pub verify_seconds: f64,
    pub disk: Option<GenerationBundleDiskAccounting>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationBundleDiskBudget {
    pub generations_root: std::path::PathBuf,
    pub max_local_bytes: u64,
    pub reserve_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationBundleDiskAccounting {
    pub reused_bytes: u64,
    pub new_bytes: u64,
    pub current_allocated_bytes: u64,
    pub staging_allocated_bytes: u64,
    /// What the generation DIRECTORY retains. For an inventory generation the
    /// derivative bytes live in the shared content store, not here, so this is
    /// the link/entry cost plus each rebased `manifest.json` -- the same thing
    /// `preflight_existing_disk_budget` measures for an already-admitted
    /// generation.
    pub final_derivative_allocated_bytes: u64,
    /// Content-store growth this generation retains (0 for legacy bundles and
    /// for an already-admitted generation, which adds nothing new). Sizing a
    /// local cap means adding this to `final_derivative_allocated_bytes`.
    pub final_object_store_allocated_bytes: u64,
    pub peak_allocated_bytes: u64,
    pub available_bytes_before: u64,
    pub max_local_bytes: u64,
    pub reserve_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "generation bundle has insufficient local capacity: reused={reused_bytes} new={new_bytes} current={current_allocated_bytes} staging={staging_allocated_bytes} peak={peak_allocated_bytes} cap={max_local_bytes} available={available_bytes_before} reserve={reserve_bytes} shortfall={shortfall_bytes} content_addressed={content_addressed}"
)]
pub struct GenerationBundleCapacityError {
    pub shortfall_bytes: u64,
    /// NAN-2559: whether the staging term was content-addressed. False means
    /// the publisher emitted a legacy archive bundle, so the whole successor
    /// had to be staged beside the generation being served and this shortfall
    /// is the 2x staging requirement, not a workload that outgrew its volume.
    /// Publish with an inventory (LAKE_GENERATION_BUNDLE_INCREMENTAL_INVENTORY,
    /// default on) and the staging term collapses to the delta. True with
    /// `staging=0` is an already-admitted generation, which stages nothing.
    pub content_addressed: bool,
    pub reused_bytes: u64,
    pub new_bytes: u64,
    pub current_allocated_bytes: u64,
    pub staging_allocated_bytes: u64,
    pub peak_allocated_bytes: u64,
    pub max_local_bytes: u64,
    pub available_bytes_before: u64,
    pub reserve_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationBundleAdmissionReceipt {
    schema_version: u8,
    bundle_identity_sha256: String,
    generation_id: String,
    manifest_key: String,
    manifest_sha256: String,
    manifest_bytes: u64,
    manifest_etag: String,
    signer_key_id: String,
    local_files: Vec<GenerationBundleAdmissionFile>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationBundleAdmissionFile {
    relative_path: String,
    sha256: String,
    bytes: u64,
}

fn validate_bundle_pointer(
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
) -> Result<()> {
    let expected_identity = bundle_identity(&GenerationBundleIdentity {
        tenant_id: expected.tenant_id,
        table_uuid: expected.table_uuid,
        snapshot_id: expected.snapshot_id,
        manifest_list_sha256: &expected.manifest_list_sha256,
        derivative_contract_sha256: &expected.derivative_contract_sha256,
        hmac_key_sha256: &expected.hmac_key_sha256,
        read_schema_sha256: &expected.read_schema_sha256,
    })?;
    pointer.validate(&expected_identity)?;
    let expected_manifest_key = format!(
        "{}/retained-generation/v1/bundles/{}/{}-{}/{}/manifest-{}.json",
        expected.tenant_id,
        expected.table_uuid,
        expected.snapshot_id,
        &expected.manifest_list_sha256[..16],
        &expected_identity[..16],
        pointer.manifest_sha256
    );
    if pointer.manifest_key != expected_manifest_key {
        bail!("published generation bundle pointer escaped its exact tenant identity");
    }
    if pointer.assignment_revision != expected.assignment_revision
        || pointer.irreversible_event_time_floor < expected.irreversible_event_time_floor
    {
        bail!("published generation bundle pointer is stale");
    }
    Ok(())
}

/// Authenticate the publisher's metadata pin before reading any Iceberg data.
/// The object inventory is checked independently after snapshot hydration.
pub async fn published_metadata_location(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
) -> Result<String> {
    validate_bundle_pointer(pointer, expected)?;
    let bytes = reader
        .read_exact(
            &pointer.manifest_key,
            pointer.manifest_bytes,
            &pointer.manifest_sha256,
            &pointer.manifest_etag,
        )
        .await?;
    let signed: SignedGenerationBundleManifest = serde_json::from_slice(&bytes)?;
    let mut admission = expected.clone();
    admission.object_stamp_manifest_sha256 = signed.manifest.object_stamp_manifest_sha256.clone();
    signed.verify(&admission)?;
    pointer.validate(&signed.manifest.bundle_identity_sha256)?;
    Ok(signed.manifest.iceberg_metadata_location)
}

/// Check the complete source + derivative peak before downloading event data.
/// Only the signed manifest and its small source inventory are read here.
pub async fn preflight_generation_bundle(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
    budget: &GenerationBundleDiskBudget,
    reclaim: impl FnOnce() -> Result<()>,
) -> Result<GenerationBundleDiskAccounting> {
    preflight_generation_bundle_proven(reader, pointer, expected, target, budget, None, None, reclaim).await
}

pub async fn preflight_generation_bundle_proven(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
    budget: &GenerationBundleDiskBudget,
    proof_key: Option<&[u8]>,
    prior_source: Option<&crate::generation_proof::Body>,
    reclaim: impl FnOnce() -> Result<()>,
) -> Result<GenerationBundleDiskAccounting> {
    validate_bundle_pointer(pointer, expected)?;
    let bytes = reader
        .read_exact(
            &pointer.manifest_key,
            pointer.manifest_bytes,
            &pointer.manifest_sha256,
            &pointer.manifest_etag,
        )
        .await?;
    let signed: SignedGenerationBundleManifest = serde_json::from_slice(&bytes)?;
    let mut admission = expected.clone();
    admission.object_stamp_manifest_sha256 = signed.manifest.object_stamp_manifest_sha256.clone();
    signed.verify(&admission)?;
    pointer.validate(&signed.manifest.bundle_identity_sha256)?;
    let manifest = signed.manifest;
    let source = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.role == "source-object-stamps")
        .context("signed bundle omitted source inventory")?;
    let archive = reader
        .read_exact(&source.key, source.bytes, &source.sha256, &source.etag)
        .await?;
    let stamps: ObjectStampManifest =
        serde_json::from_slice(single_archive_member(source, &archive)?)?;
    validate_source_object_stamps(&stamps, &manifest)?;
    if object_stamp_manifest_sha256(&GenerationBundleObjectStampManifest::from(&stamps))?
        != manifest.object_stamp_manifest_sha256
    {
        bail!("signed source inventory digest differs");
    }
    let snapshot = target
        .parent()
        .context("bundle target has no parent")?
        .join("snapshot");
    let prior_stamps = prior_source.filter(|proof| proof.root.parent() == Some(budget.generations_root.as_path())
        && proof.identity.tenant_id == expected.tenant_id.to_string() && proof.identity.table_uuid == expected.table_uuid.to_string())
        .and_then(|proof| {
            let path = proof.root.join("snapshot/object-stamps.json");
            proof.file_digest(&path)?;
            serde_json::from_slice::<ObjectStampManifest>(&std::fs::read(path).ok()?).ok()
        });
    let prior_objects: BTreeMap<_, _> = prior_stamps.as_ref().map(|stamps| stamps.objects.iter().map(|o| (o.source_uri.as_str(), o)).collect()).unwrap_or_default();
    let mut source_reused_bytes = 0u64;
    let mut source_new_bytes = 0u64;
    let source_allocation = if snapshot.exists() {
        0
    } else {
        stamps.objects.iter().try_fold(0_u64, |total, object| {
            let reused = prior_objects.get(object.source_uri.as_str()).is_some_and(|prior|
                prior.version_id == object.version_id && prior.relative_path == object.relative_path
                && prior.size_bytes == object.size_bytes && prior.sha256 == object.sha256
                && prior_source.is_some_and(|proof| proof.file_digest(&proof.root.join("snapshot/data").join(&prior.relative_path)) == Some(object.sha256.as_str())));
            let counter = if reused { &mut source_reused_bytes } else { &mut source_new_bytes };
            *counter = counter.checked_add(object.size_bytes).context("source byte accounting overflow")?;
            total
                .checked_add(if reused { DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES } else { conservative_allocated_bytes(object.size_bytes)? })
                .context("generation source allocation overflow")
        })?
    };
    let check = || {
        if target.exists() && snapshot.exists() {
            preflight_existing_disk_budget(budget, target)
        } else {
            let mut seen = BTreeSet::new();
            let reused = manifest.derivative_inventory.as_deref().unwrap_or(&[]).iter().filter(|member|
                proof_key.is_some_and(|key| !seen.insert(member.sha256.clone()) || crate::generation_proof::reusable_object(&budget.generations_root, &member.sha256, member.bytes, key).is_ok()))
                .map(|m| m.relative_path.clone()).collect();
            preflight_disk_budget_reusing(budget, target, &manifest, source_allocation, &reused)
                .map(|mut accounting| { accounting.reused_bytes += source_reused_bytes; accounting.new_bytes += source_new_bytes; accounting })
                .map_err(|error| match error.downcast::<GenerationBundleCapacityError>() {
                    Ok(mut capacity) => { capacity.reused_bytes += source_reused_bytes; capacity.new_bytes += source_new_bytes; capacity.into() }
                    Err(error) => error,
                })
        }
    };
    match check() {
        Err(error)
            if error
                .downcast_ref::<GenerationBundleCapacityError>()
                .is_some() =>
        {
            reclaim()?;
            check()
        }
        result => result,
    }
}

/// Hydrate and atomically admit a complete derivative directory. `target`
/// must not exist. This no-budget entry point is used only by the standalone
/// builder, whose caller may treat a cache error as an authoritative rebuild.
pub async fn hydrate_generation_bundle(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
) -> Result<GenerationBundleHydration> {
    hydrate_generation_bundle_inner(reader, pointer, expected, target, None, None, None).await
}

pub async fn hydrate_generation_bundle_with_budget(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
    disk_budget: &GenerationBundleDiskBudget,
) -> Result<GenerationBundleHydration> {
    hydrate_generation_bundle_inner(reader, pointer, expected, target, Some(disk_budget), None, None).await
}

/// Query admission carries the tenant key and in-process snapshot evidence.
pub async fn hydrate_generation_bundle_proven(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
    budget: &GenerationBundleDiskBudget,
    key: &[u8],
    received: Option<&crate::generation_proof::ReceivedFiles>,
) -> Result<GenerationBundleHydration> {
    hydrate_generation_bundle_inner(reader, pointer, expected, target, Some(budget), Some((key, received)), None).await
}

/// `hydrate_generation_bundle_proven` with the same reclaim escape hatch
/// `preflight_generation_bundle_proven` has.
///
/// NAN-2532: the hydrate-time budget is recomputed under the content-store
/// lock, and it is authoritative -- but between preflight and hydrate a
/// concurrent `prune_local_generations`/`collect_objects` can delete an object
/// preflight counted as reusable, so the recheck can fail on capacity for a
/// roll that preflight passed. Without a reclaim retry that fails the roll
/// hard and only recovers on the next reconcile.
pub async fn hydrate_generation_bundle_proven_reclaiming(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
    budget: &GenerationBundleDiskBudget,
    key: &[u8],
    received: Option<&crate::generation_proof::ReceivedFiles>,
    reclaim: &(dyn Fn() -> Result<()> + Send + Sync),
) -> Result<GenerationBundleHydration> {
    hydrate_generation_bundle_inner(reader, pointer, expected, target, Some(budget), Some((key, received)), Some(reclaim)).await
}

pub fn proof_identity(pointer: &PublishedGenerationBundlePointer, signed: &SignedGenerationBundleManifest) -> crate::generation_proof::Identity {
    crate::generation_proof::Identity {
        tenant_id: signed.manifest.tenant_id.to_string(),
        table_uuid: signed.manifest.table_uuid.to_string(),
        snapshot_id: signed.manifest.snapshot_id,
        generation_id: signed.manifest.generation_id.clone(),
        signed_manifest_sha256: pointer.manifest_sha256.clone(),
        source_stamp_sha256: signed.manifest.object_stamp_manifest_sha256.clone(),
        assignment_revision: pointer.assignment_revision,
    }
}

async fn hydrate_generation_bundle_inner(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &GenerationBundleAdmission,
    target: &Path,
    disk_budget: Option<&GenerationBundleDiskBudget>,
    proof_input: Option<(&[u8], Option<&crate::generation_proof::ReceivedFiles>)>,
    reclaim: Option<&(dyn Fn() -> Result<()> + Send + Sync)>,
) -> Result<GenerationBundleHydration> {
    let started = Instant::now();
    if !target.is_absolute() {
        bail!("generation bundle target must be an absolute directory");
    }
    if target.exists() && disk_budget.is_none() {
        bail!("generation bundle builder target must be absent");
    }
    if target.exists()
        && (!std::fs::symlink_metadata(target)?.is_dir()
            || std::fs::symlink_metadata(target)?.file_type().is_symlink())
    {
        bail!("generation bundle target is not a real directory");
    }
    validate_bundle_pointer(pointer, expected)?;
    let manifest_bytes = reader
        .read_exact(
            &pointer.manifest_key,
            pointer.manifest_bytes,
            &pointer.manifest_sha256,
            &pointer.manifest_etag,
        )
        .await
        .context("download signed generation bundle manifest")?;
    let signed: SignedGenerationBundleManifest = serde_json::from_slice(&manifest_bytes)
        .context("decode signed generation bundle manifest")?;
    signed.verify(expected)?;
    if signed.manifest.bundle_identity_sha256 != pointer.bundle_identity_sha256 {
        bail!("signed generation bundle differs from its PostgreSQL pointer");
    }

    let parent = target
        .parent()
        .context("generation bundle target has no parent")?;
    let snapshot_root = parent.join("snapshot");
    if !snapshot_root.is_dir() || !snapshot_root.join("object-stamps.json").is_file() {
        bail!("generation bundle requires the already-hydrated authoritative snapshot");
    }
    let hydrated_bytes = signed
        .manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.role != "source-object-stamps")
        .try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.unpacked_bytes)
                .context("generation bundle hydrated byte total overflow")
        })?;
    if target.exists() {
        let budget = disk_budget.expect("existing target requires a disk budget");
        let proven = proof_input.and_then(|(key, _)| {
            let reference = crate::generation_proof::Reference { path: target.join(crate::generation_proof::FILE_NAME), identity: proof_identity(pointer, &signed) };
            match crate::generation_proof::Body::load(&reference, key) {
                Ok(proof) if proof.root == parent => Some(proof),
                Ok(_) => { tracing::warn!("generation proof root mismatch; full verification required"); None }
                Err(error) => { tracing::warn!(%error, "generation proof unavailable; full verification required"); None }
            }
        });
        let disk = if proven.is_some() { preflight_existing_disk_budget(budget, target)? }
            else if let Some((key, _)) = proof_input {
                let known = verify_existing_signed_files(reader, target, &snapshot_root, &signed).await?;
                rebuild_existing_proof(target, &snapshot_root, pointer, &signed, key, &known)?;
                preflight_existing_disk_budget(budget, target)?
            } else { verify_existing_admission_receipt(target, pointer, &signed, budget)? };
        return Ok(GenerationBundleHydration {
            payload_hashed_bytes: 0, downloaded_payload_bytes: 0,
            bundle_identity_sha256: signed.manifest.bundle_identity_sha256,
            generation_id: signed.manifest.generation_id,
            artifacts: signed.manifest.artifacts.len(),
            bytes: hydrated_bytes,
            verify_seconds: started.elapsed().as_secs_f64(),
            disk: Some(disk),
        });
    }
    let inventory = signed.manifest.derivative_inventory.as_deref().unwrap_or(&[]);
    let generations_root = parent.parent().context("generation root missing")?;
    if !inventory.is_empty() && proof_input.is_some() && disk_budget.is_some_and(|budget| budget.generations_root != generations_root) {
        bail!("content store must be directly beneath the budgeted generations root");
    }
    // Held across the download so a concurrent collection cannot delete an
    // object this hydration decided to reuse; explicitly dropped once every
    // object is linked into the private candidate, well before the proof,
    // snapshot hashing and rename. Acquisition is bounded and non-blocking
    // (see `object_store_lock_async`), so a nested collection surfaces as an
    // error rather than a self-deadlock.
    let mut objects_lock = if !inventory.is_empty() && proof_input.is_some() {
        Some(crate::generation_proof::object_store_lock_async(generations_root).await?)
    } else { None };
    let key = proof_input.map(|v| v.0);
    // Without a local authentication key keep the legacy extraction path.
    let incremental = !inventory.is_empty() && key.is_some();
    let probe_reusable = || {
        let mut reused = BTreeMap::new();
        if let Some(key) = key {
            for member in inventory {
                if let Ok(path) = crate::generation_proof::reusable_object(generations_root, &member.sha256, member.bytes, key) {
                    reused.insert(member.relative_path.clone(), path);
                }
            }
        }
        let mut seen_contents = BTreeSet::new();
        let aliases: BTreeSet<_> = inventory.iter().filter(|member| incremental && !seen_contents.insert(member.sha256.clone()))
            .map(|member| member.relative_path.clone()).collect();
        (reused, aliases)
    };
    let (mut reused, mut aliases) = probe_reusable();
    let mut disk = disk_budget.map(|budget| preflight_disk_budget_reusing(budget, target, &signed.manifest, 0, &reused.keys().cloned().chain(aliases.iter().cloned()).collect())).transpose();
    // An object preflight counted as reusable can be collected between
    // preflight and here. Reclaim retained generations and re-probe once
    // rather than failing the roll until the next reconcile.
    if let (Err(error), Some(reclaim)) = (&disk, reclaim) {
        if error.downcast_ref::<GenerationBundleCapacityError>().is_some() {
            tracing::warn!(%error, "hydrate-time capacity recheck failed; reclaiming retained generations and re-probing the content store");
            // Reclaim collects the content store under this very lock.
            let held = objects_lock.take();
            drop(held);
            reclaim()?;
            if !inventory.is_empty() && proof_input.is_some() {
                objects_lock = Some(crate::generation_proof::object_store_lock_async(generations_root).await?);
            }
            let probed = probe_reusable();
            reused = probed.0; aliases = probed.1;
            disk = disk_budget.map(|budget| preflight_disk_budget_reusing(budget, target, &signed.manifest, 0, &reused.keys().cloned().chain(aliases.iter().cloned()).collect())).transpose();
        }
    }
    let disk = disk?;
    std::fs::create_dir_all(parent)?;
    let candidate = tempfile::Builder::new()
        .prefix(".lake-derivatives-")
        .tempdir_in(parent)
        .context("create generation bundle hydration candidate")?;
    let mut admission = AdmissionDigests { trees_enabled: proof_input.is_some() && !incremental,
        inventory: if incremental { inventory.iter().map(|m| (m.relative_path.clone(), m.clone())).collect() } else { BTreeMap::new() },
        ..AdmissionDigests::default() };
    for member in inventory.iter().filter(|m| reused.contains_key(&m.relative_path)) {
        admission.files.insert(member.relative_path.clone(), (member.sha256.clone(), member.bytes));
    }
    // One active GET with eight 256 KiB queued chunks: extents of a large
    // logical file still append in signed order. The extraction state remains
    // sequential, so sibling GETs would risk timing out while waiting to drain.
    // No detached producer: any error drops the GET and private candidate
    // before it can be renamed into a serving directory.
    let pending: Vec<_> = signed.manifest.artifacts.iter().filter(|a| !a.members.iter().all(|m| reused.contains_key(&m.relative_path) || aliases.contains(&m.relative_path))).collect();
    let downloaded_payload_bytes = pending.iter().map(|a| a.bytes).sum::<u64>();
    let mut source_hashed_bytes = 0u64;

    // NAN-2532: the incremental-inventory publisher emits ONE raw object per
    // derivative file, so a cold bundle that used to be ~18 shard GETs becomes
    // N GETs. At one active GET that is N sequential round-trips and cold pod
    // start regresses badly with file count (measured in
    // `nan2532_cold_hydration_legacy_vs_inventory`). Raw objects share no
    // extraction state -- each one is a whole file, or an extent at a signed
    // offset of one file -- so they fan out. Extents of the SAME logical file
    // stay ordered within their group; different files are independent.
    let (raw_pending, archive_pending): (Vec<_>, Vec<_>) = pending
        .iter()
        .copied()
        .partition(|artifact| artifact.role.starts_with("inventory-object-") && artifact.unpacked_bytes > 0);
    let mut raw_groups: BTreeMap<&str, Vec<&GenerationBundleArtifact>> = BTreeMap::new();
    for artifact in &raw_pending {
        raw_groups.entry(artifact.members[0].relative_path.as_str()).or_default().push(artifact);
    }
    for extents in raw_groups.values_mut() {
        extents.sort_by_key(|artifact| artifact.members[0].offset);
    }
    if !raw_groups.is_empty() {
        use futures::{StreamExt, TryStreamExt};
        let candidate_root = candidate.path();
        let fetched: Vec<&str> = futures::stream::iter(raw_groups.into_iter().map(|(relative_path, extents)| async move {
            for artifact in extents {
                let member = &artifact.members[0];
                let path = candidate_root.join(&member.relative_path);
                std::fs::create_dir_all(path.parent().context("raw object parent missing")?)?;
                let mut options = OpenOptions::new();
                options.write(true);
                if member.offset == 0 { options.create_new(true); } else { options.append(true); }
                let mut file = options.open(&path)?;
                if file.metadata()?.len() != member.offset { bail!("raw object offset mismatch"); }
                let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
                let download = reader.read_to(artifact, sender);
                let write = async {
                    let mut total = 0u64;
                    while let Some(bytes) = receiver.recv().await {
                        total = total.checked_add(bytes.len() as u64).context("object size overflow")?;
                        if total > member.bytes { bail!("raw object exceeds declared size"); }
                        file.write_all(&bytes)?;
                    }
                    if total != member.bytes { bail!("raw object truncated"); }
                    file.sync_all()?;
                    Ok::<_, anyhow::Error>(())
                };
                tokio::try_join!(download, write)?;
            }
            Ok::<_, anyhow::Error>(relative_path)
        }))
        .buffer_unordered(raw_object_fetch_concurrency())
        .try_collect()
        .await?;
        for relative_path in fetched {
            if incremental {
                let member = &admission.inventory[relative_path];
                // The owner signs both the complete file identity and its
                // ordered extent digests. Each extent was authenticated once
                // by read_to, including ETag/size.
                admission.files.insert(relative_path.to_owned(), (member.sha256.clone(), member.bytes));
                continue;
            }
            // No HMAC key: still verify the raw transfer, then use the legacy
            // local layout and transformed manifests.
            let member = inventory.iter().find(|i| i.relative_path == relative_path).context("unlisted raw object")?;
            admission.files.insert(relative_path.to_owned(), (member.sha256.clone(), member.bytes));
            if relative_path.ends_with("/manifest.json") {
                if member.bytes > MAX_PORTABLE_MANIFEST_BYTES {
                    bail!("portable manifest exceeds bound: {relative_path} is {} bytes, bound is {MAX_PORTABLE_MANIFEST_BYTES}", member.bytes);
                }
                let path = candidate.path().join(relative_path);
                let rebased = rebase_manifest_file(&path, &path, target, &snapshot_root)?;
                admission.files.insert(relative_path.to_owned(), rebased);
            }
        }
    }
    let pending = archive_pending;
    for batch in pending.chunks(1) {
        let mut downloads = futures::stream::FuturesUnordered::new();
        let mut receivers = Vec::new();
        for artifact in batch {
            let (sender, receiver) = tokio::sync::mpsc::channel(8);
            downloads.push(reader.read_to(artifact, sender));
            receivers.push((artifact, receiver));
        }
        let download = async {
            use futures::TryStreamExt;
            while downloads.try_next().await?.is_some() {}
            Ok::<_, anyhow::Error>(())
        };
        let extract = async {
            for (artifact, mut receiver) in receivers {
                let mut extractor = StreamingArchive::new(candidate.path(), artifact)?;
                while let Some(bytes) = receiver.recv().await {
                    extractor.receive(&bytes, &mut admission, target, &snapshot_root)?;
                }
                extractor.finish()?;
            }
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(download, extract)?;
    }
    if !admission.partial.is_empty() { bail!("generation admission has incomplete file digests"); }
    let source_stamps: GenerationBundleObjectStampManifest = serde_json::from_slice(
        &std::fs::read(candidate.path().join("bundle-metadata/object-stamps.json"))?,
    )?;
    if object_stamp_manifest_sha256(&source_stamps)? != signed.manifest.object_stamp_manifest_sha256
    {
        bail!("generation bundle source-stamp identity differs from its signed digest");
    }
    std::fs::remove_dir_all(candidate.path().join("bundle-metadata"))
        .context("remove generation bundle source-inventory staging member")?;
    // Manifests were transformed before their admission digests were accumulated.
    admission.files.remove("bundle-metadata/object-stamps.json");
    if incremental {
        for member in inventory {
            let local = candidate.path().join(&member.relative_path);
            std::fs::create_dir_all(local.parent().context("object parent missing")?)?;
            let object = if let Some(path) = reused.get(&member.relative_path) { path.clone() }
                else if aliases.contains(&member.relative_path) { crate::generation_proof::reusable_object(generations_root, &member.sha256, member.bytes, key.unwrap())? }
                else { crate::generation_proof::install_object(generations_root, &local, &member.sha256, member.bytes, key.unwrap(), crate::generation_proof::ObjectSource::Authenticated)? };
            if member.relative_path.ends_with("/manifest.json") {
                if member.bytes > MAX_PORTABLE_MANIFEST_BYTES {
                    bail!("portable manifest exceeds bound: {} is {} bytes, bound is {MAX_PORTABLE_MANIFEST_BYTES}", member.relative_path, member.bytes);
                }
                // write_candidate_file used create_new; keep refusing a preexisting file.
                if std::fs::symlink_metadata(&local).is_ok() { bail!("portable manifest candidate already exists: {}", member.relative_path); }
                let (digest, bytes) = rebase_manifest_file(&object, &local, target, &snapshot_root)?;
                admission.hashed_bytes += bytes;
                admission.files.insert(member.relative_path.clone(), (digest, bytes));
            } else {
                std::os::unix::fs::symlink(&object, &local)?;
                admission.files.insert(member.relative_path.clone(), (member.sha256.clone(), member.bytes));
            }
        }
    }
    // Every object is now linked from the private candidate, which
    // `collect_objects` scans, so the content store no longer needs this
    // writer's lock for the proof, snapshot hashing, sync and rename below.
    drop(objects_lock.take());
    if disk_budget.is_some() {
        let receipt = admission_receipt(pointer, &signed, admission.files.iter().map(|(path, (sha256, bytes))| GenerationBundleAdmissionFile {
            relative_path: path.clone(), sha256: sha256.clone(), bytes: *bytes,
        }).collect());
        write_candidate_file(&candidate.path().join(GENERATION_BUNDLE_ADMISSION_RECEIPT), &serde_json::to_vec(&receipt)?)?;
    }
    if let Some((key, received)) = proof_input {
        let mut proof = crate::generation_proof::Body::new(proof_identity(pointer, &signed), parent.to_path_buf());
        let prefix = target.file_name().context("derivative root has no name")?.to_str().context("invalid derivative root")?;
        for (path, (digest, _)) in &admission.files {
            let local = candidate.path().join(path);
            if std::fs::symlink_metadata(&local)?.file_type().is_symlink() {
                proof.record_object(&format!("{prefix}/{path}"), &local, digest)?;
            } else { proof.record(&format!("{prefix}/{path}"), &local, digest.clone())?; }
        }
        if incremental {
            proof.derivative_inventory = inventory.to_vec();
            proof.inventory_trees(prefix)?;
        }
        let receipt_path = candidate.path().join(GENERATION_BUNDLE_ADMISSION_RECEIPT);
        if receipt_path.exists() {
            proof.record(&format!("{prefix}/{GENERATION_BUNDLE_ADMISSION_RECEIPT}"), &receipt_path,
                crate::generation_proof::sha(&std::fs::read(&receipt_path)?))?;
        }
        for (directory, tree) in admission.trees {
            if tree.invalid { tracing::warn!(%directory, "archive members are not in tree order; full tree verification required"); }
            if !tree.invalid {
                proof.trees.insert(format!("{prefix}/{directory}"), crate::generation_proof::TreeRecord {
                    sha256: hex::encode(tree.hash.finalize()), members: tree.members,
                });
            }
        }
        let stamps_path = snapshot_root.join("object-stamps.json");
        let stamps: ObjectStampManifest = serde_json::from_slice(&std::fs::read(&stamps_path)?)?;
        if object_stamp_manifest_sha256(&GenerationBundleObjectStampManifest::from(&stamps))? != proof.identity.source_stamp_sha256 {
            bail!("local source stamps differ from signed bundle");
        }
        for object in &stamps.objects {
            let path = snapshot_root.join("data").join(&object.relative_path);
            let trusted = received.and_then(|files| files.0.get(&path)).is_some_and(|record|
                record.sha256 == object.sha256 && record.bytes == object.size_bytes
                && record.drift_at(&path).trusted());
            if !trusted {
                tracing::debug!(path = %path.display(), "snapshot admission evidence absent; full verification");
                source_hashed_bytes += object.size_bytes;
                if file_sha256_and_bytes(&path)? != (object.sha256.clone(), object.size_bytes) { bail!("snapshot proof admission digest mismatch"); }
            }
            proof.record(&format!("snapshot/data/{}", object.relative_path), &path, object.sha256.clone())?;
        }
        let schema_path = snapshot_root.join("clickhouse-read-schema.sql");
        if schema_path.exists() {
            let bytes = std::fs::read(&schema_path)?;
            let digest = crate::generation_proof::sha(&bytes);
            if digest != signed.manifest.read_schema_sha256 { bail!("proof read schema mismatch"); }
            proof.record("snapshot/clickhouse-read-schema.sql", &schema_path, digest)?;
        }
        proof.record("snapshot/object-stamps.json", &stamps_path, crate::generation_proof::sha(&std::fs::read(&stamps_path)?))?;
        proof.save(&candidate.path().join(crate::generation_proof::FILE_NAME), key)?;
    }
    sync_tree(candidate.path())?;
    let candidate_path = candidate.keep();
    if let Err(error) = std::fs::rename(&candidate_path, target) {
        let _ = std::fs::remove_dir_all(&candidate_path);
        return Err(error).context("atomically admit generation bundle");
    }
    File::open(parent)?.sync_all()?;
    Ok(GenerationBundleHydration {
        payload_hashed_bytes: downloaded_payload_bytes + admission.hashed_bytes + source_hashed_bytes,
        downloaded_payload_bytes,
        bundle_identity_sha256: signed.manifest.bundle_identity_sha256,
        generation_id: signed.manifest.generation_id,
        artifacts: signed.manifest.artifacts.len(),
        bytes: hydrated_bytes,
        verify_seconds: started.elapsed().as_secs_f64(),
        disk,
    })
}

/// Recover a compatible predecessor into a standalone builder's own cache.
/// Unlike exact query admission, the prior object-stamp digest is learned from
/// the owner-signed manifest after the caller has proved the snapshot's
/// manifest-list digest and ancestry. No query-Pod path participates.
pub async fn hydrate_prior_generation_bundle(
    reader: &dyn GenerationBundleObjectReader,
    pointer: &PublishedGenerationBundlePointer,
    expected: &PriorGenerationBundleAdmission,
    target: &Path,
) -> Result<GenerationBundleHydration> {
    if target.exists() || !target.is_absolute() {
        bail!("prior generation bundle target must be one absent absolute directory");
    }
    let expected_identity = bundle_identity(&GenerationBundleIdentity {
        tenant_id: expected.tenant_id,
        table_uuid: expected.table_uuid,
        snapshot_id: expected.snapshot_id,
        manifest_list_sha256: &expected.manifest_list_sha256,
        derivative_contract_sha256: &expected.derivative_contract_sha256,
        hmac_key_sha256: &expected.hmac_key_sha256,
        read_schema_sha256: &expected.read_schema_sha256,
    })?;
    pointer.validate(&expected_identity)?;
    let manifest_bytes = reader
        .read_exact(
            &pointer.manifest_key,
            pointer.manifest_bytes,
            &pointer.manifest_sha256,
            &pointer.manifest_etag,
        )
        .await
        .context("download signed prior generation bundle manifest")?;
    let signed: SignedGenerationBundleManifest = serde_json::from_slice(&manifest_bytes)
        .context("decode signed prior generation bundle manifest")?;
    let source_stamp_sha256 = signed.manifest.object_stamp_manifest_sha256.clone();
    let exact = GenerationBundleAdmission {
        tenant_id: expected.tenant_id,
        table_uuid: expected.table_uuid,
        table_location: expected.table_location.clone(),
        snapshot_id: expected.snapshot_id,
        manifest_list_sha256: expected.manifest_list_sha256.clone(),
        derivative_contract_sha256: expected.derivative_contract_sha256.clone(),
        hmac_key_sha256: expected.hmac_key_sha256.clone(),
        read_schema_sha256: expected.read_schema_sha256.clone(),
        object_stamp_manifest_sha256: source_stamp_sha256,
        assignment_revision: expected.assignment_revision,
        irreversible_event_time_floor: expected.irreversible_event_time_floor,
        signer_key_id: expected.signer_key_id.clone(),
        signer_public_key: expected.signer_public_key,
    };
    signed.verify(&exact)?;
    if signed.manifest.bundle_identity_sha256 != pointer.bundle_identity_sha256 {
        bail!("signed prior bundle differs from its PostgreSQL pointer");
    }
    let source_artifact = signed
        .manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.role == "source-object-stamps")
        .context("signed prior bundle omits its source-stamp archive")?;
    let source_archive = reader
        .read_exact(
            &source_artifact.key,
            source_artifact.bytes,
            &source_artifact.sha256,
            &source_artifact.etag,
        )
        .await
        .context("download signed prior bundle source-stamp archive")?;
    let stamp_bytes = single_archive_member(source_artifact, &source_archive)?;
    let object_stamps: ObjectStampManifest =
        serde_json::from_slice(stamp_bytes).context("decode signed prior object-stamp manifest")?;
    validate_source_object_stamps(&object_stamps, &signed.manifest)?;
    if object_stamp_manifest_sha256(&GenerationBundleObjectStampManifest::from(&object_stamps))?
        != signed.manifest.object_stamp_manifest_sha256
    {
        bail!("signed prior source-stamp bytes differ from their manifest digest");
    }
    let generation_root = target
        .parent()
        .context("prior generation derivative target has no parent")?;
    let snapshot_root = generation_root.join("snapshot");
    std::fs::create_dir_all(&snapshot_root)?;
    let stamp_path = snapshot_root.join("object-stamps.json");
    if stamp_path.exists() {
        bail!("prior generation object-stamp cache already exists without derivatives");
    }
    let mut stamp_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stamp_path)?;
    stamp_file.write_all(stamp_bytes)?;
    stamp_file.sync_all()?;
    File::open(&snapshot_root)?.sync_all()?;
    hydrate_generation_bundle(reader, pointer, &exact, target).await
}

// A missing or bad authenticated proof cannot turn the unsigned legacy
// receipt into authority. Verify persisted bytes against the owner's signed
// member inventory; reconstruct only the small transformed JSON manifests.
/// Whole-file (sha256, bytes) already proven in this process, keyed by the
/// derivative-relative path, so later passes never hash a file twice. Each
/// entry carries the identity the file had while it was hashed; a file whose
/// identity moved since is hashed again rather than trusted.
type KnownDigests = BTreeMap<String, (String, u64, FileIdentity)>;

/// (dev, inode, size, mtime, mtime_ns, ctime, ctime_ns), following links.
type FileIdentity = (u64, u64, u64, i64, i64, i64, i64);
fn file_identity(path: &Path) -> Result<FileIdentity> {
    let m = std::fs::metadata(path)?;
    Ok((m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()))
}

/// NAN-2837: every signed extent is hashed exactly once, with bounded
/// parallelism, and single-extent files are handed back as proven whole-file
/// digests. This fallback used to hash the derivatives THREE times on one
/// thread (extents here, then `signed_local_inventory` for the path set, then
/// again to rebuild the proof): 1378 s for a 28 GB bundle on tenant1.
async fn verify_existing_signed_files(reader: &dyn GenerationBundleObjectReader, target: &Path, snapshot: &Path, signed: &SignedGenerationBundleManifest) -> Result<KnownDigests> {
    struct Extent { relative: String, path: std::path::PathBuf, offset: u64, bytes: u64, total: u64, sha256: String }
    let mut extents = Vec::new();
    // Only incomplete multi-part manifests are held; each is verified and
    // dropped as soon as its last extent arrives. The bytes themselves must
    // be in memory because the metadata archive is fetched whole.
    let mut manifests = BTreeMap::<String, Vec<u8>>::new();
    let mut verified = BTreeSet::<String>::new();
    let mut expected_paths = BTreeSet::new();
    for artifact in signed.manifest.artifacts.iter().filter(|a| a.role != "source-object-stamps") {
        for member in &artifact.members {
            expected_paths.insert(member.relative_path.clone());
            if member.relative_path.ends_with("/manifest.json") { continue; }
            let path = target.join(&member.relative_path);
            if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
                let inventory = signed.manifest.derivative_inventory.as_ref().context("legacy admission file is a symlink")?;
                let member = inventory.iter().find(|m| m.relative_path == member.relative_path).context("unlisted object link")?;
                let objects_root = target.parent().and_then(Path::parent).context("object root absent")?;
                let object = crate::generation_proof::object_path(objects_root, &member.sha256)?;
                if std::fs::read_link(&path)? != object || crate::generation_proof::Guard::read(&object).is_err() {
                    bail!("signed admission object link differs");
                }
            }
            if std::fs::metadata(&path)?.len() != member.total_bytes { bail!("signed admission file extent mismatch"); }
            extents.push(Extent { relative: member.relative_path.clone(), path, offset: member.offset, bytes: member.bytes,
                total: member.total_bytes, sha256: member.sha256.clone() });
        }
        if !artifact.members.iter().any(|m| m.relative_path.ends_with("/manifest.json")) { continue; }
        let archive = reader.read_exact(&artifact.key, artifact.bytes, &artifact.sha256, &artifact.etag).await?;
        if artifact.role.starts_with("inventory-object-") {
            let member = &artifact.members[0];
            if member.total_bytes > MAX_PORTABLE_MANIFEST_BYTES {
                bail!("signed metadata exceeds bound: {} is {} bytes, bound is {MAX_PORTABLE_MANIFEST_BYTES}",
                    member.relative_path, member.total_bytes);
            }
            if member.offset == 0 && archive.len() as u64 == member.total_bytes && !manifests.contains_key(&member.relative_path) {
                // Whole manifest in one object: verify straight from the
                // fetched bytes instead of copying them into the map.
                verify_rebased_manifest(target, snapshot, &member.relative_path, &archive)?;
                verified.insert(member.relative_path.clone());
                continue;
            }
            manifests.entry(member.relative_path.clone()).or_default().extend_from_slice(&archive);
            continue;
        }
        let mut cursor = GENERATION_BUNDLE_ARCHIVE_MAGIC.len() + 4;
        if !archive.starts_with(GENERATION_BUNDLE_ARCHIVE_MAGIC) { bail!("signed metadata archive magic mismatch"); }
        for member in &artifact.members {
            let width = u16::from_be_bytes(take_archive_bytes(&archive, &mut cursor, 2)?.try_into()?) as usize;
            let path = std::str::from_utf8(take_archive_bytes(&archive, &mut cursor, width)?)?;
            let length = u64::from_be_bytes(take_archive_bytes(&archive, &mut cursor, 8)?.try_into()?);
            let digest = hex::encode(take_archive_bytes(&archive, &mut cursor, 32)?);
            if path != member.relative_path || length != member.bytes || digest != member.sha256 { bail!("signed metadata archive header mismatch"); }
            let bytes = take_archive_bytes(&archive, &mut cursor, usize::try_from(length)?)?;
            if path.ends_with("/manifest.json") {
                if member.total_bytes > MAX_PORTABLE_MANIFEST_BYTES {
                    bail!("signed local manifest exceeds bound: {path} is {} bytes, bound is {MAX_PORTABLE_MANIFEST_BYTES}", member.total_bytes);
                }
                if crate::generation_proof::sha(bytes) != digest { bail!("signed local manifest differs: {path}"); }
                let output = manifests.entry(path.to_string()).or_default();
                if output.len() as u64 != member.offset { bail!("signed manifest chunk order mismatch"); }
                output.extend_from_slice(bytes);
                if output.len() as u64 == member.total_bytes {
                    // Complete: verify and release it rather than holding
                    // every manifest until all archives are read.
                    let complete = manifests.remove(path).unwrap_or_default();
                    verify_rebased_manifest(target, snapshot, path, &complete)?;
                    verified.insert(path.to_string());
                }
            }
        }
        if cursor != archive.len() { bail!("signed metadata archive has trailing bytes"); }
    }
    for (path, bytes) in manifests {
        // Multi-object manifests assembled from inventory objects.
        if verified.contains(&path) { bail!("signed manifest chunk order mismatch"); }
        verify_rebased_manifest(target, snapshot, &path, &bytes)?;
    }
    // Path membership only: hashing here was a whole second pass.
    let actual = if let Some(inventory) = signed.manifest.derivative_inventory.as_ref() {
        for member in inventory { std::fs::metadata(target.join(&member.relative_path))?; }
        inventory.iter().map(|member| member.relative_path.clone()).collect::<BTreeSet<_>>()
    } else { admitted_paths(target)?.into_iter().collect::<BTreeSet<_>>() };
    if actual != expected_paths { bail!("signed admission inventory mismatch"); }
    // Largest first so one big file does not start last and become the tail.
    extents.sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.relative.cmp(&right.relative)));
    let identities = crate::verify::parallel_map(&extents, crate::verify::verify_workers(), |extent| {
        let before = file_identity(&extent.path)?;
        let digest = file_extent_sha256(&extent.path, extent.offset, extent.bytes)?;
        if digest != extent.sha256 { bail!("signed admission file digest mismatch"); }
        // Unchanged across the hash, or the digest is not evidence for later.
        Ok((file_identity(&extent.path)? == before).then_some(before))
    })?;
    Ok(extents.into_iter().zip(identities)
        .filter_map(|(extent, identity)| Some((extent, identity?)))
        .filter(|(extent, _)| extent.offset == 0 && extent.bytes == extent.total)
        .map(|(extent, identity)| (extent.relative, (extent.sha256, extent.total, identity))).collect())
}

/// SHA-256 of exactly `bytes` bytes at `offset`; a short file is an error.
fn file_extent_sha256(path: &Path, offset: u64, bytes: u64) -> Result<String> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut limited = file.take(bytes);
    let mut hash = Sha256::new(); let mut buffer = vec![0; 1024 * 1024]; let mut total = 0;
    loop { let count = limited.read(&mut buffer)?; if count == 0 { break; } hash.update(&buffer[..count]); total += count as u64; }
    if total != bytes { bail!("signed admission file digest mismatch"); }
    Ok(hex::encode(hash.finalize()))
}

/// Hash `relative_paths` under `root` in parallel, reusing `known` digests.
fn hash_admission_files(root: &Path, relative_paths: Vec<String>, known: &KnownDigests) -> Result<Vec<GenerationBundleAdmissionFile>> {
    crate::verify::parallel_map(&relative_paths, crate::verify::verify_workers(), |relative_path| {
        let path = root.join(relative_path);
        let (sha256, bytes) = match known.get(relative_path) {
            // Hashed by this process moments ago and the inode is untouched since.
            Some((sha256, bytes, identity)) if file_identity(&path)? == *identity => (sha256.clone(), *bytes),
            _ => file_sha256_and_bytes(&path)?,
        };
        Ok(GenerationBundleAdmissionFile { relative_path: relative_path.clone(), sha256, bytes })
    })
}

/// The persisted manifest must equal the rebased signed bytes. Compared by
/// digest and length: the rebased form is streamed into a hasher, never
/// materialized as a `serde_json::Value` or a second byte buffer.
fn verify_rebased_manifest(target: &Path, snapshot: &Path, path: &str, signed_bytes: &[u8]) -> Result<()> {
    let expected = rebased_manifest_digest(signed_bytes, target, snapshot)?;
    if file_sha256_and_bytes(&target.join(path))? != expected {
        bail!("transformed local manifest differs from signed authority");
    }
    Ok(())
}

fn signed_local_inventory(target: &Path, signed: &SignedGenerationBundleManifest, known: &KnownDigests) -> Result<Vec<GenerationBundleAdmissionFile>> {
    let paths = signed.manifest.derivative_inventory.as_ref().context("missing signed inventory")?
        .iter().map(|member| member.relative_path.clone()).collect();
    hash_admission_files(target, paths, known)
}

fn rebuild_existing_proof(target: &Path, snapshot: &Path, pointer: &PublishedGenerationBundlePointer, signed: &SignedGenerationBundleManifest, key: &[u8], known: &KnownDigests) -> Result<()> {
    let mut proof = crate::generation_proof::Body::new(proof_identity(pointer, signed), target.parent().context("proof root absent")?.to_path_buf());
    let prefix = target.file_name().and_then(|s| s.to_str()).context("invalid proof directory")?;
    let files = if signed.manifest.derivative_inventory.is_some() { signed_local_inventory(target, signed, known)? }
        else { inventory_admitted_files_known(target, known)? };
    let receipt = admission_receipt(pointer, signed, files.clone());
    let receipt_path = target.join(GENERATION_BUNDLE_ADMISSION_RECEIPT);
    crate::generation_boot::atomic(&receipt_path, &serde_json::to_vec(&receipt)?)?;
    for file in files {
        let path = target.join(&file.relative_path);
        if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
            proof.record_object(&format!("{prefix}/{}", file.relative_path), &path, &file.sha256)?;
        } else { proof.record(&format!("{prefix}/{}", file.relative_path), &path, file.sha256)?; }
    }
    proof.record(&format!("{prefix}/{GENERATION_BUNDLE_ADMISSION_RECEIPT}"), &receipt_path, crate::generation_proof::sha(&std::fs::read(&receipt_path)?))?;
    if let Some(inventory) = &signed.manifest.derivative_inventory {
        proof.derivative_inventory = inventory.clone();
        proof.inventory_trees(prefix)?;
    }
    for directory in ["keyword-sidecar/index", "fragment-sidecar/index", "count-rollup"].into_iter().filter(|_| signed.manifest.derivative_inventory.is_none()) {
        let path = target.join(directory);
        let (sha256, _) = crate::config::index_directory_sha256(&path, directory)?;
        proof.trees.insert(format!("{prefix}/{directory}"), crate::generation_proof::TreeRecord { sha256, members: crate::generation_proof::tree_members(&path)? });
    }
    let stamps_path = snapshot.join("object-stamps.json");
    let bytes = std::fs::read(&stamps_path)?;
    let stamps: ObjectStampManifest = serde_json::from_slice(&bytes)?;
    if object_stamp_manifest_sha256(&GenerationBundleObjectStampManifest::from(&stamps))? != proof.identity.source_stamp_sha256 { bail!("snapshot source proof mismatch"); }
    crate::verify::parallel_map(&stamps.objects, crate::verify::verify_workers(), |object| {
        let path = snapshot.join("data").join(&object.relative_path);
        if file_sha256_and_bytes(&path)? != (object.sha256.clone(), object.size_bytes) { bail!("snapshot source proof digest mismatch"); }
        Ok(())
    })?;
    for object in &stamps.objects {
        let path = snapshot.join("data").join(&object.relative_path);
        proof.record(&format!("snapshot/data/{}", object.relative_path), &path, object.sha256.clone())?;
    }
    proof.record("snapshot/object-stamps.json", &stamps_path, crate::generation_proof::sha(&bytes))?;
    let schema = snapshot.join("clickhouse-read-schema.sql");
    if schema.exists() {
        let digest = crate::generation_proof::sha(&std::fs::read(&schema)?);
        if digest != signed.manifest.read_schema_sha256 { bail!("source read schema differs from signed authority"); }
        proof.record("snapshot/clickhouse-read-schema.sql", &schema, digest)?;
    }
    proof.validate_guards()?;
    proof.save(&target.join(crate::generation_proof::FILE_NAME), key)
}

fn verify_existing_admission_receipt(
    target: &Path,
    pointer: &PublishedGenerationBundlePointer,
    signed: &SignedGenerationBundleManifest,
    budget: &GenerationBundleDiskBudget,
) -> Result<GenerationBundleDiskAccounting> {
    let receipt_path = target.join(GENERATION_BUNDLE_ADMISSION_RECEIPT);
    let metadata = std::fs::symlink_metadata(&receipt_path)
        .context("required generation bundle has no admission receipt")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_GENERATION_BUNDLE_ADMISSION_RECEIPT_BYTES
    {
        bail!("required generation bundle admission receipt is not a bounded regular file");
    }
    let bytes = std::fs::read(&receipt_path)?;
    let receipt: GenerationBundleAdmissionReceipt =
        serde_json::from_slice(&bytes).context("decode generation bundle admission receipt")?;
    if serde_json::to_vec(&receipt)? != bytes {
        bail!("generation bundle admission receipt is not canonical");
    }
    let expected = build_admission_receipt(target, pointer, signed)?;
    if receipt != expected {
        bail!("existing derivative tree differs from its exact signed bundle admission receipt");
    }
    preflight_existing_disk_budget(budget, target)
}

fn build_admission_receipt(
    root: &Path,
    pointer: &PublishedGenerationBundlePointer,
    signed: &SignedGenerationBundleManifest,
) -> Result<GenerationBundleAdmissionReceipt> {
    let local_files = inventory_admitted_files(root)?;
    let expected_paths = signed
        .manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.role != "source-object-stamps")
        .flat_map(|artifact| artifact.members.iter())
        .map(|member| member.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    let actual_paths = local_files
        .iter()
        .map(|file| file.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    if expected_paths != actual_paths {
        bail!("generation bundle admission receipt inventory is not exact");
    }
    Ok(admission_receipt(pointer, signed, local_files))
}

fn admission_receipt(pointer: &PublishedGenerationBundlePointer, signed: &SignedGenerationBundleManifest, local_files: Vec<GenerationBundleAdmissionFile>) -> GenerationBundleAdmissionReceipt {
    GenerationBundleAdmissionReceipt {
        schema_version: GENERATION_BUNDLE_SCHEMA_VERSION,
        bundle_identity_sha256: signed.manifest.bundle_identity_sha256.clone(),
        generation_id: signed.manifest.generation_id.clone(),
        manifest_key: pointer.manifest_key.clone(),
        manifest_sha256: pointer.manifest_sha256.clone(),
        manifest_bytes: pointer.manifest_bytes,
        manifest_etag: pointer.manifest_etag.clone(),
        signer_key_id: signed.signature.key_id.clone(),
        local_files,
    }
}

fn inventory_admitted_files(root: &Path) -> Result<Vec<GenerationBundleAdmissionFile>> {
    inventory_admitted_files_known(root, &KnownDigests::new())
}

fn inventory_admitted_files_known(root: &Path, known: &KnownDigests) -> Result<Vec<GenerationBundleAdmissionFile>> {
    let files = hash_admission_files(root, admitted_paths(root)?, known)?;
    for file in &files {
        if file.bytes == 0 && !generation_bundle_allows_empty_file(&file.relative_path) {
            bail!("generation bundle admission file is unexpectedly empty: {}", file.relative_path);
        }
    }
    Ok(files)
}

/// Every admitted regular file under `root`, sorted, without hashing.
fn admitted_paths(root: &Path) -> Result<Vec<String>> {
    fn walk(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("generation bundle admission tree contains a symbolic link");
            }
            if metadata.is_dir() {
                walk(root, &path, files)?;
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .context("generation bundle admission file escaped its root")?;
                let relative_path = relative
                    .to_str()
                    .context("generation bundle admission file path is not UTF-8")?
                    .to_string();
                if relative_path == GENERATION_BUNDLE_ADMISSION_RECEIPT || relative_path == crate::generation_proof::FILE_NAME {
                    continue;
                }
                if !safe_relative_path(&relative_path) {
                    bail!("generation bundle admission file path is unsafe");
                }
                files.push(relative_path);
            } else {
                bail!("generation bundle admission tree contains a non-regular entry");
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    files.sort();
    if files.is_empty() {
        bail!("generation bundle admission tree is empty");
    }
    Ok(files)
}

fn file_sha256_and_bytes(path: &Path) -> Result<(String, u64)> {
    let file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        bail!("generation bundle admission file is non-regular");
    }
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total
            .checked_add(u64::try_from(read)?)
            .context("generation bundle admission file length overflow")?;
    }
    let after = reader.get_ref().metadata()?;
    if total != before.len() || after.len() != before.len() {
        bail!("generation bundle admission file changed while it was verified");
    }
    Ok((hex::encode(digest.finalize()), total))
}

fn preflight_disk_budget_reusing(
    budget: &GenerationBundleDiskBudget, target: &Path, manifest: &GenerationBundleManifest,
    source_allocation: u64, reused: &BTreeSet<String>,
) -> Result<GenerationBundleDiskAccounting> {
    if !budget.generations_root.is_absolute()
        || !budget.generations_root.is_dir()
        || budget.max_local_bytes == 0
        || budget.reserve_bytes >= budget.max_local_bytes
        || !target.starts_with(&budget.generations_root)
    {
        bail!("generation bundle disk budget is malformed or outside its generation root");
    }
    let current_allocated_bytes = allocated_tree_bytes(&budget.generations_root)?;
    let mut staging_allocated_bytes = source_allocation;
    let mut final_derivative_allocated_bytes = 0_u64;
    let mut final_object_store_allocated_bytes = 0_u64;
    // NAN-2532 accounting, member by member. An inventory generation stores a
    // derivative ONCE in `objects/` and links it from the generation tree, so
    // the two costs are reported separately: `final_derivative_allocated_bytes`
    // is what the generation directory itself holds (which is what
    // `preflight_existing_disk_budget` measures with `allocated_tree_bytes`, so
    // the two paths finally agree), and `final_object_store_allocated_bytes` is
    // the content-store growth this generation retains. A `manifest.json`
    // member is genuinely stored TWICE -- the portable bytes as an object, the
    // rebased bytes in the tree -- and is charged twice here.
    let inventory_mode = manifest.derivative_inventory.is_some();
    for artifact in &manifest.artifacts {
        let source_inventory = artifact.role == "source-object-stamps";
        for member in &artifact.members {
            let allocated = conservative_allocated_bytes(member.bytes)?;
            let whole = conservative_allocated_bytes(member.total_bytes)?;
            let transformed = member.relative_path.ends_with("/manifest.json");
            let reused_member = reused.contains(&member.relative_path);
            let content_addressed = inventory_mode && !source_inventory;
            // First extent of a logical file: the local entry and the object
            // receipt are created once, not once per extent.
            let first = member.offset == 0;
            let mut staging = if reused_member { 0 } else { allocated };
            if content_addressed && first {
                if !reused_member {
                    staging = staging
                        .checked_add(OBJECT_RECEIPT_ALLOCATION_BYTES)
                        .context("object receipt staging allocation overflow")?;
                }
                staging = staging
                    .checked_add(if transformed { whole } else { DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES })
                    .context("object entry staging allocation overflow")?;
            }
            staging_allocated_bytes = staging_allocated_bytes
                .checked_add(staging)
                .context("generation bundle staging allocation overflow")?;
            if source_inventory {
                continue;
            }
            let tree = if content_addressed {
                if first { if transformed { whole } else { DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES } } else { 0 }
            } else {
                allocated
            };
            final_derivative_allocated_bytes = final_derivative_allocated_bytes
                .checked_add(tree)
                .context("generation bundle final allocation overflow")?;
            if content_addressed && !reused_member {
                let object = if first {
                    allocated
                        .checked_add(OBJECT_RECEIPT_ALLOCATION_BYTES)
                        .context("object receipt final allocation overflow")?
                } else {
                    allocated
                };
                final_object_store_allocated_bytes = final_object_store_allocated_bytes
                    .checked_add(object)
                    .context("content store final allocation overflow")?;
            }
        }
    }
    let receipt_allocation =
        conservative_allocated_bytes(MAX_GENERATION_BUNDLE_ADMISSION_RECEIPT_BYTES)?;
    staging_allocated_bytes = staging_allocated_bytes
        .checked_add(receipt_allocation)
        .context("generation bundle receipt staging allocation overflow")?;
    final_derivative_allocated_bytes = final_derivative_allocated_bytes
        .checked_add(receipt_allocation)
        .context("generation bundle receipt final allocation overflow")?;
    let peak_allocated_bytes = current_allocated_bytes
        .checked_add(staging_allocated_bytes)
        .and_then(|bytes| bytes.checked_add(budget.reserve_bytes))
        .context("generation bundle peak allocation overflow")?;
    let available_bytes_before = fs2::available_space(&budget.generations_root)
        .context("read generation bundle filesystem capacity")?;
    let required_available = staging_allocated_bytes
        .checked_add(budget.reserve_bytes)
        .context("generation bundle available-space requirement overflow")?;
    if peak_allocated_bytes > budget.max_local_bytes || required_available > available_bytes_before
    {
        return Err(GenerationBundleCapacityError {
            content_addressed: inventory_mode,
            reused_bytes: manifest.artifacts.iter().flat_map(|a| &a.members).filter(|m| reused.contains(&m.relative_path)).map(|m| m.bytes).sum(),
            new_bytes: manifest.artifacts.iter().flat_map(|a| &a.members).filter(|m| !reused.contains(&m.relative_path)).map(|m| m.bytes).sum(),
            shortfall_bytes: peak_allocated_bytes
                .saturating_sub(budget.max_local_bytes)
                .max(required_available.saturating_sub(available_bytes_before)),
            current_allocated_bytes,
            staging_allocated_bytes,
            peak_allocated_bytes,
            max_local_bytes: budget.max_local_bytes,
            available_bytes_before,
            reserve_bytes: budget.reserve_bytes,
        }
        .into());
    }
    Ok(GenerationBundleDiskAccounting {
        reused_bytes: manifest.artifacts.iter().flat_map(|a| &a.members).filter(|m| reused.contains(&m.relative_path)).map(|m| m.bytes).sum(),
        new_bytes: manifest.artifacts.iter().flat_map(|a| &a.members).filter(|m| !reused.contains(&m.relative_path)).map(|m| m.bytes).sum(),
        current_allocated_bytes,
        staging_allocated_bytes,
        final_derivative_allocated_bytes,
        final_object_store_allocated_bytes,
        peak_allocated_bytes,
        available_bytes_before,
        max_local_bytes: budget.max_local_bytes,
        reserve_bytes: budget.reserve_bytes,
    })
}

fn preflight_existing_disk_budget(
    budget: &GenerationBundleDiskBudget,
    target: &Path,
) -> Result<GenerationBundleDiskAccounting> {
    if !budget.generations_root.is_absolute()
        || !budget.generations_root.is_dir()
        || budget.max_local_bytes == 0
        || budget.reserve_bytes >= budget.max_local_bytes
        || !target.starts_with(&budget.generations_root)
    {
        bail!("generation bundle disk budget is malformed or outside its generation root");
    }
    let current_allocated_bytes = allocated_tree_bytes(&budget.generations_root)?;
    let final_derivative_allocated_bytes = allocated_tree_bytes(target)?;
    let available_bytes_before = fs2::available_space(&budget.generations_root)
        .context("read existing generation bundle filesystem capacity")?;
    let peak_allocated_bytes = current_allocated_bytes
        .checked_add(budget.reserve_bytes)
        .context("existing generation reserve overflow")?;
    if peak_allocated_bytes > budget.max_local_bytes
        || available_bytes_before < budget.reserve_bytes
    {
        return Err(GenerationBundleCapacityError {
            content_addressed: true,
            reused_bytes: 0,
            new_bytes: 0,
            shortfall_bytes: peak_allocated_bytes
                .saturating_sub(budget.max_local_bytes)
                .max(budget.reserve_bytes.saturating_sub(available_bytes_before)),
            current_allocated_bytes,
            staging_allocated_bytes: 0,
            peak_allocated_bytes,
            max_local_bytes: budget.max_local_bytes,
            available_bytes_before,
            reserve_bytes: budget.reserve_bytes,
        }
        .into());
    }
    Ok(GenerationBundleDiskAccounting {
        reused_bytes: 0,
        new_bytes: 0,
        current_allocated_bytes,
        staging_allocated_bytes: 0,
        final_derivative_allocated_bytes,
        final_object_store_allocated_bytes: 0,
        peak_allocated_bytes,
        available_bytes_before,
        max_local_bytes: budget.max_local_bytes,
        reserve_bytes: budget.reserve_bytes,
    })
}

fn conservative_allocated_bytes(bytes: u64) -> Result<u64> {
    bytes
        .checked_add(DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES - 1)
        .map(|value| value / DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES)
        .and_then(|blocks| blocks.checked_mul(DISK_ACCOUNTING_ALLOCATION_UNIT_BYTES))
        .context("generation bundle conservative allocation overflow")
}

#[cfg(unix)]
pub(crate) fn allocated_tree_bytes(root: &Path) -> Result<u64> {
    fn walk(root: &Path, seen: &mut HashSet<(u64, u64)>, total: &mut u64) -> Result<()> {
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                *total = total.checked_add(metadata.blocks().saturating_mul(512)).context("link allocation overflow")?;
                continue;
            }
            if metadata.is_dir() {
                walk(&entry.path(), seen, total)?;
            } else if metadata.is_file() && seen.insert((metadata.dev(), metadata.ino())) {
                *total = total
                    .checked_add(metadata.blocks().saturating_mul(512))
                    .context("generation root allocated-byte total overflow")?;
            } else if !metadata.is_file() {
                bail!("generation root contains a non-regular entry");
            }
        }
        Ok(())
    }
    let mut seen = HashSet::new();
    let mut total = 0_u64;
    walk(root, &mut seen, &mut total)?;
    Ok(total)
}

#[cfg(not(unix))]
pub(crate) fn allocated_tree_bytes(_root: &Path) -> Result<u64> {
    bail!("generation bundle disk accounting requires Unix allocation metadata")
}

#[derive(Default)]
struct AdmissionDigests {
    hashed_bytes: u64,
    trees_enabled: bool,
    inventory: BTreeMap<String, DerivativeMember>,
    partial: BTreeMap<String, (Sha256, u64)>,
    files: BTreeMap<String, (String, u64)>,
    trees: BTreeMap<String, AdmissionTree>,
}
#[derive(Default)]
struct AdmissionTree { hash: Sha256, members: Vec<String>, invalid: bool }
impl AdmissionDigests {
    fn receive(&mut self, member: &GenerationBundleArtifactMember, bytes: &[u8], candidate: &Path, target: &Path, snapshot: &Path) -> Result<()> {
        self.receive_part(member, 0, bytes, candidate, target, snapshot)
    }
    fn receive_part(&mut self, member: &GenerationBundleArtifactMember, part_offset: u64, bytes: &[u8], candidate: &Path, target: &Path, snapshot: &Path) -> Result<()> {
        let path = &member.relative_path;
        if let Some(expected) = self.inventory.get(path) {
            let state = self.partial.entry(path.clone()).or_default();
            if state.1 != member.offset + part_offset { bail!("inventory extent order mismatch"); }
            state.1 += bytes.len() as u64;
            if state.1 == expected.bytes {
                self.files.insert(path.clone(), (expected.sha256.clone(), expected.bytes));
                self.partial.remove(path);
            }
            return Ok(());
        }
        let transformed = path.ends_with("/manifest.json");
        let state = self.partial.entry(path.clone()).or_default();
        if state.1 != member.offset + part_offset { bail!("proof chunk order mismatch"); }
        let whole_file_member = member.offset == 0 && member.bytes == member.total_bytes;
        // extract_archive_recording already verified this member digest. Only
        // multi-member files need a separate whole-file running digest.
        if !whole_file_member && !transformed { state.0.update(bytes); self.hashed_bytes += bytes.len() as u64; }
        state.1 += bytes.len() as u64;
        let complete = state.1 == member.total_bytes;
        let mut replacement = None;
        if complete && transformed {
            // Name the file and both numbers. This bound is a memory guard on
            // rebasing a manifest through serde_json::Value, and it was reached
            // only once NAN-2559 cleared the capacity fence that used to fail
            // first. "a manifest is too big" without saying which one or by how
            // much cannot be acted on -- it cost a live investigation.
            if member.total_bytes > MAX_PORTABLE_MANIFEST_BYTES {
                bail!("portable manifest exceeds bound: {} is {} bytes, bound is {MAX_PORTABLE_MANIFEST_BYTES}",
                    path, member.total_bytes);
            }
            // Streamed in place: neither the manifest nor its rebased form is
            // held in memory (rebase_manifest_stream).
            let local = candidate.join(path);
            replacement = Some(rebase_manifest_file(&local, &local, target, snapshot)?);
        }
        if complete {
            let (hash, size) = self.partial.remove(path).unwrap();
            let (digest, size) = match &replacement {
                Some((digest, bytes)) => { self.hashed_bytes += bytes; (digest.clone(), *bytes) },
                None if whole_file_member => (member.sha256.clone(), size),
                None => (hex::encode(hash.finalize()), size),
            };
            self.files.insert(path.clone(), (digest, size));
        }
        let p = Path::new(path);
        let directory = p.parent().and_then(Path::to_str).unwrap_or("");
        if self.trees_enabled && matches!(directory, "keyword-sidecar/index" | "fragment-sidecar/index" | "count-rollup") {
            let name = p.file_name().unwrap().to_str().context("invalid proof tree filename")?;
            if !name.ends_with(".lock") {
                let tree = self.trees.entry(directory.to_string()).or_default();
                // Portable manifests are bounded metadata. Feed transformed bytes
                // in their lexical position; index payloads stream without rereads.
                if !transformed || complete {
                    if (member.offset == 0 && part_offset == 0) || transformed {
                        if tree.members.last().is_some_and(|prior| prior.as_str() >= name) { tree.invalid = true; }
                        tree.members.push(name.to_owned());
                        tree.hash.update((name.len() as u64).to_be_bytes()); tree.hash.update(name.as_bytes());
                        tree.hash.update(replacement.as_ref().map(|(_, b)| *b).unwrap_or(member.total_bytes).to_be_bytes());
                    }
                    if replacement.is_some() {
                        // The rebased manifest lives only on disk: feed it back in chunks.
                        let mut file = File::open(candidate.join(path))?;
                        let mut buffer = vec![0; 256 * 1024];
                        loop {
                            let count = file.read(&mut buffer)?;
                            if count == 0 { break; }
                            tree.hash.update(&buffer[..count]);
                            self.hashed_bytes += count as u64;
                        }
                    } else {
                        tree.hash.update(bytes);
                        self.hashed_bytes += bytes.len() as u64;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Incremental decoder for the exact signed framing. Only one header and one
/// open member are retained; payload size never determines buffer allocation.
struct StreamingArchive<'a> {
    candidate: &'a Path,
    artifact: &'a GenerationBundleArtifact,
    member: usize,
    header: Vec<u8>,
    header_offset: usize,
    payload_offset: u64,
    file: Option<File>,
    hash: Sha256,
    received: u64,
}
impl<'a> StreamingArchive<'a> {
    fn new(candidate: &'a Path, artifact: &'a GenerationBundleArtifact) -> Result<Self> {
        if artifact.members.is_empty() { bail!("archive has no signed members"); }
        let mut header = GENERATION_BUNDLE_ARCHIVE_MAGIC.to_vec();
        header.extend_from_slice(&u32::try_from(artifact.members.len())?.to_be_bytes());
        header.extend(Self::member_header(&artifact.members[0])?);
        Ok(Self { candidate, artifact, member: 0, header, header_offset: 0,
            payload_offset: 0, file: None, hash: Sha256::new(), received: 0 })
    }
    fn member_header(member: &GenerationBundleArtifactMember) -> Result<Vec<u8>> {
        if !safe_relative_path(&member.relative_path) { bail!("unsafe archive member path"); }
        if member.offset.checked_add(member.bytes).is_none_or(|end| end > member.total_bytes) {
            bail!("invalid archive member extent");
        }
        let mut header = u16::try_from(member.relative_path.len())?.to_be_bytes().to_vec();
        header.extend_from_slice(member.relative_path.as_bytes());
        header.extend_from_slice(&member.bytes.to_be_bytes());
        header.extend_from_slice(&decode_sha256(&member.sha256)?);
        Ok(header)
    }
    fn receive(&mut self, mut bytes: &[u8], admission: &mut AdmissionDigests, target: &Path, snapshot: &Path) -> Result<()> {
        self.received = self.received.checked_add(bytes.len() as u64).context("archive byte count overflow")?;
        if self.received > self.artifact.bytes { bail!("archive exceeds signed length"); }
        while !bytes.is_empty() {
            if self.member == self.artifact.members.len() { bail!("generation bundle archive has trailing bytes"); }
            let member = &self.artifact.members[self.member];
            if self.header_offset < self.header.len() {
                let count = bytes.len().min(self.header.len() - self.header_offset);
                if bytes[..count] != self.header[self.header_offset..self.header_offset + count] {
                    bail!("generation bundle archive header differs from its signed inventory");
                }
                self.header_offset += count;
                bytes = &bytes[count..];
                if self.header_offset != self.header.len() { continue; }
                let path = self.candidate.join(&member.relative_path);
                std::fs::create_dir_all(path.parent().context("archive member has no parent")?)?;
                let mut options = OpenOptions::new();
                options.write(true);
                if member.offset == 0 { options.create_new(true); } else { options.append(true); }
                let file = options.open(&path)?;
                if file.metadata()?.len() != member.offset { bail!("archive member offset differs from candidate"); }
                self.file = Some(file);
            }
            if bytes.is_empty() && self.payload_offset < member.bytes { break; }
            let count = bytes.len().min(usize::try_from(member.bytes - self.payload_offset)?);
            let part = &bytes[..count];
            self.file.as_mut().context("archive member has no file")?.write_all(part)?;
            if !admission.inventory.contains_key(&member.relative_path) {
                self.hash.update(part);
                admission.hashed_bytes += part.len() as u64;
            }
            admission.receive_part(member, self.payload_offset, part, self.candidate, target, snapshot)?;
            self.payload_offset += count as u64;
            bytes = &bytes[count..];
            if self.payload_offset == member.bytes {
                let digest = hex::encode(std::mem::take(&mut self.hash).finalize());
                // read_to authenticates the entire signed archive before this
                // candidate can be admitted. Inventory mode needs one SHA pass.
                if !admission.inventory.contains_key(&member.relative_path) && digest != member.sha256 { bail!("generation bundle archive member digest differs"); }
                self.file.take().context("archive member has no file")?.sync_all()?;
                self.member += 1;
                self.payload_offset = 0;
                self.header_offset = 0;
                self.header = match self.artifact.members.get(self.member) {
                    Some(member) => Self::member_header(member)?,
                    None => Vec::new(),
                };
            }
        }
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.received != self.artifact.bytes || self.member != self.artifact.members.len() || self.file.is_some() {
            bail!("generation bundle archive is truncated");
        }
        Ok(())
    }
}

fn extract_archive(
    candidate: &Path,
    artifact: &GenerationBundleArtifact,
    archive: &[u8],
) -> Result<()> {
    extract_archive_recording(candidate, artifact, archive, None)
}

fn extract_archive_recording(
    candidate: &Path,
    artifact: &GenerationBundleArtifact,
    archive: &[u8],
    mut admission: Option<(&mut AdmissionDigests, &Path, &Path)>,
) -> Result<()> {
    let mut cursor = 0_usize;
    if take_archive_bytes(archive, &mut cursor, GENERATION_BUNDLE_ARCHIVE_MAGIC.len())?
        != GENERATION_BUNDLE_ARCHIVE_MAGIC
    {
        bail!("generation bundle archive magic differs");
    }
    let count = u32::from_be_bytes(
        take_archive_bytes(archive, &mut cursor, 4)?
            .try_into()
            .expect("archive count has fixed width"),
    );
    if usize::try_from(count)? != artifact.members.len() {
        bail!("generation bundle archive member count differs");
    }
    for expected in &artifact.members {
        let path_bytes = u16::from_be_bytes(
            take_archive_bytes(archive, &mut cursor, 2)?
                .try_into()
                .expect("archive path length has fixed width"),
        ) as usize;
        let path = std::str::from_utf8(take_archive_bytes(archive, &mut cursor, path_bytes)?)
            .context("generation bundle archive path is not UTF-8")?;
        let member_bytes = u64::from_be_bytes(
            take_archive_bytes(archive, &mut cursor, 8)?
                .try_into()
                .expect("archive member length has fixed width"),
        );
        let member_sha256 = hex::encode(take_archive_bytes(archive, &mut cursor, 32)?);
        if path != expected.relative_path
            || member_bytes != expected.bytes
            || member_sha256 != expected.sha256
        {
            bail!("generation bundle archive header differs from its signed inventory");
        }
        let member = take_archive_bytes(archive, &mut cursor, usize::try_from(member_bytes)?)?;
        if hex::encode(Sha256::digest(member)) != expected.sha256 {
            bail!("generation bundle archive member digest differs");
        }
        write_candidate_file_chunk(
            &candidate.join(&expected.relative_path),
            expected.offset,
            expected.total_bytes,
            member,
        )?;
        if let Some((digests, target, snapshot)) = admission.as_mut() {
            digests.hashed_bytes += member.len() as u64;
            digests.receive(expected, member, candidate, target, snapshot)?;
        }
    }
    if cursor != archive.len() {
        bail!("generation bundle archive has trailing bytes");
    }
    Ok(())
}

pub(crate) fn single_archive_member<'a>(
    artifact: &GenerationBundleArtifact,
    archive: &'a [u8],
) -> Result<&'a [u8]> {
    let [expected] = artifact.members.as_slice() else {
        bail!("generation bundle source archive is not a single-member shard");
    };
    let mut cursor = 0_usize;
    if take_archive_bytes(archive, &mut cursor, GENERATION_BUNDLE_ARCHIVE_MAGIC.len())?
        != GENERATION_BUNDLE_ARCHIVE_MAGIC
    {
        bail!("generation bundle source archive magic differs");
    }
    let count = u32::from_be_bytes(
        take_archive_bytes(archive, &mut cursor, 4)?
            .try_into()
            .expect("archive count has fixed width"),
    );
    if count != 1 {
        bail!("generation bundle source archive member count differs");
    }
    let path_bytes = u16::from_be_bytes(
        take_archive_bytes(archive, &mut cursor, 2)?
            .try_into()
            .expect("archive path length has fixed width"),
    ) as usize;
    let path = std::str::from_utf8(take_archive_bytes(archive, &mut cursor, path_bytes)?)?;
    let member_bytes = u64::from_be_bytes(
        take_archive_bytes(archive, &mut cursor, 8)?
            .try_into()
            .expect("archive member length has fixed width"),
    );
    let member_sha256 = hex::encode(take_archive_bytes(archive, &mut cursor, 32)?);
    if path != expected.relative_path
        || member_bytes != expected.bytes
        || member_sha256 != expected.sha256
    {
        bail!("generation bundle source archive header differs from its signed inventory");
    }
    let member = take_archive_bytes(archive, &mut cursor, usize::try_from(member_bytes)?)?;
    if cursor != archive.len() || hex::encode(Sha256::digest(member)) != expected.sha256 {
        bail!("generation bundle source archive payload differs");
    }
    Ok(member)
}

fn validate_source_object_stamps(
    stamps: &ObjectStampManifest,
    manifest: &GenerationBundleManifest,
) -> Result<()> {
    if stamps.metadata_location != manifest.iceberg_metadata_location
        || stamps.snapshot_id != manifest.snapshot_id
        || stamps.table.is_empty()
        || stamps.table.len() > 512
        || stamps.objects.len() != manifest.source_object_count
    {
        bail!("generation bundle object-stamp authority is invalid");
    }
    let mut relative_paths = BTreeSet::new();
    let mut source_identities = BTreeSet::new();
    for object in &stamps.objects {
        if !safe_relative_path(&object.relative_path)
            || !object.source_uri.starts_with(&format!(
                "{}/data/",
                manifest.table_location.trim_end_matches('/')
            ))
            || object.version_id.is_empty()
            || object.version_id.len() > 1_024
            || object.version_id.chars().any(char::is_control)
            || object.size_bytes == 0
            || !lower_sha256(&object.sha256)
            || !relative_paths.insert(object.relative_path.as_str())
            || !source_identities.insert((object.source_uri.as_str(), object.version_id.as_str()))
        {
            bail!("generation bundle source object identity is invalid");
        }
    }
    Ok(())
}

fn take_archive_bytes<'a>(archive: &'a [u8], cursor: &mut usize, bytes: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(bytes)
        .context("generation bundle archive offset overflow")?;
    let value = archive
        .get(*cursor..end)
        .context("generation bundle archive is truncated")?;
    *cursor = end;
    Ok(value)
}

/// Outcome of a streaming manifest rebase.
#[derive(Debug)]
enum StreamedRebase {
    /// The rebased manifest was written; its digest and length.
    Written { sha256: String, bytes: u64 },
    /// An object's keys were not strictly increasing. `serde_json::Value`
    /// (without `preserve_order`) would re-sort or de-duplicate them, so the
    /// in-order stream is not byte-identical: the caller must use the
    /// bounded `Value` path instead. Output written so far is garbage.
    NeedsCanonicalOrder,
    /// The rewrite rule refused a value. Only a `Value` rebase is
    /// authoritative here: with a duplicate key later in the same object the
    /// refused value would have been overwritten. Callers re-run the `Value`
    /// path when it fits the in-memory bound and report this error otherwise.
    Refused(anyhow::Error),
}

/// Streaming equivalent of `rebase_manifest_value` + `serde_json::to_vec` +
/// trailing newline: a deserializer-to-writer transcoder that rewrites only
/// the targeted string values. Memory is O(nesting depth x largest key) plus
/// the largest single string token and the reader/writer buffers --
/// independent of how many objects the manifest lists.
///
/// Byte identity with the `Value` path rests on three facts: (1) every scalar
/// reaches the visitor through the same serde_json call the `Value` builder
/// receives (`visit_u64`/`visit_i64`/`visit_f64`/`visit_str`) and is written
/// back through the same serde_json serializer; (2) `Value` maps are
/// key-sorted, so in-order output is identical exactly when every object's
/// keys are strictly increasing, which is checked (and otherwise reported as
/// `NeedsCanonicalOrder`); (3) the rewrite rule is applied to a string value
/// with its enclosing object key, exactly as `rebase_manifest_value` does.
fn rebase_manifest_stream<R: Read, W: Write>(
    input: R,
    output: W,
    final_target: &Path,
    snapshot_root: &Path,
) -> Result<StreamedRebase> {
    let context = RebaseStream {
        output: std::cell::RefCell::new(DigestWriter { inner: output, hash: Sha256::new(), bytes: 0 }),
        final_target,
        snapshot_root,
        failure: std::cell::RefCell::new(None),
        refusal: std::cell::RefCell::new(None),
        unordered: std::cell::Cell::new(false),
    };
    let mut deserializer = serde_json::Deserializer::from_reader(input);
    let result = serde::de::DeserializeSeed::deserialize(
        RebaseSeed { context: &context, key: None, comma: false },
        &mut deserializer,
    )
    .and_then(|()| deserializer.end());
    if context.unordered.get() {
        return Ok(StreamedRebase::NeedsCanonicalOrder);
    }
    if let Some(refusal) = context.refusal.into_inner() {
        return Ok(StreamedRebase::Refused(refusal));
    }
    if let Some(failure) = context.failure.into_inner() {
        return Err(failure);
    }
    result?;
    let mut writer = context.output.into_inner();
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(StreamedRebase::Written { sha256: hex::encode(writer.hash.finalize()), bytes: writer.bytes })
}

struct DigestWriter<W> {
    inner: W,
    hash: Sha256,
    bytes: u64,
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buf)?;
        self.hash.update(&buf[..count]);
        self.bytes += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

struct RebaseStream<'p, W> {
    output: std::cell::RefCell<DigestWriter<W>>,
    final_target: &'p Path,
    snapshot_root: &'p Path,
    /// Rebase/IO errors keep their anyhow context; serde only sees a marker.
    failure: std::cell::RefCell<Option<anyhow::Error>>,
    /// A rewrite-rule refusal (as opposed to an I/O failure).
    refusal: std::cell::RefCell<Option<anyhow::Error>>,
    unordered: std::cell::Cell<bool>,
}

impl<W: Write> RebaseStream<'_, W> {
    fn fail<E: serde::de::Error>(&self, error: anyhow::Error) -> E {
        let message = format!("{error:#}");
        self.failure.borrow_mut().get_or_insert(error);
        E::custom(message)
    }
    fn emit<E: serde::de::Error>(&self, bytes: &[u8]) -> Result<(), E> {
        self.output.borrow_mut().write_all(bytes).map_err(|e| self.fail(e.into()))
    }
    fn emit_json<E: serde::de::Error, T: Serialize + ?Sized>(&self, value: &T) -> Result<(), E> {
        serde_json::to_writer(&mut *self.output.borrow_mut(), value)
            .map_err(|e| self.fail(e.into()))
    }
    /// The string rule of `rebase_manifest_value`, for a string value whose
    /// enclosing object key is `key` (`None` inside arrays or at top level).
    fn string<E: serde::de::Error>(&self, key: Option<&str>, value: &str) -> Result<(), E> {
        let Some(name) = key else { return self.emit_json(value) };
        match rebased_manifest_string(name, value, self.final_target, self.snapshot_root) {
            Ok(Some(replacement)) => self.emit_json(replacement.as_str()),
            Ok(None) => self.emit_json(value),
            Err(error) => {
                let message = format!("{error:#}");
                self.refusal.borrow_mut().get_or_insert(error);
                Err(E::custom(message))
            }
        }
    }
}

struct RebaseSeed<'c, 'p, 'k, W> {
    context: &'c RebaseStream<'p, W>,
    key: Option<&'k str>,
    comma: bool,
}

impl<'de, W: Write> serde::de::DeserializeSeed<'de> for RebaseSeed<'_, '_, '_, W> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if self.comma {
            self.context.emit::<D::Error>(b",")?;
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de, W: Write> serde::de::Visitor<'de> for RebaseSeed<'_, '_, '_, W> {
    type Value = ();
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a portable derivative manifest JSON value")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<(), E> { self.context.emit_json(&value) }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<(), E> { self.context.emit_json(&value) }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<(), E> { self.context.emit_json(&value) }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<(), E> {
        // Identical to Value: Number::from_f64 keeps every finite f64, and
        // serde_json never yields a non-finite one.
        self.context.emit_json(&value)
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> { self.context.emit(b"null") }
    fn visit_none<E: serde::de::Error>(self) -> Result<(), E> { self.context.emit(b"null") }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<(), E> { self.context.string(self.key, value) }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        self.context.emit::<A::Error>(b"[")?;
        let mut comma = false;
        while sequence.next_element_seed(RebaseSeed { context: self.context, key: None, comma })?.is_some() {
            comma = true;
        }
        self.context.emit(b"]")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.context.emit::<A::Error>(b"{")?;
        let mut prior: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            if prior.as_deref().is_some_and(|prior| prior >= key.as_str()) {
                self.context.unordered.set(true);
                return Err(serde::de::Error::custom("manifest object keys are not in canonical order"));
            }
            if prior.is_some() {
                self.context.emit::<A::Error>(b",")?;
            }
            self.context.emit_json::<A::Error, _>(key.as_str())?;
            self.context.emit::<A::Error>(b":")?;
            map.next_value_seed(RebaseSeed { context: self.context, key: Some(&key), comma: false })?;
            prior = Some(key);
        }
        self.context.emit(b"}")
    }
}

/// Rebase the portable manifest at `source` into `destination` (which may be
/// the same path) and return the rebased bytes' digest and length. Streams
/// when the manifest's object keys are in canonical (sorted) order -- every
/// manifest the derivative builder emits through `serde_json::Value` is -- and
/// otherwise falls back to the `Value` rebase under
/// `MAX_PORTABLE_MANIFEST_IN_MEMORY_BYTES`; a value the rewrite rule refuses
/// is also re-decided by the `Value` path when it fits (see
/// `StreamedRebase::Refused`). The output is written to a sibling
/// temporary file, synced, and renamed over `destination`.
fn rebase_manifest_file(
    source: &Path,
    destination: &Path,
    final_target: &Path,
    snapshot_root: &Path,
) -> Result<(String, u64)> {
    let parent = destination.parent().context("rebased manifest has no parent")?;
    let name = destination.file_name().and_then(|n| n.to_str()).context("rebased manifest name is not UTF-8")?;
    let temporary = parent.join(format!(".{name}.rebase-{}", Uuid::new_v4()));
    let result = (|| {
        let mut output = std::io::BufWriter::with_capacity(
            256 * 1024,
            OpenOptions::new().write(true).create_new(true).open(&temporary)?,
        );
        let input = BufReader::with_capacity(256 * 1024, File::open(source)?);
        let written = match rebase_manifest_stream(input, &mut output, final_target, snapshot_root)? {
            StreamedRebase::Written { sha256, bytes } => (sha256, bytes),
            fallback => {
                let size = std::fs::metadata(source)?.len();
                if size > MAX_PORTABLE_MANIFEST_IN_MEMORY_BYTES {
                    if let StreamedRebase::Refused(error) = fallback { return Err(error); }
                    bail!("portable manifest is not in canonical key order and exceeds the in-memory rebase bound: {} is {size} bytes, bound is {MAX_PORTABLE_MANIFEST_IN_MEMORY_BYTES}", source.display());
                }
                let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(source)?)?;
                rebase_manifest_value(&mut value, final_target, snapshot_root)?;
                let mut bytes = serde_json::to_vec(&value)?; bytes.push(b'\n');
                drop(value);
                let mut output = output.into_inner().map_err(|e| e.into_error())?;
                output.set_len(0)?;
                use std::io::Seek;
                output.seek(std::io::SeekFrom::Start(0))?;
                output.write_all(&bytes)?;
                output.sync_all()?;
                return Ok((crate::generation_proof::sha(&bytes), bytes.len() as u64));
            }
        };
        output.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        Ok(written)
    })();
    match result {
        Ok(written) => {
            std::fs::rename(&temporary, destination)?;
            Ok(written)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

/// Digest and length of the rebased form of in-memory manifest bytes, without
/// materializing either a `serde_json::Value` or the rebased bytes.
fn rebased_manifest_digest(bytes: &[u8], final_target: &Path, snapshot_root: &Path) -> Result<(String, u64)> {
    match rebase_manifest_stream(bytes, std::io::sink(), final_target, snapshot_root)? {
        StreamedRebase::Written { sha256, bytes } => Ok((sha256, bytes)),
        fallback => {
            if bytes.len() as u64 > MAX_PORTABLE_MANIFEST_IN_MEMORY_BYTES {
                if let StreamedRebase::Refused(error) = fallback { return Err(error); }
                bail!("portable manifest is not in canonical key order and exceeds the in-memory rebase bound: {} bytes, bound is {MAX_PORTABLE_MANIFEST_IN_MEMORY_BYTES}", bytes.len());
            }
            let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
            rebase_manifest_value(&mut value, final_target, snapshot_root)?;
            let mut rebased = serde_json::to_vec(&value)?; rebased.push(b'\n');
            Ok((crate::generation_proof::sha(&rebased), rebased.len() as u64))
        }
    }
}

/// The string rule shared by the `Value` and streaming rebases: the
/// replacement for string `value` held under object key `name`, `None` to
/// keep it, or an error for an unknown absolute path.
fn rebased_manifest_string(
    name: &str,
    path: &str,
    final_target: &Path,
    snapshot_root: &Path,
) -> Result<Option<String>> {
    let replacement = match name {
        "input_root" => snapshot_root.to_path_buf(),
        "object_stamp_manifest" => snapshot_root.join("object-stamps.json"),
        "path"
        | "data_directory"
        | "index_directory"
        | "fragment_index_directory"
        | "database_path"
        | "scan_file"
        | "part_file" => rebase_derivative_path(path, final_target)?,
        _ if Path::new(path).is_absolute() => {
            bail!("portable derivative manifest contains an unknown absolute path")
        }
        _ => return Ok(None),
    };
    let replacement = if name == "database_path" {
        replacement
            .strip_prefix("/")
            .context("rebased prevalence database path is not absolute")?
            .to_path_buf()
    } else {
        replacement
    };
    Ok(Some(
        replacement
            .to_str()
            .context("rebased derivative path is not UTF-8")?
            .to_string(),
    ))
}

fn rebase_manifest_value(
    value: &mut serde_json::Value,
    final_target: &Path,
    snapshot_root: &Path,
) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            for (name, value) in object {
                if let Some(path) = value.as_str() {
                    if let Some(replacement) =
                        rebased_manifest_string(name, path, final_target, snapshot_root)?
                    {
                        *value = serde_json::Value::String(replacement);
                        continue;
                    }
                }
                rebase_manifest_value(value, final_target, snapshot_root)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                rebase_manifest_value(value, final_target, snapshot_root)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn rebase_derivative_path(value: &str, final_target: &Path) -> Result<std::path::PathBuf> {
    const ROOTS: &[&str] = &[
        "entity-sidecar",
        "keyword-sidecar",
        "fragment-sidecar",
        "identity-snapshot",
        "count-rollup",
        "prevalence-snapshot-v2",
        "uid-ledger",
    ];
    let components = value.trim_start_matches('/').split('/').collect::<Vec<_>>();
    let root = components
        .iter()
        .position(|component| ROOTS.contains(component))
        .context("portable derivative path has no contracted derivative root")?;
    let relative = components[root..].iter().collect::<std::path::PathBuf>();
    if !safe_relative_path(
        relative
            .to_str()
            .context("portable derivative path is not UTF-8")?,
    ) {
        bail!("portable derivative path is invalid");
    }
    Ok(final_target.join(relative))
}

fn validate_artifact(
    manifest: &GenerationBundleManifest,
    artifact: &GenerationBundleArtifact,
) -> Result<()> {
    let source_inventory = artifact.role == "source-object-stamps";
    let inventory_object = artifact.role.starts_with("inventory-object-");
    let raw = inventory_object && artifact.unpacked_bytes > 0;
    // Any inventory object, raw or an empty WAL file, is only meaningful
    // beside its signed inventory (the Nano Main owner refuses it too).
    if (inventory_object && manifest.derivative_inventory.is_none())
        || (raw && (artifact.members.len() != 1
            || artifact.bytes != artifact.members[0].bytes
            || artifact.sha256 != artifact.members[0].sha256)) {
        bail!("invalid raw inventory object");
    }
    let mut member_bytes = 0_u64;
    let mut prior_path: Option<&str> = None;
    for member in &artifact.members {
        let contracted_empty_file = !source_inventory
            && artifact.family == GenerationBundleArtifactFamily::PrevalenceArtifact
            && generation_bundle_allows_empty_file(&member.relative_path)
            && member.bytes == 0
            && member.total_bytes == 0
            && member.offset == 0;
        let invalid_extent = if contracted_empty_file {
            false
        } else {
            member.bytes == 0
                || member.total_bytes == 0
                || member
                    .offset
                    .checked_add(member.bytes)
                    .is_none_or(|end| end > member.total_bytes)
        };
        if !safe_relative_path(&member.relative_path)
            || invalid_extent
            || member.bytes > MAX_GENERATION_BUNDLE_ARTIFACT_BYTES
            || member.total_bytes > MAX_GENERATION_BUNDLE_TOTAL_BYTES
            || !lower_sha256(&member.sha256)
            || prior_path.is_some_and(|prior| prior >= member.relative_path.as_str())
            || if source_inventory {
                artifact.family != GenerationBundleArtifactFamily::RetainedGeneration
                    || artifact.members.len() != 1
                    || member.relative_path != "bundle-metadata/object-stamps.json"
                    || member.offset != 0
                    || member.total_bytes != member.bytes
            } else {
                member.relative_path.starts_with("bundle-metadata/")
                    || (member.relative_path.starts_with("prevalence-snapshot-v2/")
                        != (artifact.family == GenerationBundleArtifactFamily::PrevalenceArtifact))
            }
        {
            bail!("generation bundle archive member identity is invalid");
        }
        member_bytes = member_bytes
            .checked_add(member.bytes)
            .context("generation bundle archive member bytes overflow")?;
        prior_path = Some(&member.relative_path);
    }
    // An artifact that unpacks to zero bytes holds only contracted empty WAL
    // files, each carrying the empty digest. Mirrors the Nano Main owner's
    // generation bundle schema exactly (the platform).
    let empty_artifact = artifact.members.iter().all(|member| {
        artifact.family == GenerationBundleArtifactFamily::PrevalenceArtifact
            && generation_bundle_allows_empty_file(&member.relative_path)
            && member.bytes == 0
            && member.total_bytes == 0
            && member.offset == 0
            && member.sha256 == EMPTY_FILE_SHA256
    });
    if artifact.role.is_empty()
        || artifact.role.len() > 128
        || artifact
            .role
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        || !safe_object_key(&artifact.key)
        || artifact.bytes == 0
        || artifact.bytes > MAX_GENERATION_BUNDLE_ARTIFACT_BYTES
        || artifact.members.is_empty()
        || (artifact.unpacked_bytes == 0 && !empty_artifact)
        || artifact.unpacked_bytes != member_bytes
        || !lower_sha256(&artifact.sha256)
        || !strong_etag(&artifact.etag)
        || artifact.min_event_time.is_some() != artifact.max_event_time.is_some()
        || artifact
            .min_event_time
            .zip(artifact.max_event_time)
            .is_some_and(|(minimum, maximum)| {
                minimum > maximum
                    || minimum < manifest.min_event_time
                    || maximum > manifest.max_event_time
            })
    {
        bail!("generation bundle artifact identity is invalid");
    }
    let required_prefix = format!("{}/{}/v1/", manifest.tenant_id, artifact.family.key_token());
    if !artifact.key.starts_with(&required_prefix)
        || artifact.key.contains("/legal-holds/")
        || artifact.key.contains("/lifecycle/")
        || !artifact
            .key
            .rsplit_once("/sha256/")
            .is_some_and(|(_, name)| {
                name == artifact.sha256 || name.starts_with(&format!("{}.", artifact.sha256))
            })
    {
        bail!("generation bundle artifact escaped its tenant/family content address");
    }
    Ok(())
}

fn write_candidate_file_chunk(
    path: &Path,
    offset: u64,
    total_bytes: u64,
    bytes: &[u8],
) -> Result<()> {
    let parent = path.parent().context("bundle artifact has no parent")?;
    std::fs::create_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.write(true);
    if offset == 0 {
        options.create_new(true);
    } else {
        options.append(true);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open generation bundle artifact {}", path.display()))?;
    if file.metadata()?.len() != offset {
        bail!("generation bundle artifact chunk offset differs from the candidate file");
    }
    file.write_all(bytes)?;
    if file.metadata()?.len() != offset + bytes.len() as u64 || file.metadata()?.len() > total_bytes
    {
        bail!("generation bundle artifact chunk changed its installed extent");
    }
    file.sync_all()?;
    Ok(())
}

fn write_candidate_file(path: &Path, bytes: &[u8]) -> Result<()> {
    write_candidate_file_chunk(path, 0, bytes.len() as u64, bytes)
}

fn sync_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut cursor = 0;
    while cursor < directories.len() {
        let directory = directories[cursor].clone();
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                continue; // Only signed object links are installed in private candidates.
            }
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            }
        }
        cursor += 1;
    }
    for directory in directories.into_iter().rev() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 2_048
        && !path.is_absolute()
        && !value.chars().any(char::is_control)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(part) if !part.is_empty()))
}

fn safe_object_key(value: &str) -> bool {
    (8..=1_024).contains(&value.len())
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn strong_etag(value: &str) -> bool {
    (3..=1_024).contains(&value.len())
        && value.starts_with('"')
        && value.ends_with('"')
        && !value[1..value.len() - 1].contains('"')
        && !value.chars().any(char::is_control)
}

fn valid_generation_id(value: &str, snapshot_id: i64) -> bool {
    value
        .strip_prefix(&format!("lake-{snapshot_id}-"))
        .is_some_and(|digest| {
            digest.len() == 24
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn valid_table_location(value: &str) -> bool {
    value.starts_with("s3://")
        && value.len() <= 2_048
        && !value.ends_with('/')
        && !value.chars().any(char::is_control)
        && !value.split('/').any(|part| part == "." || part == "..")
}

fn valid_provenance(value: &GenerationBundleBuilderProvenance) -> bool {
    valid_digest_reference(&value.image_digest)
        && lower_sha256(&value.compiler_sha256)
        && lower_sha256(&value.libchdb_sha256)
        && !value.worker_identity.is_empty()
        && value.worker_identity.len() <= 256
        && !value.worker_identity.chars().any(char::is_control)
        && value.phase_timings_seconds.is_object()
}

fn valid_digest_reference(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(lower_sha256)
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value != "0".repeat(64)
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA-256 digest length differs"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[test]
    fn only_exact_slatedb_writer_epoch_fences_may_be_empty() {
        assert!(generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/1h/slatedb/wal/00000000000000000001.sst"
        ));
        assert!(generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/24h/slatedb/wal/00000000000000000001.sst"
        ));
        assert!(generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/7d/slatedb/wal/00000000000000000001.sst"
        ));
        assert!(generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/30d/slatedb/wal/00000000000000000001.sst"
        ));
        assert!(!generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/90d/slatedb/wal/00000000000000000001.sst"
        ));
        assert!(!generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/30d/slatedb/wal/0000000000000000001.sst"
        ));
        assert!(!generation_bundle_allows_empty_file(
            "prevalence-snapshot-v2/1h/slatedb/manifest/00000000000000000001.manifest"
        ));
        assert!(!generation_bundle_allows_empty_file(
            "uid-ledger/window.uids"
        ));
    }

    /// Every window the prevalence builder materializes can carry its own
    /// SlateDB database (a window whose scan differs from every shorter one),
    /// so every window's WAL fences must be admissible.
    #[test]
    fn every_prevalence_window_wal_fence_may_be_empty() {
        // Three-way lockstep: the builder's windows == the lake's serving
        // windows (nanosiem-core lookup.rs) == the Nano Main owner's
        // `fixtures/generation-bundle-prevalence-windows.json`, of which
        // `tests/fixtures/generation-bundle-prevalence-windows.json` is a
        // byte-identical copy. A new builder window must land in the owner
        // first, or the owner refuses the signed manifest after a multi-hour
        // upload.
        let builder = crate::prevalence_build::PREVALENCE_WINDOWS
            .iter()
            .map(|(window, _)| *window)
            .collect::<Vec<_>>();
        assert_eq!(builder, nanosiem_core::prevalence::lookup::PREVALENCE_SNAPSHOT_WINDOWS);
        let fixture = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/generation-bundle-prevalence-windows.json"),
        )
        .unwrap();
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OwnerWindows {
            prevalence_snapshot_windows: Vec<String>,
        }
        let owner: OwnerWindows = serde_json::from_slice(&fixture).unwrap();
        assert_eq!(owner.prevalence_snapshot_windows, builder);
        // Byte-identical to the owner's copy: compact JSON, no trailing newline.
        assert_eq!(
            fixture,
            serde_json::to_vec(&serde_json::json!({ "prevalence_snapshot_windows": builder })).unwrap()
        );
        for &(window, _) in crate::prevalence_build::PREVALENCE_WINDOWS {
            assert!(
                generation_bundle_allows_empty_file(&format!(
                    "prevalence-snapshot-v2/{window}/slatedb/wal/00000000000000000001.sst"
                )),
                "{window}"
            );
        }
    }

    struct MemoryReader {
        objects: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
    }

    impl GenerationBundleObjectReader for MemoryReader {
        fn read_exact<'a>(
            &'a self,
            key: &'a str,
            expected_bytes: u64,
            expected_sha256: &'a str,
            expected_etag: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                let objects = self.objects.lock().unwrap();
                let (bytes, etag) = objects.get(key).context("missing memory object")?;
                if bytes.len() as u64 != expected_bytes
                    || hex::encode(Sha256::digest(bytes)) != expected_sha256
                    || etag != expected_etag
                {
                    bail!("memory object differs");
                }
                Ok(bytes.clone())
            })
        }
    }

    pub(crate) fn fixture() -> (
        SignedGenerationBundleManifest,
        GenerationBundleAdmission,
        PublishedGenerationBundlePointer,
        BTreeMap<String, (Vec<u8>, String)>,
    ) {
        fixture_with_metadata_codec(false)
    }

    fn fixture_with_metadata_codec(
        compressed: bool,
    ) -> (
        SignedGenerationBundleManifest,
        GenerationBundleAdmission,
        PublishedGenerationBundlePointer,
        BTreeMap<String, (Vec<u8>, String)>,
    ) {
        let tenant_id = Uuid::parse_str("23610000-0000-4000-8000-0000000000aa").unwrap();
        let table_uuid = Uuid::parse_str("23610000-0000-4000-8000-0000000000bb").unwrap();
        let digest = |byte: u8| hex::encode([byte; 32]);
        let codec = if compressed { ".gz" } else { "" };
        let object_stamp_manifest = GenerationBundleObjectStampManifest {
            metadata_location: format!(
                "s3://nano-shared-r2-{tenant_id}/warehouse/nano/events/metadata/v42{codec}.metadata.json"
            ),
            snapshot_id: 42,
            table: "nano.events".to_string(),
            objects: vec![GenerationBundleSourceObject {
                relative_path: "data/part-42.parquet".to_string(),
                source_uri: format!(
                    "s3://nano-shared-r2-{tenant_id}/warehouse/nano/events/data/part-42.parquet"
                ),
                version_id: "version-42".to_string(),
                size_bytes: 4096,
                sha256: crate::generation_proof::sha(&vec![10; 4096]),
            }],
        };
        let paths = [
            "bundle-metadata/object-stamps.json",
            "entity-sidecar/manifest.json",
            "entity-sidecar/object-0000.parquet",
            "keyword-sidecar/manifest.json",
            "keyword-sidecar/index/meta.json",
            "fragment-sidecar/manifest.json",
            "fragment-sidecar/index/meta.json",
            "identity-snapshot/manifest.json",
            "identity-snapshot/by-ip.parquet",
            "count-rollup/manifest.json",
            "count-rollup/object-0000.parquet",
            "prevalence-snapshot-v2/manifest.json",
            "prevalence-snapshot-v2/7d/snapshot.parquet",
        ];
        let mut objects = BTreeMap::new();
        let artifacts = paths
            .into_iter()
            .enumerate()
            .map(|(index, relative_path)| {
                let member_bytes = match relative_path {
                    "bundle-metadata/object-stamps.json" => {
                        serde_json::to_vec(&object_stamp_manifest).unwrap()
                    }
                    "entity-sidecar/manifest.json" => serde_json::to_vec(&serde_json::json!({
                        "input_root": "/builder/snapshot",
                        "object_stamp_manifest": "/builder/snapshot/object-stamps.json",
                    }))
                    .unwrap(),
                    "prevalence-snapshot-v2/manifest.json" => {
                        serde_json::to_vec(&serde_json::json!({
                            "windows": [{
                                "scan_file": "/builder/derivatives/prevalence-snapshot-v2/7d/snapshot.parquet",
                                "database_path": "builder/derivatives/prevalence-snapshot-v2/7d/slatedb",
                            }],
                        }))
                        .unwrap()
                    }
                    path if path.ends_with("/manifest.json") => {
                        serde_json::to_vec(&serde_json::json!({"fixture": index})).unwrap()
                    }
                    _ => format!("artifact-{index}").into_bytes(),
                };
                let member_sha256 = hex::encode(Sha256::digest(&member_bytes));
                let family = if relative_path.starts_with("prevalence-snapshot-v2/") {
                    GenerationBundleArtifactFamily::PrevalenceArtifact
                } else {
                    GenerationBundleArtifactFamily::RetainedGeneration
                };
                let mut bytes = Vec::new();
                bytes.extend_from_slice(GENERATION_BUNDLE_ARCHIVE_MAGIC);
                bytes.extend_from_slice(&1_u32.to_be_bytes());
                bytes.extend_from_slice(&(relative_path.len() as u16).to_be_bytes());
                bytes.extend_from_slice(relative_path.as_bytes());
                bytes.extend_from_slice(&(member_bytes.len() as u64).to_be_bytes());
                bytes.extend_from_slice(&hex::decode(&member_sha256).unwrap());
                bytes.extend_from_slice(&member_bytes);
                let sha256 = hex::encode(Sha256::digest(&bytes));
                let key = format!(
                    "{}/{}/v1/files/test/v1/sha256/{}",
                    tenant_id,
                    family.key_token(),
                    sha256
                );
                objects.insert(key.clone(), (bytes.clone(), format!("\"etag-{index}\"")));
                GenerationBundleArtifact {
                    family,
                    role: if relative_path == "bundle-metadata/object-stamps.json" {
                        "source-object-stamps".to_string()
                    } else {
                        format!("artifact-{index}")
                    },
                    key,
                    etag: format!("\"etag-{index}\""),
                    sha256,
                    bytes: bytes.len() as u64,
                    unpacked_bytes: member_bytes.len() as u64,
                    members: vec![GenerationBundleArtifactMember {
                        relative_path: relative_path.to_string(),
                        offset: 0,
                        total_bytes: member_bytes.len() as u64,
                        sha256: member_sha256,
                        bytes: member_bytes.len() as u64,
                    }],
                    min_event_time: None,
                    max_event_time: None,
                }
            })
            .collect::<Vec<_>>();
        let identity = GenerationBundleIdentity {
            tenant_id,
            table_uuid,
            snapshot_id: 42,
            manifest_list_sha256: &digest(1),
            derivative_contract_sha256: &digest(2),
            hmac_key_sha256: &digest(3),
            read_schema_sha256: &digest(4),
        };
        let manifest = GenerationBundleManifest {
            schema_version: GENERATION_BUNDLE_SCHEMA_VERSION,
            contract_version: GENERATION_BUNDLE_CONTRACT_VERSION.to_string(),
            tenant_id,
            table_uuid,
            table_location: format!("s3://nano-shared-r2-{tenant_id}/warehouse/nano/events"),
            snapshot_id: 42,
            manifest_list_sha256: identity.manifest_list_sha256.to_string(),
            iceberg_metadata_location: format!(
                "s3://nano-shared-r2-{tenant_id}/warehouse/nano/events/metadata/v42{codec}.metadata.json"
            ),
            object_stamp_manifest_sha256: object_stamp_manifest_sha256(&object_stamp_manifest)
                .unwrap(),
            source_object_count: object_stamp_manifest.objects.len(),
            ancestor_snapshot_ids: vec![42, 41, 40],
            ancestor_snapshot_ids_sha256: ancestor_snapshot_ids_sha256(&[42, 41, 40]).unwrap(),
            derivative_contract_sha256: identity.derivative_contract_sha256.to_string(),
            hmac_key_sha256: identity.hmac_key_sha256.to_string(),
            read_schema_sha256: identity.read_schema_sha256.to_string(),
            min_event_time: "2026-08-01T00:00:00Z".parse().unwrap(),
            max_event_time: "2026-09-01T00:00:00Z".parse().unwrap(),
            bundle_identity_sha256: bundle_identity(&identity).unwrap(),
            generation_id: "lake-42-aaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            event_config_sha256: digest(5),
            published_sequence: None,
            derivative_inventory: None,
            builder: GenerationBundleBuilderProvenance {
                image_digest: format!("sha256:{}", digest(6)),
                compiler_sha256: digest(7),
                libchdb_sha256: digest(8),
                worker_identity: "builder-a".to_string(),
                phase_timings_seconds: serde_json::json!({"total": 1.0}),
            },
            artifacts,
        };
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let signature = signing_key.sign(&manifest.signature_message().unwrap());
        let signed = SignedGenerationBundleManifest {
            manifest: manifest.clone(),
            signature: GenerationBundleSignature {
                key_id: "platform-bundle-2026-01".to_string(),
                domain: GENERATION_BUNDLE_SIGNATURE_DOMAIN.to_string(),
                signature_base64: BASE64_STANDARD.encode(signature.to_bytes()),
            },
        };
        let signed_bytes = serde_json::to_vec(&signed).unwrap();
        let manifest_sha256 = hex::encode(Sha256::digest(&signed_bytes));
        let manifest_key = format!(
            "{tenant_id}/retained-generation/v1/bundles/{table_uuid}/42-{}/{}/manifest-{manifest_sha256}.json",
            &manifest.manifest_list_sha256[..16],
            &manifest.bundle_identity_sha256[..16]
        );
        objects.insert(
            manifest_key.clone(),
            (signed_bytes.clone(), "\"manifest-etag\"".to_string()),
        );
        let admission = GenerationBundleAdmission {
            tenant_id,
            table_uuid,
            table_location: manifest.table_location.clone(),
            snapshot_id: 42,
            manifest_list_sha256: manifest.manifest_list_sha256.clone(),
            derivative_contract_sha256: manifest.derivative_contract_sha256.clone(),
            hmac_key_sha256: manifest.hmac_key_sha256.clone(),
            read_schema_sha256: manifest.read_schema_sha256.clone(),
            object_stamp_manifest_sha256: manifest.object_stamp_manifest_sha256.clone(),
            assignment_revision: 7,
            irreversible_event_time_floor: "2026-08-01T00:00:00Z".parse().unwrap(),
            signer_key_id: "platform-bundle-2026-01".to_string(),
            signer_public_key: signing_key.verifying_key().to_bytes(),
        };
        let pointer = PublishedGenerationBundlePointer {
            bundle_identity_sha256: manifest.bundle_identity_sha256.clone(),
            manifest_key,
            manifest_sha256,
            manifest_bytes: signed_bytes.len() as u64,
            manifest_etag: "\"manifest-etag\"".to_string(),
            assignment_revision: 7,
            irreversible_event_time_floor: admission.irreversible_event_time_floor,
        };
        (signed, admission, pointer, objects)
    }

    /// NAN-2801: a reader accepts a published pointer up to the
    /// by-reference bound (tenant1's 17,973,474-byte manifest was over the
    /// inline 16 MiB), because the signature, not the transport, is what it
    /// verifies; above the bound it still refuses before downloading.
    #[test]
    fn nan2801_pointer_admits_reference_transport_manifests() {
        let (signed, _, pointer, _) = fixture();
        let identity = signed.manifest.bundle_identity_sha256.clone();
        for bytes in [17_973_474, MAX_GENERATION_BUNDLE_REF_MANIFEST_BYTES] {
            PublishedGenerationBundlePointer { manifest_bytes: bytes, ..pointer.clone() }
                .validate(&identity)
                .unwrap();
        }
        assert!(PublishedGenerationBundlePointer {
            manifest_bytes: MAX_GENERATION_BUNDLE_REF_MANIFEST_BYTES + 1,
            ..pointer.clone()
        }
        .validate(&identity)
        .is_err());
        let key = unsigned_manifest_key(
            signed.manifest.tenant_id, signed.manifest.table_uuid, signed.manifest.snapshot_id,
            &signed.manifest.manifest_list_sha256, &identity, &"e".repeat(64),
        )
        .unwrap();
        // The staged unsigned manifest sits in the signed manifest's directory.
        let directory = pointer.manifest_key.rsplit_once('/').unwrap().0;
        assert_eq!(key, format!("{directory}/sha256/{}.unsigned-manifest.json", "e".repeat(64)));
    }

    /// NAN-2837 benchmark: the full-verification fallback that took 1378 s on
    /// tenant1 (28 GB derivatives + 22 GB snapshot). OLD is the former call
    /// graph -- one serial SHA-256 stream hashing the derivatives three times
    /// (extent check, `signed_local_inventory` for the path set, again in
    /// `rebuild_existing_proof`) plus the snapshot once. NEW is the current
    /// graph -- derivatives and snapshot each hashed once through the bounded
    /// pool. Run:
    /// `NAN2837_BENCH_GB=4 [NAN2837_BENCH_COLD=1] [NANO_LAKE_VERIFY_WORKERS=4] cargo test --release -p nanosiem-lake-worker --lib nan2837_full_verification -- --ignored --nocapture`
    #[test]
    #[ignore = "NAN-2837 offline benchmark; writes NAN2837_BENCH_GB (default 2) under NAN2837_BENCH_DIR or ~/.cache"]
    fn nan2837_full_verification_throughput() {
        let gigabytes: f64 = std::env::var("NAN2837_BENCH_GB").ok().and_then(|v| v.parse().ok()).unwrap_or(2.0);
        let base = std::env::var("NAN2837_BENCH_DIR").map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(std::env::var("HOME").unwrap()).join(".cache/nan-proof-guard/bench"));
        std::fs::create_dir_all(&base).unwrap();
        let root = tempfile::tempdir_in(&base).unwrap();
        // tenant1 shape: derivatives ~1.3 MB/file, snapshot ~3.2 MB/object, 28:22 bytes.
        let total = (gigabytes * 1e9) as u64;
        let make = |dir: &str, bytes: u64, each: u64| -> Vec<String> {
            std::fs::create_dir_all(root.path().join(dir)).unwrap();
            let mut seed = 0x2837_u64;
            (0..bytes.div_ceil(each)).map(|index| {
                let relative = format!("{dir}/{index:06}.bin");
                let mut data = vec![0_u8; each as usize];
                for chunk in data.chunks_mut(8) { seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); chunk.copy_from_slice(&seed.to_le_bytes()[..chunk.len()]); }
                std::fs::write(root.path().join(&relative), &data).unwrap();
                relative
            }).collect()
        };
        let derivatives = make("derivatives", total * 28 / 50, 1_300_000);
        let snapshot = make("snapshot", total * 22 / 50, 3_200_000);
        let bytes = |paths: &[String]| paths.iter().map(|p| std::fs::metadata(root.path().join(p)).unwrap().len()).sum::<u64>();
        let (derivative_bytes, snapshot_bytes) = (bytes(&derivatives), bytes(&snapshot));
        // NAN2837_BENCH_COLD=1 drops each file from the page cache before every
        // pass (POSIX_FADV_DONTNEED, no root needed), as the 7.4 GiB consumer
        // cgroup does to a 28 GB tree in production.
        let cold = std::env::var("NAN2837_BENCH_COLD").is_ok_and(|v| v == "1");
        let evict = |paths: &[String]| if cold { for path in paths {
            use std::os::fd::AsRawFd;
            let file = File::open(root.path().join(path)).unwrap();
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        } } else { for path in paths { file_sha256_and_bytes(&root.path().join(path)).unwrap(); } };

        let mut old_seconds = 0.0;
        let mut old_hashed = 0_u64;
        for _pass in 0..3 {
            evict(&derivatives);
            let started = Instant::now();
            for path in &derivatives { old_hashed += file_sha256_and_bytes(&root.path().join(path)).unwrap().1; }
            old_seconds += started.elapsed().as_secs_f64();
        }
        evict(&snapshot);
        let started = Instant::now();
        for path in &snapshot { old_hashed += file_sha256_and_bytes(&root.path().join(path)).unwrap().1; }
        old_seconds += started.elapsed().as_secs_f64();

        evict(&derivatives); evict(&snapshot);
        let started = Instant::now();
        let hashed = hash_admission_files(root.path(), derivatives.clone(), &KnownDigests::new()).unwrap();
        let snapshot_hashed = crate::verify::parallel_map(&snapshot, crate::verify::verify_workers(), |p| file_sha256_and_bytes(&root.path().join(p))).unwrap();
        let new_seconds = started.elapsed().as_secs_f64();
        let new_hashed = hashed.iter().map(|f| f.bytes).sum::<u64>() + snapshot_hashed.iter().map(|f| f.1).sum::<u64>();
        assert_eq!(new_hashed, derivative_bytes + snapshot_bytes);

        evict(&snapshot);
        let started = Instant::now();
        let mut one_core = 0_u64;
        for path in &snapshot { one_core += file_sha256_and_bytes(&root.path().join(path)).unwrap().1; }
        let core_label = if cold { "sha256_mb_per_s_one_core_cold" } else { "sha256_mb_per_s_one_core" };
        let core_mb_s = one_core as f64 / 1e6 / started.elapsed().as_secs_f64();
        let logical = (derivative_bytes + snapshot_bytes) as f64;
        println!("NAN2837_BENCH {}", serde_json::json!({
            "cold": cold, "derivative_bytes": derivative_bytes, "snapshot_bytes": snapshot_bytes,
            "workers": crate::verify::verify_workers(), core_label: core_mb_s,
            "old_hashed_bytes": old_hashed, "old_seconds": old_seconds, "old_effective_mb_per_s": logical / 1e6 / old_seconds,
            "new_hashed_bytes": new_hashed, "new_seconds": new_seconds, "new_effective_mb_per_s": logical / 1e6 / new_seconds,
            "speedup": old_seconds / new_seconds,
        }));
    }

    fn inventory_fixture() -> (SignedGenerationBundleManifest, GenerationBundleAdmission, PublishedGenerationBundlePointer, BTreeMap<String, (Vec<u8>, String)>) {
        let (mut signed, expected, mut pointer, mut objects) = fixture();
        let mut inventory = Vec::new();
        for (index, artifact) in signed.manifest.artifacts.iter_mut().enumerate() {
            if artifact.role == "source-object-stamps" { continue; }
            let bytes = single_archive_member(artifact, &objects[&artifact.key].0).unwrap().to_vec();
            artifact.role = format!("inventory-object-{index:08}");
            artifact.sha256 = crate::generation_proof::sha(&bytes);
            artifact.bytes = bytes.len() as u64;
            artifact.key = format!("{}/{}/v1/sha256/{}.{}", expected.tenant_id, artifact.family.key_token(), artifact.sha256, index);
            inventory.push(DerivativeMember { relative_path: artifact.members[0].relative_path.clone(),
                sha256: artifact.sha256.clone(), bytes: artifact.bytes, content_id: format!("sha256:{}", artifact.sha256) });
            objects.insert(artifact.key.clone(), (bytes, artifact.etag.clone()));
        }
        signed.manifest.derivative_inventory = Some(inventory);
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        (signed, expected, pointer, objects)
    }
    /// a8f810a3 shape (tenant1, 2026-09-23): in inventory mode an empty
    /// prevalence WAL segment is its own artifact that unpacks to zero bytes.
    fn empty_wal_inventory_object(tenant_id: Uuid, sha256: &str) -> GenerationBundleArtifact {
        let archive = "d".repeat(64);
        GenerationBundleArtifact {
            family: GenerationBundleArtifactFamily::PrevalenceArtifact,
            role: "inventory-object-99999999".to_string(),
            key: format!("{tenant_id}/prevalence-artifact/v1/bundles/0000000000000000/sha256/{archive}.1111111111111111"),
            etag: "\"empty-wal\"".to_string(),
            sha256: archive,
            bytes: 1_024,
            unpacked_bytes: 0,
            members: vec![GenerationBundleArtifactMember {
                relative_path: "prevalence-snapshot-v2/1h/slatedb/wal/00000000000000000001.sst".to_string(),
                offset: 0,
                total_bytes: 0,
                sha256: sha256.to_string(),
                bytes: 0,
            }],
            min_event_time: None,
            max_event_time: None,
        }
    }

    /// Lockstep with the Nano Main owner schema (the platform): a
    /// zero-unpacked artifact is admitted only as contracted empty WAL files
    /// carrying the empty digest, and any `inventory-object-*` role (an empty
    /// WAL object included) needs the signed inventory.
    #[test]
    fn empty_wal_inventory_objects_match_the_owner_contract() {
        let (signed, expected, _, _) = inventory_fixture();
        let with_wal = |sha256: &str, inventory: bool| {
            let mut manifest = signed.manifest.clone();
            manifest.artifacts.push(empty_wal_inventory_object(expected.tenant_id, sha256));
            if inventory {
                manifest.derivative_inventory.as_mut().unwrap().push(DerivativeMember {
                    relative_path: "prevalence-snapshot-v2/1h/slatedb/wal/00000000000000000001.sst".to_string(),
                    sha256: sha256.to_string(),
                    bytes: 0,
                    content_id: format!("sha256:{sha256}"),
                });
            } else {
                manifest.derivative_inventory = None;
            }
            manifest
        };
        with_wal(EMPTY_FILE_SHA256, true).validate_structure().unwrap();
        // A zero-byte member claiming non-empty content is refused.
        let forged = "c".repeat(64);
        assert!(with_wal(&forged, true).validate_structure().is_err());
        // An inventory object without the signed inventory is refused, even
        // one that unpacks to zero bytes.
        let mut legacy = signed.manifest.clone();
        legacy.derivative_inventory = None;
        legacy.artifacts.retain(|artifact| artifact.role == "source-object-stamps");
        legacy.artifacts.push(empty_wal_inventory_object(expected.tenant_id, EMPTY_FILE_SHA256));
        let error = legacy.validate_structure().unwrap_err().to_string();
        assert!(error.contains("invalid raw inventory object"), "{error}");
        assert!(with_wal(EMPTY_FILE_SHA256, false).validate_structure().is_err());
    }

    fn resign_inventory(signed: &mut SignedGenerationBundleManifest, pointer: &mut PublishedGenerationBundlePointer, objects: &mut BTreeMap<String, (Vec<u8>, String)>) {
        signed.manifest.validate_structure().unwrap();
        signed.signature.signature_base64 = BASE64_STANDARD.encode(SigningKey::from_bytes(&[9;32]).sign(&signed.manifest.signature_message().unwrap()).to_bytes());
        let bytes = serde_json::to_vec(signed).unwrap();
        pointer.manifest_sha256 = crate::generation_proof::sha(&bytes);
        pointer.manifest_bytes = bytes.len() as u64;
        pointer.manifest_key = format!("{}/manifest-{}.json", pointer.manifest_key.rsplit_once('/').unwrap().0, pointer.manifest_sha256);
        objects.insert(pointer.manifest_key.clone(), (bytes, pointer.manifest_etag.clone()));
    }
    fn inventory_snapshot(generation: &Path, signed: &SignedGenerationBundleManifest, objects: &BTreeMap<String, (Vec<u8>, String)>) {
        let source = signed.manifest.artifacts.iter().find(|a| a.role == "source-object-stamps").unwrap();
        std::fs::create_dir_all(generation.join("snapshot/data/data")).unwrap();
        std::fs::write(generation.join("snapshot/object-stamps.json"), single_archive_member(source, &objects[&source.key].0).unwrap()).unwrap();
        std::fs::write(generation.join("snapshot/data/data/part-42.parquet"), vec![10;4096]).unwrap();
    }

    #[tokio::test]
    async fn inventory_reuses_without_get_or_rehash_and_pins_preserve_objects() {
        use crate::generation_proof::{Body, Reference, FILE_NAME, tests::KEY};
        let (mut signed, expected, mut pointer, mut objects) = inventory_fixture();
        let root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 1024*1024*1024, reserve_bytes: 0 };
        let first = root.path().join("snapshot-first");
        inventory_snapshot(&first, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &first.join("derivatives"), &budget, KEY, None).await.unwrap();
        let proof = Body::load(&Reference { path: first.join("derivatives").join(FILE_NAME), identity: proof_identity(&pointer, &signed) }, KEY).unwrap();
        let original_guards: BTreeMap<_, _> = proof.files.iter().filter(|(_, r)| r.object_sha256.is_some()).map(|(p, r)| (p.clone(), r.guard.clone())).collect();
        for artifact in signed.manifest.artifacts.iter().filter(|a| a.role != "source-object-stamps") { reader.objects.lock().unwrap().remove(&artifact.key); }
        signed.manifest.generation_id = "lake-42-bbbbbbbbbbbbbbbbbbbbbbbb".into();
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        reader.objects.lock().unwrap().insert(pointer.manifest_key.clone(), objects[&pointer.manifest_key].clone());
        let second = root.path().join("snapshot-second");
        let preflight = preflight_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, Some(KEY), Some(&proof), || Ok(())).await.unwrap();
        assert_eq!(preflight.reused_bytes, 4096 + signed.manifest.derivative_inventory.as_ref().unwrap().iter().map(|m| m.bytes).sum::<u64>());
        inventory_snapshot(&second, &signed, &objects);
        let outcome = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None).await.unwrap();
        assert!(outcome.disk.unwrap().reused_bytes > 0);
        let second_proof = Body::load(&Reference { path: second.join("derivatives").join(FILE_NAME), identity: proof_identity(&pointer, &signed) }, KEY).unwrap();
        for (path, guard) in original_guards { assert_eq!(second_proof.files[&path].guard, guard); }
        let mut plan = crate::verify::VerificationPlan::new();
        for (path, record) in second_proof.files.iter().filter(|(_, record)| record.object_sha256.is_some()) {
            plan.file(&crate::config::VerifiedArtifact { path: second.join(path), sha256: record.sha256.clone() });
        }
        assert_eq!(plan.run_proven(1, Some(&second_proof), &[]).unwrap().report.bytes, 0);
        let retained = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None).await.unwrap();
        assert_eq!(retained.payload_hashed_bytes, 0);
        // Loss of the local HMAC proof triggers signed, full verification; raw
        // portable manifests can still be reconstructed without an archive.
        for artifact in signed.manifest.artifacts.iter().filter(|a| a.members[0].relative_path.ends_with("/manifest.json")) {
            reader.objects.lock().unwrap().insert(artifact.key.clone(), objects[&artifact.key].clone());
        }
        std::fs::remove_file(second.join("derivatives").join(FILE_NAME)).unwrap();
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None).await.unwrap();
        proof.validate_guards().unwrap(); // another generation cannot invalidate ctime
        assert_eq!(crate::generation_proof::collect_objects(root.path()).unwrap(), 0);
        std::fs::remove_dir_all(&second).unwrap(); // first is still rollback/durable pinned
        assert_eq!(crate::generation_proof::collect_objects(root.path()).unwrap(), 0);
        proof.validate_guards().unwrap();
        std::fs::remove_dir_all(&first).unwrap();
        assert!(crate::generation_proof::collect_objects(root.path()).unwrap() > 0);
    }

    /// NAN-2532 item 5: `prune_local_generations`/`collect_objects` can delete
    /// an object that the capacity preflight counted as reusable. The
    /// hydrate-time recheck under the content-store lock is authoritative and
    /// then fails on capacity -- so it needs the same reclaim retry preflight
    /// has, or the roll dies and only recovers on the next reconcile.
    /// NAN-2532 item 6: the two REPORTED figures. `final_derivative_allocated_bytes`
    /// is what an operator sizes the local cap from (it is logged at
    /// `lake_generation_manage.rs`), and for an inventory generation it used to
    /// charge every member at full size while the generation directory holds
    /// only links -- `preflight_existing_disk_budget` measured the same
    /// generation at ~0. And a `manifest.json` member really is stored twice:
    /// the portable bytes as a content object, the rebased bytes in the tree.
    #[tokio::test]
    async fn inventory_reports_tree_allocation_and_content_store_growth_separately() {
        use crate::generation_proof::tests::KEY;
        let (mut signed, expected, pointer, objects) = inventory_fixture();
        // Make the payloads big enough that a link-sized charge is unmistakable.
        let member_bytes = 32 * 1024 * 1024_u64;
        let mut manifest_bytes = 0_u64;
        let mut payload_bytes = 0_u64;
        for artifact in signed.manifest.artifacts.iter_mut().filter(|a| a.role != "source-object-stamps") {
            artifact.members[0].bytes = member_bytes;
            artifact.members[0].total_bytes = member_bytes;
            if artifact.members[0].relative_path.ends_with("/manifest.json") { manifest_bytes += member_bytes; }
            else { payload_bytes += member_bytes; }
        }
        let root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 64 * 1024 * 1024 * 1024, reserve_bytes: 0 };
        let target = root.path().join("snapshot-next/derivatives");

        let fresh = preflight_disk_budget_reusing(&budget, &target, &signed.manifest, 0, &BTreeSet::new()).unwrap();
        // The generation directory holds links plus the rebased manifests --
        // NOT the payloads. (The receipt's conservative constant is the rest.)
        let tree_payload = fresh.final_derivative_allocated_bytes
            - conservative_allocated_bytes(MAX_GENERATION_BUNDLE_ADMISSION_RECEIPT_BYTES).unwrap();
        assert!(tree_payload < manifest_bytes + 1024 * 1024, "tree charge {tree_payload} must be manifests plus links, not payloads");
        assert!(tree_payload >= manifest_bytes, "the rebased manifests are in the tree");
        // The payload bytes are reported as content-store growth instead, and
        // a manifest is charged there TOO because it is stored twice.
        assert!(fresh.final_object_store_allocated_bytes >= payload_bytes + manifest_bytes);

        // Reusing the same objects adds nothing to the content store.
        let reused: BTreeSet<_> = signed.manifest.derivative_inventory.as_ref().unwrap().iter().map(|m| m.relative_path.clone()).collect();
        let warm = preflight_disk_budget_reusing(&budget, &target, &signed.manifest, 0, &reused).unwrap();
        assert_eq!(warm.final_object_store_allocated_bytes, 0);
        assert_eq!(warm.final_derivative_allocated_bytes, fresh.final_derivative_allocated_bytes);
        assert!(warm.peak_allocated_bytes < fresh.peak_allocated_bytes);

        // A legacy bundle is unchanged: everything lands in the generation tree.
        let (legacy, ..) = fixture();
        let legacy_accounting = preflight_disk_budget_reusing(&budget, &target, &legacy.manifest, 0, &BTreeSet::new()).unwrap();
        assert_eq!(legacy_accounting.final_object_store_allocated_bytes, 0);

        // And the reported tree figure agrees with what the directory really
        // holds once the generation is admitted.
        let generation = root.path().join("snapshot-admitted");
        inventory_snapshot(&generation, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        let admitted = generation.join("derivatives");
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &admitted, &budget, KEY, None).await.unwrap();
        let existing = preflight_existing_disk_budget(&budget, &admitted).unwrap();
        assert_eq!(existing.final_object_store_allocated_bytes, 0);
        // Both paths now describe the same thing: the generation directory.
        assert!(existing.final_derivative_allocated_bytes <= fresh.final_derivative_allocated_bytes,
            "existing {} vs planned {}", existing.final_derivative_allocated_bytes, fresh.final_derivative_allocated_bytes);
    }

    #[tokio::test]
    async fn an_object_collected_between_preflight_and_hydrate_is_reclaimed_not_fatal() {
        use crate::generation_proof::{tests::KEY, Body, Reference, FILE_NAME};
        let (mut signed, expected, mut pointer, mut objects) = inventory_fixture();
        let root = tempfile::tempdir().unwrap();
        let generous = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 1024 * 1024 * 1024, reserve_bytes: 0 };
        let first = root.path().join("snapshot-first");
        inventory_snapshot(&first, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &first.join("derivatives"), &generous, KEY, None).await.unwrap();
        let proof = Body::load(&Reference { path: first.join("derivatives").join(FILE_NAME), identity: proof_identity(&pointer, &signed) }, KEY).unwrap();

        signed.manifest.generation_id = "lake-42-bbbbbbbbbbbbbbbbbbbbbbbb".into();
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        reader.objects.lock().unwrap().insert(pointer.manifest_key.clone(), objects[&pointer.manifest_key].clone());
        let second = root.path().join("snapshot-second");
        inventory_snapshot(&second, &signed, &objects);
        let target = second.join("derivatives");

        // 4 MiB of retained-generation ballast: this is the space the
        // reclaim releases when the roll no longer fits.
        std::fs::write(first.join("ballast.bin"), vec![7_u8; 4 * 1024 * 1024]).unwrap();
        let reused: BTreeSet<_> = signed.manifest.derivative_inventory.as_ref().unwrap().iter().map(|m| m.relative_path.clone()).collect();
        let planned = preflight_disk_budget_reusing(&generous, &target, &signed.manifest, 0, &reused).unwrap();
        let tight = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: planned.peak_allocated_bytes, reserve_bytes: 0 };

        // Preflight passes: every object is in the content store, so the roll
        // is charged only its new bytes and it fits the cap exactly.
        let admitted = preflight_generation_bundle_proven(&reader, &pointer, &expected, &target, &tight, Some(KEY), Some(&proof), || Ok(())).await.unwrap();
        assert!(admitted.reused_bytes > 0);

        // ... and then the collector runs.
        for member in signed.manifest.derivative_inventory.as_ref().unwrap() {
            let object = root.path().join("objects").join(&member.sha256);
            if object.exists() {
                std::fs::remove_file(&object).unwrap();
                std::fs::remove_file(root.path().join("objects/.receipts").join(&member.sha256)).unwrap();
            }
        }

        // Without a reclaim the roll dies on capacity.
        let error = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &target, &tight, KEY, None).await.unwrap_err();
        assert!(error.downcast_ref::<GenerationBundleCapacityError>().is_some(), "{error}");
        assert!(!target.exists(), "a failed hydration leaves nothing behind");

        // With one, the retained generation is released and the roll lands.
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let reclaim = || -> Result<()> {
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::fs::remove_dir_all(&first)?;
            Ok(())
        };
        hydrate_generation_bundle_proven_reclaiming(&reader, &pointer, &expected, &target, &tight, KEY, None, &reclaim).await.unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1, "exactly one reclaim, then the roll proceeds");
        Body::load(&Reference { path: target.join(FILE_NAME), identity: proof_identity(&pointer, &signed) }, KEY).unwrap();
    }

    #[tokio::test]
    async fn inventory_additions_removals_and_tampered_content_ids() {
        use crate::generation_proof::{Body, Reference, FILE_NAME, tests::KEY};
        let (mut signed, expected, mut pointer, mut objects) = inventory_fixture();
        let root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 1024*1024*1024, reserve_bytes: 0 };
        let first = root.path().join("snapshot-first"); inventory_snapshot(&first, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &first.join("derivatives"), &budget, KEY, None).await.unwrap();
        let old = signed.manifest.artifacts.iter().find(|a| a.members[0].relative_path == "entity-sidecar/object-0000.parquet").unwrap().clone();
        for artifact in signed.manifest.artifacts.iter().filter(|a| a.role != "source-object-stamps") { reader.objects.lock().unwrap().remove(&artifact.key); }
        let artifact = signed.manifest.artifacts.iter_mut().find(|a| a.key == old.key).unwrap();
        let bytes = b"changed derivative".to_vec(); let digest = crate::generation_proof::sha(&bytes);
        artifact.sha256 = digest.clone(); artifact.bytes = bytes.len() as u64; artifact.unpacked_bytes = artifact.bytes;
        artifact.key = format!("{}/retained-generation/v1/sha256/{digest}", expected.tenant_id);
        artifact.members[0] = GenerationBundleArtifactMember { relative_path: "entity-sidecar/object-0001.parquet".into(), offset: 0, total_bytes: artifact.bytes, sha256: digest.clone(), bytes: artifact.bytes };
        let member = signed.manifest.derivative_inventory.as_mut().unwrap().iter_mut().find(|m| m.relative_path == old.members[0].relative_path).unwrap();
        *member = DerivativeMember { relative_path: artifact.members[0].relative_path.clone(), sha256: digest.clone(), bytes: artifact.bytes, content_id: format!("sha256:{digest}") };
        reader.objects.lock().unwrap().insert(artifact.key.clone(), (bytes, artifact.etag.clone()));
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        reader.objects.lock().unwrap().insert(pointer.manifest_key.clone(), objects[&pointer.manifest_key].clone());
        let second = root.path().join("snapshot-second"); inventory_snapshot(&second, &signed, &objects);
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None).await.unwrap();
        assert!(!second.join("derivatives/entity-sidecar/object-0000.parquet").exists());
        assert_eq!(std::fs::read(second.join("derivatives/entity-sidecar/object-0001.parquet")).unwrap(), b"changed derivative");
        let proof = Body::load(&Reference { path: second.join("derivatives").join(FILE_NAME), identity: proof_identity(&pointer, &signed) }, KEY).unwrap();
        let path = second.join("derivatives/entity-sidecar/object-0001.parquet");
        std::fs::remove_file(&path).unwrap(); std::os::unix::fs::symlink(root.path().join("objects").join(&old.sha256), &path).unwrap();
        assert!(proof.validate_guards().is_err());
        signed.manifest.derivative_inventory.as_mut().unwrap()[0].content_id = format!("sha256:{}", "f".repeat(64));
        assert!(signed.verify(&expected).is_err());
        assert!(signed.manifest.validate_structure().is_err());
    }

    /// NAN-2532 item 7: cold-hydration wall time, legacy archive shards vs one
    /// raw object per derivative file, against a latency-injecting stub.
    ///
    /// Both paths transfer IDENTICAL payload bytes, so the only difference is
    /// the number of round trips: legacy packs files into <=512 MiB archive
    /// shards, the inventory publisher emits one object per file. Run it with
    /// `LAKE_GENERATION_BUNDLE_OBJECT_FETCH_CONCURRENCY=1` to reproduce the
    /// pre-fix, one-active-GET behaviour.
    struct LatencyReader {
        objects: Mutex<BTreeMap<String, (Vec<u8>, String)>>,
        first_byte: std::time::Duration,
        bytes_per_second: u64,
        gets: std::sync::atomic::AtomicUsize,
        peak_in_flight: Mutex<(usize, usize)>,
    }

    impl LatencyReader {
        fn new(objects: BTreeMap<String, (Vec<u8>, String)>, first_byte: std::time::Duration, bytes_per_second: u64) -> Self {
            Self { objects: Mutex::new(objects), first_byte, bytes_per_second,
                gets: std::sync::atomic::AtomicUsize::new(0), peak_in_flight: Mutex::new((0, 0)) }
        }
        fn enter(&self) { let mut state = self.peak_in_flight.lock().unwrap(); state.0 += 1; state.1 = state.1.max(state.0); }
        fn leave(&self) { self.peak_in_flight.lock().unwrap().0 -= 1; }
    }

    impl GenerationBundleObjectReader for LatencyReader {
        fn read_exact<'a>(&'a self, key: &'a str, expected_bytes: u64, expected_sha256: &'a str, expected_etag: &'a str)
            -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                self.gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.enter();
                tokio::time::sleep(self.first_byte).await;
                let bytes = {
                    let objects = self.objects.lock().unwrap();
                    let (bytes, etag) = objects.get(key).context("missing memory object")?;
                    if bytes.len() as u64 != expected_bytes || hex::encode(Sha256::digest(bytes)) != expected_sha256 || etag != expected_etag {
                        bail!("memory object differs");
                    }
                    bytes.clone()
                };
                tokio::time::sleep(std::time::Duration::from_secs_f64(bytes.len() as f64 / self.bytes_per_second as f64)).await;
                self.leave();
                Ok(bytes)
            })
        }
    }

    /// Base fixture plus `count` derivative parquet files of `bytes` each, in
    /// both wire shapes: legacy archive shards and one raw object per file.
    fn scaled_bundles(count: usize, bytes: usize) -> (
        (SignedGenerationBundleManifest, PublishedGenerationBundlePointer, BTreeMap<String, (Vec<u8>, String)>),
        (SignedGenerationBundleManifest, PublishedGenerationBundlePointer, BTreeMap<String, (Vec<u8>, String)>),
        GenerationBundleAdmission,
    ) {
        let (base, expected, base_pointer, base_objects) = fixture();
        let tenant = expected.tenant_id;
        let payloads: Vec<(String, Vec<u8>)> = (0..count)
            .map(|index| {
                // Distinct content per file: identical bytes would collapse
                // into one content-store object and measure nothing.
                let mut payload = vec![0_u8; bytes];
                payload[..8].copy_from_slice(&(index as u64).to_be_bytes());
                (format!("entity-sidecar/object-{index:06}.parquet"), payload)
            })
            .collect();

        // ---- legacy: pack the added files into <=512 MiB archive shards ----
        let mut legacy = base.clone();
        let mut legacy_objects = base_objects.clone();
        let mut shard: Vec<&(String, Vec<u8>)> = Vec::new();
        let mut shard_bytes = 0_usize;
        let mut shards: Vec<Vec<&(String, Vec<u8>)>> = Vec::new();
        for file in &payloads {
            if shard_bytes + file.1.len() > 512 * 1024 * 1024_usize && !shard.is_empty() {
                shards.push(std::mem::take(&mut shard));
                shard_bytes = 0;
            }
            shard_bytes += file.1.len();
            shard.push(file);
        }
        if !shard.is_empty() { shards.push(shard); }
        for (index, members) in shards.iter().enumerate() {
            let mut archive = GENERATION_BUNDLE_ARCHIVE_MAGIC.to_vec();
            archive.extend_from_slice(&(members.len() as u32).to_be_bytes());
            let mut signed_members = Vec::new();
            for (path, payload) in members {
                let digest = hex::encode(Sha256::digest(payload));
                archive.extend_from_slice(&(path.len() as u16).to_be_bytes());
                archive.extend_from_slice(path.as_bytes());
                archive.extend_from_slice(&(payload.len() as u64).to_be_bytes());
                archive.extend_from_slice(&hex::decode(&digest).unwrap());
                archive.extend_from_slice(payload);
                signed_members.push(GenerationBundleArtifactMember { relative_path: path.clone(), offset: 0,
                    total_bytes: payload.len() as u64, sha256: digest, bytes: payload.len() as u64 });
            }
            let sha256 = hex::encode(Sha256::digest(&archive));
            let key = format!("{tenant}/retained-generation/v1/sha256/{sha256}.shard{index}");
            let etag = format!("\"shard-etag-{index}\"");
            legacy_objects.insert(key.clone(), (archive.clone(), etag.clone()));
            legacy.manifest.artifacts.push(GenerationBundleArtifact {
                family: GenerationBundleArtifactFamily::RetainedGeneration,
                role: format!("retained-generation-shard-{index:05}"),
                key, etag, sha256,
                bytes: archive.len() as u64,
                unpacked_bytes: signed_members.iter().map(|m| m.bytes).sum(),
                members: signed_members, min_event_time: None, max_event_time: None,
            });
        }
        let mut legacy_pointer = base_pointer.clone();
        resign_inventory(&mut legacy, &mut legacy_pointer, &mut legacy_objects);

        // ---- inventory: one raw object per derivative file ----
        let (mut incremental, _, mut incremental_pointer, mut incremental_objects) = inventory_fixture();
        let mut members = incremental.manifest.derivative_inventory.clone().unwrap();
        for (index, (path, payload)) in payloads.iter().enumerate() {
            let sha256 = hex::encode(Sha256::digest(payload));
            let key = format!("{tenant}/retained-generation/v1/sha256/{sha256}.{index}");
            let etag = format!("\"raw-etag-{index}\"");
            incremental_objects.insert(key.clone(), (payload.clone(), etag.clone()));
            incremental.manifest.artifacts.push(GenerationBundleArtifact {
                family: GenerationBundleArtifactFamily::RetainedGeneration,
                role: format!("inventory-object-{:08}", 1000 + index),
                key, etag, sha256: sha256.clone(),
                bytes: payload.len() as u64, unpacked_bytes: payload.len() as u64,
                members: vec![GenerationBundleArtifactMember { relative_path: path.clone(), offset: 0,
                    total_bytes: payload.len() as u64, sha256: sha256.clone(), bytes: payload.len() as u64 }],
                min_event_time: None, max_event_time: None,
            });
            members.push(DerivativeMember { relative_path: path.clone(), sha256: sha256.clone(),
                bytes: payload.len() as u64, content_id: format!("sha256:{sha256}") });
        }
        incremental.manifest.derivative_inventory = Some(members);
        resign_inventory(&mut incremental, &mut incremental_pointer, &mut incremental_objects);

        ((legacy, legacy_pointer, legacy_objects), (incremental, incremental_pointer, incremental_objects), expected)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "NAN-2532 cold-hydration measurement; wall-clock, run explicitly"]
    async fn nan2532_cold_hydration_legacy_vs_inventory() {
        use crate::generation_proof::tests::KEY;
        let count: usize = std::env::var("NAN2532_FILES").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
        let bytes: usize = std::env::var("NAN2532_FILE_BYTES").ok().and_then(|v| v.parse().ok()).unwrap_or(256 * 1024);
        let first_byte = std::time::Duration::from_millis(std::env::var("NAN2532_TTFB_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(45));
        let bandwidth: u64 = std::env::var("NAN2532_BYTES_PER_SECOND").ok().and_then(|v| v.parse().ok()).unwrap_or(120 * 1000 * 1000);
        let (legacy, incremental, expected) = scaled_bundles(count, bytes);

        let root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 64 * 1024 * 1024 * 1024, reserve_bytes: 0 };
        let generation = root.path().join("snapshot-legacy");
        inventory_snapshot(&generation, &legacy.0, &legacy.2);
        let reader = LatencyReader::new(legacy.2.clone(), first_byte, bandwidth);
        let started = Instant::now();
        let hydrated = hydrate_generation_bundle_proven(&reader, &legacy.1, &expected, &generation.join("derivatives"), &budget, KEY, None).await.unwrap();
        let legacy_seconds = started.elapsed().as_secs_f64();
        let legacy_gets = reader.gets.load(std::sync::atomic::Ordering::Relaxed);
        let payload_bytes = hydrated.bytes;

        let inventory_root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget { generations_root: inventory_root.path().into(), max_local_bytes: 64 * 1024 * 1024 * 1024, reserve_bytes: 0 };
        let generation = inventory_root.path().join("snapshot-inventory");
        inventory_snapshot(&generation, &incremental.0, &incremental.2);
        let reader = LatencyReader::new(incremental.2.clone(), first_byte, bandwidth);
        let started = Instant::now();
        hydrate_generation_bundle_proven(&reader, &incremental.1, &expected, &generation.join("derivatives"), &budget, KEY, None).await.unwrap();
        let inventory_seconds = started.elapsed().as_secs_f64();
        let inventory_gets = reader.gets.load(std::sync::atomic::Ordering::Relaxed);
        let peak_in_flight = reader.peak_in_flight.lock().unwrap().1;

        println!("NAN2532_COLD_HYDRATION {}", serde_json::json!({
            "files": count, "file_bytes": bytes, "payload_bytes": payload_bytes,
            "injected_ttfb_ms": first_byte.as_millis(), "injected_bytes_per_second": bandwidth,
            "object_fetch_concurrency": raw_object_fetch_concurrency(),
            "legacy_gets": legacy_gets, "legacy_seconds": legacy_seconds,
            "inventory_gets": inventory_gets, "inventory_seconds": inventory_seconds,
            "inventory_peak_gets_in_flight": peak_in_flight,
            "inventory_vs_legacy": inventory_seconds / legacy_seconds,
        }));
    }

    #[tokio::test]
    async fn inventory_split_raw_extents_preserve_full_file_identity() {
        use crate::generation_proof::tests::KEY;
        let (mut signed, expected, mut pointer, mut objects) = inventory_fixture();
        let index = signed.manifest.artifacts.iter().position(|a| a.members[0].relative_path == "entity-sidecar/object-0000.parquet").unwrap();
        let original = signed.manifest.artifacts[index].clone();
        let payload = objects[&original.key].0.clone();
        let cut = payload.len()/2;
        let chunks: Vec<_> = [(&payload[..cut], 0), (&payload[cut..], cut)].into_iter().enumerate().map(|(index, (bytes, offset))| {
            let mut chunk = original.clone(); chunk.role.push_str(&format!("-{index}"));
            chunk.sha256 = crate::generation_proof::sha(bytes); chunk.bytes = bytes.len() as u64; chunk.unpacked_bytes = chunk.bytes;
            chunk.members[0].offset = offset as u64; chunk.members[0].bytes = chunk.bytes; chunk.members[0].sha256 = chunk.sha256.clone();
            chunk.key = format!("{}/retained-generation/v1/sha256/{}.{}", expected.tenant_id, chunk.sha256, index);
            objects.insert(chunk.key.clone(), (bytes.to_vec(), chunk.etag.clone())); chunk
        }).collect();
        signed.manifest.artifacts.splice(index..index+1, chunks);
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        let root = tempfile::tempdir().unwrap(); let generation = root.path().join("snapshot-first"); inventory_snapshot(&generation, &signed, &objects);
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 1024*1024*1024, reserve_bytes: 0 };
        let reader = MemoryReader { objects: Mutex::new(objects) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &generation.join("derivatives"), &budget, KEY, None).await.unwrap();
        assert_eq!(std::fs::read(generation.join("derivatives/entity-sidecar/object-0000.parquet")).unwrap(), payload);
    }

    /// NAN-2768: a bundle that references the prior bundle's unchanged
    /// objects hydrates from a mix of keys under two bundle prefixes. The
    /// reader resolves every artifact by its signed key and re-verifies the
    /// exact digest, so key provenance is irrelevant; a prior object that is
    /// gone or altered still fails closed.
    #[tokio::test]
    async fn nan2768_bundle_hydrates_from_prior_bundle_objects_mixed_with_new_ones() {
        use crate::generation_proof::tests::KEY;
        let (mut signed, expected, mut pointer, mut objects) = inventory_fixture();
        let tenant = expected.tenant_id;
        let prior = "aaaaaaaaaaaaaaaa";
        let current = "bbbbbbbbbbbbbbbb";
        let mut moved = 0;
        let mut kept = 0;
        for (index, artifact) in signed.manifest.artifacts.iter_mut().enumerate() {
            let (bytes, etag) = objects.remove(&artifact.key).unwrap();
            // Alternate: even artifacts were referenced from the prior bundle,
            // odd ones (and the stamps) were uploaded by this one.
            let owner = if artifact.role != "source-object-stamps" && index % 2 == 0 { kept += 1; prior } else { moved += 1; current };
            artifact.key = format!("{tenant}/{}/v1/bundles/{owner}/sha256/{}.{index:016x}", artifact.family.key_token(), artifact.sha256);
            objects.insert(artifact.key.clone(), (bytes, etag));
        }
        assert!(kept > 0 && moved > 1);
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        let root = tempfile::tempdir().unwrap();
        let generation = root.path().join("snapshot-mixed");
        inventory_snapshot(&generation, &signed, &objects);
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 1024 * 1024 * 1024, reserve_bytes: 0 };
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &generation.join("derivatives"), &budget, KEY, None).await.unwrap();
        // Sidecar manifests are rebased to the install root on hydration; every
        // other file is installed byte for byte.
        for artifact in signed.manifest.artifacts.iter()
            .filter(|a| a.role != "source-object-stamps" && !a.members[0].relative_path.ends_with("manifest.json")) {
            let member = &artifact.members[0];
            let installed = std::fs::read(generation.join("derivatives").join(&member.relative_path)).unwrap();
            assert_eq!(crate::generation_proof::sha(&installed), member.sha256, "{}", member.relative_path);
        }

        // Fail closed: a referenced prior object that was deleted, or replaced
        // under the same key, never installs.
        let victim = signed.manifest.artifacts.iter()
            .find(|a| a.role != "source-object-stamps" && a.key.contains(&format!("/bundles/{prior}/")) && a.bytes > 0)
            .unwrap().clone();
        for tamper in [false, true] {
            let mut broken = objects.clone();
            if tamper {
                let entry = broken.get_mut(&victim.key).unwrap();
                entry.0[0] ^= 0xff;
            } else {
                broken.remove(&victim.key);
            }
            let root = tempfile::tempdir().unwrap();
            let generation = root.path().join("snapshot-broken");
            inventory_snapshot(&generation, &signed, &broken);
            let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 1024 * 1024 * 1024, reserve_bytes: 0 };
            let reader = MemoryReader { objects: Mutex::new(broken) };
            assert!(hydrate_generation_bundle_proven(&reader, &pointer, &expected, &generation.join("derivatives"), &budget, KEY, None).await.is_err());
        }
    }

    #[test]
    fn inventory_capacity_charges_only_new_bytes_and_legacy_wire_stays_identical() {
        let (legacy, _, _, _) = fixture();
        assert!(!String::from_utf8(legacy.manifest.canonical_bytes().unwrap()).unwrap().contains("derivative_inventory"));
        let (mut signed, _, _, _) = inventory_fixture();
        let root = tempfile::tempdir().unwrap();
        let reused: BTreeSet<_> = signed.manifest.derivative_inventory.as_ref().unwrap().iter().map(|m| m.relative_path.clone()).collect();
        for artifact in signed.manifest.artifacts.iter_mut().filter(|a| a.role != "source-object-stamps") {
            if !artifact.members[0].relative_path.ends_with("/manifest.json") { artifact.members[0].bytes = 2 * 1024*1024*1024; }
        }
        let budget = GenerationBundleDiskBudget { generations_root: root.path().into(), max_local_bytes: 25*1024*1024*1024, reserve_bytes: 0 };
        let target = root.path().join("snapshot-next/derivatives");
        let accounting = preflight_disk_budget_reusing(&budget, &target, &signed.manifest, 14*1024*1024*1024, &reused).unwrap();
        assert!(accounting.reused_bytes >= 12*1024*1024*1024);
        assert!(accounting.peak_allocated_bytes < 15*1024*1024*1024);
        let error = preflight_disk_budget_reusing(&budget, &target, &signed.manifest, 14*1024*1024*1024, &BTreeSet::new()).unwrap_err();
        assert!(error.to_string().contains("reused=0 new="));
    }

    /// NAN-2559: a generation LARGER THAN HALF the volume must still reconcile.
    ///
    /// A legacy archive bundle is opaque, so the successor is staged whole
    /// beside the generation still being served and reconciliation needs ~2x
    /// the generation size: past half the volume every cycle fences itself
    /// ("isolated generation reconciliation failed; active generation remains
    /// fenced" on tenant1, 2026-09-22). The content-addressed shape stages
    /// only what the content store does not already hold, so the requirement
    /// is one generation plus the delta -- the active generation's bytes are
    /// shared, not copied.
    #[tokio::test]
    async fn nan2559_generation_larger_than_half_the_volume_reconciles() {
        use crate::generation_proof::tests::KEY;
        // 64 MiB of derivative payload per generation in a 112 MiB volume.
        let (legacy, incremental, expected) = scaled_bundles(64, 1024 * 1024);
        const VOLUME: u64 = 112 * 1024 * 1024;
        const RESERVE: u64 = 1024 * 1024;
        const GENERATION: u64 = 64 * 1024 * 1024;
        assert!(GENERATION > VOLUME / 2, "the fixture must exceed half the volume");

        // A successor generation whose derivative content is unchanged: the
        // publisher rebuilds the tree every cycle, but ~75-80% of its bytes
        // are the prior generation's (measured on tenant1: two adjacent
        // publisher trees, 12 GB each, 15 GB deduplicated).
        fn successor(
            signed: &mut SignedGenerationBundleManifest,
            pointer: &mut PublishedGenerationBundlePointer,
            objects: &mut BTreeMap<String, (Vec<u8>, String)>,
        ) {
            signed.manifest.generation_id = "lake-42-bbbbbbbbbbbbbbbbbbbbbbbb".into();
            resign_inventory(signed, pointer, objects);
        }

        // ---- legacy archive shape: the successor cannot be staged ----
        let root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget {
            generations_root: root.path().into(),
            max_local_bytes: VOLUME,
            reserve_bytes: RESERVE,
        };
        let (mut signed, mut pointer, mut objects) = legacy;
        let first = root.path().join("snapshot-first");
        inventory_snapshot(&first, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &first.join("derivatives"), &budget, KEY, None).await.unwrap();
        successor(&mut signed, &mut pointer, &mut objects);
        let second = root.path().join("snapshot-second");
        inventory_snapshot(&second, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects) };
        let error = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None)
            .await
            .expect_err("a legacy bundle stages the whole successor beside the active generation");
        let legacy = error
            .downcast::<GenerationBundleCapacityError>()
            .expect("the failure is the capacity fence");
        assert!(!legacy.content_addressed, "{legacy}");
        assert!(legacy.staging_allocated_bytes > GENERATION, "{legacy}");
        assert!(legacy.peak_allocated_bytes > VOLUME, "{legacy}");

        // ---- content-addressed shape: same generation, same volume ----
        let root = tempfile::tempdir().unwrap();
        let budget = GenerationBundleDiskBudget {
            generations_root: root.path().into(),
            max_local_bytes: VOLUME,
            reserve_bytes: RESERVE,
        };
        let (mut signed, mut pointer, mut objects) = incremental;
        let first = root.path().join("snapshot-first");
        inventory_snapshot(&first, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        hydrate_generation_bundle_proven(&reader, &pointer, &expected, &first.join("derivatives"), &budget, KEY, None).await.unwrap();
        successor(&mut signed, &mut pointer, &mut objects);
        let second = root.path().join("snapshot-second");
        inventory_snapshot(&second, &signed, &objects);
        let reader = MemoryReader { objects: Mutex::new(objects) };
        let hydrated = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None)
            .await
            .expect("the successor reuses the resident generation instead of copying it");
        let disk = hydrated.disk.expect("a budgeted hydration reports its accounting");
        assert!(disk.current_allocated_bytes > VOLUME / 2, "{disk:?}");
        assert!(disk.reused_bytes > GENERATION, "{disk:?}");
        assert!(disk.peak_allocated_bytes <= VOLUME, "{disk:?}");
        // The whole point: staging is the delta, not a second generation.
        assert!(
            disk.staging_allocated_bytes * 3 < legacy.staging_allocated_bytes,
            "{disk:?} vs legacy staging {}",
            legacy.staging_allocated_bytes
        );
        // Both generations serve from the same bytes: the content store holds
        // one copy, and the successor's tree entries are links into it.
        assert!(allocated_tree_bytes(root.path()).unwrap() < GENERATION * 3 / 2);
    }

    #[tokio::test]
    async fn received_digests_prove_trees_manifests_and_resume_with_signed_fallback() {
        use crate::generation_proof::{Body, Reference, FILE_NAME};
        use std::os::unix::fs::PermissionsExt;
        let (signed, admission, pointer, objects) = fixture();
        let source = signed.manifest.artifacts.iter().find(|a| a.role == "source-object-stamps").unwrap();
        let stamps = single_archive_member(source, &objects[&source.key].0).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("snapshot/data/data")).unwrap();
        std::fs::write(root.path().join("snapshot/object-stamps.json"), stamps).unwrap();
        std::fs::write(root.path().join("snapshot/data/data/part-42.parquet"), vec![10;4096]).unwrap();
        let reader = MemoryReader { objects: Mutex::new(objects) };
        let target = root.path().join("derivatives-v1-fixture");
        let budget = GenerationBundleDiskBudget { generations_root: root.path().to_path_buf(), max_local_bytes: 1024*1024*1024, reserve_bytes: 0 };
        let key = crate::generation_proof::tests::KEY;
        hydrate_generation_bundle_proven(&reader, &pointer, &admission, &target, &budget, key, None).await.unwrap();
        let reference = Reference { path: target.join(FILE_NAME), identity: proof_identity(&pointer, &signed) };
        let proof = Body::load(&reference, key).unwrap();
        for directory in ["keyword-sidecar/index", "fragment-sidecar/index", "count-rollup"] {
            let path = target.join(directory);
            let expected = crate::config::index_directory_sha256(&path, "fixture").unwrap();
            assert_eq!(proof.tree_digest(&path), Some((expected.0.as_str(), expected.1)));
        }
        for file in inventory_admitted_files(&target).unwrap() {
            assert_eq!(proof.file_digest(&target.join(file.relative_path)), Some(file.sha256.as_str()));
        }
        // A valid retained proof needs only the small signed manifest fetch.
        let mut archived = reader.objects.lock().unwrap().clone();
        reader.objects.lock().unwrap().retain(|key, _| key == &pointer.manifest_key);
        hydrate_generation_bundle_proven(&reader, &pointer, &admission, &target, &budget, key, None).await.unwrap();
        *reader.objects.lock().unwrap() = std::mem::take(&mut archived);
        // No proof is a full signed verification, followed by re-issuance.
        std::fs::remove_file(&reference.path).unwrap();
        hydrate_generation_bundle_proven(&reader, &pointer, &admission, &target, &budget, key, None).await.unwrap();
        Body::load(&reference, key).unwrap();
        let damaged = target.join("identity-snapshot/by-ip.parquet");
        std::fs::set_permissions(&damaged, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&damaged, b"tampered payload").unwrap();
        assert!(hydrate_generation_bundle_proven(&reader, &pointer, &admission, &target, &budget, key, None).await.is_err());
    }

    struct FragmentedReader {
        memory: MemoryReader,
        active: std::sync::atomic::AtomicUsize,
        maximum: std::sync::atomic::AtomicUsize,
        reject_at_eof: bool,
    }
    impl GenerationBundleObjectReader for FragmentedReader {
        fn read_exact<'a>(&'a self, key: &'a str, bytes: u64, sha: &'a str, etag: &'a str) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
            self.memory.read_exact(key, bytes, sha, etag)
        }
        fn read_to<'a>(&'a self, artifact: &'a GenerationBundleArtifact, sender: tokio::sync::mpsc::Sender<bytes::Bytes>) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                use std::sync::atomic::Ordering::SeqCst;
                struct Active<'a>(&'a std::sync::atomic::AtomicUsize);
                impl Drop for Active<'_> { fn drop(&mut self) { self.0.fetch_sub(1, SeqCst); } }
                let count = self.active.fetch_add(1, SeqCst) + 1;
                let _active = Active(&self.active);
                self.maximum.fetch_max(count, SeqCst);
                let bytes = self.memory.read_exact(&artifact.key, artifact.bytes, &artifact.sha256, &artifact.etag).await?;
                for byte in bytes {
                    sender.send(bytes::Bytes::from(vec![byte])).await.context("receiver dropped")?;
                }
                if self.reject_at_eof { bail!("simulated final provider identity mismatch"); }
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn single_get_streams_stop_on_failure_and_never_admit_partial_candidates() {
        use std::sync::atomic::Ordering::SeqCst;
        for reject_at_eof in [false, true] {
            let (_, admission, pointer, objects) = fixture();
            let reader = FragmentedReader { memory: MemoryReader { objects: Mutex::new(objects) }, active: Default::default(), maximum: Default::default(), reject_at_eof };
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir(root.path().join("snapshot")).unwrap();
            std::fs::write(root.path().join("snapshot/object-stamps.json"), b"{}").unwrap();
            let target = root.path().join("derivatives");
            let result = hydrate_generation_bundle(&reader, &pointer, &admission, &target).await;
            assert_eq!(result.is_err(), reject_at_eof);
            assert_eq!(target.exists(), !reject_at_eof);
            assert_eq!(reader.active.load(SeqCst), 0);
            assert_eq!(reader.maximum.load(SeqCst), 1);
            assert!(std::fs::read_dir(root.path()).unwrap().all(|entry| !entry.unwrap().file_name().to_string_lossy().starts_with(".lake-derivatives-")));
        }
    }

    #[tokio::test]
    #[ignore = "offline NAN-2469 native incremental acquisition benchmark"]
    async fn nan2469_inventory_acquisition_benchmark() {
        use crate::generation_proof::{Body, Reference, FILE_NAME, tests::KEY};
        let runtime = crate::native::NativeChdb::load_verified(std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(), &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap()).unwrap();
        std::mem::forget(runtime.clone()); let connection = runtime.connect(&[]).unwrap();
        let root = tempfile::tempdir().unwrap();
        let schema: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/nan2469-live-tail-read-schema.json")).unwrap();
        let input = root.path().join("event.jsonl");
        std::fs::write(&input, serde_json::json!({"time":"2026-08-10 12:00:00", "message":"admission proof fixture ".repeat(160), "user":{"name":"jsmith"}, "src_endpoint":{"ip":"8.8.8.8"}}).to_string()).unwrap();
        let (mut signed, expected, mut pointer, mut objects) = inventory_fixture();
        for (index, artifact) in signed.manifest.artifacts.iter_mut().filter(|a| a.members[0].relative_path.ends_with(".parquet")).enumerate() {
            let path = root.path().join(format!("part-{index}.parquet")); let part = index.to_string();
            connection.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT e.* REPLACE(concat(message, toString(n.number), {part:String}) AS message) FROM file({input:String}, JSONEachRow, {schema:String}) AS e CROSS JOIN numbers(5000) AS n SETTINGS output_format_parquet_compression_method='none'", "JSONEachRow",
                &[("output", path.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", schema["read_schema"].as_str().unwrap()), ("part", &part)]).unwrap();
            let bytes = std::fs::read(&path).unwrap(); let sha = crate::generation_proof::sha(&bytes);
            artifact.bytes = bytes.len() as u64; artifact.unpacked_bytes = artifact.bytes; artifact.sha256 = sha.clone();
            artifact.members[0].bytes = artifact.bytes; artifact.members[0].total_bytes = artifact.bytes; artifact.members[0].sha256 = sha.clone();
            artifact.key = format!("{}/{}/v1/sha256/{}", expected.tenant_id, artifact.family.key_token(), sha);
            let member = signed.manifest.derivative_inventory.as_mut().unwrap().iter_mut().find(|m| m.relative_path == artifact.members[0].relative_path).unwrap();
            member.bytes = artifact.bytes; member.sha256 = sha.clone(); member.content_id = format!("sha256:{sha}");
            objects.insert(artifact.key.clone(), (bytes, artifact.etag.clone()));
        }
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        let generations = root.path().join("generations"); std::fs::create_dir(&generations).unwrap();
        let budget = GenerationBundleDiskBudget { generations_root: generations.clone(), max_local_bytes: 25*1024*1024*1024, reserve_bytes: 0 };
        let reader = MemoryReader { objects: Mutex::new(objects.clone()) };
        let first = generations.join("snapshot-first"); inventory_snapshot(&first, &signed, &objects);
        let started = Instant::now();
        let cold = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &first.join("derivatives"), &budget, KEY, None).await.unwrap();
        let cold_seconds = started.elapsed().as_secs_f64();
        let size = cold.bytes;
        let retained_bytes = allocated_tree_bytes(&generations).unwrap();
        for artifact in signed.manifest.artifacts.iter().filter(|a| a.role != "source-object-stamps") { reader.objects.lock().unwrap().remove(&artifact.key); }
        // New generation, all derivative bytes unchanged: no data keys available.
        signed.manifest.generation_id = "lake-42-bbbbbbbbbbbbbbbbbbbbbbbb".into();
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        reader.objects.lock().unwrap().insert(pointer.manifest_key.clone(), objects[&pointer.manifest_key].clone());
        let second = generations.join("snapshot-second"); inventory_snapshot(&second, &signed, &objects);
        let started = Instant::now();
        let warm = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &second.join("derivatives"), &budget, KEY, None).await.unwrap();
        let warm_seconds = started.elapsed().as_secs_f64();
        let peak = allocated_tree_bytes(&generations).unwrap();
        let started = Instant::now();
        Body::load(&Reference { path: second.join("derivatives").join(FILE_NAME), identity: proof_identity(&pointer, &signed) }, KEY).unwrap();
        let boot_seconds = started.elapsed().as_secs_f64();
        assert!((cold.payload_hashed_bytes as f64 / size as f64) <= 1.1);
        assert!(peak < retained_bytes + 1024*1024);
        let changed_path = root.path().join("changed.parquet");
        connection.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT e.* REPLACE(concat(message, toString(n.number), 'changed') AS message) FROM file({input:String}, JSONEachRow, {schema:String}) AS e CROSS JOIN numbers(5000) AS n SETTINGS output_format_parquet_compression_method='none'", "JSONEachRow",
            &[("output", changed_path.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", schema["read_schema"].as_str().unwrap())]).unwrap();
        let bytes = std::fs::read(changed_path).unwrap(); let changed_bytes = bytes.len() as u64;
        let digest = crate::generation_proof::sha(&bytes);
        let artifact = signed.manifest.artifacts.iter_mut().find(|a| a.members[0].relative_path == "entity-sidecar/object-0000.parquet").unwrap();
        artifact.sha256 = digest.clone(); artifact.bytes = changed_bytes; artifact.unpacked_bytes = changed_bytes;
        artifact.members[0].sha256 = digest.clone(); artifact.members[0].bytes = changed_bytes; artifact.members[0].total_bytes = changed_bytes;
        artifact.key = format!("{}/retained-generation/v1/sha256/{digest}", expected.tenant_id);
        let member = signed.manifest.derivative_inventory.as_mut().unwrap().iter_mut().find(|m| m.relative_path == artifact.members[0].relative_path).unwrap();
        member.sha256 = digest.clone(); member.content_id = format!("sha256:{digest}"); member.bytes = changed_bytes;
        reader.objects.lock().unwrap().insert(artifact.key.clone(), (bytes, artifact.etag.clone()));
        signed.manifest.generation_id = "lake-42-cccccccccccccccccccccccc".into();
        resign_inventory(&mut signed, &mut pointer, &mut objects);
        reader.objects.lock().unwrap().insert(pointer.manifest_key.clone(), objects[&pointer.manifest_key].clone());
        let third = generations.join("snapshot-third"); inventory_snapshot(&third, &signed, &objects);
        let started = Instant::now();
        let changed = hydrate_generation_bundle_proven(&reader, &pointer, &expected, &third.join("derivatives"), &budget, KEY, None).await.unwrap();
        let changed_seconds = started.elapsed().as_secs_f64(); let changed_peak = allocated_tree_bytes(&generations).unwrap();
        assert!(changed.payload_hashed_bytes < changed_bytes + 1024*1024);
        assert!(changed_peak < retained_bytes + changed_bytes + 1024*1024);
        println!("NAN2532_INVENTORY_BENCH {}", serde_json::json!({"fixture":"live-tail read schema", "generation_bytes":size,
            "cold_payload_hashed_bytes":cold.payload_hashed_bytes, "cold_bytes_hashed_per_GB_admitted":cold.payload_hashed_bytes as f64 / size as f64 * 1e9,
            "warm_payload_hashed_bytes":warm.payload_hashed_bytes, "warm_bytes_hashed_per_GB_admitted":warm.payload_hashed_bytes as f64 / size as f64 * 1e9,
            "retained_local_bytes":retained_bytes, "peak_local_bytes":peak, "peak_vs_generation":peak as f64 / size as f64,
            "cold_seconds":cold_seconds, "warm_seconds":warm_seconds, "retained_proof_boot_seconds":boot_seconds,
            "changed_bytes":changed_bytes, "changed_payload_hashed_bytes":changed.payload_hashed_bytes,
            "changed_bytes_hashed_per_GB_admitted":changed.payload_hashed_bytes as f64 / changed.bytes as f64 * 1e9,
            "changed_peak_local_bytes":changed_peak, "changed_peak_vs_generation":changed_peak as f64 / changed.bytes as f64, "changed_seconds":changed_seconds}));
    }

    /// Offline fixture benchmark; requires the same native chDB library as
    /// generation_proof::benchmark. Counts payload SHA input, not metadata MACs.
    #[test]
    #[ignore = "offline native NAN-2469 acquisition benchmark"]
    fn nan2469_streaming_acquisition_benchmark() {
        use crate::native::NativeChdb;
        let runtime = NativeChdb::load_verified(std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(), &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap()).unwrap();
        std::mem::forget(runtime.clone());
        let connection = runtime.connect(&[]).unwrap();
        let root = tempfile::tempdir().unwrap();
        let schema: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/nan2469-live-tail-read-schema.json")).unwrap();
        let schema = schema["read_schema"].as_str().unwrap();
        let input = root.path().join("event.jsonl");
        std::fs::write(&input, serde_json::json!({"time":"2026-08-10 12:00:00", "message":"admission proof fixture ".repeat(160), "user":{"name":"jsmith"}, "src_endpoint":{"ip":"8.8.8.8"}}).to_string()).unwrap();
        let fixture_path = root.path().join("fixture.parquet");
        connection.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT e.* REPLACE(concat(message, toString(n.number)) AS message) FROM file({input:String}, JSONEachRow, {schema:String}) AS e CROSS JOIN numbers(5000) AS n SETTINGS output_format_parquet_compression_method='none'", "JSONEachRow",
            &[("output", fixture_path.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", schema)]).unwrap();
        let payload = std::fs::read(&fixture_path).unwrap();
        let (signed, _, _, _) = fixture();
        let mut artifact = signed.manifest.artifacts[0].clone();
        artifact.members.clear();
        let mut archive = GENERATION_BUNDLE_ARCHIVE_MAGIC.to_vec();
        archive.extend_from_slice(&4_u32.to_be_bytes());
        for part in 0..4 {
            let member = GenerationBundleArtifactMember {
                relative_path: format!("entity-sidecar/part-{part}.parquet"), offset: 0,
                total_bytes: payload.len() as u64, bytes: payload.len() as u64,
                sha256: crate::generation_proof::sha(&payload),
            };
            archive.extend(StreamingArchive::member_header(&member).unwrap());
            archive.extend_from_slice(&payload);
            artifact.members.push(member);
        }
        artifact.bytes = archive.len() as u64;
        artifact.unpacked_bytes = payload.len() as u64 * 4;
        artifact.sha256 = crate::generation_proof::sha(&archive);
        let mut results = Vec::new();
        for streaming in [false, true] {
            let generations = root.path().join(if streaming { "after" } else { "before" });
            let retained = generations.join("retained");
            let candidate = generations.join("candidate");
            std::fs::create_dir_all(&retained).unwrap();
            std::fs::create_dir(&candidate).unwrap();
            for member in &artifact.members {
                let path = retained.join(&member.relative_path);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, &payload).unwrap();
            }
            let current_bytes = allocated_tree_bytes(&generations).unwrap();
            let mut admission = AdmissionDigests { trees_enabled: true, ..Default::default() };
            let started = Instant::now();
            if streaming {
                let mut archive_hash = Sha256::new();
                let mut extractor = StreamingArchive::new(&candidate, &artifact).unwrap();
                for chunk in archive.chunks(256 * 1024) {
                    archive_hash.update(chunk);
                    extractor.receive(chunk, &mut admission, &candidate, &candidate).unwrap();
                }
                extractor.finish().unwrap();
                assert_eq!(hex::encode(archive_hash.finalize()), artifact.sha256);
            } else {
                assert_eq!(crate::generation_proof::sha(&archive), artifact.sha256);
                extract_archive_recording(&candidate, &artifact, &archive, Some((&mut admission, &candidate, &candidate))).unwrap();
            }
            let elapsed = started.elapsed().as_secs_f64();
            let peak_bytes = allocated_tree_bytes(&generations).unwrap();
            let hashed_bytes = artifact.bytes + admission.hashed_bytes;
            results.push(serde_json::json!({"streaming":streaming, "admitted_bytes":artifact.unpacked_bytes,
                "payload_hashed_bytes":hashed_bytes, "bytes_hashed_per_GB_admitted":hashed_bytes as f64 / artifact.unpacked_bytes as f64 * 1_000_000_000.0,
                "current_allocated_bytes":current_bytes, "peak_local_bytes":peak_bytes,
                "peak_vs_generation":peak_bytes as f64 / artifact.unpacked_bytes as f64, "seconds":elapsed,
                "archive_payload_buffer_bound":if streaming { 1 * 8 * 256 * 1024 } else { archive.len() }}));
        }
        println!("NAN2532_BENCH {}", serde_json::to_string(&results).unwrap());
    }

    #[test]
    fn signed_inventory_is_not_limited_to_twenty_thousand_members() {
        let (mut signed, _, _, _) = fixture();
        let artifact = signed.manifest.artifacts.iter_mut().find(|a| a.members[0].relative_path == "entity-sidecar/object-0000.parquet").unwrap();
        let original = artifact.members[0].clone();
        for index in 1..=20_000 {
            let mut member = original.clone();
            member.relative_path = format!("entity-sidecar/object-{index:08}.parquet");
            artifact.unpacked_bytes += member.bytes;
            artifact.bytes += 42 + member.relative_path.len() as u64 + member.bytes;
            artifact.members.push(member);
        }
        artifact.members.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        signed.manifest.validate_structure().unwrap();
    }

    #[test]
    fn streaming_archive_accepts_every_header_and_payload_split() {
        let (signed, _, _, objects) = fixture();
        for artifact in &signed.manifest.artifacts {
            let bytes = &objects[&artifact.key].0;
            for width in [1, 2, 7, 31, 256, 4096] {
                let root = tempfile::tempdir().unwrap();
                let candidate = root.path().join("candidate");
                std::fs::create_dir(&candidate).unwrap();
                let target = root.path().join("installed");
                let snapshot = root.path().join("snapshot");
                let mut admission = AdmissionDigests { trees_enabled: true, ..Default::default() };
                let mut extractor = StreamingArchive::new(&candidate, artifact).unwrap();
                for part in bytes.chunks(width) {
                    extractor.receive(part, &mut admission, &target, &snapshot).unwrap();
                }
                extractor.finish().unwrap();
                assert!(admission.partial.is_empty());
                for (path, (digest, length)) in admission.files {
                    assert_eq!(file_sha256_and_bytes(&candidate.join(path)).unwrap(), (digest, length));
                }
            }
        }
    }

    #[test]
    fn streaming_archive_rejects_truncation_tamper_trailing_bytes_and_wrong_offset() {
        let (signed, _, _, objects) = fixture();
        let artifact = signed.manifest.artifacts.iter().find(|a| a.members[0].relative_path.ends_with(".parquet")).unwrap();
        let original = &objects[&artifact.key].0;
        for cut in 0..original.len() {
            let root = tempfile::tempdir().unwrap();
            let mut admission = AdmissionDigests::default();
            let mut extractor = StreamingArchive::new(root.path(), artifact).unwrap();
            extractor.receive(&original[..cut], &mut admission, root.path(), root.path()).unwrap();
            assert!(extractor.finish().is_err(), "accepted truncation at {cut}");
        }
        for index in 0..original.len() {
            let root = tempfile::tempdir().unwrap();
            let mut corrupt = original.clone(); corrupt[index] ^= 1;
            let mut admission = AdmissionDigests::default();
            let mut extractor = StreamingArchive::new(root.path(), artifact).unwrap();
            assert!(extractor.receive(&corrupt, &mut admission, root.path(), root.path()).is_err(), "accepted corruption at {index}");
        }
        let root = tempfile::tempdir().unwrap();
        let mut trailing = original.clone(); trailing.push(0);
        let mut admission = AdmissionDigests::default();
        assert!(StreamingArchive::new(root.path(), artifact).unwrap().receive(&trailing, &mut admission, root.path(), root.path()).is_err());
        let mut wrong = artifact.clone(); wrong.members[0].offset = 1; wrong.members[0].total_bytes += 1;
        assert!(StreamingArchive::new(root.path(), &wrong).unwrap().receive(original, &mut admission, root.path(), root.path()).is_err());
    }

    #[test]
    fn streaming_empty_member_and_split_logical_file_preserve_proof_digests() {
        let root = tempfile::tempdir().unwrap();
        let (signed, _, _, _) = fixture();
        let mut artifact = signed.manifest.artifacts[0].clone();
        let path = "prevalence-snapshot-v2/1h/slatedb/wal/00000000000000000001.sst";
        let mut admission = AdmissionDigests::default();
        for (name, offset, total, payload) in [(path, 0, 0, b"".as_slice()), ("uid-ledger/window.uids", 0, 10, b"alpha"), ("uid-ledger/window.uids", 5, 10, b"bravo")] {
            artifact.members = vec![GenerationBundleArtifactMember { relative_path: name.into(), offset, total_bytes: total, bytes: payload.len() as u64, sha256: crate::generation_proof::sha(payload) }];
            let mut bytes = GENERATION_BUNDLE_ARCHIVE_MAGIC.to_vec();
            bytes.extend_from_slice(&1_u32.to_be_bytes());
            bytes.extend(StreamingArchive::member_header(&artifact.members[0]).unwrap());
            bytes.extend_from_slice(payload);
            artifact.bytes = bytes.len() as u64;
            let mut extractor = StreamingArchive::new(root.path(), &artifact).unwrap();
            for chunk in bytes.chunks(1) { extractor.receive(chunk, &mut admission, root.path(), root.path()).unwrap(); }
            extractor.finish().unwrap();
        }
        assert_eq!(admission.files["uid-ledger/window.uids"], (crate::generation_proof::sha(b"alphabravo"), 10));
        assert_eq!(admission.files[path], (crate::generation_proof::sha(b""), 0));
        assert!(admission.partial.is_empty());
    }

    #[test]
    fn bundle_identity_is_field_boundary_safe_and_runtime_independent() {
        let tenant = Uuid::parse_str("23610000-0000-4000-8000-0000000000aa").unwrap();
        let table = Uuid::parse_str("23610000-0000-4000-8000-0000000000bb").unwrap();
        let digest = "a".repeat(64);
        let first = bundle_identity(&GenerationBundleIdentity {
            tenant_id: tenant,
            table_uuid: table,
            snapshot_id: 42,
            manifest_list_sha256: &digest,
            derivative_contract_sha256: &"b".repeat(64),
            hmac_key_sha256: &"c".repeat(64),
            read_schema_sha256: &"d".repeat(64),
        })
        .unwrap();
        let second = bundle_identity(&GenerationBundleIdentity {
            tenant_id: tenant,
            table_uuid: table,
            snapshot_id: 43,
            manifest_list_sha256: &digest,
            derivative_contract_sha256: &"b".repeat(64),
            hmac_key_sha256: &"c".repeat(64),
            read_schema_sha256: &"d".repeat(64),
        })
        .unwrap();
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn published_snapshot_pin_survives_new_commits_and_rejects_tampered_inventory() {
        check_published_snapshot_pin(false).await;
    }

    #[tokio::test]
    async fn compressed_published_snapshot_pin_survives_new_commits() {
        check_published_snapshot_pin(true).await;
    }

    async fn check_published_snapshot_pin(compressed: bool) {
        use iceberg::spec::{
            NestedField, Operation, PrimitiveType, Schema, Snapshot, Summary, TableMetadataBuilder,
            Type,
        };
        let (signed, mut admission, pointer, objects) = fixture_with_metadata_codec(compressed);
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        let metadata_location = published_metadata_location(&reader, &pointer, &admission)
            .await
            .unwrap();
        let schema = Schema::builder()
            .with_fields(vec![std::sync::Arc::new(NestedField::required(
                1,
                "time",
                Type::Primitive(PrimitiveType::Long),
            ))])
            .build()
            .unwrap();
        let creation = iceberg::TableCreation::builder()
            .name("events".to_string())
            .location(admission.table_location.clone())
            .schema(schema)
            .build();
        let mut metadata = TableMetadataBuilder::from_table_creation(creation)
            .unwrap()
            .assign_uuid(admission.table_uuid)
            .build()
            .unwrap()
            .metadata;
        let mut published = None;
        for id in 42..=47 {
            let snapshot = Snapshot::builder()
                .with_snapshot_id(id)
                .with_parent_snapshot_id(metadata.current_snapshot_id())
                .with_sequence_number(id - 41)
                .with_timestamp_ms(chrono::Utc::now().timestamp_millis() + id)
                .with_manifest_list(format!(
                    "{}/metadata/snap-{id}-1-91c52ccb-328e-4820-8ee8-e7cf32990af3.avro",
                    admission.table_location
                ))
                .with_summary(Summary {
                    operation: Operation::Append,
                    additional_properties: Default::default(),
                })
                .with_schema_id(metadata.current_schema_id())
                .build();
            metadata = TableMetadataBuilder::new_from_metadata(metadata, None)
                .set_branch_snapshot(snapshot, "main")
                .unwrap()
                .build()
                .unwrap()
                .metadata;
            if id == 42 {
                published = Some(metadata.clone());
            }
        }
        let file_io = iceberg::io::FileIO::new_with_memory();
        let published_bytes = serde_json::to_vec(&published.unwrap()).unwrap();
        let metadata_bytes = if compressed {
            use std::io::Write;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&published_bytes).unwrap();
            encoder.finish().unwrap()
        } else {
            published_bytes
        };
        file_io
            .new_output(&metadata_location)
            .unwrap()
            .write(metadata_bytes.into())
            .await
            .unwrap();
        let head_location = format!("{}/metadata/v47.metadata.json", admission.table_location);
        let current = iceberg::table::Table::builder()
            .identifier(crate::iceberg::table_ident("nano.events").unwrap())
            .metadata(metadata)
            .metadata_location(head_location.clone())
            .file_io(file_io)
            .runtime(iceberg::Runtime::current())
            .build()
            .unwrap();
        let pinned = crate::generation::pinned_snapshot_table(
            &current,
            &admission.table_location,
            42,
            &metadata_location,
        )
        .await
        .unwrap();
        assert_eq!(pinned.metadata().current_snapshot_id(), Some(42));
        assert_eq!(current.metadata().current_snapshot_id(), Some(47));
        assert!(crate::generation::pinned_snapshot_table(
            &current,
            &admission.table_location,
            47,
            &metadata_location
        )
        .await
        .is_err());
        let source = signed
            .manifest
            .artifacts
            .iter()
            .find(|a| a.role == "source-object-stamps")
            .unwrap();
        let archive = reader
            .read_exact(&source.key, source.bytes, &source.sha256, &source.etag)
            .await
            .unwrap();
        let mut stamps: ObjectStampManifest =
            serde_json::from_slice(single_archive_member(source, &archive).unwrap()).unwrap();
        // These are the full-file bytes bound by identity/count/prevalence activation.
        let publisher_stamp_sha =
            hex::encode(Sha256::digest(serde_json::to_vec_pretty(&stamps).unwrap()));
        stamps.metadata_location = head_location;
        assert_ne!(
            publisher_stamp_sha,
            hex::encode(Sha256::digest(serde_json::to_vec_pretty(&stamps).unwrap()))
        );
        stamps.metadata_location = pinned.metadata_location_result().unwrap().to_string();
        assert_eq!(
            publisher_stamp_sha,
            hex::encode(Sha256::digest(serde_json::to_vec_pretty(&stamps).unwrap()))
        );
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("snapshot")).unwrap();
        std::fs::write(
            root.path().join("snapshot/object-stamps.json"),
            serde_json::to_vec_pretty(&stamps).unwrap(),
        )
        .unwrap();
        admission.object_stamp_manifest_sha256 =
            object_stamp_manifest_sha256(&GenerationBundleObjectStampManifest::from(&stamps))
                .unwrap();
        hydrate_generation_bundle(
            &reader,
            &pointer,
            &admission,
            &root.path().join("derivatives"),
        )
        .await
        .unwrap();
        stamps.objects[0].sha256 = "f".repeat(64);
        admission.object_stamp_manifest_sha256 =
            object_stamp_manifest_sha256(&GenerationBundleObjectStampManifest::from(&stamps))
                .unwrap();
        assert!(hydrate_generation_bundle(
            &reader,
            &pointer,
            &admission,
            &root.path().join("tampered")
        )
        .await
        .is_err());
        let mut crossed = admission.clone();
        crossed.table_uuid = Uuid::new_v4();
        assert!(published_metadata_location(&reader, &pointer, &crossed)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn signed_bundle_hydrates_atomically_after_every_fence() {
        let (_signed, admission, pointer, objects) = fixture();
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        let root = tempfile::tempdir().unwrap();
        let snapshot = root.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();
        std::fs::write(snapshot.join("object-stamps.json"), b"{}").unwrap();
        let target = root.path().join("derivatives-v1-test");
        let result = hydrate_generation_bundle_with_budget(
            &reader,
            &pointer,
            &admission,
            &target,
            &GenerationBundleDiskBudget {
                generations_root: root.path().to_path_buf(),
                max_local_bytes: u64::MAX,
                reserve_bytes: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(result.artifacts, 13);
        assert!(result.disk.as_ref().unwrap().staging_allocated_bytes > result.bytes);
        assert!(!target.join("bundle-metadata").exists());
        assert!(target.join("entity-sidecar/manifest.json").is_file());
        assert!(target
            .join("prevalence-snapshot-v2/manifest.json")
            .is_file());
        assert!(target.join(GENERATION_BUNDLE_ADMISSION_RECEIPT).is_file());
        let entity: serde_json::Value = serde_json::from_slice(
            &std::fs::read(target.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(entity["input_root"], snapshot.to_str().unwrap());
        let prevalence: serde_json::Value = serde_json::from_slice(
            &std::fs::read(target.join("prevalence-snapshot-v2/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            prevalence["windows"][0]["scan_file"],
            target
                .join("prevalence-snapshot-v2/7d/snapshot.parquet")
                .to_str()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn required_restart_rejects_unproven_or_changed_local_derivatives() {
        let (_signed, admission, pointer, objects) = fixture();
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        let root = tempfile::tempdir().unwrap();
        let snapshot = root.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();
        std::fs::write(snapshot.join("object-stamps.json"), b"{}").unwrap();
        let target = root.path().join("derivatives-v1-test");
        let budget = GenerationBundleDiskBudget {
            generations_root: root.path().to_path_buf(),
            max_local_bytes: u64::MAX,
            reserve_bytes: 0,
        };

        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("legacy-partial"), b"not bundle admitted").unwrap();
        let error =
            hydrate_generation_bundle_with_budget(&reader, &pointer, &admission, &target, &budget)
                .await
                .unwrap_err();
        assert!(format!("{error:#}").contains("admission receipt"));

        std::fs::remove_dir_all(&target).unwrap();
        hydrate_generation_bundle_with_budget(&reader, &pointer, &admission, &target, &budget)
            .await
            .unwrap();
        // Simulate a new reader/process with only the signed manifest online:
        // a persistent admitted tree must issue ZERO artifact GETs on restart.
        reader.objects.lock().unwrap().retain(|key, _| key == &pointer.manifest_key);
        let restart =
            hydrate_generation_bundle_with_budget(&reader, &pointer, &admission, &target, &budget)
                .await
                .unwrap();
        assert_eq!(restart.disk.unwrap().staging_allocated_bytes, 0);

        std::fs::write(
            target.join("entity-sidecar/object-0000.parquet"),
            b"locally changed",
        )
        .unwrap();
        let error =
            hydrate_generation_bundle_with_budget(&reader, &pointer, &admission, &target, &budget)
                .await
                .unwrap_err();
        assert!(format!("{error:#}").contains("differs from its exact signed bundle"));
    }

    #[tokio::test]
    async fn source_preflight_reclaims_before_download_and_reports_remaining_shortfall() {
        let (signed, admission, pointer, mut objects) = fixture();
        // An accidental derivative download fails: only metadata is available.
        objects.retain(|key, _| {
            key == &pointer.manifest_key
                || signed
                    .manifest
                    .artifacts
                    .iter()
                    .any(|a| a.role == "source-object-stamps" && &a.key == key)
        });
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        let root = tempfile::tempdir().unwrap();
        let candidate = root.path().join("candidate");
        std::fs::create_dir(&candidate).unwrap();
        let target = candidate.join("derivatives");
        let obsolete = root.path().join("superseded");
        std::fs::write(&obsolete, vec![7_u8; 4 * 1024 * 1024]).unwrap();
        let mut budget = GenerationBundleDiskBudget {
            generations_root: root.path().to_path_buf(),
            max_local_bytes: 128 * 1024 * 1024,
            reserve_bytes: 1024 * 1024,
        };
        let before =
            preflight_generation_bundle(&reader, &pointer, &admission, &target, &budget, || {
                panic!("ample capacity must not prune")
            })
            .await
            .unwrap();
        budget.max_local_bytes = before.peak_allocated_bytes - 1024 * 1024;
        let after =
            preflight_generation_bundle(&reader, &pointer, &admission, &target, &budget, || {
                std::fs::remove_file(&obsolete)?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(after.peak_allocated_bytes <= budget.max_local_bytes);
        assert!(!obsolete.exists());
        assert!(!candidate.join("snapshot").exists());
        assert!(!target.exists());
        budget.max_local_bytes = after.peak_allocated_bytes - 1;
        let mut reclaimed = false;
        let error =
            preflight_generation_bundle(&reader, &pointer, &admission, &target, &budget, || {
                reclaimed = true;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(reclaimed);
        assert_eq!(
            error
                .downcast_ref::<GenerationBundleCapacityError>()
                .unwrap()
                .shortfall_bytes,
            1
        );
        assert!(error.to_string().contains("shortfall=1"));
    }

    #[tokio::test]
    async fn insufficient_declared_capacity_is_terminal_before_archive_download() {
        let (_signed, admission, pointer, objects) = fixture();
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        let root = tempfile::tempdir().unwrap();
        let snapshot = root.path().join("snapshot");
        std::fs::create_dir(&snapshot).unwrap();
        std::fs::write(snapshot.join("object-stamps.json"), b"{}").unwrap();
        let target = root.path().join("derivatives-v1-test");
        let error = hydrate_generation_bundle_with_budget(
            &reader,
            &pointer,
            &admission,
            &target,
            &GenerationBundleDiskBudget {
                generations_root: root.path().to_path_buf(),
                max_local_bytes: 1,
                reserve_bytes: 0,
            },
        )
        .await
        .unwrap_err();
        assert!(error
            .downcast_ref::<GenerationBundleCapacityError>()
            .is_some());
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn corruption_or_stale_floor_never_admits_a_partial_directory() {
        let (_signed, mut admission, pointer, mut objects) = fixture();
        objects.get_mut(&pointer.manifest_key).unwrap().0.push(b'!');
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("derivatives-v1-test");
        assert!(
            hydrate_generation_bundle(&reader, &pointer, &admission, &target)
                .await
                .is_err()
        );
        assert!(!target.exists());

        let (_signed, _old_admission, pointer, objects) = fixture();
        admission.irreversible_event_time_floor = "2026-08-02T00:00:00Z".parse().unwrap();
        let reader = MemoryReader {
            objects: Mutex::new(objects),
        };
        assert!(
            hydrate_generation_bundle(&reader, &pointer, &admission, &target)
                .await
                .is_err()
        );
        assert!(!target.exists());
    }

    #[test]
    fn wrong_tenant_or_signature_is_rejected_before_artifact_admission() {
        let (mut signed, admission, _, _) = fixture();
        signed.manifest.tenant_id =
            Uuid::parse_str("23610000-0000-4000-8000-0000000000cc").unwrap();
        assert!(signed.verify(&admission).is_err());

        let (mut signed, admission, _, _) = fixture();
        signed.signature.signature_base64 = BASE64_STANDARD.encode([0x44; 64]);
        assert!(signed.verify(&admission).is_err());

        let (signed, mut admission, _, _) = fixture();
        admission.object_stamp_manifest_sha256 = "b".repeat(64);
        assert!(signed.verify(&admission).is_err());
    }

    #[test]
    fn stamp_identity_ignores_moving_head_but_binds_snapshot_and_objects() {
        let mut stamps = GenerationBundleObjectStampManifest {
            metadata_location: "s3://bucket/table/metadata/00001.json".to_string(),
            snapshot_id: 42,
            table: "events".to_string(),
            objects: vec![GenerationBundleSourceObject {
                relative_path: "data/a.parquet".to_string(),
                source_uri: "s3://bucket/table/data/a.parquet".to_string(),
                version_id: "v1".to_string(),
                size_bytes: 10,
                sha256: "a".repeat(64),
            }],
        };
        let original = object_stamp_manifest_sha256(&stamps).unwrap();
        stamps.metadata_location = "s3://bucket/table/metadata/00002.json".to_string();
        assert_eq!(original, object_stamp_manifest_sha256(&stamps).unwrap());
        assert!(serde_json::to_string(&stamps)
            .unwrap()
            .contains("00002.json"));
        stamps.snapshot_id += 1;
        assert_ne!(original, object_stamp_manifest_sha256(&stamps).unwrap());
        stamps.snapshot_id -= 1;
        stamps.objects[0].sha256 = "b".repeat(64);
        assert_ne!(original, object_stamp_manifest_sha256(&stamps).unwrap());
    }

    #[test]
    fn old_bundle_contract_is_refused_before_admission() {
        let (mut signed, admission, _, _) = fixture();
        signed.manifest.schema_version = 2;
        signed.manifest.contract_version = "nano-lake-generation-bundle-v2".to_string();
        let error = signed.verify(&admission).unwrap_err();
        assert!(error
            .to_string()
            .starts_with("unsupported generation bundle contract/schema"));
    }

    #[test]
    fn admission_mismatch_preserves_outer_error_and_names_first_field() {
        let (signed, mut admission, _, _) = fixture();
        admission.manifest_list_sha256 = "a".repeat(64);
        admission.object_stamp_manifest_sha256 = "b".repeat(64);
        let error = signed.verify(&admission).unwrap_err();
        assert_eq!(
            error.to_string(),
            "generation bundle differs from its server-owned admission identity"
        );
        let detail = error.root_cause().to_string();
        assert!(detail.starts_with("manifest_list_sha256:"));
        assert!(detail.contains(&format!("expected {:?}", admission.manifest_list_sha256)));
        assert!(detail.contains(&format!(
            "actual {:?}",
            signed.manifest.manifest_list_sha256
        )));
        assert!(!detail.contains("object_stamp_manifest_sha256"));
    }

    #[test]
    fn logical_file_chunks_are_appended_only_at_the_signed_offset() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("uid-ledger/window.uids");
        write_candidate_file_chunk(&path, 0, 10, b"alpha").unwrap();
        assert!(write_candidate_file_chunk(&path, 4, 10, b"wrong").is_err());
        write_candidate_file_chunk(&path, 5, 10, b"bravo").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"alphabravo");
    }
    // NAN-2478: a real signed B bundle, A's server-owned admission identity.
    #[test]
    fn cross_tenant_isolation_generation_bundle_foreign_uuid_and_object_key_denied() {
        let (signed_b, admission_b, pointer_b, _) = fixture();
        signed_b.verify(&admission_b).expect("B positive control");
        let mut admission_a = admission_b.clone();
        admission_a.tenant_id = Uuid::from_u128(0xa);
        admission_a.table_location = format!("s3://nano-shared-r2-{}/warehouse/nano/events", admission_a.tenant_id);
        let denial = signed_b.verify(&admission_a).expect_err("A must reject B signed bundle");
        assert!(denial.to_string().contains("server-owned admission identity"), "{denial:#}");
        eprintln!("NAN2478 generation_bundle: tenant={} object_key={} denied={denial:#}", admission_a.tenant_id, pointer_b.manifest_key);
    }

}

/// Peak-memory measurement of portable-manifest rebasing (NAN-2559 follow-up).
/// The live entity sidecar manifest outgrew the 16 MiB metadata bound; the
/// bound exists because a manifest is rebased through `serde_json::Value`.
#[cfg(test)]
mod manifest_memory_tests {
    use super::*;
    use std::io::BufWriter;

    /// Write a manifest with the real entity-sidecar shape (derivative
    /// generation `build_entity` / `build_entity_object`): a sorted-key top
    /// level whose `objects` array carries per-object OCSF path inventories.
    /// Streamed to disk so generating it does not raise the measured peak.
    pub(super) fn write_entity_sidecar_shaped_manifest(path: &Path, target_bytes: u64) -> u64 {
        const PATHS: usize = 420;
        let names = (0..PATHS)
            .map(|i| format!("{}.{}_{i:03}", ["actor.process", "src_endpoint", "dst_endpoint", "metadata.product", "unmapped.event_data", "device.hw_info"][i % 6], ["name", "uid", "ip", "hostname", "cmd_line", "file.path", "port"][i % 7]))
            .collect::<Vec<_>>();
        let mut sorted = names.clone();
        sorted.sort();
        let mut out = BufWriter::new(File::create(path).unwrap());
        let head = format!(
            "{{\"build_seconds\":1.25,\"built_objects\":1,\"event_rows\":1,\"field_specs\":[{{\"name\":\"src_ip\",\"role\":\"ip\"}}],\"granularity\":\"exact\",\"hash_algorithm\":\"hmac-sha256\",\"index_bytes\":1,\"index_rows\":1,\"index_version\":2,\"input_root\":\"/var/lib/nano-lake/generations/build/snapshot\",\"key_id\":\"k1\",\"next_object_id\":1,\"normalization\":\"trim then lowercase\",\"normalization_version\":1,\"object_builds\":[],\"object_id_model\":\"stable\",\"object_stamp_manifest\":\"/var/lib/nano-lake/generations/build/snapshot/object-stamps.json\",\"objects\":["
        );
        out.write_all(head.as_bytes()).unwrap();
        let mut written = head.len() as u64;
        let mut id = 0_u64;
        while written < target_bytes {
            let mut object = String::with_capacity(64 * 1024);
            if id > 0 { object.push(','); }
            object.push_str("{\"available_paths\":[");
            for (i, name) in sorted.iter().enumerate() {
                if i > 0 { object.push(','); }
                object.push('"'); object.push_str(name); object.push('"');
            }
            object.push_str("],\"column_compressed_bytes\":{");
            for (i, name) in sorted.iter().enumerate() {
                if i > 0 { object.push(','); }
                object.push_str(&format!("\"{name}\":{}", 1000 + i as u64 * 37 + id));
            }
            object.push_str(&format!("}},\"event_object_bytes\":{},\"event_object_key\":\"s3://nano-lake/tenant1/ocsf/data/hour=2026-09-22-{id:06}/part-{id:08}.parquet\",\"event_object_version\":\"v{id}\",\"field_types\":{{", 1_000_000 + id));
            for (i, name) in sorted.iter().enumerate() {
                if i > 0 { object.push(','); }
                object.push_str(&format!("\"{name}\":\"{}\"", ["Utf8", "Int64", "Timestamp(Microsecond, Some(\\\"UTC\\\"))", "List(Utf8)"][i % 4]));
            }
            object.push_str(&format!("}},\"object_id\":{id},\"relative_path\":\"data/hour=2026-09-22-{id:06}/part-{id:08}.parquet\",\"row_group_ranges\":["));
            for g in 0..8_u64 {
                if g > 0 { object.push(','); }
                object.push_str(&format!("{{\"row_end\":{},\"row_group\":{g},\"row_start\":{}}}", (g + 1) * 65536, g * 65536));
            }
            object.push_str("],\"row_groups\":8,\"rows\":524288}");
            out.write_all(object.as_bytes()).unwrap();
            written += object.len() as u64;
            id += 1;
        }
        let tail = "],\"plaintext_values\":false,\"reused_objects\":0,\"source_bytes\":1,\"source_files\":1,\"source_uri_prefix\":null,\"tenant_id\":\"tenant1\",\"value_hash_bytes\":16}";
        out.write_all(tail.as_bytes()).unwrap();
        out.flush().unwrap();
        written + tail.len() as u64
    }

    fn proc_status_kib(field: &str) -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        status.lines().find_map(|line| line.strip_prefix(field))
            .map(|rest| rest.trim().trim_end_matches("kB").trim().parse::<u64>().unwrap())
            .unwrap()
    }

    /// Peak RSS growth of the CURRENT Value-based rebase (read, parse,
    /// rebase, re-serialize, keep the bytes -- exactly the admission site).
    fn measure_value_rebase(target_bytes: u64) -> (u64, u64) {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("manifest.json");
        let bytes = write_entity_sidecar_shaped_manifest(&path, target_bytes);
        let target = root.path().join("tree");
        let snapshot = root.path().join("snapshot");
        // Reset VmHWM to the current RSS (Linux clear_refs "5").
        std::fs::write("/proc/self/clear_refs", "5").unwrap();
        let baseline = proc_status_kib("VmRSS:");
        let replacement = {
            let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            rebase_manifest_value(&mut value, &target, &snapshot).unwrap();
            let mut out = serde_json::to_vec(&value).unwrap(); out.push(b'\n');
            out
        };
        let peak = proc_status_kib("VmHWM:");
        assert!(replacement.len() as u64 > target_bytes / 2);
        (bytes, (peak.saturating_sub(baseline)) * 1024)
    }

    /// Run alone: `cargo test --lib --features enterprise manifest_memory_tests
    /// -- --ignored --nocapture --test-threads 1`. Other concurrently running
    /// tests would pollute the process-wide high-water mark.
    #[test]
    #[ignore = "measurement; run alone with --test-threads 1"]
    fn measure_value_rebase_peak_memory() {
        for mib in [62_u64, 250] {
            let (bytes, peak) = measure_value_rebase(mib * 1024 * 1024);
            eprintln!(
                "value-rebase: manifest={bytes} bytes ({:.1} MiB) peak_rss_growth={peak} bytes ({:.1} MiB) ratio={:.2}x",
                bytes as f64 / 1048576.0, peak as f64 / 1048576.0, peak as f64 / bytes as f64
            );
        }
    }

    /// Verbatim copy of `rebase_manifest_value` as it stood before the
    /// streaming rebase: the oracle the streaming path must match byte for byte.
    fn legacy_rebase_manifest_value(
        value: &mut serde_json::Value,
        final_target: &Path,
        snapshot_root: &Path,
    ) -> Result<()> {
        match value {
            serde_json::Value::Object(object) => {
                for (name, value) in object {
                    if let Some(path) = value.as_str() {
                        let replacement = match name.as_str() {
                            "input_root" => Some(snapshot_root.to_path_buf()),
                            "object_stamp_manifest" => Some(snapshot_root.join("object-stamps.json")),
                            "path"
                            | "data_directory"
                            | "index_directory"
                            | "fragment_index_directory"
                            | "database_path"
                            | "scan_file"
                            | "part_file" => Some(rebase_derivative_path(path, final_target)?),
                            _ if Path::new(path).is_absolute() => {
                                bail!("portable derivative manifest contains an unknown absolute path")
                            }
                            _ => None,
                        };
                        if let Some(replacement) = replacement {
                            let replacement = if name == "database_path" {
                                replacement
                                    .strip_prefix("/")
                                    .context("rebased prevalence database path is not absolute")?
                                    .to_path_buf()
                            } else {
                                replacement
                            };
                            *value = serde_json::Value::String(
                                replacement
                                    .to_str()
                                    .context("rebased derivative path is not UTF-8")?
                                    .to_string(),
                            );
                            continue;
                        }
                    }
                    legacy_rebase_manifest_value(value, final_target, snapshot_root)?;
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    legacy_rebase_manifest_value(value, final_target, snapshot_root)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn legacy_rebase(input: &[u8], target: &Path, snapshot: &Path) -> Result<Vec<u8>> {
        let mut value: serde_json::Value = serde_json::from_slice(input)?;
        legacy_rebase_manifest_value(&mut value, target, snapshot)?;
        let mut bytes = serde_json::to_vec(&value)?; bytes.push(b'\n');
        Ok(bytes)
    }

    fn streamed_rebase(input: &[u8], target: &Path, snapshot: &Path) -> Result<(StreamedRebase, Vec<u8>)> {
        let mut output = Vec::new();
        match rebase_manifest_stream(input, &mut output, target, snapshot)? {
            StreamedRebase::Refused(error) => Err(error),
            outcome => Ok((outcome, output)),
        }
    }

    fn equivalence_cases() -> Vec<String> {
        let mut cases = vec![
            r#"{}"#.to_string(),
            r#"[]"#.to_string(),
            r#"null"#.to_string(),
            r#""/top/level/absolute/string/is/untouched""#.to_string(),
            r#"{"a":1,"b":[1,2,3],"c":{"d":null,"e":true,"f":false}}"#.to_string(),
            // Every targeted key, with realistic producer paths.
            r#"{"data_directory":"/var/lib/nano-lake/build/out/count-rollup","database_path":"/var/lib/nano-lake/build/out/prevalence-snapshot-v2/1h/db","fragment_index_directory":"/x/y/fragment-sidecar/index","index_directory":"/x/y/keyword-sidecar/index","input_root":"/var/lib/nano-lake/build/snapshot","object_stamp_manifest":"/var/lib/nano-lake/build/snapshot/object-stamps.json","part_file":"/b/uid-ledger/part-0001.bin","path":"/b/entity-sidecar/object-0001.parquet","scan_file":"relative/identity-snapshot/scan.parquet"}"#.to_string(),
            // Nested objects and arrays of objects carrying targeted keys;
            // absolute strings inside arrays are not checked by the rule.
            r#"{"objects":[{"files":[{"path":"/a/keyword-sidecar/index/0.idx","sha256":"00"},{"path":"/a/keyword-sidecar/index/1.idx"}],"id":1},{"id":2,"list":["/abs/in/array","rel"]}],"root":{"inner":{"input_root":"/old/root"}}}"#.to_string(),
            // Targeted keys holding non-strings recurse like any other value.
            r#"{"path":{"path":"/q/count-rollup/manifest-part"},"input_root":null,"scan_file":[1,"/not/rewritten/in/array"],"data_directory":7}"#.to_string(),
            // Numbers: every serde_json representation Value can hold.
            r#"{"big":18446744073709551615,"f":1.0,"g":-0.0,"h":1e300,"i":-9223372036854775808,"j":0.1,"k":123456789012345678901234567890,"l":2.5e-8,"m":-0,"n":100}"#.to_string(),
            // Escapes, unicode and whitespace in the input are normalized.
            "{ \"esc\" : \"a\\\"b\\\\c\\/d\\n\\u0001\\u00e9\u{1F600}\" ,\n  \"k\\u0041\": [ 1 , { } , [ ] ] }\n".to_string(),
            // Relative non-targeted strings stay; empty strings stay.
            r#"{"empty":"","name":"relative/path","s3":"s3://bucket/key"}"#.to_string(),
        ];
        // Pretty-printed deep nesting.
        let mut deep = String::new();
        for i in 0..60 { deep.push_str(&format!("{{\"k{i:02}\": [")); }
        deep.push_str("{\"path\": \"/r/fragment-sidecar/leaf\"}");
        for _ in 0..60 { deep.push_str("]}"); }
        cases.push(deep);
        cases
    }

    #[test]
    fn streaming_rebase_is_byte_identical_to_value_rebase() {
        let target = Path::new("/var/lib/nano-lake/generations/active/tree");
        let snapshot = Path::new("/var/lib/nano-lake/generations/active/snapshot");
        let cases = equivalence_cases();
        let mut streamed_cases = 0;
        for (index, case) in cases.iter().enumerate() {
            let legacy = legacy_rebase(case.as_bytes(), target, snapshot);
            let streamed = streamed_rebase(case.as_bytes(), target, snapshot);
            match (legacy, streamed) {
                (Ok(expected), Ok((StreamedRebase::Written { sha256, bytes }, actual))) => {
                    assert_eq!(String::from_utf8_lossy(&actual), String::from_utf8_lossy(&expected), "case {index}: {case}");
                    assert_eq!(sha256, crate::generation_proof::sha(&expected), "case {index}");
                    assert_eq!(bytes, expected.len() as u64, "case {index}");
                    assert_eq!(rebased_manifest_digest(case.as_bytes(), target, snapshot).unwrap(), (sha256, bytes));
                    streamed_cases += 1;
                }
                (Ok(_), Ok((StreamedRebase::NeedsCanonicalOrder, _))) => {
                    // Order-sensitive inputs must go through the fallback,
                    // which is the Value path itself.
                    let (digest, bytes) = rebased_manifest_digest(case.as_bytes(), target, snapshot).unwrap();
                    let expected = legacy_rebase(case.as_bytes(), target, snapshot).unwrap();
                    assert_eq!((digest, bytes), (crate::generation_proof::sha(&expected), expected.len() as u64), "case {index}");
                }
                (legacy, streamed) => panic!("case {index} diverged: legacy={:?} streamed={:?}", legacy.map(|b| b.len()), streamed.map(|(o, _)| o)),
            }
        }
        // Only the one deliberately unsorted case may take the fallback.
        assert_eq!(streamed_cases, cases.len() - 1, "streamed {streamed_cases} of {}", cases.len());
    }

    #[test]
    fn streaming_rebase_refuses_what_the_value_rebase_refuses() {
        let target = Path::new("/t/tree");
        let snapshot = Path::new("/t/snapshot");
        for (case, message) in [
            (r#"{"a":{"b":[{"unknown":"/etc/passwd"}]}}"#, "unknown absolute path"),
            (r#"{"unknown":"/abs"}"#, "unknown absolute path"),
            (r#"{"path":"/no/contracted/root/here"}"#, "no contracted derivative root"),
            (r#"{"path":"/x/entity-sidecar/../escape"}"#, "portable derivative path is invalid"),
            (r#"{"database_path":"relative/prevalence-snapshot-v2/db"}"#, ""),
        ] {
            let legacy = legacy_rebase(case.as_bytes(), target, snapshot);
            let streamed = streamed_rebase(case.as_bytes(), target, snapshot);
            match (&legacy, &streamed) {
                (Err(legacy), Err(streamed)) => {
                    assert!(format!("{streamed:#}").contains(message), "{case}: {streamed:#}");
                    assert_eq!(format!("{legacy:#}"), format!("{streamed:#}"), "{case}");
                }
                (Ok(expected), Ok((StreamedRebase::Written { .. }, actual))) => assert_eq!(expected, actual, "{case}"),
                _ => panic!("{case}: legacy={:?} streamed={:?}", legacy.map(|b| b.len()), streamed.map(|(o, _)| o)),
            }
        }
        for broken in [r#"{"a":1"#, r#"{"a":1} trailing"#, r#"{"a":}"#, "", r#"[1,]"#] {
            assert!(legacy_rebase(broken.as_bytes(), target, snapshot).is_err(), "{broken}");
            assert!(streamed_rebase(broken.as_bytes(), target, snapshot).is_err(), "{broken}");
        }
    }

    #[test]
    fn out_of_order_and_duplicate_keys_fall_back_to_the_value_rebase() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("tree");
        let snapshot = root.path().join("snapshot");
        for case in [
            r#"{"b":1,"a":{"input_root":"/old"}}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"outer":{"z":"x","y":"/abs/fine/after/sort/entity-sidecar"},"path":"/p/entity-sidecar/o"}"#,
        ] {
            let (outcome, _) = streamed_rebase(case.as_bytes(), &target, &snapshot).unwrap();
            assert!(matches!(outcome, StreamedRebase::NeedsCanonicalOrder), "{case}");
            let expected = legacy_rebase(case.as_bytes(), &target, &snapshot);
            let path = root.path().join("manifest.json");
            std::fs::write(&path, case).unwrap();
            let rebased = rebase_manifest_file(&path, &path, &target, &snapshot);
            match expected {
                Ok(expected) => {
                    assert_eq!(std::fs::read(&path).unwrap(), expected, "{case}");
                    assert_eq!(rebased.unwrap(), (crate::generation_proof::sha(&expected), expected.len() as u64));
                }
                Err(_) => assert!(rebased.is_err(), "{case}"),
            }
        }
        // No temporary file survives, success or failure.
        let leftovers = std::fs::read_dir(root.path()).unwrap().filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".rebase-")).count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn rebase_manifest_file_streams_an_entity_sidecar_manifest_identically() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.json");
        write_entity_sidecar_shaped_manifest(&source, 4 * 1024 * 1024);
        let target = root.path().join("tree");
        let snapshot = root.path().join("snapshot");
        let expected = legacy_rebase(&std::fs::read(&source).unwrap(), &target, &snapshot).unwrap();
        // Streaming path, not the fallback.
        let (outcome, _) = streamed_rebase(&std::fs::read(&source).unwrap(), &target, &snapshot).unwrap();
        assert!(matches!(outcome, StreamedRebase::Written { .. }));
        let destination = root.path().join("manifest.json");
        let rebased = rebase_manifest_file(&source, &destination, &target, &snapshot).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), expected);
        assert_eq!(rebased, (crate::generation_proof::sha(&expected), expected.len() as u64));
        // In place as well.
        let rebased = rebase_manifest_file(&source, &source, &target, &snapshot).unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), expected);
        assert_eq!(rebased.1, expected.len() as u64);
        // A refused manifest leaves the destination untouched.
        let refused = root.path().join("refused.json");
        std::fs::write(&refused, br#"{"x":"/unknown/abs"}"#).unwrap();
        assert!(rebase_manifest_file(&refused, &refused, &target, &snapshot).is_err());
        assert_eq!(std::fs::read(&refused).unwrap(), br#"{"x":"/unknown/abs"}"#);
    }

    #[test]
    fn a_refused_value_overwritten_by_a_duplicate_key_is_decided_by_the_value_rebase() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("tree");
        let snapshot = root.path().join("snapshot");
        // Value keeps the LAST duplicate, so the refused first value never
        // reaches the rule; the stream sees it first and must defer.
        let case = br#"{"x":"/unknown/abs","x":"relative"}"#;
        let expected = legacy_rebase(case, &target, &snapshot).unwrap();
        assert!(streamed_rebase(case, &target, &snapshot).is_err());
        assert_eq!(rebased_manifest_digest(case, &target, &snapshot).unwrap(),
            (crate::generation_proof::sha(&expected), expected.len() as u64));
        let path = root.path().join("manifest.json");
        std::fs::write(&path, case).unwrap();
        rebase_manifest_file(&path, &path, &target, &snapshot).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        // And a genuinely refused manifest is still refused with the rule's message.
        let refused = br#"{"a":"/unknown/abs","b":1}"#;
        let error = rebased_manifest_digest(refused, &target, &snapshot).unwrap_err();
        assert!(format!("{error:#}").contains("unknown absolute path"), "{error:#}");
    }

    /// Streaming peak for the same shapes the Value measurement uses.
    #[test]
    #[ignore = "measurement; run alone with --test-threads 1"]
    fn measure_streaming_rebase_peak_memory() {
        for mib in [62_u64, 250] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("manifest.json");
            let bytes = write_entity_sidecar_shaped_manifest(&path, mib * 1024 * 1024);
            let target = root.path().join("tree");
            let snapshot = root.path().join("snapshot");
            std::fs::write("/proc/self/clear_refs", "5").unwrap();
            let baseline = proc_status_kib("VmRSS:");
            let (_, written) = rebase_manifest_file(&path, &path, &target, &snapshot).unwrap();
            let peak = (proc_status_kib("VmHWM:").saturating_sub(baseline)) * 1024;
            assert!(written > bytes / 2);
            eprintln!("stream-rebase: manifest={bytes} bytes ({:.1} MiB) peak_rss_growth={peak} bytes ({:.2} MiB)",
                bytes as f64 / 1048576.0, peak as f64 / 1048576.0);
        }
    }
}
