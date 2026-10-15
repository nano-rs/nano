// SPDX-License-Identifier: AGPL-3.0-or-later

//! What to adopt: the objects of one owner-signed generation, before T0.
//!
//! The authority is the generation bundle manifest signed by the platform's
//! bundle key. Its signature covers `object_stamp_manifest_sha256`, which
//! pins the object-stamp ledger; each ledger stamp pins one Iceberg data
//! object by key, version, size and SHA-256. The plan keeps that chain so
//! every adoption record can name it (`inputs.anchor`, `stamp_sha256`).

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::generation::ObjectStampManifest;
use crate::generation_bundle::{
    bundle_manifest_directory, object_stamp_manifest_sha256, GenerationBundleObjectStampManifest,
    GenerationBundleSourceObject, SignedGenerationBundleManifest, GENERATION_BUNDLE_SIGNATURE_DOMAIN,
};
use crate::parts::format::validate_tenant_uuid;
use crate::parts::provenance::{is_adopted_object_key, AdoptionAnchor};
use crate::parts::{event_hour_of, sha256_hex, HOUR_US};

/// One object to adopt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedObject {
    /// The ledger stamp, exactly as the signed ledger holds it.
    pub stamp: GenerationBundleSourceObject,
    /// Bucket-relative key of the object (from `stamp.source_uri`).
    pub key: String,
    /// SHA-256 of `serde_json::to_vec(&stamp)` (contract 8.1).
    pub stamp_sha256: String,
}

/// A verified adoption plan for one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionPlan {
    pub tenant_id: String,
    /// Hour-aligned start of shadow ingest; only rows before it are adopted.
    pub t0_us: i64,
    pub anchor: AdoptionAnchor,
    /// The bucket every object lives in (from the stamps' `s3://` URIs).
    pub bucket: String,
    /// Sorted by key.
    pub objects: Vec<PlannedObject>,
    /// The generation's event-time bounds (signed), as event hours.
    pub generation_min_event_hour: i32,
    pub generation_max_event_hour: i32,
}

/// The tenant's own bucket.
pub fn tenant_bucket(tenant_id: &str) -> String {
    format!("nano-shared-r2-{tenant_id}")
}

/// The Hive-style `event_hour=<n>` partition of an object key, when present.
/// Used to skip objects at or after T0 before reading them.
pub fn key_event_hour(key: &str) -> Option<i32> {
    key.split('/').find_map(|segment| segment.strip_prefix("event_hour=")?.parse().ok())
}

/// `SHA-256(serde_json::to_vec(stamp))`.
pub fn stamp_sha256(stamp: &GenerationBundleSourceObject) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(stamp)?))
}

/// Split `s3://bucket/key` into (bucket, key).
pub fn split_source_uri(uri: &str) -> Result<(&str, &str)> {
    let rest = uri.strip_prefix("s3://").context("object source URI is not s3://")?;
    let (bucket, key) = rest.split_once('/').context("object source URI has no key")?;
    if bucket.is_empty() || !is_adopted_object_key(key) {
        bail!("object source URI {uri} is not a valid bucket key");
    }
    Ok((bucket, key))
}

/// A generation bundle manifest whose owner signature, tenant, structure and
/// published-pointer identity were verified by [`verify_generation`]. The
/// only way to build an [`AdoptionPlan`].
#[derive(Debug, Clone)]
pub struct VerifiedGeneration {
    signed: SignedGenerationBundleManifest,
    bytes_sha256: String,
    manifest_key: String,
}

impl VerifiedGeneration {
    pub fn manifest(&self) -> &SignedGenerationBundleManifest {
        &self.signed
    }

    /// The manifest's bucket key, derived from the signed identity and the
    /// exact bytes (`bundle_manifest_directory` + `manifest-<sha>.json`).
    pub fn manifest_key(&self) -> &str {
        &self.manifest_key
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.bytes_sha256
    }
}

/// Verify a signed generation bundle manifest against the platform's bundle
/// public key for `tenant_id`. `expected_identity` is the
/// `bundle_identity_sha256` of the tenant's **current** published pointer:
/// adoption must anchor on the generation the reader serves.
pub fn verify_generation(
    signed_bytes: &[u8],
    tenant_id: &str,
    signer_public_key: &[u8; 32],
    expected_identity: &str,
) -> Result<VerifiedGeneration> {
    let signed: SignedGenerationBundleManifest =
        serde_json::from_slice(signed_bytes).context("generation bundle manifest does not parse")?;
    signed.manifest.validate_structure()?;
    if signed.manifest.is_prevalence_handoff() {
        bail!("a prevalence hand-off is not a retained generation");
    }
    if signed.manifest.tenant_id.hyphenated().to_string() != tenant_id {
        bail!("generation bundle belongs to another tenant");
    }
    if signed.signature.domain != GENERATION_BUNDLE_SIGNATURE_DOMAIN {
        bail!("generation bundle signature domain is wrong");
    }
    if signed.manifest.bundle_identity_sha256 != expected_identity {
        bail!("generation bundle differs from the published pointer's identity");
    }
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&signed.signature.signature_base64)
        .context("generation bundle signature is not base64")?;
    let signature = Signature::from_slice(&signature).context("generation bundle signature is malformed")?;
    VerifyingKey::from_bytes(signer_public_key)
        .context("generation bundle public key is invalid")?
        .verify_strict(&signed.manifest.signature_message()?, &signature)
        .context("generation bundle signature does not verify")?;
    let bytes_sha256 = sha256_hex(signed_bytes);
    let manifest_key = format!(
        "{}manifest-{bytes_sha256}.json",
        bundle_manifest_directory(
            signed.manifest.tenant_id,
            signed.manifest.table_uuid,
            signed.manifest.snapshot_id,
            &signed.manifest.manifest_list_sha256,
            &signed.manifest.bundle_identity_sha256,
        )?
    );
    Ok(VerifiedGeneration { signed, bytes_sha256, manifest_key })
}

/// Extract the object-stamp ledger from the bundle's signed
/// `source-object-stamps` archive (downloaded read-only from its artifact
/// key). The archive bytes are checked against the signed artifact entry and
/// the member against its signed digest; the plan then checks the ledger
/// against `object_stamp_manifest_sha256`.
pub fn extract_stamp_ledger(verified: &VerifiedGeneration, archive: &[u8]) -> Result<ObjectStampManifest> {
    let artifact = verified
        .signed
        .manifest
        .artifacts
        .iter()
        .find(|a| a.role == "source-object-stamps")
        .context("generation bundle has no source-object-stamps artifact")?;
    if archive.len() as u64 != artifact.bytes || sha256_hex(archive) != artifact.sha256 {
        bail!("stamp archive differs from the signed artifact {}", artifact.key);
    }
    let member = crate::generation_bundle::single_archive_member(artifact, archive)?;
    serde_json::from_slice(member).context("object-stamp ledger does not parse")
}

impl AdoptionPlan {
    /// Build the plan from a verified bundle (see [`verify_generation`]) and
    /// the object-stamp ledger it names.
    pub fn from_verified_generation(verified: &VerifiedGeneration, stamps: &ObjectStampManifest, t0_us: i64) -> Result<Self> {
        let signed = &verified.signed;
        let manifest = &signed.manifest;
        let ledger = GenerationBundleObjectStampManifest::from(stamps);
        if object_stamp_manifest_sha256(&ledger)? != manifest.object_stamp_manifest_sha256 {
            bail!("object-stamp ledger does not match the signed generation");
        }
        if stamps.snapshot_id != manifest.snapshot_id
            || stamps.metadata_location != manifest.iceberg_metadata_location
            || stamps.objects.len() != manifest.source_object_count
        {
            bail!("object-stamp ledger identity differs from the signed generation");
        }
        let data_prefix = format!("{}/data/", manifest.table_location.trim_end_matches('/'));
        if ledger.objects.iter().any(|o| !o.source_uri.starts_with(&data_prefix)) {
            bail!("an object stamp lies outside the generation's table data prefix");
        }
        let anchor = AdoptionAnchor {
            generation_id: manifest.generation_id.clone(),
            snapshot_id: u64::try_from(manifest.snapshot_id).context("generation snapshot id is negative")?,
            bundle_identity_sha256: manifest.bundle_identity_sha256.clone(),
            object_stamp_manifest_sha256: manifest.object_stamp_manifest_sha256.clone(),
            bundle_manifest_key: verified.manifest_key.clone(),
            bundle_manifest_sha256: verified.bytes_sha256.clone(),
            signer_key_id: signed.signature.key_id.clone(),
        };
        Self::new(
            &manifest.tenant_id.hyphenated().to_string(),
            t0_us,
            anchor,
            ledger.objects,
            event_hour_of(manifest.min_event_time.timestamp_micros()),
            event_hour_of(manifest.max_event_time.timestamp_micros()),
        )
    }

    /// Build and validate a plan from already-authenticated stamps. Not
    /// public: production plans come only from a [`VerifiedGeneration`].
    pub(crate) fn new(
        tenant_id: &str,
        t0_us: i64,
        anchor: AdoptionAnchor,
        stamps: Vec<GenerationBundleSourceObject>,
        generation_min_event_hour: i32,
        generation_max_event_hour: i32,
    ) -> Result<Self> {
        validate_tenant_uuid(tenant_id)?;
        if t0_us <= 0 || t0_us % HOUR_US != 0 {
            bail!("T0 must be a positive, hour-aligned UTC time");
        }
        if stamps.is_empty() {
            bail!("the generation has no objects to adopt");
        }
        if !is_adopted_object_key(&anchor.bundle_manifest_key) {
            bail!("bundle manifest key is invalid");
        }
        let mut bucket = None::<String>;
        let mut keys = BTreeSet::new();
        let mut objects = Vec::with_capacity(stamps.len());
        for stamp in stamps {
            let (object_bucket, key) = split_source_uri(&stamp.source_uri)?;
            // Zero cross-tenant sharing: every object is in the tenant's own bucket.
            if object_bucket != tenant_bucket(tenant_id) {
                bail!("object {key} is in bucket {object_bucket}, not the tenant's {}", tenant_bucket(tenant_id));
            }
            bucket.get_or_insert_with(|| object_bucket.to_string());
            if !crate::parts::is_sha256_hex(&stamp.sha256) || stamp.size_bytes == 0 {
                bail!("object stamp for {key} has an invalid digest or size");
            }
            if !keys.insert(key.to_string()) {
                bail!("object {key} appears twice in the generation");
            }
            let key = key.to_string();
            objects.push(PlannedObject { stamp_sha256: stamp_sha256(&stamp)?, stamp, key });
        }
        objects.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(Self {
            tenant_id: tenant_id.to_string(),
            t0_us,
            anchor,
            bucket: bucket.expect("nonempty"),
            objects,
            generation_min_event_hour,
            generation_max_event_hour,
        })
    }

    pub fn t0_hour(&self) -> i32 {
        event_hour_of(self.t0_us)
    }

    pub fn total_bytes(&self) -> u64 {
        self.objects.iter().map(|o| o.stamp.size_bytes).sum()
    }

    /// The largest object (by bytes); the plan's memory-bound driver.
    pub fn largest_object(&self) -> Option<&PlannedObject> {
        self.objects.iter().max_by_key(|o| o.stamp.size_bytes)
    }

    /// Objects the key partition already places at or after T0.
    pub fn objects_at_or_after_t0(&self) -> usize {
        let t0 = self.t0_hour();
        self.objects.iter().filter(|o| key_event_hour(&o.key).is_some_and(|h| h >= t0)).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation_bundle::tests::fixture;

    fn stamps_of(signed: &SignedGenerationBundleManifest, objects: &std::collections::BTreeMap<String, (Vec<u8>, String)>) -> ObjectStampManifest {
        let artifact = signed.manifest.artifacts.iter().find(|a| a.role == "source-object-stamps").unwrap();
        let archive = &objects[&artifact.key].0;
        // Single-member archive: the member bytes are its tail.
        let member = &archive[archive.len() - artifact.unpacked_bytes as usize..];
        serde_json::from_slice(member).unwrap()
    }

    #[test]
    fn plan_verifies_the_owner_signature_and_the_stamp_ledger() {
        let (signed, admission, _, objects) = fixture();
        let bytes = serde_json::to_vec(&signed).unwrap();
        let tenant = admission.tenant_id.hyphenated().to_string();
        let identity = signed.manifest.bundle_identity_sha256.clone();
        let verified = verify_generation(&bytes, &tenant, &admission.signer_public_key, &identity).unwrap();
        // The key is bound to the signed identity and the exact bytes.
        assert!(verified.manifest_key().ends_with(&format!("manifest-{}.json", sha256_hex(&bytes))));
        assert!(verified.manifest_key().starts_with(&format!("{tenant}/retained-generation/v1/bundles/")));
        let stamps = stamps_of(&signed, &objects);
        let artifact = signed.manifest.artifacts.iter().find(|a| a.role == "source-object-stamps").unwrap();
        let extracted = extract_stamp_ledger(&verified, &objects[&artifact.key].0).unwrap();
        assert_eq!(serde_json::to_value(&extracted).unwrap(), serde_json::to_value(&stamps).unwrap());
        let mut corrupt = objects[&artifact.key].0.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(extract_stamp_ledger(&verified, &corrupt).is_err());
        let t0 = 1_790_330_400_000_000;
        let plan = AdoptionPlan::from_verified_generation(&verified, &stamps, t0).unwrap();
        assert_eq!(plan.anchor.bundle_manifest_key, verified.manifest_key());
        assert_eq!(plan.objects.len(), 1);
        assert_eq!(plan.anchor.bundle_manifest_sha256, sha256_hex(&bytes));
        assert!(plan.objects[0].key.ends_with("/data/part-42.parquet"));
        assert!(!plan.objects[0].key.starts_with("s3://"));
        assert_eq!(plan.bucket, format!("nano-shared-r2-{}", admission.tenant_id));
        assert_eq!(plan.objects[0].stamp_sha256, stamp_sha256(&plan.objects[0].stamp).unwrap());

        // Wrong key, wrong tenant, tampered manifest, wrong pointer identity.
        assert!(verify_generation(&bytes, &tenant, &[7; 32], &identity).is_err());
        assert!(verify_generation(&bytes, "00000000-0000-4000-8000-000000000000", &admission.signer_public_key, &identity).is_err());
        let tampered = String::from_utf8(bytes.clone()).unwrap().replace("\"snapshot_id\":42", "\"snapshot_id\":43");
        assert!(verify_generation(tampered.as_bytes(), &tenant, &admission.signer_public_key, &identity).is_err());
        assert!(verify_generation(&bytes, &tenant, &admission.signer_public_key, &"0".repeat(64)).is_err());

        // A ledger that is not the signed one.
        let mut forged = stamps.clone();
        forged.objects[0].sha256 = "f".repeat(64);
        assert!(AdoptionPlan::from_verified_generation(&verified, &forged, t0).is_err());
        // T0 must be hour aligned.
        assert!(AdoptionPlan::from_verified_generation(&verified, &stamps, t0 + 1).is_err());
    }

    #[test]
    fn objects_outside_the_tenant_bucket_are_refused() {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let stamp = |bucket: &str| GenerationBundleSourceObject {
            relative_path: "data/a.parquet".into(),
            source_uri: format!("s3://{bucket}/warehouse/nano/events/data/event_hour=5/a.parquet"),
            version_id: "v".into(),
            size_bytes: 1,
            sha256: "a".repeat(64),
        };
        let anchor = AdoptionAnchor {
            generation_id: "g".into(),
            snapshot_id: 1,
            bundle_identity_sha256: "1".repeat(64),
            object_stamp_manifest_sha256: "2".repeat(64),
            bundle_manifest_key: "m/manifest.json".into(),
            bundle_manifest_sha256: "3".repeat(64),
            signer_key_id: "platform-bundle-2026-01".into(),
        };
        let own = tenant_bucket(tenant);
        let plan = AdoptionPlan::new(tenant, HOUR_US * 10, anchor.clone(), vec![stamp(&own)], 0, 9).unwrap();
        assert_eq!(plan.bucket, own);
        assert_eq!(plan.objects_at_or_after_t0(), 0);
        assert_eq!(key_event_hour(&plan.objects[0].key), Some(5));
        let other = tenant_bucket("00000000-0000-4000-8000-000000000000");
        assert!(AdoptionPlan::new(tenant, HOUR_US * 10, anchor, vec![stamp(&other)], 0, 9).is_err());
    }

    #[test]
    fn source_uris_split_into_bucket_keys() {
        assert_eq!(split_source_uri("s3://b/x/y.parquet").unwrap(), ("b", "x/y.parquet"));
        assert!(split_source_uri("s3://b/../y").is_err());
        assert!(split_source_uri("https://b/y").is_err());
        assert!(split_source_uri("s3://b/lake/parts/v1/x").is_err());
    }
}
