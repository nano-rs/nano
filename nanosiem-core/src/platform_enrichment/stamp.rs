// SPDX-License-Identifier: AGPL-3.0-or-later
//! V1 metadata lives additively in OCSF enrichments[].data; legacy name/value/
//! type/provider fields remain unchanged. No historical rewriting is allowed.
use super::{digest_valid, slug, FeedClass};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StampStatus {
    Match,
    NoMatch,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StampReason {
    Missing,
    Expired,
    Revoked,
    Disabled,
    Unavailable,
    AuthorityFailure,
    ResourceLimit,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessAtIngest {
    Fresh,
    Stale,
    Unknown,
}
/// Exact owned leaves. Enrichment records themselves are bound by the signed
/// output digest, so arbitrary JSON paths cannot claim a producer's fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum OwnedField {
    #[serde(rename = "src_endpoint.location.country")]
    SrcCountry,
    #[serde(rename = "src_endpoint.location.continent")]
    SrcContinent,
    #[serde(rename = "src_endpoint.location.provider")]
    SrcGeoProvider,
    #[serde(rename = "src_endpoint.autonomous_system.number")]
    SrcAsn,
    #[serde(rename = "src_endpoint.autonomous_system.name")]
    SrcAsName,
    #[serde(rename = "dst_endpoint.location.country")]
    DstCountry,
    #[serde(rename = "dst_endpoint.location.continent")]
    DstContinent,
    #[serde(rename = "dst_endpoint.location.provider")]
    DstGeoProvider,
    #[serde(rename = "dst_endpoint.autonomous_system.number")]
    DstAsn,
    #[serde(rename = "dst_endpoint.autonomous_system.name")]
    DstAsName,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PremiumStampRight {
    pub tier: String,
    pub grant_revision: i64,
    pub entitlement_revision: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FeedStampV1 {
    pub contract_version: u16,
    pub feed_id: String,
    pub feed_class: FeedClass,
    /// None only when no revision could be selected; still record coverage.
    pub feed_revision_id: Option<i64>,
    pub payload_digest: Option<String>,
    pub mapping_revision: Option<i64>,
    pub admitted_at: DateTime<Utc>,
    pub upstream_at: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
    pub freshness_at_ingest: FreshnessAtIngest,
    pub status: StampStatus,
    pub reason: Option<StampReason>,
    pub owned_fields: Vec<OwnedField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub premium: Option<PremiumStampRight>,
}
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StampError {
    #[error("invalid platform stamp")]
    Invalid,
    #[error("producer supplied reserved platform provenance")]
    ProducerSpoof,
    #[error("platform writer provenance verification failed")]
    Untrusted,
}
impl FeedStampV1 {
    pub fn validate(&self) -> Result<(), StampError> {
        let selected = matches!((self.feed_revision_id, self.payload_digest.as_deref(),self.mapping_revision),
            (Some(r),Some(d),Some(m)) if r>0 && m>0 && digest_valid(d));
        let absent = self.feed_revision_id.is_none()
            && self.payload_digest.is_none()
            && self.mapping_revision.is_none();
        if (self.feed_class == FeedClass::Baseline && self.premium.is_some())
            || (self.feed_class == FeedClass::Premium
                && self.status != StampStatus::Unknown
                && self.premium.is_none())
            || self.contract_version != 1
            || !slug(&self.feed_id)
            || (!selected && !absent)
            || (self.status == StampStatus::Unknown) != self.reason.is_some()
            || (self.status != StampStatus::Unknown
                && (!selected
                    || self.valid_until.is_none()
                    || self.freshness_at_ingest == FreshnessAtIngest::Unknown))
            || (self.status != StampStatus::Match && !self.owned_fields.is_empty())
            || self.upstream_at.is_some_and(|t| t > self.admitted_at)
            || (self.status != StampStatus::Unknown
                && self.valid_until.is_some_and(|t| t <= self.admitted_at))
            || self
                .owned_fields
                .iter()
                .enumerate()
                .any(|(i, f)| self.owned_fields[..i].contains(f))
            || self.premium.as_ref().is_some_and(|r| {
                !slug(&r.tier)
                    || r.tier == "included"
                    || r.grant_revision <= 0
                    || r.entitlement_revision <= 0
            })
        {
            return Err(StampError::Invalid);
        }
        Ok(())
    }
}

/// Detached writer envelope. It binds the pre-decoration source identity,
/// durable admission vector and FINAL output bytes, not a producer signature.
/// V1 signatures cover DOMAIN || serde_json::to_vec(envelope), in struct field
/// order. No maps or floating point values occur in the signed structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WriterEnvelopeV1 {
    pub contract_version: u16,
    pub tenant_id: Uuid,
    pub admission_id: Uuid,
    pub source_identity_sha256: String,
    pub admitted_at: DateTime<Utc>,
    pub catalog_revision: i64,
    pub revision_vector_sha256: String,
    pub output_sha256: String,
    pub writer_receipt_id: Uuid,
    pub writer_key_id: String,
}
impl WriterEnvelopeV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, StampError> {
        if self.contract_version != 1
            || self.tenant_id.is_nil()
            || self.admission_id.is_nil()
            || self.writer_receipt_id.is_nil()
            || self.catalog_revision <= 0
            || !slug(&self.writer_key_id)
            || ![
                &self.source_identity_sha256,
                &self.revision_vector_sha256,
                &self.output_sha256,
            ]
            .into_iter()
            .all(|d| digest_valid(d))
        {
            return Err(StampError::Invalid);
        }
        let mut bytes = b"nano/platform-enrichment/writer-envelope/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| StampError::Invalid)?);
        Ok(bytes)
    }
}
/// Only verification constructs this type. A JSON envelope is never authority.
#[derive(Debug)]
pub struct VerifiedWriterEnvelope(WriterEnvelopeV1);
impl VerifiedWriterEnvelope {
    pub fn envelope(&self) -> &WriterEnvelopeV1 {
        &self.0
    }
}
/// `expected` must come from the trusted durable admission/output receipt, and
/// `key` from the writer trust store, NEVER from the event. The byte digest is
/// checked here against the exact immutable bytes before returning authority.
pub fn verify_writer_envelope(
    envelope: WriterEnvelopeV1,
    signature: &[u8; 64],
    key: &VerifyingKey,
    expected: &WriterEnvelopeV1,
    output_bytes: &[u8],
) -> Result<VerifiedWriterEnvelope, StampError> {
    if &envelope != expected || hex::encode(Sha256::digest(output_bytes)) != envelope.output_sha256
    {
        return Err(StampError::Untrusted);
    }
    key.verify_strict(
        &envelope.signing_bytes()?,
        &Signature::from_bytes(signature),
    )
    .map_err(|_| StampError::Untrusted)?;
    Ok(VerifiedWriterEnvelope(envelope))
}

/// Called on producer JSON BEFORE any platform value is persisted. Reject
/// reserved provenance even when nested in custom data/arrays; preserve the
/// ordinary source fields and legacy non-platform enrichment shape.
pub fn reject_producer_provenance(event: &serde_json::Value) -> Result<(), StampError> {
    fn visit(value: &serde_json::Value, depth: usize) -> Result<(), StampError> {
        if depth > 128 {
            return Err(StampError::Invalid);
        }
        match value {
            serde_json::Value::Object(object) => {
                if object
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|p| p.starts_with("platform/"))
                {
                    return Err(StampError::ProducerSpoof);
                }
                for (key, child) in object {
                    if matches!(
                        key.as_str(),
                        "platform_enrichment"
                            | "feed_revision_id"
                            | "writer_receipt_id"
                            | "revision_vector_sha256"
                            | "owned_fields"
                    ) {
                        return Err(StampError::ProducerSpoof);
                    }
                    visit(child, depth + 1)?;
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    visit(child, depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    visit(event, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn stamp() -> FeedStampV1 {
        FeedStampV1 {
            contract_version: 1,
            feed_id: "ipinfo_lite".into(),
            feed_class: FeedClass::Baseline,
            feed_revision_id: Some(1),
            payload_digest: Some("ab".repeat(32)),
            mapping_revision: Some(1),
            admitted_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
            upstream_at: None,
            valid_until: Some(DateTime::from_timestamp(1_800_001_000, 0).unwrap()),
            freshness_at_ingest: FreshnessAtIngest::Fresh,
            status: StampStatus::Match,
            reason: None,
            owned_fields: vec![OwnedField::SrcCountry],
            premium: None,
        }
    }
    #[test]
    fn validates_coverage_and_ownership() {
        let mut s = stamp();
        s.validate().unwrap();
        s.status = StampStatus::Unknown;
        assert!(s.validate().is_err());
        s.reason = Some(StampReason::Unavailable);
        s.owned_fields.clear();
        s.validate().unwrap();
        s.payload_digest = None;
        assert!(s.validate().is_err());
    }
    #[test]
    fn additive_ocsf_data_remains_readable() {
        #[derive(Deserialize)]
        struct Legacy {
            name: String,
            value: String,
            provider: String,
            data: serde_json::Value,
        }
        let s = stamp();
        let mut data = serde_json::to_value(&s).unwrap();
        data["future_optional_field"] = true.into();
        let newer: FeedStampV1 = serde_json::from_value(data.clone()).unwrap();
        newer.validate().unwrap();
        let old:Legacy=serde_json::from_value(serde_json::json!({"name":"src_endpoint.ip","value":"192.0.2.1","provider":"ipinfo_lite","data":data})).unwrap();
        assert_eq!(old.name, "src_endpoint.ip");
        assert_eq!(old.value, "192.0.2.1");
        assert_eq!(old.provider, "ipinfo_lite");
        assert_eq!(old.data["feed_revision_id"], 1);
    }
    #[test]
    fn producer_spoofs_rejected_before_persistence() {
        for key in [
            "platform_enrichment",
            "feed_revision_id",
            "writer_receipt_id",
            "revision_vector_sha256",
            "owned_fields",
        ] {
            let v = serde_json::json!({"enrichments":[{"data":{key:"forged"}}]});
            assert_eq!(
                reject_producer_provenance(&v),
                Err(StampError::ProducerSpoof)
            );
        }
        reject_producer_provenance(
            &serde_json::json!({"src_endpoint":{"location":{"country":"US"}}}),
        )
        .unwrap();
    }
    #[test]
    fn writer_signature_binds_tenant_revision_time_and_output() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let expected = WriterEnvelopeV1 {
            contract_version: 1,
            tenant_id: Uuid::from_u128(1),
            admission_id: Uuid::from_u128(2),
            source_identity_sha256: "11".repeat(32),
            admitted_at: stamp().admitted_at,
            catalog_revision: 1,
            revision_vector_sha256: "22".repeat(32),
            output_sha256: hex::encode(Sha256::digest(b"fixture")),
            writer_receipt_id: Uuid::from_u128(3),
            writer_key_id: "writer_v1".into(),
        };
        let signature = key.sign(&expected.signing_bytes().unwrap()).to_bytes();
        verify_writer_envelope(
            expected.clone(),
            &signature,
            &key.verifying_key(),
            &expected,
            b"fixture",
        )
        .unwrap();
        let mut changed = expected.clone();
        changed.tenant_id = Uuid::from_u128(4);
        assert!(verify_writer_envelope(
            changed,
            &signature,
            &key.verifying_key(),
            &expected,
            b"fixture"
        )
        .is_err());
        let mut changed = expected.clone();
        changed.output_sha256 = "44".repeat(32);
        assert!(verify_writer_envelope(
            changed.clone(),
            &signature,
            &key.verifying_key(),
            &changed,
            b"fixture"
        )
        .is_err());
        let mut changed = expected.clone();
        changed.admitted_at += chrono::Duration::seconds(1);
        assert!(verify_writer_envelope(
            changed.clone(),
            &signature,
            &key.verifying_key(),
            &changed,
            b"fixture"
        )
        .is_err());
        assert!(verify_writer_envelope(
            expected.clone(),
            &signature,
            &SigningKey::from_bytes(&[8; 32]).verifying_key(),
            &expected,
            b"fixture"
        )
        .is_err());
    }
}
