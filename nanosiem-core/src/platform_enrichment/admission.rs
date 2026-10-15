// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical immutable revision-vector encoding used by the detached receipt.
use super::{digest_valid, slug, StampError, StampReason};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SelectedFeedRevision {
    pub revision: i64,
    pub digest: String,
    pub mapping_revision: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdmissionRight {
    pub tier: String,
    pub grant_revision: i64,
    pub entitlement_revision: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdmissionDecision {
    Selected {
        artifact: SelectedFeedRevision,
        right: AdmissionRight,
    },
    Unknown {
        reason: StampReason,
        artifact: Option<SelectedFeedRevision>,
        right: Option<AdmissionRight>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdmissionFeed {
    pub feed_id: String,
    pub deny_epoch: i64,
    pub decision: AdmissionDecision,
}
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdmissionRevisionVectorV1 {
    pub contract_version: u16,
    pub tenant_id: Uuid,
    pub admission_id: Uuid,
    pub source_identity_sha256: String,
    pub admitted_at: DateTime<Utc>,
    pub catalog_revision: i64,
    /// Strictly sorted by feed_id; exactly one decision per feed, including
    /// unknown decisions. This is never recomputed on a retry or a read.
    pub feeds: Vec<AdmissionFeed>,
}
impl AdmissionRevisionVectorV1 {
    /// Domain-separated typed JSON in declared field order, with lexically
    /// sorted feeds. No maps, omitted fields or floating point values. Persist
    /// these bytes/digest once; version changes require a new domain.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StampError> {
        if self.contract_version != 1
            || self.tenant_id.is_nil()
            || self.admission_id.is_nil()
            || !digest_valid(&self.source_identity_sha256)
            || self.catalog_revision <= 0
            || self.feeds.is_empty()
            || self.feeds.len() > 64
            || self
                .feeds
                .windows(2)
                .any(|pair| pair[0].feed_id >= pair[1].feed_id)
        {
            return Err(StampError::Invalid);
        }
        for feed in &self.feeds {
            if !slug(&feed.feed_id) || feed.deny_epoch < 0 {
                return Err(StampError::Invalid);
            }
            let (artifact, right) = match &feed.decision {
                AdmissionDecision::Selected { artifact, right } => (Some(artifact), Some(right)),
                AdmissionDecision::Unknown {
                    artifact, right, ..
                } => (artifact.as_ref(), right.as_ref()),
            };
            if artifact.is_some_and(|a| {
                a.revision <= 0 || a.mapping_revision <= 0 || !digest_valid(&a.digest)
            }) || right.is_some_and(|r| {
                !slug(&r.tier) || r.grant_revision <= 0 || r.entitlement_revision <= 0
            }) {
                return Err(StampError::Invalid);
            }
        }
        let mut bytes = b"nano/platform-enrichment/admission-vector/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| StampError::Invalid)?);
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<String, StampError> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_decisions_are_durable_digest_inputs() {
        let mut vector = AdmissionRevisionVectorV1 {
            contract_version: 1,
            tenant_id: Uuid::from_u128(1),
            admission_id: Uuid::from_u128(2),
            source_identity_sha256: "ab".repeat(32),
            admitted_at: DateTime::UNIX_EPOCH,
            catalog_revision: 1,
            feeds: vec![AdmissionFeed {
                feed_id: "ipinfo_lite".into(),
                deny_epoch: 0,
                decision: AdmissionDecision::Unknown {
                    reason: StampReason::Unavailable,
                    artifact: None,
                    right: None,
                },
            }],
        };
        let original = vector.digest().unwrap();
        let decoded: AdmissionRevisionVectorV1 =
            serde_json::from_str(&serde_json::to_string(&vector).unwrap()).unwrap();
        assert_eq!(decoded.digest().unwrap(), original);
        vector.admitted_at += chrono::Duration::seconds(1);
        assert_ne!(vector.digest().unwrap(), original);
        vector.feeds.push(vector.feeds[0].clone());
        assert!(vector.digest().is_err());
    }
}
