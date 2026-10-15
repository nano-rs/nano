// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant "Internal domains" distribution for lean cells (NAN-3226).
//!
//! The API stores the tenant's internal DNS suffixes in PostgreSQL (the
//! `internal_domains` tenant settings section) and pushes them to the
//! tenant's lean enrichment coordinator (`PUT /v1/internal-domains`), which
//! writes ONE small JSON document under the tenant's R2 enrichment prefix
//! (`lake/enrichment/v1/tenant_id=<T>/`, the coordinator's write scope and
//! lean ingest's `enrichment_reader` scope):
//!
//! `internal_domains/current.json` =
//! `{"schema":"nano/internal-domains/1","tenant_id":..,"suffixes":[..],"sha256":..}`
//!
//! Lean ingest re-reads it on its 30 s enrichment refresh and installs it
//! process-wide (`ocsf_domains::set_internal_domains`), so a change reaches
//! domain prevalence without a code roll or restart. Each part writer pins the
//! set at creation. The document is bounded (256 suffixes, 64 KiB) and bound to
//! the process tenant; a refused or unreadable document keeps the active set.

use anyhow::{ensure, Context, Result};
use nanosiem_core::internal_domains::{normalize_tenant_suffixes, InternalDomains};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::parts::part_log::ObjectStore;

/// Object key relative to the tenant enrichment prefix.
pub const INTERNAL_DOMAINS_KEY: &str = "internal_domains/current.json";
/// Document schema tag.
pub const INTERNAL_DOMAINS_SCHEMA: &str = "nano/internal-domains/1";
/// 256 suffixes × 253 bytes plus JSON framing fits well under this.
const MAX_DOCUMENT_BYTES: usize = 96 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalDomainsDocument {
    pub schema: String,
    pub tenant_id: Uuid,
    /// Normalized, sorted tenant suffixes (built-ins implicit).
    pub suffixes: Vec<String>,
    /// SHA-256 of the newline-joined suffixes (change detection / logs).
    pub sha256: String,
}

fn digest(suffixes: &[String]) -> String {
    hex::encode(Sha256::digest(suffixes.join("\n").as_bytes()))
}

impl InternalDomainsDocument {
    /// Build a document from an untrusted list (normalized and validated).
    pub fn new(tenant_id: Uuid, suffixes: &[String]) -> Result<Self> {
        let suffixes =
            normalize_tenant_suffixes(suffixes).map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok(Self {
            schema: INTERNAL_DOMAINS_SCHEMA.to_string(),
            tenant_id,
            sha256: digest(&suffixes),
            suffixes,
        })
    }

    /// Parse and check a stored document against the process tenant.
    pub fn parse(bytes: &[u8], tenant_id: Uuid) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_DOCUMENT_BYTES,
            "internal domains document is oversized"
        );
        let document: Self =
            serde_json::from_slice(bytes).context("internal domains document is malformed")?;
        ensure!(
            document.schema == INTERNAL_DOMAINS_SCHEMA,
            "internal domains document schema is unknown"
        );
        ensure!(
            document.tenant_id == tenant_id,
            "internal domains document tenant differs from process tenant"
        );
        let normalized = normalize_tenant_suffixes(&document.suffixes)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        ensure!(
            normalized == document.suffixes,
            "internal domains document is not normalized"
        );
        ensure!(
            document.sha256 == digest(&document.suffixes),
            "internal domains document digest mismatch"
        );
        Ok(document)
    }

    pub fn internal_domains(&self) -> InternalDomains {
        InternalDomains::with_tenant(&self.suffixes)
    }
}

/// Read the tenant's document; `Ok(None)` when none was ever published
/// (built-ins only).
pub async fn read(
    objects: &dyn ObjectStore,
    tenant_id: Uuid,
) -> Result<Option<InternalDomainsDocument>> {
    let Some(bytes) = objects.get(INTERNAL_DOMAINS_KEY).await? else {
        return Ok(None);
    };
    InternalDomainsDocument::parse(&bytes, tenant_id).map(Some)
}

/// Write the tenant's document (the coordinator is the single writer per
/// tenant; a whole-object PUT replaces it atomically).
pub async fn publish(
    objects: &dyn ObjectStore,
    tenant_id: Uuid,
    suffixes: &[String],
) -> Result<InternalDomainsDocument> {
    let document = InternalDomainsDocument::new(tenant_id, suffixes)?;
    objects
        .put(INTERNAL_DOMAINS_KEY, &serde_json::to_vec(&document)?)
        .await?;
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT_A: Uuid = Uuid::from_u128(0xa);
    const TENANT_B: Uuid = Uuid::from_u128(0xb);

    #[test]
    fn documents_are_normalized_tenant_bound_and_digested() {
        let doc = InternalDomainsDocument::new(
            TENANT_A,
            &[
                "Prod.".to_string(),
                "local".to_string(),
                "nano.cloud".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(
            doc.suffixes,
            vec!["nano.cloud".to_string(), "prod".to_string()]
        );
        let bytes = serde_json::to_vec(&doc).unwrap();
        assert_eq!(
            InternalDomainsDocument::parse(&bytes, TENANT_A).unwrap(),
            doc
        );
        assert!(
            InternalDomainsDocument::parse(&bytes, TENANT_B).is_err(),
            "tenant isolation"
        );
        let internal = doc.internal_domains();
        assert!(
            internal.is_internal("db1.prod")
                && internal.is_internal("ws.corp.local")
                && !internal.is_internal("myprod.com")
        );

        let mut tampered = doc.clone();
        tampered.suffixes.push("zz.example".into());
        assert!(
            InternalDomainsDocument::parse(&serde_json::to_vec(&tampered).unwrap(), TENANT_A)
                .is_err()
        );
        let mut unnormalized = doc;
        unnormalized.suffixes = vec!["PROD".into()];
        unnormalized.sha256 = digest(&unnormalized.suffixes);
        assert!(InternalDomainsDocument::parse(
            &serde_json::to_vec(&unnormalized).unwrap(),
            TENANT_A
        )
        .is_err());
        assert!(InternalDomainsDocument::new(TENANT_A, &["a..b".to_string()]).is_err());
    }
}
