// SPDX-License-Identifier: AGPL-3.0-or-later

//! Single-tenant detect bootstrap. Never accepted by a hosted assignment.

use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::server::{QueryBootstrap, BOOTSTRAP_FORMAT};
use crate::parts::format::validate_tenant_uuid;
use crate::parts::provenance::LocalPartSigner;

pub const FORMAT: &str = "nano.lake-detect-trusted-local.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedLocalDetectBootstrap {
    pub format: String,
    pub query: QueryBootstrap,
    /// The open single-tenant PostgreSQL database, supplied by sealed memfd.
    #[serde(deserialize_with = "deserialize_seed")]
    pub database_url: Zeroizing<String>,
    pub signer_key_id: String,
    #[serde(deserialize_with = "deserialize_seed")]
    pub signer_seed_hex: Zeroizing<String>,
    pub writer_epoch: u64,
}

fn deserialize_seed<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl TrustedLocalDetectBootstrap {
    pub fn parse(secret: &[u8], tenant: &str, control_url: Option<&str>) -> Result<Self> {
        ensure!(
            control_url.is_none(),
            "trusted-local detect refuses a control plane"
        );
        validate_tenant_uuid(tenant)?;
        ensure!(
            !uuid::Uuid::parse_str(tenant)?.is_nil(),
            "trusted-local detect tenant must not be nil"
        );
        let document: Self = serde_json::from_slice(secret)
            .map_err(|_| anyhow::anyhow!("invalid trusted-local detect bootstrap document"))?;
        ensure!(
            document.format == FORMAT && document.query.format == BOOTSTRAP_FORMAT,
            "trusted-local detect bootstrap format differs"
        );
        ensure!(
            document.query.tenant_id == tenant,
            "trusted-local detect tenant differs"
        );
        ensure!(
            document.writer_epoch > 0,
            "trusted-local detect has no writer epoch"
        );
        ensure!(
            document.query.r2.is_none()
                && document.query.part_write_r2.is_none()
                && document.query.part_log_r2.is_none()
                && document.query.enrichment_r2.is_none()
                && document.query.job_results_r2.is_none()
                && document.query.expires_at.is_none(),
            "trusted-local detect requires local storage and static authority"
        );
        let database = reqwest::Url::parse(document.database_url.as_str())
            .map_err(|_| anyhow::anyhow!("invalid trusted-local detect database URL"))?;
        ensure!(
            matches!(database.scheme(), "postgres" | "postgresql") && database.host_str().is_some(),
            "trusted-local detect database must be PostgreSQL"
        );
        document.signer()?;
        Ok(document)
    }

    pub fn signer(&self) -> Result<LocalPartSigner> {
        let bytes = Zeroizing::new(
            hex::decode(self.signer_seed_hex.as_str())
                .context("trusted-local detect signer seed is not hex")?,
        );
        let seed: Zeroizing<[u8; 32]> =
            Zeroizing::new(bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("trusted-local detect signer seed must be 32 bytes")
            })?);
        let key = SigningKey::from_bytes(&seed);
        let public = hex::encode(key.verifying_key().as_bytes());
        ensure!(
            self.query
                .trusted_signer_keys
                .iter()
                .any(|trusted| trusted.key_id == self.signer_key_id
                    && trusted.public_key_hex == public),
            "trusted-local detect signer is not trusted by the reader"
        );
        LocalPartSigner::new(&self.signer_key_id, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    const TENANT: &str = "00000000-0000-4000-8000-000000000001";

    fn document() -> Value {
        let key = SigningKey::from_bytes(&[7; 32]);
        json!({"format":FORMAT,"database_url":"postgres://test@localhost/test",
            "writer_epoch":1,"signer_key_id":"lab-local","signer_seed_hex":hex::encode([7;32]),
            "query":{"format":BOOTSTRAP_FORMAT,"tenant_id":TENANT,"bucket":"local",
                "trusted_signer_keys":[{"key_id":"lab-local","public_key_hex":hex::encode(key.verifying_key().as_bytes())}],
                "engine":{"chdb_library":"/lib/libchdb.so","chdb_sha256":"00","compiler":"/bin/compiler"}}})
    }

    #[test]
    fn local_document_is_tenant_and_signer_bound() {
        let secret = serde_json::to_vec(&document()).unwrap();
        if let Err(error) = TrustedLocalDetectBootstrap::parse(&secret, TENANT, None) {
            panic!("valid fixture refused: {error}");
        }
        assert!(TrustedLocalDetectBootstrap::parse(&secret, "default", None).is_err());
        assert!(TrustedLocalDetectBootstrap::parse(
            &secret,
            "00000000-0000-0000-0000-000000000000",
            None
        )
        .is_err());
        assert!(TrustedLocalDetectBootstrap::parse(
            &secret,
            "00000000-0000-4000-8000-000000000002",
            None
        )
        .is_err());
        assert!(
            TrustedLocalDetectBootstrap::parse(&secret, TENANT, Some("https://control")).is_err()
        );
        for (path, value) in [
            ("/writer_epoch", json!(0)),
            ("/signer_seed_hex", json!(hex::encode([8; 32]))),
            ("/database_url", json!("https://db")),
            ("/query/expires_at", json!("2030-01-01T00:00:00Z")),
        ] {
            let mut invalid = document();
            if path == "/query/expires_at" {
                invalid["query"]["expires_at"] = value;
            } else {
                *invalid.pointer_mut(path).unwrap() = value;
            }
            assert!(
                TrustedLocalDetectBootstrap::parse(
                    &serde_json::to_vec(&invalid).unwrap(),
                    TENANT,
                    None
                )
                .is_err(),
                "{path}"
            );
        }
    }
}
