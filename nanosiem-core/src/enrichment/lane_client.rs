// SPDX-License-Identifier: AGPL-3.0-or-later

//! Client for pushing records onto the Vector "nano_enrich" enrichment lane
//! (NAN-1151).
//!
//! Identity providers (and, later, other enrichment sources) emit raw records
//! here — tagged with a `kind` (e.g. `identity`) and `source` (e.g. `ad`,
//! `entra`) discriminator — instead of writing ClickHouse directly. The
//! repo-sourced per-source normalize VRL (NAN-1149) maps each raw shape into
//! its target enrichment table, so the field mapping lives in the parsers repo
//! rather than hard-coded in this binary.
//!
//! Wire contract (see `config/vector/04-enrichment-source.toml`): POST NDJSON
//! to the dedicated Vector enrichment source (`:8090`) with
//! `X-Source-Type: nano_enrich` and
//! `Authorization: Bearer <VECTOR_AUTH_TOKEN>`. The source validates the
//! bearer token and stamps every decoded object as `nano_enrich`; the
//! `enrichment_router` routes by `.source` to the per-source normalize
//! transforms. Public edges reject this source type on generic `/ingest` so
//! callers cannot receive a log-lane acknowledgement for enrichment data.

use serde::Serialize;
use thiserror::Error;

use crate::ingestion::{VectorIngestClient, VectorIngestError};

/// `.source_type` value the enrichment lane router claims — keeps these records
/// out of the logs pipeline (`source_router.generic` excludes `nano_enrich`).
pub const ENRICH_SOURCE_TYPE: &str = "nano_enrich";

const DEFAULT_ENRICH_URL: &str = "http://vector:8090/";

#[derive(Debug, Error)]
pub enum EnrichmentLaneError {
    #[error("enrichment lane POST failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serializing enrichment record: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl From<VectorIngestError> for EnrichmentLaneError {
    fn from(e: VectorIngestError) -> Self {
        match e {
            VectorIngestError::Http(e) => EnrichmentLaneError::Http(e),
            VectorIngestError::Serialize(e) => EnrichmentLaneError::Serialize(e),
        }
    }
}

/// Pushes pre-shaped enrichment records onto the Vector `nano_enrich` lane.
///
/// Cheap to clone (wraps a connection-pooling `reqwest::Client`). Construct once
/// (e.g. at app startup via [`EnrichmentLaneClient::from_env`]) and share.
#[derive(Clone)]
pub struct EnrichmentLaneClient {
    /// The shared Vector ingest envelope. This type exists to pin the
    /// `source_type` to [`ENRICH_SOURCE_TYPE`] so no caller can accidentally
    /// route enrichment records into the logs pipeline.
    inner: VectorIngestClient,
}

impl EnrichmentLaneClient {
    pub fn new(ingest_url: impl Into<String>, auth_token: Option<String>) -> Self {
        Self {
            inner: VectorIngestClient::new(ingest_url, auth_token),
        }
    }

    /// Build from the environment: `VECTOR_ENRICH_URL` (default
    /// `http://vector:8090/`) and `VECTOR_AUTH_TOKEN`. NAN-1151 provisions both
    /// to `nanosiem-jobs` (which schedules identity sync) and `nanosiem-api`
    /// (which can run it on demand). Without the token, protected Vector returns
    /// 401; callers should gate on [`is_configured`](Self::is_configured).
    pub fn from_env() -> Self {
        let url = std::env::var("VECTOR_ENRICH_URL")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_ENRICH_URL.to_string());
        Self::new(url, std::env::var("VECTOR_AUTH_TOKEN").ok())
    }

    /// Whether a bearer token is present. A token-protected Vector rejects
    /// unauthenticated pushes, so callers should check this before relying on
    /// the lane in a deployment where Vector enforces auth.
    pub fn is_configured(&self) -> bool {
        self.inner.is_configured()
    }

    /// POST a batch of pre-shaped enrichment records as NDJSON.
    ///
    /// Each record must already carry its `kind` + `source` discriminators plus
    /// the raw provider fields; this only frames the envelope (the
    /// `X-Source-Type: nano_enrich` header + bearer auth). An empty batch is a
    /// no-op (no request is sent).
    pub async fn push_records<T: Serialize>(
        &self,
        records: &[T],
    ) -> Result<(), EnrichmentLaneError> {
        let result = self.inner.push(ENRICH_SOURCE_TYPE, records).await;
        if let Err(VectorIngestError::Http(error)) = &result {
            if error.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
                tracing::error!(
                    error = %error,
                    "ENRICHMENT DELIVERY REFUSED: Vector returned 401; verify VECTOR_AUTH_TOKEN on nano-jobs/api and the Vector enrichment source"
                );
            } else if error.is_connect() {
                tracing::error!(
                    error = %error,
                    "ENRICHMENT DELIVERY UNREACHABLE: cannot connect to the dedicated Vector listener; verify VECTOR_ENRICH_URL and port 8090 exposure"
                );
            }
        }
        result.map_err(EnrichmentLaneError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::to_ndjson;
    use serde_json::json;

    #[test]
    fn to_ndjson_is_newline_delimited_no_trailing_newline() {
        let recs = vec![
            json!({"kind": "identity", "source": "ad", "external_id": "S-1-5-21-1"}),
            json!({"kind": "identity", "source": "ad", "external_id": "S-1-5-21-2"}),
        ];
        let body = to_ndjson(&recs).unwrap();
        let lines: Vec<&str> = body.split('\n').collect();
        assert_eq!(lines.len(), 2, "one line per record, no trailing newline");
        // Each line is a standalone JSON object carrying the discriminators.
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["kind"], "identity");
            assert_eq!(v["source"], "ad");
        }
    }

    #[test]
    fn to_ndjson_empty_is_empty_string() {
        let recs: Vec<serde_json::Value> = vec![];
        assert_eq!(to_ndjson(&recs).unwrap(), "");
    }

    #[test]
    fn empty_token_is_treated_as_unconfigured() {
        assert!(
            !EnrichmentLaneClient::new("http://vector:8080/", Some(String::new())).is_configured()
        );
        assert!(!EnrichmentLaneClient::new("http://vector:8080/", None).is_configured());
        assert!(
            EnrichmentLaneClient::new("http://vector:8080/", Some("tok".into())).is_configured()
        );
    }
}
