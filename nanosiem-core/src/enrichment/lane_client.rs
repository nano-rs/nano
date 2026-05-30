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
//! Wire contract (see `config/vector/00-base.toml`): POST NDJSON to the Vector
//! HTTP ingest source (`:8080`) with `X-Source-Type: nano_enrich` and
//! `Authorization: Bearer <VECTOR_AUTH_TOKEN>`. The `auth_check` transform
//! validates the bearer token and the `enrichment_router` claims
//! `source_type == "nano_enrich"`, routing by `.source` to the per-source
//! normalize transforms.

use serde::Serialize;
use thiserror::Error;

/// `.source_type` value the enrichment lane router claims — keeps these records
/// out of the logs pipeline (`source_router.generic` excludes `nano_enrich`).
pub const ENRICH_SOURCE_TYPE: &str = "nano_enrich";

/// Default ingest endpoint when `VECTOR_INGEST_URL` is unset. Matches the
/// in-cluster Vector service (a separate pod — never loopback); dev overrides
/// to `http://localhost:8080/` via the env var.
const DEFAULT_INGEST_URL: &str = "http://vector:8080/";

#[derive(Debug, Error)]
pub enum EnrichmentLaneError {
    #[error("enrichment lane POST failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serializing enrichment record: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Pushes pre-shaped enrichment records onto the Vector `nano_enrich` lane.
///
/// Cheap to clone (wraps a connection-pooling `reqwest::Client`). Construct once
/// (e.g. at app startup via [`EnrichmentLaneClient::from_env`]) and share.
#[derive(Clone)]
pub struct EnrichmentLaneClient {
    http: reqwest::Client,
    ingest_url: String,
    /// Bearer token for the Vector ingest source. `None` posts unauthenticated,
    /// which only succeeds against a Vector whose `VECTOR_AUTH_TOKEN` is also
    /// unset (its `auth_check` then reports `auth_status = "skipped"`).
    auth_token: Option<String>,
}

impl EnrichmentLaneClient {
    pub fn new(ingest_url: impl Into<String>, auth_token: Option<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            ingest_url: ingest_url.into(),
            // Treat an empty token the same as unset so a blank env var doesn't
            // send `Authorization: Bearer ` (which Vector would reject).
            auth_token: auth_token.filter(|t| !t.is_empty()),
        }
    }

    /// Build from the environment: `VECTOR_INGEST_URL` (default
    /// `http://vector:8080/`) and `VECTOR_AUTH_TOKEN`. NAN-1151 provisions both
    /// to `nanosiem-api` (where the identity-sync scheduler runs); without the
    /// token, pushes to a token-protected Vector will 401 — callers should gate
    /// on [`is_configured`](Self::is_configured) and surface that rather than
    /// drop enrichment data silently.
    pub fn from_env() -> Self {
        let url = std::env::var("VECTOR_INGEST_URL")
            .ok()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_INGEST_URL.to_string());
        let token = std::env::var("VECTOR_AUTH_TOKEN").ok();
        Self::new(url, token)
    }

    /// Whether a bearer token is present. A token-protected Vector rejects
    /// unauthenticated pushes, so callers should check this before relying on
    /// the lane in a deployment where Vector enforces auth.
    pub fn is_configured(&self) -> bool {
        self.auth_token.is_some()
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
        if records.is_empty() {
            return Ok(());
        }
        let body = to_ndjson(records)?;
        let mut req = self
            .http
            .post(&self.ingest_url)
            .header("Content-Type", "application/x-ndjson")
            .header("X-Source-Type", ENRICH_SOURCE_TYPE)
            .body(body);
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        req.send().await?.error_for_status()?;
        Ok(())
    }
}

/// Frame records as newline-delimited JSON (one compact JSON object per line).
/// Pure helper so the envelope shape is unit-testable without a live Vector.
fn to_ndjson<T: Serialize>(records: &[T]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for (i, rec) in records.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&serde_json::to_string(rec)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(!EnrichmentLaneClient::new("http://vector:8080/", Some(String::new())).is_configured());
        assert!(!EnrichmentLaneClient::new("http://vector:8080/", None).is_configured());
        assert!(
            EnrichmentLaneClient::new("http://vector:8080/", Some("tok".into())).is_configured()
        );
    }
}
