// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generic client for POSTing NDJSON onto the Vector HTTP ingest source.
//!
//! Several subsystems push events into Vector rather than writing ClickHouse
//! directly — the enrichment lane (NAN-1151), operational telemetry, and
//! collector integrations (NAN-2189). They differ only in the `X-Source-Type`
//! they claim, so the envelope lives here once.
//!
//! Wire contract (see `config/vector/00-base.toml`): POST NDJSON to the Vector
//! HTTP ingest source (`:8080`) with `X-Source-Type: <type>` and
//! `Authorization: Bearer <VECTOR_AUTH_TOKEN>`. The `auth_check` transform
//! validates the bearer token before any router claims the event.

use serde::Serialize;
use thiserror::Error;

/// Default ingest endpoint when `VECTOR_INGEST_URL` is unset. Matches the
/// in-cluster Vector service (a separate pod — never loopback); dev overrides
/// to `http://localhost:8080/` via the env var.
const DEFAULT_INGEST_URL: &str = "http://vector:8080/";

#[derive(Debug, Error)]
pub enum VectorIngestError {
    #[error("vector ingest POST failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("serializing ingest record: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Posts NDJSON batches to the Vector HTTP ingest source under a caller-chosen
/// `source_type`.
///
/// Cheap to clone (wraps a connection-pooling `reqwest::Client`). Construct
/// once and share.
#[derive(Clone)]
pub struct VectorIngestClient {
    http: reqwest::Client,
    ingest_url: String,
    /// Bearer token for the Vector ingest source. `None` posts
    /// unauthenticated, which only succeeds against a Vector that is *also*
    /// tokenless **and** has explicitly opted into unauthenticated ingest
    /// (`VECTOR_ALLOW_UNAUTHENTICATED_INGEST=true`); otherwise `auth_check`
    /// fails closed and aborts the push (NAN-1351).
    auth_token: Option<String>,
}

impl VectorIngestClient {
    pub fn new(ingest_url: impl Into<String>, auth_token: Option<String>) -> Self {
        Self::with_timeout(ingest_url, auth_token, std::time::Duration::from_secs(30))
    }

    /// Same, with an explicit request timeout. Collector batches are far larger
    /// than enrichment batches, so their caller wants a longer ceiling than the
    /// 30s default.
    pub fn with_timeout(
        ingest_url: impl Into<String>,
        auth_token: Option<String>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            ingest_url: ingest_url.into(),
            // Treat an empty token the same as unset so a blank env var doesn't
            // send `Authorization: Bearer ` (which Vector would reject).
            auth_token: auth_token.filter(|t| !t.is_empty()),
        }
    }

    /// Build from the environment: `VECTOR_INGEST_URL` (default
    /// `http://vector:8080/`) and `VECTOR_AUTH_TOKEN`.
    pub fn from_env() -> Self {
        Self::new(Self::url_from_env(), std::env::var("VECTOR_AUTH_TOKEN").ok())
    }

    pub fn url_from_env() -> String {
        std::env::var("VECTOR_INGEST_URL")
            .ok()
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| DEFAULT_INGEST_URL.to_string())
    }

    /// Whether a bearer token is present. A token-protected Vector rejects
    /// unauthenticated pushes, so callers should check this before relying on
    /// the lane in a deployment where Vector enforces auth.
    pub fn is_configured(&self) -> bool {
        self.auth_token.is_some()
    }

    /// POST a batch of pre-shaped records as NDJSON under `source_type`.
    ///
    /// An empty batch is a no-op (no request is sent).
    pub async fn push<T: Serialize>(
        &self,
        source_type: &str,
        records: &[T],
    ) -> Result<(), VectorIngestError> {
        if records.is_empty() {
            return Ok(());
        }
        self.push_ndjson(source_type, to_ndjson(records)?).await
    }

    /// POST an already-framed NDJSON body. Lets a caller that received JSON
    /// from elsewhere avoid a deserialize/reserialize round trip.
    pub async fn push_ndjson(
        &self,
        source_type: &str,
        body: String,
    ) -> Result<(), VectorIngestError> {
        if body.is_empty() {
            return Ok(());
        }
        let mut req = self
            .http
            .post(&self.ingest_url)
            .header("Content-Type", "application/x-ndjson")
            .header("X-Source-Type", source_type)
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
pub fn to_ndjson<T: Serialize>(records: &[T]) -> Result<String, serde_json::Error> {
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
        let recs = vec![json!({"a": 1}), json!({"a": 2})];
        let body = to_ndjson(&recs).unwrap();
        assert_eq!(body.split('\n').count(), 2);
        assert!(!body.ends_with('\n'));
    }

    #[test]
    fn to_ndjson_empty_is_empty_string() {
        let recs: Vec<serde_json::Value> = vec![];
        assert_eq!(to_ndjson(&recs).unwrap(), "");
    }

    #[test]
    fn blank_token_is_treated_as_unset() {
        let client = VectorIngestClient::new("http://vector:8080/", Some(String::new()));
        assert!(
            !client.is_configured(),
            "a blank VECTOR_AUTH_TOKEN must not produce `Authorization: Bearer `"
        );
    }
}
