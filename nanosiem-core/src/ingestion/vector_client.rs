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
//! `Authorization: Bearer <token>`. The source authenticates the token before
//! any router claims the event.
//!
//! NAN-4907: source-bound ingest tokens decide the source, so a sender's
//! `X-Source-Type` routes only for a multiplex credential. The platform's own
//! senders post many types over one client, so they authenticate with the
//! platform credential (`NANO_PLATFORM_INGEST_TOKEN`, a random secret only
//! nano-api / nano-jobs hold, never derived from `VECTOR_AUTH_TOKEN`), which
//! nano-api lists in Vector's tokens file as a multiplex credential. If Vector
//! refuses it (401: no tokens file on this deployment, which then must opt into
//! the static install-token fallback) the client retries once with the install
//! token.

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
    /// Bearer tokens for the Vector ingest source, tried in order on a 401:
    /// the platform pull credential, then the install token. Empty posts
    /// unauthenticated, which only succeeds against a Vector that is *also*
    /// tokenless **and** has explicitly opted into unauthenticated ingest
    /// (`VECTOR_ALLOW_UNAUTHENTICATED_INGEST=true`); otherwise the source
    /// refuses the push (NAN-1351).
    auth_tokens: Vec<String>,
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
            auth_tokens: Self::bearer_candidates(
                crate::ingest_tokens::secret_from_env(crate::ingest_tokens::PLATFORM_TOKEN_ENV),
                auth_token,
            ),
        }
    }

    /// Replaces the platform credential (tests; production reads
    /// `NANO_PLATFORM_INGEST_TOKEN`).
    pub fn with_platform_token(mut self, platform: Option<String>, install: Option<String>) -> Self {
        self.auth_tokens = Self::bearer_candidates(platform, install);
        self
    }

    /// The bearers tried in order: the platform credential, then the install
    /// token (accepted only where the deployment opted into the static
    /// fallback, or in legacy multiplex mode).
    fn bearer_candidates(platform: Option<String>, install: Option<String>) -> Vec<String> {
        [platform, install]
            .into_iter()
            .flatten()
            .filter(|t| !t.trim().is_empty())
            .fold(Vec::with_capacity(2), |mut acc, t| {
                if !acc.contains(&t) {
                    acc.push(t);
                }
                acc
            })
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
        !self.auth_tokens.is_empty()
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
        let request = |token: Option<&String>| {
            let req = self
                .http
                .post(&self.ingest_url)
                .header("Content-Type", "application/x-ndjson")
                .header("X-Source-Type", source_type)
                .body(body.clone());
            match token {
                Some(token) => req.bearer_auth(token),
                None => req,
            }
        };
        let mut tokens = self.auth_tokens.iter().peekable();
        loop {
            let token = tokens.next();
            let response = request(token).send().await?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED && tokens.peek().is_some() {
                continue;
            }
            response.error_for_status()?;
            return Ok(());
        }
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
    fn platform_credential_is_tried_before_the_install_token() {
        let client = VectorIngestClient::new("http://vector:8080/", None)
            .with_platform_token(Some("platform".into()), Some("install".into()));
        assert_eq!(client.auth_tokens, vec!["platform".to_string(), "install".to_string()]);
        // Never derived from the install token.
        let client = VectorIngestClient::new("http://vector:8080/", None)
            .with_platform_token(None, Some("install".into()));
        assert_eq!(client.auth_tokens, vec!["install".to_string()]);
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
