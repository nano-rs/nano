// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transport to the tenant Worker's edge-log consumer route.
//!
//! The credential is the tenant's edge-log consumer token only: it cannot
//! ingest, administer, delete or write R2. The cell supervisor delivers it to
//! `ingest[T]` over an fd (phase 5); the lab reads a 0600 file.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use std::time::Duration;
use zeroize::Zeroizing;

use super::protocol::{
    decode_pull, CommitOutcome, CommitRequest, KindBody, Lease, PullOutcome, MAX_PULL_BYTES, MAX_PULL_RESPONSE_BYTES,
    MAX_PULL_SEGMENTS,
};

/// The three calls `EdgeLogSource` needs. A fake implements it in tests.
#[async_trait]
pub trait EdgeLogTransport: Send + Sync {
    /// `at`: the consumer's resume point; the lease reports the DO's chain there.
    async fn lease(&self, consumer_id: &str, at: Option<u64>) -> Result<Lease>;
    async fn pull(&self, epoch: u64, after: u64, max_bytes: u64, max_segments: u32) -> Result<PullOutcome>;
    async fn commit(&self, request: &CommitRequest) -> Result<CommitOutcome>;
}

/// HTTPS client for `https://<tenant>.ingest.nano.rs/edge-log/v1/*`.
pub struct HttpEdgeLogClient {
    base: reqwest::Url,
    /// Swappable: the cell supervisor refreshes the consumer credential
    /// (`set_token`) without rebuilding the client or the source.
    token: std::sync::RwLock<Zeroizing<String>>,
    http: reqwest::Client,
}

impl std::fmt::Debug for HttpEdgeLogClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpEdgeLogClient").field("base", &self.base.as_str()).finish_non_exhaustive()
    }
}

impl HttpEdgeLogClient {
    /// `base` is the tenant Worker origin, e.g. `https://acme.ingest.nano.rs`.
    /// Plain `http` is accepted only for loopback (`wrangler dev`, tests).
    pub fn new(base: &str, token: Zeroizing<String>) -> Result<Self> {
        let base = reqwest::Url::parse(base).context("edge log base URL is invalid")?;
        let loopback = matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
        if base.scheme() != "https" && !(base.scheme() == "http" && loopback) {
            bail!("edge log base URL must be https");
        }
        check_token(&token)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { base, token: std::sync::RwLock::new(token), http })
    }

    /// Replace the consumer credential (rotation); later requests use it.
    pub fn set_token(&self, token: Zeroizing<String>) -> Result<()> {
        check_token(&token)?;
        *self.token.write().map_err(|_| anyhow::anyhow!("edge log token lock is poisoned"))? = token;
        Ok(())
    }

    /// Read the token from a file that only the owner can read.
    pub fn from_token_file(base: &str, path: &std::path::Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).context("edge log token file is unreadable")?.permissions().mode();
            if mode & 0o077 != 0 {
                bail!("edge log token file must not be readable by group or others");
            }
        }
        let raw = Zeroizing::new(std::fs::read_to_string(path).context("edge log token file is unreadable")?);
        Self::new(base, Zeroizing::new(raw.trim().to_string()))
    }

    fn url(&self, action: &str) -> Result<reqwest::Url> {
        Ok(self.base.join(&format!("/edge-log/v1/{action}"))?)
    }

    async fn post(&self, action: &str, body: serde_json::Value) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let bearer = Zeroizing::new(
            self.token.read().map_err(|_| anyhow::anyhow!("edge log token lock is poisoned"))?.as_str().to_string(),
        );
        let response = self
            .http
            .post(self.url(action)?)
            .bearer_auth(bearer.as_str())
            .json(&body)
            .send()
            .await
            .with_context(|| format!("edge log {action} request failed"))?;
        let status = response.status();
        let mut stream = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("edge log {action} response failed"))?;
            if bytes.len() + chunk.len() > MAX_PULL_RESPONSE_BYTES {
                bail!("edge log {action} response exceeds its bound");
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }
}

fn check_token(token: &str) -> Result<()> {
    if token.trim().is_empty() || token.contains(char::is_whitespace) {
        bail!("edge log consumer token is empty or malformed");
    }
    Ok(())
}

fn refused(action: &str, status: reqwest::StatusCode) -> anyhow::Error {
    // Never echo the body: it is provider text, not ours.
    anyhow::anyhow!("edge log {action} refused with HTTP {status}")
}

#[async_trait]
impl EdgeLogTransport for HttpEdgeLogClient {
    async fn lease(&self, consumer_id: &str, at: Option<u64>) -> Result<Lease> {
        let mut request = serde_json::json!({ "consumerId": consumer_id });
        if let Some(at) = at {
            request["at"] = serde_json::json!(at);
        }
        let (status, body) = self.post("lease", request).await?;
        if status != reqwest::StatusCode::OK {
            return Err(refused("lease", status));
        }
        let lease: Lease = serde_json::from_slice(&body).context("edge log lease does not parse")?;
        if lease.kind != "ok" {
            bail!("edge log lease kind is {}", lease.kind);
        }
        Ok(lease)
    }

    async fn pull(&self, epoch: u64, after: u64, max_bytes: u64, max_segments: u32) -> Result<PullOutcome> {
        let body = serde_json::json!({
            "epoch": epoch,
            "after": after,
            "maxBytes": max_bytes.clamp(1, MAX_PULL_BYTES),
            "maxSegments": max_segments.clamp(1, MAX_PULL_SEGMENTS),
        });
        let (status, bytes) = self.post("pull", body).await?;
        match status.as_u16() {
            200 => Ok(PullOutcome::Batch(decode_pull(&bytes, after)?)),
            503 => Ok(PullOutcome::Busy),
            409 => {
                let kind: KindBody = serde_json::from_slice(&bytes).context("edge log pull refusal does not parse")?;
                match kind.kind.as_str() {
                    "fenced" => Ok(PullOutcome::Fenced),
                    "behind" => Ok(PullOutcome::Behind {
                        committed_through: kind.committed_through.unwrap_or(0),
                        committed_chain: kind.committed_chain.unwrap_or_default(),
                    }),
                    other => bail!("edge log pull refused: {other}"),
                }
            }
            _ => Err(refused("pull", status)),
        }
    }

    async fn commit(&self, request: &CommitRequest) -> Result<CommitOutcome> {
        let (status, bytes) = self.post("commit", serde_json::to_value(request)?).await?;
        if !matches!(status.as_u16(), 200 | 409) {
            return Err(refused("commit", status));
        }
        let kind: KindBody = serde_json::from_slice(&bytes).context("edge log commit response does not parse")?;
        Ok(match kind.kind.as_str() {
            "ok" => CommitOutcome::Committed,
            "replay" => CommitOutcome::Replayed,
            "fenced" => CommitOutcome::Fenced,
            "conflict" => CommitOutcome::Conflict { committed_through: kind.committed_through.unwrap_or(0) },
            other => bail!("edge log commit returned {other}"),
        })
    }
}
