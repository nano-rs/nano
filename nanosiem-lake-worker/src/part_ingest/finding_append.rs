// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed detect[T] -> ingest[T] publication. Only ingest owns the tenant
//! `PartLogWriter`; this socket conveys already uploaded, owner-signed finding
//! parts and returns the immutable log entry used for the PG outbox ack.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::parts::part_log::{LogSchema, PartRef, SourceRef};

pub const MAX_REQUEST_BYTES: u64 = 1_048_576;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingAppendRequest {
    pub tenant_id: String,
    pub writer_epoch: u64,
    pub schema: LogSchema,
    pub parts: Vec<PartRef>,
    pub receipts: Vec<SourceRef>,
    /// Unix ms after which the requester no longer waits for the ack:
    /// ingest refuses to START the commit past it (the rows stay in the
    /// outbox) instead of committing an append nobody will acknowledge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_unix_ms: Option<i64>,
}

/// Most receipts (and parts) in one append.
pub const MAX_APPEND_RECEIPTS: usize = 512;
/// How long detect waits for an append's acknowledgement.
pub const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Detect's commit deadline: the ack timeout minus the commit's own budget.
pub const COMMIT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingAppendResponse {
    pub seq: u64,
    pub entry_sha256: String,
}

#[async_trait::async_trait]
pub trait FindingAppendTransport: Send + Sync {
    async fn submit(&self, request: &FindingAppendRequest) -> Result<FindingAppendResponse>;
}

/// One bounded request over a supervisor-provided stream. The jailed roles
/// never create AF_UNIX sockets: the supervisor checks Detect's role and
/// passes each endpoint over the existing sealed control channel.
pub async fn submit_stream(mut stream: tokio::net::UnixStream, request: &FindingAppendRequest) -> Result<FindingAppendResponse> {
    ensure!(!request.receipts.is_empty() && request.receipts.len() <= MAX_APPEND_RECEIPTS, "finding append receipt count is invalid");
    let bytes = serde_json::to_vec(request)?;
    ensure!(bytes.len() as u64 <= MAX_REQUEST_BYTES, "finding append request is too large");
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;
    let mut response = Vec::new();
    tokio::time::timeout(ACK_TIMEOUT,
        stream.take(4097).read_to_end(&mut response)).await.context("finding append acknowledgement timed out")??;
    ensure!(response.len() <= 4096, "finding append acknowledgement is too large");
    serde_json::from_slice::<FindingAppendResponse>(&response).context("finding append was not durably acknowledged")
}
