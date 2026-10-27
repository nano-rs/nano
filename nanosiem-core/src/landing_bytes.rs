// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fixed LandingBytesV1 transport data for an independently guarded channel.
//! This codec grants no tenant/source/worker authority, decodes no Parquet and
//! supplies no execution witness. Its caller owns current C04 checks, process
//! termination, memory admission and durable incoming obligations.
//! Use one dedicated connected stream per request. Discard it after any error
//! or cancellation; partial frames are never safe to resume or replay here.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, future::Future, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

mod io;
pub use io::{read_request, read_response, write_request, write_response};

pub const MAX_METADATA_BYTES: usize = 4096;
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 500;
pub const MAX_CHUNK_ROWS: u64 = 10_000;
pub const MAX_ROWS: u64 = 2_000_000;
/// Mirrors the existing C01/C13 transport counter bound, not SQL authority.
pub const MAX_CREDENTIAL_REVISION: u64 = (1_u64 << 53) - 1;
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid landing byte frame")]
    Invalid,
    #[error("landing byte frame exceeds a limit")]
    Limit,
    #[error("landing byte frame identity or counts differ")]
    Mismatch,
    #[error("landing byte frame is truncated")]
    Truncated,
    #[error("landing byte frame has trailing data")]
    Trailing,
    #[error("landing byte exchange deadline exceeded")]
    Deadline,
    #[error("landing byte transport unavailable")]
    Io,
}

/// Create ONCE before the owner's guarded exchange and retain through its
/// closing current-process checks. Reusing it never starts a fresh timeout.
#[derive(Clone, Copy, Debug)]
pub struct ExchangeDeadline(Instant);
impl Default for ExchangeDeadline {
    fn default() -> Self {
        Self::new()
    }
}
impl ExchangeDeadline {
    pub fn new() -> Self {
        Self(Instant::now() + EXCHANGE_TIMEOUT)
    }
    pub fn deadline(&self) -> Instant {
        self.0
    }
    async fn run<T>(&self, work: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        if Instant::now() >= self.0 {
            return Err(Error::Deadline);
        }
        let result = tokio::time::timeout_at(self.0, work)
            .await
            .map_err(|_| Error::Deadline)?;
        if Instant::now() >= self.0 {
            return Err(Error::Deadline);
        }
        result
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Parquet,
    Ndjson,
    NdjsonGzip,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestHeader {
    pub schema_version: u8,
    pub request_id: u64,
    #[serde(with = "uuid_wire")]
    pub tenant_id: Uuid,
    #[serde(with = "uuid_wire")]
    pub source_id: Uuid,
    pub source_revision: i64,
    #[serde(with = "uuid_wire")]
    pub credential_id: Uuid,
    pub credential_revision: u64,
    pub route_key: String,
    pub format: Format,
    #[serde(deserialize_with = "required_option")]
    pub partition_class: Option<u32>,
    #[serde(with = "digest_wire")]
    pub file_sha256: [u8; 32],
    #[serde(with = "uuid_wire")]
    pub conversion_id: Uuid,
    pub received_unix_millis: u64,
}
impl RequestHeader {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1
            || [
                self.tenant_id,
                self.source_id,
                self.credential_id,
                self.conversion_id,
            ]
            .iter()
            .any(Uuid::is_nil)
            || self.source_revision <= 0
            || !(1..=MAX_CREDENTIAL_REVISION).contains(&self.credential_revision)
            || self.route_key.is_empty()
            || self.route_key.len() > 128
            || !self
                .route_key
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
            || self.partition_class.is_some_and(|class| {
                class == 0 || !crate::parsers::is_known_ocsf_class(i64::from(class))
            })
            || self.received_unix_millis == 0
            || i64::try_from(self.received_unix_millis)
                .ok()
                .and_then(DateTime::<Utc>::from_timestamp_millis)
                .is_none()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
impl fmt::Debug for RequestHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestHeader([redacted])")
    }
}

/// A correlation/hash fact only. It cannot prove who executed the request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestBinding {
    pub request_id: u64,
    pub frame_sha256: [u8; 32],
}
impl fmt::Debug for RequestBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestBinding([redacted])")
    }
}
pub struct ReceivedRequest {
    pub header: RequestHeader,
    pub bytes: Vec<u8>,
    pub binding: RequestBinding,
}
impl fmt::Debug for ReceivedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceivedRequest([redacted])")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Converted,
    Refused,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    InvalidInput,
    ConversionRefused,
    OutputLimit,
    Internal,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseSummary {
    pub schema_version: u8,
    pub request_id: u64,
    #[serde(with = "digest_wire")]
    pub request_frame_sha256: [u8; 32],
    pub outcome: Outcome,
    #[serde(deserialize_with = "required_option")]
    pub refusal_reason: Option<RefusalReason>,
    pub chunk_count: u32,
    pub rows_seen: u64,
    pub rows_accepted: u64,
    pub rows_refused: u64,
    pub rows_time_clamped: u64,
    pub rows_class_from_path: u64,
}
impl ResponseSummary {
    pub fn validate(&self) -> Result<(), Error> {
        if self.schema_version != 1 {
            return Err(Error::Invalid);
        }
        if self.chunk_count as usize > MAX_CHUNKS
            || self.rows_seen > MAX_ROWS
            || self.rows_accepted > MAX_ROWS
            || self.rows_refused > MAX_ROWS
            || self.rows_time_clamped > self.rows_accepted
            || self.rows_class_from_path > self.rows_seen
        {
            return Err(Error::Limit);
        }
        if self.rows_accepted.checked_add(self.rows_refused) != Some(self.rows_seen) {
            return Err(Error::Mismatch);
        }
        let minimum = u64::from(self.chunk_count);
        let maximum = minimum.checked_mul(MAX_CHUNK_ROWS).ok_or(Error::Limit)?;
        if self.rows_accepted < minimum || self.rows_accepted > maximum {
            return Err(Error::Mismatch);
        }
        match self.outcome {
            Outcome::Converted
                if self.chunk_count > 0
                    && self.rows_accepted > 0
                    && self.refusal_reason.is_none() =>
            {
                Ok(())
            }
            Outcome::Refused
                if self.chunk_count == 0
                    && self.rows_accepted == 0
                    && self.refusal_reason.is_some() =>
            {
                Ok(())
            }
            _ => Err(Error::Mismatch),
        }
    }
}
impl fmt::Debug for ResponseSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseSummary([redacted])")
    }
}

pub struct ChunkRef<'a> {
    pub ordinal: u32,
    pub events: u64,
    pub bytes: &'a [u8],
}
pub struct OwnedChunk {
    pub ordinal: u32,
    pub events: u64,
    pub bytes: Vec<u8>,
}
impl fmt::Debug for ChunkRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ChunkRef([redacted])")
    }
}
impl fmt::Debug for OwnedChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedChunk([redacted])")
    }
}
/// Opaque bytes and consistency facts, never validated bronze or authority.
pub struct UntrustedResponse {
    pub summary: ResponseSummary,
    pub chunks: Vec<OwnedChunk>,
    pub frame_sha256: [u8; 32],
}
impl fmt::Debug for UntrustedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UntrustedResponse([redacted])")
    }
}

fn required_option<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}
mod uuid_wire {
    use super::*;
    pub fn serialize<S: Serializer>(value: &Uuid, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
        let raw = String::deserialize(d)?;
        Uuid::parse_str(&raw)
            .ok()
            .filter(|id| !id.is_nil() && id.to_string() == raw)
            .ok_or_else(|| serde::de::Error::custom("invalid landing UUID"))
    }
}
mod digest_wire {
    use super::*;
    pub fn serialize<S: Serializer>(value: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let raw = String::deserialize(d)?;
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(serde::de::Error::custom("invalid landing digest"));
        }
        let mut out = [0; 32];
        hex::decode_to_slice(raw, &mut out)
            .map_err(|_| serde::de::Error::custom("invalid landing digest"))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
