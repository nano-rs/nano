// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact object reads with a provider identity fence (NAN-3861).
//!
//! A reader that already holds an object's admitted byte length, SHA-256 and
//! strong ETag reads it with an If-Match GET and refuses any byte, length or
//! identity drift. Nothing here writes, deletes or needs a writer authority,
//! so open code (generation hydration, OTLP mirrors) uses it directly; the
//! hosted append-only writer builds on the same identity.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use opendal::{Metadata, Operator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Provider identity of one object read or written exactly.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectIdentity {
    pub version_id: String,
    pub etag: String,
    pub size_bytes: u64,
    pub sha256: String,
    /// Digest of the exact serialized-writer permit/commit authority. Reads
    /// from an ordinary object store have no such receipt.
    pub writer_authority_sha256: Option<String>,
}

pub fn strong_etag(metadata: &Metadata) -> Result<&str> {
    metadata
        .etag()
        .filter(|etag| {
            (3..=1_024).contains(&etag.len())
                && etag.starts_with('"')
                && etag.ends_with('"')
                && !etag[1..etag.len() - 1].contains('"')
                && !etag.chars().any(char::is_control)
        })
        .context("enterprise_shared R2 metadata omitted a strong authoritative ETag")
}

pub fn metadata_provider_identity(metadata: &Metadata) -> Result<(String, String)> {
    let etag = strong_etag(metadata)?.to_string();
    let version_id = metadata
        .version()
        .filter(|version| !version.is_empty() && *version != "null")
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "r2-etag-sha256:{}",
                hex::encode(Sha256::digest(etag.as_bytes()))
            )
        });
    Ok((version_id, etag))
}

pub(crate) fn identity(metadata: &Metadata, sha256: String) -> Result<ObjectIdentity> {
    let (version_id, etag) = metadata_provider_identity(metadata)?;
    Ok(ObjectIdentity {
        version_id,
        etag,
        size_bytes: metadata.content_length(),
        sha256,
        writer_authority_sha256: None,
    })
}

pub async fn read_exact(
    operator: &Operator,
    key: &str,
    expected_bytes: u64,
    expected_sha256: Option<&str>,
    expected_etag: Option<&str>,
) -> Result<(Vec<u8>, ObjectIdentity)> {
    let mut body = Vec::new();
    let identity = read_exact_stream(operator, key, expected_bytes, expected_sha256, expected_etag, |chunk| {
        body.extend_from_slice(&chunk);
        std::future::ready(Ok(()))
    }).await?;
    Ok((body, identity))
}

/// Receive into private staging with bounded transport buffers. The sink must
/// discard its candidate on ANY error, including the final identity fence.
/// Only this layer hashes the R2 body; consumers use the returned digest.
pub async fn read_exact_stream<F, Fut>(
    operator: &Operator,
    key: &str,
    expected_bytes: u64,
    expected_sha256: Option<&str>,
    expected_etag: Option<&str>,
    mut receive: F,
) -> Result<ObjectIdentity>
where
    F: FnMut(Bytes) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if key.is_empty() || expected_bytes == 0 {
        bail!("enterprise_shared R2 read identity is empty");
    }
    use opendal::raw::{oio::Read, Access, OpRead};
    // Discovery/ledger identities already fence the GET. Without one, establish
    // it with HEAD before reading. Never retry a mismatch against a newer ETag.
    let etag = if let Some(etag) = expected_etag {
        let metadata = Metadata::new(opendal::EntryMode::FILE).with_etag(etag.to_owned());
        strong_etag(&metadata)?.to_owned()
    } else {
        let metadata = operator.stat(key).await.context("HEAD R2 read identity")?;
        if metadata.content_length() != expected_bytes {
            bail!("enterprise_shared R2 object differs from its admitted byte length");
        }
        strong_etag(&metadata)?.to_owned()
    };
    // The raw accessor retains the operator's transport/retry/metrics layers and
    // exposes GET metadata that the convenience read API discards.
    let result = operator
        .inner()
        .read(
            &opendal::raw::normalize_path(key),
            OpRead::default().with_if_match(&etag),
        )
        .await;
    let (response, mut reader) = match result {
        Ok(result) => result,
        Err(error) => {
            if error.kind() == opendal::ErrorKind::ConditionNotMatch {
                let _ = operator.stat(key).await;
            }
            return Err(error).context("If-Match read enterprise_shared R2 object");
        }
    };
    let mut digest = Sha256::new();
    let mut received = 0_u64;
    loop {
        let buffer = reader.read().await.context("read exact R2 response body")?;
        if buffer.is_empty() { break; }
        for chunk in buffer {
            received = received.checked_add(chunk.len() as u64).context("R2 response length overflow")?;
            if received > expected_bytes { bail!("enterprise_shared R2 response exceeds its admitted byte length"); }
            digest.update(&chunk);
            receive(chunk).await?;
        }
    }
    let digest = hex::encode(digest.finalize());
    if received != expected_bytes || expected_sha256.is_some_and(|expected| expected != digest) {
        bail!("enterprise_shared R2 object failed its byte length or SHA-256 fence");
    }
    let metadata = match response.into_metadata() {
        Some(metadata) if metadata.etag().is_some() => metadata,
        // Providers without response identity retain the verification HEAD.
        _ => operator
            .stat(key)
            .await
            .context("HEAD R2 response without ETag")?,
    };
    if metadata.content_length() != expected_bytes || strong_etag(&metadata)? != etag {
        let _ = operator.stat(key).await;
        bail!("enterprise_shared R2 object changed during exact read");
    }
    identity(&metadata, digest)
}
