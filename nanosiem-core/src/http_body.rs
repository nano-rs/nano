// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded reads of HTTP response bodies from servers we do not control
//! (security review 2026-11-08).
//!
//! `reqwest::Response::bytes()` / `text()` buffer the WHOLE body before the
//! caller can look at its size. A `Content-Length` check only helps when the
//! server sends one: a chunked response streams for as long as the request
//! timeout allows, and the process holds every byte. Every fetch of a
//! tenant-configured or remote URL reads through these helpers instead, which
//! stop as soon as the running byte count passes the cap.

use reqwest::Response;

/// Why a bounded body read failed.
#[derive(Debug, thiserror::Error)]
pub enum BodyReadError {
    /// The body is larger than the cap. `observed` is the declared
    /// `Content-Length` when the server sent one, otherwise the number of
    /// bytes read before the read stopped (always > `limit`).
    #[error("response body exceeds the {limit}-byte limit (at least {observed} bytes)")]
    TooLarge { limit: usize, observed: u64 },
    /// The connection failed while reading the body.
    #[error("failed to read response body: {0}")]
    Transport(#[from] reqwest::Error),
}

/// Read the whole body, failing with [`BodyReadError::TooLarge`] as soon as it
/// is known to exceed `limit` bytes: up front from `Content-Length`, otherwise
/// the moment the streamed total passes the cap. At most `limit` bytes plus one
/// network chunk are ever held.
pub async fn read_capped(mut response: Response, limit: usize) -> Result<Vec<u8>, BodyReadError> {
    if let Some(declared) = response.content_length() {
        if declared > limit as u64 {
            return Err(BodyReadError::TooLarge {
                limit,
                observed: declared,
            });
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        let total = body.len() + chunk.len();
        if total > limit {
            return Err(BodyReadError::TooLarge {
                limit,
                observed: total as u64,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Read at most `limit` bytes of the body and drop the rest, never failing.
/// For error excerpts and diagnostics, where a partial body is still useful and
/// a transport error just ends the excerpt. Decoded lossily, so the result is
/// always valid UTF-8 of at most `limit` bytes plus replacement characters.
pub async fn read_prefix_lossy(mut response: Response, limit: usize) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < limit {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = (limit - buf.len()).min(chunk.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            Ok(None) | Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
#[path = "http_body_tests.rs"]
pub(crate) mod tests;
