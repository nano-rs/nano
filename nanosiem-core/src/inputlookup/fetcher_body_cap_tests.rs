// SPDX-License-Identifier: AGPL-3.0-or-later
//! `max_response_size` holds for chunked responses (security review
//! 2026-11-08, NAN-5016).

use super::*;
use crate::http_body::tests::{get, serve};

fn fetcher(max_response_size: usize) -> UrlFetcher {
    UrlFetcher::new(InputLookupConfig {
        max_response_size,
        ..Default::default()
    })
}

/// Exploit regression: before, a chunked (no Content-Length) body was read
/// whole with `bytes()` and only then compared to the cap.
#[tokio::test]
async fn chunked_body_over_max_response_size_is_rejected() {
    let (addr, _) = serve(64 * 1024, None).await; // 64 MiB offered
    let err = fetcher(1024 * 1024)
        .read_body_limited(get(addr).await)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::ResponseTooLarge { limit: 1048576, .. }),
        "{err}"
    );
}

/// Legitimate path: a chunked CSV under the cap is returned intact.
#[tokio::test]
async fn chunked_body_under_max_response_size_is_returned() {
    let (addr, _) = serve(16, None).await;
    let body = fetcher(1024 * 1024)
        .read_body_limited(get(addr).await)
        .await
        .unwrap();
    assert_eq!(body.len(), 16 * 1024);
}
