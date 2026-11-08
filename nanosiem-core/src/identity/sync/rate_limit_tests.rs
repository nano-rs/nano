// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3483: bounded 429 retry inside an identity sync.

use super::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

fn limited(secs: Option<u64>) -> SyncError {
    SyncError::RateLimited { retry_after_secs: secs }
}

#[tokio::test(start_paused = true)]
async fn retries_after_the_requested_wait_then_succeeds() {
    let calls = AtomicU32::new(0);
    let started = tokio::time::Instant::now();
    let out = retry_rate_limited(RateLimitPolicy::default(), || async {
        match calls.fetch_add(1, Ordering::SeqCst) {
            0 => Err(limited(Some(3))),
            1 => Err(limited(Some(7))),
            _ => Ok("page"),
        }
    })
    .await
    .unwrap();
    assert_eq!(out, "page");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    // Slept exactly what the provider asked for, in order.
    assert_eq!(started.elapsed(), Duration::from_secs(10));
}

#[tokio::test(start_paused = true)]
async fn gives_up_after_max_retries() {
    let calls = AtomicU32::new(0);
    let policy = RateLimitPolicy { max_retries: 2, ..Default::default() };
    let err = retry_rate_limited(policy, || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(limited(Some(1)))
    })
    .await
    .unwrap_err();
    assert!(matches!(err, SyncError::RateLimited { retry_after_secs: Some(1) }));
    assert_eq!(calls.load(Ordering::SeqCst), 3, "first attempt + 2 retries");
}

#[tokio::test(start_paused = true)]
async fn a_wait_over_the_cap_fails_now() {
    let calls = AtomicU32::new(0);
    let started = tokio::time::Instant::now();
    let err = retry_rate_limited(RateLimitPolicy::default(), || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(limited(Some(3600)))
    })
    .await
    .unwrap_err();
    assert!(matches!(err, SyncError::RateLimited { retry_after_secs: Some(3600) }));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(started.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn no_header_uses_the_default_wait_and_zero_waits_a_second() {
    let calls = AtomicU32::new(0);
    let started = tokio::time::Instant::now();
    retry_rate_limited(RateLimitPolicy::default(), || async {
        match calls.fetch_add(1, Ordering::SeqCst) {
            0 => Err(limited(None)),
            1 => Err(limited(Some(0))),
            _ => Ok(()),
        }
    })
    .await
    .unwrap();
    assert_eq!(started.elapsed(), Duration::from_secs(30 + 1));
}

#[tokio::test(start_paused = true)]
async fn other_errors_are_not_retried() {
    let calls = AtomicU32::new(0);
    let err = retry_rate_limited(RateLimitPolicy::default(), || async {
        calls.fetch_add(1, Ordering::SeqCst);
        Err::<(), _>(SyncError::AuthError("E0000011".into()))
    })
    .await
    .unwrap_err();
    assert!(matches!(err, SyncError::AuthError(_)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn wait_prefers_retry_after_then_okta_reset() {
    use reqwest::header::{HeaderMap, HeaderValue};
    let mut h = HeaderMap::new();
    h.insert("x-rate-limit-reset", HeaderValue::from_static("1000060"));
    assert_eq!(rate_limit_wait_secs(&h, 1_000_000), Some(60));
    // Reset already passed: zero, not an underflow.
    assert_eq!(rate_limit_wait_secs(&h, 2_000_000), Some(0));
    h.insert("retry-after", HeaderValue::from_static("5"));
    assert_eq!(rate_limit_wait_secs(&h, 1_000_000), Some(5));
    assert_eq!(rate_limit_wait_secs(&HeaderMap::new(), 1_000_000), None);
    let mut bad = HeaderMap::new();
    bad.insert("retry-after", HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"));
    assert_eq!(rate_limit_wait_secs(&bad, 1_000_000), None);
}
