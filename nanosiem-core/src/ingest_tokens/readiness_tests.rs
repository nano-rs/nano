// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5395: what the issue / rotate call reports about a new token on ingest.
//! Paused tokio time.

use std::time::Duration;

use super::*;

const SETTLE: Duration = Duration::from_millis(2_100);

#[test]
fn wait_budget_parses_and_clamps() {
    assert_eq!(ready_wait_from(None), DEFAULT_READY_WAIT);
    assert_eq!(ready_wait_from(Some("  ")), DEFAULT_READY_WAIT);
    assert_eq!(ready_wait_from(Some("nope")), DEFAULT_READY_WAIT);
    assert_eq!(ready_wait_from(Some("-1")), DEFAULT_READY_WAIT);
    assert_eq!(ready_wait_from(Some("0")), Duration::ZERO);
    assert_eq!(ready_wait_from(Some("5")), Duration::from_secs(5));
    assert_eq!(ready_wait_from(Some("3600")), MAX_READY_WAIT);
}

#[tokio::test(start_paused = true)]
async fn shared_volume_waits_one_reread_interval_then_is_ready() {
    let readiness = wait_for_ingest(TokenDelivery::SharedVolume, DEFAULT_READY_WAIT, SETTLE).await;
    assert!(readiness.ready);
    assert_eq!(readiness.delivery, TokenDelivery::SharedVolume);
    assert_eq!(readiness.waited_ms, SETTLE.as_millis() as u64);
    assert_eq!(readiness.retry_after_secs, None);
    let json = serde_json::to_value(&readiness).unwrap();
    assert_eq!(json["delivery"], "shared_volume");
    assert!(json.get("retry_after_secs").is_none());
}

/// Review P1: nano-api cannot see when each pulling ingest host installed the
/// file, so `http` never reports ready, and it does not wait or poll either.
#[tokio::test(start_paused = true)]
async fn http_never_claims_ready_and_returns_at_once() {
    let started = tokio::time::Instant::now();
    let readiness = wait_for_ingest(TokenDelivery::Http, MAX_READY_WAIT, SETTLE).await;
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert!(!readiness.ready);
    assert_eq!(readiness.delivery, TokenDelivery::Http);
    assert_eq!(readiness.waited_ms, 0);
    assert_eq!(readiness.retry_after_secs, Some(NOT_READY_RETRY_AFTER_SECS));
}

#[tokio::test(start_paused = true)]
async fn no_delivery_is_never_ready() {
    let readiness = wait_for_ingest(TokenDelivery::None, DEFAULT_READY_WAIT, SETTLE).await;
    assert!(!readiness.ready);
    assert_eq!(readiness.waited_ms, 0);
    assert_eq!(readiness.retry_after_secs, Some(NOT_READY_RETRY_AFTER_SECS));
}

/// A budget below the re-read interval (including `0` = do not wait) returns
/// at once with a retry hint instead of a premature `ready`.
#[tokio::test(start_paused = true)]
async fn a_budget_below_the_settle_returns_at_once_not_ready() {
    for budget in [Duration::ZERO, Duration::from_secs(2)] {
        let readiness = wait_for_ingest(TokenDelivery::SharedVolume, budget, SETTLE).await;
        assert!(!readiness.ready, "{budget:?}");
        assert_eq!(readiness.waited_ms, 0, "{budget:?}");
        assert_eq!(readiness.retry_after_secs, Some(NOT_READY_RETRY_AFTER_SECS));
    }
}

/// Review P2: the budget is a hard upper bound for every delivery, even when
/// the settle interval itself would run past it.
#[tokio::test(start_paused = true)]
async fn a_call_never_exceeds_its_budget() {
    let budget = Duration::from_secs(3);
    for delivery in [TokenDelivery::SharedVolume, TokenDelivery::Http, TokenDelivery::None] {
        for settle in [SETTLE, budget, Duration::from_secs(60)] {
            let started = tokio::time::Instant::now();
            let readiness = wait_for_ingest(delivery, budget, settle).await;
            assert!(started.elapsed() <= budget, "{delivery:?} {settle:?}");
            assert!(readiness.waited_ms <= budget.as_millis() as u64);
            // `ready` only ever after the full re-read interval.
            if readiness.ready {
                assert!(started.elapsed() >= settle, "{delivery:?} {settle:?}");
            }
        }
    }
}
