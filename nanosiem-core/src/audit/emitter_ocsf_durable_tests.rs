// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5354: the OCSF-only write (case lifecycle audit on OCSF) is the event's
//! only copy, so it is durable: a synchronous insert, and a saturated insert
//! bound is waited on (bounded) instead of failing at once.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::audit::{AuditEvent, AuditSource};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn event() -> AuditEvent {
    AuditEvent::builder(AuditSource::Case, "resolved")
        .resource("case", Some(uuid::Uuid::now_v7()), Some("nan5354".to_string()))
        .build()
}

#[tokio::test]
async fn a_saturated_bound_is_waited_on_and_then_acquired() {
    let bound = Arc::new(tokio::sync::Semaphore::new(1));
    let held = bound.clone().acquire_owned().await.unwrap();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
    });
    let permit = acquire_within(&bound, Duration::from_secs(5)).await;
    assert!(permit.is_ok(), "the permit freed within the wait must be acquired");
}

#[tokio::test]
async fn a_bound_saturated_past_the_wait_returns_an_error() {
    let bound = tokio::sync::Semaphore::new(1);
    let _held = bound.acquire().await.unwrap();
    let err = acquire_within(&bound, Duration::from_millis(50))
        .await
        .expect_err("still saturated after the wait");
    assert!(err.to_string().contains("saturated"), "{err}");
}

/// The OCSF-only write goes out with the synchronous-insert settings, so
/// ClickHouse acknowledges only once the row is in a part.
#[tokio::test]
async fn the_ocsf_only_write_is_synchronous() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let emitter = AuditEmitter::with_profile(DualPool::for_mock_clickhouse_tests(&server.uri()), true);

    emitter
        .emit_ocsf_durable_within(&[event()], Duration::from_secs(5))
        .await
        .expect("ocsf write");

    let requests = server.received_requests().await.unwrap_or_default();
    let insert = requests
        .iter()
        .find(|r| {
            String::from_utf8_lossy(&r.body).contains("ocsf_logs_system_raw")
                || r.url.query_pairs().any(|(_, v)| v.contains("ocsf_logs_system_raw"))
        })
        .expect("an INSERT into the OCSF landing table");
    let setting = |name: &str| {
        insert
            .url
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    };
    assert_eq!(setting("async_insert").as_deref(), Some("0"), "{}", insert.url);
    assert_eq!(setting("wait_end_of_query").as_deref(), Some("1"), "{}", insert.url);
}

/// A ClickHouse error on the only copy is returned, never swallowed.
#[tokio::test]
async fn a_storage_error_on_the_ocsf_only_write_is_returned() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500).set_body_string("Code: 241. DB::Exception: MEMORY_LIMIT_EXCEEDED"))
        .mount(&server)
        .await;
    let emitter = AuditEmitter::with_profile(DualPool::for_mock_clickhouse_tests(&server.uri()), true);
    emitter
        .emit_ocsf_durable_within(&[event()], Duration::from_secs(5))
        .await
        .expect_err("a failed only-copy write must be returned");
}
