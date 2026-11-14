// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5354: an audit event is written once, to the active profile's store.
//! On an OCSF install it lands only in `ocsf_logs` (through the
//! `ocsf_logs_system_raw` landing); on a UDM install only in `logs`.
//!
//! The real emitter runs against a mock ClickHouse HTTP endpoint that accepts
//! every statement and records it, so the test sees exactly which tables the
//! emitter inserted into, for both the routine (async-insert) path and the
//! durable outbox-drainer delivery path.

use super::*;
use crate::audit::{AuditEvent, AuditSource};
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

const UDM_TABLE: &str = "nanosiem.logs";
const OCSF_LANDING: &str = "nanosiem.ocsf_logs_system_raw";

async fn mock_clickhouse() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

/// Every INSERT statement the emitter sent (URL `query=` or request body).
async fn inserts(server: &MockServer) -> Vec<String> {
    let mut out = Vec::new();
    for req in server.received_requests().await.unwrap_or_default() {
        let mut text = String::new();
        for (k, v) in req.url.query_pairs() {
            if k == "query" {
                text.push_str(&v);
                text.push('\n');
            }
        }
        text.push_str(&String::from_utf8_lossy(&req.body));
        if text.contains("INSERT INTO") {
            out.push(text);
        }
    }
    out
}

fn wrote_to(statements: &[String], table: &str) -> bool {
    // Match the table name exactly: `nanosiem.logs` must not match on
    // `nanosiem.logs_…` or `ocsf_logs…`.
    statements.iter().any(|s| {
        s.match_indices(&format!("INSERT INTO {table}")).any(|(i, m)| {
            let rest = &s[i + m.len()..];
            !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        })
    })
}

fn event() -> AuditEvent {
    AuditEvent::builder(AuditSource::Detection, "rule_created")
        .actor(Some(uuid::Uuid::now_v7()), Some("analyst".to_string()))
        .resource("rule", Some(uuid::Uuid::now_v7()), Some("nan5354".to_string()))
        .build()
}

#[tokio::test]
async fn ocsf_install_writes_the_audit_event_only_to_ocsf_logs() {
    let server = mock_clickhouse().await;
    let emitter = AuditEmitter::with_profile(DualPool::for_mock_clickhouse_tests(&server.uri()), true);

    emitter.emit(&event()).await.expect("emit");

    let sent = inserts(&server).await;
    assert!(wrote_to(&sent, OCSF_LANDING), "OCSF row not written: {sent:?}");
    assert!(!wrote_to(&sent, UDM_TABLE), "UDM logs row must not be written on OCSF: {sent:?}");
    assert_eq!(sent.len(), 1, "exactly one write per event: {sent:?}");
}

#[tokio::test]
async fn udm_install_still_writes_the_audit_event_to_logs() {
    let server = mock_clickhouse().await;
    let emitter = AuditEmitter::with_profile(DualPool::for_mock_clickhouse_tests(&server.uri()), false);

    emitter.emit(&event()).await.expect("emit");

    let sent = inserts(&server).await;
    assert!(wrote_to(&sent, UDM_TABLE), "UDM row not written: {sent:?}");
    assert!(!wrote_to(&sent, OCSF_LANDING), "no OCSF row on UDM: {sent:?}");
    assert_eq!(sent.len(), 1, "exactly one write per event: {sent:?}");
}

/// The case lifecycle emitter (enterprise) writes through
/// `emit_ocsf_durable` on OCSF; it must reach `ocsf_logs` and never `logs`.
#[tokio::test]
async fn ocsf_only_write_targets_ocsf_logs_and_is_a_noop_on_udm() {
    let server = mock_clickhouse().await;
    let pool = DualPool::for_mock_clickhouse_tests(&server.uri());

    AuditEmitter::with_profile(pool.clone(), false)
        .emit_ocsf_durable(&[event()])
        .await
        .expect("udm no-op");
    assert!(inserts(&server).await.is_empty(), "nothing written on UDM");

    AuditEmitter::with_profile(pool, true)
        .emit_ocsf_durable(&[event()])
        .await
        .expect("ocsf write");
    let sent = inserts(&server).await;
    assert!(wrote_to(&sent, OCSF_LANDING), "{sent:?}");
    assert!(!wrote_to(&sent, UDM_TABLE), "{sent:?}");
}
