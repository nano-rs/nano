// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5362: the checked audit write path the Agent Lane query-audit
//! harvester uses in production (`emit_batch_checked`, `delivered_event_ids`),
//! against a mock ClickHouse HTTP endpoint that answers the existence checks
//! with chosen ids and records every INSERT.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::audit::{AuditEvent, AuditSource};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const UDM_TABLE: &str = "nanosiem.logs";
const OCSF_LANDING: &str = "nanosiem.ocsf_logs_system_raw";

/// Answers `SELECT toString(id) FROM <logs>` with `udm` and
/// `SELECT toString(id) FROM <ocsf_logs>` with `ocsf`; accepts everything else.
struct FakeClickHouse {
    udm: Vec<String>,
    ocsf: Vec<String>,
}

fn varint(mut v: usize, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn string(s: &str, out: &mut Vec<u8>) {
    varint(s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

fn sql_of(req: &Request) -> String {
    let mut text = String::new();
    for (k, v) in req.url.query_pairs() {
        if k == "query" {
            text.push_str(&v);
            text.push('\n');
        }
    }
    text.push_str(&String::from_utf8_lossy(&req.body));
    text
}

impl Respond for FakeClickHouse {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let sql = sql_of(req);
        if !sql.contains("SELECT toString(id)") {
            return ResponseTemplate::new(200);
        }
        let ids = if sql.contains("ocsf_logs") { &self.ocsf } else { &self.udm };
        let with_header = req
            .url
            .query_pairs()
            .any(|(k, v)| k == "default_format" && v == "RowBinaryWithNamesAndTypes");
        let mut body = Vec::new();
        if with_header {
            varint(1, &mut body);
            string("toString(id)", &mut body);
            string("String", &mut body);
        }
        for id in ids {
            string(id, &mut body);
        }
        ResponseTemplate::new(200).set_body_bytes(body)
    }
}

async fn clickhouse(udm: Vec<String>, ocsf: Vec<String>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(FakeClickHouse { udm, ocsf })
        .mount(&server)
        .await;
    server
}

/// INSERT statements sent to `table` (exact name).
async fn inserts_into(server: &MockServer, table: &str) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(sql_of)
        .filter(|s| {
            s.match_indices(&format!("INSERT INTO {table}")).any(|(i, m)| {
                !s[i + m.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            })
        })
        .collect()
}

fn event(name: &str) -> AuditEvent {
    AuditEvent::builder(AuditSource::Search, crate::audit::AGENTLANE_QUERY)
        .actor(None, Some("agentlane_x".to_string()))
        .resource("agentlane_token", None, Some(name.to_string()))
        .build()
}

const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn delivered_means_the_profile_store_holds_the_event() {
    let (a, b, c) = (event("nal-a"), event("nal-b"), event("nal-c"));
    // UDM holds A and B; OCSF holds B and C.
    let udm = vec![udm_row_id(&a).to_string(), udm_row_id(&b).to_string()];
    let ocsf = vec![b.event_id.to_string(), c.event_id.to_string()];
    let server = clickhouse(udm, ocsf).await;
    let pool = DualPool::for_mock_clickhouse_select_tests(&server.uri());
    let events = [a.clone(), b.clone(), c.clone()];

    // NAN-5354: an OCSF install writes ocsf_logs only, so a UDM row alone
    // (A) does not count and an OCSF row alone (C) does.
    let ocsf_install = AuditEmitter::with_profile(pool.clone(), true);
    let got = ocsf_install.delivered_event_ids(&events).await.unwrap();
    assert_eq!(got, HashSet::from([b.event_id, c.event_id]), "OCSF holds B and C");

    let udm_install = AuditEmitter::with_profile(pool, false);
    let got = udm_install.delivered_event_ids(&events).await.unwrap();
    assert_eq!(got, HashSet::from([a.event_id, b.event_id]));
}

#[tokio::test]
async fn a_verified_retry_writes_only_what_the_profile_store_lacks() {
    let (a, b) = (event("nal-a"), event("nal-b"));
    // UDM `logs` holds A; `ocsf_logs` holds B (NAN-5354: each install
    // writes one store, so only its own store decides what is missing).
    let udm_rows = vec![udm_row_id(&a).to_string()];
    let ocsf_rows = vec![b.event_id.to_string()];

    let server = clickhouse(udm_rows.clone(), ocsf_rows.clone()).await;
    AuditEmitter::with_profile(DualPool::for_mock_clickhouse_select_tests(&server.uri()), false)
        .emit_batch_checked(&[a.clone(), b.clone()], true, WAIT)
        .await
        .unwrap();
    let udm = inserts_into(&server, UDM_TABLE).await;
    assert_eq!(udm.len(), 1);
    assert!(udm[0].contains("nal-b") && !udm[0].contains("nal-a"), "UDM install writes only B: {udm:?}");
    assert!(inserts_into(&server, OCSF_LANDING).await.is_empty(), "UDM install never writes ocsf_logs");

    let server = clickhouse(udm_rows, ocsf_rows).await;
    AuditEmitter::with_profile(DualPool::for_mock_clickhouse_select_tests(&server.uri()), true)
        .emit_batch_checked(&[a.clone(), b.clone()], true, WAIT)
        .await
        .unwrap();
    let ocsf = inserts_into(&server, OCSF_LANDING).await;
    assert_eq!(ocsf.len(), 1);
    assert!(ocsf[0].contains("nal-a") && !ocsf[0].contains("nal-b"), "OCSF install writes only A: {ocsf:?}");
    assert!(inserts_into(&server, UDM_TABLE).await.is_empty(), "OCSF install never writes logs (NAN-5354)");
}

#[tokio::test]
async fn a_fully_delivered_batch_writes_nothing_when_verified() {
    let a = event("nal-a");
    let server = clickhouse(vec![udm_row_id(&a).to_string()], vec![a.event_id.to_string()]).await;
    let emitter = AuditEmitter::with_profile(DualPool::for_mock_clickhouse_select_tests(&server.uri()), true);
    emitter.emit_batch_checked(&[a], true, WAIT).await.unwrap();
    assert!(inserts_into(&server, UDM_TABLE).await.is_empty());
    assert!(inserts_into(&server, OCSF_LANDING).await.is_empty());
}

#[tokio::test]
async fn checked_path_writes_the_same_stores_as_emit() {
    // Pins `writes_udm()` to `perform_insert` (NAN-5354: UDM installs write
    // `logs` only, OCSF installs `ocsf_logs` only).
    for ocsf in [false, true] {
        let routine = clickhouse(vec![], vec![]).await;
        AuditEmitter::with_profile(DualPool::for_mock_clickhouse_select_tests(&routine.uri()), ocsf)
            .emit(&event("nal-r"))
            .await
            .unwrap();
        let checked = clickhouse(vec![], vec![]).await;
        AuditEmitter::with_profile(DualPool::for_mock_clickhouse_select_tests(&checked.uri()), ocsf)
            .emit_batch_checked(&[event("nal-c")], false, WAIT)
            .await
            .unwrap();
        for table in [UDM_TABLE, OCSF_LANDING] {
            assert_eq!(
                inserts_into(&routine, table).await.is_empty(),
                inserts_into(&checked, table).await.is_empty(),
                "ocsf={ocsf}: {table} written by one path only"
            );
        }
    }
}

#[tokio::test]
async fn a_full_insert_bound_is_waited_for_then_refused_without_writing() {
    let bound = Arc::new(tokio::sync::Semaphore::new(1));
    let held = bound.clone().acquire_owned().await.unwrap();
    // Full for the whole wait: refused, as Saturated.
    let refused = acquire_within(&bound, Duration::from_millis(50)).await;
    assert!(matches!(refused, Err(InsertFailure::Saturated)));
    // Freed during the wait: granted.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(held);
    });
    assert!(acquire_within(&bound, Duration::from_secs(2)).await.is_ok());
}
