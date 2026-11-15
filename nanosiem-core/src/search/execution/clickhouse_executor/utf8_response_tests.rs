// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5426: one row holding invalid UTF-8 (a byte-level eval function's
//! output, or a stored invalid byte sequence) must not fail the whole
//! ClickHouse response. Each invalid sequence decodes to U+FFFD and the other
//! rows are returned unchanged.

use tokio::sync::mpsc;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::ClickHouseExecutor;
use crate::search::StreamingChunk;

/// Two rows; the first holds `A\xFFB`, the second is clean.
fn body_with_invalid_row() -> Vec<u8> {
    let mut body = b"{\"s\":\"A".to_vec();
    body.push(0xFF);
    body.extend_from_slice(b"B\"}\n{\"s\":\"ok\"}\n");
    body
}

async fn executor_serving(body: Vec<u8>) -> (MockServer, ClickHouseExecutor) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(&server)
        .await;
    let executor = ClickHouseExecutor::new(
        clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None),
    );
    (server, executor)
}

#[tokio::test]
async fn dynamic_query_decodes_an_invalid_row_lossily() {
    let (_server, executor) = executor_serving(body_with_invalid_row()).await;
    let rows = executor
        .execute_dynamic_query("SELECT s FROM logs", true)
        .await
        .expect("an invalid row must not fail the response");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["s"], "A\u{FFFD}B");
    assert_eq!(rows[1]["s"], "ok");
}

#[tokio::test]
async fn streaming_query_decodes_an_invalid_row_lossily() {
    let (_server, executor) = executor_serving(body_with_invalid_row()).await;
    let (tx, mut rx) = mpsc::channel(8);
    executor
        .execute_dynamic_query_streaming("SELECT s FROM logs", "utf8-stream", None, tx, true)
        .await
        .expect("an invalid row must not fail the stream");
    let mut rows = Vec::new();
    while let Some(chunk) = rx.recv().await {
        match chunk {
            StreamingChunk::Rows(batch) => rows.extend(batch),
            StreamingChunk::Error(e) => panic!("stream error: {e}"),
        }
    }
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["s"], "A\u{FFFD}B");
    assert_eq!(rows[1]["s"], "ok");
}

#[tokio::test]
async fn streaming_query_keeps_multibyte_text_intact() {
    // Valid multibyte text must round-trip exactly (no replacement).
    let (_server, executor) =
        executor_serving("{\"s\":\"abcdefghiétail αβγ\"}\n".as_bytes().to_vec()).await;
    let (tx, mut rx) = mpsc::channel(8);
    executor
        .execute_dynamic_query_streaming("SELECT s FROM logs", "utf8-multibyte", None, tx, true)
        .await
        .expect("stream");
    let mut rows = Vec::new();
    while let Some(StreamingChunk::Rows(batch)) = rx.recv().await {
        rows.extend(batch);
    }
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["s"], "abcdefghiétail αβγ");
}
