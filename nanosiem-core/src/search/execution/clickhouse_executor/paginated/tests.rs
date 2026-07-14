// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1645 (finding 3.5): pin the pagination companion gate.
//!
//! Companion queries (the count companion in `paginated.rs` and the histogram
//! spawn in `service/core_search.rs`) both route their offset decision through
//! [`is_first_page`]. These tests pin the contract: offset 0 runs companions,
//! any offset > 0 skips them and reports [`paged_total_estimate`] instead.

use super::{is_first_page, paged_total_estimate, ClickHouseExecutor};

#[test]
fn first_page_runs_companion_queries() {
    assert!(
        is_first_page(0),
        "offset=0 must run the count + histogram companions (43155f11: in parallel, never sequential)"
    );
}

#[test]
fn page_flips_skip_companion_queries() {
    for offset in [1usize, 100, 100_000] {
        assert!(
            !is_first_page(offset),
            "offset={offset} must NOT re-run the count/histogram companions — page 1 already delivered them"
        );
    }
}

#[test]
fn full_page_estimate_stays_ahead_of_client_position() {
    // Full page → "there is probably more": estimate must exceed offset+returned
    // so the client's next-page fetch stays enabled.
    assert_eq!(paged_total_estimate(100, 100, 100), 300);
    assert_eq!(paged_total_estimate(500, 100, 100), 700);
}

#[test]
fn partial_page_estimate_is_exact() {
    // Partial page → definitively the last page: offset + returned is exact.
    assert_eq!(paged_total_estimate(100, 37, 100), 137);
    // Empty page N: nothing past the offset.
    assert_eq!(paged_total_estimate(200, 0, 100), 200);
}

#[tokio::test]
async fn bounded_execution_runs_one_query_with_server_result_limits() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "{\"id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"}\n",
            "application/json",
        ))
        .mount(&server)
        .await;
    let executor = ClickHouseExecutor::new(
        clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None),
    );
    let limits = crate::search::SearchExecutionLimits {
        max_result_rows: 101,
        max_result_bytes: 4096,
    };

    let (rows, total) = executor
        .execute_sql_with_query_id(
            "SELECT id FROM logs",
            101,
            0,
            "tuning-test-window-0",
            None,
            Some(&limits),
            false,
        )
        .await
        .expect("bounded execution");
    assert_eq!(rows.len(), 1);
    assert_eq!(total, 1);

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "autonomous execution must not start a count companion"
    );
    let options = requests[0]
        .url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        options.get("query_id").map(String::as_str),
        Some("tuning-test-window-0")
    );
    assert_eq!(
        options.get("max_result_rows").map(String::as_str),
        Some("101")
    );
    assert_eq!(
        options.get("max_result_bytes").map(String::as_str),
        Some("4096")
    );
    assert_eq!(
        options.get("result_overflow_mode").map(String::as_str),
        Some("throw")
    );
}

#[tokio::test]
async fn bounded_execution_rejects_response_before_materializing_past_byte_cap() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 65]))
        .mount(&server)
        .await;
    let executor = ClickHouseExecutor::new(
        clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None),
    );
    let limits = crate::search::SearchExecutionLimits {
        max_result_rows: 10,
        max_result_bytes: 64,
    };

    let error = executor
        .execute_sql_with_query_id(
            "SELECT id FROM logs",
            10,
            0,
            "tuning-byte-cap-0",
            None,
            Some(&limits),
            false,
        )
        .await
        .expect_err("oversized response must fail");
    assert!(matches!(
        error,
        crate::search::SearchError::ResponseTooLarge(65, 64)
    ));
}

#[tokio::test]
async fn bounded_execution_fails_closed_on_malformed_rows() {
    use wiremock::matchers::any;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_raw(
            "{\"id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\"}\nnot-json\n",
            "application/json",
        ))
        .mount(&server)
        .await;
    let executor = ClickHouseExecutor::new(
        clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None),
    );
    let limits = crate::search::SearchExecutionLimits {
        max_result_rows: 10,
        max_result_bytes: 4096,
    };

    let error = executor
        .execute_sql_with_query_id(
            "SELECT id FROM logs",
            10,
            0,
            "tuning-malformed-row-0",
            None,
            Some(&limits),
            false,
        )
        .await
        .expect_err("malformed rows must make exact validation fail");
    assert!(matches!(
        error,
        crate::search::SearchError::DatabaseError(sqlx::Error::Protocol(_))
    ));
}
