// SPDX-License-Identifier: AGPL-3.0-or-later
use super::insert_target;

#[test]
fn bareword_names_are_byte_identical_to_the_0_14_2_statement() {
    assert_eq!(insert_target("logs"), "logs");
    assert_eq!(insert_target("nanosiem.logs"), "nanosiem.logs");
    assert_eq!(
        insert_target("nanosiem.search_job_results"),
        "nanosiem.search_job_results"
    );
}

#[test]
fn non_bareword_parts_are_quoted_per_part_and_cannot_break_out() {
    assert_eq!(insert_target("my-db.logs"), "\"my-db\".logs");
    // A hostile part stays one identifier token.
    assert_eq!(
        insert_target("nanosiem.logs\" (x) SELECT 1 --"),
        "nanosiem.\"logs\"\" (x) SELECT 1 --\""
    );
    // Reserved words are quoted, never spliced bare.
    assert_eq!(insert_target("nanosiem.select"), "nanosiem.\"select\"");
}

#[tokio::test]
async fn the_statement_on_the_wire_names_the_qualified_table_structurally() {
    use wiremock::{matchers::any, Mock, MockServer, ResponseTemplate};
    #[derive(clickhouse::Row, serde::Serialize)]
    struct R {
        id: u64,
    }
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let client = clickhouse::Client::default()
        .with_url(server.uri())
        .with_validation(false)
        .with_compression(clickhouse::Compression::None);
    let mut insert = super::insert::<R>(&client, "nanosiem.logs").await.unwrap();
    insert.write(&R { id: 7 }).await.unwrap();
    insert.end().await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let sent: String = requests
        .iter()
        .map(|r| {
            let url: String = r
                .url
                .query_pairs()
                .filter(|(k, _)| k == "query")
                .map(|(_, v)| v.into_owned())
                .collect();
            format!("{url}\n{}", String::from_utf8_lossy(&r.body))
        })
        .collect();
    assert!(
        sent.contains("INSERT INTO nanosiem.logs(`id`)"),
        "qualified target must stay structural: {sent}"
    );
    assert!(!sent.contains("`nanosiem.logs`"), "{sent}");
}
