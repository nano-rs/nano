// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query-artifact discovery excludes internal names BEFORE `DISTINCT ...
//! LIMIT` (NAN-3226 review P2-7): with more internal hostnames than the
//! candidate budget, the external domains must still come back.
//!
//! `#[ignore]`d: point `NANOSIEM_TEST_CLICKHOUSE_URL` at a DISPOSABLE migrated
//! ClickHouse (the suite truncates `logs`).

use nanosiem_core::internal_domains::InternalDomains;
use nanosiem_core::prevalence::repository::distinct_domain_candidates_sql;

#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct Value {
    value: String,
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable migrated ClickHouse"]
async fn internal_names_never_consume_the_candidate_budget() {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL").expect("NANOSIEM_TEST_CLICKHOUSE_URL");
    let client = clickhouse::Client::default()
        .with_url(url)
        .with_database("nanosiem")
        .with_compression(clickhouse::Compression::None);
    client.query("TRUNCATE TABLE nanosiem.logs").execute().await.expect("truncate");
    // 150 internal names (built-in, added A-label suffix, added suffix written
    // as a U-label in the data, trailing dot) and 3 external domains.
    client
        .query(
            "INSERT INTO nanosiem.logs (timestamp, source_type, message, dest_host) \
             SELECT now64(3), 'discovery_test', 'x', \
                    multiIf(number % 3 = 0, concat('ws', toString(number), '.corp.local'), \
                            number % 3 = 1, concat('DB', toString(number), '.Prod.'), \
                            concat('h', toString(number), '.bücher.example')) \
             FROM numbers(150)",
        )
        .execute()
        .await
        .expect("internal rows");
    client
        .query(
            "INSERT INTO nanosiem.logs (timestamp, source_type, message, dest_host) VALUES \
             (now64(3), 'discovery_test', 'x', 'evil.example.com'), \
             (now64(3), 'discovery_test', 'x', 'myprod.com'), \
             (now64(3), 'discovery_test', 'x', 'cdn.example.net')",
        )
        .execute()
        .await
        .expect("external rows");

    let internal = InternalDomains::with_suffixes(["prod", "xn--bcher-kva.example"]);
    let sql = distinct_domain_candidates_sql("dest_host", "nanosiem.logs", "source_type = 'discovery_test'", &internal, 101);
    let mut got: Vec<String> = client
        .query(&sql)
        .fetch_all::<Value>()
        .await
        .expect("candidates")
        .into_iter()
        .map(|r| r.value)
        .collect();
    got.sort();
    assert_eq!(got, ["cdn.example.net", "evil.example.com", "myprod.com"]);

    // Without the added suffixes only the built-in names are excluded, so the
    // budget fills with `.prod` / `.bücher.example` names again.
    let builtin_only = distinct_domain_candidates_sql(
        "dest_host",
        "nanosiem.logs",
        "source_type = 'discovery_test'",
        &InternalDomains::builtin(),
        101,
    );
    let n = client.query(&builtin_only).fetch_all::<Value>().await.expect("builtin").len();
    assert_eq!(n, 101, "100 non-built-in internal names + 3 external, capped at 101");
    client.query("TRUNCATE TABLE nanosiem.logs").execute().await.expect("cleanup");
}
