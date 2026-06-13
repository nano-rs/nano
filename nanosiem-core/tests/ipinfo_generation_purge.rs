// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1441 — IPinfo sync generation/purge property harness.
//!
//! The production failure: a sync attempt dies mid-stream (pod crash, client
//! timeout), but the insert blocks already committed to the
//! ReplicatedReplacingMergeTree PERSIST, stamped with that attempt's time.
//! The retry re-streams the same feed with deterministic chunking, so when
//! rows relied on the table DEFAULTs its blocks were byte-identical to the
//! failed attempt's — ClickHouse's insert deduplication silently skipped
//! them (`written_rows` still reports the full count), the rows kept the OLD
//! stamp, and the post-success purge (`updated_at < run_ms`) deleted the
//! generation the sync had just "inserted". Saturn's ip_enrichments sat at 0
//! rows for 15 days; the one observed "successful" sync had
//! `ProfileEvents['DuplicatedInsertedBlocks'] = 11` and self-wiped seconds
//! later.
//!
//! The fix (NAN-1441) stamps `source_id` / `updated_at = run_ms` / `deleted`
//! EXPLICITLY in every row, so a retry's blocks are content-distinct from any
//! prior attempt's and the purge cutoff is exact by construction. This test
//! pins that property end-to-end on a miniature replica of the production
//! shape, with insert dedup enabled on the table
//! (`non_replicated_deduplication_window` — the plain-MergeTree equivalent
//! of the Replicated default) and the same client path production uses
//! (`clickhouse` crate, RowBinary, validation off):
//!
//!   (a) a completed partial "failed attempt" (prefix of the feed, stamp t1)
//!       persists its rows;
//!   (b) the full retry (same feed content, stamp t2) lands ALL rows with
//!       stamp t2 — dedup must NOT resurrect the t1-stamped prefix;
//!   (c) harness sanity: re-sending the retry byte-identically IS
//!       deduplicated, proving the dedup window is active and (b) is not
//!       vacuously true;
//!   (d) the purge (`updated_at < t2`, exactly as the loader issues it)
//!       removes only the t1 partials — the full feed survives.
//!
//! Requires a local ClickHouse with DDL rights. Skips cleanly if unreachable
//! or if `SKIP_DB_TESTS` is set.
//!   Run: cargo test -p nanosiem-core --test ipinfo_generation_purge -- --nocapture
//!   (local dev CH: docker-compose up -d clickhouse)

const DB: &str = "nan1441_purge_harness";
const SOURCE_ID: &str = "ipinfo_lite";
const PREFIX_ROWS: usize = 20_000;
const FULL_ROWS: usize = 40_000;

fn ch_url() -> String {
    std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into())
}
fn ch_user() -> String {
    std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "nanosiem_admin".into())
}
fn ch_pass() -> String {
    std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or_else(|_| "nanosiem_admin_secret".into())
}

/// Execute one statement; returns the response body, or Err with CH's message.
async fn exec(client: &reqwest::Client, sql: &str) -> Result<String, String> {
    let resp = client
        .post(ch_url())
        .basic_auth(ch_user(), Some(ch_pass()))
        .body(sql.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status();
    let body = resp.text().await.map_err(|e| e.to_string())?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("HTTP {status}: {body}"))
    }
}

async fn exec_ok(client: &reqwest::Client, sql: &str) -> String {
    exec(client, sql)
        .await
        .unwrap_or_else(|e| panic!("statement failed: {sql}\n{e}"))
}

async fn reachable(client: &reqwest::Client) -> bool {
    exec(client, "SELECT 1")
        .await
        .map(|b| b.trim() == "1")
        .unwrap_or(false)
}

/// Mirrors the wire shape of the loader's private `IpEnrichRow` (the unit
/// guard `ipinfo_row_shape_tests` pins the real struct's column list to this
/// shape). `updated_at` is i64 epoch-ms — RowBinary's DateTime64(3) format.
#[derive(clickhouse::Row, serde::Serialize)]
struct TestRow {
    network: String,
    country: String,
    country_code: String,
    continent: String,
    continent_code: String,
    asn: String,
    as_name: String,
    as_domain: String,
    source_id: String,
    updated_at: i64,
    deleted: u8,
}

fn row(i: usize, stamp_ms: i64) -> TestRow {
    TestRow {
        network: format!("10.{}.{}.{}/32", (i >> 16) & 255, (i >> 8) & 255, i & 255),
        country: "United States".into(),
        country_code: "US".into(),
        continent: "North America".into(),
        continent_code: "NA".into(),
        asn: format!("AS{i}"),
        as_name: "Test AS".into(),
        as_domain: "example.test".into(),
        source_id: SOURCE_ID.into(),
        updated_at: stamp_ms,
        deleted: 0,
    }
}

/// Insert rows [0, n) stamped `stamp_ms`, exactly as the loader does: the
/// `clickhouse` crate's RowBinary insert with validation off.
async fn bulk_insert(n: usize, stamp_ms: i64) {
    let ch = clickhouse::Client::default()
        .with_url(ch_url())
        .with_user(ch_user())
        .with_password(ch_pass())
        .with_database(DB)
        .with_validation(false)
        .with_option("async_insert", "0")
        .with_option("wait_end_of_query", "1");
    let mut insert = ch
        .insert::<TestRow>("ip_enrichments")
        .await
        .expect("open insert");
    for i in 0..n {
        insert.write(&row(i, stamp_ms)).await.expect("write row");
    }
    insert.end().await.expect("finalize insert");
}

async fn count_where(client: &reqwest::Client, predicate: &str) -> u64 {
    exec_ok(
        client,
        &format!("SELECT count() FROM {DB}.ip_enrichments WHERE {predicate}"),
    )
    .await
    .trim()
    .parse()
    .expect("count")
}

#[tokio::test]
async fn retry_after_partial_attempt_survives_its_own_purge() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("SKIP_DB_TESTS set; skipping");
        return;
    }
    let http = reqwest::Client::new();
    if !reachable(&http).await {
        eprintln!("ClickHouse not reachable at {}; skipping", ch_url());
        return;
    }

    exec_ok(&http, &format!("DROP DATABASE IF EXISTS {DB}")).await;
    exec_ok(&http, &format!("CREATE DATABASE {DB}")).await;
    // Same engine/key shape as nanosiem.ip_enrichments; the dedup window
    // setting gives this plain MergeTree the Replicated default's
    // insert-deduplication behavior — the mechanism behind NAN-1441.
    exec_ok(
        &http,
        &format!(
            "CREATE TABLE {DB}.ip_enrichments (
                network String,
                source_id LowCardinality(String) DEFAULT 'ipinfo_lite',
                country String DEFAULT '',
                country_code String DEFAULT '',
                continent String DEFAULT '',
                continent_code String DEFAULT '',
                asn String DEFAULT '',
                as_name String DEFAULT '',
                as_domain String DEFAULT '',
                updated_at DateTime64(3) DEFAULT now64(3),
                deleted UInt8 DEFAULT 0
            )
            ENGINE = ReplacingMergeTree(updated_at)
            ORDER BY (source_id, network)
            SETTINGS non_replicated_deduplication_window = 100"
        ),
    )
    .await;

    let t1: i64 = 1_700_000_000_000; // "failed attempt" generation
    let t2: i64 = t1 + 60_000; // the retry's run_ms

    // (a) Partial failed attempt: only the feed prefix committed.
    bulk_insert(PREFIX_ROWS, t1).await;
    let t1_pred = format!("updated_at = fromUnixTimestamp64Milli(toInt64({t1}))");
    assert_eq!(
        count_where(&http, &t1_pred).await,
        PREFIX_ROWS as u64,
        "partial attempt's rows must persist (non-transactional insert)"
    );

    // (b) Full retry stamped t2. The prefix rows' CONTENT matches the failed
    // attempt's except for the stamp — explicit stamping must defeat block
    // dedup so every row lands in the t2 generation.
    bulk_insert(FULL_ROWS, t2).await;
    let t2_pred = format!("updated_at = fromUnixTimestamp64Milli(toInt64({t2}))");
    assert_eq!(
        count_where(&http, &t2_pred).await,
        FULL_ROWS as u64,
        "retry rows were dedup-skipped against the failed attempt's blocks — \
         the NAN-1441 self-wipe is back (stamps no longer make blocks distinct?)"
    );

    // (c) Harness sanity: a byte-identical re-send IS deduplicated, so (b)
    // wasn't vacuously true with dedup disabled.
    bulk_insert(FULL_ROWS, t2).await;
    assert_eq!(
        count_where(&http, &t2_pred).await,
        FULL_ROWS as u64,
        "identical re-send must be block-deduplicated — dedup window inactive, \
         this harness no longer exercises the NAN-1441 mechanism"
    );

    // (d) The purge, exactly as the loader issues it (cutoff = the retry's
    // run_ms): removes the t1 partials, keeps the full t2 generation.
    exec_ok(
        &http,
        &format!(
            "ALTER TABLE {DB}.ip_enrichments \
             DELETE WHERE source_id = '{SOURCE_ID}' \
             AND updated_at < fromUnixTimestamp64Milli(toInt64({t2})) \
             SETTINGS mutations_sync = 2"
        ),
    )
    .await;
    assert_eq!(
        count_where(&http, "1").await,
        FULL_ROWS as u64,
        "purge must leave exactly the full retry generation"
    );
    assert_eq!(
        count_where(&http, &t1_pred).await,
        0,
        "purge must remove the failed attempt's partial generation"
    );

    exec_ok(&http, &format!("DROP DATABASE IF EXISTS {DB}")).await;
}
