// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 lane G: run the production IOC-store reader SQL (retro-hunt
//! candidates, `ioc in <feed>(...)`, the feed picker) against a real
//! ClickHouse with the production `custom_enrichment_results` /
//! `ioc_list_commits` DDL. Each test uses its own database, so partition and
//! row counts are exact.
//!
//! Proves:
//! - per-key version collapse BEFORE selectors (a tombstone or a dropped tag
//!   in the latest version stops matching even while the old row is unmerged);
//! - uncommitted IOC list rows are invisible (migration 182);
//! - `feed("name")` is exact and provider selectors never pull IOC lists;
//! - the candidate and feed-picker scans are partition-pruned (EXPLAIN).
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:48123 \
//! NANOSIEM_TEST_CLICKHOUSE_USER=default NANOSIEM_TEST_CLICKHOUSE_PASSWORD=... \
//!   cargo test -p nanosiem-core --test retro_hunt_candidates_clickhouse -- --ignored
//! ```

use nanosiem_core::query::{ioc_feed_indicator_sql, IocFeed};
use nanosiem_core::search::SearchService;
use serde::Deserialize;

const INIT_SQL: &str = include_str!("../../clickhouse/init.sql");

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    // Shared transport: pins LZ4 (raw clients fail against CH 26.9+).
    let mut client = nanosiem_core::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

/// The init.sql statement starting at `head`, comment lines stripped.
fn statement(head: &str) -> String {
    let start = INIT_SQL.find(head).unwrap_or_else(|| panic!("{head} not in init.sql"));
    let body: String = INIT_SQL[start..]
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    body.split(';').next().unwrap().to_string()
}

/// A fresh database holding the production tables; returns its name.
async fn fresh_db(ch: &clickhouse::Client) -> String {
    let db = format!("lg_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    ch.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
    for head in [
        "CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results",
        "CREATE TABLE IF NOT EXISTS nanosiem.ioc_list_commits",
    ] {
        let sql = statement(head).replace("nanosiem.", &format!("{db}."));
        ch.query(&sql).execute().await.unwrap();
    }
    for sql in migration_184_schema(&db, &["custom_enrichment_results"]) {
        ch.query(&sql).execute().await.unwrap();
    }
    db
}

/// Schema statements of CH migration 184 (NAN-4948): the `platform_feed`
/// ownership column on `tables` and the commits table, which the IOC readers'
/// visibility predicate needs. Taken from the migration itself (init.sql keeps
/// dev's shape; 184 upgrades both fresh and existing installs).
fn migration_184_schema(db: &str, tables: &[&str]) -> Vec<String> {
    const MIGRATION_184: &str = include_str!("../../clickhouse/184_platform_feed_commits.sql");
    let sql: String = MIGRATION_184
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    sql.split(';')
        .map(str::trim)
        .filter(|s| {
            s.starts_with("CREATE TABLE")
                || (s.starts_with("ALTER TABLE")
                    && s.contains("ADD COLUMN")
                    && tables.iter().any(|t| s.starts_with(&format!("ALTER TABLE nanosiem.{t} "))))
        })
        .map(|s| s.replace("nanosiem.", &format!("{db}.")))
        .collect()
}


#[derive(Debug, clickhouse::Row, Deserialize)]
struct Candidate {
    value: String,
    #[allow(dead_code)]
    key_type: String,
    #[allow(dead_code)]
    enrichment_name: String,
    confidence: u32,
    fetched_at_ms: i64,
}

struct Row<'a> {
    namespace: &'a str,
    feed: &'a str,
    value: &'a str,
    fetched: &'a str,
    expires: &'a str,
    version: u32,
    confidence: u8,
    tags: &'a str,
}

fn row<'a>(namespace: &'a str, feed: &'a str, value: &'a str, fetched: &'a str, expires: &'a str, version: u32) -> Row<'a> {
    Row { namespace, feed, value, fetched, expires, version, confidence: 50, tags: "[]" }
}

async fn insert(ch: &clickhouse::Client, db: &str, rows: &[Row<'_>]) {
    let values: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "('{}', generateUUIDv4(), '{}', 'domain', '{}', NULL, {}, '{{}}', {}, {}, {}, 1, '', '', {}, 0)",
                r.namespace, r.feed, r.value, r.tags, r.fetched, r.expires, r.version, r.confidence
            )
        })
        .collect();
    let sql = format!(
        "INSERT INTO {db}.custom_enrichment_results (namespace, enrichment_id, enrichment_name, \
         key_type, key_value, risk_score, tags, data, fetched_at, expires_at, version, is_ioc, \
         threat_type, malware, confidence, is_marketplace) VALUES {}",
        values.join(", ")
    );
    ch.query(&sql).execute().await.unwrap();
}

const LIST_A: &str = "00000000-0000-0000-0000-00000000000a";

async fn commit(ch: &clickhouse::Client, db: &str, version: u32, list_id: &str) {
    ch.query(&format!(
        "INSERT INTO {db}.ioc_list_commits (version, list_id, list_name, action) \
         VALUES ({version}, toUUID('{list_id}'), 'x', 'publish')"
    ))
    .execute()
    .await
    .unwrap();
}

async fn candidates(ch: &clickhouse::Client, db: &str, feed: &str, cursor: Option<(i64, &str)>) -> Vec<Candidate> {
    let table = format!("{db}.custom_enrichment_results");
    let sql = SearchService::retro_hunt_candidates_sql(&table, &[feed.to_string()], &[], cursor, None, 100);
    ch.query(&sql).fetch_all::<Candidate>().await.unwrap()
}

/// Run the production `ioc in <name>("<arg>")` subquery against `db`.
async fn feed_values(ch: &clickhouse::Client, db: &str, name: &str, arg: &str) -> Vec<String> {
    let sql = ioc_feed_indicator_sql(&IocFeed { name: name.into(), arg: arg.into() }, false)
        .replace("nanosiem.", &format!("{db}."));
    let mut out: Vec<String> = ch.query(&sql).fetch_all::<String>().await.unwrap();
    out.sort();
    out
}

const T1: &str = "toDateTime64('2026-10-01 00:00:00', 3, 'UTC')";
const T2: &str = "toDateTime64('2026-10-02 00:00:00', 3, 'UTC')";
const LIVE: &str = "toDateTime64('2100-01-01 00:00:00', 3, 'UTC')";
const GONE: &str = "toDateTime64('2020-01-01 00:00:00', 3, 'UTC')";

#[tokio::test]
#[ignore = "requires ClickHouse; run with --ignored"]
async fn candidate_sql_collapses_each_key_to_its_latest_committed_version() {
    let ch = ch();
    let db = fresh_db(&ch).await;
    let list = "list-a";
    // IOC list storage model (migration 182): each publication writes the
    // complete live set under `ioc_list/<version>`; the active version is the
    // highest committed one. v10: kept + removed. v11: kept (same learned-at,
    // new confidence) + added. v12 never commits (a failed publication).
    let mut kept_v11 = row("ioc_list/11", list, "kept.example", T1, LIVE, 11);
    kept_v11.confidence = 90;
    insert(
        &ch,
        &db,
        &[
            row("ioc_list/10", list, "kept.example", T1, LIVE, 10),
            row("ioc_list/10", list, "removed.example", T1, LIVE, 10),
            kept_v11,
            row("ioc_list/11", list, "added.example", T2, LIVE, 11),
            row("ioc_list/12", list, "uncommitted.example", T2, LIVE, 12),
        ],
    )
    .await;
    commit(&ch, &db, 10, LIST_A).await;
    commit(&ch, &db, 11, LIST_A).await;
    let all = candidates(&ch, &db, list, None).await;
    let values: Vec<&str> = all.iter().map(|c| c.value.as_str()).collect();
    assert_eq!(values, vec!["kept.example", "added.example"], "superseded / uncommitted rows: {all:?}");
    assert_eq!(all[0].confidence, 90, "latest committed version's attributes");

    let t1_ms = all[0].fetched_at_ms;
    let delta = candidates(&ch, &db, list, Some((t1_ms, "kept.example"))).await;
    assert_eq!(delta.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(), vec!["added.example"]);

    // A version-1 feed restamped by a later sync: newest fetch wins.
    insert(
        &ch,
        &db,
        &[
            row("default", "feedx", "restamped.example", T1, LIVE, 1),
            row("default", "feedx", "restamped.example", T2, LIVE, 1),
        ],
    )
    .await;
    let fed = candidates(&ch, &db, "feedx", Some((t1_ms, "zzz"))).await;
    assert_eq!(fed.len(), 1);
    assert!(fed[0].fetched_at_ms > t1_ms, "newest fetch is the learned-at for v1 feeds");
    ch.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
}

/// P1-3: the selector reads the collapsed latest row — a tag dropped by the
/// latest version, or a tombstone (empty tags), stops a provider/tag match.
/// P2-5: `feed("name")` is exact; providers never pull IOC list rows.
#[tokio::test]
#[ignore = "requires ClickHouse; run with --ignored"]
async fn feed_selectors_apply_to_the_latest_row_and_feed_is_exact() {
    let ch = ch();
    let db = fresh_db(&ch).await;
    let tagged = |value, version, expires, tags| Row { tags, ..row("default", "campaign-feed", value, T1, expires, version) };
    insert(
        &ch,
        &db,
        &[
            // still tagged in its latest version
            tagged("still.example", 1, LIVE, "['apt29']"),
            // tag removed by a later version (same storage key)
            tagged("untagged.example", 1, LIVE, "['apt29']"),
            tagged("untagged.example", 2, LIVE, "[]"),
            // tombstoned by a later version
            tagged("tombstoned.example", 1, LIVE, "['apt29']"),
            tagged("tombstoned.example", 2, GONE, "[]"),
            // an IOC list named like the campaign and a ThreatFox feed
            Row { tags: "['apt29']", ..row("ioc_list/7", "apt29", "listed.example", T1, LIVE, 7) },
            row("default", "threatfox", "tf.example", T1, LIVE, 1),
            row("default", "my-list-copy", "copy.example", T1, LIVE, 1),
        ],
    )
    .await;
    commit(&ch, &db, 7, LIST_A).await;

    assert_eq!(feed_values(&ch, &db, "misp", "apt29").await, vec!["still.example"]);
    assert_eq!(
        feed_values(&ch, &db, "threatfox", "apt29").await,
        vec!["still.example", "tf.example"],
        "provider selector: provider feed + tagged rows, never the IOC list"
    );
    assert_eq!(feed_values(&ch, &db, "feed", "APT29").await, vec!["listed.example"], "exact, case-insensitive");
    assert_eq!(feed_values(&ch, &db, "feed", "my-list").await, Vec::<String>::new(), "no substring match");

    // Uncommitted list rows are invisible to feed() as well.
    insert(&ch, &db, &[row("ioc_list/8", "apt29", "pending.example", T2, LIVE, 8)]).await;
    assert_eq!(feed_values(&ch, &db, "feed", "apt29").await, vec!["listed.example"]);
    ch.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
}

/// P2-7: the first-run / floored candidate scan and the feed picker prune
/// partitions (EXPLAIN indexes = 1 → Min-Max `Parts: 1/3`).
#[tokio::test]
#[ignore = "requires ClickHouse; run with --ignored"]
async fn candidate_and_feed_picker_scans_are_partition_pruned() {
    let ch = ch();
    let db = fresh_db(&ch).await;
    // Three monthly partitions: two old, one inside the window.
    for month in ["2026-01-15", "2026-05-15"] {
        let at = format!("toDateTime64('{month} 00:00:00', 3, 'UTC')");
        insert(&ch, &db, &[row("default", "feedx", "old.example", &at, LIVE, 1)]).await;
    }
    insert(&ch, &db, &[row("default", "feedx", "new.example", "now64(3)", LIVE, 1)]).await;
    let table = format!("{db}.custom_enrichment_results");

    let floor_ms = chrono::Utc::now().timestamp_millis() - 5 * 86_400_000;
    let candidate_sql =
        SearchService::retro_hunt_candidates_sql(&table, &[], &[], Some((floor_ms, "")), None, 100);
    let plan = explain(&ch, &candidate_sql).await;
    assert!(plan.contains("Parts: 1/3"), "candidate scan must prune partitions:\n{plan}");

    // Feed picker: needs the (real) staging table it reads.
    ch.query(&statement("CREATE TABLE IF NOT EXISTS nanosiem.custom_ioc_enrichment_dict_staging").replace("nanosiem.", &format!("{db}.")))
        .execute()
        .await
        .unwrap();
    let picker_sql = SearchService::ioc_feed_names_sql(&table)
        .replace("nanosiem.custom_ioc_enrichment_dict_staging", &format!("{db}.custom_ioc_enrichment_dict_staging"));
    let plan = explain(&ch, &picker_sql).await;
    assert!(plan.contains("Parts: 1/3"), "feed picker must prune partitions:\n{plan}");
    let names: Vec<String> = ch.query(&picker_sql).fetch_all::<String>().await.unwrap();
    assert_eq!(names, vec!["feedx".to_string()]);
    ch.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
}

async fn explain(ch: &clickhouse::Client, sql: &str) -> String {
    ch.query(&format!("EXPLAIN indexes = 1 {sql}"))
        .fetch_all::<String>()
        .await
        .unwrap()
        .join("\n")
}
