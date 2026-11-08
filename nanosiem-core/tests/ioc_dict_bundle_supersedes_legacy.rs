// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4959 (IOC parity): CH migration 187 and the Rust readers' predicate
//! (`enrichment::ioc::committed_rows_predicate` ->
//! `platform_enrichment::state::ioc_visible_predicate`) retire legacy
//! marketplace IOC rows (a Deno ThreatFox / Tor install, an air-gap IOC
//! import: platform_feed = 0, is_marketplace = 1) once the bundle commits a
//! ThreatFox or Tor generation. User custom enrichments and IOC lists
//! (is_marketplace = 0) are never affected.
//!
//! Static checks always run; the behaviour check runs migration 187's exact
//! refresh SELECT and the Rust predicate against a REAL ClickHouse in its own
//! database (production `custom_enrichment_results` DDL + migrations 182/184
//! schema):
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:<own port> \
//! NANOSIEM_TEST_CLICKHOUSE_USER=... NANOSIEM_TEST_CLICKHOUSE_PASSWORD=... \
//!   cargo test -p nanosiem-core --test ioc_dict_bundle_supersedes_legacy -- --include-ignored --nocapture
//! ```

use nanosiem_core::enrichment::ioc::committed_rows_predicate;
use nanosiem_core::platform_enrichment::state::ioc_visible_predicate;

const MIGRATION_187: &str = include_str!("../../clickhouse/187_ioc_dict_bundle_supersedes_legacy.sql");
const MIGRATION_184: &str = include_str!("../../clickhouse/184_platform_feed_commits.sql");
const MIGRATION_182: &str = include_str!("../../clickhouse/182_ioc_list_commits.sql");
const INIT_SQL: &str = include_str!("../../clickhouse/init.sql");

fn uncommented(sql: &str) -> String {
    sql.lines().filter(|l| !l.trim_start().starts_with("--")).collect::<Vec<_>>().join("\n")
}

fn refresh_select() -> String {
    let sql = uncommented(MIGRATION_187);
    let start = sql.find("MODIFY QUERY ").expect("MODIFY QUERY") + "MODIFY QUERY ".len();
    sql[start..].trim().trim_end_matches(';').to_string()
}

/// 184's IOC refresh body (the one 187 supersedes).
fn body_184() -> String {
    let sql = uncommented(MIGRATION_184);
    let start = sql.find("ALTER TABLE nanosiem.ioc_enrichment_dict_refresh").unwrap();
    let rest = &sql[start..];
    let q = rest.find("MODIFY QUERY ").unwrap() + "MODIFY QUERY ".len();
    rest[q..].split(';').next().unwrap().trim().to_string()
}

#[test]
fn migration_187_changes_only_the_visibility_clause_of_184s_ioc_body() {
    let sql = uncommented(MIGRATION_187);
    let statements: Vec<&str> = sql.split(';').map(str::trim).filter(|s| !s.is_empty()).collect();
    assert_eq!(statements.len(), 1, "{statements:?}");
    assert!(statements[0].starts_with("ALTER TABLE nanosiem.ioc_enrichment_dict_refresh\nMODIFY QUERY SELECT"));
    let old_where = "WHERE platform_feed = 0 OR namespace GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id)";
    let new_where = "WHERE (platform_feed = 0 AND 'ioc' GLOBAL NOT IN (SELECT 'ioc' FROM nanosiem.platform_feed_commits WHERE feed_id IN ('threatfox', 'tor_exit_nodes') AND storage_key != '')) OR (platform_feed = 1 AND namespace GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id))";
    assert!(body_184().contains(old_where));
    let body = refresh_select();
    assert_eq!(body.replace(new_where, old_where), body_184(), "only the WHERE changes");
    // The Rust readers apply the same commit gate (plus the is_marketplace
    // clause the CH body cannot name).
    let rust = ioc_visible_predicate("nanosiem.platform_feed_commits");
    assert!(rust.contains("(SELECT 'ioc' FROM nanosiem.platform_feed_commits WHERE feed_id IN ('threatfox', 'tor_exit_nodes') AND storage_key != '')"), "{rust}");
    assert!(!INIT_SQL.contains("platform_feed"), "init.sql bodies are not edited");
}

#[test]
fn readers_predicate_gates_only_legacy_marketplace_rows() {
    let p = committed_rows_predicate("nanosiem.ioc_list_commits_distributed");
    assert!(p.contains("is_marketplace = 0 OR 'ioc' GLOBAL NOT IN (SELECT 'ioc' FROM nanosiem.platform_feed_commits_distributed WHERE feed_id IN ('threatfox', 'tor_exit_nodes') AND storage_key != '')"), "{p}");
    assert!(p.contains("platform_feed = 1 AND namespace GLOBAL IN"), "{p}");
    assert!(p.contains("version GLOBAL IN (SELECT max(version) FROM nanosiem.ioc_list_commits_distributed GROUP BY list_id)"), "IOC list rule kept: {p}");
}

fn ch() -> Option<clickhouse::Client> {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL").ok()?;
    let mut client = nanosiem_core::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    Some(client)
}

fn schema(db: &str) -> Vec<String> {
    let init = uncommented(INIT_SQL);
    let start = init.find("CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results").unwrap();
    let mut out = vec![init[start..].split(';').next().unwrap().to_string()];
    for (sql, keep) in [
        (MIGRATION_184, &["CREATE TABLE IF NOT EXISTS nanosiem.platform_feed_commits", "ALTER TABLE nanosiem.custom_enrichment_results ADD COLUMN"][..]),
        (MIGRATION_182, &["CREATE TABLE IF NOT EXISTS nanosiem.ioc_list_commits"][..]),
    ] {
        for s in uncommented(sql).split(';').map(str::trim) {
            if keep.iter().any(|k| s.starts_with(k)) {
                out.push(s.to_string());
            }
        }
    }
    assert_eq!(out.len(), 4, "schema statements: {out:?}");
    out.into_iter().map(|s| s.replace("nanosiem.", &format!("{db}."))).collect()
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct Ioc {
    ioc_value: String,
    source_id: String,
}

async fn dict_rows(ch: &clickhouse::Client, db: &str) -> Vec<(String, String)> {
    let sql = format!(
        "SELECT ioc_value, source_id FROM ({}) ORDER BY ioc_value",
        refresh_select().replace("nanosiem.", &format!("{db}."))
    );
    let rows: Vec<Ioc> = ch.query(&sql).fetch_all().await.unwrap();
    rows.into_iter().map(|r| (r.ioc_value, r.source_id)).collect()
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct Key {
    key_value: String,
}

/// What a Rust reader sees (custom AND marketplace rows), through the predicate.
async fn reader_rows(ch: &clickhouse::Client, db: &str) -> Vec<String> {
    let visible = committed_rows_predicate(&format!("{db}.ioc_list_commits"));
    let sql = format!(
        "SELECT DISTINCT key_value FROM {db}.custom_enrichment_results WHERE {visible} ORDER BY key_value"
    );
    let rows: Vec<Key> = ch.query(&sql).fetch_all().await.unwrap();
    rows.into_iter().map(|r| r.key_value).collect()
}

async fn insert(ch: &clickhouse::Client, db: &str, namespace: &str, name: &str, value: &str, marketplace: u8, platform: u8) {
    ch.query(&format!(
        "INSERT INTO {db}.custom_enrichment_results (namespace, enrichment_id, enrichment_name, key_type, key_value, tags, data, \
         fetched_at, expires_at, version, is_ioc, threat_type, confidence, is_marketplace, platform_feed) \
         VALUES (?, generateUUIDv4(), ?, 'ip', ?, [], '{{}}', now64(3), now64(3) + INTERVAL 20 DAY, 1, 1, 'botnet_cc', 80, ?, ?)"
    ))
    .bind(namespace)
    .bind(name)
    .bind(value)
    .bind(marketplace)
    .bind(platform)
    .execute()
    .await
    .unwrap();
}

async fn commit(ch: &clickhouse::Client, db: &str, sequence: u64, feed: &str, key: &str) {
    ch.query(&format!(
        "INSERT INTO {db}.platform_feed_commits (sequence, feed_id, storage_key, revision, hard_expiry) \
         VALUES (?, ?, ?, 1, now64(3) + INTERVAL 1 DAY)"
    ))
    .bind(sequence)
    .bind(feed)
    .bind(key)
    .execute()
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "requires ClickHouse (NANOSIEM_TEST_CLICKHOUSE_URL); run with --include-ignored"]
async fn bundle_ioc_commit_retires_legacy_marketplace_rows() {
    let ch = ch().expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let db = format!("ioc187_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    ch.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
    for sql in schema(&db) {
        ch.query(&sql).execute().await.unwrap();
    }
    // Legacy marketplace rows: a Deno ThreatFox install (an indicator the
    // bundle has delisted) and an air-gap IOC import.
    insert(&ch, &db, "default", "ThreatFox", "203.0.113.66", 1, 0).await;
    insert(&ch, &db, "airgap", "Air-gap IOC bundle", "203.0.113.77", 1, 0).await;
    // A user's own custom IOC enrichment (custom_ioc_* path): never affected.
    insert(&ch, &db, "default", "my-blocklist", "198.51.100.5", 0, 0).await;
    // The bundle's ThreatFox generation (uncommitted for now).
    let key = "platform_feed/threatfox/100";
    insert(&ch, &db, key, "threatfox", "203.0.113.7", 1, 1).await;

    // 1. Before any IOC commit: legacy marketplace rows served, uncommitted bundle not.
    let before = dict_rows(&ch, &db).await;
    println!("dict before: {before:?}");
    assert_eq!(
        before,
        vec![("203.0.113.66".into(), "ThreatFox".into()), ("203.0.113.77".into(), "Air-gap IOC bundle".into())]
    );
    assert_eq!(reader_rows(&ch, &db).await, ["198.51.100.5", "203.0.113.66", "203.0.113.77"]);

    // 2. An IPinfo-only commit does not touch IOC rows.
    commit(&ch, &db, 90, "ipinfo_lite", "platform_feed/ipinfo_lite/90").await;
    assert_eq!(dict_rows(&ch, &db).await, before);

    // 3. The bundle commits ThreatFox: only its generation in the dict; the
    //    user's custom enrichment still visible to readers.
    commit(&ch, &db, 100, "threatfox", key).await;
    let after = dict_rows(&ch, &db).await;
    println!("dict after threatfox commit: {after:?}");
    assert_eq!(after, vec![("203.0.113.7".into(), "threatfox".into())]);
    assert_eq!(reader_rows(&ch, &db).await, ["198.51.100.5", "203.0.113.7"]);

    // 4. A replayed legacy write after the commit stays invisible.
    insert(&ch, &db, "airgap", "Air-gap IOC bundle", "203.0.113.88", 1, 0).await;
    assert_eq!(dict_rows(&ch, &db).await, after, "replayed legacy marketplace row ignored");

    // 5. Withdrawal does not bring legacy rows back.
    commit(&ch, &db, 101, "threatfox", "").await;
    assert!(dict_rows(&ch, &db).await.is_empty(), "withdrawn: nothing, never legacy");

    ch.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
}
