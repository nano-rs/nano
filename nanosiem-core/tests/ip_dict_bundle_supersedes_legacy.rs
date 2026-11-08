// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4959 review P2: CH migration 186 — legacy IP rows (native BYO
//! `ipinfo_lite`, retired air-gap `airgap_ip_enrichment`; platform_feed = 0)
//! feed the IP dictionaries only until the platform feed bundle commits an
//! ipinfo_lite generation.
//!
//! Static checks always run. The behaviour check runs the migration's exact
//! refresh SELECT against a REAL ClickHouse in its own database (production
//! `ip_enrichments` DDL from init.sql + migration 184's schema):
//!
//! - before any IPinfo commit, legacy rows are served (an upgraded install
//!   keeps geo/ASN until the bundle arrives);
//! - after the bundle commits, ONLY its generation is served: a stale legacy
//!   /24 inside the bundle's corrected /23 and a network the bundle dropped
//!   are both gone (the IP_TRIE longest-prefix case);
//! - a later withdrawal (hard expiry, empty key) does not bring legacy back;
//! - a ThreatFox/Tor-only commit does not hide legacy IP rows.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:<own port> \
//! NANOSIEM_TEST_CLICKHOUSE_USER=... NANOSIEM_TEST_CLICKHOUSE_PASSWORD=... \
//!   cargo test -p nanosiem-core --test ip_dict_bundle_supersedes_legacy -- --include-ignored --nocapture
//! ```

const MIGRATION_186: &str = include_str!("../../clickhouse/186_ip_dict_bundle_supersedes_legacy.sql");
const MIGRATION_184: &str = include_str!("../../clickhouse/184_platform_feed_commits.sql");
const MIGRATION_185: &str = include_str!("../../clickhouse/185_ip_geo_dict_split.sql");
const INIT_SQL: &str = include_str!("../../clickhouse/init.sql");

fn uncommented(sql: &str) -> String {
    sql.lines().filter(|l| !l.trim_start().starts_with("--")).collect::<Vec<_>>().join("\n")
}

/// The SELECT body migration 186 sets on ip_enrichment_dict_refresh.
fn refresh_select() -> String {
    let sql = uncommented(MIGRATION_186);
    let start = sql.find("MODIFY QUERY ").expect("MODIFY QUERY") + "MODIFY QUERY ".len();
    sql[start..].trim().trim_end_matches(';').to_string()
}

#[test]
fn migration_186_modifies_only_the_ip_refresh_view_and_gates_legacy_rows() {
    let sql = uncommented(MIGRATION_186);
    let statements: Vec<&str> = sql.split(';').map(str::trim).filter(|s| !s.is_empty()).collect();
    assert_eq!(statements.len(), 1, "one statement: {statements:?}");
    assert!(statements[0].starts_with("ALTER TABLE nanosiem.ip_enrichment_dict_refresh\nMODIFY QUERY SELECT"));
    assert!(!statements[0].contains("MODIFY QUERY AS"), "MODIFY QUERY takes the SELECT directly (NAN-1727)");
    let body = refresh_select();
    assert!(
        body.contains("(platform_feed = 0 AND 'ipinfo_lite' GLOBAL NOT IN (SELECT feed_id FROM nanosiem.platform_feed_commits WHERE storage_key != ''))"),
        "legacy rows only until an ipinfo_lite generation commits: {body}"
    );
    assert!(
        body.contains("(platform_feed = 1 AND source_id GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id))"),
        "platform rows keep 184's active-generation rule: {body}"
    );
    // Every base reference is the bare local name, which the cluster
    // post-reconcile step repoints to the _distributed wrappers.
    assert!(!body.contains("_distributed"));
    // Memory bounds (NAN-4957 / migration 185 settings).
    for setting in ["max_bytes_before_external_group_by = 268435456", "max_memory_usage = 1500000000", "max_threads = 2"] {
        assert!(body.contains(setting), "{setting} missing");
    }
    assert!(!INIT_SQL.contains("platform_feed"), "init.sql bodies are not edited");
}

/// 186 is the latest definition of ip_enrichment_dict_refresh: NAN-4957's 185
/// body (its spill / insert-block settings, which the split geo pair's staging
/// refresh depends on) with only the visibility WHERE replaced.
#[test]
fn migration_186_is_185s_refresh_body_with_only_the_where_changed() {
    let sql = uncommented(MIGRATION_185);
    let head = "ALTER TABLE nanosiem.ip_enrichment_dict_refresh\nMODIFY QUERY ";
    let start = sql.find(head).expect("185 re-issues the IP refresh view") + head.len();
    let body_185 = sql[start..].split(';').next().unwrap().trim().to_string();
    let old_where = "WHERE platform_feed = 0 OR source_id GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id)";
    let new_where = "WHERE (platform_feed = 0 AND 'ipinfo_lite' GLOBAL NOT IN (SELECT feed_id FROM nanosiem.platform_feed_commits WHERE storage_key != '')) OR (platform_feed = 1 AND source_id GLOBAL IN (SELECT argMax(storage_key, (sequence, committed_at)) FROM nanosiem.platform_feed_commits GROUP BY feed_id))";
    assert!(body_185.contains(old_where), "185's WHERE moved: {body_185}");
    assert_eq!(refresh_select().replace(new_where, old_where), body_185, "186 must only change 185's WHERE");
    // No migration after 186 redefines the IP refresh view (186 stays latest).
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../clickhouse");
    for entry in std::fs::read_dir(dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let num: u32 = name.split('_').next().and_then(|n| n.parse().ok()).unwrap_or(0);
        if num > 186 {
            let text = std::fs::read_to_string(format!("{dir}/{name}")).unwrap();
            assert!(!text.contains("ALTER TABLE nanosiem.ip_enrichment_dict_refresh"), "{name} redefines the IP refresh view after 186");
        }
    }
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

/// init.sql's `ip_enrichments` CREATE plus 184's column and commits table, in `db`.
fn schema(db: &str) -> Vec<String> {
    let init = uncommented(INIT_SQL);
    let head = "CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichments";
    let start = init.find(head).expect("ip_enrichments in init.sql");
    let create = init[start..].split(';').next().unwrap().to_string();
    let mut out = vec![create];
    for s in uncommented(MIGRATION_184).split(';').map(str::trim) {
        if s.starts_with("CREATE TABLE IF NOT EXISTS nanosiem.platform_feed_commits")
            || s.starts_with("ALTER TABLE nanosiem.ip_enrichments ADD COLUMN")
        {
            out.push(s.to_string());
        }
    }
    assert_eq!(out.len(), 3, "schema statements");
    out.into_iter().map(|s| s.replace("nanosiem.", &format!("{db}."))).collect()
}

#[derive(clickhouse::Row, serde::Deserialize, Debug, PartialEq)]
struct Served {
    network: String,
    country: String,
}

async fn served(ch: &clickhouse::Client, db: &str) -> Vec<(String, String)> {
    let sql = format!(
        "SELECT network, country FROM ({}) ORDER BY network",
        refresh_select().replace("nanosiem.", &format!("{db}."))
    );
    let rows: Vec<Served> = ch.query(&sql).fetch_all().await.unwrap();
    rows.into_iter().map(|r| (r.network, r.country)).collect()
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
async fn bundle_ipinfo_commit_retires_legacy_rows_from_the_dictionary() {
    let ch = ch().expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let db = format!("ip186_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    ch.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
    for sql in schema(&db) {
        ch.query(&sql).execute().await.unwrap();
    }
    // Legacy rows: a native BYO sync (stale /24 + a network the bundle drops)
    // and a retired air-gap import.
    ch.query(&format!(
        "INSERT INTO {db}.ip_enrichments (network, source_id, country, updated_at, deleted, platform_feed) VALUES \
         ('198.51.100.0/24', 'ipinfo_lite', 'XX-stale', now64(3) - INTERVAL 2 DAY, 0, 0), \
         ('192.0.2.0/24', 'ipinfo_lite', 'XX-dropped', now64(3) - INTERVAL 2 DAY, 0, 0), \
         ('203.0.113.0/24', 'airgap_ip_enrichment', 'XX-airgap', now64(3) - INTERVAL 2 DAY, 0, 0)"
    ))
    .execute()
    .await
    .unwrap();
    // The bundle's generation (written, not yet committed): a corrected /23.
    let key = "platform_feed/ipinfo_lite/100";
    ch.query(&format!(
        "INSERT INTO {db}.ip_enrichments (network, source_id, country, updated_at, deleted, platform_feed) VALUES \
         ('198.51.100.0/23', ?, 'NL', now64(3), 0, 1)"
    ))
    .bind(key)
    .execute()
    .await
    .unwrap();

    // 1. No IPinfo commit yet: legacy served, the uncommitted generation is not.
    let before = served(&ch, &db).await;
    println!("before commit: {before:?}");
    assert_eq!(
        before,
        vec![
            ("192.0.2.0/24".into(), "XX-dropped".into()),
            ("198.51.100.0/24".into(), "XX-stale".into()),
            ("203.0.113.0/24".into(), "XX-airgap".into()),
        ]
    );

    // 2. A Tor-only commit does not hide legacy IP rows.
    commit(&ch, &db, 50, "tor_exit_nodes", "platform_feed/tor_exit_nodes/50").await;
    assert_eq!(served(&ch, &db).await, before, "non-IP commit leaves legacy IP rows alone");

    // 3. The bundle commits IPinfo: only its generation is served.
    commit(&ch, &db, 100, "ipinfo_lite", key).await;
    let after = served(&ch, &db).await;
    println!("after ipinfo commit: {after:?}");
    assert_eq!(after, vec![("198.51.100.0/23".into(), "NL".into())], "stale /24, dropped and air-gap rows gone");

    // 4. Withdrawal (hard expiry) does not bring stale legacy data back.
    commit(&ch, &db, 101, "ipinfo_lite", "").await;
    assert_eq!(served(&ch, &db).await, Vec::<(String, String)>::new(), "withdrawn: nothing, never legacy");

    // Nothing was deleted: the legacy rows are still stored.
    let stored: u64 = ch
        .query(&format!("SELECT count() FROM {db}.ip_enrichments WHERE platform_feed = 0"))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(stored, 3);

    ch.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
}
