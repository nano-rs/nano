// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4948: the platform feed bundle install policy against a REAL
//! ClickHouse and PostgreSQL, with a fixture signing key (an expired or
//! tampered production-signed bundle cannot be produced on demand).
//!
//! Each run uses its own PostgreSQL database (migrated) and ClickHouse
//! database (the production `custom_enrichment_results` and `ip_enrichments`
//! DDL from init.sql, upgraded by migration 184's schema statements), so
//! counts are exact.
//!
//! Proves, through `PlatformFeedConsumer::import_file`:
//! - a valid bundle installs: IOC rows land under its generation key and the
//!   commit makes them visible through the production reader predicate;
//! - an entirely expired bundle, a tampered payload, a tampered descriptor and
//!   a rollback are REFUSED, and the last good install (PG state and the
//!   visible ClickHouse generation) is untouched;
//! - re-importing the installed bundle is `current` (nothing re-loaded);
//! - a newer bundle replaces the old generation at once, a feed it no longer
//!   carries is withdrawn, and superseded rows are reclaimed;
//! - a feed that passes its hard expiry is withdrawn by `reconcile`;
//! - (codex review) tenant rows in a `platform_feed/…` namespace are never
//!   hidden or reclaimed (ownership is the `platform_feed` column); a lost
//!   PostgreSQL record is repaired from the ClickHouse commit receipt; a feed
//!   omitted and re-introduced below its committed high-water revision is
//!   refused; a held install lease refuses a concurrent import before staging;
//!   a configured BYO IPinfo source no longer gates the install (NAN-4959); a
//!   superseded leader (NAN-4933 fence) cannot commit.
//!
//! ```text
//! NANOSIEM_TEST_DATABASE_URL=postgres://nanosiem:...@127.0.0.1:25448/nanosiem \
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:28123 \
//! NANOSIEM_TEST_CLICKHOUSE_USER=nanosiem_admin NANOSIEM_TEST_CLICKHOUSE_PASSWORD=... \
//!   cargo test -p nanosiem-core --test platform_feed_consumer_integration -- --ignored --nocapture
//! ```

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use nanosiem_core::platform_enrichment::consumer::{
    ConsumerConfig, ConsumerError, Outcome, PlatformFeedConsumer,
};
use nanosiem_core::platform_enrichment::loader::ClickHouseLoader;
use nanosiem_core::platform_enrichment::nanpfb::{self, IocSnapshotInput};
use nanosiem_core::platform_enrichment::portable::{self, FeedEntry, KeyRing};
use nanosiem_core::platform_enrichment::state::{visible_predicate, StateRepository};

const INIT_SQL: &str = include_str!("../../clickhouse/init.sql");
const KEY_ID: &str = "fixture-integration-1";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[0x37; 32])
}

fn ring() -> KeyRing {
    KeyRing::from_hex(&[(KEY_ID, &hex::encode(key().verifying_key().as_bytes()))]).unwrap()
}

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
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

async fn fresh_ch_db(ch: &clickhouse::Client) -> String {
    let db = format!("pf_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    ch.query(&format!("CREATE DATABASE {db}")).execute().await.unwrap();
    for head in [
        "CREATE TABLE IF NOT EXISTS nanosiem.custom_enrichment_results",
        "CREATE TABLE IF NOT EXISTS nanosiem.ip_enrichments",
    ] {
        let sql = statement(head).replace("nanosiem.", &format!("{db}."));
        ch.query(&sql).execute().await.unwrap();
    }
    // Upgrade exactly as an existing install does: migration 184's schema.
    for sql in migration_184_schema(&db, &["custom_enrichment_results", "ip_enrichments"]) {
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


async fn fresh_pg() -> (sqlx::PgPool, String) {
    let url = std::env::var("NANOSIEM_TEST_DATABASE_URL")
        .expect("NANOSIEM_TEST_DATABASE_URL must target a disposable PostgreSQL");
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("pf_{}", &uuid::Uuid::now_v7().simple().to_string()[18..]);
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let (base, _) = url.rsplit_once('/').unwrap();
    let pool = sqlx::PgPool::connect(&format!("{base}/{name}")).await.unwrap();
    nanosiem_core::db::run_postgres_migrations(&pool).await.unwrap();
    (pool, name)
}

fn entry(feed: &str, revision: i64, upstream_at: DateTime<Utc>, hard_expiry: DateTime<Utc>, rows: u64) -> FeedEntry {
    FeedEntry {
        revision,
        license_id: portable::portable_terms(feed).unwrap().license_id.into(),
        terms_revision: format!("{feed}-reviewed").replace('_', "-"),
        upstream_at,
        produced_at: upstream_at + Duration::minutes(10),
        hard_expiry,
        row_count: rows,
        source_sha256: "ab".repeat(32),
    }
}

fn ioc(feed: &str, ty: &str, value: &str, threat: &str) -> IocSnapshotInput {
    IocSnapshotInput {
        ioc_value: value.into(),
        ioc_type: ty.into(),
        source_id: feed.into(),
        enrichment_name: feed.into(),
        threat_type: threat.into(),
        confidence_level: 80,
        ..Default::default()
    }
}

/// Seal `feeds` + `rows` at `sequence` into `dir/<name>.nanfeed`.
fn seal(dir: &Path, name: &str, feeds: BTreeMap<String, FeedEntry>, rows: &[IocSnapshotInput], sequence: u64) -> PathBuf {
    let payload = dir.join(format!("{name}.nanpfb"));
    nanpfb::write(
        &payload,
        None,
        rows,
        None,
        feeds.iter().map(|(k, f)| (k.clone(), f.revision)).collect(),
        feeds.iter().map(|(k, f)| (k.clone(), f.hard_expiry)).collect(),
    )
    .unwrap();
    let produced = feeds.values().map(|f| f.produced_at).max().unwrap();
    let out = dir.join(format!("{name}.nanfeed"));
    portable::seal(&payload, feeds, sequence, produced, KEY_ID, &key(), &ring(), &out).unwrap();
    out
}

#[derive(clickhouse::Row, serde::Deserialize, Debug)]
struct Visible {
    enrichment_name: String,
    key_value: String,
}

async fn visible(ch: &clickhouse::Client, db: &str) -> Vec<(String, String)> {
    let predicate = visible_predicate("namespace", &format!("{db}.platform_feed_commits"));
    let mut rows: Vec<Visible> = ch
        .query(&format!(
            "SELECT toString(enrichment_name) AS enrichment_name, key_value FROM {db}.custom_enrichment_results \
             WHERE {predicate} AND expires_at > now64(3) AND enrichment_name != 'acme' ORDER BY enrichment_name, key_value"
        ))
        .fetch_all()
        .await
        .unwrap();
    rows.drain(..).map(|r| (r.enrichment_name, r.key_value)).collect()
}

async fn stored_rows(ch: &clickhouse::Client, db: &str) -> u64 {
    // Loader-owned rows only (tenant rows are counted separately).
    ch.query(&format!("SELECT count() FROM {db}.custom_enrichment_results WHERE platform_feed = 1"))
        .fetch_one::<u64>()
        .await
        .unwrap()
}

async fn installed_sequence(pool: &sqlx::PgPool) -> Option<i64> {
    sqlx::query_scalar::<_, Option<i64>>("SELECT sequence FROM platform_feed_state WHERE id = TRUE")
        .fetch_optional(pool)
        .await
        .unwrap()
        .flatten()
}

#[tokio::test]
#[ignore = "needs NANOSIEM_TEST_DATABASE_URL + NANOSIEM_TEST_CLICKHOUSE_URL (disposable)"]
async fn install_policy_against_real_clickhouse_and_postgres() {
    let ch = ch();
    let db = fresh_ch_db(&ch).await;
    let (pool, pg_name) = fresh_pg().await;
    let work = tempfile::tempdir().unwrap();
    let files = tempfile::tempdir().unwrap();
    let consumer = PlatformFeedConsumer::new(
        StateRepository::new(pool.clone()),
        ClickHouseLoader::new(ch.clone(), ch.clone()).with_database(&db),
        ConsumerConfig {
            open_url: "https://unused.invalid/open".into(),
            sovereign_url: "https://unused.invalid/sovereign".into(),
            mirror_url: None,
            license: None,
            work_dir: work.path().join("feeds"),
            poll_interval: StdDuration::from_secs(3600),
            auto_update: false,
        },
    )
    .with_ring(ring());
    let now = Utc::now();
    let up = now - Duration::hours(2);
    let live = up + Duration::hours(20);

    // A pre-existing TENANT enrichment whose namespace happens to start with
    // `platform_feed/` (written before the feature; marker column default 0).
    ch.query(&format!(
        "INSERT INTO {db}.custom_enrichment_results (namespace, enrichment_id, enrichment_name, key_type, key_value, \
         tags, data, fetched_at, expires_at, version, is_ioc, threat_type, confidence, is_marketplace) VALUES \
         ('platform_feed/acme', generateUUIDv4(), 'acme', 'ip', '192.0.2.44', [], '{{}}', now64(3), now64(3) + INTERVAL 30 DAY, 1, 1, 'tenant', 50, 0), \
         ('platform_feed/threatfox/1', generateUUIDv4(), 'acme', 'domain', 'tenant.example', [], '{{}}', now64(3), now64(3) + INTERVAL 30 DAY, 1, 1, 'tenant', 50, 0)"
    ))
    .execute()
    .await
    .unwrap();

    // 1. A valid bundle installs and becomes visible in one commit.
    let a_feeds: BTreeMap<_, _> = [
        ("threatfox".to_string(), entry("threatfox", 10, up, live, 2)),
        ("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 5, up, live, 1)),
    ]
    .into();
    let a = seal(
        files.path(),
        "a",
        a_feeds,
        &[
            ioc("threatfox", "ip:port", "203.0.113.7:8080", "botnet_cc"),
            ioc("threatfox", "domain", "evil.example", "botnet_cc"),
            ioc("tor_exit_nodes", "ip", "198.51.100.9", "tor_exit"),
        ],
        100,
    );
    let outcome = consumer.import_file(&a).await.unwrap();
    assert!(matches!(&outcome, Outcome::Installed { sequence: 100, loaded } if loaded["threatfox"] == 2 && loaded["tor_exit_nodes"] == 1), "{outcome:?}");
    let good = vec![
        ("threatfox".to_string(), "203.0.113.7".to_string()),
        ("threatfox".to_string(), "evil.example".to_string()),
        ("tor_exit_nodes".to_string(), "198.51.100.9".to_string()),
    ];
    assert_eq!(visible(&ch, &db).await, good);
    assert_eq!(installed_sequence(&pool).await, Some(100));
    println!("1. installed sequence 100: {:?}", visible(&ch, &db).await);

    // 2. Re-importing the installed bundle is current.
    assert_eq!(consumer.import_file(&a).await.unwrap(), Outcome::Current { sequence: 100 });
    println!("2. re-import of the installed bundle: current");

    // 3. An entirely expired newer bundle is refused; last good kept.
    let old_up = now - Duration::days(3);
    let expired = seal(
        files.path(),
        "expired",
        [("threatfox".to_string(), entry("threatfox", 11, old_up, old_up + Duration::hours(20), 1))].into(),
        &[ioc("threatfox", "domain", "expired.example", "botnet_cc")],
        200,
    );
    let err = consumer.import_file(&expired).await.unwrap_err();
    assert!(matches!(&err, ConsumerError::Refused(m) if m.contains("expired")), "{err}");
    assert_eq!(installed_sequence(&pool).await, Some(100));
    assert_eq!(visible(&ch, &db).await, good);
    println!("3. expired bundle refused ({err}); last good kept");

    // 4. A tampered payload byte is refused before anything is written.
    let fresh: BTreeMap<_, _> = [("threatfox".to_string(), entry("threatfox", 12, up, live, 1))].into();
    let tampered = seal(files.path(), "tampered", fresh.clone(), &[ioc("threatfox", "domain", "new.example", "botnet_cc")], 300);
    let mut bytes = std::fs::read(&tampered).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 0x01;
    std::fs::write(&tampered, &bytes).unwrap();
    let before = stored_rows(&ch, &db).await;
    let err = consumer.import_file(&tampered).await.unwrap_err();
    assert!(matches!(&err, ConsumerError::Refused(m) if m.contains("payload")), "{err}");
    assert_eq!(stored_rows(&ch, &db).await, before, "nothing written for a refused bundle");
    assert_eq!(visible(&ch, &db).await, good);
    println!("4. tampered payload refused ({err}); nothing written");

    // 5. A tampered descriptor (sequence bumped without re-signing) is refused.
    let honest = seal(files.path(), "honest", fresh.clone(), &[ioc("threatfox", "domain", "new.example", "botnet_cc")], 300);
    let mut bytes = std::fs::read(&honest).unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let at = text.find("\"sequence\":300").unwrap();
    bytes[at + "\"sequence\":".len()] = b'9';
    std::fs::write(&honest, &bytes).unwrap();
    let err = consumer.import_file(&honest).await.unwrap_err();
    assert!(matches!(&err, ConsumerError::Refused(m) if m.contains("signature")), "{err}");
    assert_eq!(installed_sequence(&pool).await, Some(100));
    println!("5. tampered descriptor refused ({err})");

    // 6. A rollback (older sequence) is refused.
    let older = seal(files.path(), "older", fresh.clone(), &[ioc("threatfox", "domain", "old.example", "botnet_cc")], 50);
    let err = consumer.import_file(&older).await.unwrap_err();
    assert!(matches!(&err, ConsumerError::Refused(m) if m.contains("older")), "{err}");
    assert_eq!(visible(&ch, &db).await, good);
    println!("6. rollback refused ({err})");

    // The refusals are recorded; the installed bundle is not.
    let status = consumer.status().await.unwrap();
    assert_eq!((status.sequence, status.last_check_status.as_deref()), (Some(100), Some("refused")));
    assert!(status.last_error.unwrap().contains("older"));

    // 7. A newer bundle replaces the generation at once; the feed it dropped
    // (tor) is withdrawn; superseded rows are reclaimed.
    let b = seal(files.path(), "b", fresh, &[ioc("threatfox", "domain", "new.example", "botnet_cc")], 400);
    assert!(matches!(consumer.import_file(&b).await.unwrap(), Outcome::Installed { sequence: 400, .. }));
    assert_eq!(visible(&ch, &db).await, vec![("threatfox".to_string(), "new.example".to_string())]);
    let status = consumer.status().await.unwrap();
    assert_eq!(status.sequence, Some(400));
    assert_eq!(status.last_check_status.as_deref(), Some("installed"));
    assert!(status.last_error.is_none());
    for _ in 0..50 {
        if stored_rows(&ch, &db).await == 1 {
            break;
        }
        tokio::time::sleep(StdDuration::from_millis(200)).await;
    }
    assert_eq!(stored_rows(&ch, &db).await, 1, "superseded generation reclaimed");
    println!("7. sequence 400 installed; tor withdrawn; old generation reclaimed");

    // 8. A feed that passes its hard expiry is withdrawn by reconcile.
    let soon = Utc::now() + Duration::seconds(3);
    let c = seal(
        files.path(),
        "c",
        [
            ("threatfox".to_string(), entry("threatfox", 13, up, live, 1)),
            ("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 6, up, soon, 1)),
        ]
        .into(),
        &[
            ioc("threatfox", "domain", "new.example", "botnet_cc"),
            ioc("tor_exit_nodes", "ip", "198.51.100.10", "tor_exit"),
        ],
        500,
    );
    assert!(matches!(consumer.import_file(&c).await.unwrap(), Outcome::Installed { sequence: 500, .. }));
    assert!(!consumer.reconcile().await.unwrap(), "nothing expired yet");
    tokio::time::sleep(StdDuration::from_secs(4)).await;
    assert!(consumer.reconcile().await.unwrap(), "tor withdrawn after its hard expiry");
    let status = consumer.status().await.unwrap();
    let tor = status.feeds.iter().find(|f| f.feed_id == "tor_exit_nodes").unwrap();
    assert!(!tor.active);
    let active: Vec<(String, String)> = consumer_active(&ch, &db).await;
    assert!(active.contains(&("tor_exit_nodes".to_string(), String::new())), "{active:?}");
    println!("8. tor withdrawn by reconcile after its hard expiry: {active:?}");

    // 9. Tenant rows were never hidden nor reclaimed through 8 installs.
    let tenant: u64 = ch
        .query(&format!(
            "SELECT count() FROM {db}.custom_enrichment_results WHERE enrichment_name = 'acme' \
             AND {}",
            visible_predicate("namespace", &format!("{db}.platform_feed_commits"))
        ))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(tenant, 2, "tenant platform_feed/* rows stay visible and unreclaimed");
    println!("9. tenant rows in platform_feed/* namespaces still visible: {tenant}");

    // 10. Split-brain: PostgreSQL lost the record after the ClickHouse commit.
    sqlx::query("DELETE FROM platform_feed_state").execute(&pool).await.unwrap();
    assert!(!consumer.status().await.unwrap().installed);
    assert!(consumer.repair_from_clickhouse().await.unwrap(), "repaired");
    let status = consumer.status().await.unwrap();
    assert_eq!(status.sequence, Some(500));
    assert!(!status.feeds.iter().find(|f| f.feed_id == "tor_exit_nodes").unwrap().active);
    assert!(!consumer.repair_from_clickhouse().await.unwrap(), "already in agreement");
    // ...and an older record is repaired before any decision uses it.
    sqlx::query("UPDATE platform_feed_state SET sequence = 400").execute(&pool).await.unwrap();
    let reimport = consumer.import_file(&c).await.unwrap();
    assert_eq!(reimport, Outcome::Current { sequence: 500 }, "decided against the repaired generation");
    println!("10. PostgreSQL record rebuilt from the ClickHouse commit receipt");

    // 11. Per-feed high-water: omit threatfox, then re-introduce it lower.
    let up2 = Utc::now() - Duration::hours(1);
    let live2 = up2 + Duration::hours(20);
    let omit = seal(
        files.path(),
        "omit",
        [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 7, up2, live2, 1))].into(),
        &[ioc("tor_exit_nodes", "ip", "198.51.100.11", "tor_exit")],
        600,
    );
    assert!(matches!(consumer.import_file(&omit).await.unwrap(), Outcome::Installed { sequence: 600, .. }));
    let lower = seal(
        files.path(),
        "lower",
        [
            ("threatfox".to_string(), entry("threatfox", 5, up2, live2, 1)),
            ("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 7, up2, live2, 1)),
        ]
        .into(),
        &[
            ioc("threatfox", "domain", "stale.example", "botnet_cc"),
            ioc("tor_exit_nodes", "ip", "198.51.100.11", "tor_exit"),
        ],
        700,
    );
    let err = consumer.import_file(&lower).await.unwrap_err();
    assert!(matches!(&err, ConsumerError::Refused(m) if m.contains("older than revision 13")), "{err}");
    println!("11. feed re-introduced below its high-water refused ({err})");

    // 12. Single flight: a held lease refuses an import before staging it.
    let lease = consumer.lease().await.unwrap();
    assert!(matches!(consumer.import_file(&lower).await, Err(ConsumerError::Busy)));
    assert_eq!(std::fs::read_dir(work.path().join("feeds")).unwrap().count(), 0, "nothing staged");
    lease.release().await;
    println!("12. concurrent import refused (Busy) with nothing staged");

    // 13. NAN-4959: a configured BYO IPinfo source (as an install from before
    // this change has) no longer gates anything: the consumer never reads
    // enrichment_sources, so the install proceeds.
    let byo = sqlx::query(
        "UPDATE enrichment_sources SET enabled = true, download_url = 'https://ipinfo.io/data/ipinfo_lite.csv.gz?token=byo' \
         WHERE id = 'ipinfo_lite'",
    )
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(byo, 1, "seeded ipinfo_lite source");
    let up3 = Utc::now() - Duration::minutes(30);
    let with_byo = seal(
        files.path(),
        "with-byo",
        [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 7, up3, up3 + Duration::hours(20), 1))].into(),
        &[ioc("tor_exit_nodes", "ip", "198.51.100.11", "tor_exit")],
        750,
    );
    assert!(matches!(consumer.import_file(&with_byo).await.unwrap(), Outcome::Installed { sequence: 750, .. }));
    assert_eq!(installed_sequence(&pool).await, Some(750));
    println!("13. a configured BYO IPinfo source does not block or alter the install");
    // 14. A revision gap is accepted end to end by the real consumer. The
    // publisher may burn revision 8 after uploading it without activation;
    // the next valid bundle therefore advances directly from r7 to r9.
    let gap = seal(
        files.path(),
        "gap",
        [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 9, up3, up3 + Duration::hours(20), 1))].into(),
        &[ioc("tor_exit_nodes", "ip", "198.51.100.13", "tor_exit")],
        800,
    );
    assert!(matches!(consumer.import_file(&gap).await.unwrap(), Outcome::Installed { sequence: 800, .. }));
    assert_eq!(installed_sequence(&pool).await, Some(800));
    assert_eq!(visible(&ch, &db).await, vec![("tor_exit_nodes".to_string(), "198.51.100.13".to_string())]);
    println!("14. real consumer accepted tor revision gap r7 -> r9");

    let next = seal(
        files.path(),
        "next",
        [("tor_exit_nodes".to_string(), entry("tor_exit_nodes", 10, up3, up3 + Duration::hours(20), 1))].into(),
        &[ioc("tor_exit_nodes", "ip", "198.51.100.14", "tor_exit")],
        850,
    );

    // 15. NAN-4933 leader fence: a superseded leader's commit is refused.
    let stale = PlatformFeedConsumer::new(
        StateRepository::new(pool.clone()),
        ClickHouseLoader::new(ch.clone(), ch.clone()).with_database(&db),
        ConsumerConfig {
            open_url: "https://unused.invalid/open".into(),
            sovereign_url: "https://unused.invalid/sovereign".into(),
            mirror_url: None,
            license: None,
            work_dir: work.path().join("feeds"),
            poll_interval: StdDuration::from_secs(3600),
            auto_update: false,
        },
    )
    .with_ring(ring())
    .with_fence(nanosiem_core::leader::LeaderFence::pinned(0x4e53_5046_4544, 999));
    let err = stale.import_file(&next).await.unwrap_err();
    assert!(matches!(&err, ConsumerError::Install(m) if m.contains("no longer current")), "{err}");
    assert_eq!(installed_sequence(&pool).await, Some(800), "superseded leader committed nothing");
    assert!(consumer_active(&ch, &db).await.iter().all(|(_, key)| !key.ends_with("/850")));
    println!("15. superseded leader's commit refused by the lease-epoch fence ({err})");

    ch.query(&format!("DROP DATABASE {db}")).execute().await.unwrap();
    pool.close().await;
    let admin = sqlx::PgPool::connect(&std::env::var("NANOSIEM_TEST_DATABASE_URL").unwrap()).await.unwrap();
    sqlx::query(&format!("DROP DATABASE {pg_name}")).execute(&admin).await.unwrap();
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct ActiveRow {
    feed_id: String,
    storage_key: String,
}

async fn consumer_active(ch: &clickhouse::Client, db: &str) -> Vec<(String, String)> {
    let rows: Vec<ActiveRow> = ch
        .query(&format!(
            "SELECT toString(feed_id) AS feed_id, argMax(storage_key, (sequence, committed_at)) AS storage_key \
             FROM {db}.platform_feed_commits GROUP BY feed_id ORDER BY feed_id"
        ))
        .fetch_all()
        .await
        .unwrap();
    rows.into_iter().map(|r| (r.feed_id, r.storage_key)).collect()
}
