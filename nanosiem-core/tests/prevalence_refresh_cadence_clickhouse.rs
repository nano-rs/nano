// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5345: the planned-volume prevalence refresh cadence on a real
//! single-node ClickHouse. The shipped migration-160 views are created, then
//! rescheduled to 30 min (window 60), re-applied (no-op), left alone for an
//! unset cadence, and restored to the shipped 10 / 40 pair. The pure rewrite
//! is unit-tested in `src/db/clickhouse_migrate/prevalence_cadence_tests.rs`.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test prevalence_refresh_cadence_clickhouse -- --ignored
//! ```

use nanosiem_core::db::ClickHouseMigrator;

const MVS: [&str; 3] = [
    "hash_prevalence_final_refresh",
    "domain_prevalence_final_refresh",
    "ip_prevalence_final_refresh",
];

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

async fn exec(ch: &clickhouse::Client, sql: &str) {
    ch.query(sql).execute().await.unwrap_or_else(|e| panic!("{e}\n{sql}"));
}

/// `(cadence minutes, window minutes)` of every view, from the live catalog.
async fn schedule(ch: &clickhouse::Client, db: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for mv in MVS {
        let create: String = ch
            .query(&format!(
                "SELECT create_table_query FROM system.tables WHERE database = '{db}' AND name = '{mv}'"
            ))
            .fetch_one()
            .await
            .unwrap();
        // ClickHouse prints whole hours as HOUR.
        let every = create.split("REFRESH EVERY ").nth(1).unwrap().split(" APPEND").next().unwrap();
        let window = create.split("toIntervalMinute(").nth(1).unwrap().split(')').next().unwrap();
        assert!(create.contains(" APPEND TO "), "{mv} lost APPEND: {create}");
        out.push((every.to_string(), window.to_string()));
    }
    out
}

fn all(every: &str, window: &str) -> Vec<(String, String)> {
    vec![(every.to_string(), window.to_string()); 3]
}

/// Create the shipped migration-160 views (and minimal summaries) in `db`.
async fn create_shipped_views(ch: &clickhouse::Client, db: &str) {
    for (table, key, hosts, extra) in [
        ("hash_prevalence_summary", "file_hash", "host_count", ""),
        ("domain_prevalence_summary", "domain", "source_host_count", ""),
        ("ip_prevalence_summary", "ip", "source_host_count", "is_private UInt8, "),
    ] {
        exec(
            ch,
            &format!(
                "CREATE TABLE {db}.{table} ({key} String, {extra}{hosts} AggregateFunction(uniq, String), \
                 first_seen DateTime64(6), last_seen DateTime64(6), total_count UInt64) \
                 ENGINE = MergeTree ORDER BY {key}"
            ),
        )
        .await;
    }
    let shipped = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../clickhouse/160_prevalence_finalized_host_count.sql"
    ));
    for statement in shipped.split(";\n") {
        let sql: String = statement
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        if sql.trim().is_empty() {
            continue;
        }
        exec(ch, &sql.replace("nanosiem.", &format!("{db}."))).await;
    }
}

async fn with_databases<F, Fut>(names: &[&str], body: F)
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let ch = ch();
    let suffix = uuid::Uuid::now_v7().simple().to_string();
    let dbs: Vec<String> = names.iter().map(|n| format!("nan5345_{n}_{suffix}")).collect();
    for db in &dbs {
        exec(&ch, &format!("CREATE DATABASE {db}")).await;
    }
    let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(body(dbs.clone()))).await;
    for db in &dbs {
        exec(&ch, &format!("DROP DATABASE IF EXISTS {db}")).await;
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn cadence_follows_the_tier_and_resets_on_downsize() {
    with_databases(&["cadence"], |dbs| async move {
        let ch = ch();
        let db = &dbs[0];
        create_shipped_views(&ch, db).await;
        assert_eq!(schedule(&ch, db).await, all("10 MINUTE", "40"));

        let mut migrator = ClickHouseMigrator::new(ch.clone(), db).with_cluster(None);
        // An install that never had a planned volume: unset = 10, nothing to do.
        assert_eq!(migrator.apply_prevalence_refresh_cadence(10).await.unwrap(), 0);
        assert_eq!(schedule(&ch, db).await, all("10 MINUTE", "40"));
        // ~1 TB/day: 30 min over a 60 min window; a second run is a no-op.
        assert_eq!(migrator.apply_prevalence_refresh_cadence(30).await.unwrap(), 6);
        assert_eq!(schedule(&ch, db).await, all("30 MINUTE", "60"));
        assert_eq!(migrator.apply_prevalence_refresh_cadence(30).await.unwrap(), 0);
        // large -> volume cleared / small preset (unset = 10): reset.
        assert_eq!(migrator.apply_prevalence_refresh_cadence(10).await.unwrap(), 6);
        assert_eq!(schedule(&ch, db).await, all("10 MINUTE", "40"));
        // >=10 TB/day: whole hours read back as HOUR, still recognised.
        assert_eq!(migrator.apply_prevalence_refresh_cadence(60).await.unwrap(), 6);
        assert_eq!(schedule(&ch, db).await, all("1 HOUR", "90"));
        assert_eq!(migrator.apply_prevalence_refresh_cadence(60).await.unwrap(), 0);
        // xlarge -> unset: reset again.
        assert_eq!(migrator.apply_prevalence_refresh_cadence(10).await.unwrap(), 6);
        assert_eq!(schedule(&ch, db).await, all("10 MINUTE", "40"));
    })
    .await;
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn an_unrecognised_window_keeps_its_cadence() {
    with_databases(&["foreign"], |dbs| async move {
        let ch = ch();
        let db = &dbs[0];
        create_shipped_views(&ch, db).await;
        // Replace the hash view's body with one that has no recency window.
        exec(
            &ch,
            &format!(
                "ALTER TABLE {db}.hash_prevalence_final_refresh MODIFY QUERY \
                 SELECT file_hash, toUInt16(1) AS host_count, min(first_seen) AS first_seen, \
                 max(last_seen) AS last_seen, toUInt64(sum(total_count)) AS total_occurrences, \
                 now64(6) AS version FROM {db}.hash_prevalence_summary GROUP BY file_hash"
            ),
        )
        .await;
        let mut migrator = ClickHouseMigrator::new(ch.clone(), db).with_cluster(None);
        // Only the two recognisable views move (window + cadence each).
        assert_eq!(migrator.apply_prevalence_refresh_cadence(60).await.unwrap(), 4);
        let hash: String = ch
            .query(&format!(
                "SELECT create_table_query FROM system.tables \
                 WHERE database = '{db}' AND name = 'hash_prevalence_final_refresh'"
            ))
            .fetch_one()
            .await
            .unwrap();
        assert!(hash.contains("REFRESH EVERY 10 MINUTE APPEND"), "{hash}");
    })
    .await;
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn cadence_discovery_reads_only_the_connection_database() {
    with_databases(&["mine", "other"], |dbs| async move {
        let ch = ch();
        let (mine, other) = (&dbs[0], &dbs[1]);
        create_shipped_views(&ch, mine).await;
        create_shipped_views(&ch, other).await;
        // Same view names in another database, on a longer cadence.
        ClickHouseMigrator::new(ch.clone(), other)
            .with_cluster(None)
            .apply_prevalence_refresh_cadence(60)
            .await
            .unwrap();
        let sql = nanosiem_core::prevalence::coverage::PREVALENCE_REFRESH_SECONDS_SQL;
        let read = |db: &String| ch.clone().with_database(db).query(sql).fetch_one::<u32>();
        assert_eq!(read(mine).await.unwrap(), 600);
        assert_eq!(read(other).await.unwrap(), 3600);
    })
    .await;
}
