// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4918: the operator drop of `ocsf_logs_legacy_v179` on a real
//! single-node ClickHouse. The drop is refused while any legacy day is missing
//! or mismatched in `ocsf_logs` (post-cutover ingest on the same day does not
//! count, duplicates do), is a dry run without `confirm`, and drops only when
//! every day matches. The cluster statements are unit-tested in
//! `src/db/clickhouse_migrate/ocsf_legacy_drop_tests.rs`.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test ocsf_legacy_drop_clickhouse -- --ignored
//! ```

use nanosiem_core::db::clickhouse_migrate::{LegacyDayStatus, OcsfLegacyDropOutcome};
use nanosiem_core::db::ClickHouseMigrator;

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

async fn exec(ch: &clickhouse::Client, sql: &str) {
    ch.query(sql).execute().await.unwrap_or_else(|e| panic!("{e}\n{sql}"));
}

/// Statuses by day, as `(day, legacy rows, missing ids, duplicate ids, status)`.
fn summary(outcome: &OcsfLegacyDropOutcome) -> Vec<(String, u64, u64, u64, LegacyDayStatus)> {
    let plan = match outcome {
        OcsfLegacyDropOutcome::Refused(p)
        | OcsfLegacyDropOutcome::DryRun(p)
        | OcsfLegacyDropOutcome::Dropped(p) => p,
        OcsfLegacyDropOutcome::Absent => return vec![],
    };
    plan.days
        .iter()
        .map(|d| (d.day.to_string(), d.legacy_rows, d.missing_ids, d.duplicate_ids, d.status()))
        .collect()
}

async fn legacy_exists(ch: &clickhouse::Client, db: &str) -> bool {
    ch.query(&format!("EXISTS TABLE {db}.ocsf_logs_legacy_v179"))
        .fetch_one::<u8>()
        .await
        .unwrap()
        == 1
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn drop_is_refused_until_every_day_matches_then_drops_only_with_confirm() {
    let ch = ch();
    let db = format!("nan4918_legacy_{}", uuid::Uuid::now_v7().simple());
    exec(&ch, &format!("CREATE DATABASE {db}")).await;
    let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(scenario(&ch, &db))).await;
    exec(&ch, &format!("DROP DATABASE IF EXISTS {db}")).await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

async fn scenario(ch: &clickhouse::Client, db: &str) {
    // Single node: pin it, so a test cluster defined on the server (see
    // `a_cluster_with_an_unavailable_shard_is_refused`) is not auto-detected.
    let mut migrator = ClickHouseMigrator::new(ch.clone(), db).with_cluster(None);

    // No legacy table: nothing to drop.
    assert!(matches!(migrator.drop_ocsf_legacy(true).await.unwrap(), OcsfLegacyDropOutcome::Absent));

    for t in ["ocsf_logs_legacy_v179", "ocsf_logs"] {
        exec(
            ch,
            &format!(
                "CREATE TABLE {db}.{t} (id UUID, timestamp DateTime64(3), source_type LowCardinality(String)) \
                 ENGINE = MergeTree PARTITION BY toYYYYMMDD(timestamp) ORDER BY (timestamp, id)"
            ),
        )
        .await;
    }
    // Legacy: 3 rows on 2026-10-01, 2 rows on 2026-10-02.
    exec(
        ch,
        &format!(
            "INSERT INTO {db}.ocsf_logs_legacy_v179 SELECT generateUUIDv7(number), \
             if(number < 3, toDateTime64('2026-10-01 05:00:00', 3, 'UTC'), toDateTime64('2026-10-02 23:59:59.999', 3, 'UTC')), 'edr' \
             FROM numbers(5)"
        ),
    )
    .await;
    // Backfill day 1 only, plus 4 rows of new (post-cutover) ingest on day 2:
    // a plain per-day count would equal or exceed legacy there, the id match
    // does not.
    let copy_day = |day: &str| {
        format!(
            "INSERT INTO {db}.ocsf_logs SELECT id, timestamp, source_type FROM {db}.ocsf_logs_legacy_v179 \
             WHERE toDate(timestamp, 'UTC') = '{day}'"
        )
    };
    exec(ch, &copy_day("2026-10-01")).await;
    exec(
        ch,
        &format!(
            "INSERT INTO {db}.ocsf_logs SELECT generateUUIDv7(number), toDateTime64('2026-10-02 12:00:00', 3, 'UTC'), 'edr' FROM numbers(4)"
        ),
    )
    .await;

    let out = migrator.drop_ocsf_legacy(true).await.unwrap();
    assert!(matches!(out, OcsfLegacyDropOutcome::Refused(_)), "{out:?}");
    assert_eq!(
        summary(&out),
        vec![
            ("2026-10-01".into(), 3, 0, 0, LegacyDayStatus::Match),
            ("2026-10-02".into(), 2, 2, 0, LegacyDayStatus::Missing),
        ]
    );
    assert!(legacy_exists(ch, db).await);

    // Partial copy of day 2: mismatch.
    exec(
        ch,
        &format!(
            "INSERT INTO {db}.ocsf_logs SELECT id, timestamp, source_type FROM {db}.ocsf_logs_legacy_v179 \
             WHERE toDate(timestamp, 'UTC') = '2026-10-02' ORDER BY id LIMIT 1"
        ),
    )
    .await;
    let out = migrator.drop_ocsf_legacy(true).await.unwrap();
    assert_eq!(summary(&out)[1], ("2026-10-02".into(), 2, 1, 0, LegacyDayStatus::Mismatch));
    assert!(matches!(out, OcsfLegacyDropOutcome::Refused(_)));

    // Complete day 2, but day 1 copied twice: a duplicate also refuses.
    exec(
        ch,
        &format!(
            "INSERT INTO {db}.ocsf_logs SELECT id, timestamp, source_type FROM {db}.ocsf_logs_legacy_v179 \
             WHERE toDate(timestamp, 'UTC') = '2026-10-02' ORDER BY id LIMIT 1 OFFSET 1"
        ),
    )
    .await;
    exec(ch, &copy_day("2026-10-01")).await;
    let out = migrator.drop_ocsf_legacy(true).await.unwrap();
    assert_eq!(summary(&out)[0], ("2026-10-01".into(), 3, 0, 3, LegacyDayStatus::Mismatch));
    assert_eq!(summary(&out)[1].4, LegacyDayStatus::Match);
    assert!(legacy_exists(ch, db).await);

    // Remove the duplicates (keep one copy per id): every day matches.
    exec(ch, &format!("CREATE TABLE {db}.dedup AS {db}.ocsf_logs")).await;
    exec(ch, &format!("INSERT INTO {db}.dedup SELECT DISTINCT id, timestamp, source_type FROM {db}.ocsf_logs")).await;
    exec(ch, &format!("EXCHANGE TABLES {db}.dedup AND {db}.ocsf_logs")).await;

    // Without confirm: a dry run that keeps the table.
    let out = migrator.drop_ocsf_legacy(false).await.unwrap();
    let OcsfLegacyDropOutcome::DryRun(plan) = &out else { panic!("{out:?}") };
    assert!(plan.safe_to_drop() && plan.cluster.is_none());
    assert_eq!(plan.legacy_rows(), 5);
    assert_eq!(
        plan.drop_sql,
        format!("DROP TABLE IF EXISTS {db}.ocsf_logs_legacy_v179 SYNC SETTINGS max_table_size_to_drop = 0")
    );
    assert!(legacy_exists(ch, db).await);

    // With confirm: dropped; the new store is untouched; a rerun is a no-op.
    let out = migrator.drop_ocsf_legacy(true).await.unwrap();
    assert!(matches!(out, OcsfLegacyDropOutcome::Dropped(_)), "{out:?}");
    assert!(!legacy_exists(ch, db).await);
    let kept: u64 = ch
        .query(&format!("SELECT count() FROM {db}.ocsf_logs"))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(kept, 9);
    assert!(matches!(migrator.drop_ocsf_legacy(true).await.unwrap(), OcsfLegacyDropOutcome::Absent));
}

/// Throwaway database with the two tables (same layout as the scenario).
async fn setup(ch: &clickhouse::Client) -> String {
    let db = format!("nan4918_legacy_{}", uuid::Uuid::now_v7().simple());
    exec(ch, &format!("CREATE DATABASE {db}")).await;
    for t in ["ocsf_logs_legacy_v179", "ocsf_logs"] {
        exec(
            ch,
            &format!(
                "CREATE TABLE {db}.{t} (id UUID, timestamp DateTime64(3), source_type LowCardinality(String)) \
                 ENGINE = MergeTree ORDER BY (timestamp, id)"
            ),
        )
        .await;
    }
    db
}

/// NAN-4918 codex P1: equal aggregate counts are not a proof. Legacy {A, B}
/// against target {B, B} (same hour) is refused: A missing, B duplicated.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn equal_counts_with_a_missing_and_a_duplicated_id_are_refused() {
    let ch = ch();
    let db = setup(&ch).await;
    let a = "018f0000-0000-7000-8000-00000000000a";
    let b = "018f0000-0000-7000-8000-00000000000b";
    exec(&ch, &format!("INSERT INTO {db}.ocsf_logs_legacy_v179 VALUES ('{a}', '2026-10-01 05:00:00', 'edr'), ('{b}', '2026-10-01 05:10:00', 'edr')")).await;
    exec(&ch, &format!("INSERT INTO {db}.ocsf_logs VALUES ('{b}', '2026-10-01 05:10:00', 'edr'), ('{b}', '2026-10-01 05:10:00', 'edr')")).await;
    let out = ClickHouseMigrator::new(ch.clone(), &db).with_cluster(None).drop_ocsf_legacy(true).await;
    let kept = legacy_exists(&ch, &db).await;
    exec(&ch, &format!("DROP DATABASE IF EXISTS {db}")).await;
    let out = out.unwrap();
    assert!(matches!(out, OcsfLegacyDropOutcome::Refused(_)), "{out:?}");
    assert_eq!(summary(&out), vec![("2026-10-01".into(), 2, 1, 1, LegacyDayStatus::Mismatch)]);
    assert!(kept, "nothing may be dropped");
}

/// NAN-4918 codex P1: a cluster with an unreachable shard is never verified,
/// even when the session would skip unavailable shards. Needs the server to
/// define `nan4918_one` (one shard: this server) and `nan4918_broken` (this
/// server plus an unreachable second shard), e.g. via a config.d file:
/// `NANOSIEM_TEST_CLICKHOUSE_CLUSTERS=1` opts in.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL with the nan4918_one / nan4918_broken test clusters"]
async fn a_cluster_with_an_unavailable_shard_is_refused() {
    if std::env::var("NANOSIEM_TEST_CLICKHOUSE_CLUSTERS").is_err() {
        eprintln!("Skipping: NANOSIEM_TEST_CLICKHOUSE_CLUSTERS not set");
        return;
    }
    let ch = ch();
    let db = setup(&ch).await;
    exec(&ch, &format!("INSERT INTO {db}.ocsf_logs_legacy_v179 SELECT generateUUIDv7(number), toDateTime64('2026-10-01 05:00:00', 3, 'UTC'), 'edr' FROM numbers(3)")).await;
    exec(&ch, &format!("INSERT INTO {db}.ocsf_logs SELECT * FROM {db}.ocsf_logs_legacy_v179")).await;

    // Healthy cluster: every shard answers, the per-id proof passes (dry run).
    let healthy = ClickHouseMigrator::new(ch.clone(), &db)
        .with_cluster(Some("nan4918_one".into()))
        .drop_ocsf_legacy(false)
        .await;
    // Broken cluster, with a session that would skip unavailable shards: the
    // proof pins skip_unavailable_shards = 0 and the coverage check refuses.
    let skipping = ch.clone().with_option("skip_unavailable_shards", "1");
    let broken = ClickHouseMigrator::new(skipping, &db)
        .with_cluster(Some("nan4918_broken".into()))
        .drop_ocsf_legacy(true)
        .await;
    let kept = legacy_exists(&ch, &db).await;
    exec(&ch, &format!("DROP DATABASE IF EXISTS {db}")).await;

    let healthy = healthy.unwrap();
    let OcsfLegacyDropOutcome::DryRun(plan) = &healthy else { panic!("{healthy:?}") };
    assert_eq!(plan.cluster.as_deref(), Some("nan4918_one"));
    assert_eq!(summary(&healthy), vec![("2026-10-01".into(), 3, 0, 0, LegacyDayStatus::Match)]);
    let err = broken.expect_err("a partial cluster must not be verified");
    assert!(err.to_string().contains("nan4918_broken"), "{err}");
    assert!(kept, "nothing may be dropped");
}
