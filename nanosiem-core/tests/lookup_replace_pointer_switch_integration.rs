// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-2875 review fix: a ClickHouse-backed lookup replace is a registry
//! pointer switch, so a PostgreSQL failure after staging leaves the old data
//! and schema fully intact, and readers never see old and new rows together.
//!
//! The old flow re-keyed staged rows onto the live name, synchronously deleted
//! the previous generation, and only then updated the PostgreSQL schema. A
//! PostgreSQL failure at that last step left the new rows live under the old
//! schema, with the old data already gone.
//!
//! The failure is forced with a real PostgreSQL trigger that rejects the
//! registry UPDATE for this one table, so the publish transaction fails after
//! every new row is already staged in ClickHouse.
//!
//! `#[ignore]`d like the other DB suites: needs Postgres (`DATABASE_URL`) and
//! ClickHouse (`CLICKHOUSE_TEST_URL` / `_USER` / `_PASSWORD`).

mod common;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use nanosiem_core::{
    lookup::{
        BatchLookupQuery, ClickHouseLookupRepository, LookupGenerationReconciler, LookupQuery,
        LookupStore,
    },
    ColumnType, LookupColumn, LookupService, NewLookupTable,
};

fn col(name: &str, data_type: ColumnType) -> LookupColumn {
    LookupColumn {
        name: name.to_string(),
        data_type,
        nullable: true,
    }
}

fn rec(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn ch_client() -> clickhouse::Client {
    let url =
        std::env::var("CLICKHOUSE_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".into());
    let mut client = clickhouse::Client::default()
        .with_url(url)
        .with_database("nanosiem")
        .with_compression(clickhouse::Compression::None);
    if let Ok(user) = std::env::var("CLICKHOUSE_TEST_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("CLICKHOUSE_TEST_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

async fn ch_row_names(ch: &clickhouse::Client, like: &str) -> Vec<String> {
    ch.query("SELECT DISTINCT lookup_table_name FROM lookup_rows WHERE lookup_table_name LIKE ? ORDER BY 1")
        .bind(like)
        .fetch_all::<String>()
        .await
        .expect("read lookup_rows names")
}

#[tokio::test]
#[ignore = "requires Postgres (DATABASE_URL) and ClickHouse (CLICKHOUSE_TEST_URL)"]
async fn pg_failure_after_staging_keeps_old_generation_and_schema() {
    let pool = common::migrated_pool().await;
    let ch = ch_client();
    let svc = LookupService::new(ClickHouseLookupRepository::new(pool.clone(), ch.clone()));
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let name = format!("nan2875_ptr_{suffix}");
    let definition = |columns: Vec<LookupColumn>| NewLookupTable {
        name: name.clone(),
        description: None,
        columns,
        primary_key: Some("ip".to_string()),
    };

    svc.create_table(
        definition(vec![
            col("ip", ColumnType::Text),
            col("label", ColumnType::Text),
        ]),
        None,
    )
    .await
    .expect("create");
    svc.insert_records(
        &name,
        vec![
            rec(&[("ip", "10.0.0.1".into()), ("label", "old-a".into())]),
            rec(&[("ip", "10.0.0.2".into()), ("label", "old-b".into())]),
        ],
    )
    .await
    .expect("seed");
    let before = svc.get_table(&name).await.expect("table");

    // Reject any registry UPDATE for this table: the publish step fails AFTER
    // the replacement rows are staged in ClickHouse.
    let trigger_fn = format!("nan2875_fail_{suffix}");
    sqlx::query(&format!(
        "CREATE FUNCTION {trigger_fn}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.name = '{name}' THEN RAISE EXCEPTION 'forced registry failure'; END IF; \
         RETURN NEW; END $$"
    ))
    .execute(&pool)
    .await
    .expect("create trigger fn");
    sqlx::query(&format!(
        "CREATE TRIGGER {trigger_fn} BEFORE UPDATE ON lookup_tables_registry \
         FOR EACH ROW EXECUTE FUNCTION {trigger_fn}()"
    ))
    .execute(&pool)
    .await
    .expect("create trigger");

    let failed = svc
        .replace_table(
            definition(vec![
                col("ip", ColumnType::Text),
                col("owner", ColumnType::Text),
            ]),
            vec![rec(&[("ip", "10.9.9.9".into()), ("owner", "new".into())])],
        )
        .await;

    sqlx::query(&format!(
        "DROP TRIGGER {trigger_fn} ON lookup_tables_registry"
    ))
    .execute(&pool)
    .await
    .expect("drop trigger");
    sqlx::query(&format!("DROP FUNCTION {trigger_fn}()"))
        .execute(&pool)
        .await
        .expect("drop trigger fn");

    assert!(failed.is_err(), "a failed publish must surface as an error");

    // Registry: same physical pointer and schema as before.
    let after = svc.get_table(&name).await.expect("table survives");
    assert_eq!(after.table_name, before.table_name, "pointer must not move");
    assert!(after.columns.iter().any(|c| c.name == "label"));
    assert!(
        !after.columns.iter().any(|c| c.name == "owner"),
        "new schema must not apply"
    );

    // Data: exactly the old rows, none of the new.
    let rows = svc.sample_rows(&name, 10).await.expect("rows");
    let mut ips: Vec<String> = rows
        .iter()
        .map(|r| r["ip"].as_str().unwrap_or("").to_string())
        .collect();
    ips.sort();
    assert_eq!(
        ips,
        vec!["10.0.0.1", "10.0.0.2"],
        "old generation intact, no union"
    );

    // The staged generation was cleaned up; only the live physical name holds rows.
    let names = ch_row_names(&ch, &format!("lookup_{name}%")).await;
    assert_eq!(
        names,
        vec![before.table_name.clone()],
        "staging rows purged: {names:?}"
    );

    // A clean replace then switches the pointer and purges the old name.
    let replaced = svc
        .replace_table(
            definition(vec![
                col("ip", ColumnType::Text),
                col("owner", ColumnType::Text),
            ]),
            vec![rec(&[("ip", "10.9.9.9".into()), ("owner", "new".into())])],
        )
        .await
        .expect("replace");
    assert_ne!(
        replaced.table_name, before.table_name,
        "pointer moved to the staged name"
    );
    assert!(replaced.columns.iter().any(|c| c.name == "owner"));
    let rows = svc.sample_rows(&name, 10).await.expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["ip"], serde_json::json!("10.9.9.9"));
    let names = ch_row_names(&ch, &format!("lookup_{name}%")).await;
    assert_eq!(
        names,
        vec![replaced.table_name.clone()],
        "old generation purged: {names:?}"
    );

    // A second replace stages from the logical name, not the staged one.
    let again = svc
        .replace_table(
            definition(vec![
                col("ip", ColumnType::Text),
                col("owner", ColumnType::Text),
            ]),
            vec![rec(&[("ip", "10.9.9.8".into()), ("owner", "newer".into())])],
        )
        .await
        .expect("second replace");
    assert_eq!(
        again.table_name.matches("_stg_").count(),
        1,
        "{}",
        again.table_name
    );

    svc.drop_table(&name).await.expect("cleanup");
    assert!(ch_row_names(&ch, &format!("lookup_{name}%"))
        .await
        .is_empty());
}

#[tokio::test]
#[ignore = "requires Postgres (DATABASE_URL) and ClickHouse (CLICKHOUSE_TEST_URL)"]
async fn concurrent_readers_see_one_complete_generation_during_replace() {
    let pool = common::migrated_pool().await;
    let svc = LookupService::new(ClickHouseLookupRepository::new(pool, ch_client()));
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let name = format!("nan4958_read_{suffix}");
    let definition = |table_name: &str| NewLookupTable {
        name: table_name.to_string(),
        description: None,
        columns: vec![
            col("key", ColumnType::Text),
            col("generation", ColumnType::Text),
        ],
        primary_key: Some("key".to_string()),
    };
    let records = |generation: &str| {
        (0..64)
            .map(|n| {
                rec(&[
                    ("key", format!("key-{n:02}").into()),
                    ("generation", generation.into()),
                ])
            })
            .collect::<Vec<_>>()
    };

    svc.create_table(definition(&name), None)
        .await
        .expect("create");
    svc.insert_records(&name, records("old"))
        .await
        .expect("seed");

    let stop = Arc::new(AtomicBool::new(false));
    let replacing = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let overlap_reads = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let svc = svc.clone();
        let name = name.clone();
        let stop = stop.clone();
        let replacing = replacing.clone();
        let reads = reads.clone();
        let overlap_reads = overlap_reads.clone();
        readers.push(tokio::spawn(async move {
            let keys = (0..64)
                .map(|n| serde_json::json!(format!("key-{n:02}")))
                .collect::<Vec<_>>();
            while !stop.load(Ordering::Acquire) {
                let page = svc
                    .list_rows(&name, 1, 100)
                    .await
                    .expect("reader never sees a gap");
                assert_eq!(page.total, 64, "reader saw a partial generation");
                assert_eq!(page.rows.len(), 64, "reader saw a partial generation");
                let generation = page.rows[0]["generation"].clone();
                assert!(
                    page.rows.iter().all(|row| row["generation"] == generation),
                    "reader mixed lookup generations"
                );

                // Search `| lookup` enrichment and detection execution both use
                // this batch path. It must retry a pointer switch instead of
                // accepting an empty result from a just-retired generation.
                let batch = svc
                    .lookup_batch(BatchLookupQuery {
                        table_name: name.clone(),
                        key_field: "key".into(),
                        key_values: keys.clone(),
                        output_fields: None,
                        case_insensitive: false,
                    })
                    .await
                    .expect("batch reader never sees a gap");
                assert_eq!(
                    batch.matched_count, 64,
                    "batch lookup returned empty/partial success"
                );
                let batch_generation = batch.results.values().next().unwrap()["generation"].clone();
                assert!(
                    batch
                        .results
                        .values()
                        .all(|row| row["generation"] == batch_generation),
                    "batch lookup mixed generations"
                );

                let point = svc
                    .lookup(LookupQuery {
                        table_name: name.clone(),
                        key_field: "key".into(),
                        key_value: serde_json::json!("key-00"),
                        output_fields: None,
                        case_insensitive: false,
                    })
                    .await
                    .expect("point reader never sees a gap");
                assert!(point.found, "point lookup returned empty success");
                reads.fetch_add(1, Ordering::Relaxed);
                if replacing.load(Ordering::Acquire) {
                    overlap_reads.fetch_add(1, Ordering::Relaxed);
                }
                tokio::task::yield_now().await;
            }
        }));
    }

    tokio::task::yield_now().await;
    replacing.store(true, Ordering::Release);
    for generation in 0..12 {
        svc.replace_table(definition(&name), records(&format!("new-{generation}")))
            .await
            .expect("replace");
    }
    replacing.store(false, Ordering::Release);
    stop.store(true, Ordering::Release);
    for reader in readers {
        reader.await.expect("reader task");
    }
    assert!(
        reads.load(Ordering::Relaxed) > 0,
        "reader tasks did not run"
    );
    assert!(
        overlap_reads.load(Ordering::Relaxed) > 0,
        "no reader overlapped the replacement window"
    );

    svc.drop_table(&name).await.expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres (DATABASE_URL) and ClickHouse (CLICKHOUSE_TEST_URL)"]
async fn append_queued_behind_replace_writes_the_new_generation() {
    let pool = common::migrated_pool().await;
    let svc = LookupService::new(ClickHouseLookupRepository::new(pool.clone(), ch_client()));
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let name = format!("nan4958_write_{suffix}");
    let definition = || NewLookupTable {
        name: name.clone(),
        description: None,
        columns: vec![
            col("key", ColumnType::Text),
            col("generation", ColumnType::Text),
        ],
        primary_key: Some("key".to_string()),
    };

    svc.create_table(definition(), None).await.expect("create");
    svc.insert_records(
        &name,
        vec![rec(&[("key", "seed".into()), ("generation", "old".into())])],
    )
    .await
    .expect("seed");

    // Hold the same transaction advisory lock, queue Replace first, then append.
    // PostgreSQL grants queued advisory locks in arrival order, so append can
    // only resolve its physical pointer after Replace publishes the new one.
    let mut blocker = pool.begin().await.expect("blocker transaction");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('nanosiem.lookup:' || $1, 0))")
        .bind(&name)
        .execute(&mut *blocker)
        .await
        .expect("hold lookup lock");

    let replace_service = svc.clone();
    let replace_name = name.clone();
    let replace = tokio::spawn(async move {
        replace_service
            .replace_table(
                NewLookupTable {
                    name: replace_name,
                    description: None,
                    columns: vec![
                        col("key", ColumnType::Text),
                        col("generation", ColumnType::Text),
                    ],
                    primary_key: Some("key".to_string()),
                },
                vec![rec(&[
                    ("key", "replacement".into()),
                    ("generation", "new".into()),
                ])],
            )
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let append_service = svc.clone();
    let append_name = name.clone();
    let append = tokio::spawn(async move {
        append_service
            .insert_records(
                &append_name,
                vec![rec(&[
                    ("key", "appended".into()),
                    ("generation", "new".into()),
                ])],
            )
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    assert!(
        !replace.is_finished(),
        "Replace escaped the held advisory lock"
    );
    assert!(
        !append.is_finished(),
        "append escaped the held advisory lock"
    );
    blocker.commit().await.expect("release blocker");

    replace.await.expect("replace task").expect("replace");
    append.await.expect("append task").expect("append");
    let page = svc.list_rows(&name, 1, 100).await.expect("final rows");
    assert_eq!(page.total, 2);
    assert!(page.rows.iter().any(|row| row["key"] == "replacement"));
    assert!(page.rows.iter().any(|row| row["key"] == "appended"));

    svc.drop_table(&name).await.expect("cleanup");
}

#[tokio::test]
#[ignore = "requires Postgres (DATABASE_URL) and ClickHouse (CLICKHOUSE_TEST_URL)"]
async fn failed_cleanup_is_reclaimed_by_a_later_reconciler_pass() {
    let pool = common::migrated_pool().await;
    let ch = ch_client();
    let repo = ClickHouseLookupRepository::new(pool.clone(), ch.clone());
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let logical = format!("nan4958_cleanup_{suffix}");
    let physical = format!("lookup_{logical}_stg_orphan");
    let columns = vec![col("key", ColumnType::Text), col("value", ColumnType::Text)];

    repo.record_staged_generation(&logical, &physical)
        .await
        .expect("journal staging");
    repo.create_dynamic_table(&physical, &columns, Some("key"))
        .await
        .expect("validate staging");
    repo.insert_records(
        &physical,
        &columns,
        &[rec(&[
            ("key", "orphan".into()),
            ("value", "cleanup".into()),
        ])],
    )
    .await
    .expect("stage orphan row");

    let unavailable = clickhouse::Client::default()
        .with_url("http://127.0.0.1:1")
        .with_database("nanosiem")
        .with_compression(clickhouse::Compression::None);
    let failed = LookupGenerationReconciler::new(pool.clone(), unavailable)
        .run_once(100)
        .await
        .expect("failed pass is durable");
    assert!(failed.failed >= 1, "cleanup failure was not recorded");
    let (attempt_count, last_error): (i32, Option<String>) = sqlx::query_as(
        "SELECT attempt_count, last_error FROM lookup_generation_cleanup WHERE physical_name = $1",
    )
    .bind(&physical)
    .fetch_one(&pool)
    .await
    .expect("journal survives failed cleanup");
    assert_eq!(attempt_count, 1);
    assert!(last_error.is_some());
    let active_health: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_health_events \
         WHERE dedup_key = 'lookup:generation_cleanup_failed' AND status = 'active'",
    )
    .fetch_one(&pool)
    .await
    .expect("cleanup failure health event");
    assert_eq!(
        active_health, 1,
        "cleanup failure must surface in SIEM Health"
    );

    sqlx::query(
        "UPDATE lookup_generation_cleanup SET next_attempt_at = NOW() WHERE physical_name = $1",
    )
    .bind(&physical)
    .execute(&pool)
    .await
    .expect("make retry due");
    let recovered = LookupGenerationReconciler::new(pool.clone(), ch.clone())
        .run_once(100)
        .await
        .expect("recovery pass");
    assert!(recovered.purged >= 1);
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM lookup_generation_cleanup WHERE physical_name = $1",
    )
    .bind(&physical)
    .fetch_one(&pool)
    .await
    .expect("journal count");
    assert_eq!(
        remaining, 0,
        "reconciler must clear the durable journal row"
    );
    let active_health: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_health_events \
         WHERE dedup_key = 'lookup:generation_cleanup_failed' AND status = 'active'",
    )
    .fetch_one(&pool)
    .await
    .expect("resolved cleanup health event");
    assert_eq!(
        active_health, 0,
        "recovery must resolve the SIEM Health event"
    );
    assert!(
        !ch_row_names(&ch, &physical).await.contains(&physical),
        "reconciler must purge the ClickHouse generation"
    );
}
