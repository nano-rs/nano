// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-5230: creating a lookup must own a freshly created
//! physical table.
//!
//! Physical names were derived by sanitizing the logical name, so `Foo-Bar`
//! and `foo_bar` both mapped to `lookup_foo_bar`, and `CREATE TABLE IF NOT
//! EXISTS` silently handed the second create the first lookup's table. Writes
//! to either lookup then landed in one table, and dropping (or failing to
//! finish creating) one of them dropped the other's data.
//!
//! Gated like the other DB suites: `#[ignore]`d — run via the
//! `pg-integration-tests` CI job, or locally against a disposable database
//! with `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 cargo test -p nanosiem-core \
//!   --test lookup_create_owns_physical_table_integration -- --ignored`.

mod common;

use std::collections::HashMap;

use nanosiem_core::{ColumnType, LookupColumn, LookupRepository, LookupService, NewLookupTable};
use sqlx::PgPool;
use uuid::Uuid;

fn table(name: &str) -> NewLookupTable {
    NewLookupTable {
        name: name.to_string(),
        description: None,
        columns: vec![LookupColumn {
            name: "id".to_string(),
            data_type: ColumnType::Integer,
            nullable: true,
        }],
        primary_key: Some("id".to_string()),
    }
}

fn rows(ids: &[i64]) -> Vec<HashMap<String, serde_json::Value>> {
    ids.iter()
        .map(|id| HashMap::from([("id".to_string(), serde_json::json!(id))]))
        .collect()
}

async fn physical_rows(pool: &PgPool, physical: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM \"{physical}\""))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("count rows in {physical}: {e}"))
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn colliding_sanitized_names_get_separate_tables() {
    let pool = common::migrated_pool().await;
    let svc = LookupService::new(LookupRepository::new(pool.clone()));

    // Two logical names that sanitize identically.
    let tag = &Uuid::now_v7().simple().to_string()[..10];
    let first_name = format!("Nan5230-{tag}");
    let second_name = format!("nan5230_{tag}");
    assert_eq!(
        table(&first_name).generate_table_name(),
        table(&second_name).generate_table_name(),
        "fixture: the two names must collide after sanitization"
    );

    let first = svc.create_table(table(&first_name), None).await.expect("create first");
    svc.insert_records(&first_name, rows(&[1, 2, 3]))
        .await
        .expect("seed first");

    let second = svc
        .create_table(table(&second_name), None)
        .await
        .expect("create second");
    assert_ne!(
        first.table_name, second.table_name,
        "a new lookup must never adopt another lookup's physical table"
    );
    assert!(second.table_name.len() <= 63, "PostgreSQL identifier limit");

    // Writes to the second lookup do not land in the first.
    svc.insert_records(&second_name, rows(&[10]))
        .await
        .expect("seed second");
    assert_eq!(physical_rows(&pool, &first.table_name).await, 3);
    assert_eq!(physical_rows(&pool, &second.table_name).await, 1);

    // Dropping the second lookup leaves the first lookup's data intact.
    svc.drop_table(&second_name).await.expect("drop second");
    assert_eq!(physical_rows(&pool, &first.table_name).await, 3);

    svc.drop_table(&first_name).await.expect("drop first");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn create_dynamic_table_refuses_an_existing_table() {
    let pool = common::migrated_pool().await;
    let repo = LookupRepository::new(pool.clone());
    let physical = format!("lookup_nan5230_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let columns = table("x").columns;

    repo.create_dynamic_table(&physical, &columns, None)
        .await
        .expect("first create");
    let again = repo.create_dynamic_table(&physical, &columns, None).await;
    assert!(
        matches!(again, Err(nanosiem_core::LookupRepositoryError::TableAlreadyExists(ref n)) if *n == physical),
        "a second create of the same physical name must be refused, got {again:?}"
    );

    repo.drop_dynamic_table(&physical).await.expect("cleanup");
}

#[test]
fn unique_physical_names_are_bounded_and_distinct() {
    let long = table(&"x".repeat(200));
    let a = long.generate_unique_table_name();
    let b = long.generate_unique_table_name();
    assert_ne!(a, b);
    assert!(a.len() <= 63, "{a} exceeds the PostgreSQL identifier limit");
    assert!(a.starts_with("lookup_x"));
    assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
}
