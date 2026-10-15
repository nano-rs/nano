// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-1362: a failed/malformed Replace must NOT destroy
//! the existing lookup table's data.
//!
//! The lookup upload + ingestion Replace paths used to do drop -> create ->
//! insert non-transactionally, so a failed insert (a malformed CSV / remote
//! payload) left the table dropped and recreated empty — silent data loss.
//! `LookupService::replace_table` now builds + populates a staging table and
//! atomically swaps it in, so a failure leaves the live table untouched.
//!
//! Gated like the other DB suites: compiles with every `cargo test` but is
//! `#[ignore]`d — run via the `pg-integration-tests` CI job, or locally with
//! `docker compose up -d postgres` and `cargo test -- --ignored`.

mod common;

use std::collections::HashMap;

use nanosiem_core::{ColumnType, LookupColumn, LookupRepository, LookupService, NewLookupTable};

fn col(name: &str, data_type: ColumnType, nullable: bool) -> LookupColumn {
    LookupColumn {
        name: name.to_string(),
        data_type,
        nullable,
    }
}

fn rec(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn failed_replace_preserves_existing_data() {
    let pool = common::migrated_pool().await;
    let svc = LookupService::new(LookupRepository::new(pool.clone()));

    let name = "nan1362_replace_atomic";
    let _ = svc.drop_table(name).await; // clean any leftover from a prior run

    // Seed a table with two good rows.
    svc.create_table(
        NewLookupTable {
            name: name.to_string(),
            description: None,
            columns: vec![col("id", ColumnType::Integer, true)],
            primary_key: Some("id".to_string()),
        },
        None,
    )
    .await
    .expect("create_table");

    svc.insert_records(
        name,
        vec![
            rec(&[("id", serde_json::json!(1))]),
            rec(&[("id", serde_json::json!(2))]),
        ],
    )
    .await
    .expect("seed rows");

    // Replace with a schema that adds a NOT NULL column, but supply a record
    // missing it -> NULL into NOT NULL -> the staging insert fails.
    let result = svc
        .replace_table(
            NewLookupTable {
                name: name.to_string(),
                description: None,
                columns: vec![
                    col("id", ColumnType::Integer, true),
                    col("req", ColumnType::Integer, false), // NOT NULL
                ],
                primary_key: Some("id".to_string()),
            },
            vec![rec(&[("id", serde_json::json!(9))])],
        )
        .await;
    assert!(result.is_err(), "a malformed replace must return an error");

    // The original table + data must be intact (not dropped / emptied / reschema'd).
    let table = svc.get_table(name).await.expect("table still exists");
    assert!(
        table.columns.iter().any(|c| c.name == "id"),
        "original schema preserved"
    );
    assert!(
        !table.columns.iter().any(|c| c.name == "req"),
        "the failed replacement schema must not have been applied"
    );
    assert_eq!(table.row_count, 2, "original rows must be preserved");

    let _ = svc.drop_table(name).await;
}

#[tokio::test]
#[ignore = "requires an explicitly disposable Postgres (DATABASE_URL)"]
async fn successful_replace_and_delete_with_rule_conflict() {
    let pool = common::migrated_pool().await;
    let svc = LookupService::new(LookupRepository::new(pool.clone()));
    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let name = format!("nan2875_replace_{suffix}");
    let rule_name = format!("nan2875_rule_{suffix}");
    let definition = |columns: Vec<LookupColumn>| NewLookupTable {
        name: name.clone(),
        description: None,
        columns,
        primary_key: Some("id".to_string()),
    };

    svc.create_table(definition(vec![col("id", ColumnType::Integer, false)]), None)
        .await.expect("create table");
    svc.insert_records(&name, vec![rec(&[("id", serde_json::json!(1))])])
        .await.expect("seed table");
    let replaced = svc.replace_table(
        definition(vec![col("id", ColumnType::Integer, false), col("label", ColumnType::Text, true)]),
        vec![rec(&[("id", serde_json::json!(2)), ("label", serde_json::json!("new"))])],
    ).await.expect("replace existing table");
    assert_eq!(replaced.row_count, 1);
    assert!(replaced.columns.iter().any(|column| column.name == "label"));
    let rows = svc.sample_rows(&name, 10).await.expect("sample replaced rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], serde_json::json!(2));

    let rule_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO detection_rules (name, query, severity) VALUES ($1, $2, 'low') RETURNING id",
    ).bind(&rule_name).bind(format!("search * | lookup @{name}.id")).fetch_one(&pool).await.expect("create referencing rule");
    let conflict = svc.drop_table(&name).await.expect_err("referenced table must stay");
    assert!(matches!(conflict, nanosiem_core::LookupError::TableInUse(rules) if rules.contains(&rule_name)));
    assert_eq!(svc.get_table(&name).await.expect("table survives conflict").row_count, 1);

    sqlx::query("DELETE FROM detection_rules WHERE id = $1").bind(rule_id).execute(&pool).await.expect("remove rule");
    svc.drop_table(&name).await.expect("delete unreferenced table");
    assert!(matches!(svc.get_table(&name).await, Err(nanosiem_core::LookupError::TableNotFound(_))));
    let physical_exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(&replaced.table_name).fetch_one(&pool).await.expect("check physical table");
    assert!(!physical_exists);
}
