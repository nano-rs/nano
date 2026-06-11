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
