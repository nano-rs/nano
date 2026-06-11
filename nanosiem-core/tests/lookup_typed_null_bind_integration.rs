// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-1361 (real fix): a ragged CSV whose extra column is
//! numeric-inferred but absent from some rows must insert cleanly, not 500.
//!
//! The F-4 payload (a CSV-injection `=HYPERLINK("…","…")` formula with an
//! unquoted comma) parses into 4 fields on one row, so the parser synthesizes a
//! numeric `col_3` that's missing on the other row. `detect_column_types` infers
//! it `Integer` (bigint). `bind_value` used to bind `None::<String>` (a *text*
//! NULL) for the missing value → SQLSTATE 42804 (text into bigint) → 500. It now
//! binds a type-correct NULL.
//!
//! `#[ignore]`d DB suite — run via `pg-integration-tests` CI or
//! `docker compose up -d postgres` + `cargo test -- --ignored`.

mod common;

use std::collections::HashMap;

use nanosiem_core::{LookupRepository, LookupService};

fn rec(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn ragged_numeric_column_inserts_typed_null_not_500() {
    let pool = common::migrated_pool().await;
    let repo = LookupRepository::new(pool.clone());

    // Mirrors the real parser output for the ragged F-4 row: a numeric `col_3`
    // present in one record, absent in the next.
    let records = vec![
        rec(&[("id", serde_json::json!(1)), ("col_3", serde_json::json!(10))]),
        rec(&[("id", serde_json::json!(2))]), // col_3 missing -> typed NULL
    ];

    let columns = LookupService::detect_column_types(&records, None);
    assert!(
        columns
            .iter()
            .any(|c| c.name == "col_3" && matches!(c.data_type, nanosiem_core::ColumnType::Integer)),
        "col_3 should infer as Integer (the condition that triggered 42804)"
    );

    let t = "nan1361_typed_null_bind";
    let _ = repo.drop_dynamic_table(t).await;
    repo.create_dynamic_table(t, &columns, None)
        .await
        .expect("create_dynamic_table");

    // Pre-fix this failed with 42804 (None::<String> into bigint col_3).
    let inserted = repo
        .insert_records(t, &columns, &records)
        .await
        .expect("insert must not 42804 — missing numeric value binds a typed NULL");
    assert_eq!(inserted, 2, "both rows inserted (col_3 NULL on the second)");

    let _ = repo.drop_dynamic_table(t).await;
}
