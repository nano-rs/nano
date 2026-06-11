// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression test for NAN-1389 (G15a): `| lookup <missing-table>` must be
//! rejected up front with an actionable error naming the missing lookup (and
//! the available tables), instead of proceeding to a masked failure / silently
//! un-enriched results.
//!
//! `#[ignore]`d DB suite — run via `pg-integration-tests` CI or
//! `docker compose up -d postgres` + `cargo test -- --ignored`.

mod common;

use nanosiem_core::search::query_processing::LookupCommandInfo;
use nanosiem_core::search::validate_lookup_tables;
use nanosiem_core::{ColumnType, LookupColumn, LookupRepository, LookupService, NewLookupTable};

fn lookup_cmd(table: &str) -> LookupCommandInfo {
    LookupCommandInfo {
        table_name: table.to_string(),
        key_field: "src_ip".to_string(),
        output_fields: None,
        case_insensitive: false,
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn missing_lookup_table_is_rejected_with_actionable_message() {
    let pool = common::migrated_pool().await;
    let service = LookupService::new(LookupRepository::new(pool.clone()));

    // A table that definitely does not exist → actionable rejection naming it.
    let err = validate_lookup_tables(
        &[lookup_cmd("nan1389_definitely_missing")],
        Some(&service),
    )
    .await
    .expect_err("missing lookup table must be rejected up front");
    let msg = err.to_string();
    assert!(
        msg.contains("'nan1389_definitely_missing'"),
        "error must name the missing lookup: {msg}"
    );
    assert!(
        matches!(err, nanosiem_core::SearchError::SqlValidationError(_)),
        "must map to the 400 QUERY_ERROR path, got: {err:?}"
    );

    // Create a real lookup table → the same pre-check passes.
    let name = "nan1389_precheck_exists";
    let _ = service.drop_table(name).await;
    service
        .create_table(
            NewLookupTable {
                name: name.to_string(),
                description: None,
                columns: vec![LookupColumn {
                    name: "src_ip".to_string(),
                    data_type: ColumnType::Text,
                    nullable: true,
                }],
                primary_key: Some("src_ip".to_string()),
            },
            None,
        )
        .await
        .expect("create lookup table");

    validate_lookup_tables(&[lookup_cmd(name)], Some(&service))
        .await
        .expect("existing lookup table must pass the pre-check");

    // And the missing-table error now lists the available table as guidance.
    let err = validate_lookup_tables(&[lookup_cmd("still_missing")], Some(&service))
        .await
        .expect_err("missing lookup table must be rejected");
    assert!(
        err.to_string().contains(name),
        "error should list available lookup tables: {err}"
    );

    // Cleanup
    let _ = service.drop_table(name).await;
}
