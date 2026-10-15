// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3492 — a rule with no metrics history must yield `InsufficientData`,
//! not a decode error.
//!
//! `establish_baseline` read `SELECT MIN(timestamp) ...` with
//! `fetch_optional`, which decodes the scalar as a non-null `DateTime`. MIN()
//! over zero rows returns one row holding NULL, so every new rule failed with
//! "unexpected null; try decoding as an Option" and nano-jobs logged a WARN
//! per rule per cycle. `#[ignore]`d like the sibling DB suites; the
//! `pg-integration-tests` lane runs them with `-- --ignored`.

mod common;

use nanosiem_core::tuning::{BaselineMonitor, BaselineMonitorError};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires Postgres"]
async fn rule_without_metrics_is_insufficient_data_not_decode_error() {
    let pool = common::migrated_pool().await;
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (id, name, description, query, severity, mode)
        VALUES ($1, $2, 'NAN-3492 integration test', 'error', 'medium', 'alerting')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-3492-{rule_id}"))
    .execute(&pool)
    .await
    .expect("insert test rule");

    let result = BaselineMonitor::new(pool.clone())
        .establish_baseline(rule_id)
        .await;

    sqlx::query("DELETE FROM detection_rules WHERE id = $1")
        .bind(rule_id)
        .execute(&pool)
        .await
        .expect("delete test rule");

    assert!(
        matches!(result, Err(BaselineMonitorError::InsufficientData(_))),
        "expected InsufficientData for a rule with no metrics, got {:?}",
        result.as_ref().map(|_| "Ok(baseline)")
    );
}
