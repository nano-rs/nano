// SPDX-License-Identifier: AGPL-3.0-or-later

//! Upgrade proof for migration 315.
//!
//! The test starts from a fully migrated disposable database, removes only
//! migration 315's schema/history to reconstruct the preceding dev schema,
//! seeds a legacy paused row, and then runs the production migrator twice.

mod common;

use nanosiem_core::db::run_postgres_migrations;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a disposable Postgres database"]
async fn migration_315_upgrades_legacy_paused_rows_and_is_rerunnable() {
    let pool = common::migrated_pool().await;

    sqlx::query(
        "ALTER TABLE detection_rules \
         DROP CONSTRAINT IF EXISTS detection_rules_paused_from_mode_check",
    )
    .execute(&pool)
    .await
    .expect("drop migration 315 constraint");
    sqlx::query("DROP TRIGGER IF EXISTS trg_detection_rules_pause_origin ON detection_rules")
        .execute(&pool)
        .await
        .expect("drop migration 315 trigger");
    sqlx::query("DROP FUNCTION IF EXISTS public.sync_detection_rule_paused_from_mode()")
        .execute(&pool)
        .await
        .expect("drop migration 315 trigger function");
    sqlx::query(
        "ALTER TABLE detection_rules \
         DROP COLUMN IF EXISTS paused_from_mode, \
         DROP COLUMN IF EXISTS legacy_lifecycle_transition_at",
    )
    .execute(&pool)
    .await
    .expect("drop migration 315 columns");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 315")
        .execute(&pool)
        .await
        .expect("remove migration 315 history");

    let id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules
            (id, name, description, query, severity, mode, detection_mode)
        VALUES ($1, $2, 'NAN-4995B migration upgrade probe',
                'source_type=apache', 'medium', 'paused', 'scheduled')
        "#,
    )
    .bind(id)
    .bind(format!("NAN-4995B-upgrade-{id}"))
    .execute(&pool)
    .await
    .expect("seed legacy paused row");

    run_postgres_migrations(&pool)
        .await
        .expect("apply migration 315 as an upgrade");
    let state: (String, Option<String>) = sqlx::query_as(
        "SELECT mode::text, paused_from_mode FROM detection_rules WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("read upgraded paused row");
    assert_eq!(state, ("paused".into(), Some("alerting".into())));

    // Exercise the SQL shape used by a pre-315 process during a rolling
    // deployment. It does not know about paused_from_mode, so the migration's
    // trigger must maintain the invariant until the old process drains.
    sqlx::query("UPDATE detection_rules SET mode = 'alerting' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("old process resumes without clearing the pause marker");
    sqlx::query("UPDATE detection_rules SET mode = 'live' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("put upgraded rule in live mode");
    sqlx::query("UPDATE detection_rules SET mode = 'paused' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("old process pauses without recording the source mode");

    let rolling_pause_state: (String, Option<String>) = sqlx::query_as(
        "SELECT mode::text, paused_from_mode FROM detection_rules WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("read rolling-upgrade pause state");
    assert_eq!(rolling_pause_state, ("paused".into(), Some("live".into())));

    sqlx::query("UPDATE detection_rules SET mode = 'alerting' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("old process resumes after rolling-upgrade pause");
    let rolling_resume_state: (String, Option<String>) = sqlx::query_as(
        "SELECT mode::text, paused_from_mode FROM detection_rules WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&pool)
    .await
    .expect("read rolling-upgrade resume state");
    assert_eq!(rolling_resume_state, ("live".into(), None));

    run_postgres_migrations(&pool)
        .await
        .expect("second production migrator pass");
    let marker_column_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'detection_rules'
              AND column_name = 'legacy_lifecycle_transition_at'
        )
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("check legacy transition marker column");
    assert!(marker_column_exists);
}
