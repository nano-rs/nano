// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5839: migration 400 puts a shape CHECK on `log_sources.timezone` (the
//! per-source timezone the Vector config injects as `.nano.source_timezone`),
//! and the publication trigger republishes when it changes.
//!
//! The text tests are DB-free. The DB-backed test runs against migrated
//! PostgreSQL (ignored in ordinary unit runs; executed by the pg-integration
//! lane).

mod common;

use sqlx::PgPool;
use uuid::Uuid;

const MIGRATION: &str = include_str!("../../migrations/postgres/400_log_source_timezone_check.sql");
const PUBLICATION_TRIGGER: &str =
    include_str!("../../migrations/postgres/271_remove_legacy_log_source_transports.sql");

/// The SQL with `--` comments stripped.
fn code(sql: &str) -> String {
    sql.lines()
        .map(|l| l.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn migration_adds_an_idempotent_shape_check_and_no_column() {
    let sql = code(MIGRATION);
    assert!(sql.contains("ADD CONSTRAINT log_sources_timezone_shape CHECK"), "{sql}");
    assert!(sql.contains("length(timezone) <= 64"));
    assert!(sql.contains("'^[+-][0-9]{2}:[0-9]{2}$'"));
    assert!(sql.contains("EXCEPTION WHEN duplicate_object"));
    assert!(sql.contains("invalid_table_definition"));
    // Forward-only: no column add/drop, no NOT NULL / default change.
    for forbidden in ["ADD COLUMN", "DROP COLUMN", "DROP NOT NULL", "DROP DEFAULT", "ALTER COLUMN"] {
        assert!(!sql.contains(forbidden), "400 must not {forbidden}");
    }
    // The reset runs only when a row needs it (no republish of every source).
    assert!(sql.contains("IF EXISTS"), "{sql}");
}

#[test]
fn the_publication_trigger_already_lists_timezone() {
    // A change to the column must bump the Vector config revision; 271 is the
    // latest definition of the trigger.
    let sql = code(PUBLICATION_TRIGGER);
    let start = sql
        .find("CREATE TRIGGER vector_config_log_sources_update")
        .expect("271 defines the log_sources update trigger");
    let body = &sql[start..sql[start..].find("EXECUTE FUNCTION").map(|i| start + i).unwrap()];
    assert!(body.contains("timezone"), "{body}");
}

/// The picker offers exactly the fractional offsets the server accepts.
#[test]
fn web_picker_offsets_match_the_server() {
    let web = include_str!("../../nanosiem-web/src/lib/source-timezones.ts");
    let start = web.find("FRACTIONAL_SOURCE_OFFSETS = [").expect("web list");
    let end = start + web[start..].find("]").unwrap();
    let listed: Vec<&str> = web[start..end]
        .split('\'')
        .filter(|s| s.starts_with('+') || s.starts_with('-'))
        .collect();
    assert_eq!(listed, nanosiem_core::timezone::FRACTIONAL_SOURCE_OFFSETS);
}

async fn insert(pool: &PgPool, tz: &str) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO log_sources (id, name, source_type, parser_vrl, timezone)
         VALUES ($1, $2, 'routed', '.', $3)",
    )
    .bind(id)
    .bind(format!("nan5839_{}", id.simple()))
    .bind(tz)
    .execute(pool)
    .await
    .map(|_| id)
}

async fn revision(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT source_revision FROM vector_config_publication_state WHERE singleton = TRUE")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(-1)
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn timezone_shape_is_enforced_and_a_change_republishes() {
    let pool = common::migrated_pool().await;

    let mut ids = Vec::new();
    for ok in ["UTC", "America/New_York", "America/Argentina/Buenos_Aires", "Etc/GMT+5", "-05:00", "+05:30"] {
        ids.push(insert(&pool, ok).await.unwrap_or_else(|e| panic!("{ok} must be accepted: {e}")));
    }
    for bad in ["", "America/New York", "-0500", "UTC\n[sinks.x]", "${CLICKHOUSE_PASSWORD}", "a/b/c/d"] {
        assert!(insert(&pool, bad).await.is_err(), "{bad:?} must be refused by the CHECK");
    }
    let too_long = "A".repeat(65);
    assert!(insert(&pool, &too_long).await.is_err());

    // Default stays 'UTC' (migration 087), NOT NULL.
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO log_sources (id, name, source_type, parser_vrl) VALUES ($1, $2, 'routed', '.')")
        .bind(id)
        .bind(format!("nan5839_default_{}", id.simple()))
        .execute(&pool)
        .await
        .expect("insert without timezone");
    let tz: String = sqlx::query_scalar("SELECT timezone FROM log_sources WHERE id = $1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(tz, "UTC");
    ids.push(id);

    // A timezone change bumps the Vector config publication revision, when
    // the publication state exists on this database.
    let before = revision(&pool).await;
    sqlx::query("UPDATE log_sources SET timezone = 'Asia/Tokyo' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let after = revision(&pool).await;
    if before >= 0 {
        assert!(after > before, "timezone change must republish ({before} -> {after})");
    }

    // A deployed source whose timezone CHANGES needs a deploy (it renders the
    // `_source_tz` step); re-sending the stored value does not undeploy it.
    let repo = nanosiem_core::log_sources::LogSourceRepository::new(pool.clone());
    sqlx::query("UPDATE log_sources SET deployed = true WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let same = nanosiem_core::log_sources::UpdateLogSource {
        timezone: Some("Asia/Tokyo".into()),
        ..Default::default()
    };
    assert!(repo.update(id, &same).await.expect("same timezone").deployed, "unchanged value keeps deployed");
    let changed = nanosiem_core::log_sources::UpdateLogSource {
        timezone: Some("America/Chicago".into()),
        ..Default::default()
    };
    let after = repo.update(id, &changed).await.expect("changed timezone");
    assert_eq!(after.timezone, "America/Chicago");
    assert!(!after.deployed, "a changed timezone needs a deploy");

    sqlx::query("DELETE FROM log_sources WHERE id = ANY($1)")
        .bind(&ids)
        .execute(&pool)
        .await
        .unwrap();
}
