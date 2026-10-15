// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3374: a fresh open-core database must accept the bronze publisher's
//! late-arrival publication record.
//!
//! The publisher binds `security_tenant_id` and names it in its conflict
//! target. Before core migration 336 that column (and the tenant-first key)
//! came only from enterprise overlay 9000084, so every bronze batch on a fresh
//! open-core lake install failed with `column "security_tenant_id" ... does
//! not exist`. The pg-integration suite never caught it because nothing ran
//! the publisher's statement against the open-only migration path; this test
//! does, with the exact SQL the publisher executes.

use chrono::{Duration, SubsecRound, Utc};
use nanosiem_core::db::repository::detection_rules::LAKE_DETECTION_EVENT_PUBLICATION_UPSERT_SQL;
use nanosiem_core::db::run_postgres_migrations;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Row};
use uuid::Uuid;

const TEST_DB_NAME: &str = "nanosiem_nan3374_open_lake_publication_test";
const SHAPED_TEST_DB_NAME: &str = "nanosiem_nan3398_shaped_lake_handoff_test";
const MIGRATION_336: &str =
    include_str!("../../migrations/postgres/336_lake_publication_security_tenant_core.sql");
const COMPAT_TENANT: Uuid = Uuid::from_u128(0x100);
const HANDOFF_TABLES: [&str; 3] = [
    "detection_finding_lake_outbox",
    "detection_late_replay_jobs",
    "lake_detection_event_publications",
];

fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/postgres".to_string())
}

fn test_db_url(db_name: &str) -> String {
    let admin = admin_url();
    let last_slash = admin.rfind('/').expect("admin url must contain '/'");
    format!("{}/{}", &admin[..last_slash], db_name)
}

async fn recreate_test_db(db_name: &str) -> Result<PgPool, sqlx::Error> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url())
        .await?;
    let _ = admin
        .execute(
            format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                 WHERE datname = '{db_name}' AND pid <> pg_backend_pid()"
            )
            .as_str(),
        )
        .await;
    admin
        .execute(format!("DROP DATABASE IF EXISTS {db_name}").as_str())
        .await?;
    admin
        .execute(format!("CREATE DATABASE {db_name}").as_str())
        .await?;
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&test_db_url(db_name))
        .await
}

async fn primary_key_columns(pool: &PgPool, table: &str) -> Vec<String> {
    sqlx::query(
        "SELECT attribute.attname::text AS column_name \
         FROM pg_constraint constraint_row \
         CROSS JOIN LATERAL unnest(constraint_row.conkey) WITH ORDINALITY key(attnum, position) \
         JOIN pg_attribute attribute \
           ON attribute.attrelid = constraint_row.conrelid AND attribute.attnum = key.attnum \
         WHERE constraint_row.conrelid = ('public.' || $1)::regclass \
           AND constraint_row.contype = 'p' \
         ORDER BY key.position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.get::<String, _>("column_name"))
    .collect()
}

#[tokio::test]
async fn fresh_open_core_schema_accepts_bronze_publication_record() {
    let pool = match recreate_test_db(TEST_DB_NAME).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("NAN-3374 integration skipped; PostgreSQL unavailable: {error}");
            return;
        }
    };
    // Open-only path: snapshot + core migrations, no enterprise overlay.
    std::env::set_var("NANOSIEM_MIGRATION_MODE", "fresh");
    run_postgres_migrations(&pool)
        .await
        .expect("apply fresh open-core migrations");
    std::env::remove_var("NANOSIEM_MIGRATION_MODE");

    for table in HANDOFF_TABLES {
        let key = primary_key_columns(&pool, table).await;
        assert_eq!(
            key.first().map(String::as_str),
            Some("security_tenant_id"),
            "{table} primary key must lead with security_tenant_id on open core: {key:?}"
        );
    }

    let batch_sha256 = "a".repeat(64);
    let min_event_time = (Utc::now() - Duration::minutes(5)).trunc_subsecs(6);
    let max_event_time = Utc::now().trunc_subsecs(6);
    let publish = |min, max| {
        sqlx::query(LAKE_DETECTION_EVENT_PUBLICATION_UPSERT_SQL)
            .bind("default")
            .bind("bronze-default")
            .bind(batch_sha256.clone())
            .bind(min)
            .bind(max)
            .bind(COMPAT_TENANT)
    };

    let first = publish(min_event_time, max_event_time)
        .fetch_optional(&pool)
        .await
        .expect("bronze publication record inserts on a fresh open-core schema");
    assert!(first.is_some(), "first publication must return its batch");

    // An exact retry is accepted; a retry with different bounds is refused.
    let retry = publish(min_event_time, max_event_time)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(retry.is_some(), "exact retry must be accepted");
    let conflicting = publish(min_event_time - Duration::minutes(1), max_event_time)
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(
        conflicting.is_none(),
        "a retry with different event bounds must not be accepted"
    );

    let stored: Uuid = sqlx::query_scalar(
        "SELECT security_tenant_id FROM lake_detection_event_publications \
         WHERE batch_sha256 = $1",
    )
    .bind(&batch_sha256)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, COMPAT_TENANT);

    // The column default covers the open writers that do not bind it.
    let defaulted: Uuid = sqlx::query_scalar(
        "INSERT INTO detection_finding_lake_outbox \
         (tenant_id, finding_id, compact_finding, ocsf_event) \
         VALUES ('default', 'nan3374-finding', '{}'::jsonb, '{}'::jsonb) \
         ON CONFLICT DO NOTHING RETURNING security_tenant_id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(defaulted, COMPAT_TENANT);

    // Re-running the migration set is a no-op (sqlx records 336 as applied),
    // and the migration body itself is idempotent over an already-reshaped
    // schema, which is the state enterprise databases are in after 9000084.
    sqlx::raw_sql(MIGRATION_336)
        .execute(&pool)
        .await
        .expect("migration 336 is idempotent");
    for table in HANDOFF_TABLES {
        let key = primary_key_columns(&pool, table).await;
        assert_eq!(
            key.iter()
                .filter(|c| c.as_str() == "security_tenant_id")
                .count(),
            1,
            "{table} key must not gain a duplicate authority column: {key:?}"
        );
    }
}

/// NAN-3398: production databases already shaped by enterprise overlay
/// 9000084 own the three handoff tables as `nano_shared_app_owner`, while
/// migrations run as `postgres`. PostgreSQL checks ownership for ALTER TABLE
/// even when `ADD COLUMN IF NOT EXISTS` would be a no-op, so 336 must issue
/// no DDL/DML at all on an in-shape schema. This runs 336 as a role that only
/// has SELECT on tables owned by another role: any ALTER fails with "must be
/// owner" and any UPDATE fails with "permission denied".
#[tokio::test]
async fn migration_336_is_a_noop_on_shaped_tables_owned_by_another_role() {
    let pool = match recreate_test_db(SHAPED_TEST_DB_NAME).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("NAN-3398 integration skipped; PostgreSQL unavailable: {error}");
            return;
        }
    };

    // Roles are cluster-wide; create them once and reuse across runs.
    sqlx::raw_sql(
        "DO $roles$ BEGIN \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nan3398_table_owner') THEN \
             CREATE ROLE nan3398_table_owner NOLOGIN NOSUPERUSER; END IF; \
           IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nan3398_migrator') THEN \
             CREATE ROLE nan3398_migrator NOLOGIN NOSUPERUSER; END IF; \
         END $roles$;",
    )
    .execute(&pool)
    .await
    .unwrap();

    // The final 9000084 shape: column present, NOT NULL, compatibility
    // default, every primary/unique key and unique index tenant-first.
    let default = "DEFAULT '00000000-0000-0000-0000-000000000100'::uuid";
    sqlx::raw_sql(&format!(
        "CREATE TABLE detection_finding_lake_outbox ( \
           security_tenant_id UUID NOT NULL {default}, \
           tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, \
           PRIMARY KEY (security_tenant_id, tenant_id, finding_id)); \
         CREATE TABLE lake_detection_event_publications ( \
           security_tenant_id UUID NOT NULL {default}, \
           tenant_id TEXT NOT NULL, bronze_store_id TEXT NOT NULL, \
           batch_sha256 TEXT NOT NULL, \
           PRIMARY KEY (security_tenant_id, tenant_id, bronze_store_id, batch_sha256)); \
         CREATE TABLE detection_late_replay_jobs ( \
           security_tenant_id UUID NOT NULL {default}, \
           id UUID NOT NULL, rule_id UUID NOT NULL, tenant_id TEXT NOT NULL, \
           bronze_store_id TEXT NOT NULL, batch_sha256 TEXT NOT NULL, \
           PRIMARY KEY (security_tenant_id, id), \
           UNIQUE (security_tenant_id, rule_id, tenant_id, bronze_store_id, batch_sha256)); \
         CREATE UNIQUE INDEX nan3398_replay_extra \
           ON detection_late_replay_jobs (security_tenant_id, tenant_id, batch_sha256); \
         INSERT INTO detection_finding_lake_outbox (tenant_id, finding_id) VALUES ('t', 'f');"
    ))
    .execute(&pool)
    .await
    .unwrap();
    for table in HANDOFF_TABLES {
        sqlx::raw_sql(&format!(
            "ALTER TABLE public.{table} OWNER TO nan3398_table_owner; \
             GRANT SELECT ON public.{table} TO nan3398_migrator;"
        ))
        .execute(&pool)
        .await
        .unwrap();
    }

    let mut conn = pool.acquire().await.unwrap();
    sqlx::raw_sql("SET ROLE nan3398_migrator")
        .execute(&mut *conn)
        .await
        .unwrap();
    for attempt in 1..=2 {
        sqlx::raw_sql(MIGRATION_336)
            .execute(&mut *conn)
            .await
            .unwrap_or_else(|error| {
                panic!("336 must issue no DDL on an in-shape schema (run {attempt}): {error}")
            });
    }
    sqlx::raw_sql("RESET ROLE")
        .execute(&mut *conn)
        .await
        .unwrap();
    drop(conn);

    for table in HANDOFF_TABLES {
        let owner: String = sqlx::query_scalar(
            "SELECT pg_get_userbyid(relowner)::text FROM pg_class \
             WHERE oid = ('public.' || $1)::regclass",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            owner, "nan3398_table_owner",
            "{table} owner must not change"
        );
        let key = primary_key_columns(&pool, table).await;
        assert_eq!(
            key.iter()
                .filter(|c| c.as_str() == "security_tenant_id")
                .count(),
            1,
            "{table} key must keep exactly one authority column: {key:?}"
        );
    }
}
