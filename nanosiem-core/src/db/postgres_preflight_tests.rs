// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for the PostgreSQL compatibility preflight (NAN-5260). The DB-backed
//! test needs a disposable PostgreSQL at `NANOSIEM_TEST_DATABASE_URL` and is a
//! no-op without one.

use std::collections::BTreeSet;
use std::path::Path;

use super::*;

/// Extensions named by `CREATE EXTENSION` in every `.sql` file of `dir`.
/// A directory stripped from the open-core mirror (enterprise) is skipped.
fn extensions_created_in(dir: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let sql = std::fs::read_to_string(&path).expect("read migration");
        for line in sql.lines() {
            let line = line.trim();
            if line.starts_with("--") {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            let Some(rest) = lower.split("create extension").nth(1) else {
                continue;
            };
            let rest = rest.trim_start();
            let rest = rest.strip_prefix("if not exists").unwrap_or(rest).trim_start();
            let name: String = rest
                .trim_start_matches('"')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

#[test]
fn every_extension_a_migration_creates_is_in_the_preflight_list() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../migrations");
    let mut created = BTreeSet::new();
    for dir in ["postgres", "postgres-open", "postgres-enterprise"] {
        created.extend(extensions_created_in(&root.join(dir)));
    }
    assert!(
        created.contains("pg_trgm"),
        "scanner found no extensions; is the migrations path right? {created:?}"
    );
    for ext in &created {
        assert!(
            REQUIRED_POSTGRES_EXTENSIONS.contains(&ext.as_str()),
            "a migration creates extension `{ext}`, which the preflight does not check. \
             Add it to REQUIRED_POSTGRES_EXTENSIONS and to the managed-PostgreSQL docs \
             (Azure azure.extensions allow-list)."
        );
    }
}

#[test]
fn snapshot_does_not_set_pg17_only_parameters_unguarded() {
    let snapshot = include_str!("../../../migrations/postgres-open/000_open_init.sql");
    for line in snapshot.lines() {
        let l = line.trim().to_ascii_lowercase();
        assert!(
            !l.starts_with("set transaction_timeout"),
            "000_open_init.sql has a bare `{line}`; transaction_timeout exists only from \
             PostgreSQL 17 and aborts a fresh install on 16 (NAN-5260)"
        );
    }
}

#[test]
fn platform_detection_maps_each_provider_marker() {
    assert_eq!(platform_from_markers(true, false, false), PostgresPlatform::AzureFlexibleServer);
    assert_eq!(platform_from_markers(false, true, false), PostgresPlatform::Rds);
    assert_eq!(platform_from_markers(false, false, true), PostgresPlatform::CloudSql);
    assert_eq!(platform_from_markers(false, false, false), PostgresPlatform::Other);
}

#[test]
fn missing_extension_message_names_extensions_and_leads_with_the_platform_fix() {
    let missing = vec![MissingExtension {
        name: "pg_trgm".into(),
        reason: "extension \"pg_trgm\" is not allow-listed".into(),
    }];
    let msg = missing_extensions_message(&PostgresPlatform::AzureFlexibleServer, &missing);
    assert!(msg.contains("pg_trgm"), "{msg}");
    assert!(msg.contains("Fix: Azure flexible server"), "{msg}");
    assert!(msg.contains("azure.extensions"), "{msg}");
    assert!(msg.contains("pg_trgm,pgcrypto,uuid-ossp"), "{msg}");
    assert!(msg.contains("Nothing was applied"), "{msg}");

    let msg = missing_extensions_message(&PostgresPlatform::Rds, &missing);
    assert!(msg.contains("Fix: Amazon RDS"), "{msg}");
    assert!(msg.contains("rds.allowed_extensions"), "{msg}");
}

#[test]
fn only_a_checksum_mismatch_is_not_pending_work() {
    use crate::db::{schema_check_means_pending, SchemaCheckError};
    let pending = SchemaCheckError::Pending { label: "core", version: 1, description: "x".into() };
    let failed = SchemaCheckError::Failed { label: "core", version: 1, description: "x".into() };
    let drift = SchemaCheckError::ChecksumMismatch { label: "core", version: 1, description: "x".into() };
    let fresh = SchemaCheckError::HistoryUnavailable { label: "core", source: sqlx::Error::RowNotFound };
    assert!(schema_check_means_pending(&pending));
    assert!(schema_check_means_pending(&failed));
    assert!(schema_check_means_pending(&fresh));
    assert!(!schema_check_means_pending(&drift));
}

#[test]
fn schema_create_message_names_the_user_and_both_fixes() {
    let access = PublicSchemaAccess {
        user: "nanosiem".into(),
        database: "nanosiem".into(),
        owner: Some("azure_pg_admin".into()),
        can_create: false,
    };
    let msg = schema_create_message(&PostgresPlatform::AzureFlexibleServer, &access);
    assert!(msg.contains("Azure Database for PostgreSQL flexible server"), "{msg}");
    assert!(msg.contains("schema owner: azure_pg_admin"), "{msg}");
    assert!(msg.contains("ALTER SCHEMA public OWNER TO nanosiem;"), "{msg}");
    assert!(msg.contains("GRANT ALL ON SCHEMA public TO nanosiem;"), "{msg}");
    assert!(msg.contains("as the server admin user, connected to database nanosiem"), "{msg}");
    assert!(msg.contains("Nothing was applied"), "{msg}");

    let absent = PublicSchemaAccess { owner: None, ..access };
    let msg = schema_create_message(&PostgresPlatform::Rds, &absent);
    assert!(msg.contains("CREATE SCHEMA public AUTHORIZATION nanosiem;"), "{msg}");
    assert!(msg.contains("the master user"), "{msg}");
}

/// NAN-5269: a role that owns the database but not schema `public` and has no
/// CREATE on it (Azure flexible server's layout) must be refused before any DDL.
/// Needs `NANOSIEM_TEST_DATABASE_URL` to connect as a superuser of a disposable
/// server; creates and drops its own role and database.
#[tokio::test]
async fn preflight_refuses_a_role_without_create_on_public() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else {
        return;
    };
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect test database");
    let suffix = format!("{:08x}", rand::random::<u32>());
    let role = format!("nano_pf_{suffix}");
    let db = format!("nano_pf_{suffix}");
    let password = format!("pw{suffix}");
    for sql in [
        format!("CREATE ROLE {role} LOGIN PASSWORD '{password}'"),
        format!("CREATE DATABASE {db} OWNER {role}"),
    ] {
        sqlx::query(&sql).execute(&admin).await.expect("setup");
    }
    let mut opts: sqlx::postgres::PgConnectOptions = url.parse().expect("parse url");
    let admin_db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts.clone().database(&db))
        .await
        .expect("connect new database as admin");
    // Azure flexible server's layout: someone else owns `public`, the
    // database owner keeps only USAGE.
    for sql in [
        "ALTER SCHEMA public OWNER TO CURRENT_USER".to_string(),
        "REVOKE ALL ON SCHEMA public FROM PUBLIC".to_string(),
        "GRANT USAGE ON SCHEMA public TO PUBLIC".to_string(),
    ] {
        sqlx::query(&sql).execute(&admin_db).await.expect("schema setup");
    }
    opts = opts.database(&db).username(&role).password(&password);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts.clone())
        .await
        .expect("connect as nano role");
    let err = check_postgres_compatibility(&pool, true).await.expect_err("must refuse");
    let msg = err.to_string();
    assert!(matches!(err, PostgresPreflightError::NoCreateOnPublicSchema { .. }), "{msg}");
    assert!(msg.contains(&format!("ALTER SCHEMA public OWNER TO {role};")), "{msg}");

    // Nothing pending (an existing, working install): warn with the same fix
    // and carry on; this check must never stop an install that runs.
    let report = check_postgres_compatibility(&pool, false)
        .await
        .expect("nothing pending: warn, don't fail");
    let warning = report.schema_warning.expect("the warning carries the fix");
    assert!(warning.contains("no migration pending, continuing"), "{warning}");
    assert!(warning.contains(&format!("ALTER SCHEMA public OWNER TO {role};")), "{warning}");
    assert!(warning.contains(&format!("GRANT ALL ON SCHEMA public TO {role};")), "{warning}");
    // This database has no migration history, so the core migrations are pending.
    assert!(crate::db::postgres_migrations_pending(&pool).await);
    pool.close().await;

    // The documented fix makes the same role pass.
    sqlx::query(&format!("GRANT ALL ON SCHEMA public TO {role}"))
        .execute(&admin_db)
        .await
        .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    let report = check_postgres_compatibility(&pool, true).await.expect("passes after GRANT");
    assert!(report.schema_warning.is_none());
    pool.close().await;
    admin_db.close().await;
    sqlx::query(&format!("DROP DATABASE {db} WITH (FORCE)")).execute(&admin).await.unwrap();
    sqlx::query(&format!("DROP ROLE {role}")).execute(&admin).await.unwrap();
}

#[tokio::test]
async fn preflight_passes_on_a_stock_server_and_installs_nothing() {
    let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else {
        return;
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect test database");
    let before: Vec<String> = sqlx::query_scalar("SELECT extname::text FROM pg_extension ORDER BY 1")
        .fetch_all(&pool)
        .await
        .unwrap();
    let report = check_postgres_compatibility(&pool, true).await.expect("preflight passes");
    assert!(report.server_version_num >= MIN_POSTGRES_VERSION_NUM);
    let after: Vec<String> = sqlx::query_scalar("SELECT extname::text FROM pg_extension ORDER BY 1")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(before, after, "the preflight must roll back its probe");
}
