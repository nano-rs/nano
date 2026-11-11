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
    let report = check_postgres_compatibility(&pool).await.expect("preflight passes");
    assert!(report.server_version_num >= MIN_POSTGRES_VERSION_NUM);
    let after: Vec<String> = sqlx::query_scalar("SELECT extname::text FROM pg_extension ORDER BY 1")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(before, after, "the preflight must roll back its probe");
}
