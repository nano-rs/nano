// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runtime demo migrations
//!
//! Unlike the main PostgreSQL migrations (compiled via sqlx::migrate!()),
//! demo migrations are loaded at runtime only when DEPLOYMENT_MODE=demo.
//! This ensures zero demo artifacts in production binaries and databases.

use sqlx::PgPool;
use std::path::Path;
use tracing::{info, warn};

/// Run demo-specific migrations from the `migrations/demo/` directory.
/// Only call this when DEPLOYMENT_MODE=demo.
pub async fn run_demo_migrations(pool: &PgPool) -> Result<(), sqlx::Error> {
    info!("Running demo migrations...");

    // Determine migrations directory relative to the binary's working directory
    let migrations_dir = find_migrations_dir();

    let mut entries: Vec<_> = std::fs::read_dir(&migrations_dir)
        .map_err(|e| {
            warn!(
                path = %migrations_dir.display(),
                error = %e,
                "Demo migrations directory not found — skipping"
            );
            e
        })
        .unwrap_or_else(|_| {
            // Return an empty iterator if directory doesn't exist
            std::fs::read_dir(".").unwrap()
        })
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "sql")
                .unwrap_or(false)
        })
        .collect();

    if entries.is_empty() {
        info!("No demo migrations found");
        return Ok(());
    }

    entries.sort_by_key(|e| e.file_name());

    // Ensure the demo schema exists (needed for the migrations table check)
    sqlx::query("CREATE SCHEMA IF NOT EXISTS demo")
        .execute(pool)
        .await?;

    // Ensure the demo migrations tracking table exists
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS demo.migrations (
            version INT PRIMARY KEY,
            filename TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(pool)
    .await?;

    for entry in entries {
        let filename = entry.file_name().to_string_lossy().to_string();

        // Extract version number from filename (e.g., "001_demo_schema.sql" -> 1)
        let version: i32 = filename
            .split('_')
            .next()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        if version == 0 {
            warn!(filename = %filename, "Skipping migration with unparseable version");
            continue;
        }

        // Check if already applied
        let already_applied: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM demo.migrations WHERE version = $1)")
                .bind(version)
                .fetch_one(pool)
                .await?;

        if already_applied {
            continue;
        }

        // Read and execute migration
        let sql = std::fs::read_to_string(entry.path()).map_err(|e| {
            sqlx::Error::Configuration(
                format!("Failed to read demo migration {}: {}", filename, e).into(),
            )
        })?;

        info!(version = version, filename = %filename, "Applying demo migration");

        // Use raw_sql for multi-statement migration files
        sqlx::raw_sql(&sql).execute(pool).await?;

        // Record as applied
        sqlx::query("INSERT INTO demo.migrations (version, filename) VALUES ($1, $2)")
            .bind(version)
            .bind(&filename)
            .execute(pool)
            .await?;
    }

    info!("Demo migrations complete");
    Ok(())
}

/// Find the demo migrations directory, checking common locations.
fn find_migrations_dir() -> std::path::PathBuf {
    let candidates = [
        Path::new("migrations/demo"),
        Path::new("../migrations/demo"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return candidate.to_path_buf();
        }
    }

    // Default — will be handled gracefully if missing
    Path::new("../migrations/demo").to_path_buf()
}
