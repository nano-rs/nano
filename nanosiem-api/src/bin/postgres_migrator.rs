// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone PostgreSQL schema migrator for canonical lake deployments.

use anyhow::{Context, Result};
use std::process::ExitCode;

#[path = "postgres_migrator/connection.rs"]
mod connection;

#[tokio::main]
async fn main() -> ExitCode {
    let _tracing_guard = nanosiem_core::telemetry::init_tracing("postgres-migrator");

    match run().await {
        Ok(()) => {
            tracing::info!("PostgreSQL schema migration complete");
            ExitCode::SUCCESS
        }
        Err(error) => {
            tracing::error!("PostgreSQL schema migration failed: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// `postgres_migrator tenant-purge-fk-indexes [--receipt PATH]` (NAN-2900):
/// the pre-migrate phase that builds the FK indexes migration 9003420 needs
/// on a populated control database, CONCURRENTLY and in autocommit, on the
/// same migrator connection configuration. Run it before the migrate step
/// that carries 9003420 and again after it (the second run adopts the
/// indexes and requires `tenant_purge_coverage_gaps()` to be empty). Prints
/// the JSON receipt; exits non-zero when `passed` is false.
#[cfg(feature = "enterprise")]
async fn run_tenant_purge_fk_indexes(receipt_path: Option<std::path::PathBuf>) -> Result<()> {
    let pool = connection::MigrationConnection::from_env()?
        .connect()
        .await?;
    let receipt = nanosiem_core::enterprise_shared_tenant_purge_prebuild::run(&pool).await;
    pool.close().await;
    let json = serde_json::to_string_pretty(&receipt)?;
    if let Some(path) = receipt_path {
        std::fs::write(&path, format!("{json}\n"))
            .with_context(|| format!("writing receipt {}", path.display()))?;
    }
    println!("{json}");
    anyhow::ensure!(
        receipt.passed,
        "tenant purge FK index phase failed: {}",
        receipt.error.as_deref().unwrap_or("unknown")
    );
    Ok(())
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        #[cfg(feature = "enterprise")]
        [phase] if phase == "tenant-purge-fk-indexes" => return run_tenant_purge_fk_indexes(None).await,
        #[cfg(feature = "enterprise")]
        [phase, flag, path] if phase == "tenant-purge-fk-indexes" && flag == "--receipt" => {
            return run_tenant_purge_fk_indexes(Some(path.into())).await
        }
        #[cfg(not(feature = "enterprise"))]
        [phase, ..] if phase == "tenant-purge-fk-indexes" => {
            anyhow::bail!("tenant-purge-fk-indexes requires the enterprise feature")
        }
        _ => anyhow::bail!("usage: postgres_migrator [tenant-purge-fk-indexes [--receipt PATH]]"),
    }
    let pool = connection::MigrationConnection::from_env()?
        .connect()
        .await?;
    nanosiem_core::db::run_postgres_migrations(&pool)
        .await
        .context("running open PostgreSQL migrations")?;

    #[cfg(feature = "enterprise")]
    {
        // NAN-4328: CONCURRENTLY prebuild for 9014330 on a populated control
        // DB, in this same migrate step (autocommit, before the migration
        // transaction); a no-op once 9014330 is applied.
        let receipt = nanosiem_core::enterprise_shared_writer_jti_prebuild::run(&pool)
            .await
            .context("NAN-4328 writer JTI retention index prebuild")?;
        tracing::info!(
            receipt = %serde_json::to_string(&receipt).unwrap_or_default(),
            "writer JTI retention index prebuild"
        );
        nanosiem_enterprise::postgres_migrations::run(&pool)
            .await
            .context("running enterprise PostgreSQL overlay migrations")?;
    }

    pool.close().await;
    Ok(())
}
