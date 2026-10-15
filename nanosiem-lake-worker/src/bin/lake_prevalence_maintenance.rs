// SPDX-License-Identifier: AGPL-3.0-or-later

//! Standalone tenant-private SlateDB compactor. Deployment supplies a
//! maintenance-only owner bearer and a separate exact-prefix read credential.

use std::os::unix::fs::PermissionsExt;
use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{ensure, Context, Result};
use nanosiem_lake_worker::part_ingest::{
    prevalence_owner_store::{MaintenanceAccess, OwnerAccess, OwnerStore},
    s3_store::S3Location,
};
use serde::Deserialize;
use slatedb::{
    admin::AdminBuilder,
    object_store::{aws::AmazonS3Builder, prefix::PrefixStore, ObjectStore},
};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    read: S3Location,
    owner: OwnerAccess,
    journal_dir: PathBuf,
    /// The owner's private server CA bundle (the release-pinned
    /// `part_signing.ca_file`); required for the https owner URL. System
    /// roots are never trusted.
    #[serde(default)]
    owner_ca_file: Option<PathBuf>,
}

fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

async fn run() -> Result<()> {
    let config_file = std::env::var("NANO_PREVALENCE_MAINTENANCE_CONFIG")
        .context("NANO_PREVALENCE_MAINTENANCE_CONFIG is required")?;
    ensure!(
        std::fs::metadata(&config_file)?.permissions().mode() & 0o077 == 0,
        "maintenance config must be private"
    );
    let config: Config = serde_json::from_slice(&std::fs::read(config_file)?)?;
    let tenant = uuid::Uuid::parse_str(&config.owner.tenant_id)?;
    ensure!(
        tenant.to_string() == config.owner.tenant_id,
        "noncanonical tenant"
    );
    ensure!(
        config.read.prefix == format!("lake/prevalence-state/v1/tenant={tenant}/"),
        "maintenance read prefix differs from tenant"
    );
    ensure!(
        config.read.endpoint.starts_with("https://"),
        "maintenance reads require HTTPS"
    );
    ensure!(
        config.owner.url.starts_with("https://"),
        "maintenance owner requires HTTPS"
    );
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&config.read.bucket)
        .with_region(&config.read.region)
        .with_endpoint(&config.read.endpoint)
        .with_access_key_id(&config.read.access_key_id)
        .with_secret_access_key(&config.read.secret_access_key);
    if let Some(token) = &config.read.session_token {
        builder = builder.with_token(token);
    }
    let reads: Arc<dyn ObjectStore> = Arc::new(PrefixStore::new(
        Arc::new(builder.build()?),
        config.read.prefix.as_str(),
    ));
    let store: Arc<dyn ObjectStore> = Arc::new(OwnerStore::new_maintenance(
        reads,
        MaintenanceAccess {
            read: config.read,
            owner: config.owner,
            owner_ca_file: config.owner_ca_file,
        },
        &config.journal_dir,
    )?);
    let admin = AdminBuilder::new("db", store).build();
    // The same bounded options as the cell's maintenance[T].
    let options = nanosiem_lake_worker::part_ingest::maintenance::compactor_options();
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
        signal.cancel();
    });
    admin.run_compactor_with_options(shutdown, options).await?;
    Ok(())
}
