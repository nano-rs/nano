// SPDX-License-Identifier: AGPL-3.0-or-later

//! Installation-owned audit delivery worker. No hosted control plane.
use anyhow::{ensure, Context, Result};
use nanosiem_core::audit::trusted_local_delivery::LocalAuditDelivery;
use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    ensure!(
        !std::env::var("DEPLOYMENT_MODE").is_ok_and(|mode| mode == "enterprise_shared"),
        "local audit delivery refuses shared mode"
    );
    let tenant = std::env::var("NANO_LAKE_TENANT_ID")?.parse::<uuid::Uuid>()?;
    let endpoint = std::env::var("NANO_LOCAL_AUDIT_URL")?;
    let token_path = std::env::var("NANO_LOCAL_AUDIT_TOKEN_FILE")?;
    let token = std::fs::read_to_string(token_path)
        .context("read local audit token")?
        .trim()
        .to_owned();
    let database = zeroize::Zeroizing::new(std::env::var("DATABASE_URL")?);
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(database.as_str())
        .await
        .map_err(|_| anyhow::anyhow!("connect local audit database failed"))?;
    let delivery =
        LocalAuditDelivery::new(pool, tenant, &endpoint, token).map_err(anyhow::Error::msg)?;
    delivery.prepare().await.map_err(anyhow::Error::msg)?;
    loop {
        match delivery.deliver_once().await {
            Ok(count) if count > 0 => {
                tracing::info!(count, "Local audit batch delivered to bronze")
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error,"Local audit batch retained for retry"),
        }
        tokio::select! {
            _=tokio::time::sleep(std::time::Duration::from_secs(1))=>{},
            _=tokio::signal::ctrl_c()=>break,
        }
    }
    Ok(())
}
