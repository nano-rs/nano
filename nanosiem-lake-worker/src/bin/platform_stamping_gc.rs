// SPDX-License-Identifier: AGPL-3.0-or-later
//! One bounded sweep. Explicit --apply is required to mutate retained data.
#[cfg(feature = "enterprise")]
use anyhow::Result;

#[cfg(feature = "enterprise")]
#[tokio::main]
async fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    use nanosiem_core::platform_enrichment::retention::{self, Options};
    let options = Options::parse(std::env::args().skip(1))?;
    let url = zeroize::Zeroizing::new(std::env::var("PLATFORM_STAMPING_GC_DATABASE_URL")?);
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(10)).connect(&url).await?;
    let report = retention::run_once(&pool, &options).await?;
    println!("{}", serde_json::to_string(&report)?);
    if report["ready"] == false {
        eprintln!("platform stamping alarm: database_bytes={} soft_limit_bytes={}",
            report["database_bytes"], report["soft_limit_bytes"]);
        pool.close().await;
        anyhow::bail!("platform stamping database soft limit exceeded");
    }
    pool.close().await;
    Ok(())
}
#[cfg(not(feature = "enterprise"))]
fn main() { eprintln!("platform_stamping_gc requires --features enterprise"); std::process::exit(2); }
