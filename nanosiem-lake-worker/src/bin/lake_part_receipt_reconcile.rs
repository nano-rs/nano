// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3499 operator tool: backfill control evidence for committed part
//! files that have no lake_part writer receipt. Dry run by default.
//!
//! ```text
//! lake_part_receipt_reconcile --tenant <uuid> [--evidence cloudflare|s3|r2-env|cell-exchange] [--limit N]
//!                             [--apply --reason "<text>"]
//! ```
//!
//! - `CONTROL_DATABASE_URL`: control Postgres. A dry run only reads, inside
//!   a READ ONLY transaction; `--apply` must connect as a member of
//!   `nano_shared_r2_reclaim_operator`.
//! - `--evidence cloudflare` (default): `CLOUDFLARE_API_TOKEN` (R2 read) and
//!   `CLOUDFLARE_ACCOUNT_ID`.
//! - `--evidence s3`: `NANO_RECONCILE_S3_LOCATION`, a private JSON
//!   `S3Location` for the tenant bucket with an empty prefix.
//! - `--evidence r2-env` (NAN-3524, the in-cluster Job): the tenant bucket
//!   through its S3 API with the AWS-style credential the reconciliation
//!   workloads mount by `envFrom` (`AWS_ACCESS_KEY_ID`,
//!   `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`, `AWS_REGION`
//!   default `auto`, and the bare R2 origin in `AWS_ENDPOINT_URL_S3`), read
//!   exactly as `writer_reclaim::r2_operator` reads it. Read-only use: GET
//!   and list.
//! - `--evidence cell-exchange` (NAN-3524, a LEAN tenant's in-cluster Job;
//!   lean stores no tenant R2 credential): the Job's projected token
//!   (`NANO_RECONCILE_TOKEN_FILE`) is exchanged at `NANO_RECONCILE_EXCHANGE_URL`
//!   (`{control_url}/v1/lake/cells/<cell>/receipt-reconcile-exchange`) for one
//!   read-only `lake_part_read` credential on the tenant's part tree
//!   (`lake_part_gc::receipt_reconcile_exchange`). The run stops a minute
//!   before that credential expires.
//!
//! Output: one JSON line per part (and per applied file), then a summary line.

use std::os::unix::fs::PermissionsExt;

use anyhow::{bail, ensure, Context, Result};
use nanosiem_lake_worker::lake_part_gc::receipt_backfill::{
    reconcile, BucketEvidence, CloudflareBucketEvidence, PgReceiptLedger, S3BucketEvidence,
};
use nanosiem_lake_worker::lake_part_gc::receipt_reconcile_exchange as cell_exchange;
use nanosiem_lake_worker::part_ingest::s3_store::{S3Location, S3ObjectStore};

struct Args {
    tenant: uuid::Uuid,
    evidence: String,
    limit: i32,
    apply: bool,
    reason: String,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let (mut tenant, mut evidence, mut limit, mut apply, mut reason) = (None, "cloudflare".to_owned(), 10_000, false, String::new());
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tenant" => tenant = Some(args.next().context("--tenant needs a value")?),
            "--evidence" => evidence = args.next().context("--evidence needs a value")?,
            "--limit" => limit = args.next().context("--limit needs a value")?.parse()?,
            "--reason" => reason = args.next().context("--reason needs a value")?,
            "--apply" => apply = true,
            other => bail!("unknown argument {other}"),
        }
    }
    let tenant_text = tenant.context("--tenant is required")?;
    let tenant = uuid::Uuid::parse_str(&tenant_text)?;
    ensure!(tenant.to_string() == tenant_text, "noncanonical tenant");
    ensure!((1..=100_000).contains(&limit), "--limit must be 1..=100000");
    Ok(Args { tenant, evidence, limit, apply, reason })
}

/// The tenant bucket, unprefixed, from the reconciliation workloads' AWS-style env.
fn r2_env_location(bucket: &str) -> Result<S3Location> {
    let var = |name: &str| std::env::var(name).with_context(|| format!("{name} is required for --evidence r2-env"));
    Ok(S3Location {
        endpoint: nanosiem_lake_worker::writer_reclaim::r2_endpoint_from_env()?,
        region: std::env::var("AWS_REGION").unwrap_or_else(|_| "auto".into()),
        bucket: bucket.to_owned(),
        prefix: String::new(),
        access_key_id: var("AWS_ACCESS_KEY_ID")?,
        secret_access_key: var("AWS_SECRET_ACCESS_KEY")?,
        session_token: std::env::var("AWS_SESSION_TOKEN").ok().filter(|t| !t.is_empty()),
    })
}

fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<()> {
    let args = parse_args()?;
    let bucket_name = format!("nano-shared-r2-{}", args.tenant);
    // Only the exchanged credential has a known end; the run must finish on it.
    let mut deadline: Option<chrono::DateTime<chrono::Utc>> = None;
    let bucket: Box<dyn BucketEvidence> = match args.evidence.as_str() {
        "cloudflare" => {
            let token = zeroize::Zeroizing::new(std::env::var("CLOUDFLARE_API_TOKEN").context("CLOUDFLARE_API_TOKEN is required")?);
            let account = std::env::var("CLOUDFLARE_ACCOUNT_ID").context("CLOUDFLARE_ACCOUNT_ID is required")?;
            Box::new(CloudflareBucketEvidence::new(account.trim(), &bucket_name, token)?)
        }
        "s3" => {
            let file = std::env::var("NANO_RECONCILE_S3_LOCATION").context("NANO_RECONCILE_S3_LOCATION is required")?;
            ensure!(std::fs::metadata(&file)?.permissions().mode() & 0o077 == 0, "S3 location file must be private");
            let location: S3Location = serde_json::from_slice(&std::fs::read(file)?)?;
            ensure!(location.bucket == bucket_name && location.prefix.is_empty(), "S3 location must be the tenant bucket, unprefixed");
            Box::new(S3BucketEvidence { store: S3ObjectStore::new(&location)? })
        }
        "r2-env" => Box::new(S3BucketEvidence { store: S3ObjectStore::new(&r2_env_location(&bucket_name)?)? }),
        "cell-exchange" => {
            let url = std::env::var(cell_exchange::RECONCILE_EXCHANGE_URL_ENV)
                .with_context(|| format!("{} is required", cell_exchange::RECONCILE_EXCHANGE_URL_ENV))?;
            let file = std::env::var(cell_exchange::RECONCILE_TOKEN_FILE_ENV)
                .with_context(|| format!("{} is required", cell_exchange::RECONCILE_TOKEN_FILE_ENV))?;
            let token = cell_exchange::read_token_file(std::path::Path::new(&file))?;
            let grant = cell_exchange::exchange(&url, &token, &args.tenant.to_string()).await?;
            ensure!(grant.location.bucket == bucket_name, "exchanged credential names another bucket");
            deadline = Some(grant.expires_at - cell_exchange::RECONCILE_EXPIRY_MARGIN);
            println!("{}", serde_json::json!({"kind": "evidence", "source": "cell_exchange", "class": "lake_part_read",
                "expires_at": grant.expires_at.to_rfc3339()}));
            Box::new(S3BucketEvidence { store: S3ObjectStore::new(&grant.location)? })
        }
        other => bail!("unknown --evidence {other}"),
    };
    let url = zeroize::Zeroizing::new(std::env::var("CONTROL_DATABASE_URL").context("CONTROL_DATABASE_URL is required")?);
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(url.as_str()).await
        .map_err(|error| anyhow::anyhow!("control connect failed: {}", error.as_database_error().map(|e| e.message().to_owned())
            .unwrap_or_else(|| "connection error".into())))?;
    let ledger = PgReceiptLedger { pool };
    let mut emit = |line: serde_json::Value| println!("{line}");
    let run = reconcile(args.tenant, &ledger, bucket.as_ref(), args.limit, args.apply, &args.reason, &mut emit);
    // Each backfill is idempotent, so stopping between writes is safe; a
    // rerun with a fresh credential continues where this one stopped.
    let summary = match deadline {
        Some(at) => {
            let left = (at - chrono::Utc::now()).to_std().context("the exchanged credential is already too close to expiry")?;
            tokio::time::timeout(left, run).await.map_err(|_| anyhow::anyhow!("stopped: the exchanged R2 credential expires"))??
        }
        None => run.await?,
    };
    println!("{}", serde_json::json!({"kind": "summary", "tenant": args.tenant, "apply": args.apply, "summary": summary}));
    ensure!(summary.apply_errors == 0, "{} backfills failed", summary.apply_errors);
    Ok(())
}
