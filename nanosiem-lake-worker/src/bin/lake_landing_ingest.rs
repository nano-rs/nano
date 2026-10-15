// SPDX-License-Identifier: AGPL-3.0-or-later

//! OCSF bucket drop for open core (NAN-3807).
//!
//! `lake_landing_ingest` (or `lake_landing_ingest run`) is the converter: it
//! polls `landing-ocsf-v1/tenant_id=<T>/` and turns each landed file into an
//! ordinary bronze object that part ingest admits like Vector's
//! ([`nanosiem_lake_worker::landing`]).
//!
//! The admin subcommands provision sources. They hold the object store's root
//! key, so they run as a one-shot (`docker compose run --rm lean-landing-admin
//! ...`), never inside the API:
//!
//! ```text
//! lake_landing_ingest add --name <name> [--route <key>] [--endpoint <host:port>] [--scheme http|https]
//! lake_landing_ingest revoke <source_id>
//! lake_landing_ingest list
//! ```
//!
//! `add` creates a disabled log source (so Vector never renders it), a
//! landing source, and a write-only object-store user whose one policy allows
//! `s3:PutObject` under that source's folder only. It prints the key and a
//! ready-to-paste Tenzir pipeline to the operator's terminal once; the key is
//! never stored or logged. `revoke` deletes the object-store user and its
//! policy and marks the source revoked.
//!
//! The converter also revokes every landing source whose log source was
//! deleted (no foreign key ties them, migration 364): it stops taking that
//! source's files at once and, on its next tick, deletes the object-store user
//! and policy, then the row.

use anyhow::{bail, ensure, Context, Result};
use nanosiem_core::parsers::landing_ocsf::LandingOcsfStage;
use nanosiem_lake_worker::landing::{source_policy, Converter, CredentialRemover, PgLedger, LANDING_PREFIX, REFUSED_PREFIX};
use opendal::{layers::RetryLayer, services::S3, Operator};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::process::{Command, Stdio};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

const USAGE: &str = "usage: lake_landing_ingest [run]
       lake_landing_ingest add --name <name> [--route <key>] [--endpoint <host:port>] [--scheme http|https]
       lake_landing_ingest revoke <source_id>
       lake_landing_ingest list
environment: DATABASE_URL, NANO_LAKE_TENANT_ID, NANO_LAKE_BRONZE_BUCKET (nano-lake),
  NANO_LAKE_OBJECT_ENDPOINT (http://lake-object-store:9000), NANO_LAKE_ACCESS_KEY_ID,
  NANO_LAKE_SECRET_ACCESS_KEY, AWS_REGION, NANO_LAKE_BRONZE_SHARDS (1),
  NANO_LANDING_POLL_SECS (10), NANO_LANDING_MAX_FILES_PER_TICK (64), NANO_LANDING_LEASE_SECS (600),
  NANO_LANDING_SENDER_ENDPOINT (the host:port senders reach the store on; default: the object endpoint)";

struct Env {
    database_url: Zeroizing<String>,
    tenant_id: String,
    bucket: String,
    endpoint: String,
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
    region: String,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn parsed<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match var(name) {
        Some(text) => text.parse().map_err(|_| anyhow::anyhow!("{name} is not a valid number")),
        None => Ok(default),
    }
}

impl Env {
    fn load() -> Result<Self> {
        let tenant_id = var("NANO_LAKE_TENANT_ID").context("NANO_LAKE_TENANT_ID is required")?.to_ascii_lowercase();
        ensure!(
            tenant_id.len() <= 128 && tenant_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "NANO_LAKE_TENANT_ID is not a tenant id"
        );
        Ok(Self {
            database_url: Zeroizing::new(var("DATABASE_URL").context("DATABASE_URL is required")?),
            tenant_id,
            bucket: var("NANO_LAKE_BRONZE_BUCKET").unwrap_or_else(|| "nano-lake".into()),
            endpoint: var("NANO_LAKE_OBJECT_ENDPOINT").unwrap_or_else(|| "http://lake-object-store:9000".into()),
            access_key: Zeroizing::new(var("NANO_LAKE_ACCESS_KEY_ID").context("NANO_LAKE_ACCESS_KEY_ID is required")?),
            secret_key: Zeroizing::new(var("NANO_LAKE_SECRET_ACCESS_KEY").context("NANO_LAKE_SECRET_ACCESS_KEY is required")?),
            region: var("AWS_REGION").unwrap_or_else(|| "us-east-1".into()),
        })
    }

    async fn pool(&self) -> Result<PgPool> {
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(30))
            .connect(self.database_url.as_str())
            .await
            // The URL carries the password: never echo the driver's error.
            .map_err(|_| anyhow::anyhow!("connect to the database failed"))
    }

    fn store(&self) -> Result<Operator> {
        let builder = S3::default()
            .bucket(&self.bucket)
            .region(&self.region)
            .endpoint(&self.endpoint)
            .access_key_id(&self.access_key)
            .secret_access_key(&self.secret_key)
            .disable_config_load()
            .disable_ec2_metadata();
        Ok(Operator::new(builder)?.layer(RetryLayer::new().with_max_times(3)).finish())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    ensure!(
        !std::env::var("DEPLOYMENT_MODE").is_ok_and(|mode| mode == "enterprise_shared"),
        "the OCSF bucket drop is open core only; it refuses shared mode"
    );
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        None | Some("run") => run(Env::load()?).await,
        Some("add") => add(Env::load()?, &args[1..]).await,
        Some("revoke") => revoke(Env::load()?, &args[1..]).await,
        Some("list") => list(Env::load()?).await,
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(_) => bail!("{USAGE}"),
    }
}

async fn run(env: Env) -> Result<()> {
    let shards = parsed("NANO_LAKE_BRONZE_SHARDS", 1_u32)?;
    let poll = Duration::from_secs(parsed("NANO_LANDING_POLL_SECS", 10_u64)?.clamp(1, 3_600));
    let lease = Duration::from_secs(parsed("NANO_LANDING_LEASE_SECS", 600_u64)?.clamp(30, 86_400));
    let max_files_per_tick = parsed("NANO_LANDING_MAX_FILES_PER_TICK", 64_usize)?.clamp(1, 10_000);
    let converter = Converter {
        store: env.store()?,
        ledger: PgLedger { pool: env.pool().await?, lease },
        stage: LandingOcsfStage::new(shards).map_err(|e| anyhow::anyhow!("compile the lake storage stage: {e}"))?,
        tenant_id: env.tenant_id.clone(),
        max_files_per_tick,
    };
    tracing::info!(
        tenant_id = %env.tenant_id,
        bucket = %env.bucket,
        prefix = %format!("{LANDING_PREFIX}tenant_id={}/", env.tenant_id),
        shards,
        poll_secs = poll.as_secs(),
        "OCSF bucket drop converter started"
    );
    let mut ticks: u64 = 0;
    loop {
        match converter.tick().await {
            Ok(report) if report.listed > 0 => tracing::info!(?report, "landing tick"),
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "landing tick failed; retrying"),
        }
        // A landing source whose log source was deleted still owns a
        // write-only key: revoke it (user + policy, then the row).
        match converter.ledger.revoke_orphans(&RcRemover { env: &env }).await {
            Ok(revoked) if !revoked.is_empty() => tracing::info!(count = revoked.len(), "revoked orphaned landing sources"),
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "orphaned landing source sweep failed; retrying"),
        }
        ticks += 1;
        if ticks % 360 == 1 {
            match converter.ledger.prune().await {
                Ok(0) => {}
                Ok(pruned) => tracing::info!(pruned, "pruned finished landing ledger rows"),
                Err(error) => tracing::warn!(error = %format!("{error:#}"), "landing ledger prune failed"),
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// `route_key` alphabet: the slug `metadata.log_source` takes (NAN-3806).
fn route_key(text: &str) -> Result<String> {
    let mut key = String::with_capacity(text.len());
    for c in text.trim().chars() {
        match c {
            'a'..='z' | '0'..='9' | '_' => key.push(c),
            'A'..='Z' => key.push(c.to_ascii_lowercase()),
            ' ' | '-' | '.' => key.push('_'),
            _ => {}
        }
    }
    let key = key.trim_matches('_').to_string();
    ensure!(
        !key.is_empty() && key.len() <= 100 && key.as_bytes()[0].is_ascii_alphanumeric(),
        "--route must be 1-100 characters of a-z, 0-9 and _ starting with a letter or digit"
    );
    Ok(key)
}

fn flag<'a>(args: &'a [String], name: &str) -> Result<Option<&'a str>> {
    match args.iter().position(|a| a == name) {
        Some(i) => args.get(i + 1).map(|v| Some(v.as_str())).context(format!("{name} needs a value")),
        None => Ok(None),
    }
}

/// The RustFS CLI (`rc`, shipped in the cell image) with a private config
/// directory holding the root alias. Argument vectors that carry a key are
/// never logged.
struct Rc {
    home: tempfile::TempDir,
}

impl Rc {
    fn new(env: &Env) -> Result<Self> {
        let rc = Self { home: tempfile::tempdir().context("rc config directory")? };
        rc.run(
            "alias set",
            &["alias", "set", "nano-root", &env.endpoint, &env.access_key, &env.secret_key, "--bucket-lookup", "path"],
        )?;
        Ok(rc)
    }

    /// Run `rc`; on failure report only the step and exit status (the
    /// command line and the tool's output may carry a key).
    fn run(&self, step: &str, args: &[&str]) -> Result<()> {
        let status = Command::new("rc")
            .args(args)
            .env("HOME", self.home.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("run rc ({step}); is the RustFS CLI installed?"))?;
        ensure!(status.success(), "rc {step} failed ({status})");
        Ok(())
    }
}

/// Removes a landing source's object-store user and policy with the root key.
struct RcRemover<'a> {
    env: &'a Env,
}

#[async_trait::async_trait]
impl CredentialRemover for RcRemover<'_> {
    async fn remove(&self, object_user: &str, source_id: Uuid) -> Result<()> {
        let rc = Rc::new(self.env)?;
        if rc.run("admin user remove", &["admin", "user", "remove", "nano-root", object_user]).is_err() {
            // Already gone is success; a user that still exists is not.
            ensure!(
                rc.run("admin user info", &["admin", "user", "info", "nano-root", object_user]).is_err(),
                "object-store user still exists after a failed removal"
            );
        }
        let policy_name = format!("landing-{source_id}");
        let _ = rc.run("admin policy remove", &["admin", "policy", "remove", "nano-root", &policy_name]);
        Ok(())
    }
}

fn random_hex(chars: usize) -> String {
    let mut out = String::with_capacity(chars + 32);
    while out.len() < chars {
        out.push_str(&Uuid::new_v4().simple().to_string());
    }
    out.truncate(chars);
    out
}

async fn add(env: Env, args: &[String]) -> Result<()> {
    let name = flag(args, "--name")?.context("add needs --name <name>")?.trim().to_string();
    ensure!(!name.is_empty() && name.len() <= 255, "--name must be 1-255 characters");
    let route = route_key(flag(args, "--route")?.unwrap_or(&name))?;
    let sender_endpoint = flag(args, "--endpoint")?
        .map(str::to_string)
        .or_else(|| var("NANO_LANDING_SENDER_ENDPOINT"))
        .unwrap_or_else(|| env.endpoint.trim_start_matches("http://").trim_start_matches("https://").to_string());
    let scheme = flag(args, "--scheme")?
        .map(str::to_string)
        .unwrap_or_else(|| if env.endpoint.starts_with("https://") { "https".into() } else { "http".into() });
    ensure!(scheme == "http" || scheme == "https", "--scheme must be http or https");

    let pool = env.pool().await?;
    let source_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();
    // RustFS (like MinIO) caps access keys at 20 characters.
    let access_key = format!("nl{}", random_hex(18));
    let secret_key = Zeroizing::new(random_hex(48));
    let policy_name = format!("landing-{source_id}");

    let mut tx = pool.begin().await.context("begin")?;
    sqlx::query(
        "INSERT INTO log_sources (id, name, description, source_type, parser_vrl, match_values, \
                                  vendor, product, enabled, deployed) \
         VALUES ($1, $2, $3, 'tenzir_bucket', '', ARRAY[$4], 'Tenzir', 'OCSF bucket drop', false, false)",
    )
    .bind(source_id)
    .bind(&name)
    .bind("OCSF files dropped into the object store. Not rendered into Vector.")
    .bind(&route)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e.as_database_error().and_then(|d| d.constraint()) {
        Some(c) if c.contains("name") => anyhow::anyhow!("a log source named {name:?} already exists"),
        _ => anyhow::anyhow!("create log source: {e}"),
    })?;
    sqlx::query(
        "INSERT INTO landing_sources (source_id, route_key, credential_id, object_user, created_by) \
         VALUES ($1, $2, $3, $4, 'lean-landing-admin')",
    )
    .bind(source_id)
    .bind(&route)
    .bind(credential_id)
    .bind(&access_key)
    .execute(&mut *tx)
    .await
    .context("create landing source")?;

    let rc = Rc::new(&env)?;
    let policy_file = rc.home.path().join("policy.json");
    std::fs::write(&policy_file, serde_json::to_vec(&source_policy(&env.bucket, &env.tenant_id, source_id))?)?;
    let policy_path = policy_file.to_string_lossy().to_string();
    let provisioned = (|| -> Result<()> {
        rc.run("admin user add", &["admin", "user", "add", "nano-root", &access_key, &secret_key])?;
        rc.run("admin policy create", &["admin", "policy", "create", "nano-root", &policy_name, &policy_path])?;
        rc.run("admin policy attach", &["admin", "policy", "attach", "nano-root", &policy_name, "--user", &access_key])?;
        Ok(())
    })();
    let committed = match provisioned {
        Ok(()) => tx.commit().await.context("commit landing source"),
        Err(error) => Err(error),
    };
    if let Err(error) = committed {
        // Roll back the object-store side; the transaction rolls back on drop.
        let _ = rc.run("admin user remove", &["admin", "user", "remove", "nano-root", &access_key]);
        let _ = rc.run("admin policy remove", &["admin", "policy", "remove", "nano-root", &policy_name]);
        return Err(error.context("add landing source (rolled back)"));
    }
    tracing::info!(%source_id, %credential_id, route_key = %route, "landing source added");

    let folder = format!("{LANDING_PREFIX}tenant_id={}/source={source_id}/", env.tenant_id);
    println!(
        "Landing source added.
  name:          {name}
  source_id:     {source_id}
  route key:     {route} (rows are stamped metadata.log_source = {route})
  folder:        s3://{bucket}/{folder}
  credential id: {credential_id}

This key is shown once and is not stored. It may only PUT objects under the folder above.
  access_key_id:     {access_key}
  secret_access_key: {secret}

Ready-to-paste Tenzir pipeline tail (after your OCSF 1.9 mapping):

to_s3 \"s3://{bucket}/{folder}{{uuid}}.parquet?endpoint_override={sender_endpoint}&scheme={scheme}\",
  aws_iam={{access_key_id: \"{access_key}\", secret_access_key: \"{secret}\"}} {{
  write_parquet
}}

Each event must be OCSF 1.9 with metadata.version \"1.9.0\". Keep metadata.uid stable per event
(not a random UUIDv4) so a resend is deduplicated. Files that cannot be read are moved to
s3://{bucket}/{REFUSED_PREFIX}... and shown on Ingestion > Credentials > Bucket drop sources.
Revoke: docker compose run --rm lean-landing-admin revoke {source_id}",
        bucket = env.bucket,
        secret = secret_key.as_str(),
    );
    Ok(())
}

async fn revoke(env: Env, args: &[String]) -> Result<()> {
    let source_id: Uuid = args.first().context("revoke needs <source_id>")?.parse().context("source_id is not a UUID")?;
    let pool = env.pool().await?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT object_user, state FROM landing_sources WHERE source_id = $1")
            .bind(source_id)
            .fetch_optional(&pool)
            .await
            .context("read landing source")?;
    let (object_user, state) = row.context("no landing source with that id")?;
    let rc = Rc::new(&env)?;
    let policy_name = format!("landing-{source_id}");
    // Deleting the user is the revocation; an already-removed user is fine.
    let removed = rc.run("admin user remove", &["admin", "user", "remove", "nano-root", &object_user]);
    if let Err(error) = &removed {
        if state == "active" {
            tracing::warn!(error = %error, "object-store user removal failed; check it is gone before trusting the revocation");
        }
    }
    let _ = rc.run("admin policy remove", &["admin", "policy", "remove", "nano-root", &policy_name]);
    sqlx::query(
        "UPDATE landing_sources SET state = 'revoked', revoked_at = COALESCE(revoked_at, NOW()) WHERE source_id = $1",
    )
    .bind(source_id)
    .execute(&pool)
    .await
    .context("mark landing source revoked")?;
    removed.context("landing source marked revoked, but its object-store user could not be removed")?;
    println!("Landing source {source_id} revoked: its object-store user and policy are deleted.");
    Ok(())
}

async fn list(env: Env) -> Result<()> {
    let pool = env.pool().await?;
    let rows: Vec<(Uuid, String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT s.source_id, l.name, s.route_key, s.state, \
                COUNT(f.id) FILTER (WHERE f.state = 'accepted'), COUNT(f.id) FILTER (WHERE f.state = 'refused') \
           FROM landing_sources s JOIN log_sources l ON l.id = s.source_id \
           LEFT JOIN landing_files f ON f.source_id = s.source_id \
          GROUP BY s.source_id, l.name, s.route_key, s.state, s.created_at ORDER BY s.created_at",
    )
    .fetch_all(&pool)
    .await
    .context("list landing sources")?;
    println!("{:<36}  {:<8}  {:>8}  {:>8}  {:<24}  NAME", "SOURCE_ID", "STATE", "ACCEPTED", "REFUSED", "ROUTE_KEY");
    for (id, name, route, state, accepted, refused) in rows {
        println!("{id:<36}  {state:<8}  {accepted:>8}  {refused:>8}  {route:<24}  {name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_keys_follow_the_log_source_slug() {
        assert_eq!(route_key("Tenzir Sysmon").unwrap(), "tenzir_sysmon");
        assert_eq!(route_key("edge-fw.01").unwrap(), "edge_fw_01");
        assert!(route_key("***").is_err());
        assert!(route_key(&"a".repeat(101)).is_err());
    }

    #[test]
    fn generated_keys_have_the_object_store_shape() {
        let access = format!("nl{}", random_hex(18));
        assert_eq!(access.len(), 20);
        assert_eq!(random_hex(48).len(), 48);
        assert_ne!(random_hex(48), random_hex(48));
    }
}
