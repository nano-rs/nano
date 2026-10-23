//! nano-connector-runner: the connector feed runner as a jobs-style worker.
//!
//! `nano-connector-runner feed create|list|enable|disable ...` is the operator
//! feed CLI (see `admin::USAGE`); it uses the same environment, plus
//! `CONNECTOR_INGEST_DOMAIN` on hosted-shared.
//!
//! Environment:
//!   DEPLOYMENT_MODE                    hosted shared = signed tenant
//!                                      transactions + worker-assignment discovery;
//!                                      anything else = dedicated (plain pool)
//!   NANOSIEM_ENCRYPTION_KEY            deployment cipher (sealed feed secrets)
//!   dedicated:
//!     DATABASE_URL                     the one pool
//!   hosted-shared (build with `--features enterprise`: hosted feeds get
//!   their per-feed ingest token from the NAN-2590 issuance pass). The same
//!   layout as the jobs runtime and the region's database Secret:
//!     DATABASE_URL                     control login (tenant discovery, catalog)
//!     NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL  signed RLS runtime login
//!     NANOSIEM_SHARED_RLS_DATABASE / _RUNTIME_ROLE  checked against the login
//!     NANOSIEM_SHARED_RLS_KEY_ID / _CONTEXT_KEY_HEX / _KEY_NOT_AFTER
//!     NANOSIEM_SHARED_DETECTION_WORKER_IDENTITY
//!     CONNECTOR_INGEST_HOST_SUFFIX     tenant ingress host suffix; feeds whose
//!                                      ingest_url is elsewhere fail
//!   Pooler URLs (port 6432) get the transaction-pool settings of
//!   `nanosiem_core::db::pooler` (no statement cache, qualified roles only).
//!   optional:
//!     CONNECTOR_POLL_INTERVAL_SECS (30)  CONNECTOR_MAX_CONCURRENT (8)
//!     CONNECTOR_MAX_PER_TENANT (2)       CONNECTOR_DEFAULT_MAX_RUN_SECS (600)
//!     CONNECTOR_MAX_RUN_SECS (3600)      CONNECTOR_ALLOW_HTTP_INGEST (0)
//!     CONNECTOR_VRL_WORKER_EXE           (default: the `nano-connector` binary
//!                                         next to this one)
//!     CONNECTOR_VRL_MAX_WORKERS (32)     VRL workers alive at once
//!     CONNECTOR_VRL_MAX_PER_TENANT       VRL workers per tenant (default
//!                                        4 x CONNECTOR_MAX_PER_TENANT)
//!     CONNECTOR_VRL_WORKER_AS_BYTES (1 GiB)  per-worker address space;
//!                                        keep MAX_WORKERS x this under the
//!                                        pod memory limit
//!     CONNECTOR_VRL_ACQUIRE_SECS (60)    wait for a worker slot, then defer
//!     HOSTNAME                           lease owner / node id
//!   sandbox (see nano-connector/docs/SECURITY.md):
//!     NANO_CONNECTOR_SECCOMP / NANO_CONNECTOR_CGROUP = off|prefer|require
//!     NANO_CONNECTOR_SANDBOX=strict, NANO_CONNECTOR_CGROUP_PARENT
//!     hosted-shared requires NANO_CONNECTOR_SECCOMP=require (or strict)
//!   egress:
//!     CONNECTOR_EGRESS_DENY_CIDRS        comma-separated ranges no vendor
//!                                        request may reach (required on
//!                                        hosted-shared)
//!     CONNECTOR_EGRESS_DENY_HOSTS        comma-separated names / .suffixes;
//!                                        CONNECTOR_INGEST_HOST_SUFFIX is
//!                                        always added
//!   identity feeds (`kind: identity`, NAN-3503):
//!     NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE  the server-owned tenant ->
//!                                        coordinator map the API uses; unset:
//!                                        identity feeds fail as unconfigured
//!   dedicated / open core (NAN-3767), all four or none; refused on
//!   hosted-shared:
//!     CONNECTOR_IDENTITY_VECTOR_URL      the deployment's Vector enrichment
//!                                        ingress (e.g. http://vector:8090/):
//!                                        rows and deltas go through Vector
//!     VECTOR_AUTH_TOKEN                  its ingest token
//!     CONNECTOR_IDENTITY_COORDINATOR_URL the deployment's lean enrichment
//!                                        coordinator (commit, abort, delete)
//!     CONNECTOR_IDENTITY_COORDINATOR_TOKEN_FILE  its token file
//!     NANO_LAKE_TENANT_ID                the coordinator's tenant; feeds of
//!                                        the compatibility tenant map to it
//!     CONNECTOR_IDENTITY_V2_FIELDS (0)   the coordinator's v2 identity
//!                                        contract: `is_admin`, raw
//!                                        `deprovisioned`/`locked`/`staged`
//!                                        statuses, and delta runs (patch
//!                                        deltas + `manager_refs`). Off:
//!                                        users streams always run full.
//!                                        Only once every cell's coordinator
//!                                        has #6294 and #6302;
//!                                        CONNECTOR_IDENTITY_EMIT_IS_ADMIN is
//!                                        an alias
//!     CONNECTOR_IDENTITY_SPILL_DIR       private dir for rows waiting for
//!                                        their manager (default: temp dir);
//!                                        back it with a sized emptyDir.
//!                                        Stale `nano-identity-*` files in it
//!                                        are removed at startup
//!   schema: apply migration 350 / 9013180 before rolling a runner that
//!   has identity feeds; started before it, the runner runs HEC feeds only
//!   (legacy mode, identity disabled, logged at WARN).
//!
//! Before taking work the runner spawns one sandboxed VRL worker as a
//! self-test and refuses to start if a required isolation layer is missing.

use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use nano_connector::engine::EngineConfig;
use nano_connector::sandbox::{self, Enforce, SandboxPolicy};
use nano_connector::service::pg::{PgFeedStore, Tenancy};
use nano_connector::service::runner::platform_egress_deny;
use nano_connector::service::{Runner, RunnerConfig};
use nano_connector::vrl_exec::PoolConfig;
use nanosiem_core::crypto::EncryptionService;
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_security::TenantDetectionWorkerDiscovery;
#[cfg(feature = "enterprise")]
use nanosiem_core::rls_context_key_env::RlsContextKeyMaterial;
use sqlx::postgres::PgPoolOptions;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn env_num<T: FromStr>(name: &str, default: T) -> Result<T, String> {
    match env(name) {
        None => Ok(default),
        Some(v) => v.trim().parse().map_err(|_| format!("{name} is invalid")),
    }
}

/// `CONNECTOR_IDENTITY_V2_FIELDS`, or its older alias
/// `CONNECTOR_IDENTITY_EMIT_IS_ADMIN`: on only for `1` / `true`. The new
/// name wins when both are set.
fn identity_v2_fields(v2: Option<String>, alias: Option<String>) -> bool {
    v2.or(alias).is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
}

#[cfg(test)]
mod identity_flag_tests {
    use super::identity_v2_fields;

    #[test]
    fn v2_fields_flag_and_its_alias() {
        let s = |v: &str| Some(v.to_string());
        assert!(!identity_v2_fields(None, None), "off by default");
        assert!(identity_v2_fields(s("1"), None));
        assert!(identity_v2_fields(s("true"), None));
        assert!(identity_v2_fields(None, s("1")), "EMIT_IS_ADMIN alias");
        assert!(!identity_v2_fields(s("0"), s("1")), "the new name wins");
        assert!(!identity_v2_fields(s("yes please"), None));
    }
}

fn main() -> ExitCode {
    // First: this process will hold every tenant's decrypted credentials and
    // the platform keys. Not dumpable = no ptrace and no /proc/<pid>/mem or
    // environ for any other process of this uid (a VRL worker that escaped a
    // degraded sandbox included), and no core file.
    let hardened = sandbox::harden_host_process();
    // `feed ...` prints its result on stdout; its log lines go to stderr.
    let cli = matches!(std::env::args().nth(1).as_deref(), Some("feed" | "catalog"));
    let logs = tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()));
    if cli {
        logs.with_writer(std::io::stderr).init();
    } else {
        logs.init();
    }
    if let Err(e) = hardened {
        tracing::error!(error = %e, "nano-connector-runner could not make itself non-dumpable");
        return ExitCode::FAILURE;
    }
    if let Err(error) = EncryptionService::try_from_env() {
        tracing::error!(%error, "credential key configuration refused");
        return ExitCode::FAILURE;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "tokio runtime");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if cli => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
        Err(e) => {
            tracing::error!(error = %e, "nano-connector-runner refused to start");
            ExitCode::FAILURE
        }
    }
}

struct Deployment {
    tenancy: Tenancy,
    shared: bool,
    /// hosted-shared: the control pool (catalog reads); otherwise the
    /// runtime pool.
    catalog_pool: sqlx::PgPool,
}

/// `DEPLOYMENT_MODE`, fail closed (nano-red F1/C1). Every hosted protection
/// (signed RLS on the runtime login, seccomp=require, mandatory egress deny
/// CIDRs, https-only ingest, the ingest host suffix) keys on
/// hosted shared, so a typo must not silently select the dedicated
/// path on the control login. Accepted: exactly hosted shared, or the
/// dedicated / open-core values the API accepts (`managed`, `selfhosted`,
/// `self-hosted`, unset or empty). And a dedicated mode is refused when the
/// shared database layout is present.
fn deployment_mode(mode: Option<&str>, present: &[String]) -> Result<bool, String> {
    let shared = match mode {
        Some("enterprise_shared") => true,
        None | Some("" | "managed" | "selfhosted" | "self-hosted") => false,
        Some(other) => {
            return Err(format!(
                "invalid DEPLOYMENT_MODE {other:?}; expected enterprise_shared, managed, selfhosted, self-hosted, or unset"
            ));
        }
    };
    if !shared {
        let mut shared_vars: Vec<&str> = present
            .iter()
            .map(String::as_str)
            .filter(|k| k.starts_with("NANOSIEM_SHARED_RLS_") || *k == "NANOSIEM_SHARED_DETECTION_WORKER_IDENTITY")
            .collect();
        if !shared_vars.is_empty() {
            shared_vars.sort_unstable();
            return Err(format!(
                "DEPLOYMENT_MODE is {} but the enterprise_shared database layout is present ({}); refusing to run the dedicated path on it",
                mode.map_or_else(|| "unset".to_string(), |m| format!("{m:?}")),
                shared_vars.join(", ")
            ));
        }
    }
    Ok(shared)
}

/// Host memory the runner keeps for itself (pools, runs, the batches in
/// flight) on top of the VRL workers.
const RUNNER_RESERVE_BYTES: u64 = 256 << 20;

/// The effective memory limit of this process's cgroup: the smallest
/// cgroup v2 `memory.max` from its own cgroup (`/proc/self/cgroup`) up to
/// the root (in a pod's cgroup namespace that is just `/`), else v1
/// `memory.limit_in_bytes`. `None` = unlimited or unreadable.
fn cgroup_memory_limit() -> Option<u64> {
    let read = |p: &str| -> Option<u64> {
        let v = std::fs::read_to_string(p).ok()?;
        // "max" (v2) does not parse; v1 reports unlimited as ~i64::MAX.
        v.trim().parse::<u64>().ok().filter(|n| *n < 1 << 62)
    };
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|c| c.lines().find_map(|l| l.strip_prefix("0::").map(str::to_string)))
        .unwrap_or_else(|| "/".into());
    let mut path = std::path::PathBuf::from(own.trim());
    let mut limit: Option<u64> = None;
    loop {
        let rel = path.to_string_lossy().trim_start_matches('/').to_string();
        let file = if rel.is_empty() { "/sys/fs/cgroup/memory.max".to_string() } else { format!("/sys/fs/cgroup/{rel}/memory.max") };
        if let Some(n) = read(&file) {
            limit = Some(limit.map_or(n, |l| l.min(n)));
        }
        if !path.pop() {
            break;
        }
    }
    limit.or_else(|| read("/sys/fs/cgroup/memory/memory.limit_in_bytes"))
}

/// nano-red C3: per-worker memory rests on RLIMIT_AS (no cgroup delegation
/// under Kubernetes), so every worker at its address-space cap, plus the
/// host's copy of its input and output (the response ceiling, and its 2x
/// output cap), plus the runner's reserve, must fit the pod limit, or the
/// OOM killer, not the sandbox, is what stops a hostile spec. On
/// hosted-shared an unlimited pod is refused too.
fn check_vrl_memory(limit: Option<u64>, max_workers: usize, worker_as: u64, shared: bool) -> Result<(), String> {
    let per_call_io = nano_connector::engine::default_ceilings().max_response_bytes * 3;
    let per_worker = worker_as + per_call_io;
    let Some(limit) = limit else {
        return if shared { Err("enterprise_shared needs a pod memory limit (cgroup memory.max) to bound the VRL workers".into()) } else { Ok(()) };
    };
    let need = (max_workers as u64).saturating_mul(per_worker).saturating_add(RUNNER_RESERVE_BYTES);
    if need > limit {
        let fit = limit.saturating_sub(RUNNER_RESERVE_BYTES) / per_worker;
        return Err(format!(
            "CONNECTOR_VRL_MAX_WORKERS ({max_workers}) x (CONNECTOR_VRL_WORKER_AS_BYTES {} MiB + {} MiB call I/O) + {} MiB reserve = {} MiB exceeds the pod memory limit ({} MiB); at most {fit} workers fit",
            worker_as >> 20,
            per_call_io >> 20,
            RUNNER_RESERVE_BYTES >> 20,
            need >> 20,
            limit >> 20
        ));
    }
    Ok(())
}

#[cfg(feature = "enterprise")]
fn is_enterprise_shared() -> Result<bool, String> {
    let mode = std::env::var("DEPLOYMENT_MODE").ok();
    let present: Vec<String> = std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).collect();
    deployment_mode(mode.as_deref(), &present)
}

async fn pool(url: &str, what: &str, max_connections: u32) -> Result<sqlx::PgPool, String> {
    let options = nanosiem_core::db::pooler::options(url).map_err(|e| format!("{what} is invalid: {e}"))?;
    PgPoolOptions::new()
        .min_connections(0)
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(30))
        .connect_with(options)
        .await
        .map_err(|e| format!("{what}: {e}"))
}

async fn connect(max_connections: u32) -> Result<Deployment, String> {
    #[cfg(feature = "enterprise")]
    let shared = is_enterprise_shared()?;
    // Open builds still parse DEPLOYMENT_MODE so a shared layout is refused.
    #[cfg(not(feature = "enterprise"))]
    let shared = deployment_mode(
        std::env::var("DEPLOYMENT_MODE").ok().as_deref(),
        &std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).collect::<Vec<String>>(),
    )?;
    if shared && !cfg!(feature = "enterprise") {
        // Hosted feeds get their ingest token from the runner's NAN-2590
        // issuance pass, which only the enterprise build carries.
        return Err("DEPLOYMENT_MODE=enterprise_shared needs a runner built with --features enterprise".into());
    }
    let url = env("DATABASE_URL").ok_or("DATABASE_URL is required")?;
    if !shared {
        let pool = pool(&url, "DATABASE_URL", max_connections).await?;
        return Ok(Deployment { tenancy: Tenancy::Dedicated { pool: pool.clone() }, shared, catalog_pool: pool });
    }
    #[cfg(not(feature = "enterprise"))]
    { Err("enterprise_shared requires an enterprise runner".into()) }
    #[cfg(feature = "enterprise")]
    {
    // enterprise_shared: the jobs runtime's layout (the region database
    // Secret): DATABASE_URL is the control login, the runtime login is
    // NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL.
    let identity = env("NANOSIEM_SHARED_DETECTION_WORKER_IDENTITY").ok_or("NANOSIEM_SHARED_DETECTION_WORKER_IDENTITY is required")?;
    let runtime_url = env("NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL")
        .ok_or("NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL is required on enterprise_shared")?;
    let database = env("NANOSIEM_SHARED_RLS_DATABASE").ok_or("NANOSIEM_SHARED_RLS_DATABASE is required on enterprise_shared")?;
    let role = env("NANOSIEM_SHARED_RLS_RUNTIME_ROLE").ok_or("NANOSIEM_SHARED_RLS_RUNTIME_ROLE is required on enterprise_shared")?;
    let key = RlsContextKeyMaterial::from_env().map_err(|e| e.to_string())?;
    let control = pool(&url, "DATABASE_URL (control)", 2).await?;
    let runtime = pool(&runtime_url, "NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL", max_connections).await?;
    // The signer binds tenant contexts to this database and role: refuse a
    // runtime login that is anything else (the jobs runtime's check).
    let (user, db): (String, String) = sqlx::query_as("SELECT current_user::text, current_database()::text")
        .fetch_one(&runtime)
        .await
        .map_err(|e| format!("runtime database: {e}"))?;
    if user != role || db != database {
        return Err(format!(
            "the runtime login is {user}@{db}, not NANOSIEM_SHARED_RLS_RUNTIME_ROLE@NANOSIEM_SHARED_RLS_DATABASE ({role}@{database})"
        ));
    }
    key.spawn_expiry_monitor("nano-connector-runner");
    let signer = Arc::new(key.into_signer(database, role, 30).map_err(|e| e.to_string())?);
    let discovery = Arc::new(
        TenantDetectionWorkerDiscovery::new("enterprise_shared", control.clone(), runtime.clone(), Arc::clone(&signer))
            .map_err(|e| e.to_string())?,
    );
    Ok(Deployment {
        tenancy: Tenancy::Shared { pool: runtime, signer, discovery, worker_identity: identity },
        shared,
        catalog_pool: control,
    })
    }
}

/// The VRL worker binary: `CONNECTOR_VRL_WORKER_EXE`, else the
/// `nano-connector` binary next to this one.
fn worker_exe() -> Result<std::path::PathBuf, String> {
    match env("CONNECTOR_VRL_WORKER_EXE") {
        Some(p) => Ok(p.into()),
        None => Ok(std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("nano-connector")),
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("feed") => return admin::run(&args[1..]).await,
        #[cfg(feature = "enterprise")]
        Some("catalog") => return mock_catalog::run(&args[1..]).await,
        #[cfg(not(feature = "enterprise"))]
        Some("catalog") => return Err("Hosted mock catalog tools require an enterprise build".into()),
        _ => {}
    }
    // Configuration errors first, before any connection is made.
    #[cfg(feature = "enterprise")]
    let shared = is_enterprise_shared()?;
    // Open builds still parse DEPLOYMENT_MODE so a shared layout is refused.
    #[cfg(not(feature = "enterprise"))]
    let shared = deployment_mode(
        std::env::var("DEPLOYMENT_MODE").ok().as_deref(),
        &std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).collect::<Vec<String>>(),
    )?;
    let policy = SandboxPolicy::from_env()?;
    if shared && policy.seccomp != Enforce::Require {
        return Err(format!(
            "enterprise_shared requires NANO_CONNECTOR_SECCOMP=require (or NANO_CONNECTOR_SANDBOX=strict); it is `{}`",
            policy.seccomp.as_str()
        ));
    }
    let max_per_tenant = env_num("CONNECTOR_MAX_PER_TENANT", 2usize)?.max(1);
    let pool_cfg = PoolConfig {
        max_workers: env_num("CONNECTOR_VRL_MAX_WORKERS", 32usize)?.max(1),
        max_per_tenant: env_num("CONNECTOR_VRL_MAX_PER_TENANT", max_per_tenant * 4)?,
        acquire_timeout: Duration::from_secs(env_num("CONNECTOR_VRL_ACQUIRE_SECS", 60u64)?),
    };
    if pool_cfg.max_per_tenant < max_per_tenant {
        return Err(format!(
            "CONNECTOR_VRL_MAX_PER_TENANT ({}) is below CONNECTOR_MAX_PER_TENANT ({max_per_tenant}): a tenant's runs would wait on each other for VRL workers",
            pool_cfg.max_per_tenant
        ));
    }
    let worker_as: u64 = env_num("CONNECTOR_VRL_WORKER_AS_BYTES", 1u64 << 30)?;
    if worker_as < 64 << 20 {
        return Err("CONNECTOR_VRL_WORKER_AS_BYTES must be at least 64 MiB".into());
    }
    check_vrl_memory(cgroup_memory_limit(), pool_cfg.max_workers, worker_as, shared)?;
    let ingest_suffix = env("CONNECTOR_INGEST_HOST_SUFFIX");
    let platform_deny = platform_egress_deny(
        env("CONNECTOR_EGRESS_DENY_CIDRS").as_deref(),
        env("CONNECTOR_EGRESS_DENY_HOSTS").as_deref(),
        ingest_suffix.as_deref(),
        shared,
    )?;
    let worker = worker_exe()?;
    let mut engine = EngineConfig::with_sandbox(worker, policy, pool_cfg);
    engine.worker_address_space = worker_as;
    engine.platform_deny = platform_deny;
    // NAN-3490 item 5: the platform pull broker for keyless Google DWD. A
    // missing or invalid setting never stops the runner: other feeds run,
    // and `google_dwd_broker` feeds fail with `google_dwd_broker_unconfigured`.
    engine.pull_broker = match nano_connector::pull_broker::PlatformBroker::from_env() {
        Ok(Some(b)) => match b.check_platform_deny(&engine.platform_deny) {
            Ok(()) => {
                tracing::info!(endpoint = %b.endpoint(), "platform pull broker configured for google_dwd_broker and entra_fic_broker feeds");
                Some(Arc::new(b))
            }
            Err(e) => {
                tracing::warn!(error = %e, "platform pull broker is unusable; google_dwd_broker feeds will fail as unconfigured");
                None
            }
        },
        Ok(None) => {
            tracing::info!("no platform pull broker configured; google_dwd_broker feeds will fail as unconfigured");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "platform pull broker configuration is invalid; google_dwd_broker feeds will fail as unconfigured");
            None
        }
    };
    // Operator-only loopback transport for dedicated lab validation. A spec
    // still passes the exact vendor host policy; shared mode refuses it.
    if let Some(mock_url) = env("CONNECTOR_TEST_MOCK_URL") {
        if shared || env("CONNECTOR_TEST_MODE").as_deref() != Some("1") {
            return Err("CONNECTOR_TEST_MOCK_URL requires dedicated CONNECTOR_TEST_MODE=1".into());
        }
        engine.transport = Some(Arc::new(nano_connector::loopback::LoopbackTransport::new(&mock_url)?));
        tracing::warn!("dedicated connector test mode: requests route to the operator's loopback mock");
    }
    // Boot self-test: one real worker under the configured policy. A host
    // that cannot provide a required layer fails the pod here.
    let report = engine.sandbox_self_test().await.map_err(|e| format!("VRL sandbox self-test failed: {e}"))?;
    if report.degraded() {
        tracing::warn!(seccomp = %report.seccomp, cgroup = %report.cgroup, "VRL sandbox self-test passed with DEGRADED isolation");
    } else {
        tracing::info!(seccomp = %report.seccomp, cgroup = %report.cgroup, "VRL sandbox self-test passed");
    }

    let max_concurrent: usize = env_num("CONNECTOR_MAX_CONCURRENT", 8)?;
    let Deployment { tenancy, .. } = connect((max_concurrent as u32 + 2).min(32)).await?;
    // Migrate first (350 / 9013180), then roll the runner: before the
    // migration the runner keeps HEC feeds going with identity disabled.
    let store = Arc::new(PgFeedStore::new(tenancy, EncryptionService::from_env()).probe_schema().await?);

    let node = env("HOSTNAME").unwrap_or_else(|| "nano-connector-runner".into());
    let mut cfg = RunnerConfig::new(node, engine);
    cfg.poll_interval = Duration::from_secs(env_num("CONNECTOR_POLL_INTERVAL_SECS", 30u64)?.max(5));
    cfg.max_concurrent = max_concurrent.max(1);
    cfg.max_per_tenant = max_per_tenant;
    cfg.default_max_run_secs = env_num("CONNECTOR_DEFAULT_MAX_RUN_SECS", 600u64)?;
    cfg.max_run_secs_ceiling = env_num("CONNECTOR_MAX_RUN_SECS", 3600u64)?;
    cfg.hec.require_ack = !shared;
    cfg.hec.allow_http = env("CONNECTOR_ALLOW_HTTP_INGEST").as_deref() == Some("1");
    cfg.hec.allowed_host_suffix = ingest_suffix;
    if shared && cfg.hec.allow_http {
        return Err("CONNECTOR_ALLOW_HTTP_INGEST is refused on enterprise_shared".into());
    }
    if shared && cfg.hec.allowed_host_suffix.is_none() {
        return Err("CONNECTOR_INGEST_HOST_SUFFIX is required on enterprise_shared".into());
    }
    cfg.identity_assignments = nanosiem_core::enrichment::lean_assignments::LeanAssignmentSource::from_env();
    cfg.identity_local = match local_identity(shared, &env) {
        Ok(local) => local,
        Err(e) if shared => return Err(e.into()),
        // Dedicated: HEC feeds keep running; identity feeds fail with
        // `identity_coordinator_unconfigured` and this line says why.
        Err(e) => {
            tracing::error!(error = %e, "the local identity directory path is misconfigured; identity feeds will fail as unconfigured");
            None
        }
    };
    if !store.identity_enabled() {
        cfg.identity_assignments = None;
        cfg.identity_local = None;
    }
    if let Some(local) = &cfg.identity_local {
        tracing::info!(lake_tenant = %local.lake_tenant, coordinator = %local.coordinator_url, vector = ?local.vector.host(),
            "identity feeds deliver through this deployment's Vector enrichment ingress and coordinator");
    } else if cfg.identity_assignments.is_none() {
        tracing::warn!("identity feeds are not configured on this runner (open core: CONNECTOR_IDENTITY_VECTOR_URL, CONNECTOR_IDENTITY_COORDINATOR_URL, CONNECTOR_IDENTITY_COORDINATOR_TOKEN_FILE, NANO_LAKE_TENANT_ID); identity feeds will fail as unconfigured");
    }
    cfg.identity.v2_fields = identity_v2_fields(env("CONNECTOR_IDENTITY_V2_FIELDS"), env("CONNECTOR_IDENTITY_EMIT_IS_ADMIN"));
    cfg.identity.spill_dir = env("CONNECTOR_IDENTITY_SPILL_DIR").map(Into::into);
    // Spill files of a runner that died mid-run (same pod restarted on its
    // emptyDir): nothing else owns them.
    let swept = nano_connector::identity::sweep_spill_dir(cfg.identity.spill_dir.as_deref());
    if swept > 0 {
        tracing::info!(files = swept, "removed stale identity spill files");
    }
    let runner = Runner::new(store, cfg);
    runner
        .run_until(async {
            let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        })
        .await;
    Ok(())
}

/// NAN-3767: the dedicated identity path from the environment. All of the
/// settings or none. Any of them on hosted-shared stops the runner; on a
/// dedicated deployment a partial or unusable set is logged at ERROR and
/// identity feeds fail with `identity_coordinator_unconfigured`.
fn local_identity(
    shared: bool,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Arc<nano_connector::identity::LocalIdentity>>, String> {
    let vector_url = env("CONNECTOR_IDENTITY_VECTOR_URL");
    let coordinator = env("CONNECTOR_IDENTITY_COORDINATOR_URL");
    let token_file = env("CONNECTOR_IDENTITY_COORDINATOR_TOKEN_FILE");
    let set = [&vector_url, &coordinator, &token_file].iter().filter(|v| v.is_some()).count();
    if set == 0 {
        return Ok(None);
    }
    if shared {
        return Err("CONNECTOR_IDENTITY_* local identity settings are refused on enterprise_shared (hosted uses the assignments map)".into());
    }
    let (Some(vector_url), Some(coordinator), Some(token_file)) = (vector_url, coordinator, token_file) else {
        return Err("CONNECTOR_IDENTITY_VECTOR_URL, CONNECTOR_IDENTITY_COORDINATOR_URL and CONNECTOR_IDENTITY_COORDINATOR_TOKEN_FILE go together".into());
    };
    let lake_tenant: uuid::Uuid = env("NANO_LAKE_TENANT_ID")
        .and_then(|t| t.trim().parse().ok())
        .filter(|t: &uuid::Uuid| !t.is_nil())
        .ok_or_else(|| "the local identity path needs NANO_LAKE_TENANT_ID (the lake tenant UUID)".to_string())?;
    let token = env("VECTOR_AUTH_TOKEN").unwrap_or_default();
    let timeout = Duration::from_secs(env("CONNECTOR_IDENTITY_TIMEOUT_SECS").and_then(|v| v.parse().ok()).unwrap_or(600).clamp(10, 3600));
    let vector = nano_connector::identity::VectorEnrichment::new(&vector_url, &token, timeout)?;
    let local = nano_connector::identity::LocalIdentity {
        claim_tenant: nanosiem_core::reports::COMPATIBILITY_TENANT_ID,
        lake_tenant,
        coordinator_url: coordinator,
        coordinator_token_file: token_file.into(),
        timeout: Duration::from_secs(60),
        vector: Arc::new(vector),
    };
    // Fail at boot on an unusable endpoint or token file, not per feed.
    local.client(local.claim_tenant)?;
    Ok(Some(Arc::new(local)))
}

/// `nano-connector-runner feed ...`: operator feed administration.
mod admin {
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    use nano_connector::service::admin::{NewFeed, hosted_ingest_url, plan_from_catalog};
    use nano_connector::service::pg::{PgFeedStore, read_catalog_entry};
    use nanosiem_core::crypto::EncryptionService;
    use serde_json::{Map, Value};
    use uuid::Uuid;

    use super::{connect, env};

    pub const USAGE: &str = "usage:
  nano-connector-runner feed create --tenant <uuid> --catalog <slug> --name <name>
        [--config-file <file.json>] [--credentials-file <file.json>] [--schedule <cron>]
        [--max-run-secs <10..3600>] [--disabled]
        (no backfill: a new feed starts at now − 5 min, NAN-3697)
        dedicated / open core only: --ingest-url <url> --ingest-token-file <file>
        (enterprise_shared derives the ingest URL from the tenant slug and
         CONNECTOR_INGEST_DOMAIN, and issues the token itself)
  nano-connector-runner feed list --tenant <uuid>
  nano-connector-runner feed enable|disable --tenant <uuid> --feed <uuid>
Secret files (credentials, ingest token) must not be group/world readable.";

    #[derive(Debug, Default, PartialEq)]
    pub struct Create {
        pub tenant: Uuid,
        pub catalog: String,
        pub name: String,
        pub config_file: Option<String>,
        pub credentials_file: Option<String>,
        pub schedule: Option<String>,
        pub max_run_secs: Option<i32>,
        pub disabled: bool,
        pub ingest_url: Option<String>,
        pub ingest_token_file: Option<String>,
    }

    #[derive(Debug, PartialEq)]
    pub enum Command {
        Create(Create),
        List { tenant: Uuid },
        SetEnabled { tenant: Uuid, feed: Uuid, enabled: bool },
    }

    pub fn parse(args: &[String]) -> Result<Command, String> {
        let (verb, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
        let mut flags: HashMap<&str, Option<&str>> = HashMap::new();
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            let key = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument `{a}`\n{USAGE}"))?;
            let value = if key == "disabled" { None } else { Some(it.next().ok_or_else(|| format!("--{key} needs a value"))?.as_str()) };
            if flags.insert(key, value).is_some() {
                return Err(format!("--{key} given twice"));
            }
        }
        let allowed: &[&str] = match verb.as_str() {
            "create" => &["tenant", "catalog", "name", "config-file", "credentials-file", "schedule", "max-run-secs", "disabled", "ingest-url", "ingest-token-file"],
            "list" => &["tenant"],
            "enable" | "disable" => &["tenant", "feed"],
            _ => return Err(USAGE.to_string()),
        };
        if let Some(k) = flags.keys().find(|k| !allowed.contains(k)) {
            return Err(format!("--{k} is not a `feed {verb}` option"));
        }
        let take = |k: &str| flags.get(k).copied().flatten().map(str::to_string);
        let need = |k: &str| take(k).ok_or_else(|| format!("--{k} is required"));
        let uuid = |k: &str| need(k).and_then(|v| Uuid::parse_str(&v).map_err(|_| format!("--{k} must be a UUID")));
        let tenant = uuid("tenant")?;
        Ok(match verb.as_str() {
            "list" => Command::List { tenant },
            "enable" | "disable" => Command::SetEnabled { tenant, feed: uuid("feed")?, enabled: verb == "enable" },
            _ => Command::Create(Create {
                tenant,
                catalog: need("catalog")?,
                name: need("name")?,
                config_file: take("config-file"),
                credentials_file: take("credentials-file"),
                schedule: take("schedule"),
                max_run_secs: take("max-run-secs").map(|v| v.parse().map_err(|_| "--max-run-secs must be a number".to_string())).transpose()?,
                disabled: flags.contains_key("disabled"),
                ingest_url: take("ingest-url"),
                ingest_token_file: take("ingest-token-file"),
            }),
        })
    }

    fn read_secret_file(path: &str) -> Result<String, String> {
        let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!("{path} is readable by group/others; chmod 600 it"));
        }
        std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
    }

    fn json_object(path: &str, text: &str) -> Result<Map<String, Value>, String> {
        match serde_json::from_str::<Value>(text).map_err(|e| format!("{path}: {e}"))? {
            Value::Object(m) => Ok(m),
            _ => Err(format!("{path} must hold a JSON object")),
        }
    }

    pub async fn run(args: &[String]) -> Result<(), String> {
        let command = parse(args)?;
        let deployment = connect(2).await?;
        let shared = deployment.shared;
        let catalog_pool = deployment.catalog_pool.clone();
        let store = PgFeedStore::new(deployment.tenancy, EncryptionService::from_env()).probe_schema().await?;
        let out = match command {
            Command::List { tenant } => {
                let slot = store.slot_for(tenant).await.map_err(|e| e.to_string())?;
                serde_json::to_value(store.list_feeds(&slot).await.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?
            }
            Command::SetEnabled { tenant, feed, enabled } => {
                let slot = store.slot_for(tenant).await.map_err(|e| e.to_string())?;
                store.set_enabled(&slot, feed, enabled).await.map_err(|e| e.to_string())?;
                serde_json::json!({ "feed_id": feed, "enabled": enabled })
            }
            Command::Create(c) => {
                let slot = store.slot_for(c.tenant).await.map_err(|e| e.to_string())?;
                let (catalog_id, config) = read_catalog_entry(&catalog_pool, &c.catalog).await.map_err(|e| e.to_string())?;
                let plan = plan_from_catalog(catalog_id, &c.catalog, &config).map_err(|e| e.to_string())?;
                // The catalog spec's VRL compiles only in a sandboxed worker.
                nano_connector::preview::validate(super::worker_exe()?, &plan.spec)
                    .await
                    .map_err(|e| format!("catalog `{}`: {e}", c.catalog))?;
                let feed_config = match &c.config_file {
                    Some(p) => json_object(p, &std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?)?,
                    None => Map::new(),
                };
                let vendor_credentials = match &c.credentials_file {
                    Some(p) => json_object(p, &read_secret_file(p)?)?
                        .into_iter()
                        .map(|(k, v)| match v {
                            Value::String(s) => Ok((k, s)),
                            _ => Err(format!("{p}: credential `{k}` must be a string")),
                        })
                        .collect::<Result<HashMap<_, _>, _>>()?,
                    None => HashMap::new(),
                };
                let identity = plan.spec.kind == nano_connector::spec::Kind::Identity;
                if identity && (c.ingest_url.is_some() || c.ingest_token_file.is_some()) {
                    return Err("identity feeds write to the tenant's identity directory; drop --ingest-url / --ingest-token-file".into());
                }
                let (ingest_url, token) = if identity {
                    (String::new(), None)
                } else if shared {
                    if c.ingest_url.is_some() || c.ingest_token_file.is_some() {
                        return Err("on enterprise_shared the ingest URL is derived from the tenant and the token is issued; drop --ingest-url / --ingest-token-file".into());
                    }
                    let domain = env("CONNECTOR_INGEST_DOMAIN").ok_or("CONNECTOR_INGEST_DOMAIN is required on enterprise_shared")?;
                    let slug = store.tenant_slug(&slot).await.map_err(|e| e.to_string())?;
                    let suffix = env("CONNECTOR_INGEST_HOST_SUFFIX").ok_or("CONNECTOR_INGEST_HOST_SUFFIX is required on enterprise_shared")?;
                    (hosted_ingest_url(&slug, &domain, Some(&suffix)).map_err(|e| e.to_string())?, None)
                } else {
                    let url = c.ingest_url.clone().ok_or("--ingest-url is required outside enterprise_shared")?;
                    let path = c.ingest_token_file.clone().ok_or("--ingest-token-file is required outside enterprise_shared")?;
                    (url, Some(read_secret_file(&path)?.trim().to_string()))
                };
                let feed = NewFeed {
                    name: c.name.clone(),
                    config: feed_config,
                    vendor_credentials,
                    schedule: c.schedule.clone(),
                    max_run_secs: c.max_run_secs,
                    enabled: !c.disabled,
                };
                let id = store
                    .create_feed(&slot, &plan, &feed, &ingest_url, token.as_deref())
                    .await
                    .map_err(|e| e.to_string())?;
                serde_json::json!({
                    "feed_id": id, "tenant_id": c.tenant, "connector": plan.connector, "source_slug": plan.source_slug,
                    "spec_sha256": plan.spec_sha256, "ingest_url": ingest_url,
                    "credential": if identity { "not required" } else if token.is_some() { "ready" } else { "issued by the runner" },
                })
            }
        };
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(s: &str) -> Vec<String> {
            s.split_whitespace().map(str::to_string).collect()
        }

        #[test]
        fn parses_the_verbs() {
            let t = "11111111-1111-4111-8111-111111111111";
            let f = "22222222-2222-4222-8222-222222222222";
            assert_eq!(parse(&args(&format!("list --tenant {t}"))).unwrap(), Command::List { tenant: t.parse().unwrap() });
            assert_eq!(
                parse(&args(&format!("disable --tenant {t} --feed {f}"))).unwrap(),
                Command::SetEnabled { tenant: t.parse().unwrap(), feed: f.parse().unwrap(), enabled: false }
            );
            let Command::Create(c) = parse(&args(&format!(
                "create --tenant {t} --catalog okta_system_log --name Okta --credentials-file /x.json --disabled"
            )))
            .unwrap() else {
                panic!()
            };
            assert_eq!((c.catalog.as_str(), c.name.as_str(), c.disabled), ("okta_system_log", "Okta", true));
            // NAN-3697: there is no backfill option.
            assert!(parse(&args(&format!("create --tenant {t} --catalog c --name n --backfill-from 2026-10-01T00:00:00Z"))).is_err());
        }

        #[test]
        fn refuses_bad_input() {
            let t = "11111111-1111-4111-8111-111111111111";
            assert!(parse(&args("list")).is_err());
            assert!(parse(&args("list --tenant nope")).is_err());
            assert!(parse(&args(&format!("list --tenant {t} --feed {t}"))).is_err(), "option of another verb");
            assert!(parse(&args(&format!("create --tenant {t} --name x"))).is_err(), "catalog required");
            assert!(parse(&args(&format!("list --tenant {t} --tenant {t}"))).is_err());
            assert!(parse(&args(&format!("create --tenant {t} --catalog c --name n --max-run-secs x"))).is_err());
            assert!(parse(&args("drop")).is_err());
        }

        #[test]
        fn secret_files_must_be_private() {
            let dir = std::env::temp_dir().join(format!("ncr-{}", Uuid::new_v4()));
            std::fs::create_dir(&dir).unwrap();
            let p = dir.join("creds.json");
            std::fs::write(&p, "{}").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_secret_file(p.to_str().unwrap()).is_err());
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_secret_file(p.to_str().unwrap()).unwrap(), "{}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// `nano-connector-runner catalog put-mock|remove-mock`: the live-validation
/// catalog entry (NAN-3490 item 5), as a coded, audited operator action
/// instead of hand SQL. Only `_mock` slugs whose spec reaches exactly one
/// literal `<worker>.<account>.workers.dev` host on the given account are
/// accepted; remove deletes only rows this command created, and refuses
/// while an integration instance or an enabled feed references the row
/// unless `--force-with-instances`. Every attempt, refused ones included,
/// writes one audit line.
#[cfg(feature = "enterprise")]
mod mock_catalog {
    use nano_connector::service::admin::{check_mock_account, check_mock_slug, plan_mock_catalog};
    use nano_connector::service::pg::{catalog_references, mock_catalog_id, put_mock_catalog_entry, remove_mock_catalog_entry};
    use serde_json::{Value, json};

    use super::connect;

    pub const USAGE: &str = "usage:
  nano-connector-runner catalog put-mock --slug <name_mock> --config-file <catalog.json> --account <cf-subdomain> --operator <who>
  nano-connector-runner catalog remove-mock --slug <name_mock> --operator <who> [--force-with-instances]
<catalog.json> is the marketplace_catalog config (runtime, connector_spec,
connector_spec_sha256), e.g. from nano-integrations testing/okta-mock-public/catalog.ts.
<cf-subdomain> is the Cloudflare workers.dev account label the mock Worker runs on
(<worker>.<cf-subdomain>.workers.dev); the spec's one allow host must sit on it.
remove-mock refuses while an integration instance or an enabled feed references
the entry; --force-with-instances removes it anyway (instances cascade).";

    #[derive(Debug, PartialEq)]
    pub enum Command {
        Put { slug: String, config_file: String, account: String, operator: String },
        Remove { slug: String, operator: String, force: bool },
    }

    pub fn parse(args: &[String]) -> Result<Command, String> {
        let (verb, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
        let allowed: &[&str] = match verb.as_str() {
            "put-mock" => &["slug", "config-file", "account", "operator"],
            "remove-mock" => &["slug", "operator", "force-with-instances"],
            _ => return Err(USAGE.to_string()),
        };
        let mut flags = std::collections::HashMap::new();
        let mut force = false;
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            let key = a.strip_prefix("--").ok_or_else(|| format!("unexpected argument `{a}`\n{USAGE}"))?;
            if !allowed.contains(&key) {
                return Err(format!("--{key} is not a `catalog {verb}` option"));
            }
            if key == "force-with-instances" {
                if std::mem::replace(&mut force, true) {
                    return Err(format!("--{key} given twice"));
                }
                continue;
            }
            let v = it.next().ok_or_else(|| format!("--{key} needs a value"))?;
            if flags.insert(key, v.clone()).is_some() {
                return Err(format!("--{key} given twice"));
            }
        }
        let mut need = |k: &str| flags.remove(k).ok_or_else(|| format!("--{k} is required"));
        let slug = need("slug")?;
        check_mock_slug(&slug).map_err(|e| e.to_string())?;
        let operator = need("operator")?;
        if operator.trim() != operator || operator.is_empty() || operator.chars().count() > 100 || operator.chars().any(char::is_control) {
            return Err("--operator must be 1-100 characters, trimmed, no control characters".into());
        }
        Ok(if verb == "put-mock" {
            let config_file = need("config-file")?;
            let account = need("account")?;
            check_mock_account(&account).map_err(|e| e.to_string())?;
            Command::Put { slug, config_file, account, operator }
        } else {
            Command::Remove { slug, operator, force }
        })
    }

    /// The audit fields for an attempt the parser refused (nano-red M5):
    /// the verb and whatever slug / operator / account were given, raw but
    /// length-capped. No argument is a secret (the config is a file path).
    pub fn refusal_fields(args: &[String], error: &str) -> Value {
        let cap = |v: &str| v.chars().take(120).collect::<String>();
        let given = |k: &str| {
            args.iter().position(|a| a == &format!("--{k}")).and_then(|i| args.get(i + 1)).map(|v| cap(v))
        };
        json!({
            "event": "connector_catalog_mock_refused",
            "verb": args.first().map(|v| cap(v)),
            "slug": given("slug"),
            "operator": given("operator"),
            "account": given("account"),
            "ok": false,
            "error": cap(error.lines().next().unwrap_or_default()),
        })
    }

    fn audit(ok: bool, fields: Value) {
        if ok {
            tracing::info!(target: "nano_connector::audit", catalog = %fields, "connector catalog mock");
        } else {
            tracing::warn!(target: "nano_connector::audit", catalog = %fields, "connector catalog mock");
        }
    }

    pub async fn run(args: &[String]) -> Result<(), String> {
        let command = match parse(args) {
            Ok(command) => command,
            Err(e) => {
                audit(false, refusal_fields(args, &e));
                return Err(e);
            }
        };
        let (event, slug, operator) = match &command {
            Command::Put { slug, operator, .. } => ("connector_catalog_mock_put", slug.clone(), operator.clone()),
            Command::Remove { slug, operator, .. } => ("connector_catalog_mock_removed", slug.clone(), operator.clone()),
        };
        let result = async {
            match command {
                Command::Put { slug, config_file, account, .. } => {
                    let text = std::fs::read_to_string(&config_file).map_err(|e| format!("{config_file}: {e}"))?;
                    let config: Value = serde_json::from_str(&text).map_err(|e| format!("{config_file}: {e}"))?;
                    let plan = plan_mock_catalog(&slug, &config, &account).map_err(|e| e.to_string())?;
                    // The spec's VRL compiles only in a sandboxed worker.
                    nano_connector::preview::validate(super::worker_exe()?, &plan.spec)
                        .await
                        .map_err(|e| format!("catalog `{slug}`: {e}"))?;
                    let deployment = connect(1).await?;
                    let id = put_mock_catalog_entry(&deployment.catalog_pool, &slug, &config).await.map_err(|e| e.to_string())?;
                    let host = plan.spec.allow.first().and_then(|r| r.host.clone()).unwrap_or_default();
                    Ok(json!({ "catalog_id": id, "slug": slug, "account": account, "spec_sha256": plan.spec_sha256, "host": host }))
                }
                Command::Remove { slug, force, .. } => {
                    let deployment = connect(1).await?;
                    let id = mock_catalog_id(&deployment.catalog_pool, &slug)
                        .await
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| format!("catalog entry `{slug}` not found"))?;
                    let refs = catalog_references(&deployment.tenancy, id).await.map_err(|e| e.to_string())?;
                    if refs.blocks_removal() && !force {
                        return Err(format!(
                            "catalog entry `{slug}` is still referenced ({} enabled feed(s), {} integration instance(s) across {} tenant(s)); disable the feeds first, or pass --force-with-instances",
                            refs.enabled_feeds, refs.integration_instances, refs.tenants_checked
                        ));
                    }
                    let removed = remove_mock_catalog_entry(&deployment.catalog_pool, &slug).await.map_err(|e| e.to_string())?;
                    Ok(json!({ "catalog_id": removed, "slug": slug, "removed": true, "forced": force && refs.blocks_removal(), "references": refs }))
                }
            }
        }
        .await;
        match result {
            Ok(out) => {
                let mut fields = json!({ "event": event, "operator": operator, "ok": true });
                if let (Some(f), Some(o)) = (fields.as_object_mut(), out.as_object()) {
                    f.extend(o.clone());
                }
                audit(true, fields);
                println!("{out}");
                Ok(())
            }
            Err(e) => {
                audit(false, json!({ "event": event, "operator": operator, "slug": slug, "ok": false, "error": e }));
                Err(e)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(v: &[&str]) -> Vec<String> {
            v.iter().map(|s| s.to_string()).collect()
        }

        #[test]
        fn parses_put_and_remove() {
            assert_eq!(
                parse(&args(&["put-mock", "--slug", "okta_system_log_mock", "--config-file", "c.json", "--account", "acct", "--operator", "dan"])).unwrap(),
                Command::Put { slug: "okta_system_log_mock".into(), config_file: "c.json".into(), account: "acct".into(), operator: "dan".into() }
            );
            assert_eq!(
                parse(&args(&["remove-mock", "--slug", "okta_system_log_mock", "--operator", "dan"])).unwrap(),
                Command::Remove { slug: "okta_system_log_mock".into(), operator: "dan".into(), force: false }
            );
            assert_eq!(
                parse(&args(&["remove-mock", "--force-with-instances", "--slug", "okta_system_log_mock", "--operator", "dan"])).unwrap(),
                Command::Remove { slug: "okta_system_log_mock".into(), operator: "dan".into(), force: true }
            );
        }

        #[test]
        fn refuses_non_mock_slugs_and_bad_flags() {
            for a in [
                vec!["remove-mock", "--slug", "okta_system_log", "--operator", "dan"],
                vec!["put-mock", "--slug", "okta_system_log", "--config-file", "c.json", "--account", "acct", "--operator", "dan"],
                vec!["remove-mock", "--slug", "okta_system_log_mock"],
                vec!["remove-mock", "--slug", "okta_system_log_mock", "--operator", " dan"],
                vec!["remove-mock", "--slug", "okta_system_log_mock", "--operator", "dan", "--config-file", "c.json"],
                vec!["remove-mock", "--slug", "okta_system_log_mock", "--operator", "dan", "--force-with-instances", "--force-with-instances"],
                vec!["remove-mock", "--slug", "okta_system_log_mock", "--operator", "dan", "--account", "acct"],
                vec!["put-mock", "--slug", "okta_system_log_mock", "--operator", "dan"],
                vec!["put-mock", "--slug", "okta_system_log_mock", "--config-file", "c.json", "--operator", "dan"],
                vec!["put-mock", "--slug", "okta_system_log_mock", "--config-file", "c.json", "--account", "Acct.workers", "--operator", "dan"],
                vec!["put-mock", "--slug", "okta_system_log_mock", "--config-file", "c.json", "--account", "acct", "--operator", "dan", "--force-with-instances"],
                vec!["delete", "--slug", "okta_system_log_mock"],
                vec![],
            ] {
                assert!(parse(&args(&a)).is_err(), "{a:?}");
            }
        }

        #[test]
        fn refusals_are_audited_with_what_was_given() {
            let a = args(&["put-mock", "--slug", "okta_system_log", "--operator", "dan", "--account", "acct"]);
            let e = parse(&a).unwrap_err();
            let f = refusal_fields(&a, &e);
            assert_eq!(f["event"], "connector_catalog_mock_refused");
            assert_eq!((f["verb"].as_str(), f["slug"].as_str(), f["operator"].as_str(), f["account"].as_str()), (Some("put-mock"), Some("okta_system_log"), Some("dan"), Some("acct")));
            assert_eq!(f["ok"], false);
            assert!(f["error"].as_str().unwrap().contains("not a mock catalog slug"), "{f}");
            // Nothing given, a multi-line usage error, and an overlong value.
            let f = refusal_fields(&[], USAGE);
            assert_eq!((f["verb"].clone(), f["slug"].clone()), (Value::Null, Value::Null));
            assert_eq!(f["error"], "usage:");
            let long = "x".repeat(500);
            let f = refusal_fields(&args(&["remove-mock", "--slug", &long]), "e");
            assert_eq!(f["slug"].as_str().unwrap().len(), 120);
        }
    }
}

#[cfg(test)]
mod deployment_mode_tests {
    use super::{check_vrl_memory, deployment_mode};

    const MIB: u64 = 1 << 20;

    #[test]
    fn vrl_workers_must_fit_the_pod_memory_limit() {
        // 256 MiB AS + 192 MiB call I/O = 448 MiB per worker, + 256 MiB reserve.
        assert!(check_vrl_memory(Some(2047 * MIB), 4, 256 * MIB, true).is_err());
        assert!(check_vrl_memory(Some(2048 * MIB), 4, 256 * MIB, true).is_ok());
        assert!(check_vrl_memory(Some(2048 * MIB), 3, 256 * MIB, true).is_ok());
        assert!(check_vrl_memory(Some(2048 * MIB), 4, 1 << 30, false).is_err(), "dedicated with a limit is checked too");
        let e = check_vrl_memory(Some(1024 * MIB), 32, 1 << 30, true).unwrap_err();
        assert!(e.contains("at most 0 workers fit"), "{e}");
        // No limit: refused on shared, allowed on dedicated / open core.
        assert!(check_vrl_memory(None, 32, 1 << 30, true).unwrap_err().contains("memory limit"));
        assert!(check_vrl_memory(None, 32, 1 << 30, false).is_ok());
    }

    fn vars(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_exact_known_modes_pass() {
        assert_eq!(deployment_mode(Some("enterprise_shared"), &vars(&["NANOSIEM_SHARED_RLS_KEY_ID"])), Ok(true));
        for m in [None, Some(""), Some("managed"), Some("selfhosted"), Some("self-hosted")] {
            assert_eq!(deployment_mode(m, &vars(&["DATABASE_URL", "PATH"])), Ok(false), "{m:?}");
        }
        for m in ["enterprise-shared", "Enterprise_Shared", " enterprise_shared", "enterprise_shared ", "shared", "demo", " ", "dedicated"] {
            let e = deployment_mode(Some(m), &[]).unwrap_err();
            assert!(e.contains("invalid DEPLOYMENT_MODE"), "{m:?}: {e}");
        }
    }

    #[test]
    fn a_dedicated_mode_refuses_the_shared_layout() {
        for v in ["NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL", "NANOSIEM_SHARED_RLS_CONTEXT_KEY_HEX", "NANOSIEM_SHARED_DETECTION_WORKER_IDENTITY"] {
            for m in [None, Some("managed"), Some("")] {
                let e = deployment_mode(m, &vars(&["DATABASE_URL", v])).unwrap_err();
                assert!(e.contains("enterprise_shared database layout is present") && e.contains(v), "{m:?} {v}: {e}");
            }
        }
    }
}
