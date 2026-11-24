// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nano-connector-runner`: the pull-feed runner service (NAN-4914 phase 4).
//!
//! Its own process / container, not a task inside nano-jobs: the VRL worker
//! sandbox re-execs this binary (`vrl-worker`) with rlimits, seccomp and an
//! optional cgroup, so the runner wants its own process tree without jobs'
//! secrets (AI keys). It needs PostgreSQL, the credential key and the local
//! Vector HEC endpoint; identity feeds (`kind: identity`, G22) also need the
//! ClickHouse user directory, so `CLICKHOUSE_URL` is optional and only
//! identity feeds fail without it. Lease fencing makes N replicas safe without
//! leader election.
//!
//! ```text
//!   nano-connector-runner              serve (default)
//!   nano-connector-runner serve
//!   nano-connector-runner vrl-worker   internal: VRL sandbox child
//! ```
//!
//! Environment:
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `DATABASE_URL` | required | PostgreSQL (migrations 293 + 298 applied) |
//! | `NANOSIEM_ENCRYPTION_KEY` (or `_FILE`) | required | the API's credential key or key ring JSON (opens bound credentials; keep it in step with the API during a rotation) |
//! | `CONNECTOR_HEC_URL` | `http://vector:8088` | Vector HEC base URL |
//! | `NANO_PLATFORM_INGEST_TOKEN` (or `CONNECTOR_HEC_TOKEN[_FILE]`) | required | the platform multiplex ingest credential; the install token is refused |
//! | `CONNECTOR_ALLOW_HTTP_INGEST` | `1` | allow `http://` to a loopback / private / in-cluster host |
//! | `CONNECTOR_POLL_INTERVAL_SECS` | 30 | scheduler tick |
//! | `CONNECTOR_MAX_CONCURRENT` | 4 | runs in flight |
//! | `CONNECTOR_DEFAULT_MAX_RUN_SECS` / `CONNECTOR_MAX_RUN_SECS` | 600 / 3600 | run wall clock |
//! | `CONNECTOR_VRL_MAX_WORKERS` / `CONNECTOR_VRL_WORKER_AS_BYTES` | 8 / 256 MiB | VRL worker pool |
//! | `CONNECTOR_EGRESS_DENY_CIDRS` / `CONNECTOR_EGRESS_DENY_HOSTS` | none | extra vendor egress deny |
//! | `CONNECTOR_EGRESS_PROXY_URL` | none | operator egress proxy for vendor calls |
//! | `CONNECTOR_HEALTH_FILE` | none | touched after every tick (container health check) |
//! | `CLICKHOUSE_URL` (+ `CLICKHOUSE_USER` / `CLICKHOUSE_PASSWORD` / `CLICKHOUSE_DATABASE`) | none | identity feeds: the `user_registry` directory (unset: identity feeds fail, collectors run) |
//! | `CONNECTOR_TEST_MODE=1` + `CONNECTOR_TEST_MOCK_URL` | off | lab only: route vendor requests to a loopback mock |
//! | `NANO_CONNECTOR_SECCOMP` / `NANO_CONNECTOR_CGROUP` | require | sandbox policy (`prefer` on hosts without them) |

use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use nano_connector::engine::EngineConfig;
use nano_connector::sandbox::SandboxPolicy;
use nano_connector::service::pg::PgFeedStore;
use nano_connector::service::runner::platform_egress_deny;
use nano_connector::service::{Runner, RunnerConfig, Secret, StaticIngest};
use nano_connector::vrl_exec::PoolConfig;
use nanosiem_core::crypto::EncryptionService;
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

/// PostgreSQL pool size and the feed concurrency it supports (NAN-5822).
///
/// Each running feed holds one connection and the runner needs two more for
/// claims and bookkeeping, capped at 32. `PG_MAX_CONNECTIONS` (sized from the
/// PostgreSQL memory budget) caps the pool too, and the concurrency comes
/// down with it so runs never wait on connections the cap took away.
fn connector_pool_size(requested_concurrent: usize, pg_cap: Option<u32>) -> (u32, usize) {
    let wanted = (requested_concurrent.max(1) as u32 + 2).min(32);
    let pool = match pg_cap {
        Some(cap) => wanted.min(cap.max(3)),
        None => wanted,
    };
    (pool, requested_concurrent.max(1).min(pool as usize - 2))
}

fn main() -> ExitCode {
    // NAN-5214: one rustls provider for PostgreSQL TLS (see tls_provider).
    nanosiem_core::db::tls_provider::install_default_crypto_provider();
    // Before anything else: the host process holds credentials, so it must
    // not be dumpable or ptrace-able by a same-uid worker that escaped a
    // degraded sandbox, nor write a core file.
    if let Err(e) = nano_connector::sandbox::harden_host_process() {
        eprintln!("nano-connector-runner: refusing to start: host process hardening failed: {e}");
        return ExitCode::from(3);
    }
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("vrl-worker") => {
            return match nano_connector::vrl_exec::worker_main(&args[2..]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        None | Some("serve") => {}
        Some(other) => {
            eprintln!("usage: nano-connector-runner [serve | vrl-worker]   (unknown: {other})");
            return ExitCode::from(2);
        }
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .json()
        .init();
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("nano-connector-runner: tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(serve()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "nano-connector-runner refused to start");
            eprintln!("nano-connector-runner: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The API's credential cipher: the same key ring loader as the API and jobs
/// (plain key, ring JSON, or `NANOSIEM_ENCRYPTION_KEY_FILE`; NAN-4933), so the
/// runner opens credentials re-wrapped onto a rotated key. Refused (not
/// panicking) when the key is missing or invalid.
fn credential_cipher() -> Result<EncryptionService, String> {
    EncryptionService::try_from_env().map_err(|error| error.to_string())
}

/// The runner's ingest token: the platform multiplex credential, never the
/// install token (see `service::ingest`).
fn ingest_token() -> Result<Secret, String> {
    nano_connector::service::ingest::resolve_ingest_token(&env, &|path| {
        std::fs::read_to_string(path).map_err(|e| e.to_string())
    })
}

async fn serve() -> Result<(), String> {
    let cipher = credential_cipher()?;
    let token = ingest_token()?;
    let database_url = env("DATABASE_URL").ok_or("DATABASE_URL is required")?;

    let policy = SandboxPolicy::from_env()?;
    let pool_cfg = PoolConfig {
        max_workers: env_num("CONNECTOR_VRL_MAX_WORKERS", 8usize)?.max(1),
        max_per_tenant: env_num("CONNECTOR_VRL_MAX_PER_FEED", 4usize)?.max(1),
        acquire_timeout: Duration::from_secs(env_num("CONNECTOR_VRL_ACQUIRE_SECS", 60u64)?),
    };
    let worker_as: u64 = env_num("CONNECTOR_VRL_WORKER_AS_BYTES", 256u64 << 20)?;
    if worker_as < 64 << 20 {
        return Err("CONNECTOR_VRL_WORKER_AS_BYTES must be at least 64 MiB".into());
    }
    let worker = match env("CONNECTOR_VRL_WORKER_EXE") {
        Some(p) => p.into(),
        None => std::env::current_exe().map_err(|e| e.to_string())?,
    };
    let mut engine = EngineConfig::with_sandbox(worker, policy, pool_cfg);
    nano_connector::egress::configure_from_env(&mut engine.broker, nano_connector::egress::CONNECTOR_PROXY_ENV)
        .map_err(|e| format!("{}: {e}", nano_connector::egress::CONNECTOR_PROXY_ENV))?;
    engine.worker_address_space = worker_as;
    engine.platform_deny =
        platform_egress_deny(env("CONNECTOR_EGRESS_DENY_CIDRS").as_deref(), env("CONNECTOR_EGRESS_DENY_HOSTS").as_deref())?;
    // Operator-only loopback transport for lab validation with recorded
    // vendor responses. A spec still passes its exact vendor host policy.
    if let Some(mock_url) = env("CONNECTOR_TEST_MOCK_URL") {
        if env("CONNECTOR_TEST_MODE").as_deref() != Some("1") {
            return Err("CONNECTOR_TEST_MOCK_URL requires CONNECTOR_TEST_MODE=1".into());
        }
        engine.transport = Some(Arc::new(nano_connector::loopback::LoopbackTransport::new(&mock_url)?));
        tracing::warn!("connector test mode: vendor requests route to the operator's loopback mock");
    }
    // Boot self-test: one real worker under the configured policy. A host
    // that cannot provide a required layer fails here.
    let report = engine.sandbox_self_test().await.map_err(|e| format!("VRL sandbox self-test failed: {e}"))?;
    if report.degraded() {
        tracing::warn!(seccomp = %report.seccomp, cgroup = %report.cgroup, "VRL sandbox self-test passed with DEGRADED isolation");
    } else {
        tracing::info!(seccomp = %report.seccomp, cgroup = %report.cgroup, "VRL sandbox self-test passed");
    }

    let requested_concurrent: usize = env_num("CONNECTOR_MAX_CONCURRENT", 4usize)?.max(1);
    let pg_cap: Option<u32> = env("PG_MAX_CONNECTIONS")
        .map(|v| v.trim().parse::<u32>().map_err(|_| "PG_MAX_CONNECTIONS is invalid".to_string()))
        .transpose()?;
    let (pool_size, max_concurrent) = connector_pool_size(requested_concurrent, pg_cap);
    if max_concurrent < requested_concurrent {
        tracing::warn!(
            requested = requested_concurrent,
            max_concurrent,
            pool_size,
            "CONNECTOR_MAX_CONCURRENT exceeds what PG_MAX_CONNECTIONS allows; running fewer feeds at once"
        );
    }
    let pool = PgPoolOptions::new()
        .min_connections(0)
        .max_connections(pool_size)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&database_url)
        .await
        .map_err(|e| format!("database: {e}"))?;
    let store = Arc::new(PgFeedStore::new(pool.clone(), cipher));

    let ingest = Arc::new(StaticIngest {
        url: env("CONNECTOR_HEC_URL").unwrap_or_else(|| "http://vector:8088".into()),
        token,
    });
    let node = env("HOSTNAME").unwrap_or_else(|| "nano-connector-runner".into());
    let mut cfg = RunnerConfig::new(node, engine, ingest);
    cfg.poll_interval = Duration::from_secs(env_num("CONNECTOR_POLL_INTERVAL_SECS", 30u64)?.max(1));
    cfg.max_concurrent = max_concurrent;
    cfg.default_max_run_secs = env_num("CONNECTOR_DEFAULT_MAX_RUN_SECS", 600u64)?;
    cfg.max_run_secs_ceiling = env_num("CONNECTOR_MAX_RUN_SECS", 3600u64)?;
    cfg.hec.require_ack = env("CONNECTOR_HEC_REQUIRE_ACK").as_deref() != Some("0");
    cfg.hec.allow_http = env("CONNECTOR_ALLOW_HTTP_INGEST").as_deref() != Some("0");
    cfg.health_file = env("CONNECTOR_HEALTH_FILE").map(Into::into);
    // G22: identity feeds write the ClickHouse user directory.
    match env("CLICKHOUSE_URL") {
        Some(url) => {
            let ch = clickhouse::Client::default()
                .with_url(url)
                .with_user(env("CLICKHOUSE_USER").unwrap_or_else(|| "nanosiem".into()))
                .with_password(env("CLICKHOUSE_PASSWORD").unwrap_or_default())
                .with_database(env("CLICKHOUSE_DATABASE").unwrap_or_else(|| "nanosiem".into()));
            cfg.identity = Some(Arc::new(nano_connector::service::directory::ClickHouseDirectories::new(pool.clone(), ch)));
        }
        None => tracing::info!("CLICKHOUSE_URL is not set: identity feeds are refused (collectors run)"),
    }
    if !cfg.hec.require_ack {
        tracing::warn!("CONNECTOR_HEC_REQUIRE_ACK=0: cursors advance on HEC 200, before Vector delivered the events");
    }

    let runner = Runner::new(store, cfg);
    let shutdown = async {
        #[cfg(unix)]
        {
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
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    runner.run_until(shutdown).await;
    Ok(())
}

#[cfg(test)]
mod pool_size_tests {
    use super::connector_pool_size;

    #[test]
    fn pg_max_connections_caps_the_pool_and_the_concurrency() {
        // No cap: concurrency + 2, at most 32.
        assert_eq!(connector_pool_size(2, None), (4, 2));
        assert_eq!(connector_pool_size(64, None), (32, 30));
        // The sized cap wins over a raised CONNECTOR_MAX_CONCURRENT.
        assert_eq!(connector_pool_size(30, Some(4)), (4, 2));
        assert_eq!(connector_pool_size(2, Some(20)), (4, 2));
        // A cap too small for one run still leaves one run and its two extras.
        assert_eq!(connector_pool_size(8, Some(1)), (3, 1));
        assert_eq!(connector_pool_size(0, Some(2)), (3, 1));
    }
}
