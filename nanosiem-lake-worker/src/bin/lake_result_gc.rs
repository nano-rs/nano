// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable query-result garbage collector.
//!
//! `lake_job_runner` publishes result artifacts under
//! `{result_root}/tenant-{sha256}/job-{id}/attempt-{n}/` and the Redis job
//! records expire on a TTL, so without this coordinator the object store is
//! write-only: unreferenceable Parquet accrues forever. Each pass deletes only
//! artifacts whose job holds NO remaining reference (record, admission index,
//! durable queue, or lease) AND whose newest object is older than the
//! operator's results-retention window, then reconciles orphaned members out
//! of the Redis job index sets. If the metadata service is unreachable the
//! pass deletes nothing.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
#[cfg(feature = "enterprise")]
use nanosiem_core::enterprise_shared_retention_policy::EnterpriseSharedQueryRetentionAuthority;
use nanosiem_core::search::{RedisJobStore, SearchTenantScope};
use nanosiem_lake_worker::job::result_gc::{DEFAULT_RESULT_RETENTION_DAYS, sweep_result_root};
use nanosiem_lake_worker::startup_bounds::BoundChecks;
use uuid::Uuid;

#[derive(Debug, PartialEq)]
struct Arguments {
    redis_url: String,
    result_root: String,
    tenant_id: String,
    tenant_scope: SearchTenantScope,
    results_retention: Duration,
    index_reconcile_limit: usize,
    poll: Duration,
    once: bool,
}

impl Arguments {
    fn parse(values: impl Iterator<Item = String>) -> Result<Self> {
        let mut map = BTreeMap::new();
        let mut once = false;
        let mut values = values.peekable();
        while let Some(flag) = values.next() {
            if flag == "--once" {
                once = true;
                continue;
            }
            let value = values
                .next()
                .with_context(|| format!("{flag} requires a value"))?;
            if map.insert(flag.clone(), value).is_some() {
                bail!("{flag} was provided twice");
            }
        }
        let results_retention_days = map
            .remove("--results-retention-days")
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(DEFAULT_RESULT_RETENTION_DAYS);
        let poll_seconds = map
            .remove("--poll-seconds")
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(3_600);
        let index_reconcile_limit = map
            .remove("--index-reconcile-limit")
            .map(|value| value.parse::<usize>())
            .transpose()?
            .unwrap_or(10_000);
        // NAN-2823: named checks; the error lists every failing bound.
        ResultGcBounds {
            results_retention_days,
            poll_seconds,
            index_reconcile_limit,
        }
        .check()
        .finish()?;
        let result = Self {
            redis_url: map
                .remove("--redis-url")
                .or_else(|| std::env::var("REDIS_URL").ok())
                .context("--redis-url or REDIS_URL is required")?,
            result_root: map
                .remove("--result-root")
                .or_else(|| std::env::var("NANO_LAKE_JOB_RESULT_ROOT").ok())
                .context("--result-root or NANO_LAKE_JOB_RESULT_ROOT is required")?,
            tenant_id: map
                .remove("--tenant-id")
                .context("--tenant-id is required")?,
            tenant_scope: SearchTenantScope::Dedicated,
            results_retention: Duration::from_secs(results_retention_days * 24 * 60 * 60),
            index_reconcile_limit,
            poll: Duration::from_secs(poll_seconds),
            once,
        };
        if result.tenant_id.is_empty()
            || result.tenant_id.len() > 512
            || result.tenant_id.chars().any(char::is_control)
        {
            bail!("--tenant-id is invalid");
        }
        if !(result.result_root.starts_with("s3://")
            || result.result_root.starts_with("file://")
            || result.result_root.starts_with('/'))
        {
            bail!("--result-root must be an s3:// URI, file:// URI, or absolute path");
        }
        let deployment_mode = map
            .remove("--deployment-mode")
            .or_else(|| std::env::var("DEPLOYMENT_MODE").ok());
        let tenant_scope = search_tenant_scope(deployment_mode.as_deref(), &result.tenant_id)?;
        let result = Self {
            tenant_scope,
            ..result
        };
        if !map.is_empty() {
            bail!(
                "unknown arguments: {}",
                map.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        Ok(result)
    }
}

fn search_tenant_scope(
    deployment_mode: Option<&str>,
    tenant_id: &str,
) -> Result<SearchTenantScope> {
    match deployment_mode {
        // Open builds fall through to the invalid-mode refusal below.
        #[cfg(feature = "enterprise")]
        Some("enterprise_shared") => {
            let parsed = Uuid::parse_str(tenant_id)
                .context("enterprise-shared result GC tenant ID must be a UUID")?;
            if parsed.as_hyphenated().to_string() != tenant_id {
                bail!("enterprise-shared result GC tenant ID must be canonical");
            }
            SearchTenantScope::enterprise_shared(Some(parsed)).map_err(Into::into)
        }
        None | Some("") | Some("managed") | Some("selfhosted") | Some("self-hosted")
        | Some("demo") => Ok(SearchTenantScope::Dedicated),
        Some(value) => bail!("invalid DEPLOYMENT_MODE {value:?} for result GC"),
    }
}

async fn connect_job_store(args: &Arguments) -> Result<RedisJobStore> {
    match args.tenant_scope {
        SearchTenantScope::Dedicated => RedisJobStore::connect(&args.redis_url)
            .await
            .context("connect result GC to the dedicated durable job store; deleting nothing"),
        SearchTenantScope::EnterpriseShared(tenant_id) => {
            #[cfg(feature = "enterprise")]
            {
                let database_url = std::env::var("DATABASE_URL")
                    .ok()
                    .filter(|value| !value.trim().is_empty())
                    .context("enterprise-shared result GC requires DATABASE_URL")?;
                let pool = nanosiem_core::db::pooler::connect_lazy(nanosiem_core::db::connection_budget::pool_options(1), &database_url)
                    .context("connect result GC to the retention authority database")?;
                let retention =
                    EnterpriseSharedQueryRetentionAuthority::load_current(&pool, tenant_id)
                        .await
                        .context("load current enterprise-shared result GC retention identity")?;
                let retained = retention
                    .search_scope()
                    .context("resolve enterprise-shared result GC retention identity")?;
                RedisJobStore::connect_enterprise_shared_retained(&args.redis_url, retained)
                    .await
                    .context(
                        "connect result GC to the tenant-scoped durable job store; deleting nothing",
                    )
            }
            #[cfg(not(feature = "enterprise"))]
            {
                let _ = tenant_id;
                bail!("enterprise_shared result GC requires the enterprise build")
            }
        }
        SearchTenantScope::EnterpriseSharedRetained { .. } => {
            bail!("result GC retention scope must be resolved from PostgreSQL")
        }
    }
}

fn require_delete_authority(args: &Arguments) -> Result<()> {
    #[cfg(feature = "enterprise")]
    let shared_scope = args.tenant_scope.is_enterprise_shared();
    #[cfg(not(feature = "enterprise"))]
    let shared_scope = !matches!(args.tenant_scope, SearchTenantScope::Dedicated);
    if shared_scope && args.result_root.starts_with("s3://") {
        bail!(
            "direct enterprise_shared durable-query-result deletion is release-blocked: use the owner-authorized copy-class purge authority"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    nanosiem_lake_worker::process_limits::initialize()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lake_result_gc=info,nanosiem_lake_worker=info".into()),
        )
        .json()
        .init();
    let args = Arguments::parse(std::env::args().skip(1))?;
    require_delete_authority(&args)?;
    loop {
        // Reconnect each pass: a dead metadata connection must fail the pass
        // (deleting nothing), never masquerade as "no references anywhere".
        let store = connect_job_store(&args).await?;
        let sweep = sweep_result_root(
            &args.result_root,
            Some(&args.tenant_id),
            &store,
            args.results_retention,
            Utc::now(),
        )
        .await;
        let reconciliation = match &sweep {
            Ok(_) => Some(
                store
                    .reconcile_index_orphans(args.index_reconcile_limit)
                    .await
                    .map_err(|error| anyhow::anyhow!("reconcile job index orphans: {error}"))?,
            ),
            Err(_) => None,
        };
        match sweep {
            Ok(report) => println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "result_gc": report,
                    "index_reconciliation": reconciliation,
                }))?
            ),
            Err(error) => {
                if args.once {
                    return Err(error).context("durable query-result GC pass failed");
                }
                tracing::error!(error = %format!("{error:#}"),
                    "durable query-result GC pass failed; nothing was deleted this pass");
            }
        }
        if args.once {
            return Ok(());
        }
        tokio::time::sleep(args.poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Result<Arguments> {
        Arguments::parse(values.iter().map(|value| value.to_string()))
    }

    #[test]
    fn parse_applies_safe_defaults_and_bounds() {
        let parsed = args(&[
            "--redis-url",
            "redis://localhost:6379",
            "--result-root",
            "s3://nano-lake/query-results-v1",
            "--tenant-id",
            "tenant-a",
            "--once",
        ])
        .expect("minimal arguments parse");
        assert_eq!(
            parsed.results_retention,
            Duration::from_secs(DEFAULT_RESULT_RETENTION_DAYS * 24 * 60 * 60)
        );
        assert_eq!(parsed.poll, Duration::from_secs(3_600));
        assert_eq!(parsed.index_reconcile_limit, 10_000);
        assert_eq!(parsed.tenant_scope, SearchTenantScope::Dedicated);
        assert!(parsed.once);

        for invalid in [
            vec![
                "--redis-url",
                "redis://localhost:6379",
                "--result-root",
                "s3://nano-lake/query-results-v1",
                "--tenant-id",
                "tenant-a",
                "--results-retention-days",
                "0",
            ],
            vec![
                "--redis-url",
                "redis://localhost:6379",
                "--result-root",
                "relative/path",
                "--tenant-id",
                "tenant-a",
            ],
            vec![
                "--redis-url",
                "redis://localhost:6379",
                "--result-root",
                "s3://nano-lake/query-results-v1",
            ],
        ] {
            assert!(args(&invalid).is_err(), "must reject: {invalid:?}");
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_mode_requires_an_exact_uuid_and_never_uses_the_dedicated_scope() {
        let parsed = args(&[
            "--redis-url",
            "redis://localhost:6379",
            "--result-root",
            "s3://tenant-bucket/query-results-v1",
            "--tenant-id",
            "8b672aca-e503-4c43-81fb-3c7f5550d86a",
            "--deployment-mode",
            "enterprise_shared",
        ])
        .expect("shared arguments parse");
        assert_eq!(
            parsed.tenant_scope,
            SearchTenantScope::EnterpriseShared(
                Uuid::parse_str("8b672aca-e503-4c43-81fb-3c7f5550d86a").unwrap()
            )
        );
        assert!(
            args(&[
                "--redis-url",
                "redis://localhost:6379",
                "--result-root",
                "s3://tenant-bucket/query-results-v1",
                "--tenant-id",
                "tenant-a",
                "--deployment-mode",
                "enterprise_shared",
            ])
            .is_err()
        );
        assert!(
            args(&[
                "--redis-url",
                "redis://localhost:6379",
                "--result-root",
                "s3://tenant-bucket/query-results-v1",
                "--tenant-id",
                "8B672ACA-E503-4C43-81FB-3C7F5550D86A",
                "--deployment-mode",
                "enterprise_shared",
            ])
            .is_err()
        );
        assert!(require_delete_authority(&parsed).is_err());
    }
}

/// Startup bounds of the result GC (NAN-2823).
#[derive(Clone, Debug)]
struct ResultGcBounds {
    results_retention_days: u64,
    poll_seconds: u64,
    index_reconcile_limit: usize,
}

impl ResultGcBounds {
    fn check(&self) -> BoundChecks {
        let mut checks = BoundChecks::new();
        checks
            .in_range("--results-retention-days", self.results_retention_days, 1..=3_650)
            .in_range("--poll-seconds", self.poll_seconds, 60..=86_400)
            .in_range("--index-reconcile-limit", self.index_reconcile_limit, 1..=100_000);
        checks
    }
}

#[cfg(test)]
mod startup_bound_tests {
    use super::*;
    use nanosiem_lake_worker::bound_mutations;
    use nanosiem_lake_worker::startup_bounds::assert_same_accept_set;

    /// The pre-NAN-2823 combined predicate, verbatim (negated to "accepts").
    fn legacy_accepts(b: &ResultGcBounds) -> bool {
        !(!(1..=3_650).contains(&b.results_retention_days)
            || !(60..=86_400).contains(&b.poll_seconds)
            || !(1..=100_000).contains(&b.index_reconcile_limit))
    }

    #[test]
    fn named_checks_accept_exactly_the_legacy_set() {
        let mutations = bound_mutations!(ResultGcBounds;
            results_retention_days => [0_u64, 1, 3_650, 3_651],
            poll_seconds => [0_u64, 59, 60, 86_400, 86_401],
            index_reconcile_limit => [0_usize, 1, 100_000, 100_001],
        );
        assert_same_accept_set(
            &ResultGcBounds {
                results_retention_days: DEFAULT_RESULT_RETENTION_DAYS,
                poll_seconds: 3_600,
                index_reconcile_limit: 10_000,
            },
            &mutations,
            |b| b.check().violations().is_empty(),
            legacy_accepts,
        );
    }

    #[test]
    fn every_failing_bound_is_named() {
        let error = ResultGcBounds {
            results_retention_days: 0,
            poll_seconds: 30,
            index_reconcile_limit: 10,
        }
        .check()
        .finish()
        .expect_err("invalid")
        .to_string();
        assert_eq!(
            error,
            "invalid bounds: --results-retention-days 0 is outside 1..=3650; \
             --poll-seconds 30 is outside 60..=86400"
        );
    }
}
