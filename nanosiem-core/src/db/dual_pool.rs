// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dual database connection pool management for PostgreSQL and ClickHouse
//!
//! This module provides a unified interface for managing connections to both
//! PostgreSQL (for metadata, configuration, alerts) and ClickHouse (for log storage).

use clickhouse::Client as ClickHouseClient;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors that can occur when working with the dual database pool
#[derive(Error, Debug)]
pub enum DualPoolError {
    #[error("PostgreSQL connection failed: {0}")]
    PostgresConnectionError(String),

    #[error("ClickHouse connection failed: {0}")]
    ClickHouseConnectionError(String),

    #[error("PostgreSQL health check failed: {0}")]
    PostgresHealthCheckError(String),

    #[error("ClickHouse health check failed: {0}")]
    ClickHouseHealthCheckError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Both databases failed health check - PostgreSQL: {postgres_error}, ClickHouse: {clickhouse_error}")]
    BothDatabasesUnhealthy {
        postgres_error: String,
        clickhouse_error: String,
    },

    /// ClickHouse is reachable but the schema is behind the binary — some
    /// migrations from `/clickhouse/*.sql` are not yet applied. Distinct from
    /// connection errors so callers can hard-fail (rather than silently
    /// falling back to PostgreSQL-only mode against a stale ClickHouse).
    /// Run the `clickhouse_migrator` binary to bring the schema forward.
    /// See NAN-607.
    #[error("ClickHouse schema is behind: {0}")]
    SchemaBehind(String),
}

/// Configuration for dual database connections
#[derive(Debug, Clone)]
pub struct DualPoolConfig {
    /// PostgreSQL connection URL
    pub postgres_url: String,
    /// ClickHouse connection URL (e.g., "http://localhost:8123")
    pub clickhouse_url: String,
    /// ClickHouse database name
    pub clickhouse_database: String,
    /// ClickHouse username (runtime user - no DDL permissions)
    pub clickhouse_user: String,
    /// ClickHouse password (runtime user)
    pub clickhouse_password: String,
    /// ClickHouse admin username (for migrations - has DDL permissions)
    pub clickhouse_admin_user: Option<String>,
    /// ClickHouse admin password (for migrations)
    pub clickhouse_admin_password: Option<String>,
    /// NAN-2001: raw-SQL feature identity (audit-capable, read-only). Its GRANT
    /// SELECT list IS the raw-SQL table allowlist. Username defaults to
    /// `nanosiem_rawsql`; password is REQUIRED (boot fails if absent — no
    /// fallback to the broad `nanosiem` client).
    pub clickhouse_rawsql_user: String,
    pub clickhouse_rawsql_password: Option<String>,
    /// NAN-2001: raw-SQL feature identity for callers WITHOUT `audit:view`
    /// (narrower grants + a RESTRICTIVE `source_type!='audit'` row policy).
    /// Username defaults to `nanosiem_rawsql_noaudit`; password REQUIRED.
    pub clickhouse_rawsql_noaudit_user: String,
    pub clickhouse_rawsql_noaudit_password: Option<String>,
    /// Maximum PostgreSQL connections
    pub pg_max_connections: u32,
    /// Minimum PostgreSQL connections
    pub pg_min_connections: u32,
    /// Maximum ClickHouse connections (used for connection pool sizing)
    pub ch_max_connections: u32,
    /// PostgreSQL connection timeout in seconds
    pub pg_connect_timeout_secs: u64,
    /// ClickHouse connection timeout in seconds
    pub ch_connect_timeout_secs: u64,
    /// PostgreSQL idle timeout in seconds
    pub pg_idle_timeout_secs: u64,
    /// PostgreSQL max connection lifetime in seconds
    pub pg_max_lifetime_secs: u64,
    /// Test PostgreSQL connections before use
    pub pg_test_before_acquire: bool,
}

/// Connection pool defaults.
///
/// **Multi-node sizing:** With N API nodes, total PostgreSQL connections =
/// N × pg_max_connections. Ensure PostgreSQL `max_connections` ≥ (N × 20) + 20 headroom.
/// For 3 API nodes + 1 search node: recommend `max_connections` ≥ 100.
///
/// All pool sizes are configurable via environment variables:
/// `PG_MAX_CONNECTIONS`, `PG_MIN_CONNECTIONS`, `CH_MAX_CONNECTIONS`.
impl Default for DualPoolConfig {
    fn default() -> Self {
        Self {
            postgres_url: "postgres://localhost/nanosiem".to_string(),
            clickhouse_url: "http://localhost:8123".to_string(),
            clickhouse_database: "nanosiem".to_string(),
            clickhouse_user: "default".to_string(),
            clickhouse_password: String::new(),
            clickhouse_admin_user: None,
            clickhouse_admin_password: None,
            clickhouse_rawsql_user: "nanosiem_rawsql".to_string(),
            clickhouse_rawsql_password: None,
            clickhouse_rawsql_noaudit_user: "nanosiem_rawsql_noaudit".to_string(),
            clickhouse_rawsql_noaudit_password: None,
            pg_max_connections: 20, // Increased for tuning workload
            pg_min_connections: 2,  // Maintain ready connections
            ch_max_connections: 10,
            pg_connect_timeout_secs: 30,
            ch_connect_timeout_secs: 30,
            pg_idle_timeout_secs: 600,
            pg_max_lifetime_secs: 1800, // 30 minutes
            pg_test_before_acquire: true,
        }
    }
}

impl DualPoolConfig {
    /// Create a new configuration from environment variables
    ///
    /// Environment variables:
    /// - `DATABASE_URL`: PostgreSQL connection URL
    /// - `CLICKHOUSE_URL`: ClickHouse HTTP interface URL
    /// - `CLICKHOUSE_DATABASE`: ClickHouse database name
    /// - `CLICKHOUSE_USER`: ClickHouse username for runtime queries (default: "nanosiem")
    /// - `CLICKHOUSE_PASSWORD`: ClickHouse password for runtime user (default: empty)
    /// - `CLICKHOUSE_ADMIN_USER`: ClickHouse admin username for migrations (optional, defaults to CLICKHOUSE_USER)
    /// - `CLICKHOUSE_ADMIN_PASSWORD`: ClickHouse admin password for migrations (optional, defaults to CLICKHOUSE_PASSWORD)
    /// - `PG_MAX_CONNECTIONS`: Maximum PostgreSQL connections (default: 10)
    /// - `CH_MAX_CONNECTIONS`: Maximum ClickHouse connections (default: 10)
    /// - `PG_CONNECT_TIMEOUT`: PostgreSQL connection timeout in seconds (default: 30)
    /// - `CH_CONNECT_TIMEOUT`: ClickHouse connection timeout in seconds (default: 30)
    pub fn from_env() -> Result<Self, DualPoolError> {
        let postgres_url = std::env::var("DATABASE_URL").map_err(|_| {
            DualPoolError::ConfigError("DATABASE_URL environment variable is required".to_string())
        })?;

        let clickhouse_url = std::env::var("CLICKHOUSE_URL").map_err(|_| {
            DualPoolError::ConfigError(
                "CLICKHOUSE_URL environment variable is required".to_string(),
            )
        })?;

        let clickhouse_database =
            std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "nanosiem".to_string());

        let clickhouse_user =
            std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "nanosiem".to_string());

        let clickhouse_password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();

        // Admin credentials for migrations (optional - falls back to runtime credentials)
        let clickhouse_admin_user = std::env::var("CLICKHOUSE_ADMIN_USER").ok();
        let clickhouse_admin_password = std::env::var("CLICKHOUSE_ADMIN_PASSWORD").ok();

        // NAN-2001: raw-SQL feature identities. Username overridable; password
        // REQUIRED (validated at DualPool::new — boot fails closed if absent).
        let clickhouse_rawsql_user =
            std::env::var("CLICKHOUSE_RAWSQL_USER").unwrap_or_else(|_| "nanosiem_rawsql".to_string());
        let clickhouse_rawsql_password = std::env::var("CLICKHOUSE_RAWSQL_PASSWORD").ok();
        let clickhouse_rawsql_noaudit_user = std::env::var("CLICKHOUSE_RAWSQL_NOAUDIT_USER")
            .unwrap_or_else(|_| "nanosiem_rawsql_noaudit".to_string());
        let clickhouse_rawsql_noaudit_password =
            std::env::var("CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD").ok();

        let pg_max_connections = std::env::var("PG_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let pg_min_connections = std::env::var("PG_MIN_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);

        let ch_max_connections = std::env::var("CH_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let pg_connect_timeout_secs = std::env::var("PG_CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let ch_connect_timeout_secs = std::env::var("CH_CONNECT_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let pg_idle_timeout_secs = std::env::var("PG_IDLE_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600);

        let pg_max_lifetime_secs = std::env::var("PG_MAX_LIFETIME")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1800);

        let pg_test_before_acquire = std::env::var("PG_TEST_BEFORE_ACQUIRE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true);

        Ok(Self {
            postgres_url,
            clickhouse_url,
            clickhouse_database,
            clickhouse_user,
            clickhouse_password,
            clickhouse_admin_user,
            clickhouse_admin_password,
            clickhouse_rawsql_user,
            clickhouse_rawsql_password,
            clickhouse_rawsql_noaudit_user,
            clickhouse_rawsql_noaudit_password,
            pg_max_connections,
            pg_min_connections,
            ch_max_connections,
            pg_connect_timeout_secs,
            ch_connect_timeout_secs,
            pg_idle_timeout_secs,
            pg_max_lifetime_secs,
            pg_test_before_acquire,
        })
    }

    /// Create configuration with explicit values (useful for testing)
    pub fn new(
        postgres_url: impl Into<String>,
        clickhouse_url: impl Into<String>,
        clickhouse_database: impl Into<String>,
    ) -> Self {
        Self {
            postgres_url: postgres_url.into(),
            clickhouse_url: clickhouse_url.into(),
            clickhouse_database: clickhouse_database.into(),
            ..Default::default()
        }
    }

    /// Create configuration with authentication (useful for testing)
    pub fn with_auth(
        postgres_url: impl Into<String>,
        clickhouse_url: impl Into<String>,
        clickhouse_database: impl Into<String>,
        clickhouse_user: impl Into<String>,
        clickhouse_password: impl Into<String>,
    ) -> Self {
        Self {
            postgres_url: postgres_url.into(),
            clickhouse_url: clickhouse_url.into(),
            clickhouse_database: clickhouse_database.into(),
            clickhouse_user: clickhouse_user.into(),
            clickhouse_password: clickhouse_password.into(),
            ..Default::default()
        }
    }

    /// Create a ClickHouse client with admin credentials for running migrations
    ///
    /// If admin credentials are not configured, falls back to runtime credentials.
    /// Returns the client and whether admin credentials were used.
    pub fn create_admin_clickhouse_client(&self) -> (ClickHouseClient, bool) {
        let (user, password, is_admin) =
            match (&self.clickhouse_admin_user, &self.clickhouse_admin_password) {
                (Some(user), Some(password)) => (user.clone(), password.clone(), true),
                _ => (
                    self.clickhouse_user.clone(),
                    self.clickhouse_password.clone(),
                    false,
                ),
            };

        let mut client = ClickHouseClient::default()
            .with_url(&self.clickhouse_url)
            .with_database(&self.clickhouse_database)
            .with_user(&user);

        if !password.is_empty() {
            client = client.with_password(&password);
        }

        if is_admin {
            tracing::info!(
                "Using admin credentials for ClickHouse migrations (user: {})",
                user
            );
        } else {
            tracing::warn!(
                "No admin credentials configured (CLICKHOUSE_ADMIN_USER/PASSWORD), \
                 using runtime user '{}' for migrations. This may fail if DDL is restricted.",
                user
            );
        }

        (client, is_admin)
    }
}

/// Health status for both database connections
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Whether PostgreSQL is healthy
    pub postgres_healthy: bool,
    /// Whether ClickHouse is healthy
    pub clickhouse_healthy: bool,
    /// PostgreSQL health check latency in milliseconds
    pub postgres_latency_ms: u64,
    /// ClickHouse health check latency in milliseconds
    pub clickhouse_latency_ms: u64,
    /// PostgreSQL error message if unhealthy
    pub postgres_error: Option<String>,
    /// ClickHouse error message if unhealthy
    pub clickhouse_error: Option<String>,
}

impl HealthStatus {
    /// Returns true if both databases are healthy
    pub fn is_healthy(&self) -> bool {
        self.postgres_healthy && self.clickhouse_healthy
    }
}

/// Manages connections to both PostgreSQL and ClickHouse databases
///
/// PostgreSQL is used for:
/// - Detection rules and alerts
/// - Dashboards and saved searches
/// - Parser configurations
/// - Enrichment data and lookup tables
/// - AI/meloD settings
/// - System configuration
///
/// ClickHouse is used for:
/// - Log storage and retrieval
/// - Time-series queries and aggregations

/// Resolves ClickHouse table names for read vs. write/DDL queries.
///
/// In cluster mode, read queries target `{table}_distributed` (Distributed engine)
/// so they fan out across all shards. DDL/mutation queries (ALTER TABLE UPDATE/DELETE)
/// must target the local MergeTree table because the Distributed engine does not
/// support mutations.
///
/// In standalone mode, all methods return the base table name — no behavior change.
#[derive(Clone, Debug)]
pub struct TableNames {
    is_clustered: bool,
}

/// **The** canonical list of tables that get `_distributed` wrappers on a
/// cluster.
///
/// This is the single source of truth shared by BOTH consumers so they can
/// never drift (findings L-5 / D9 — they were split into two hand-maintained
/// lists that had silently diverged before):
///   1. Read routing here (`TableNames::read` / `read_bare`) — a table listed
///      here is read via `{table}_distributed` on a cluster.
///   2. The wrapper reconciler in `clickhouse_migrate::distributed`
///      (`ClickHouseMigrator::DISTRIBUTED_TABLES` re-exports this slice) which
///      CREATEs the wrappers and column-/sharding-key-syncs them.
/// A table read-routed here without a wrapper created there would target a
/// non-existent `_distributed` table on a cluster, and vice-versa.
///
/// **Reference tables get ADDITIVE `_distributed` wrappers** (NAN-1728, revised
/// approach). `custom_enrichment_results`, `ip_enrichments`, `user_registry`,
/// and `lookup_rows` are small, key-addressed reference tables
/// (IOC/enrichment/identity/lookup sources) whose rows scatter across shards
/// (writers reach one arbitrary shard through the load-balanced ingest Service).
/// A read via the `_distributed` wrapper fans across all shards so the complete
/// keyspace is visible — WITHOUT any engine change, DROP, or recreate of the
/// populated local tables (the cluster-wide-replication rewrite was abandoned as
/// unshippable: it would DROP+recreate live enrichment/IOC data). The wrappers
/// are **read-only** — writes and per-node dictionary sources still target the
/// LOCAL table; only cross-shard SELECTs route to the wrapper. No inserts are
/// routed through these four wrappers, so their sharding key is irrelevant
/// (`sharding_key_for` gives them the default `rand()`).
pub(crate) const DISTRIBUTED_TABLES: &[&str] = &[
    "logs",
    // OCSF canonical log table (NAN-1241). Listed so cluster-mode read routing
    // (`ocsf_logs_distributed`) applies identically to the UDM `logs` table when
    // the active schema profile is OCSF.
    "ocsf_logs",
    "signals",
    "domain_prevalence_agg",
    "hash_prevalence_agg",
    "ip_prevalence_agg",
    // Per-shard prevalence SUMMARIES (AggregatingMergeTree read with uniqMerge,
    // NAN-1728 C3 / Lane L4). Without a wrapper the summary reads (rare/common
    // verdicts, D4b rescue, cache-dict pushdown) see only ~1/N of the hosts and
    // an artifact on N×k hosts reads as "rare" everywhere. Wrappers make the
    // uniqMerge GROUP BY fan out; the reconciler auto-creates them.
    "hash_prevalence_summary",
    "domain_prevalence_summary",
    "ip_prevalence_summary",
    // Reference tables — read-only additive wrappers (see doc above): the
    // reconciler creates `<t>_distributed` on clusters so cross-shard reads see
    // the complete scattered keyspace; writes/dict sources stay LOCAL.
    "custom_enrichment_results",
    "ip_enrichments",
    "user_registry",
    "lookup_rows",
    "entity_time_range_agg",
    // Per-day first-seen aggregates behind `| baseline`'s new-to-entity fast
    // path (NAN-1888). One per schema lane — the reader is profile-keyed
    // (`dimension_agg_table_key`), mirroring logs/ocsf_logs.
    "entity_dimension_day_agg",
    "ocsf_entity_dimension_day_agg",
    "cloud_user_activity_agg",
    "ingestion_errors",
    "identity_observations",
    "logs_per_source_5m",
    // Observability / OTLP native-storage tables (NAN-1721 O1). Their READ SQL
    // (traces, RED charts, metrics, synthetics) routes to the `_distributed`
    // wrapper on clusters so it unions all shards, mirroring the `logs` lane.
    "otel_spans",
    "otel_spans_trace_id_ts",
    "otel_metrics",
    "otel_metrics_1m",
    "otel_metrics_1h",
    "otel_service_red_1m",
    "synthetic_check_results",
];

/// Canonical ` ON CLUSTER \`<name>\`` clause for **runtime** DDL sites.
///
/// This is THE way runtime (non-migration) DDL should emit `ON CLUSTER`. Unlike
/// migration SQL — which the migrator's `transform_for_cluster` auto-injects
/// `ON CLUSTER` into — DDL built at runtime (GDPR erasure mutations, retention
/// `MODIFY TTL`, `DROP PARTITION`, `KILL QUERY`, dictionary reloads, real-time
/// detection MVs, …) has to add the clause itself. Downstream NAN-1728 fixes
/// call this so every runtime DDL site gates on the cluster identically.
///
/// Returns ` ON CLUSTER \`<name>\`` when `CLICKHOUSE_CLUSTER` is set to a
/// non-empty value (the deploy sets it only on clustered ClickHouse), else an
/// empty string — so on single-node / open-core the emitted DDL is
/// byte-identical to the pre-cluster form. Splice the result verbatim (it is
/// pre-spaced and self-quoting).
pub fn on_cluster_clause() -> String {
    format_on_cluster(std::env::var("CLICKHOUSE_CLUSTER").ok().as_deref())
}

/// NAN-1728 (P1) decision (pure, testable): given the current
/// `CLICKHOUSE_CLUSTER` env value and the cluster name probed from
/// `system.clusters`, return `Some(name)` when we should SET the env — i.e. the
/// env is unset/blank AND a non-empty cluster name was probed. Returns `None`
/// when the env already has a usable value (keep it) or nothing was probed
/// (nothing to converge to). Trims both sides.
pub(crate) fn cluster_env_to_set(current_env: Option<&str>, probed: Option<&str>) -> Option<String> {
    if current_env.map(str::trim).is_some_and(|v| !v.is_empty()) {
        return None;
    }
    probed
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
}

/// Pure formatter behind [`on_cluster_clause`] (testable without touching env).
/// Backtick-quoted to match the pre-existing runtime convention in
/// `detection::materialized_view` (backticks and `'…'` are both valid CH
/// `ON CLUSTER` identifier forms); the clause is spliced verbatim by callers.
pub fn format_on_cluster(cluster: Option<&str>) -> String {
    match cluster {
        Some(c) if !c.trim().is_empty() => format!(" ON CLUSTER `{}`", c.trim()),
        _ => String::new(),
    }
}

impl TableNames {
    /// Create a new TableNames resolver.
    pub fn new(is_clustered: bool) -> Self {
        Self { is_clustered }
    }

    /// Fully qualified table name for **read** queries (SELECT).
    /// Returns `nanosiem.{table}_distributed` in cluster mode for tables that have
    /// distributed variants, `nanosiem.{table}` otherwise.
    pub fn read(&self, table: &str) -> String {
        if self.is_clustered && DISTRIBUTED_TABLES.contains(&table) {
            format!("nanosiem.{}_distributed", table)
        } else {
            format!("nanosiem.{}", table)
        }
    }

    /// Fully qualified table name for **DDL / mutation** queries (ALTER TABLE, DROP, etc.).
    /// Always returns the local MergeTree table (`nanosiem.{table}`).
    pub fn local(&self, table: &str) -> String {
        format!("nanosiem.{}", table)
    }

    /// Bare table name (without database prefix) for read queries.
    /// Used by components like ClickHouseSqlGenerator that prepend `nanosiem.` themselves.
    pub fn read_bare(&self, table: &str) -> String {
        if self.is_clustered && DISTRIBUTED_TABLES.contains(&table) {
            format!("{}_distributed", table)
        } else {
            table.to_string()
        }
    }

    pub fn is_clustered(&self) -> bool {
        self.is_clustered
    }
}

/// NAN-2001: expected SELECT allowlist (bare names) for the audit-capable
/// `nanosiem_rawsql` identity. The boot-time grant assertion requires the
/// granted set (normalized of `_local`/`_distributed` twins) to be a subset of
/// this. Keep in sync with `clickhouse/users.d/nanosiem-users.xml` and the
/// per-surface user configs.
const RAWSQL_ALLOWED_TABLES: &[&str] = &[
    "logs",
    "ocsf_logs",
    "signals",
    "domain_prevalence_agg",
    "hash_prevalence_agg",
    "ip_prevalence_agg",
    "identity_observations",
    "nat_candidates",
    "entity_time_range_agg",
    "cloud_user_activity_agg",
    "custom_enrichment_results",
    "ingestion_errors",
    "otel_spans",
    "otel_metrics",
    "otel_metrics_1m",
    "otel_metrics_1h",
];

/// NAN-2001: expected SELECT allowlist for the audit-HIDDEN
/// `nanosiem_rawsql_noaudit` identity. NARROWER than `RAWSQL_ALLOWED_TABLES` —
/// the audit-baked aggregates (`*_prevalence_agg`, `entity_time_range_agg`,
/// `cloud_user_activity_agg`, `nat_candidates`) are OMITTED because a row policy
/// cannot retroactively strip audit contribution baked into their merge states.
/// Granting any of those to this identity is a boot-failing security drift.
const RAWSQL_NOAUDIT_ALLOWED_TABLES: &[&str] = &[
    "logs",
    "ocsf_logs",
    "signals",
    "identity_observations",
    "custom_enrichment_results",
    "ingestion_errors",
    "otel_spans",
    "otel_metrics",
    "otel_metrics_1m",
    "otel_metrics_1h",
];

/// NAN-2001: the RESTRICTIVE audit row-policy short-names created by the
/// migrator's `ensure_rawsql_row_policies`. Boot verifies these exist (when an
/// admin client is available) so a noaudit identity can never have grants but no
/// audit-hiding policy. Keep in sync with the reconciler's `rawsql_hide_audit_*`.
const RAWSQL_HIDE_POLICY_NAMES: &[&str] = &[
    "rawsql_hide_audit_logs",
    "rawsql_hide_audit_ocsf_logs",
    "rawsql_hide_audit_signals",
    "rawsql_hide_audit_identity_observations",
];

#[derive(Clone)]
pub struct DualPool {
    postgres: PgPool,
    clickhouse: ClickHouseClient,
    /// Admin client for DDL operations (CREATE/DROP views, etc.)
    /// Falls back to regular client if admin credentials not configured
    clickhouse_admin: ClickHouseClient,
    /// NAN-2001: raw-SQL feature clients. `clickhouse_rawsql` is audit-capable;
    /// `clickhouse_rawsql_noaudit` carries the RESTRICTIVE audit row policy. The
    /// raw-SQL handler picks by the caller's `audit:view`. Both are REQUIRED —
    /// boot fails (no fallback to `clickhouse`) if a credential is missing, and
    /// their grant sets are asserted against the expected allowlist at boot.
    clickhouse_rawsql: ClickHouseClient,
    clickhouse_rawsql_noaudit: ClickHouseClient,
    /// Whether distributed tables exist (logs_distributed, etc.)
    /// Detected at init time by checking system.tables.
    is_clustered: bool,
    /// The table name to use for log queries — "logs_distributed" when clustered, "logs" otherwise.
    logs_table: &'static str,
}

impl DualPool {
    /// Create a new dual pool with connections to both databases
    ///
    /// This will establish connections to both PostgreSQL and ClickHouse.
    /// If either connection fails, an error is returned with a clear message.
    pub async fn new(config: &DualPoolConfig) -> Result<Self, DualPoolError> {
        // Initialize PostgreSQL connection pool with enhanced configuration
        let mut pg_options = PgPoolOptions::new()
            .max_connections(config.pg_max_connections)
            .min_connections(config.pg_min_connections)
            .acquire_timeout(Duration::from_secs(config.pg_connect_timeout_secs))
            .idle_timeout(Duration::from_secs(config.pg_idle_timeout_secs))
            .test_before_acquire(config.pg_test_before_acquire);

        // Set max lifetime if configured
        if config.pg_max_lifetime_secs > 0 {
            pg_options = pg_options.max_lifetime(Duration::from_secs(config.pg_max_lifetime_secs));
        }

        let postgres = pg_options
            .connect(&config.postgres_url)
            .await
            .map_err(|e| {
                DualPoolError::PostgresConnectionError(format!(
                    "Failed to connect to PostgreSQL at '{}': {}",
                    Self::sanitize_url(&config.postgres_url),
                    e
                ))
            })?;

        // Try to ensure ClickHouse database exists using admin credentials (DDL required)
        // Must NOT set .with_database() — the database doesn't exist yet on fresh deploys
        {
            let (user, password) = match (
                &config.clickhouse_admin_user,
                &config.clickhouse_admin_password,
            ) {
                (Some(u), Some(p)) => (u.clone(), p.clone()),
                _ => (
                    config.clickhouse_user.clone(),
                    config.clickhouse_password.clone(),
                ),
            };
            let mut bootstrap = ClickHouseClient::default()
                .with_url(&config.clickhouse_url)
                .with_user(&user);
            if !password.is_empty() {
                bootstrap = bootstrap.with_password(&password);
            }
            match bootstrap
                .query(&format!(
                    "CREATE DATABASE IF NOT EXISTS `{}`",
                    config.clickhouse_database
                ))
                .execute()
                .await
            {
                Ok(_) => {
                    tracing::info!("ClickHouse database '{}' ready", config.clickhouse_database);
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not CREATE DATABASE '{}' (user may lack DDL privileges, \
                         continuing assuming it already exists): {}",
                        config.clickhouse_database,
                        e
                    );
                }
            }
        }

        // Initialize ClickHouse client with authentication
        let mut clickhouse = ClickHouseClient::default()
            .with_url(&config.clickhouse_url)
            .with_database(&config.clickhouse_database)
            .with_user(&config.clickhouse_user);

        // Only set password if it's not empty
        if !config.clickhouse_password.is_empty() {
            clickhouse = clickhouse.with_password(&config.clickhouse_password);
        }

        // Verify ClickHouse connection by running a simple query
        clickhouse
            .query("SELECT 1")
            .fetch_one::<u8>()
            .await
            .map_err(|e| {
                DualPoolError::ClickHouseConnectionError(format!(
                    "Failed to connect to ClickHouse at '{}': {}",
                    config.clickhouse_url, e
                ))
            })?;

        // Create admin client for DDL operations (CREATE/DROP views, etc.)
        // Falls back to regular client if admin credentials not configured
        let (clickhouse_admin, using_admin) = config.create_admin_clickhouse_client();

        if using_admin {
            // Verify admin connection
            clickhouse_admin
                .query("SELECT 1")
                .fetch_one::<u8>()
                .await
                .map_err(|e| {
                    DualPoolError::ClickHouseConnectionError(format!(
                        "Failed to connect to ClickHouse with admin credentials: {}",
                        e
                    ))
                })?;
            tracing::info!("ClickHouse admin client initialized for DDL operations");
        } else {
            tracing::warn!(
                "ClickHouse admin credentials not configured (CLICKHOUSE_ADMIN_USER/CLICKHOUSE_ADMIN_PASSWORD). \
                 DDL operations (real-time detection views) will use runtime credentials, which may fail if DDL is restricted."
            );
        }

        // NAN-2001: build the two raw-SQL feature clients. FAIL BOOT if a
        // credential is missing (never fall back to the broad `nanosiem` client)
        // and if a client's granted table set drifts from the expected allowlist.
        let clickhouse_rawsql = Self::build_rawsql_client(
            config,
            &config.clickhouse_rawsql_user,
            &config.clickhouse_rawsql_password,
            "CLICKHOUSE_RAWSQL_PASSWORD",
            RAWSQL_ALLOWED_TABLES,
        )
        .await?;
        let clickhouse_rawsql_noaudit = Self::build_rawsql_client(
            config,
            &config.clickhouse_rawsql_noaudit_user,
            &config.clickhouse_rawsql_noaudit_password,
            "CLICKHOUSE_RAWSQL_NOAUDIT_PASSWORD",
            RAWSQL_NOAUDIT_ALLOWED_TABLES,
        )
        .await?;

        // NAN-2001 defense-in-depth: the noaudit identity is granted SELECT
        // declaratively, but audit-hiding depends on the RESTRICTIVE row policies
        // created by the migrator's `ensure_rawsql_row_policies`. When we have an
        // access-management admin client (api / jobs / migrator services — NOT the
        // search service, which has no admin and skips this), verify those
        // policies actually exist. This catches a version-skew deploy (a new app
        // booting before the current migrator ran the reconciler): the noaudit
        // user can't self-check them (`system.row_policies` needs a grant it lacks)
        // and the search service has no admin, but api/jobs boot from the same
        // DualPool and will fail the deploy visibly rather than silently leak audit.
        if using_admin {
            Self::assert_rawsql_row_policies_present(&clickhouse_admin, &config.clickhouse_database)
                .await?;
        }

        // Detect whether distributed tables exist (cluster mode)
        let is_clustered = clickhouse
            .query(&format!(
                "SELECT count() FROM system.tables WHERE database='{}' AND name='logs_distributed'",
                config.clickhouse_database
            ))
            .fetch_one::<u64>()
            .await
            .unwrap_or(0)
            > 0;

        if is_clustered {
            tracing::info!(
                "Detected clustered ClickHouse — will use distributed tables for queries"
            );
            // NAN-1728 (P1): unify the three cluster signals. `is_clustered`
            // (logs_distributed present), `detect_cluster()` (env or
            // system.clusters probe), and `on_cluster_clause()` (CLICKHOUSE_CLUSTER
            // env) MUST agree — otherwise runtime DDL built via on_cluster_clause
            // (GDPR erasure, retention MODIFY TTL, dict reload, KILL QUERY) runs on
            // ONE shard while reads route distributed, re-opening the exact
            // single-shard bugs this epic fixes. If a cluster is detected but
            // CLICKHOUSE_CLUSTER is unset (auto-detected via system.clusters, no
            // explicit env), resolve the authoritative name and set the env so
            // every env-reading helper converges with is_clustered()/detect_cluster().
            // Safe here: DualPool::new runs at early boot before request handling,
            // and edition 2021's set_var is not `unsafe` (matches crypto.rs /
            // migrations.rs boot-time env writes).
            Self::converge_cluster_env(&clickhouse).await;
        }

        tracing::info!(
            "Dual pool initialized - PostgreSQL: {} (max_conn: {}, min_conn: {}), ClickHouse: {}/{} (clustered: {})",
            Self::sanitize_url(&config.postgres_url),
            config.pg_max_connections,
            config.pg_min_connections,
            config.clickhouse_url,
            config.clickhouse_database,
            is_clustered,
        );

        let logs_table = if is_clustered {
            "logs_distributed"
        } else {
            "logs"
        };

        Ok(Self {
            postgres,
            clickhouse,
            clickhouse_admin,
            clickhouse_rawsql,
            clickhouse_rawsql_noaudit,
            is_clustered,
            logs_table,
        })
    }

    /// NAN-2001: build + verify a raw-SQL feature client, failing boot if the
    /// credential is missing (no fallback to the broad account) or if its granted
    /// table set has drifted from the expected allowlist.
    async fn build_rawsql_client(
        config: &DualPoolConfig,
        user: &str,
        password: &Option<String>,
        env_var: &str,
        allowed: &[&str],
    ) -> Result<ClickHouseClient, DualPoolError> {
        let password = password.as_ref().ok_or_else(|| {
            DualPoolError::ConfigError(format!(
                "{env_var} is required for the raw-SQL feature identity '{user}' (NAN-2001). \
                 Boot fails closed rather than falling back to the broad ClickHouse account. \
                 Set {env_var} to the password of the '{user}' ClickHouse user."
            ))
        })?;

        let mut client = ClickHouseClient::default()
            .with_url(&config.clickhouse_url)
            .with_database(&config.clickhouse_database)
            .with_user(user);
        if !password.is_empty() {
            client = client.with_password(password);
        }

        client
            .query("SELECT 1")
            .fetch_one::<u8>()
            .await
            .map_err(|e| {
                DualPoolError::ClickHouseConnectionError(format!(
                    "Failed to connect to ClickHouse as raw-SQL identity '{user}': {e}"
                ))
            })?;

        Self::assert_rawsql_grants(&client, user, allowed).await?;
        tracing::info!(
            "ClickHouse raw-SQL identity '{}' connected and grant-verified ({} allowlisted tables)",
            user,
            allowed.len()
        );
        Ok(client)
    }

    /// NAN-2001 grant drift guard. Read the current user's own SELECT grants and
    /// assert the normalized (`_local`/`_distributed`-stripped) `nanosiem.<table>`
    /// set is a SUBSET of `allowed` (no over-grant) and includes `logs`. This is
    /// the security property: the noaudit identity must never be granted the
    /// audit-baked aggregates, and neither identity may hold a whole-DB grant.
    async fn assert_rawsql_grants(
        client: &ClickHouseClient,
        user: &str,
        allowed: &[&str],
    ) -> Result<(), DualPoolError> {
        // `SHOW GRANTS` is always readable for the current user (no privilege
        // needed) — unlike `system.grants`, which a grant-only user cannot read.
        let grant_rows: Vec<String> = client
            .query("SHOW GRANTS")
            .fetch_all::<String>()
            .await
            .map_err(|e| {
                DualPoolError::ClickHouseConnectionError(format!(
                    "Could not read grants for raw-SQL identity '{user}' to verify the allowlist \
                     (NAN-2001): {e}"
                ))
            })?;

        // Capture BOTH the database and table token from each
        // `GRANT SELECT[(...)] ON <db>.<table>` line, so the guard rejects any
        // grant outside the `nanosiem` database (not just `nanosiem.*`) and any
        // whole-database grant — both are over-grants the allowlist must exclude.
        let re =
            regex::Regex::new(r"(?i)\bON\s+`?([A-Za-z0-9_*]+)`?\.`?([A-Za-z0-9_*]+)`?").unwrap();
        let mut normalized: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for row in &grant_rows {
            // Only SELECT grants define read access (skip dictGet / other privileges).
            if !row.to_uppercase().contains("GRANT SELECT") {
                continue;
            }
            let Some(caps) = re.captures(row) else {
                continue;
            };
            let db = &caps[1];
            let table = &caps[2];
            // Cross-database SELECT grant (incl. `*.*`) → over-grant, fail closed.
            if !db.eq_ignore_ascii_case("nanosiem") {
                return Err(DualPoolError::ConfigError(format!(
                    "raw-SQL identity '{user}' holds a SELECT grant outside the nanosiem database \
                     ('{db}.{table}', NAN-2001) — it must be granted SELECT only on the explicit \
                     nanosiem allowlist tables. Fix the grant declaration for this identity."
                )));
            }
            // Whole-database grant (`nanosiem.*`) → over-grant, fail closed.
            if table == "*" {
                return Err(DualPoolError::ConfigError(format!(
                    "raw-SQL identity '{user}' holds a whole-database SELECT grant on nanosiem.* \
                     (NAN-2001) — it must be granted SELECT only on the explicit allowlist tables. \
                     Fix the grant declaration for this identity."
                )));
            }
            let norm = table
                .trim_end_matches("_distributed")
                .trim_end_matches("_local")
                .to_string();
            normalized.insert(norm);
        }

        for t in &normalized {
            if !allowed.contains(&t.as_str()) {
                return Err(DualPoolError::ConfigError(format!(
                    "raw-SQL identity '{user}' is granted SELECT on 'nanosiem.{t}', which is NOT in \
                     its expected raw-SQL allowlist (NAN-2001). This is a security drift — refusing \
                     to boot. Reconcile the grant declaration (users.d XML / k8s tpl / nano-main)."
                )));
            }
        }
        if !normalized.contains("logs") {
            return Err(DualPoolError::ConfigError(format!(
                "raw-SQL identity '{user}' is not granted SELECT on nanosiem.logs (NAN-2001) — its \
                 grants did not load. Check the user's <grants> in the ClickHouse user config."
            )));
        }
        Ok(())
    }

    /// NAN-2001: verify (via an access-management admin client) that the
    /// RESTRICTIVE audit row policies for `nanosiem_rawsql_noaudit` exist. The
    /// short-names are created cluster-wide by the migrator's
    /// `ensure_rawsql_row_policies`; policies created `ON CLUSTER` are present in
    /// every node's access storage, so a single-node `system.row_policies` read is
    /// authoritative. Fails boot if any is missing (audit-hiding would be broken).
    async fn assert_rawsql_row_policies_present(
        admin: &ClickHouseClient,
        database: &str,
    ) -> Result<(), DualPoolError> {
        let names = RAWSQL_HIDE_POLICY_NAMES.join("', '");
        let found: u64 = admin
            .query(&format!(
                "SELECT count(DISTINCT short_name) FROM system.row_policies \
                 WHERE database = '{database}' AND short_name IN ('{names}')"
            ))
            .fetch_one()
            .await
            .map_err(|e| {
                DualPoolError::ClickHouseConnectionError(format!(
                    "Could not verify raw-SQL audit row policies via the admin client (NAN-2001): {e}"
                ))
            })?;

        let expected = RAWSQL_HIDE_POLICY_NAMES.len() as u64;
        if found < expected {
            return Err(DualPoolError::ConfigError(format!(
                "Only {found}/{expected} raw-SQL audit row policies exist in ClickHouse (NAN-2001). \
                 `nanosiem_rawsql_noaudit` is granted SELECT but the RESTRICTIVE \
                 `source_type != 'audit'` policies are missing — a noaudit raw-SQL caller could read \
                 audit rows. This means the ClickHouse migrator's `ensure_rawsql_row_policies` step \
                 has not run against this database (e.g. a version-skew deploy where the app started \
                 before the current migrator). Run the current ClickHouse migrator, then restart. \
                 Refusing to boot."
            )));
        }
        Ok(())
    }

    /// NAN-1728 (P1): converge `CLICKHOUSE_CLUSTER` with the detected cluster.
    /// Called from `new` only when a cluster is detected (logs_distributed
    /// present). If the env is already set (deploy provided it) we keep it; else
    /// we probe `system.clusters` for the authoritative name (same query +
    /// deterministic tiebreak as the migrator's `detect_cluster`) and set the env
    /// so `on_cluster_clause()` and every other env-reading helper fan runtime
    /// DDL out ON CLUSTER instead of running on a single shard.
    async fn converge_cluster_env(client: &ClickHouseClient) {
        let current = std::env::var("CLICKHOUSE_CLUSTER").ok();
        // Fast path: env already provides a usable name.
        if current.as_deref().map(str::trim).is_some_and(|v| !v.is_empty()) {
            tracing::info!(
                "Cluster mode: using CLICKHOUSE_CLUSTER='{}' (from env)",
                current.as_deref().unwrap_or("").trim()
            );
            return;
        }
        let probed: Option<String> = client
            .query(
                "SELECT cluster FROM system.clusters \
                 WHERE cluster NOT IN ('_all_databases', 'system') \
                 GROUP BY cluster HAVING count() > 1 \
                 ORDER BY count() DESC, cluster ASC LIMIT 1",
            )
            .fetch_all::<String>()
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next());

        match cluster_env_to_set(current.as_deref(), probed.as_deref()) {
            Some(name) => {
                std::env::set_var("CLICKHOUSE_CLUSTER", &name);
                tracing::info!(
                    "Cluster mode: resolved CLICKHOUSE_CLUSTER='{}' from system.clusters and set \
                     it (was unset) so runtime ON CLUSTER DDL fans out to all shards",
                    name
                );
            }
            None => {
                tracing::warn!(
                    "Cluster mode (logs_distributed present) but no multi-node cluster found in \
                     system.clusters and CLICKHOUSE_CLUSTER unset — runtime ON CLUSTER DDL will be \
                     NODE-LOCAL. Set CLICKHOUSE_CLUSTER to the operator's cluster name."
                );
            }
        }
    }

    /// Get a reference to the PostgreSQL connection pool
    pub fn postgres(&self) -> &PgPool {
        &self.postgres
    }

    /// Get a reference to the ClickHouse client
    pub fn clickhouse(&self) -> &ClickHouseClient {
        &self.clickhouse
    }

    /// Get a reference to the ClickHouse admin client for DDL operations
    ///
    /// This client has elevated permissions for CREATE/DROP operations.
    /// Use this for materialized view creation, schema changes, etc.
    pub fn clickhouse_admin(&self) -> &ClickHouseClient {
        &self.clickhouse_admin
    }

    /// NAN-2001: audit-capable raw-SQL client (`nanosiem_rawsql`). Read-only,
    /// SELECT only on the raw-SQL allowlist. Used for `POST /api/search/sql`
    /// (and dashboards SQL / meloD advanced validation) when the caller HAS
    /// `audit:view`.
    pub fn clickhouse_rawsql(&self) -> &ClickHouseClient {
        &self.clickhouse_rawsql
    }

    /// NAN-2001: audit-HIDDEN raw-SQL client (`nanosiem_rawsql_noaudit`). Carries
    /// the RESTRICTIVE `source_type!='audit'` row policy and a narrower grant
    /// set. Used (fail-closed default) when the caller LACKS `audit:view`, and
    /// always for reports.
    pub fn clickhouse_rawsql_noaudit(&self) -> &ClickHouseClient {
        &self.clickhouse_rawsql_noaudit
    }

    /// Whether this ClickHouse deployment has distributed tables (cluster mode).
    /// When true, queries should target `logs_distributed` instead of `logs`.
    pub fn is_clustered(&self) -> bool {
        self.is_clustered
    }

    /// The table name to use for log queries.
    /// Returns `"logs_distributed"` in cluster mode, `"logs"` otherwise.
    pub fn logs_table(&self) -> &'static str {
        self.logs_table
    }

    /// Get a TableNames resolver for this pool's cluster state.
    /// Use `.read("logs")` for SELECT queries, `.local("logs")` for DDL/mutations.
    pub fn table_names(&self) -> TableNames {
        TableNames::new(self.is_clustered)
    }

    /// Re-detect cluster state after migrations create distributed tables.
    /// Call this after `ensure_distributed_tables()` to pick up newly created tables.
    pub async fn refresh_cluster_state(&mut self, database: &str) {
        let is_clustered = self
            .clickhouse
            .query(&format!(
                "SELECT count() FROM system.tables WHERE database='{}' AND name='logs_distributed'",
                database
            ))
            .fetch_one::<u64>()
            .await
            .unwrap_or(0)
            > 0;

        if is_clustered && !self.is_clustered {
            tracing::info!(
                "Detected clustered ClickHouse after migrations — switching to distributed tables"
            );
        }

        self.is_clustered = is_clustered;
        self.logs_table = if is_clustered {
            "logs_distributed"
        } else {
            "logs"
        };
    }

    /// Check the health of both database connections
    ///
    /// Returns detailed status including latency metrics for both databases.
    /// This method tests both connections even if one fails, providing
    /// complete diagnostic information.
    pub async fn health_check(&self) -> HealthStatus {
        // Check PostgreSQL health
        let pg_start = Instant::now();
        let pg_result = sqlx::query("SELECT 1").execute(&self.postgres).await;
        let postgres_latency_ms = pg_start.elapsed().as_millis() as u64;

        let (postgres_healthy, postgres_error) = match pg_result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        // Check ClickHouse health
        let ch_start = Instant::now();
        let ch_result = self.clickhouse.query("SELECT 1").fetch_one::<u8>().await;
        let clickhouse_latency_ms = ch_start.elapsed().as_millis() as u64;

        let (clickhouse_healthy, clickhouse_error) = match ch_result {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e.to_string())),
        };

        HealthStatus {
            postgres_healthy,
            clickhouse_healthy,
            postgres_latency_ms,
            clickhouse_latency_ms,
            postgres_error,
            clickhouse_error,
        }
    }

    /// Close all connections in both pools
    pub async fn close(&self) {
        self.postgres.close().await;
        // ClickHouse client doesn't have an explicit close method
        // as it uses HTTP connections that are managed automatically
    }

    /// Sanitize a database URL for logging (removes password)
    fn sanitize_url(url: &str) -> String {
        // Simple sanitization - replace password in postgres URLs
        if let Some(at_pos) = url.find('@') {
            if let Some(colon_pos) = url[..at_pos].rfind(':') {
                let prefix = &url[..colon_pos + 1];
                let suffix = &url[at_pos..];
                return format!("{}****{}", prefix, suffix);
            }
        }
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DualPoolConfig::default();
        assert_eq!(config.postgres_url, "postgres://localhost/nanosiem");
        assert_eq!(config.clickhouse_url, "http://localhost:8123");
        assert_eq!(config.clickhouse_database, "nanosiem");
        assert_eq!(config.pg_max_connections, 20);
        assert_eq!(config.pg_min_connections, 2);
        assert_eq!(config.ch_max_connections, 10);
        assert_eq!(config.pg_idle_timeout_secs, 600);
        assert_eq!(config.pg_max_lifetime_secs, 1800);
        assert!(config.pg_test_before_acquire);
    }

    #[test]
    fn test_config_new() {
        let config = DualPoolConfig::new(
            "postgres://user:pass@host/db",
            "http://clickhouse:8123",
            "logs",
        );
        assert_eq!(config.postgres_url, "postgres://user:pass@host/db");
        assert_eq!(config.clickhouse_url, "http://clickhouse:8123");
        assert_eq!(config.clickhouse_database, "logs");
    }

    #[test]
    fn test_sanitize_url() {
        assert_eq!(
            DualPool::sanitize_url("postgres://user:secret@localhost/db"),
            "postgres://user:****@localhost/db"
        );
        assert_eq!(
            DualPool::sanitize_url("http://localhost:8123"),
            "http://localhost:8123"
        );
    }

    #[test]
    fn test_health_status_is_healthy() {
        let healthy = HealthStatus {
            postgres_healthy: true,
            clickhouse_healthy: true,
            postgres_latency_ms: 5,
            clickhouse_latency_ms: 3,
            postgres_error: None,
            clickhouse_error: None,
        };
        assert!(healthy.is_healthy());

        let unhealthy_pg = HealthStatus {
            postgres_healthy: false,
            clickhouse_healthy: true,
            postgres_latency_ms: 0,
            clickhouse_latency_ms: 3,
            postgres_error: Some("connection refused".to_string()),
            clickhouse_error: None,
        };
        assert!(!unhealthy_pg.is_healthy());

        let unhealthy_ch = HealthStatus {
            postgres_healthy: true,
            clickhouse_healthy: false,
            postgres_latency_ms: 5,
            clickhouse_latency_ms: 0,
            postgres_error: None,
            clickhouse_error: Some("timeout".to_string()),
        };
        assert!(!unhealthy_ch.is_healthy());
    }

    #[test]
    fn format_on_cluster_gates_on_cluster_name() {
        // Single-node / open-core (no cluster name) → no clause, so runtime DDL
        // is byte-identical to the pre-cluster form. A configured cluster → the
        // clause. Whitespace-only is treated as unset.
        assert_eq!(format_on_cluster(None), "");
        assert_eq!(format_on_cluster(Some("")), "");
        assert_eq!(format_on_cluster(Some("   ")), "");
        assert_eq!(
            format_on_cluster(Some("nanosiem_cluster")),
            " ON CLUSTER `nanosiem_cluster`"
        );
        // Trimmed.
        assert_eq!(
            format_on_cluster(Some("  nanosiem_cluster  ")),
            " ON CLUSTER `nanosiem_cluster`"
        );
    }

    #[test]
    fn cluster_env_to_set_converges_only_when_needed() {
        // Env already set → keep it (return None), regardless of probe.
        assert_eq!(cluster_env_to_set(Some("nanosiem_cluster"), Some("default")), None);
        assert_eq!(cluster_env_to_set(Some("  ncl  "), None), None);
        // Env unset/blank + a probed cluster → set the probed name (trimmed).
        assert_eq!(
            cluster_env_to_set(None, Some("nanosiem_cluster")),
            Some("nanosiem_cluster".to_string())
        );
        assert_eq!(
            cluster_env_to_set(Some(""), Some("  auto_cluster  ")),
            Some("auto_cluster".to_string())
        );
        assert_eq!(
            cluster_env_to_set(Some("   "), Some("c")),
            Some("c".to_string())
        );
        // Env unset AND nothing probed → nothing to converge (None).
        assert_eq!(cluster_env_to_set(None, None), None);
        assert_eq!(cluster_env_to_set(None, Some("   ")), None);
    }

    #[test]
    fn distributed_tables_membership_invariant() {
        // L-5/D9: the read-routing set and the reconciler's wrapper list are the
        // SAME canonical slice — they cannot drift.
        //
        // Reference tables get ADDITIVE read-only `_distributed` wrappers so
        // cross-shard reads see the complete scattered keyspace (the cluster-wide
        // replication rewrite was abandoned). They MUST be present.
        for t in [
            "custom_enrichment_results",
            "ip_enrichments",
            "user_registry",
            "lookup_rows",
        ] {
            assert!(
                DISTRIBUTED_TABLES.contains(&t),
                "{t} must be distributed so cross-shard reads see its full scattered keyspace"
            );
        }
        // The per-shard prevalence summaries MUST be present (C3/Lane L4).
        for t in [
            "hash_prevalence_summary",
            "domain_prevalence_summary",
            "ip_prevalence_summary",
        ] {
            assert!(
                DISTRIBUTED_TABLES.contains(&t),
                "{t} must be distributed so its uniqMerge summary fans across shards (C3)"
            );
        }
        // No duplicates.
        let mut seen = std::collections::HashSet::new();
        for t in DISTRIBUTED_TABLES {
            assert!(seen.insert(*t), "duplicate table in DISTRIBUTED_TABLES: {t}");
        }
    }

    #[test]
    fn table_names_routing_uses_canonical_list() {
        let clustered = TableNames::new(true);
        assert_eq!(clustered.read("logs"), "nanosiem.logs_distributed");
        assert_eq!(
            clustered.read("hash_prevalence_summary"),
            "nanosiem.hash_prevalence_summary_distributed"
        );
        // Reference table: additive read-only wrapper fans reads across shards.
        assert_eq!(
            clustered.read("custom_enrichment_results"),
            "nanosiem.custom_enrichment_results_distributed"
        );
        assert_eq!(
            clustered.read("ip_enrichments"),
            "nanosiem.ip_enrichments_distributed"
        );
        // DDL/mutation always local.
        assert_eq!(clustered.local("logs"), "nanosiem.logs");
        // Standalone: never routes.
        let standalone = TableNames::new(false);
        assert_eq!(standalone.read("logs"), "nanosiem.logs");
    }

    #[test]
    fn test_config_from_env_missing_postgres() {
        // Clear env vars
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("CLICKHOUSE_URL");

        let result = DualPoolConfig::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, DualPoolError::ConfigError(_)));
    }
}
