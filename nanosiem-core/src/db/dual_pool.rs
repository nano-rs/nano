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

/// Tables that have `_distributed` variants created by `ensure_distributed_tables()`.
const DISTRIBUTED_TABLE_SET: &[&str] = &[
    "logs",
    // OCSF canonical log table (NAN-1241). Listed so cluster-mode read routing
    // (`ocsf_logs_distributed`) applies identically to the UDM `logs` table when
    // the active schema profile is OCSF.
    "ocsf_logs",
    "signals",
    "domain_prevalence_agg",
    "hash_prevalence_agg",
    "ip_prevalence_agg",
    "entity_time_range_agg",
    "cloud_user_activity_agg",
    "ingestion_errors",
    "custom_enrichment_results",
    "identity_observations",
    "logs_per_source_5m",
];

impl TableNames {
    /// Create a new TableNames resolver.
    pub fn new(is_clustered: bool) -> Self {
        Self { is_clustered }
    }

    /// Fully qualified table name for **read** queries (SELECT).
    /// Returns `nanosiem.{table}_distributed` in cluster mode for tables that have
    /// distributed variants, `nanosiem.{table}` otherwise.
    pub fn read(&self, table: &str) -> String {
        if self.is_clustered && DISTRIBUTED_TABLE_SET.contains(&table) {
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
        if self.is_clustered && DISTRIBUTED_TABLE_SET.contains(&table) {
            format!("{}_distributed", table)
        } else {
            table.to_string()
        }
    }

    pub fn is_clustered(&self) -> bool {
        self.is_clustered
    }
}

#[derive(Clone)]
pub struct DualPool {
    postgres: PgPool,
    clickhouse: ClickHouseClient,
    /// Admin client for DDL operations (CREATE/DROP views, etc.)
    /// Falls back to regular client if admin credentials not configured
    clickhouse_admin: ClickHouseClient,
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
            is_clustered,
            logs_table,
        })
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
