// SPDX-License-Identifier: AGPL-3.0-or-later

//! Product database pools and connection-cap observations.

use sqlx::{postgres::PgPoolOptions, PgConnection};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct ConnectionUsage {
    pub database: String,
    pub connections: i64,
    pub database_connections: i64,
    pub max_connections: i64,
    pub reserved_connections: i64,
}

impl ConnectionUsage {
    pub fn at_warning_threshold(&self) -> bool {
        self.connections * 5 >= self.max_connections * 4
    }
}

pub async fn read_connection_usage(
    connection: &mut PgConnection,
) -> Result<ConnectionUsage, sqlx::Error> {
    sqlx::query_as(
        "SELECT current_database()::text AS database, \
         count(*)::bigint AS connections, \
         count(*) FILTER (WHERE datname = current_database())::bigint AS database_connections, \
         current_setting('max_connections')::bigint AS max_connections, \
         current_setting('superuser_reserved_connections')::bigint AS reserved_connections \
         FROM pg_catalog.pg_stat_activity",
    ).fetch_one(connection).await
}

/// [`ConnectionUsage`] plus the sampling session's `application_name`, the
/// pool label of the gauges below. Kept apart so `ConnectionUsage`'s
/// serialized shape (pipeline health) is unchanged.
#[derive(sqlx::FromRow)]
struct PoolConnectionUsage {
    #[sqlx(flatten)]
    usage: ConnectionUsage,
    application_name: String,
}

async fn read_pool_connection_usage(
    connection: &mut PgConnection,
) -> Result<(ConnectionUsage, String), sqlx::Error> {
    let row: PoolConnectionUsage = sqlx::query_as(
        "SELECT current_database()::text AS database, \
         count(*)::bigint AS connections, \
         count(*) FILTER (WHERE datname = current_database())::bigint AS database_connections, \
         current_setting('max_connections')::bigint AS max_connections, \
         current_setting('superuser_reserved_connections')::bigint AS reserved_connections, \
         current_setting('application_name')::text AS application_name \
         FROM pg_catalog.pg_stat_activity",
    ).fetch_one(connection).await?;
    Ok((row.usage, row.application_name))
}

/// The `pool` label: the pool's `application_name`, `product` when unset
/// (the same fallback the refusal warnings use).
fn pool_label(application_name: &str) -> String {
    let name = application_name.trim();
    if name.is_empty() { "product".to_owned() } else { name.to_owned() }
}

/// The gauges published from one usage sample (NAN-3531 N2b): server-wide
/// sessions in use, the server cap, and sessions on this pool's database.
fn usage_gauges(usage: &ConnectionUsage) -> [(&'static str, f64); 3] {
    [
        ("nanosiem_pg_connections_in_use", usage.connections as f64),
        ("nanosiem_pg_max_connections", usage.max_connections as f64),
        ("nanosiem_pg_database_connections", usage.database_connections as f64),
    ]
}

/// Publish a sample on `/metrics`, labelled by pool. Called from the existing
/// at-most-every-30-s sample taken when a pooled session is released, so it
/// adds no query of its own.
fn record_usage_gauges(usage: &ConnectionUsage, application_name: &str) {
    let pool = pool_label(application_name);
    for (name, value) in usage_gauges(usage) {
        metrics::gauge!(name, "pool" => pool.clone()).set(value);
    }
}

pub fn is_connection_refusal(code: Option<&str>) -> bool {
    matches!(code, Some("53300" | "57P03"))
}

pub fn warn_connect_refusal(error: &sqlx::Error, application_name: &str) {
    let code = error.as_database_error().and_then(|error| error.code());
    if is_connection_refusal(code.as_deref()) {
        static WARNED: std::sync::OnceLock<Mutex<std::collections::BTreeSet<String>>> =
            std::sync::OnceLock::new();
        if !WARNED
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(application_name.to_owned())
        {
            return;
        }
        tracing::warn!(pool = application_name, sqlstate = code.as_deref(),
            "product database refused a new connection: N/max_connections unavailable (session refused before authentication)");
    }
}

pub fn pool_options(max_connections: u32) -> PgPoolOptions {
    pool_options_with_idle_retention(max_connections, Arc::new(AtomicBool::new(true)))
}

pub fn pool_options_with_idle_retention(
    max_connections: u32,
    retain_idle: Arc<AtomicBool>,
) -> PgPoolOptions {
    let warned = Arc::new(AtomicBool::new(false));
    let last_usage = Arc::new(Mutex::new(None::<(ConnectionUsage, Instant)>));
    let sample = Arc::clone(&last_usage);
    PgPoolOptions::new()
        .min_connections(0)
        .max_connections(max_connections)
        .idle_timeout(Duration::from_secs(15))
        .max_lifetime(Duration::from_secs(1800))
        .after_release(move |connection, _| {
            let sample = Arc::clone(&sample);
            let retain_idle = Arc::clone(&retain_idle);
            Box::pin(async move {
                if !retain_idle.load(Ordering::Acquire) {
                    return Ok(false);
                }
                let due = sample.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref()
                    .is_none_or(|(_, when)| when.elapsed() >= Duration::from_secs(30));
                if due {
                    if let Ok(Ok((usage, application_name))) = tokio::time::timeout(
                        Duration::from_millis(250), read_pool_connection_usage(connection),
                    ).await {
                        record_usage_gauges(&usage, &application_name);
                        *sample.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some((usage, Instant::now()));
                    }
                }
                Ok(true)
            })
        })
        .on_connect_error(move |pool, error| {
            let warned = Arc::clone(&warned);
            let last_usage = Arc::clone(&last_usage);
            Box::pin(async move {
                let code = error.as_database_error().and_then(|error| error.code());
                if !is_connection_refusal(code.as_deref()) || warned.swap(true, Ordering::Relaxed) {
                    return;
                }
                // Never open a diagnostic connection when the server is full.
                let usage = if let Some(mut connection) = pool.try_acquire() {
                    tokio::time::timeout(Duration::from_secs(1), read_connection_usage(&mut connection))
                        .await.ok().and_then(Result::ok).map(|usage| (usage, Instant::now()))
                } else {
                    None
                }.or_else(|| last_usage.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone());
                let options = pool.connect_options();
                if let Some((usage, sampled_at)) = usage {
                    tracing::warn!(pool = options.get_application_name().unwrap_or("product"), role = options.get_username(), sqlstate = code.as_deref(),
                        database_connections = usage.database_connections, reserved_connections = usage.reserved_connections, sample_age_seconds = sampled_at.elapsed().as_secs(),
                        "product database refused a new connection: {}/{} max_connections in use", usage.connections, usage.max_connections);
                } else {
                    tracing::warn!(pool = options.get_application_name().unwrap_or("product"), role = options.get_username(), sqlstate = code.as_deref(),
                        "product database refused a new connection: N/max_connections unavailable (no readable idle session); connection cap or database startup refusal");
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_exclude_authentication_and_query_errors() {
        assert!(is_connection_refusal(Some("53300")));
        assert!(is_connection_refusal(Some("57P03")));
        for code in [None, Some("28P01"), Some("40001"), Some("42501")] {
            assert!(!is_connection_refusal(code));
        }
    }

    /// NAN-3531 N2b: one sample publishes the three pool gauges, labelled
    /// by the pool's application_name (`product` when unset).
    #[test]
    fn usage_sample_maps_to_pool_gauges() {
        let usage = ConnectionUsage {
            database: "product".into(),
            connections: 41,
            database_connections: 17,
            max_connections: 50,
            reserved_connections: 3,
        };
        assert_eq!(
            usage_gauges(&usage),
            [
                ("nanosiem_pg_connections_in_use", 41.0),
                ("nanosiem_pg_max_connections", 50.0),
                ("nanosiem_pg_database_connections", 17.0),
            ]
        );
        assert_eq!(pool_label("nanosiem-search"), "nanosiem-search");
        assert_eq!(pool_label(""), "product");
        assert_eq!(pool_label("  "), "product");
        // Recording without an installed recorder is a no-op, never a panic.
        record_usage_gauges(&usage, "nanosiem-search");
    }

    #[test]
    fn health_warns_at_eighty_percent_of_server_cap() {
        let mut usage = ConnectionUsage {
            database: "product".into(),
            connections: 39,
            database_connections: 20,
            max_connections: 50,
            reserved_connections: 3,
        };
        assert!(!usage.at_warning_threshold());
        usage.connections = 40;
        assert!(usage.at_warning_threshold());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn connect_refusals_are_reported_once_before_pool_timeout() {
        use std::io::Write;
        use std::sync::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[derive(Clone)]
        struct Logs(Arc<Mutex<Vec<u8>>>);
        impl Write for Logs {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for code in ["53300", "57P03"] {
            let logs = Logs(Arc::new(Mutex::new(Vec::new())));
            let writer = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            let _subscriber = tracing::subscriber::set_default(subscriber);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = Arc::clone(&attempts);
            let server = tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let length = socket.read_u32().await.unwrap();
                    let mut startup = vec![0; length as usize - 4];
                    socket.read_exact(&mut startup).await.unwrap();
                    observed.fetch_add(1, Ordering::Relaxed);
                    let body = format!("SFATAL\0C{code}\0Mconnection refused\0\0");
                    socket.write_u8(b'E').await.unwrap();
                    socket.write_u32(body.len() as u32 + 4).await.unwrap();
                    socket.write_all(body.as_bytes()).await.unwrap();
                }
            });
            let pool = pool_options(1)
                .acquire_timeout(Duration::from_millis(250))
                .connect_lazy(&format!(
                    "postgres://fixture@{address}/fixture?sslmode=disable"
                ))
                .unwrap();
            assert_eq!(pool.size(), 0);
            assert!(matches!(
                pool.acquire().await,
                Err(sqlx::Error::PoolTimedOut)
            ));
            assert!(attempts.load(Ordering::Relaxed) > 1);
            let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            assert_eq!(
                output
                    .matches("product database refused a new connection:")
                    .count(),
                1,
                "{output}"
            );
            assert!(output.contains(code));
            pool.close().await;
            server.abort();
        }
    }

    #[tokio::test]
    #[ignore = "requires an explicitly assigned local TEST_DATABASE_URL"]
    async fn sequential_attestations_release_sessions_then_runtime_reaps_idle() {
        let url = std::env::var("TEST_DATABASE_URL").unwrap();
        let retain = Arc::new(AtomicBool::new(false));
        let mut pools = Vec::new();
        for _ in 0..12 {
            let pool = pool_options_with_idle_retention(1, Arc::clone(&retain))
                .idle_timeout(Duration::from_millis(100))
                .connect_lazy(&url)
                .unwrap();
            assert_eq!(pool.size(), 0);
            let mut connection = pool.acquire().await.unwrap();
            let usage = read_connection_usage(&mut connection).await.unwrap();
            assert!(usage.max_connections > 0);
            assert!(usage.connections > 1, "include sessions hidden from a narrow role");
            let (pooled, _application_name) = read_pool_connection_usage(&mut connection).await.unwrap();
            assert_eq!(pooled.max_connections, usage.max_connections);
            drop(connection);
            tokio::time::timeout(Duration::from_secs(3), async {
                while pool.size() != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            pools.push(pool);
        }
        retain.store(true, Ordering::Release);
        sqlx::query("SELECT 1").execute(&pools[0]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while pools[0].size() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        for pool in pools {
            pool.close().await;
        }
    }
}
