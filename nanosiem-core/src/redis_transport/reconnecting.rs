// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded recovery shared by search admission, cache and job coordination.
//! Never replay a command: a lost reply may already have mutated the backend.
use redis::{
    aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig},
    Client, RedisFuture, RedisResult, Value,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
pub const READINESS_GRACE: Duration = Duration::from_secs(15);

struct State {
    connection: Option<ConnectionManager>,
    generation: u64,
    supervised: bool,
    db: i64,
    unavailable_since: Option<Instant>,
}

#[derive(Clone)]
pub struct ReconnectingConnection(Arc<Mutex<State>>);

/// Compatibility for caller-owned managers. Production clients should use
/// `new(client)` so the supervisor retains the connection configuration.
impl From<ConnectionManager> for ReconnectingConnection {
    fn from(connection: ConnectionManager) -> Self {
        Self(Arc::new(Mutex::new(State {
            db: connection.get_db(),
            connection: Some(connection),
            generation: 0,
            supervised: false,
            unavailable_since: None,
        })))
    }
}

pub fn connection_config() -> ConnectionManagerConfig {
    ConnectionManagerConfig::new()
        .set_number_of_retries(0)
        .set_connection_timeout(Some(COMMAND_TIMEOUT))
        .set_response_timeout(Some(COMMAND_TIMEOUT))
}

impl ReconnectingConnection {
    /// Retain the client even when initially unavailable, so startup outages
    /// recover too. URL/TLS configuration validation remains with the caller.
    pub async fn new(client: Client) -> RedisResult<Self> {
        let db = client.get_connection_info().redis_settings().db();
        let connection = connect(client.clone()).await.ok();
        let unavailable_since = connection.is_none().then(Instant::now);
        let this = Self(Arc::new(Mutex::new(State {
            db,
            connection,
            generation: 0,
            supervised: true,
            unavailable_since,
        })));
        let weak = Arc::downgrade(&this.0);
        tokio::spawn(async move {
            let mut delay = Duration::from_millis(100);
            let mut backoff = Duration::from_millis(100);
            loop {
                // Do not keep a client alive solely for its recovery task.
                tokio::time::sleep(delay).await;
                let Some(state) = weak.upgrade() else { break };
                let mut handle = Self(state);
                let healthy = if handle.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).connection.is_some() {
                    redis::cmd("PING")
                        .query_async::<String>(&mut handle)
                        .await
                        .is_ok()
                } else {
                    false
                };
                if healthy {
                    delay = Duration::from_secs(1);
                    backoff = Duration::from_millis(100);
                    continue;
                }
                // A failed health check also replaces managers stuck on a
                // cached non-I/O reconnect error. Ordinary command errors
                // (notably NOSCRIPT) must not interrupt SCRIPT LOAD recovery.
                {
                    let mut state = handle.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    state.connection = None;
                    state.generation += 1;
                    state.unavailable_since.get_or_insert_with(Instant::now);
                }
                match connect(client.clone()).await {
                    Ok(connection) => {
                        let mut state = handle.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.connection = Some(connection);
                        state.generation += 1;
                        state.unavailable_since = None;
                        tracing::info!(
                            reason = "redis_backend_recovered",
                            "search Redis connection recovered"
                        );
                        delay = Duration::from_millis(100);
                        backoff = Duration::from_millis(100);
                    }
                    Err(_) => {
                        let mut state = handle.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.connection = None;
                        state.unavailable_since.get_or_insert_with(Instant::now);
                        delay = backoff;
                        backoff = (backoff * 2).min(Duration::from_secs(2));
                    }
                }
            }
        });
        Ok(this)
    }

    pub fn ready(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unavailable_since
            .is_none_or(|since| since.elapsed() < READINESS_GRACE)
    }

    fn snapshot(&self) -> RedisResult<(ConnectionManager, u64)> {
        let state = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .connection
            .clone()
            .map(|conn| (conn, state.generation))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "search Redis backend unavailable",
                )
                .into()
            })
    }

    fn observe<T>(&self, generation: u64, result: &RedisResult<T>) {
        let mut state = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.generation != generation {
            return;
        }
        if result
            .as_ref()
            .is_err_and(|error| error.is_io_error() || error.is_unrecoverable_error())
        {
            if state.supervised {
                state.connection = None;
                state.generation += 1;
            }
            state.unavailable_since.get_or_insert_with(Instant::now);
        } else if result.is_ok() {
            state.unavailable_since = None;
        }
    }
}

async fn connect(client: Client) -> RedisResult<ConnectionManager> {
    tokio::time::timeout(COMMAND_TIMEOUT, async {
        let mut connection =
            ConnectionManager::new_with_config(client, connection_config()).await?;
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await?;
        Ok(connection)
    })
    .await
    .unwrap_or_else(|_| Err(timeout_error()))
}

fn timeout_error() -> redis::RedisError {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "search Redis command timed out",
    )
    .into()
}

impl ConnectionLike for ReconnectingConnection {
    fn req_packed_command<'a>(&'a mut self, cmd: &'a redis::Cmd) -> RedisFuture<'a, Value> {
        Box::pin(async move {
            let (mut conn, generation) = self.snapshot()?;
            let result = tokio::time::timeout(COMMAND_TIMEOUT, conn.req_packed_command(cmd))
                .await
                .unwrap_or_else(|_| Err(timeout_error()));
            self.observe(generation, &result);
            result
        })
    }
    fn req_packed_commands<'a>(
        &'a mut self,
        cmd: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> RedisFuture<'a, Vec<Value>> {
        Box::pin(async move {
            let (mut conn, generation) = self.snapshot()?;
            let result = tokio::time::timeout(
                COMMAND_TIMEOUT,
                conn.req_packed_commands(cmd, offset, count),
            )
            .await
            .unwrap_or_else(|_| Err(timeout_error()));
            self.observe(generation, &result);
            result
        })
    }
    fn get_db(&self) -> i64 {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).db
    }
}
