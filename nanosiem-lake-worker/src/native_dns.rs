// SPDX-License-Identifier: AGPL-3.0-or-later

//! Keep embedded chDB's DNS cache from pinning a dead object-store address
//! (NAN-3391).
//!
//! ClickHouse resolves every S3/HTTP endpoint through a process-wide DNS
//! cache that has no TTL. `clickhouse-server` keeps it fresh with a background
//! task (`dns_cache_update_period`, 15 s). Embedded chDB never starts that
//! task, so the first address a worker resolved for an endpoint stays cached
//! until the process exits.
//!
//! On the open-core Compose install, recreating `lake-object-store` (a RustFS
//! upgrade) gives the container a new bridge IP. Every later object read from
//! the query worker still dials the old IP. ClickHouse's S3 client retries that
//! up to `s3_retry_attempts` (500) times with up to 5 s backoff, so the native
//! lane blocks. Native cancellation is unsupported, and the 120 s watchdog
//! (budget + hard grace + cancel grace) exited the worker so that a fresh
//! process could re-resolve the name.
//!
//! The fix restores the server's behaviour inside the worker:
//! * while any executor is open, one process-wide thread runs
//!   `SYSTEM DROP DNS CACHE` on its own chDB connection every few seconds. Because it does not share a lane, it also
//!   runs while a lane is blocked in a retry loop, and that loop's next
//!   attempt then resolves the current address;
//! * a lane that fails a statement with a connection-level error drops the
//!   cache at once, so the next statement re-resolves and does not wait for
//!   the next tick.
//!
//! Dropping the cache does not close pooled keep-alive connections. Only new
//! connections resolve again, so a stable endpoint (R2 on the hosted cells)
//! pays one cached resolver lookup per new connection.

use crate::native::{NativeChdb, NativeConnection};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

/// The statement that clears chDB's process-wide host-to-address cache.
pub const DROP_DNS_CACHE_SQL: &str = "SYSTEM DROP DNS CACHE";

/// The default refresh period. It is shorter than the server's 15 s because
/// a stalled interactive query in the worker costs a search, not a
/// background merge.
const DEFAULT_REFRESH: Duration = Duration::from_secs(5);

/// `NANO_CHDB_DNS_REFRESH_SECONDS`: the refresh period in seconds (1..=3600).
/// `0` disables the periodic refresher. The drop after a failed statement
/// stays on. An unset or invalid value uses the 5 s default.
pub fn refresh_period() -> Option<Duration> {
    parse_refresh_period(std::env::var("NANO_CHDB_DNS_REFRESH_SECONDS").ok().as_deref())
}

fn parse_refresh_period(value: Option<&str>) -> Option<Duration> {
    match value.map(str::trim).map(str::parse::<u64>) {
        Some(Ok(0)) => None,
        Some(Ok(seconds)) if seconds <= 3600 => Some(Duration::from_secs(seconds)),
        _ => Some(DEFAULT_REFRESH),
    }
}

/// Whether a failed statement's error means the object-store endpoint could
/// not be reached: a resolve failure, a refused, reset or unroutable
/// connection, or a socket timeout. HTTP status errors from a reachable store
/// (403, 404, 503) are not included.
pub fn is_connection_error(message: &str) -> bool {
    const MARKERS: &[&str] = &[
        "DNS_ERROR",
        "Not found address of host",
        "Connection refused",
        "Connection reset",
        "No route to host",
        "Host is unreachable",
        "Network is unreachable",
        "Broken pipe",
        "NETWORK_ERROR",
        "SOCKET_TIMEOUT",
        "Timeout: connect timed out",
        "connect timed out",
        "Poco::Exception. Code: 1000",
    ];
    MARKERS.iter().any(|marker| message.contains(marker))
}

/// Drop chDB's DNS cache on `connection`. The statement is executor-owned
/// maintenance and must not carry the read lane's `readonly=2`.
pub fn drop_dns_cache(connection: &NativeConnection) -> Result<(), crate::native::NativeChdbError> {
    connection.query_with_params(DROP_DNS_CACHE_SQL, "Null", &[]).map(|_| ())
}

/// A share of the process-wide refresher. Every live [`crate::executor::NativeExecutor`]
/// holds one. The refresher thread and its chDB connection exist only while a
/// lease does. When the last lease drops, the thread closes its connection
/// before the drop returns, so the refresher never keeps the embedded engine
/// (and the server settings it started with) alive after the executors close.
pub struct RefresherLease {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for RefresherLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefresherLease").finish_non_exhaustive()
    }
}

impl Drop for RefresherLease {
    fn drop(&mut self) {
        let (stopped, wake) = &*self.stop;
        *stopped.lock().unwrap_or_else(|e| e.into_inner()) = true;
        wake.notify_all();
        if let Some(thread) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = thread.join();
        }
    }
}

static ACTIVE: Mutex<Weak<RefresherLease>> = Mutex::new(Weak::new());

/// Join the running refresher, or start one. Call it only after an executor
/// lane has opened its connection: the first `chdb_connect` fixes the engine's
/// server settings, and the refresher connects with the same
/// `connection_args`. Returns `None` when the refresher is disabled or its
/// thread cannot start. The drop after a failed statement still applies then.
pub fn lease_refresher(runtime: &NativeChdb, connection_args: &Arc<[String]>) -> Option<Arc<RefresherLease>> {
    let period = refresh_period()?;
    let mut active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(lease) = active.upgrade() {
        return Some(lease);
    }
    let stop = Arc::new((Mutex::new(false), Condvar::new()));
    let thread = {
        let (runtime, connection_args, stop) = (runtime.clone(), connection_args.clone(), stop.clone());
        std::thread::Builder::new()
            .name("nano-chdb-dns".into())
            .spawn(move || refresh_loop(runtime, connection_args, period, stop))
    };
    match thread {
        Ok(thread) => {
            let lease = Arc::new(RefresherLease { stop, thread: Mutex::new(Some(thread)) });
            *active = Arc::downgrade(&lease);
            Some(lease)
        }
        Err(error) => {
            tracing::warn!(error = %error, "chDB DNS cache refresher could not start; \
                a moved object-store address is re-resolved only after a failed statement");
            None
        }
    }
}

/// Wait one period. Returns `false` once the last lease has dropped.
fn wait_period(stop: &(Mutex<bool>, Condvar), period: Duration) -> bool {
    let (stopped, wake) = stop;
    let guard = stopped.lock().unwrap_or_else(|e| e.into_inner());
    let (guard, _) = wake
        .wait_timeout_while(guard, period, |stopped| !*stopped)
        .unwrap_or_else(|e| e.into_inner());
    !*guard
}

fn refresh_loop(runtime: NativeChdb, connection_args: Arc<[String]>, period: Duration, stop: Arc<(Mutex<bool>, Condvar)>) {
    #[cfg(target_os = "linux")]
    if let Err(error) = nanosiem_lake_cell::crash_capture::register_thread() {
        eprintln!("lake_native_crash alternate stack registration failed: {error}");
    }
    let args = connection_args.iter().map(String::as_str).collect::<Vec<_>>();
    let mut connection: Option<NativeConnection> = None;
    let mut failing = false;
    while wait_period(&stop, period) {
        // One connect and one statement per period: a broken engine costs one
        // attempt per period, never a hot loop.
        if connection.is_none() {
            connection = match runtime.connect(&args) {
                Ok(connection) => Some(connection),
                Err(error) => {
                    if !failing {
                        tracing::warn!(error = %error, "chDB DNS cache refresher could not connect; retrying next period");
                    }
                    failing = true;
                    continue;
                }
            };
        }
        let Some(open) = connection.as_ref() else { continue };
        match drop_dns_cache(open) {
            Ok(()) => {
                if failing {
                    tracing::info!("chDB DNS cache refresher recovered");
                }
                failing = false;
            }
            Err(error) => {
                if !failing {
                    tracing::warn!(error = %error, "chDB DNS cache refresh failed; reopening its connection next period");
                }
                failing = true;
                // Never reuse a chDB connection after a failed statement (NAN-3046).
                connection = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_period_defaults_disables_and_bounds() {
        assert_eq!(parse_refresh_period(None), Some(DEFAULT_REFRESH));
        assert_eq!(parse_refresh_period(Some("0")), None);
        assert_eq!(parse_refresh_period(Some(" 2 ")), Some(Duration::from_secs(2)));
        assert_eq!(parse_refresh_period(Some("3600")), Some(Duration::from_secs(3600)));
        assert_eq!(parse_refresh_period(Some("3601")), Some(DEFAULT_REFRESH));
        assert_eq!(parse_refresh_period(Some("soon")), Some(DEFAULT_REFRESH));
    }

    #[test]
    fn connection_errors_are_told_apart_from_store_answers() {
        // Verbatim libchdb 26.7 messages from the NAN-3391 reproduction.
        assert!(is_connection_error(
            "Code: 499. DB::Exception: Failed to get object info: Poco::Exception. Code: 1000, \
             e.code() = 111, Connection refused (version 26.7.2.1). (S3_ERROR)"
        ));
        assert!(is_connection_error(
            "Code: 499. DB::Exception: Code: 198. DB::NetException: Not found address of host: store. (DNS_ERROR)"
        ));
        assert!(is_connection_error("Code: 209. DB::NetException: Timeout exceeded while reading from socket (SOCKET_TIMEOUT)"));
        assert!(!is_connection_error(
            "Code: 499. DB::Exception: Failed to get object info: No response body.. HTTP response code: 403. \
             Please check your AWS credentials and permissions (S3_ERROR)"
        ));
        assert!(!is_connection_error("Code: 241. DB::Exception: Memory limit (total) exceeded (MEMORY_LIMIT_EXCEEDED)"));
        assert!(!is_connection_error("Code: 62. DB::Exception: Syntax error (SYNTAX_ERROR)"));
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "native_dns_restart_tests.rs"]
mod restart_tests;
