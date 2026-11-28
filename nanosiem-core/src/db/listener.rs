// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL `LISTEN` sessions outside the service's connection pool
//! (NAN-5957).
//!
//! `sqlx::postgres::PgListener::connect_with(&pool)` takes a connection from
//! `pool` and keeps it for as long as the listener lives, which for the
//! notification listeners (`case_changes`, `license_status_changed`,
//! `agentlane_config`) is the whole life of the process. The PostgreSQL
//! sizing (NAN-5822, `PG_APP_DEDICATED_SESSIONS` in resource-sizing.sh and
//! `DEDICATED_PER_POD` in the Helm budget test) already budgets these
//! listeners as sessions OUTSIDE the pools, but the code took them from the
//! pools. On a small install (jobs pool of 4, api pool of 3) that left nano-jobs
//! 2 connections and nano-api 1 for all other work, and v2.0.36's new
//! background work (the Agent Lane harvester, the risk page cache) and the
//! new `agentlane_config` listener in nano-api tipped both into constant
//! "pool timed out" errors.
//!
//! [`dedicated_listener`] opens the listener on its own one-connection pool
//! built from the service pool's connect options (same host, credentials and
//! TLS), so a listener never takes a connection the service's queries need.
//! The listener's own reconnect logic keeps working: it re-acquires from its
//! private pool.

use std::time::Duration;

use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::PgPool;

/// How long opening the listener's session may take before the caller's
/// retry loop takes over.
const LISTENER_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A one-connection pool for a listener, from `pool`'s connect options. Lazy:
/// no connection opens until the listener asks for one.
pub fn dedicated_listener_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .min_connections(0)
        .acquire_timeout(LISTENER_CONNECT_TIMEOUT)
        // A listener session is meant to live as long as the process; the
        // pool must not retire it under the listener.
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_lazy_with((*pool.connect_options()).clone())
}

/// A [`PgListener`] on its own PostgreSQL session, outside `pool`. Use it for
/// every long-lived `LISTEN` instead of `PgListener::connect_with(pool)`.
pub async fn dedicated_listener(pool: &PgPool) -> Result<PgListener, sqlx::Error> {
    PgListener::connect_with(&dedicated_listener_pool(pool)).await
}

/// How long a listener waits for a notification before it checks that its
/// session is still alive.
pub const LISTENER_KEEPALIVE: Duration = Duration::from_secs(300);

/// Check a listener's session with a round trip on the same connection
/// (NAN-5957 review). An idle listener behind a NAT or stateful firewall can
/// lose its TCP connection silently; a keepalive that drops and reopens the
/// listener instead would hold two sessions for a moment. A failed ping
/// means the caller reconnects.
pub async fn ping(listener: &mut PgListener) -> Result<(), sqlx::Error> {
    bounded_ping(sqlx::query("SELECT 1").execute(&mut *listener), LISTENER_PING_TIMEOUT).await
}

/// How long a keepalive ping may take. A blackholed TCP connection (no RST,
/// no answer) would otherwise hang the ping until the kernel gives up, about
/// 15 minutes (NAN-5957 review r2).
pub const LISTENER_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// A ping that does not answer within `limit` fails with an `Io(TimedOut)`
/// error, so the caller reconnects (with its backoff).
async fn bounded_ping<F, T>(ping: F, limit: Duration) -> Result<(), sqlx::Error>
where
    F: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    match tokio::time::timeout(limit, ping).await {
        Ok(result) => result.map(|_| ()),
        Err(_) => Err(sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("listener keepalive ping did not answer within {}s", limit.as_secs()),
        ))),
    }
}

/// Exponential backoff for a listener's reconnect loop: 1 s doubling to 60 s.
pub fn next_backoff(current: Duration) -> Duration {
    (current * 2).clamp(Duration::from_secs(1), Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_ping_that_never_answers_fails_after_the_timeout() {
        let started = tokio::time::Instant::now();
        let hung = std::future::pending::<Result<(), sqlx::Error>>();
        let err = bounded_ping(hung, LISTENER_PING_TIMEOUT).await.expect_err("a hung ping fails");
        assert!(matches!(&err, sqlx::Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut), "{err:?}");
        assert_eq!(started.elapsed(), LISTENER_PING_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn a_ping_that_answers_passes_and_errors_pass_through() {
        assert!(bounded_ping(async { Ok::<_, sqlx::Error>(()) }, LISTENER_PING_TIMEOUT).await.is_ok());
        let err = bounded_ping(async { Err::<(), _>(sqlx::Error::PoolClosed) }, LISTENER_PING_TIMEOUT).await;
        assert!(matches!(err, Err(sqlx::Error::PoolClosed)));
    }

    #[test]
    fn backoff_doubles_to_a_minute() {
        let mut b = Duration::from_secs(1);
        let mut seen = vec![];
        for _ in 0..8 {
            b = next_backoff(b);
            seen.push(b.as_secs());
        }
        assert_eq!(seen, [2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[tokio::test]
    async fn the_listener_pool_holds_exactly_one_session_that_never_expires() {
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .unwrap();
        let listener_pool = dedicated_listener_pool(&pool);
        let options = listener_pool.options();
        assert_eq!(options.get_max_connections(), 1);
        assert_eq!(options.get_min_connections(), 0);
        assert_eq!(options.get_idle_timeout(), None);
        assert_eq!(options.get_max_lifetime(), None);
        // Separate pools: nothing the listener holds counts against `pool`.
        assert_eq!(pool.size(), 0);
        assert_eq!(listener_pool.size(), 0, "lazy until the listener connects");
    }
}
