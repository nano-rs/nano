// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential-guessing throttle for local password sign-in and the MFA code
//! step (NAN-5149 / NAN-5150 / NAN-5066).
//!
//! Three independent bounds, all stored in the shared `rate_limit_buckets`
//! table so every API replica enforces the same budget:
//!
//! 1. **(account, source IP) lock.** `threshold` failures for one email from
//!    one address lock that pair for `lock_secs`. The attacker's address is
//!    locked; the real user on another address is not. Attempts are reserved
//!    BEFORE verification (one atomic upsert), so concurrent requests cannot
//!    all verify against an unlocked pair.
//! 2. **Per-account progressive delay.** Failures for one email across every
//!    address add a delay before verification (1 s doubling to a cap), never
//!    a hard lock, so knowing an administrator's email is not enough to lock
//!    them out. Crossing [`ACCOUNT_ALERT_THRESHOLD`] is reported once per
//!    episode (audit + health finding).
//! 3. **Per-IP spraying** stays with the `login_ip` request limiter.
//!
//! Every key is the normalised email STRING, never a user id: unknown emails
//! accrue state, delays and locks exactly like existing ones, so none of this
//! reveals which accounts exist (NAN-5066).

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use sqlx::PgPool;

/// `rate_limit_buckets.category` for the (account, IP) lock.
pub const CATEGORY_ACCOUNT_IP: &str = "login_lock_acct_ip";
/// `rate_limit_buckets.category` for the per-account delay counter.
pub const CATEGORY_ACCOUNT: &str = "login_delay_acct";
/// `rate_limit_buckets.category` for the per-account delay RESERVATION. Its
/// `window_start` holds the next instant an attempt for the email may be
/// verified, so the delay is enforced by one atomic reservation rather than a
/// read-then-sleep (which concurrency defeats).
pub const CATEGORY_ACCOUNT_SLOT: &str = "login_delay_slot";
/// `rate_limit_buckets.category` for per-MFA-challenge code attempts.
pub const CATEGORY_MFA_CHALLENGE: &str = "login_mfa_challenge";

/// Account-wide failures (across all addresses) before the delay starts.
pub const ACCOUNT_DELAY_START: i32 = 5;
/// Upper bound on the per-account delay.
pub const ACCOUNT_DELAY_MAX_SECS: u64 = 30;
/// How far ahead a reserved verification slot may be and still be waited out.
/// Beyond this the attempt is rejected generically without verifying, so a
/// burst cannot pin worker tasks sleeping. 5 s is below the delay cap, so an
/// honest user whose slot lands within it still gets verified.
pub const ACCOUNT_DELAY_HORIZON_SECS: u64 = 5;
/// Account-wide failures that raise one audit event and health finding.
pub const ACCOUNT_ALERT_THRESHOLD: i32 = 20;
/// The account-wide counter resets after this long without a failure.
pub const ACCOUNT_WINDOW_SECS: i64 = 3600;
/// MFA challenge tokens live 300 s; their attempt counter needs no longer.
pub const MFA_CHALLENGE_WINDOW_SECS: i64 = 300;
/// Once the reserved slot has drained this far into the past, the attempt
/// tally that drives the delay tier resets, so a quiet email starts fresh
/// (no residual delay for an honest user after a burst ends).
pub const ACCOUNT_SLOT_IDLE_SECS: i64 = 60;

/// `system_health_events.dedup_key` for distributed guessing. One key for
/// every email: the bus holds one grouped condition (one notification per
/// lifecycle), so guessing against many emails cannot flood it. The audit
/// trail names each email.
pub const GUESSING_DEDUP_KEY: &str = "auth:login_guessing";

/// Normalise an email for throttle keys: trimmed, lowercased.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// Canonical rate-limit key for a source address, so trivial rewrites of the
/// same origin share one bucket:
/// - an unparseable or missing address becomes `"unknown"`;
/// - an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) becomes its IPv4 form;
/// - an IPv6 address is reduced to its `/64` prefix (the smallest block a
///   host is normally assigned), compressed — otherwise a single `/64` gives
///   an attacker 2^64 distinct keys to rotate through;
/// - an IPv4 address is its canonical form.
pub fn canonical_ip_key(ip: Option<&str>) -> String {
    let Some(parsed) = ip.and_then(|s| s.trim().parse::<IpAddr>().ok()) else {
        return "unknown".to_string();
    };
    match parsed {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                // Zero the low 64 bits and tag the prefix length so a /64 key
                // can never collide with a full address.
                let mut octets = v6.octets();
                octets[8..].fill(0);
                format!("{}/64", Ipv6Addr::from(octets))
            }
        },
    }
}

/// Key for the (account, IP) bucket. A newline cannot appear in either part
/// of a real request, so prefix matching on `"<email>\n"` is exact. The
/// address is canonicalised ([`canonical_ip_key`]) so a `/64` rotation cannot
/// multiply an attacker's lock budget.
pub fn account_ip_key(email: &str, ip: Option<&str>) -> String {
    format!("{}\n{}", normalize_email(email), canonical_ip_key(ip))
}

/// Reference for the delay the SQL reservation applies at attempt tally
/// `tally` (the `tally`-th attempt for the email in the current burst): none
/// up to [`ACCOUNT_DELAY_START`], then doubling to [`ACCOUNT_DELAY_MAX_SECS`].
/// The live path computes this in SQL; this mirror exists for tests.
pub fn account_delay(tally: i32) -> Duration {
    if tally <= ACCOUNT_DELAY_START {
        return Duration::ZERO;
    }
    let exp = (tally - ACCOUNT_DELAY_START).min(16) as u32;
    Duration::from_secs(2u64.saturating_pow(exp).min(ACCOUNT_DELAY_MAX_SECS))
}

/// Outcome of reserving one attempt in a lock bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The attempt may be verified. `locks_on_failure` is true when this
    /// reservation was the one that reached the threshold: a failure here is
    /// the single fresh lock to report.
    Allowed { locks_on_failure: bool },
    /// The bucket is locked: reject without verifying.
    Locked,
}

/// Postgres-backed throttle state (see the module docs).
#[derive(Clone)]
pub struct LoginThrottle {
    pool: PgPool,
}

impl LoginThrottle {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Reserve one attempt in a lock bucket. A bucket holds at most
    /// `threshold` attempts per `window_secs`; the reservation that reaches
    /// the threshold restarts the window, so the lock lasts a full
    /// `window_secs` from that attempt. `ON CONFLICT DO UPDATE ... WHERE`
    /// evaluates against the latest row version under its row lock, so
    /// concurrent reservations never exceed the threshold.
    pub async fn claim(
        &self,
        category: &str,
        key: &str,
        threshold: i32,
        window_secs: i64,
    ) -> Result<Claim, sqlx::Error> {
        let row: Option<(i32,)> = sqlx::query_as(
            r#"
            INSERT INTO rate_limit_buckets (category, key, tokens, window_start)
            VALUES ($1, $2, 1, NOW())
            ON CONFLICT (category, key) DO UPDATE SET
                tokens = CASE
                    WHEN rate_limit_buckets.window_start < NOW() - make_interval(secs => $4::float8)
                        THEN 1
                    ELSE rate_limit_buckets.tokens + 1
                END,
                window_start = CASE
                    WHEN rate_limit_buckets.window_start < NOW() - make_interval(secs => $4::float8)
                        THEN NOW()
                    WHEN rate_limit_buckets.tokens + 1 >= $3 THEN NOW()
                    ELSE rate_limit_buckets.window_start
                END
            WHERE rate_limit_buckets.tokens < $3
               OR rate_limit_buckets.window_start < NOW() - make_interval(secs => $4::float8)
            RETURNING tokens
            "#,
        )
        .bind(category)
        .bind(key)
        .bind(threshold)
        .bind(window_secs as f64)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some((tokens,)) => Claim::Allowed {
                locks_on_failure: tokens >= threshold,
            },
            None => Claim::Locked,
        })
    }

    /// Give back a reservation after the password step succeeded for an MFA
    /// account. The bucket is not cleared: a correct password must not refill
    /// the code budget. It is capped at `threshold - 1`, so the challenge
    /// always gets at least one code attempt from this address.
    pub async fn refund(&self, category: &str, key: &str, threshold: i32) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE rate_limit_buckets
               SET tokens = LEAST(GREATEST(tokens - 1, 0), GREATEST($3 - 1, 0))
             WHERE category = $1 AND key = $2
            "#,
        )
        .bind(category)
        .bind(key)
        .bind(threshold)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Forget a bucket (successful sign-in).
    pub async fn clear(&self, category: &str, key: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM rate_limit_buckets WHERE category = $1 AND key = $2")
            .bind(category)
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Atomically reserve the next verification slot for `email` and return
    /// how long the caller must wait for it.
    ///
    /// One statement, keyed on the email string, does three things under the
    /// row lock so concurrency cannot defeat it:
    /// - tally this attempt in the current burst (`tokens`), resetting the
    ///   tally once the backlog has drained and the email has been quiet for
    ///   [`ACCOUNT_SLOT_IDLE_SECS`];
    /// - compute the delay tier from the post-increment tally (mirrors
    ///   [`account_delay`]: none up to [`ACCOUNT_DELAY_START`], then doubling
    ///   to [`ACCOUNT_DELAY_MAX_SECS`]);
    /// - advance the reserved instant `next_allowed_at = GREATEST(now,
    ///   next_allowed_at) + delay` and return `next_allowed_at - now`.
    ///
    /// `next_allowed_at` is stored in `window_start`. N concurrent attempts
    /// are therefore handed N distinct, increasing slots, not one shared
    /// delay they all wake from together. An honest sign-in (tally 1) reserves
    /// `now` and waits nothing; an unknown email reserves exactly like a real
    /// one (no existence oracle).
    pub async fn reserve_account_slot(&self, email: &str) -> Result<Duration, sqlx::Error> {
        let reserved_in_secs: f64 = sqlx::query_scalar(
            r#"
            INSERT INTO rate_limit_buckets (category, key, tokens, window_start)
            VALUES ($1, $2, 1, NOW())
            ON CONFLICT (category, key) DO UPDATE SET
                tokens = LEAST(
                    1000000,
                    CASE
                        WHEN rate_limit_buckets.window_start
                             < NOW() - make_interval(secs => $5::float8)
                            THEN 1
                        ELSE rate_limit_buckets.tokens + 1
                    END
                ),
                window_start = GREATEST(
                    NOW(),
                    CASE
                        WHEN rate_limit_buckets.window_start
                             < NOW() - make_interval(secs => $5::float8)
                            THEN NOW()
                        ELSE rate_limit_buckets.window_start
                    END
                ) + make_interval(secs => (
                    CASE
                        WHEN (CASE
                                WHEN rate_limit_buckets.window_start
                                     < NOW() - make_interval(secs => $5::float8)
                                    THEN 1
                                ELSE rate_limit_buckets.tokens + 1
                              END) <= $3
                            THEN 0::float8
                        ELSE LEAST(
                            $4::float8,
                            2::float8 ^ LEAST(
                                (CASE
                                    WHEN rate_limit_buckets.window_start
                                         < NOW() - make_interval(secs => $5::float8)
                                        THEN 1
                                    ELSE rate_limit_buckets.tokens + 1
                                  END) - $3,
                                16
                            )
                        )
                    END
                ))
            RETURNING EXTRACT(EPOCH FROM (window_start - NOW()))::float8
            "#,
        )
        .bind(CATEGORY_ACCOUNT_SLOT)
        .bind(normalize_email(email))
        .bind(ACCOUNT_DELAY_START)
        .bind(ACCOUNT_DELAY_MAX_SECS as f64)
        .bind(ACCOUNT_SLOT_IDLE_SECS as f64)
        .fetch_one(&self.pool)
        .await?;
        Ok(Duration::from_secs_f64(reserved_in_secs.max(0.0)))
    }

    /// Record one account-wide failure; returns the new count. The window
    /// slides: it resets after [`ACCOUNT_WINDOW_SECS`] without a failure.
    pub async fn record_account_failure(&self, email: &str) -> Result<i32, sqlx::Error> {
        let (tokens,): (i32,) = sqlx::query_as(
            r#"
            INSERT INTO rate_limit_buckets (category, key, tokens, window_start)
            VALUES ($1, $2, 1, NOW())
            ON CONFLICT (category, key) DO UPDATE SET
                tokens = CASE
                    WHEN rate_limit_buckets.window_start < NOW() - make_interval(secs => $3::float8)
                        THEN 1
                    ELSE rate_limit_buckets.tokens + 1
                END,
                window_start = NOW()
            RETURNING tokens
            "#,
        )
        .bind(CATEGORY_ACCOUNT)
        .bind(normalize_email(email))
        .bind(ACCOUNT_WINDOW_SECS as f64)
        .fetch_one(&self.pool)
        .await?;
        Ok(tokens)
    }

    /// Forget every throttle bucket for `email`: every (account, IP) lock and
    /// the account-wide delay. Used by a successful full sign-in (delay only;
    /// see the caller) and by the administrator unlock.
    pub async fn clear_account(&self, email: &str) -> Result<(), sqlx::Error> {
        clear_account_in(&self.pool, email).await
    }
}

/// [`LoginThrottle::clear_account`] on any executor (the admin unlock runs it
/// inside its own transaction).
pub async fn clear_account_in<'e, E>(executor: E, email: &str) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    let email = normalize_email(email);
    sqlx::query(
        r#"
        DELETE FROM rate_limit_buckets
         WHERE (category = ANY($1) AND key = $3)
            OR (category = $2 AND starts_with(key, $3 || E'\n'))
        "#,
    )
    .bind(vec![
        CATEGORY_ACCOUNT.to_string(),
        CATEGORY_ACCOUNT_SLOT.to_string(),
    ])
    .bind(CATEGORY_ACCOUNT_IP)
    .bind(email)
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "login_throttle_tests.rs"]
mod tests;
