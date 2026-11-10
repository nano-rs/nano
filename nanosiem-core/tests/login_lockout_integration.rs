// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sign-in throttle (NAN-5149 / NAN-5150 / NAN-5066), and the NAN-1622
//! invariant that a lock is signalled exactly once per crossing.
//!
//! The throttle locks an (email, source address) pair after repeated
//! failures, slows every attempt for an email across all addresses with a
//! capped delay (never a hard account lock), keys everything on the email
//! STRING so unknown emails behave identically, and covers the MFA code step.
//!
//! Gated like the other DB suites: compiles with every `cargo test` but is
//! `#[ignore]`d — run via the `pg-integration-tests` CI job, or locally against
//! a throwaway Postgres with `cargo test -- --ignored`.

mod common;

use std::time::{Duration, Instant};

use nanosiem_core::auth::login_throttle::{
    self, account_ip_key, ACCOUNT_DELAY_MAX_SECS, CATEGORY_ACCOUNT, CATEGORY_ACCOUNT_IP,
};
use nanosiem_core::auth::repository::{
    GroupRepository, PrincipalAction, SessionRepository, UserRepository,
};
use nanosiem_core::auth::{
    encrypt_backup_codes, encrypt_secret, generate_totp_secret, hash_backup_codes,
    hash_password, AuthConfig, AuthError, AuthService, GrantAuthorityStamp, LoginResult,
    TokenConfig, TokenService,
};
use nanosiem_core::crypto::EncryptionService;
use nanosiem_core::settings::local_auth::LocalAuthSettings;
use sqlx::PgPool;
use uuid::Uuid;

const PASSWORD: &str = "correct-horse-battery-staple";
const IP_A: &str = "198.51.100.10";
const IP_B: &str = "203.0.113.20";

fn threshold() -> i32 {
    AuthConfig::default().lockout_threshold
}

async fn create_active_user(pool: &PgPool, password: &str) -> (Uuid, String) {
    let id = Uuid::now_v7();
    let email = format!("lockout-{id}@example.com");
    let hash = hash_password(password).expect("hash password");
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Lockout Test', $3, 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(&email)
    .bind(&hash)
    .execute(pool)
    .await
    .expect("create user");
    (id, email)
}

/// `tokens` of a throttle bucket, if it exists.
async fn bucket(pool: &PgPool, category: &str, key: &str) -> Option<i32> {
    sqlx::query_scalar("SELECT tokens FROM rate_limit_buckets WHERE category = $1 AND key = $2")
        .bind(category)
        .bind(key)
        .fetch_optional(pool)
        .await
        .expect("read bucket")
}

fn auth_service(pool: PgPool) -> AuthService {
    let token_service = TokenService::new(TokenConfig::new(
        "test-jwt-secret-not-for-production-32+chars".to_string(),
    ));
    AuthService::new(
        UserRepository::new(pool.clone()),
        SessionRepository::new(pool.clone()),
        GroupRepository::new(pool.clone()),
        token_service,
        AuthConfig::default(),
        // NAN-2181 added this parameter; these tests exercise the password
        // path, which the default (local sign-in enabled) leaves reachable.
        LocalAuthSettings::new(pool.clone()),
    )
}

fn is_generic_failure(err: &AuthError) -> bool {
    matches!(
        err,
        AuthError::InvalidCredentials | AuthError::LoginThrottled { .. }
    )
}

/// Fail `n` times for `email` from `ip`.
async fn fail(svc: &AuthService, email: &str, ip: &str, n: i32) {
    for _ in 0..n {
        let err = svc
            .login(email, "wrong-password", Some(ip), None)
            .await
            .expect_err("wrong password must fail");
        assert!(is_generic_failure(&err), "{err:?}");
    }
}

/// NAN-1622: the crossing attempt is signalled exactly once; later attempts
/// in the window return the plain generic error.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn lock_signaled_once_on_threshold_crossing() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool);

    for attempt in 1..threshold() {
        let err = svc
            .login(&email, "wrong-password", Some(IP_A), None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, AuthError::InvalidCredentials),
            "attempt {attempt} (< threshold): {err:?}"
        );
    }
    let crossing = svc
        .login(&email, "wrong-password", Some(IP_A), None)
        .await
        .unwrap_err();
    assert!(
        matches!(
            crossing,
            AuthError::LoginThrottled {
                ip_locked: true,
                account_alert: false
            }
        ),
        "{crossing:?}"
    );
    let after = svc
        .login(&email, "wrong-password", Some(IP_A), None)
        .await
        .unwrap_err();
    assert!(matches!(after, AuthError::InvalidCredentials), "{after:?}");
}

/// THE scenario: guessing from address A locks A only. The real user signs
/// in from address B, delayed by at most the cap, never locked out.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn attacker_address_is_locked_while_the_user_signs_in_from_another() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool.clone());

    fail(&svc, &email, IP_A, threshold() + 3).await;
    assert_eq!(
        bucket(&pool, CATEGORY_ACCOUNT_IP, &account_ip_key(&email, Some(IP_A))).await,
        Some(threshold()),
        "locked attempts are not counted"
    );

    // From A even the right password is refused, generically.
    let err = svc
        .login(&email, PASSWORD, Some(IP_A), None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials), "{err:?}");

    // From B the user gets in, within the capped delay.
    let started = Instant::now();
    let ok = svc
        .login(&email, PASSWORD, Some(IP_B), None)
        .await
        .expect("the user on another address is not locked out");
    assert!(matches!(ok, LoginResult::Success(_)));
    assert!(started.elapsed() <= Duration::from_secs(ACCOUNT_DELAY_MAX_SECS + 2));
    // The success clears B and the account-wide delay, but A stays locked.
    assert_eq!(bucket(&pool, CATEGORY_ACCOUNT, &email).await, None);
    assert!(svc.login(&email, PASSWORD, Some(IP_A), None).await.is_err());
}

/// The (email, address) lock is bounded: after the window the right password
/// works from that address again.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn address_lock_recovers_after_window() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool.clone());

    fail(&svc, &email, IP_A, threshold()).await;
    assert!(svc.login(&email, PASSWORD, Some(IP_A), None).await.is_err());

    // Simulate the window elapsing.
    sqlx::query(
        "UPDATE rate_limit_buckets SET window_start = NOW() - make_interval(secs => $3::float8 + 1) \
         WHERE category = $1 AND key = $2",
    )
    .bind(CATEGORY_ACCOUNT_IP)
    .bind(account_ip_key(&email, Some(IP_A)))
    .bind(AuthConfig::default().lockout_duration as f64)
    .execute(&pool)
    .await
    .unwrap();

    let ok = svc
        .login(&email, PASSWORD, Some(IP_A), None)
        .await
        .expect("login must succeed once the lock window has passed");
    assert!(matches!(ok, LoginResult::Success(_)));
    assert_eq!(
        bucket(&pool, CATEGORY_ACCOUNT_IP, &account_ip_key(&email, Some(IP_A))).await,
        None
    );
}

/// A successful sign-in resets the counters, so earlier failures do not
/// carry into a later lock.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn successful_login_resets_counters() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool.clone());

    fail(&svc, &email, IP_A, threshold() - 1).await;
    assert!(matches!(
        svc.login(&email, PASSWORD, Some(IP_A), None).await,
        Ok(LoginResult::Success(_))
    ));
    fail(&svc, &email, IP_A, threshold() - 1).await;
    assert!(matches!(
        svc.login(&email, PASSWORD, Some(IP_A), None).await,
        Ok(LoginResult::Success(_))
    ));
}

/// NAN-5066: an unknown email gets the same response and the same delay
/// curve as an existing one, because state is keyed on the email string.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn unknown_email_matches_existing_account_response_and_delay() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let unknown = format!("nobody-{}@example.com", Uuid::now_v7());
    let svc = auth_service(pool.clone());

    // Distinct addresses, so the account-wide delay (not the address lock)
    // is what grows. Attempts 6 and 7 are delayed 1 s and 2 s.
    for attempt in 1..=threshold() + 2 {
        let ip = format!("192.0.2.{attempt}");
        let t = Instant::now();
        let unknown_err = svc.login(&unknown, "wrong-password", Some(&ip), None).await.unwrap_err();
        let unknown_elapsed = t.elapsed();
        let t = Instant::now();
        let known_err = svc.login(&email, "wrong-password", Some(&ip), None).await.unwrap_err();
        let known_elapsed = t.elapsed();

        assert_eq!(
            std::mem::discriminant(&unknown_err),
            std::mem::discriminant(&known_err),
            "attempt {attempt}: {unknown_err:?} vs {known_err:?}"
        );
        assert!(is_generic_failure(&known_err));
        let expected = login_throttle::account_delay(attempt);
        for (who, elapsed) in [("unknown", unknown_elapsed), ("known", known_elapsed)] {
            assert!(
                elapsed >= expected,
                "attempt {attempt}: {who} took {elapsed:?}, expected at least {expected:?}"
            );
        }
        let diff = known_elapsed.abs_diff(unknown_elapsed);
        assert!(
            diff < Duration::from_millis(750),
            "attempt {attempt}: known {known_elapsed:?} vs unknown {unknown_elapsed:?}"
        );
    }
    assert_eq!(
        bucket(&pool, CATEGORY_ACCOUNT, &unknown).await,
        bucket(&pool, CATEGORY_ACCOUNT, &email).await
    );
}

/// Concurrent guesses from one address cannot all verify against an
/// unlocked pair: exactly one crossing signal, counter stops at threshold.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn concurrent_guesses_capped_at_threshold() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = std::sync::Arc::new(auth_service(pool.clone()));

    let mut handles = Vec::new();
    for _ in 0..20 {
        let svc = svc.clone();
        let email = email.clone();
        handles.push(tokio::spawn(async move {
            svc.login(&email, "wrong-password", Some(IP_A), None).await
        }));
    }
    let mut lock_signals = 0;
    for h in handles {
        if matches!(
            h.await.unwrap(),
            Err(AuthError::LoginThrottled { ip_locked: true, .. })
        ) {
            lock_signals += 1;
        }
    }
    assert_eq!(lock_signals, 1, "exactly one fresh-lock signal");
    assert_eq!(
        bucket(&pool, CATEGORY_ACCOUNT_IP, &account_ip_key(&email, Some(IP_A))).await,
        Some(threshold())
    );
    // Only verified attempts count toward the account-wide delay.
    assert_eq!(bucket(&pool, CATEGORY_ACCOUNT, &email).await, Some(threshold()));
}

/// The administrator unlock clears every address lock and the delay.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn admin_unlock_clears_throttle_state() {
    let pool = common::migrated_pool().await;
    let (id, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool.clone());

    fail(&svc, &email, IP_A, threshold()).await;
    fail(&svc, &email, IP_B, 1).await;
    assert!(svc.login(&email, PASSWORD, Some(IP_A), None).await.is_err());
    assert!(bucket(&pool, CATEGORY_ACCOUNT, &email).await.is_some());

    let version: i64 =
        sqlx::query_scalar("SELECT version FROM grant_authority_version WHERE singleton = TRUE")
            .fetch_one(&pool)
            .await
            .unwrap();
    UserRepository::new(pool.clone())
        .apply_principal_action_authorized(id, PrincipalAction::Unlock, GrantAuthorityStamp::new(version))
        .await
        .expect("unlock");

    for ip in [IP_A, IP_B] {
        assert_eq!(bucket(&pool, CATEGORY_ACCOUNT_IP, &account_ip_key(&email, Some(ip))).await, None);
    }
    assert_eq!(bucket(&pool, CATEGORY_ACCOUNT, &email).await, None);
    let t = Instant::now();
    assert!(matches!(
        svc.login(&email, PASSWORD, Some(IP_A), None).await,
        Ok(LoginResult::Success(_))
    ));
    assert!(t.elapsed() < Duration::from_secs(1), "no delay after unlock");
}

// === MFA (NAN-5150) ===

fn test_encryption() -> EncryptionService {
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    EncryptionService::from_config(
        &serde_json::json!({"version": 1, "active": "k1", "keys": [{"id": "k1", "key": key}]})
            .to_string(),
    )
    .expect("test key ring")
}

/// Create an active user with MFA enabled; returns (email, base32 secret).
async fn create_mfa_user(pool: &PgPool, enc: &EncryptionService) -> (String, String) {
    let (id, email) = create_active_user(pool, PASSWORD).await;
    let (_totp, secret) = generate_totp_secret(&email).unwrap();
    let (totp_ct, totp_nonce) = encrypt_secret(&secret, enc).unwrap().to_bytea().unwrap();
    let backup = hash_backup_codes(&["AAAA2222".to_string()]);
    let (bk_ct, bk_nonce) = encrypt_backup_codes(&backup, enc).unwrap().to_bytea().unwrap();
    UserRepository::new(pool.clone())
        .enable_mfa(id, &totp_ct, &totp_nonce, &bk_ct, &bk_nonce)
        .await
        .unwrap();
    (email, secret)
}

fn current_code(secret: &str, email: &str) -> String {
    nanosiem_core::auth::totp_from_secret(secret, email)
        .unwrap()
        .generate_current()
        .unwrap()
}

/// A code that is not valid now (TOTP skew 1 accepts neighbours, so pick one
/// that matches none of them).
fn wrong_code(secret: &str, email: &str) -> String {
    let totp = nanosiem_core::auth::totp_from_secret(secret, email).unwrap();
    (0u32..)
        .map(|n| format!("{n:06}"))
        .find(|c| !totp.check_current(c).unwrap())
        .unwrap()
}

async fn challenge(svc: &AuthService, email: &str, ip: &str) -> Result<String, AuthError> {
    match svc.login(email, PASSWORD, Some(ip), None).await? {
        LoginResult::MfaRequired { challenge_token } => Ok(challenge_token),
        _ => panic!("expected an MFA challenge"),
    }
}

/// N bad codes from one address lock that (email, address) pair and revoke
/// the challenge; the user still completes MFA from another address.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn mfa_bad_codes_lock_the_address_and_revoke_the_challenge() {
    let pool = common::migrated_pool().await;
    let enc = test_encryption();
    let (email, secret) = create_mfa_user(&pool, &enc).await;
    let svc = auth_service(pool.clone());

    let token = challenge(&svc, &email, IP_A).await.unwrap();
    let bad = wrong_code(&secret, &email);
    for attempt in 1..threshold() {
        let err = svc
            .complete_mfa_login(&token, &bad, &enc, Some(IP_A), None)
            .await
            .err()
            .expect("bad code must fail");
        assert!(matches!(err, AuthError::InvalidCredentials), "attempt {attempt}: {err:?}");
    }
    let crossing = svc
        .complete_mfa_login(&token, &bad, &enc, Some(IP_A), None)
        .await
        .err()
        .expect("crossing code must fail");
    assert!(
        matches!(crossing, AuthError::LoginThrottled { ip_locked: true, .. }),
        "{crossing:?}"
    );

    // The challenge is burned: even the right code no longer redeems it.
    let after = svc
        .complete_mfa_login(&token, &current_code(&secret, &email), &enc, Some(IP_A), None)
        .await
        .err()
        .expect("revoked challenge must fail");
    assert!(matches!(after, AuthError::InvalidToken), "{after:?}");
    // Address A is locked for the password step too.
    assert!(challenge(&svc, &email, IP_A).await.is_err());

    // From B: a fresh challenge and a valid code complete sign-in.
    let token_b = challenge(&svc, &email, IP_B).await.expect("B is not locked");
    let done = svc
        .complete_mfa_login(&token_b, &current_code(&secret, &email), &enc, Some(IP_B), None)
        .await
        .unwrap_or_else(|e| panic!("valid code from another address must succeed: {e:?}"));
    assert!(!done.used_backup_code);
    assert_eq!(bucket(&pool, CATEGORY_ACCOUNT, &email).await, None);
}

/// One challenge cannot be guessed from many addresses: its own budget
/// revokes it after N bad codes, whatever their source.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn mfa_challenge_budget_holds_across_addresses() {
    let pool = common::migrated_pool().await;
    let enc = test_encryption();
    let (email, secret) = create_mfa_user(&pool, &enc).await;
    let svc = auth_service(pool.clone());

    let token = challenge(&svc, &email, IP_A).await.unwrap();
    let bad = wrong_code(&secret, &email);
    for i in 0..threshold() {
        let ip = format!("192.0.2.{}", 100 + i);
        assert!(svc
            .complete_mfa_login(&token, &bad, &enc, Some(&ip), None)
            .await
            .is_err());
    }
    let err = svc
        .complete_mfa_login(&token, &current_code(&secret, &email), &enc, Some("192.0.2.200"), None)
        .await
        .err()
        .expect("spent challenge must fail");
    assert!(matches!(err, AuthError::InvalidToken), "{err:?}");
}

/// Re-entering the password does not refill this address's code budget.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn mfa_failures_accumulate_across_challenges_from_one_address() {
    let pool = common::migrated_pool().await;
    let enc = test_encryption();
    let (email, secret) = create_mfa_user(&pool, &enc).await;
    let svc = auth_service(pool.clone());
    let bad = wrong_code(&secret, &email);

    let mut last = None;
    for _ in 0..threshold() {
        let token = challenge(&svc, &email, IP_A).await.expect("password step while unlocked");
        last = svc.complete_mfa_login(&token, &bad, &enc, Some(IP_A), None).await.err();
    }
    assert!(
        matches!(last, Some(AuthError::LoginThrottled { ip_locked: true, .. })),
        "the threshold-th code failure (across challenges) must lock the address: {last:?}"
    );
    assert!(challenge(&svc, &email, IP_A).await.is_err(), "address locked");
}

/// A valid code inside the limit still completes sign-in and clears state.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn mfa_valid_code_within_limit_succeeds() {
    let pool = common::migrated_pool().await;
    let enc = test_encryption();
    let (email, secret) = create_mfa_user(&pool, &enc).await;
    let svc = auth_service(pool.clone());

    fail(&svc, &email, IP_A, 2).await;
    let token = challenge(&svc, &email, IP_A).await.unwrap();
    let bad = wrong_code(&secret, &email);
    for _ in 0..threshold() - 3 {
        assert!(svc.complete_mfa_login(&token, &bad, &enc, Some(IP_A), None).await.is_err());
    }
    let done = svc
        .complete_mfa_login(&token, &current_code(&secret, &email), &enc, Some(IP_A), None)
        .await
        .unwrap_or_else(|e| panic!("valid code within the limit must succeed: {e:?}"));
    assert!(!done.used_backup_code);
    assert_eq!(
        bucket(&pool, CATEGORY_ACCOUNT_IP, &account_ip_key(&email, Some(IP_A))).await,
        None
    );
    assert_eq!(bucket(&pool, CATEGORY_ACCOUNT, &email).await, None);
}

/// Reaching the account-wide alert threshold is signalled once (for the
/// `login_account_throttled` audit) and published to the health bus.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored (waits the 30 s delay cap)"]
async fn account_alert_threshold_signals_once_and_publishes_health_event() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool.clone());

    // Seed the account-wide counter one short of the alert threshold, as if
    // the failures had come from many addresses.
    sqlx::query(
        "INSERT INTO rate_limit_buckets (category, key, tokens, window_start) VALUES ($1, $2, $3, NOW())",
    )
    .bind(CATEGORY_ACCOUNT)
    .bind(&email)
    .bind(login_throttle::ACCOUNT_ALERT_THRESHOLD - 1)
    .execute(&pool)
    .await
    .unwrap();

    let err = svc
        .login(&email, "wrong-password", Some(IP_A), None)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            AuthError::LoginThrottled {
                ip_locked: false,
                account_alert: true
            }
        ),
        "{err:?}"
    );
    let published: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM system_health_events \
         WHERE dedup_key = $1 AND status = 'active' AND resource_name = $2",
    )
    .bind(login_throttle::GUESSING_DEDUP_KEY)
    .bind(&email)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(published, 1);
    // Past the threshold the account is still only delayed, never locked:
    // the right password from a fresh address works.
    assert!(matches!(
        svc.login(&email, PASSWORD, Some(IP_B), None).await,
        Ok(LoginResult::Success(_))
    ));
}

/// NAN-5149 review (1): a burst of concurrent wrong passwords for one email,
/// from many distinct addresses, cannot all be verified. The per-email
/// reserved-slot delay (atomic, so concurrency does not defeat it) pushes
/// later reservations past the horizon, where they are rejected without a
/// bcrypt. Only verified failures increment the account-wide counter, so its
/// value is the number actually verified.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn concurrent_burst_from_many_addresses_bounds_verifications() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = std::sync::Arc::new(auth_service(pool.clone()));

    let mut handles = Vec::new();
    for i in 0..50u32 {
        let svc = svc.clone();
        let email = email.clone();
        // 50 distinct /24s, so the (email, address) lock never engages and
        // the per-email slot is the only thing bounding verifications.
        let ip = format!("198.51.{}.{}", i / 10, i % 10 + 1);
        handles.push(tokio::spawn(async move {
            svc.login(&email, "wrong-password", Some(&ip), None).await
        }));
    }
    let mut completed = 0;
    for h in handles {
        let err = h.await.unwrap().expect_err("wrong password must fail");
        assert!(is_generic_failure(&err), "{err:?}");
        completed += 1;
    }
    assert_eq!(completed, 50);

    // Verified failures (the only ones that increment the account counter)
    // are a small bounded number, not all 50.
    let verified = bucket(&pool, CATEGORY_ACCOUNT, &email).await.unwrap_or(0);
    assert!(
        verified <= login_throttle::ACCOUNT_DELAY_START + 3,
        "expected a small bounded number of verifications, got {verified}"
    );
}

/// NAN-5149 review (2): every address in one IPv6 /64 shares the (email,
/// address) lock, so /64 rotation cannot multiply the lock budget; a
/// different /64 is independent.
#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn ipv6_64_rotation_shares_the_address_lock() {
    let pool = common::migrated_pool().await;
    let (_, email) = create_active_user(&pool, PASSWORD).await;
    let svc = auth_service(pool.clone());

    // Spend the lock budget from distinct addresses inside one /64.
    for i in 1..=threshold() {
        let ip = format!("2001:db8:7:7::{i:x}");
        let err = svc.login(&email, "wrong-password", Some(&ip), None).await.unwrap_err();
        assert!(is_generic_failure(&err), "{err:?}");
    }
    // One shared bucket for the whole /64.
    assert_eq!(
        bucket(
            &pool,
            CATEGORY_ACCOUNT_IP,
            &account_ip_key(&email, Some("2001:db8:7:7:ffff::9"))
        )
        .await,
        Some(threshold())
    );

    // Another address in the SAME /64: the correct password is refused.
    let err = svc
        .login(&email, PASSWORD, Some("2001:db8:7:7:aaaa::1"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::InvalidCredentials), "{err:?}");

    // A DIFFERENT /64 is not locked.
    let ok = svc
        .login(&email, PASSWORD, Some("2001:db8:7:8::1"), None)
        .await
        .expect("a different /64 must not be locked");
    assert!(matches!(ok, LoginResult::Success(_)));
}
