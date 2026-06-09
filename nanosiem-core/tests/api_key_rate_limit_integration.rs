//! Integration tests for per-api-key rate limiting.
//!
//! Gated like `tuning_integration.rs`: requires a live Postgres at
//! `DATABASE_URL`. Enable by removing the `cfg(any())` gate.
//!
//! Verifies the fix for NAN-675: enforcement is independent of audit
//! emission and trips at the configured limit on the next call.

// De-gated in NAN-1272: was `#![cfg(any())]` (never compiled). Now compiles
// with every `cargo test` (catches drift) but the DB-backed tests are
// `#[ignore]`d — run them via the `pg-integration-tests` CI job, or locally
// with `docker compose up -d postgres` and `cargo test -- --ignored`.

mod common;

use nanosiem_core::auth::repository::{ApiKeyRepository, AuditRepository};
use nanosiem_core::auth::{ApiKeyService, ApiKeyServiceError, CreateApiKeyRequest};
use nanosiem_core::db::repository::RateLimitRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    common::migrated_pool().await
}

fn service(pool: PgPool) -> ApiKeyService {
    ApiKeyService::new(
        ApiKeyRepository::new(pool.clone()),
        AuditRepository::new(pool.clone()),
        RateLimitRepository::new(pool),
    )
}

/// `api_keys.created_by` has an FK to `users` (added since this suite was
/// frozen), so mint against a real user row rather than a random UUID.
async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'RL Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("rl-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn mint(svc: &ApiKeyService, pool: &PgPool, name: &str, rate_limit: Option<i32>) -> String {
    let created = svc
        .create_key(
            CreateApiKeyRequest {
                name: name.to_string(),
                description: None,
                permissions: vec!["search:view".to_string()],
                expires_at: None,
                rate_limit,
            },
            Some(create_user(pool).await),
            None,
            None,
        )
        .await
        .expect("create key");
    created.key
}

async fn clear_bucket(pool: &PgPool, key_id: &str) {
    sqlx::query("DELETE FROM rate_limit_buckets WHERE category = 'api_key' AND key = $1")
        .bind(key_id)
        .execute(pool)
        .await
        .expect("clear bucket");
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn rate_limit_trips_on_next_call_after_limit() {
    let pool = pool().await;
    let svc = service(pool.clone());
    let plaintext = mint(&svc, &pool, "rl-trip", Some(2)).await;

    // Two calls within the window must succeed.
    let info1 = svc.validate_key(&plaintext, None).await.expect("call 1");
    let info2 = svc.validate_key(&plaintext, None).await.expect("call 2");
    assert_eq!(info1.id, info2.id);

    // Third call trips the limit.
    let err = svc.validate_key(&plaintext, None).await.unwrap_err();
    assert!(
        matches!(err, ApiKeyServiceError::RateLimitExceeded),
        "expected RateLimitExceeded, got {err:?}"
    );

    clear_bucket(&pool, &info1.id.to_string()).await;
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn rate_limit_none_means_unlimited() {
    let pool = pool().await;
    let svc = service(pool.clone());
    let plaintext = mint(&svc, &pool, "rl-none", None).await;

    // 10 calls in the window — none should be rate-limited.
    for _ in 0..10 {
        svc.validate_key(&plaintext, None)
            .await
            .expect("must not rate-limit");
    }
}

#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn enforcement_is_independent_of_audit_emission() {
    // The pre-fix implementation counted rows in audit_logs filtered by
    // api_key_id. validate_key does not emit any audit row itself, so
    // hammering it would never trip the old check. The new implementation
    // increments a dedicated bucket on every validate, so it must trip.
    let pool = pool().await;
    let svc = service(pool.clone());
    let plaintext = mint(&svc, &pool, "rl-no-audit", Some(1)).await;

    let info = svc.validate_key(&plaintext, None).await.expect("call 1");

    // create_key emits an APIKEY_CREATE audit row, so the baseline for this key
    // isn't necessarily zero. What NAN-675 requires is that validate_key itself
    // adds none — the limiter is bucket-driven, not audit-row-counting.
    let baseline: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE api_key_id = $1 AND timestamp > NOW() - INTERVAL '1 minute'",
    )
    .bind(info.id)
    .fetch_one(&pool)
    .await
    .expect("baseline audit count");

    let err = svc.validate_key(&plaintext, None).await.unwrap_err();
    assert!(matches!(err, ApiKeyServiceError::RateLimitExceeded));

    let after: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE api_key_id = $1 AND timestamp > NOW() - INTERVAL '1 minute'",
    )
    .bind(info.id)
    .fetch_one(&pool)
    .await
    .expect("post audit count");
    assert_eq!(
        after.0, baseline.0,
        "validate_key must not emit audit rows; the rate limit is bucket-driven",
    );

    clear_bucket(&pool, &info.id.to_string()).await;
}
