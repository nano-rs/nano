//! Integration tests for per-api-key rate limiting.
//!
//! Gated like `tuning_integration.rs`: requires a live Postgres at
//! `DATABASE_URL`. Enable by removing the `cfg(any())` gate.
//!
//! Verifies the fix for NAN-675: enforcement is independent of audit
//! emission and trips at the configured limit on the next call.

// Gated like `tuning_integration.rs`: requires a live Postgres at
// `DATABASE_URL`. Drop the gate to run locally.

#![cfg(any())]

use nanosiem_core::auth::repository::{ApiKeyRepository, AuditRepository};
use nanosiem_core::auth::{ApiKeyService, ApiKeyServiceError, CreateApiKeyRequest};
use nanosiem_core::db::repository::RateLimitRepository;
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".to_string());
    PgPool::connect(&url).await.expect("connect test db")
}

fn service(pool: PgPool) -> ApiKeyService {
    ApiKeyService::new(
        ApiKeyRepository::new(pool.clone()),
        AuditRepository::new(pool.clone()),
        RateLimitRepository::new(pool),
    )
}

async fn mint(svc: &ApiKeyService, name: &str, rate_limit: Option<i32>) -> String {
    let created = svc
        .create_key(
            CreateApiKeyRequest {
                name: name.to_string(),
                description: None,
                permissions: vec!["search:view".to_string()],
                expires_at: None,
                rate_limit,
            },
            Some(Uuid::now_v7()),
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
async fn rate_limit_trips_on_next_call_after_limit() {
    let pool = pool().await;
    let svc = service(pool.clone());
    let plaintext = mint(&svc, "rl-trip", Some(2)).await;

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
async fn rate_limit_none_means_unlimited() {
    let pool = pool().await;
    let svc = service(pool.clone());
    let plaintext = mint(&svc, "rl-none", None).await;

    // 10 calls in the window — none should be rate-limited.
    for _ in 0..10 {
        svc.validate_key(&plaintext, None)
            .await
            .expect("must not rate-limit");
    }
}

#[tokio::test]
async fn enforcement_is_independent_of_audit_emission() {
    // The pre-fix implementation counted rows in audit_logs filtered by
    // api_key_id. validate_key does not emit any audit row itself, so
    // hammering it would never trip the old check. The new implementation
    // increments a dedicated bucket on every validate, so it must trip.
    let pool = pool().await;
    let svc = service(pool.clone());
    let plaintext = mint(&svc, "rl-no-audit", Some(1)).await;

    let info = svc.validate_key(&plaintext, None).await.expect("call 1");
    let pre_fix_audit_rows: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_logs WHERE api_key_id = $1 AND timestamp > NOW() - INTERVAL '1 minute'",
    )
    .bind(info.id)
    .fetch_one(&pool)
    .await
    .expect("audit count");
    // Sanity: the validate path itself emits no audit row for the key.
    assert_eq!(pre_fix_audit_rows.0, 0, "validate_key should not emit audit");

    let err = svc.validate_key(&plaintext, None).await.unwrap_err();
    assert!(matches!(err, ApiKeyServiceError::RateLimitExceeded));

    clear_bucket(&pool, &info.id.to_string()).await;
}
