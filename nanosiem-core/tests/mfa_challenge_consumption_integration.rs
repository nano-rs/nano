// SPDX-License-Identifier: AGPL-3.0-or-later
//! MFA challenge consumption concurrency regressions.

mod common;

use chrono::Utc;
use nanosiem_core::auth::{
    BackupCodeRotation, SessionRepository, SharedMfaSetupAuthority, UserRepository,
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a live disposable Postgres (DATABASE_URL); run with --ignored"]
async fn mfa_challenge_and_backup_code_are_consumed_once_under_concurrency() {
    let pool = common::migrated_pool().await;
    let user_id = Uuid::now_v7();
    let original = b"encrypted-backup-code-list";
    let replacement = b"encrypted-list-with-used-code-removed";
    sqlx::query(
        "INSERT INTO users \
         (id,email,name,password_hash,status,backup_codes_encrypted,backup_codes_nonce) \
         VALUES ($1,$2,'MFA concurrency','x','active',$3,'original-nonce')",
    )
    .bind(user_id)
    .bind(format!("mfa-concurrency-{user_id}@example.test"))
    .bind(original.as_slice())
    .execute(&pool)
    .await
    .unwrap();

    let repository = UserRepository::new(pool.clone());
    let same_jti = Uuid::now_v7();
    let expires_at = Utc::now().timestamp() + 300;
    let (same_left, same_right) = tokio::join!(
        repository.consume_mfa_challenge(user_id, same_jti, expires_at, None),
        repository.consume_mfa_challenge(user_id, same_jti, expires_at, None),
    );
    assert_eq!(
        [same_left.unwrap(), same_right.unwrap()]
            .into_iter()
            .filter(|consumed| *consumed)
            .count(),
        1,
    );

    // Even distinct challenge JTIs cannot spend the same verified backup-code
    // snapshot twice: the losing JTI insert is rolled back with the failed CAS.
    let backup_jti_left = Uuid::now_v7();
    let backup_jti_right = Uuid::now_v7();
    let rotation = || BackupCodeRotation {
        expected_encrypted: original,
        expected_nonce: "original-nonce",
        replacement_encrypted: replacement,
        replacement_nonce: "replacement-nonce",
    };
    let (backup_left, backup_right) = tokio::join!(
        repository.consume_mfa_challenge(user_id, backup_jti_left, expires_at, Some(rotation()),),
        repository.consume_mfa_challenge(user_id, backup_jti_right, expires_at, Some(rotation()),),
    );
    assert_eq!(
        [backup_left.unwrap(), backup_right.unwrap()]
            .into_iter()
            .filter(|consumed| *consumed)
            .count(),
        1,
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM revoked_tokens WHERE jti = ANY($1)",)
            .bind(vec![backup_jti_left, backup_jti_right])
            .fetch_one(&pool)
            .await
            .unwrap(),
        1,
    );
    assert_eq!(
        sqlx::query_as::<_, (Vec<u8>, String)>(
            "SELECT backup_codes_encrypted,backup_codes_nonce FROM users WHERE id=$1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .unwrap(),
        (replacement.to_vec(), "replacement-nonce".to_string()),
    );

    sqlx::query("DELETE FROM revoked_tokens WHERE jti = ANY($1)")
        .bind(vec![same_jti, backup_jti_left, backup_jti_right])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=$1")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires a live disposable Postgres (DATABASE_URL); run with --ignored"]
async fn shared_mfa_setup_is_exact_authority_bound_and_logout_safe() {
    let pool = common::migrated_pool().await;
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,email,name,password_hash,status) \
         VALUES ($1,$2,'Shared MFA authority','x','active')",
    )
    .bind(user_id)
    .bind(format!("shared-mfa-authority-{user_id}@example.test"))
    .execute(&pool)
    .await
    .unwrap();

    let users = UserRepository::new(pool.clone());
    let sessions = SessionRepository::new(pool.clone());
    let tenant_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO tenants (id,slug,display_name,status) VALUES ($1,$2,$2,'active')",
    )
    .bind(tenant_id)
    .bind(format!("shared-mfa-{}", tenant_id.simple()))
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO tenant_members (tenant_id,user_id,status) VALUES ($1,$2,'active')",
    )
    .bind(tenant_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    let first_authenticated_at = users.authentication_fence_time().await.unwrap();
    let first = SharedMfaSetupAuthority {
        tenant_id,
        jti: Uuid::now_v7(),
        authenticated_at: first_authenticated_at,
        expires_at: first_authenticated_at + chrono::Duration::minutes(5),
        is_challenge: true,
    };
    assert!(users
        .store_pending_totp_secret_for_shared_authority(
            user_id,
            first,
            b"first-encrypted-secret",
            "first-nonce",
        )
        .await
        .unwrap());

    let competing = SharedMfaSetupAuthority {
        jti: Uuid::now_v7(),
        ..first
    };
    assert!(
        !users
            .store_pending_totp_secret_for_shared_authority(
                user_id,
                competing,
                b"attacker-overwrite",
                "attacker-nonce",
            )
            .await
            .unwrap(),
        "another valid tab/credential must not overwrite the pending secret"
    );

    sessions
        .revoke_tenant_user_sessions(tenant_id, user_id)
        .await
        .expect("tenant logout advances the member watermark and clears its pending setup");
    assert!(
        !users
            .enable_mfa_for_shared_authority(
                user_id,
                first,
                b"first-encrypted-secret",
                "first-nonce",
                b"backup",
                "backup-nonce",
            )
            .await
            .unwrap(),
        "a pre-tenant-logout setup authority must not activate MFA"
    );

    // A fresh tenant credential can start after the tenant-local revocation,
    // but a later global logout still invalidates it atomically.
    let fresh_authenticated_at = users.authentication_fence_time().await.unwrap();
    let fresh = SharedMfaSetupAuthority {
        tenant_id,
        jti: Uuid::now_v7(),
        authenticated_at: fresh_authenticated_at,
        expires_at: fresh_authenticated_at + chrono::Duration::minutes(5),
        is_challenge: true,
    };
    assert!(users
        .store_pending_totp_secret_for_shared_authority(
            user_id,
            fresh,
            b"fresh-encrypted-secret",
            "fresh-nonce",
        )
        .await
        .unwrap());
    sessions
        .revoke_all_user_sessions(user_id)
        .await
        .expect("global logout advances the user watermark and clears pending setup");
    assert!(!users
        .enable_mfa_for_shared_authority(
            user_id,
            fresh,
            b"fresh-encrypted-secret",
            "fresh-nonce",
            b"fresh-backup",
            "fresh-backup-nonce",
        )
        .await
        .unwrap());

    let final_authenticated_at = users.authentication_fence_time().await.unwrap();
    let final_authority = SharedMfaSetupAuthority {
        tenant_id,
        jti: Uuid::now_v7(),
        authenticated_at: final_authenticated_at,
        expires_at: final_authenticated_at + chrono::Duration::minutes(5),
        is_challenge: true,
    };
    assert!(users
        .store_pending_totp_secret_for_shared_authority(
            user_id,
            final_authority,
            b"final-encrypted-secret",
            "final-nonce",
        )
        .await
        .unwrap());
    assert!(users
        .enable_mfa_for_shared_authority(
            user_id,
            final_authority,
            b"final-encrypted-secret",
            "final-nonce",
            b"final-backup",
            "final-backup-nonce",
        )
        .await
        .unwrap());
    assert!(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1)",
    )
    .bind(final_authority.jti)
    .fetch_one(&pool)
    .await
    .unwrap());
    let state = sqlx::query_as::<_, (bool, bool, Option<Uuid>)>(
        "SELECT mfa_enabled,mfa_setup_pending,mfa_setup_authority_jti \
         FROM users WHERE id=$1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, (true, false, None));
}
