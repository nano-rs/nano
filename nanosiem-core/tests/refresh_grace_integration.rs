// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-2453 / NAN-5973: refresh-token rotation with a reuse interval.
//!
//! Refresh tokens are single-use. The immediately previous token is honoured
//! for REFRESH_GRACE_SECS after a rotation and gets the session's CURRENT
//! refresh token back (no new branch), so a client whose rotation response
//! was lost (an aborted request) or a racing second tab converges on one
//! token. The previous token after the window, and any older token of a known
//! session, is reuse: the whole session (token family) is revoked.
//! `#[ignore]`d DB suite (throwaway Postgres).

mod common;

use nanosiem_core::auth::repository::{GroupRepository, SessionRepository, UserRepository};
use nanosiem_core::auth::{
    hash_token, AuthConfig, AuthError, AuthService, RefreshKind, TokenConfig, TokenService, User,
};
use nanosiem_core::settings::local_auth::LocalAuthSettings;
use sqlx::PgPool;
use uuid::Uuid;

const SECRET: &str = "test-jwt-secret-not-for-production-32+chars";

fn tokens() -> TokenService {
    TokenService::new(TokenConfig::new(SECRET.to_string()))
}

fn service(pool: &PgPool) -> AuthService {
    AuthService::new(
        UserRepository::new(pool.clone()),
        SessionRepository::new(pool.clone()),
        GroupRepository::new(pool.clone()),
        tokens(),
        AuthConfig::default(),
        LocalAuthSettings::new(pool.clone()),
    )
}

async fn user(pool: &PgPool) -> User {
    let id = Uuid::now_v7();
    sqlx::query_as::<_, User>(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'Grace', 'x', 'active') RETURNING *",
    )
    .bind(id)
    .bind(format!("grace-{id}@example.com"))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// (session id, current refresh token hash) for every session of `user`.
async fn sessions_of(pool: &PgPool, user: Uuid) -> Vec<(Uuid, String)> {
    sqlx::query_as("SELECT id, refresh_token_hash FROM sessions WHERE user_id = $1 ORDER BY id")
        .bind(user)
        .fetch_all(pool)
        .await
        .unwrap()
}

async fn age_rotation(pool: &PgPool, session: Uuid) {
    sqlx::query("UPDATE sessions SET rotated_at = clock_timestamp() - interval '1 minute' WHERE id = $1")
        .bind(session)
        .execute(pool)
        .await
        .unwrap();
}

fn is_reuse(r: &Result<nanosiem_core::auth::RefreshOutcome, AuthError>, sid: Uuid) -> bool {
    matches!(r, Err(AuthError::RefreshTokenReused { session_id }) if *session_id == sid)
}

#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn login_token_names_its_session() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let claims = tokens().validate_refresh_token(&t0).unwrap();
    let rows = sessions_of(&pool, u.id).await;
    assert_eq!(claims.sid, Some(rows[0].0));
}

/// The RC1 bug: the rotation committed but its response was aborted, so the
/// client still holds t0. Replaying t0 inside the window returns the CURRENT
/// token t1 (same family, nothing new minted) and the client catches up.
#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn aborted_rotation_replay_inside_grace_returns_the_current_token() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let sid = sessions_of(&pool, u.id).await[0].0;

    let lost = auth.refresh_token(&t0, None, None).await.unwrap();
    assert_eq!(lost.kind, RefreshKind::Rotated);
    let t1 = lost.tokens.refresh_token.clone();
    assert!(!t1.is_empty() && t1 != t0);

    // Twice, as a client retrying after another aborted response would.
    for _ in 0..2 {
        let replay = auth.refresh_token(&t0, None, None).await.unwrap();
        assert_eq!(replay.kind, RefreshKind::GraceReissued);
        assert_eq!(replay.session_id, sid);
        assert_eq!(replay.tokens.refresh_token, t1, "the current token, not a new branch");
        assert!(!replay.tokens.access_token.is_empty());
        assert_eq!(sessions_of(&pool, u.id).await, vec![(sid, hash_token(&t1))]);
    }

    // The client now uses t1, which rotates normally.
    let next = auth.refresh_token(&t1, None, None).await.unwrap();
    assert_eq!(next.kind, RefreshKind::Rotated);
    assert_eq!(next.session_id, sid);
}

#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn previous_token_after_the_grace_window_revokes_the_family() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let sid = sessions_of(&pool, u.id).await[0].0;
    let t1 = auth.refresh_token(&t0, None, None).await.unwrap().tokens.refresh_token;
    age_rotation(&pool, sid).await;

    assert!(is_reuse(&auth.refresh_token(&t0, None, None).await, sid));
    assert!(sessions_of(&pool, u.id).await.is_empty(), "family revoked");
    // The current token died with its family.
    assert!(matches!(auth.refresh_token(&t1, None, None).await, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn older_than_previous_token_revokes_the_family() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let sid = sessions_of(&pool, u.id).await[0].0;
    let t1 = auth.refresh_token(&t0, None, None).await.unwrap().tokens.refresh_token;
    let t2 = auth.refresh_token(&t1, None, None).await.unwrap().tokens.refresh_token;
    let t3 = auth.refresh_token(&t2, None, None).await.unwrap().tokens.refresh_token;

    // t1 is two rotations old: reuse even though the last rotation is fresh.
    assert!(is_reuse(&auth.refresh_token(&t1, None, None).await, sid));
    assert!(sessions_of(&pool, u.id).await.is_empty(), "family revoked");
    assert!(matches!(auth.refresh_token(&t3, None, None).await, Err(AuthError::SessionNotFound)));
    // The initial login token (also older than previous) after revocation:
    // nothing left to revoke, a plain refusal.
    assert!(matches!(auth.refresh_token(&t0, None, None).await, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn concurrent_refreshes_of_one_token_converge_on_one_pair() {
    let pool = common::migrated_pool().await;
    let auth = std::sync::Arc::new(service(&pool));
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let sid = sessions_of(&pool, u.id).await[0].0;
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let auth = auth.clone();
            let t0 = t0.clone();
            tokio::spawn(async move { auth.refresh_token(&t0, None, None).await })
        })
        .collect();
    let mut rotated = 0;
    let mut refresh_tokens = std::collections::BTreeSet::new();
    for h in handles {
        let outcome = h.await.unwrap().expect("no concurrent refresh is refused");
        assert_ne!(outcome.kind, RefreshKind::GraceAccessOnly);
        assert_eq!(outcome.session_id, sid);
        rotated += usize::from(outcome.kind == RefreshKind::Rotated);
        refresh_tokens.insert(outcome.tokens.refresh_token);
    }
    assert_eq!(rotated, 1, "exactly one rotation");
    assert_eq!(refresh_tokens.len(), 1, "every caller holds the same current token");
    let current = refresh_tokens.into_iter().next().unwrap();
    assert_eq!(sessions_of(&pool, u.id).await, vec![(sid, hash_token(&current))]);
}

#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn token_of_another_session_or_user_is_refused_without_side_effects() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let other = user(&pool).await;
    let a0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let b0 = auth.create_session_for_user(&other, &[], None, None).await.unwrap().refresh_token;
    let a_sid = sessions_of(&pool, u.id).await[0].0;
    let (b_sid, b_hash) = sessions_of(&pool, other.id).await[0].clone();

    // A token naming session A presented where it matches session B's hash
    // (binding mismatch): refused, B untouched.
    let crossed = tokens().create_refresh_token_for_session(other.id, a_sid).unwrap();
    sqlx::query("UPDATE sessions SET refresh_token_hash = $1 WHERE id = $2")
        .bind(hash_token(&crossed))
        .bind(b_sid)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(auth.refresh_token(&crossed, None, None).await, Err(AuthError::SessionNotFound)));
    sqlx::query("UPDATE sessions SET refresh_token_hash = $1 WHERE id = $2")
        .bind(&b_hash)
        .bind(b_sid)
        .execute(&pool)
        .await
        .unwrap();

    // A signed token for user `other` naming user u's session cannot revoke it.
    let foreign = tokens().create_refresh_token_for_session(other.id, a_sid).unwrap();
    assert!(matches!(auth.refresh_token(&foreign, None, None).await, Err(AuthError::SessionNotFound)));
    assert_eq!(sessions_of(&pool, u.id).await.len(), 1);

    // Both real sessions still refresh independently.
    let a = auth.refresh_token(&a0, None, None).await.unwrap();
    let b = auth.refresh_token(&b0, None, None).await.unwrap();
    assert_eq!((a.kind, a.session_id), (RefreshKind::Rotated, a_sid));
    assert_eq!((b.kind, b.session_id), (RefreshKind::Rotated, b_sid));
}

/// A session rotated by a pre-NAN-5973 build: its current token cannot be
/// re-derived, so the previous token inside the window falls back to the
/// NAN-2453 access-only grace (no refresh token, cookie untouched).
#[tokio::test]
#[ignore = "requires a live Postgres (NANOSIEM_TEST_DATABASE_URL); run with --ignored"]
async fn legacy_rotation_inside_grace_falls_back_to_access_only() {
    let pool = common::migrated_pool().await;
    let auth = service(&pool);
    let u = user(&pool).await;
    let t0 = auth.create_session_for_user(&u, &[], None, None).await.unwrap().refresh_token;
    let sid = sessions_of(&pool, u.id).await[0].0;
    let legacy_current = tokens().create_refresh_token(u.id).unwrap();
    sqlx::query(
        "UPDATE sessions SET previous_refresh_token_hash = refresh_token_hash, \
         refresh_token_hash = $1, rotated_at = clock_timestamp() WHERE id = $2",
    )
    .bind(hash_token(&legacy_current))
    .bind(sid)
    .execute(&pool)
    .await
    .unwrap();

    let replay = auth.refresh_token(&t0, None, None).await.unwrap();
    assert_eq!(replay.kind, RefreshKind::GraceAccessOnly);
    assert!(replay.tokens.refresh_token.is_empty());
    assert!(!replay.sets_refresh_token());
    // The legacy current token (no sid) still rotates.
    assert_eq!(auth.refresh_token(&legacy_current, None, None).await.unwrap().kind, RefreshKind::Rotated);
}
