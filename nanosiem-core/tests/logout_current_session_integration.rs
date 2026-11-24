// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5573 / NAN-5578: logout ends only the caller's session, and the
//! session list marks the caller's own session as current.
//!
//! `POST /api/auth/logout` used to delete every session the user had, so a
//! logout in one browser signed them out everywhere. `GET /api/sessions/me`
//! compared session ids against the access token's `jti`, which is per token
//! and never a session id, so no session was ever marked current. Access
//! tokens now carry `sid`, the id of the session they were minted for.
//!
//! `#[ignore]`d DB suite: run against a DISPOSABLE migrated Postgres with
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=... cargo test -p
//! nanosiem-core --test logout_current_session_integration -- --ignored`.

mod common;

use nanosiem_core::auth::repository::{GroupRepository, SessionRepository, UserRepository};
use nanosiem_core::auth::{
    AuthConfig, AuthError, AuthService, CurrentSessionLogout, SessionConfig, SessionService,
    TokenClaims, TokenConfig, TokenPair, TokenService, User,
};
use nanosiem_core::settings::local_auth::LocalAuthSettings;
use sqlx::PgPool;
use uuid::Uuid;

const SECRET: &str = "test-jwt-secret-not-for-production-32+chars";

fn tokens() -> TokenService {
    TokenService::new(TokenConfig::new(SECRET.to_string()))
}

fn auth_service(pool: &PgPool) -> AuthService {
    AuthService::new(
        UserRepository::new(pool.clone()),
        SessionRepository::new(pool.clone()),
        GroupRepository::new(pool.clone()),
        tokens(),
        AuthConfig::default(),
        LocalAuthSettings::new(pool.clone()),
    )
}

fn session_service(pool: &PgPool) -> SessionService {
    SessionService::new(
        SessionRepository::new(pool.clone()),
        UserRepository::new(pool.clone()),
        SessionConfig::default(),
    )
}

async fn user(pool: &PgPool) -> User {
    let id = Uuid::now_v7();
    sqlx::query_as::<_, User>(
        "INSERT INTO users (id, email, name, password_hash, status) VALUES ($1, $2, 'Logout', 'x', 'active') RETURNING *",
    )
    .bind(id)
    .bind(format!("logout-{id}@example.invalid"))
    .fetch_one(pool)
    .await
    .unwrap()
}

/// What the auth middleware puts in `AuthContext.claims` for this login.
fn claims(pair: &TokenPair) -> TokenClaims {
    tokens().validate_access_token(&pair.access_token).unwrap()
}

async fn session_ids(pool: &PgPool, user: Uuid) -> Vec<Uuid> {
    sqlx::query_scalar("SELECT id FROM sessions WHERE user_id = $1 ORDER BY id")
        .bind(user)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn logging_out_one_session_leaves_the_other_signed_in() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let u = user(&pool).await;

    // Two browsers, one user.
    let laptop = auth.create_session_for_user(&u, &[], None, Some("laptop")).await.unwrap();
    let phone = auth.create_session_for_user(&u, &[], None, Some("phone")).await.unwrap();
    let laptop_sid = claims(&laptop).sid.expect("login binds the access token to its session");
    let phone_sid = claims(&phone).sid.expect("login binds the access token to its session");
    assert_ne!(laptop_sid, phone_sid);
    assert_eq!(session_ids(&pool, u.id).await.len(), 2);

    // Log out on the laptop, presenting only its bearer token (no refresh token).
    let outcome = auth
        .logout_current_session(u.id, claims(&laptop).sid, None)
        .await
        .unwrap();
    assert_eq!(outcome, CurrentSessionLogout::Ended(laptop_sid));

    // The laptop session is gone; the phone session is untouched and still refreshes.
    assert_eq!(session_ids(&pool, u.id).await, vec![phone_sid]);
    assert!(matches!(
        auth.refresh_token(&laptop.refresh_token, None, None).await,
        Err(AuthError::SessionNotFound)
    ));
    let refreshed = auth.refresh_token(&phone.refresh_token, None, None).await.unwrap();
    assert!(refreshed.rotated);
    // Refreshing keeps the access token bound to the same session.
    assert_eq!(claims(&refreshed.tokens).sid, Some(phone_sid));

    // Logout is idempotent: a second logout of the ended session is not an error.
    let again = auth
        .logout_current_session(u.id, Some(laptop_sid), None)
        .await
        .unwrap();
    assert_eq!(again, CurrentSessionLogout::AlreadyEnded(laptop_sid));
    assert_eq!(session_ids(&pool, u.id).await, vec![phone_sid]);
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn legacy_token_without_sid_falls_back_to_its_refresh_token_only() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let u = user(&pool).await;
    let laptop = auth.create_session_for_user(&u, &[], None, None).await.unwrap();
    let laptop_sid = claims(&laptop).sid.unwrap();
    let phone = auth.create_session_for_user(&u, &[], None, None).await.unwrap();
    let phone_sid = claims(&phone).sid.unwrap();

    // An access token minted before `sid` existed: the cookie / body refresh
    // token identifies the session instead, and the audit gets its id.
    let outcome = auth
        .logout_current_session(u.id, None, Some(&laptop.refresh_token))
        .await
        .unwrap();
    assert_eq!(outcome, CurrentSessionLogout::Ended(laptop_sid));
    assert_eq!(outcome.session_id(), Some(laptop_sid));
    assert_eq!(session_ids(&pool, u.id).await, vec![phone_sid]);
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn legacy_fallback_ends_the_session_of_an_already_rotated_refresh_token() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let u = user(&pool).await;
    let laptop = auth.create_session_for_user(&u, &[], None, None).await.unwrap();
    let laptop_sid = claims(&laptop).sid.unwrap();
    let phone = auth.create_session_for_user(&u, &[], None, None).await.unwrap();
    let phone_sid = claims(&phone).sid.unwrap();

    // R0 was rotated to R1 (another tab, or a thief who refreshed first).
    let r0 = laptop.refresh_token.clone();
    let rotated = auth.refresh_token(&r0, None, None).await.unwrap();
    assert!(rotated.rotated);
    let r1 = rotated.tokens.refresh_token.clone();

    // Logging out with the stale R0 still ends the whole session (R1 too).
    let outcome = auth.logout_current_session(u.id, None, Some(&r0)).await.unwrap();
    assert_eq!(outcome, CurrentSessionLogout::Ended(laptop_sid));
    assert_eq!(session_ids(&pool, u.id).await, vec![phone_sid]);
    assert!(matches!(auth.refresh_token(&r1, None, None).await, Err(AuthError::SessionNotFound)));
    assert!(matches!(auth.refresh_token(&r0, None, None).await, Err(AuthError::SessionNotFound)));
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn legacy_token_with_nothing_to_identify_its_session_ends_nothing() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let u = user(&pool).await;
    let phone = auth.create_session_for_user(&u, &[], None, None).await.unwrap();
    let phone_sid = claims(&phone).sid.unwrap();

    // No sid and no refresh token: reported as NotIdentified (the handler
    // answers 400), never a silent success and never "end every session".
    assert_eq!(
        auth.logout_current_session(u.id, None, None).await.unwrap(),
        CurrentSessionLogout::NotIdentified
    );
    // A refresh token that matches no live session of the caller: same.
    assert_eq!(
        auth.logout_current_session(u.id, None, Some("not-a-live-refresh-token"))
            .await
            .unwrap(),
        CurrentSessionLogout::NotIdentified
    );
    assert_eq!(session_ids(&pool, u.id).await, vec![phone_sid]);
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn a_database_error_is_returned_not_swallowed() {
    let pool = common::migrated_pool().await;
    let u = user(&pool).await;
    // A service on its own pool that we then close: every query fails.
    let broken = PgPool::connect(&std::env::var("DATABASE_URL").unwrap()).await.unwrap();
    let auth = auth_service(&broken);
    broken.close().await;
    for (sid, refresh) in [(Some(Uuid::now_v7()), None), (None, Some("r"))] {
        assert!(
            auth.logout_current_session(u.id, sid, refresh).await.is_err(),
            "a failed delete must reach the handler as an error (it answers 503)"
        );
    }
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn logout_never_ends_another_users_session() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let alice = user(&pool).await;
    let bob = user(&pool).await;
    let bobs = auth.create_session_for_user(&bob, &[], None, None).await.unwrap();
    let bob_sid = claims(&bobs).sid.unwrap();

    // Alice presenting Bob's session id or refresh token ends nothing.
    assert_eq!(
        auth.logout_current_session(alice.id, Some(bob_sid), None).await.unwrap(),
        CurrentSessionLogout::AlreadyEnded(bob_sid)
    );
    assert_eq!(
        auth.logout_current_session(alice.id, None, Some(&bobs.refresh_token))
            .await
            .unwrap(),
        CurrentSessionLogout::NotIdentified
    );
    assert_eq!(session_ids(&pool, bob.id).await, vec![bob_sid]);
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn my_sessions_marks_exactly_the_callers_session_as_current() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let sessions = session_service(&pool);
    let u = user(&pool).await;
    let laptop = auth.create_session_for_user(&u, &[], None, None).await.unwrap();
    let phone = auth.create_session_for_user(&u, &[], None, None).await.unwrap();

    for (caller, other) in [(&laptop, &phone), (&phone, &laptop)] {
        let caller_sid = claims(caller).sid.unwrap();
        let other_sid = claims(other).sid.unwrap();
        // What GET /api/sessions/me passes: the caller's `sid`.
        let listed = sessions.get_user_sessions(u.id, claims(caller).sid).await.unwrap();
        let current: Vec<Uuid> = listed.iter().filter(|s| s.is_current).map(|s| s.session.id).collect();
        assert_eq!(current, vec![caller_sid]);
        assert!(listed.iter().any(|s| s.session.id == other_sid && !s.is_current));
    }

    // The pre-fix lookup keyed on `jti`, which is never a session id: it
    // marked nothing. Guard against regressing to it.
    let by_jti = sessions.get_user_sessions(u.id, Some(claims(&laptop).jti)).await.unwrap();
    assert!(by_jti.iter().all(|s| !s.is_current));

    // The id the list marks as current is the one DELETE /api/sessions/{id}
    // ends, for the caller's own session.
    let laptop_sid = claims(&laptop).sid.unwrap();
    sessions
        .terminate_session(laptop_sid, u.id, false, None, None)
        .await
        .expect("the current session's id is deletable");
    assert_eq!(session_ids(&pool, u.id).await, vec![claims(&phone).sid.unwrap()]);
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn password_login_binds_the_access_token_to_its_session() {
    let pool = common::migrated_pool().await;
    let auth = auth_service(&pool);
    let u = user(&pool).await;
    let hash = nanosiem_core::auth::password::hash_password("Correct-Horse-Battery-9").unwrap();
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&hash)
        .bind(u.id)
        .execute(&pool)
        .await
        .unwrap();

    let result = auth
        .login(&u.email, "Correct-Horse-Battery-9", Some("127.0.0.1"), None)
        .await
        .unwrap();
    let nanosiem_core::auth::LoginResult::Success(response) = result else {
        panic!("expected a completed login");
    };
    let sid = claims(&response.tokens).sid.expect("password login binds sid");
    assert_eq!(session_ids(&pool, u.id).await, vec![sid]);
}
