// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5573 / NAN-5578: access tokens carry the id of the login session they
//! were minted for (`sid`), so logout can end only that session and
//! `GET /api/sessions/me` can mark it as current. `jti` stays unique per
//! access token (it is the revocation key) and is never a session id.

use super::token::{TokenConfig, TokenService};
use base64::Engine;
use uuid::Uuid;

fn service() -> TokenService {
    TokenService::new(TokenConfig::new(
        "test-jwt-secret-not-for-production-32+chars".to_string(),
    ))
}

fn payload(token: &str) -> serde_json::Value {
    let part = token.split('.').nth(1).expect("JWT payload segment");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

#[test]
fn session_token_carries_its_session_id_and_a_distinct_jti() {
    let tokens = service();
    let user = Uuid::now_v7();
    let session = Uuid::now_v7();

    let token = tokens
        .create_access_token_for_session(user, vec![], session)
        .unwrap();
    let claims = tokens.validate_access_token(&token).unwrap();

    assert_eq!(claims.sid, Some(session));
    assert_ne!(claims.jti, session, "jti is per token, not the session id");
}

#[test]
fn token_pair_for_session_binds_the_access_token() {
    let tokens = service();
    let session = Uuid::now_v7();
    let pair = tokens
        .create_token_pair_for_session(Uuid::now_v7(), vec![], session)
        .unwrap();
    let claims = tokens.validate_access_token(&pair.access_token).unwrap();
    assert_eq!(claims.sid, Some(session));
    assert!(!pair.refresh_token.is_empty());
}

#[test]
fn every_token_of_one_session_shares_the_sid() {
    let tokens = service();
    let user = Uuid::now_v7();
    let session = Uuid::now_v7();
    let a = tokens
        .validate_access_token(
            &tokens
                .create_access_token_for_session(user, vec![], session)
                .unwrap(),
        )
        .unwrap();
    let b = tokens
        .validate_access_token(
            &tokens
                .create_access_token_for_session(user, vec![], session)
                .unwrap(),
        )
        .unwrap();
    assert_eq!(a.sid, b.sid);
    assert_ne!(a.jti, b.jti, "each access token keeps its own revocation key");
}

#[test]
fn sessionless_tokens_omit_the_claim() {
    let tokens = service();
    let user = Uuid::now_v7();

    let access = tokens.create_access_token(user, vec![]).unwrap();
    assert!(payload(&access).get("sid").is_none());
    assert_eq!(tokens.validate_access_token(&access).unwrap().sid, None);

    let challenge = tokens.create_mfa_challenge_token(user).unwrap();
    assert!(payload(&challenge).get("sid").is_none());
}

#[test]
fn sid_is_encoded_as_a_session_typeid() {
    let tokens = service();
    let session = Uuid::now_v7();
    let token = tokens
        .create_access_token_for_session(Uuid::now_v7(), vec![], session)
        .unwrap();
    let sid = payload(&token)["sid"].as_str().unwrap().to_string();
    // Same wire form as session ids in the sessions API (`sess_…`).
    assert_eq!(sid, crate::typeid::encode(crate::typeid::session::PREFIX, &session));
}
