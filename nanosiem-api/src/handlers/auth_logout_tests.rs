// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5573 review (P2-1, P2-2): `POST /api/auth/logout` must never answer 204
//! while the caller's session may still be live. A session-delete database
//! error is a 503 (audited as a failure); a pre-`sid` token whose session
//! nothing identifies is a 400 before any side effect.

use super::{logout_failure, logout_rejection};
use axum::http::StatusCode;
use nanosiem_core::auth::{AuthError, CurrentSessionLogout};
use uuid::Uuid;

#[test]
fn unidentified_legacy_session_is_rejected_before_side_effects() {
    let (status, body) = logout_rejection(&Ok(CurrentSessionLogout::NotIdentified))
        .expect("a logout that cannot name its session must not 204");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.error, "session_not_identified");
}

#[test]
fn identified_sessions_and_db_errors_are_not_rejected_up_front() {
    let id = Uuid::now_v7();
    for outcome in [
        Ok(CurrentSessionLogout::Ended(id)),
        Ok(CurrentSessionLogout::AlreadyEnded(id)),
        Err(AuthError::DatabaseError("connection reset".into())),
    ] {
        assert!(logout_rejection(&outcome).is_none(), "{outcome:?}");
    }
}

#[test]
fn failed_session_delete_is_a_503_in_every_mode() {
    for (persisted, fail_closed) in [(true, false), (true, true), (false, false), (false, true)] {
        let (status, body) = logout_failure(true, persisted, fail_closed)
            .expect("a session that may still be live must not 204");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.error, "session_end_failed");
    }
}

#[test]
fn non_durable_revocation_is_a_503_only_when_fail_closed() {
    let (status, body) = logout_failure(false, false, true).unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body.error, "revocation_unavailable");
    assert!(logout_failure(false, false, false).is_none());
}

#[test]
fn clean_logout_succeeds() {
    assert!(logout_failure(false, true, true).is_none());
    assert!(logout_failure(false, true, false).is_none());
}
