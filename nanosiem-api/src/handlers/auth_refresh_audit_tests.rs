// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3460: every session refresh is audited with the refreshing client.

use super::refresh_audit_event;
use nanosiem_core::audit::{ClientContext, TOKEN_REFRESH};
use nanosiem_core::auth::AuthError;
use uuid::Uuid;

fn client() -> ClientContext {
    ClientContext::new(
        Some("203.0.113.7".to_string()),
        Some("Mozilla/5.0 refresh-test".to_string()),
    )
}

#[test]
fn successful_refresh_names_owner_and_refreshing_client() {
    let user = Uuid::now_v7();
    let event = refresh_audit_event(Some(user), &client(), None, false);
    assert_eq!(event.action, TOKEN_REFRESH);
    assert!(event.success);
    assert_eq!(event.actor_id, Some(user));
    assert_eq!(event.resource_type.as_deref(), Some("session"));
    assert_eq!(event.ip_address.as_deref(), Some("203.0.113.7"));
    assert_eq!(event.user_agent.as_deref(), Some("Mozilla/5.0 refresh-test"));
    assert!(event.details.is_none());
}

#[test]
fn rejected_refresh_is_audited_as_failure_with_reason() {
    let user = Uuid::now_v7();
    // A rotated (already-used) refresh token surfaces as SessionNotFound.
    let event = refresh_audit_event(Some(user), &client(), Some(&AuthError::SessionNotFound), false);
    assert!(!event.success);
    assert_eq!(event.actor_id, Some(user));
    assert_eq!(event.ip_address.as_deref(), Some("203.0.113.7"));
    assert_eq!(
        event.details.as_ref().and_then(|d| d["reason"].as_str()),
        Some("refresh_token_rejected")
    );

    let disabled = refresh_audit_event(Some(user), &client(), Some(&AuthError::AccountDisabled), false);
    assert_eq!(
        disabled.details.as_ref().and_then(|d| d["reason"].as_str()),
        Some("account_unavailable")
    );
}

#[test]
fn forged_refresh_token_is_audited_without_an_actor() {
    // The handler passes None when the refresh JWT fails signature/expiry
    // validation; the row must not invent an owner.
    let event = refresh_audit_event(None, &client(), Some(&AuthError::InvalidToken), false);
    assert!(!event.success);
    assert_eq!(event.actor_id, None);
    assert_eq!(event.ip_address.as_deref(), Some("203.0.113.7"));
}

#[test]
fn refresh_audit_does_not_leak_internal_error_text() {
    let event = refresh_audit_event(
        None,
        &client(),
        Some(&AuthError::DatabaseError("connection refused to 10.0.0.5".into())),
        false,
    );
    let details = event.details.expect("failure details");
    assert_eq!(details["reason"], "refresh_failed");
    assert!(!details.to_string().contains("10.0.0.5"));
}

/// Wiring guard: both arms of the refresh handler emit the audit row. The
/// handler needs a full AppState, so pin the call sites in source instead.
#[test]
fn refresh_handler_audits_success_and_failure_arms() {
    let src = include_str!("auth.rs");
    let start = src.find("pub async fn refresh_token(").expect("refresh handler");
    let end = start + src[start..].find("\n}\n").expect("handler end");
    let body = &src[start..end];
    assert!(body.contains("!outcome.rotated"));
    assert!(body.contains("refresh_audit_event(refresh_owner, &client_ctx, Some(&e), false)"));
    // A grace refresh must not rewrite the refresh cookie.
    assert!(body.contains("if rotated {"));
}

#[test]
fn grace_refresh_is_marked_in_the_audit_row() {
    let event = refresh_audit_event(Some(Uuid::now_v7()), &client(), None, true);
    assert!(event.success);
    assert_eq!(event.details.unwrap()["grace"], true);
}
