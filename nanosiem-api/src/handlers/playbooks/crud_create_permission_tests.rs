// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5231: creating a playbook as `live` needs `playbooks:publish`, the same
//! rule `ensure_update_permissions` applies to a PATCH to `live`.

use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::{permissions, TokenClaims};
use nanosiem_core::playbooks::CreatePlaybookRequest;
use uuid::Uuid;

use super::ensure_create_permissions;
use crate::error::ApiError;
use crate::middleware::AuthContext;

fn auth(permissions: &[&str]) -> AuthContext {
    AuthContext::from_jwt(TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: Uuid::now_v7(),
        roles: vec!["Editor".to_string()],
        permissions: permissions.iter().map(|value| value.to_string()).collect(),
        exp: i64::MAX,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    })
}

/// The request exactly as the API deserializes it.
fn create_request(status: Option<&str>) -> CreatePlaybookRequest {
    let mut body = serde_json::json!({
        "title": "Contain compromised host",
        "category": "endpoint",
        "doc": "# Contain\n\n1. Isolate the host",
    });
    if let Some(status) = status {
        body["status"] = serde_json::Value::String(status.to_string());
    }
    serde_json::from_value(body).expect("valid CreatePlaybookRequest")
}

#[test]
fn live_create_requires_publish() {
    let req = create_request(Some("live"));
    let manage_only = auth(&[permissions::PLAYBOOKS_MANAGE]);
    assert!(matches!(
        ensure_create_permissions(&manage_only, &req),
        Err(ApiError::Forbidden(message)) if message == "Missing permission: playbooks:publish"
    ));

    let both = auth(&[permissions::PLAYBOOKS_MANAGE, permissions::PLAYBOOKS_PUBLISH]);
    assert!(ensure_create_permissions(&both, &req).is_ok());
}

#[test]
fn live_create_still_requires_manage() {
    let req = create_request(Some("live"));
    let publish_only = auth(&[permissions::PLAYBOOKS_PUBLISH]);
    assert!(matches!(
        ensure_create_permissions(&publish_only, &req),
        Err(ApiError::Forbidden(message)) if message == "Missing permission: playbooks:manage"
    ));
}

#[test]
fn draft_or_omitted_status_needs_only_manage() {
    let manage_only = auth(&[permissions::PLAYBOOKS_MANAGE]);
    assert!(ensure_create_permissions(&manage_only, &create_request(None)).is_ok());
    assert!(ensure_create_permissions(&manage_only, &create_request(Some("draft"))).is_ok());
}
