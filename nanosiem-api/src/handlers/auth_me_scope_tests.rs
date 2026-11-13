// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5328: `/api/auth/me` tells the client whether its data scope hides
//! sources, so an empty search can say rows may be hidden by the role's scope
//! instead of only suggesting a wider time range.

use super::data_scope_restricted;
use crate::middleware::AuthContext;
use nanosiem_core::auth::{ScopeSet, TokenClaims};
use uuid::Uuid;

fn ctx(perms: &[&str], denied: &[&str]) -> AuthContext {
    let claims = TokenClaims {
        iss: "t".into(),
        aud: "t".into(),
        sub: Uuid::now_v7(),
        exp: 0,
        iat: 0,
        roles: vec![],
        permissions: perms.iter().map(|p| p.to_string()).collect(),
        jti: Uuid::now_v7(),
        purpose: "access".into(),
    };
    let mut auth = AuthContext::from_jwt(claims);
    auth.denied_sources = ScopeSet::from_denied(denied.iter().map(|s| s.to_string()).collect());
    auth
}

#[test]
fn analyst_without_audit_view_is_restricted() {
    assert!(data_scope_restricted(&ctx(&["search:execute"], &[])));
}

#[test]
fn source_scoped_caller_is_restricted() {
    assert!(data_scope_restricted(&ctx(&["search:execute", "audit:view"], &["windows_sysmon"])));
}

#[test]
fn unrestricted_audit_viewer_is_not_restricted() {
    assert!(!data_scope_restricted(&ctx(&["search:execute", "audit:view"], &[])));
}
