// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2071 / NAN-2085 / NAN-2088: the API-layer half of the source-scope
//! matrix — that BOTH principal kinds (interactive session and API key) compose
//! the identical effective scope, including the implicit `audit` deny.
//!
//! The SQL semantics live in `nanosiem-core` (`detection::match_scope`,
//! `tuning::scope`) with their own unit tests plus DB-backed suites; this file
//! only pins the `AuthContext` → scope composition the handlers depend on.

use nanosiem_core::auth::api_key::ApiKeyInfo;
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::{ScopeSet, TokenClaims};
use uuid::Uuid;

use super::effective_match_scope;
use crate::handlers::tuning::effective_tuning_scope;
use crate::middleware::AuthContext;
use nanosiem_core::detection::match_scope::MatchScope;

/// A scope's bind payload minus the NAN-2155 unresolved-provenance sentinel, so
/// the composition assertions stay about the caller's own denied sources.
fn caller_denied(scope: &MatchScope) -> Vec<String> {
    let mut got: Vec<String> = scope
        .deny_bind_values()
        .iter()
        .filter(|v| v.as_str() != nanosiem_core::auth::UNRESOLVED_SOURCE_SENTINEL)
        .cloned()
        .collect();
    got.sort();
    got
}

fn claims(permissions: &[&str]) -> TokenClaims {
    TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: Uuid::now_v7(),
        roles: vec!["analyst".to_string()],
        permissions: permissions.iter().map(|p| p.to_string()).collect(),
        exp: 0,
        iat: 0,
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    }
}

fn scope_set(denied: &[&str]) -> ScopeSet {
    let set: std::collections::BTreeSet<String> = denied.iter().map(|s| s.to_string()).collect();
    ScopeSet::from_denied(set)
}

fn session(perms: &[&str], denied: &[&str]) -> AuthContext {
    let mut auth = AuthContext::from_jwt(claims(perms));
    auth.denied_sources = scope_set(denied);
    auth
}

fn api_key(perms: &[&str], denied: &[&str]) -> AuthContext {
    let info = ApiKeyInfo {
        id: Uuid::now_v7(),
        name: "probe".to_string(),
        permissions: perms.iter().map(|p| p.to_string()).collect(),
        user_id: Some(Uuid::now_v7()),
    };
    let mut auth = AuthContext::from_api_key(&info);
    auth.denied_sources = scope_set(denied);
    auth
}

#[test]
fn unrestricted_caller_with_audit_view_gets_an_empty_match_scope() {
    // Byte-identical SQL for the unrestricted case is the NAN-1808 contract.
    let auth = session(
        &[permissions::DETECTIONS_VIEW, permissions::AUDIT_VIEW],
        &[],
    );
    assert!(effective_match_scope(&auth).is_unrestricted());
    assert!(effective_tuning_scope(&auth).is_unrestricted());
}

#[test]
fn missing_audit_view_implicitly_denies_the_audit_source() {
    let auth = session(&[permissions::DETECTIONS_VIEW], &[]);
    let scope = effective_match_scope(&auth);
    assert!(!scope.is_unrestricted());
    // NAN-2155: every restricted bind also carries the unresolved-provenance
    // sentinel; filter it out to assert the audit composition itself.
    assert_eq!(caller_denied(&scope), vec!["audit".to_string()]);

    // Same composition drives the tuning-artifact gate.
    let tuning = effective_tuning_scope(&auth);
    assert!(!tuning.allows(&["audit".to_string()], true));
    assert!(tuning.allows(&["apache".to_string()], true));
}

#[test]
fn api_key_and_session_principals_compose_identical_scopes() {
    // NAN-2071 regression matrix: "both JWT and API-key principals". The
    // per-source deny set is resolved upstream (against the KEY id for API
    // keys, NAN-2043); once resolved, the gate must not diverge by principal.
    let perms = &[permissions::DETECTIONS_VIEW, permissions::DETECTIONS_EDIT];
    let denied = &["insider_threat"];

    let s = session(perms, denied);
    let k = api_key(perms, denied);

    assert_eq!(effective_match_scope(&s), effective_match_scope(&k));
    assert_eq!(effective_tuning_scope(&s), effective_tuning_scope(&k));

    // …and both carry the implicit audit deny on top of the explicit one.
    assert_eq!(
        caller_denied(&effective_match_scope(&k)),
        vec!["audit".to_string(), "insider_threat".to_string()]
    );
}

/// NAN-2155: the composed match scope must deny the unresolved-provenance
/// sentinel for a restricted caller — that is what hides a detection match the
/// engine could not attribute to a source. Asserted at the API composition
/// layer (not only in core) because this is the object handlers actually bind.
#[test]
fn restricted_match_scope_denies_the_unresolved_provenance_sentinel() {
    let auth = session(&[permissions::DETECTIONS_VIEW], &["insider_threat"]);
    assert!(effective_match_scope(&auth)
        .deny_bind_values()
        .iter()
        .any(|v| v == nanosiem_core::auth::UNRESOLVED_SOURCE_SENTINEL));
}

#[test]
fn restricted_caller_denies_a_legacy_unstamped_tuning_proposal() {
    // Fail-closed default: an artifact with no provenance is hidden from any
    // restricted reader, while an unstamped DETECTION MATCH stays visible —
    // the two surfaces intentionally differ.
    let restricted = session(&[permissions::DETECTIONS_VIEW], &["insider_threat"]);
    assert!(!effective_tuning_scope(&restricted).allows(&[], false));

    let unrestricted = session(
        &[permissions::DETECTIONS_VIEW, permissions::AUDIT_VIEW],
        &[],
    );
    assert!(effective_tuning_scope(&unrestricted).allows(&[], false));
}
