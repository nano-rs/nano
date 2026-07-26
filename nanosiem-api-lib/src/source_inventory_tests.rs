// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2055 / NAN-2159: the live source-inventory admission policy.
//!
//! These assert the CONSTANT, not the source text of any handler. NAN-2055's
//! coverage lived as a string scan over `fields.rs`, which could only ever
//! protect the one handler it scanned — rule preview carried its own copy of
//! the gate and drifted without failing anything.

use nanosiem_core::auth::api_key::ApiKeyInfo;
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::TokenClaims;
use uuid::Uuid;

use super::{ensure_source_inventory_access, permits_source_inventory, SOURCE_INVENTORY_CAPS};
use crate::auth_context::AuthContext;

fn jwt_auth(values: &[&str]) -> AuthContext {
    AuthContext::from_jwt(TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: Uuid::now_v7(),
        roles: Vec::new(),
        permissions: values.iter().map(ToString::to_string).collect(),
        exp: chrono::Utc::now().timestamp() + 60,
        iat: chrono::Utc::now().timestamp(),
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    })
}

fn api_key_auth(values: &[&str]) -> AuthContext {
    AuthContext::from_api_key(&ApiKeyInfo {
        id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        name: "test".to_string(),
        permissions: values.iter().map(ToString::to_string).collect(),
    })
}

/// Every assertion runs against both principal kinds — NAN-2159's live repro
/// used API keys, and an authorization difference between the two is its own
/// class of finding.
fn both_principals(values: &[&str]) -> Vec<AuthContext> {
    vec![jwt_auth(values), api_key_auth(values)]
}

/// One entry per consumer surface, keyed on the capability that guards its
/// ROUTE in `nanosiem-web/src/App.tsx`. Dropping any of these silently breaks
/// that page's source picker for a custom role that holds only it.
#[test]
fn each_consumer_route_guard_admits_its_page() {
    for (cap, consumer) in [
        (permissions::SEARCH_EXECUTE, "search autocomplete"),
        (permissions::LOG_SOURCES_CREATE, "pages/AddFeed.tsx"),
        (permissions::DETECTIONS_VIEW, "pages/RuleRepositories.tsx"),
        (
            permissions::SOURCE_SCOPES_VIEW,
            "pages/Settings/SourceScopes.tsx",
        ),
    ] {
        assert!(
            SOURCE_INVENTORY_CAPS.contains(&cap),
            "{cap} dropped from the inventory policy — {consumer} loses its \
             source picker"
        );
        for auth in both_principals(&[cap]) {
            assert!(permits_source_inventory(&auth));
            assert!(ensure_source_inventory_access(&auth).is_ok());
        }
    }
}

/// NAN-2055's repro principal. `search:view` is a search-UI affordance, not a
/// log-data capability: a principal `/api/search` 403s must not be able to
/// enumerate the tenant's sources and their exact volumes by any route.
#[test]
fn search_view_never_admits_inventory() {
    assert!(!SOURCE_INVENTORY_CAPS.contains(&permissions::SEARCH_VIEW));
    for auth in both_principals(&[permissions::SEARCH_VIEW]) {
        assert!(!permits_source_inventory(&auth));
        assert!(ensure_source_inventory_access(&auth).is_err());
    }
}

/// Repository visibility is catalog visibility. NAN-2159's finding was that
/// preview treated it as sufficient once paired with the stale gate; on its own
/// it must never admit live telemetry.
#[test]
fn catalog_capabilities_never_admit_inventory() {
    for cap in [
        permissions::RULE_REPOSITORIES_VIEW,
        permissions::RULE_REPOSITORIES_IMPORT,
        permissions::LOG_SOURCES_VIEW,
    ] {
        for auth in both_principals(&[cap]) {
            assert!(
                !permits_source_inventory(&auth),
                "{cap} must not admit live source inventory"
            );
        }
    }
}

#[test]
fn zero_permissions_are_denied() {
    for auth in both_principals(&[]) {
        assert!(!permits_source_inventory(&auth));
        assert!(ensure_source_inventory_access(&auth).is_err());
    }
}

/// The 403 has to name what would satisfy it — a bare "Forbidden" on a picker
/// that silently empties is what made this class hard to spot from the UI.
#[test]
fn rejection_names_the_accepted_capabilities() {
    let auth = jwt_auth(&[permissions::SEARCH_VIEW]);
    let err = ensure_source_inventory_access(&auth).expect_err("search:view must be refused");
    let message = format!("{err:?}");
    for cap in SOURCE_INVENTORY_CAPS {
        assert!(
            message.contains(cap),
            "rejection does not mention {cap}: {message}"
        );
    }
}
