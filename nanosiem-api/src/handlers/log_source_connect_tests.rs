// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4912 (codex P1-1): the unassigned inventory is live source inventory.

use nanosiem_core::auth::api_key::ApiKeyInfo;
use nanosiem_core::auth::permissions;
use uuid::Uuid;

use super::ensure_unassigned_access;
use crate::error::ApiError;
use crate::middleware::AuthContext;

fn api_key(perms: &[&str]) -> AuthContext {
    AuthContext::from_api_key(&ApiKeyInfo {
        id: Uuid::now_v7(),
        user_id: Some(Uuid::now_v7()),
        name: "test".into(),
        permissions: perms.iter().map(ToString::to_string).collect(),
    })
}

#[test]
fn log_sources_view_alone_is_refused_unassigned_inventory() {
    let err = ensure_unassigned_access(&api_key(&[permissions::LOG_SOURCES_VIEW])).unwrap_err();
    assert!(matches!(err, ApiError::Forbidden(_)), "{err:?}");
}

#[test]
fn inventory_capability_alone_is_refused_without_log_sources_view() {
    let err = ensure_unassigned_access(&api_key(&[permissions::SEARCH_EXECUTE])).unwrap_err();
    assert!(matches!(err, ApiError::Forbidden(_)), "{err:?}");
}

#[test]
fn view_plus_any_inventory_capability_is_admitted() {
    for cap in nanosiem_api_lib::SOURCE_INVENTORY_CAPS {
        assert!(
            ensure_unassigned_access(&api_key(&[permissions::LOG_SOURCES_VIEW, cap])).is_ok(),
            "{cap}"
        );
    }
}
