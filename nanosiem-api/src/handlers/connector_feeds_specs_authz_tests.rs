// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4941 (codex P1): the connector spec list feeds the connector credential
//! rotate form, so a credentials-only role must be able to read it.

use nanosiem_core::auth::api_key::ApiKeyInfo;
use nanosiem_core::auth::permissions;
use uuid::Uuid;

use super::ensure_specs_view;
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
fn log_sources_view_reads_specs() {
    assert!(ensure_specs_view(&api_key(&[permissions::LOG_SOURCES_VIEW])).is_ok());
}

#[test]
fn credentials_view_alone_reads_specs() {
    assert!(ensure_specs_view(&api_key(&[permissions::CREDENTIALS_VIEW, permissions::CREDENTIALS_ROTATE])).is_ok());
}

#[test]
fn neither_permission_is_refused() {
    let err = ensure_specs_view(&api_key(&[permissions::SEARCH_EXECUTE])).unwrap_err();
    assert!(matches!(err, ApiError::Forbidden(_)), "{err:?}");
}
