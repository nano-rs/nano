// SPDX-License-Identifier: AGPL-3.0-or-later

//! JWT/API-key regression matrix for the source-config credential-use boundary
//! (NAN-2125).

use nanosiem_core::auth::api_key::ApiKeyInfo;
use nanosiem_core::auth::permissions;
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::TokenClaims;
use uuid::Uuid;

use super::{
    authorize_source_config_operation, SOURCE_CONFIGS_CREATE, SOURCE_CONFIGS_DEPLOY,
    SOURCE_CONFIGS_EDIT,
};
use crate::error::ApiError;
use crate::middleware::AuthContext;

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
        name: "nan-2125-probe".to_string(),
        permissions: values.iter().map(ToString::to_string).collect(),
        user_id: Some(Uuid::now_v7()),
    })
}

fn both_principals(values: &[&str]) -> [AuthContext; 2] {
    [jwt_auth(values), api_key_auth(values)]
}

fn forbidden_message(result: Result<nanosiem_core::auth::CredentialUseGrant, ApiError>) -> String {
    match result {
        Err(ApiError::Forbidden(message)) => message,
        Err(other) => panic!("expected Forbidden, got {other:?}"),
        Ok(_) => panic!("expected Forbidden, got Ok"),
    }
}

#[test]
fn explicit_credential_reference_requires_both_capabilities() {
    for source_permission in [
        SOURCE_CONFIGS_CREATE,
        SOURCE_CONFIGS_EDIT,
        SOURCE_CONFIGS_DEPLOY,
    ] {
        for auth in both_principals(&[]) {
            assert_eq!(
                forbidden_message(authorize_source_config_operation(
                    &auth,
                    source_permission,
                    true,
                )),
                format!("Missing permission: {source_permission}")
            );
        }

        for auth in both_principals(&[permissions::ALERTS_VIEW]) {
            assert_eq!(
                forbidden_message(authorize_source_config_operation(
                    &auth,
                    source_permission,
                    true,
                )),
                format!("Missing permission: {source_permission}")
            );
        }

        for auth in both_principals(&[source_permission]) {
            assert_eq!(
                forbidden_message(authorize_source_config_operation(
                    &auth,
                    source_permission,
                    true,
                )),
                "Missing permission: credentials:use"
            );
        }

        for auth in both_principals(&[permissions::CREDENTIALS_USE]) {
            assert_eq!(
                forbidden_message(authorize_source_config_operation(
                    &auth,
                    source_permission,
                    true,
                )),
                format!("Missing permission: {source_permission}")
            );
        }

        for auth in both_principals(&[source_permission, permissions::CREDENTIALS_USE]) {
            let grant = authorize_source_config_operation(&auth, source_permission, true)
                .expect("both permissions should authorize the operation");
            assert!(grant.allows());
        }
    }
}

#[test]
fn saved_credential_reference_is_checked_by_the_service_grant() {
    for held_permissions in [vec![], vec![permissions::ALERTS_VIEW]] {
        for auth in both_principals(&held_permissions) {
            assert_eq!(
                forbidden_message(authorize_source_config_operation(
                    &auth,
                    SOURCE_CONFIGS_DEPLOY,
                    false,
                )),
                "Missing permission: source_configs:deploy"
            );
        }
    }

    for auth in both_principals(&[permissions::CREDENTIALS_USE]) {
        assert_eq!(
            forbidden_message(authorize_source_config_operation(
                &auth,
                SOURCE_CONFIGS_DEPLOY,
                false,
            )),
            "Missing permission: source_configs:deploy"
        );
    }

    for auth in both_principals(&[SOURCE_CONFIGS_DEPLOY]) {
        let grant = authorize_source_config_operation(&auth, SOURCE_CONFIGS_DEPLOY, false)
            .expect("source deployment permission authorizes credentialless resources");
        assert!(!grant.allows());
    }

    for auth in both_principals(&[SOURCE_CONFIGS_DEPLOY, permissions::CREDENTIALS_USE]) {
        let grant = authorize_source_config_operation(&auth, SOURCE_CONFIGS_DEPLOY, false)
            .expect("both permissions should produce a credential-use grant");
        assert!(grant.allows());
    }
}
