// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902: an in-use credential delete is a 409 with a message naming what
//! still uses it, not a 500 "Encryption error".

use axum::http::StatusCode;
use nanosiem_core::parsers::CredentialRepositoryError;

use super::CredentialApiError;

#[test]
fn in_use_credential_maps_to_409_naming_its_users() {
    let err = CredentialRepositoryError::InUse {
        users: vec![
            "custom enrichment \"vt-lookup\"".to_string(),
            "source configuration \"Okta prod\"".to_string(),
        ],
    };
    let (status, body) = CredentialApiError::from_repo_error(&err);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.error, "credential_in_use");
    assert!(body.message.contains("in use by"), "{}", body.message);
    assert!(body.message.contains("source configuration \"Okta prod\""), "{}", body.message);
    assert!(body.message.contains("custom enrichment \"vt-lookup\""), "{}", body.message);
    assert!(!body.message.to_lowercase().contains("encryption"), "{}", body.message);
}

#[test]
fn encryption_failures_are_still_server_errors() {
    let err = CredentialRepositoryError::EncryptionError("decrypt failed".to_string());
    let (status, body) = CredentialApiError::from_repo_error(&err);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.error, "encryption_error");
}
