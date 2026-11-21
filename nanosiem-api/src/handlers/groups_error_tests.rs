// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5742: group delete errors never leak raw database text, and an
//! integrity refusal is a 409 naming the constraint.

use axum::http::StatusCode;
use nanosiem_core::auth::{DeleteIntegrityViolation, GroupRepositoryError};

#[test]
fn database_error_is_redacted() {
    let err = GroupRepositoryError::DatabaseError(sqlx::Error::Protocol(
        "new row for relation \"secret_table\" violates check constraint".to_string(),
    ));
    let (status, body) = super::GroupApiError::from_repo_error(&err);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.error, "database_error");
    assert!(!body.message.contains("secret_table"), "{}", body.message);
}

#[test]
fn delete_blocked_maps_to_conflict() {
    let err = GroupRepositoryError::DeleteBlocked(DeleteIntegrityViolation {
        sqlstate: "23514".to_string(),
        table: Some("case_handoffs".to_string()),
        column: None,
        constraint: Some("case_handoffs_target_present".to_string()),
    });
    let (status, body) = super::GroupApiError::from_repo_error(&err);
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body.error, "group_still_referenced");
    assert!(body.message.contains("case_handoffs_target_present"), "{}", body.message);
}
