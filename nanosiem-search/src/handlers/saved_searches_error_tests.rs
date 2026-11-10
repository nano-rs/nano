// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5162: saved-search handlers never send PostgreSQL error text to the
//! client. Validation failures are a 400 with their own message; database
//! failures are a masked 500.

use axum::{http::StatusCode, response::IntoResponse};
use nanosiem_core::db::repository::SavedSearchRepositoryError;
use nanosiem_core::db::repository::saved_searches::validate_saved_search_visibility;

use super::repo_error;

async fn body_of(err: crate::error::SearchError) -> (StatusCode, String) {
    let response = err.into_response();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn invalid_visibility_is_a_400_without_sql_text() {
    let err = validate_saved_search_visibility("everyone").expect_err("must reject");
    let (status, body) = body_of(repo_error(err, None, "denied")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("Invalid visibility"), "{body}");
    for leak in ["saved_searches", "constraint", "violates"] {
        assert!(!body.contains(leak), "leaked {leak}: {body}");
    }
}

#[test]
fn allowed_visibilities_pass() {
    for v in ["private", "public", "group"] {
        assert!(validate_saved_search_visibility(v).is_ok(), "{v}");
    }
}

#[tokio::test]
async fn database_errors_are_masked() {
    let raw = "new row for relation \"saved_searches\" violates check constraint \
        \"saved_searches_visibility_check\"";
    let err = SavedSearchRepositoryError::DatabaseError(sqlx::Error::Protocol(raw.to_string()));
    let (status, body) = body_of(repo_error(err, None, "denied")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("A database error occurred"), "{body}");
    assert!(!body.contains("saved_searches"), "{body}");
    assert!(!body.contains("constraint"), "{body}");
}

#[tokio::test]
async fn not_found_and_access_denied_keep_their_statuses() {
    let id = uuid::Uuid::now_v7();
    let (status, _) = body_of(repo_error(SavedSearchRepositoryError::NotFound(id), Some(id), "x")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, body) = body_of(repo_error(
        SavedSearchRepositoryError::AccessDenied,
        Some(id),
        "Only the owner can share this saved search",
    ))
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Only the owner can share"), "{body}");
}
