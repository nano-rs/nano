// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4947: a refused third-party rule repository is a 403, not a 500.
use axum::response::IntoResponse;
use nanosiem_api_lib::ApiError;
use nanosiem_core::RuleRepositoryError;

#[test]
fn repository_not_allowed_maps_to_forbidden() {
    let err: ApiError = RuleRepositoryError::RepositoryNotAllowed("sigmahq/sigma".into()).into();
    assert!(matches!(&err, ApiError::Forbidden(m) if m.contains("first-party") && m.contains("sigmahq/sigma")));
    assert_eq!(err.into_response().status(), axum::http::StatusCode::FORBIDDEN);
}
