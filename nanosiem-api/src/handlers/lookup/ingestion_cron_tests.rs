// SPDX-License-Identifier: AGPL-3.0-or-later
//! validate-cron bounds and permission gate (security review 2026-11-08,
//! NAN-5020).

use super::*;
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::TokenClaims;
use uuid::Uuid;

fn session(perms: &[&str]) -> AuthContext {
    AuthContext::from_jwt(TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: Uuid::now_v7(),
        roles: Vec::new(),
        permissions: perms.iter().map(ToString::to_string).collect(),
        exp: chrono::Utc::now().timestamp() + 60,
        iat: chrono::Utc::now().timestamp(),
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    })
}

fn request(expression: &str, preview_count: Option<usize>) -> Json<ValidateCronRequest> {
    Json(ValidateCronRequest {
        expression: expression.to_string(),
        preview_count,
    })
}

/// Exploit regression: the reported 200M preview is a 400, not a multi-GB
/// allocation.
#[tokio::test]
async fn huge_preview_count_is_rejected() {
    let err = validate_cron_expression(
        Extension(session(&[permissions::LOOKUP_VIEW])),
        request("* * * * * *", Some(200_000_000)),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("at most 100")), "{err}");
}

#[tokio::test]
async fn caller_without_lookup_view_is_forbidden() {
    let err = validate_cron_expression(Extension(session(&[])), request("0 * * * *", None))
        .await
        .unwrap_err();
    assert!(matches!(err, ApiError::Forbidden(_)), "{err}");
}

#[tokio::test]
async fn oversized_expression_is_rejected() {
    let err = validate_cron_expression(
        Extension(session(&[permissions::LOOKUP_VIEW])),
        request(&"0 ".repeat(2048), None),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, ApiError::BadRequest(_)), "{err}");
}

/// Legitimate path: the UI's default preview of 5, and the maximum, work.
#[tokio::test]
async fn default_and_maximum_previews_work() {
    let auth = session(&[permissions::LOOKUP_VIEW]);
    let Json(resp) = validate_cron_expression(Extension(auth.clone()), request("0 */6 * * *", None))
        .await
        .unwrap();
    assert!(resp.valid);
    assert_eq!(resp.next_runs.len(), 5);

    let Json(resp) =
        validate_cron_expression(Extension(auth), request("0 */6 * * *", Some(MAX_CRON_PREVIEW_COUNT)))
            .await
            .unwrap();
    assert_eq!(resp.next_runs.len(), MAX_CRON_PREVIEW_COUNT);
}

/// Defense in depth: the core function clamps whatever its caller passes.
#[test]
fn core_preview_is_clamped() {
    let runs = calculate_next_runs("* * * * * *", 10_000_000).unwrap();
    assert_eq!(runs.len(), MAX_CRON_PREVIEW_COUNT);
}
