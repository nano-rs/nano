// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// A 422 that names its own code and carries structured details verbatim
/// (the enterprise internal-domains refusal uses it for per-entry errors).
#[tokio::test]
async fn unprocessable_with_details_keeps_code_and_details() {
    let response = ApiError::UnprocessableWithDetails {
        code: "SOME_REFUSAL",
        message: "refused a, b".to_string(),
        details: serde_json::json!({"refused": [{"suffix": "a"}, {"suffix": "b"}]}),
    }
    .into_response();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bytes = axum::body::to_bytes(response.into_body(), 16_384).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "SOME_REFUSAL");
    assert_eq!(body["error"]["message"], "refused a, b");
    assert_eq!(body["error"]["details"]["refused"][1]["suffix"], "b");
}
