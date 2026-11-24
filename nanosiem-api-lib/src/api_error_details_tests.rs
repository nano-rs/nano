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

/// NAN-5561: a 409 can carry structured details too.
#[tokio::test]
async fn conflict_with_details_is_a_409_with_its_details() {
    let response = ApiError::ConflictWithDetails {
        code: "SOME_GATE",
        message: "refused".to_string(),
        details: serde_json::json!({"gate": {"passes": false, "sample": 3}}),
    }
    .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), 16_384).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "SOME_GATE");
    assert_eq!(body["error"]["details"]["gate"]["sample"], 3);
}

/// NAN-5561: a refused policy B opt-in carries the gate's numbers as fields.
#[cfg(feature = "enterprise")]
#[tokio::test]
async fn a_refused_gate_serves_its_numbers_as_fields() {
    use nanosiem_core::hunts::review::{calibrate, gate};
    let g = gate(&calibrate(&[]), Some("m1"), 0.9, 20);
    let err: ApiError = nanosiem_core::hunts::HuntError::GateRefused {
        message: "case mode refused".into(),
        gate: Box::new(g),
    }
    .into();
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), 16_384).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "ESCALATION_GATE_NOT_MET");
    assert_eq!(body["error"]["details"]["gate"]["min_sample"], 20);
    assert_eq!(body["error"]["details"]["gate"]["passes"], false);
}

/// NAN-5789: a fetch source saved without its source configuration is a 400
/// naming the field, not a 422 or a 500.
#[tokio::test]
async fn a_missing_source_configuration_is_a_400_with_a_field_error() {
    let err: ApiError = nanosiem_core::LogSourceServiceError::MissingSourceConfiguration {
        field: "dispatch_source_config_id",
        message: "a Kafka log source needs a source configuration".into(),
    }
    .into();
    let response = err.into_response();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), 16_384).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "SOURCE_CONFIGURATION_REQUIRED");
    assert_eq!(body["error"]["details"]["field_errors"][0]["field"], "dispatch_source_config_id");
    assert!(body["error"]["details"]["field_errors"][0]["message"].as_str().unwrap().contains("Kafka"));
}
