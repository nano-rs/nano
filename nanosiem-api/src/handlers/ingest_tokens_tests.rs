// SPDX-License-Identifier: AGPL-3.0-or-later

//! Request-shape, redaction and install-token state tests for the ingest token
//! handlers (ported from main's NAN-3770 / NAN-3806 tests, plus NAN-4907
//! rotation and legacy multiplex mode).

use super::*;

fn token() -> IngestToken {
    IngestToken {
        credential_id: Uuid::nil(),
        name: "fw".into(),
        token_prefix: "nit_abcdefgh".into(),
        state: "active".into(),
        source_id: None,
        source_name: None,
        route_key: None,
        source_bound_at: None,
        rotated_from: None,
        request_count: 0,
        created_at: chrono::Utc::now(),
        created_by: None,
        last_used_at: None,
        revoked_at: None,
        revoked_by: None,
        revocable: true,
    }
}

#[test]
fn create_request_rejects_unknown_fields() {
    let source = Uuid::nil().to_string();
    assert!(serde_json::from_value::<CreateIngestTokenRequest>(
        serde_json::json!({"name": "fw", "source_id": source, "token": "chosen-by-caller"})
    )
    .is_err());
    // Every token is bound at creation: no source, no token.
    assert!(
        serde_json::from_value::<CreateIngestTokenRequest>(serde_json::json!({"name": "fw"}))
            .is_err()
    );
    // A sourcetype is never a binding.
    assert!(serde_json::from_value::<CreateIngestTokenRequest>(
        serde_json::json!({"name": "fw", "sourcetype": "apache_access"})
    )
    .is_err());
    assert!(serde_json::from_value::<CreateIngestTokenRequest>(
        serde_json::json!({"name": "fw", "source_id": source})
    )
    .is_ok());
}

#[test]
fn install_token_request_accepts_mode() {
    let req: UpdateInstallTokenRequest =
        serde_json::from_value(serde_json::json!({"mode": "strict"})).unwrap();
    assert_eq!(req.mode, Some(InstallTokenMode::Strict));
    let req: UpdateInstallTokenRequest =
        serde_json::from_value(serde_json::json!({"mode": "legacy_multiplex"})).unwrap();
    assert_eq!(req.mode, Some(InstallTokenMode::LegacyMultiplex));
    assert!(serde_json::from_value::<UpdateInstallTokenRequest>(
        serde_json::json!({"mode": "open"})
    )
    .is_err());
    assert!(serde_json::from_value::<UpdateInstallTokenRequest>(
        serde_json::json!({"value": "x"})
    )
    .is_err());
}

#[test]
fn issued_token_debug_is_redacted() {
    let issued = IssuedIngestToken {
        credential: token(),
        token: "nit_abcdefghSECRETSECRET".into(),
        replaced: Some(token()),
    };
    assert!(!format!("{issued:?}").contains("SECRET"));
    let json = serde_json::to_value(&issued).unwrap();
    assert_eq!(json["token"], "nit_abcdefghSECRETSECRET", "shown once, in the response");
    assert!(json["replaced"].is_object());
    let fresh = IssuedIngestToken {
        credential: token(),
        token: "x".into(),
        replaced: None,
    };
    assert!(serde_json::to_value(&fresh).unwrap().get("replaced").is_none());
}

#[test]
fn listed_token_schema_has_no_secret_fields() {
    let value = serde_json::to_value(token()).unwrap();
    let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
    for forbidden in ["token", "value", "token_sha256", "sha256", "hash"] {
        assert!(!keys.iter().any(|k| k == forbidden), "{forbidden} in {keys:?}");
    }
}

#[test]
fn install_token_state_labels() {
    let mut settings = IngestTokenSettings::default();
    assert_eq!(install_state_label(false, false, &settings, true), "not_configured");
    assert_eq!(install_state_label(true, false, &settings, false), "unbound");
    assert_eq!(install_state_label(true, false, &settings, true), "active");
    settings.install_token_mode = InstallTokenMode::LegacyMultiplex;
    assert_eq!(install_state_label(true, false, &settings, false), "legacy_multiplex");
    settings.install_token_enabled = false;
    assert_eq!(install_state_label(true, false, &settings, false), "disabled");
    // NAN-5013: a public install token is refused whatever its settings say.
    for enabled in [true, false] {
        for mode in [InstallTokenMode::LegacyMultiplex, InstallTokenMode::Strict] {
            settings.install_token_enabled = enabled;
            settings.install_token_mode = mode;
            assert_eq!(install_state_label(true, true, &settings, true), "public_refused");
        }
    }
    assert_eq!(install_state_label(false, true, &settings, true), "not_configured");
}

#[test]
fn undelivered_tokens_are_a_clear_error_not_a_success() {
    match service_error(IngestTokenServiceError::DeliveryNotConfigured) {
        ApiError::ServiceUnavailable(message) => {
            assert!(message.contains("not configured for this deployment"), "{message}");
            assert!(message.contains("none was issued"), "{message}");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn list_reports_the_delivery_mode() {
    let list = IngestTokenList {
        tokens: vec![],
        install_token: InstallTokenState {
            name: INSTALL_TOKEN_NAME.into(),
            enabled: true,
            mode: InstallTokenMode::Strict,
            state: "unbound".into(),
            deprecated: false,
            source_id: None,
            source_name: None,
            route_key: None,
            source_bound_at: None,
            updated_at: None,
            updated_by: None,
        },
        sources: vec![],
        delivery: TokenDelivery::None,
    };
    assert_eq!(serde_json::to_value(&list).unwrap()["delivery"], "none");
}

/// NAN-4902: the request bodies accept a log source TypeID (`ls_…`) or a bare
/// UUID, so the published schema must not restrict `source_id` to `format: uuid`.
#[test]
fn request_source_id_schema_is_a_string_not_a_uuid() {
    use utoipa::OpenApi;
    let spec = serde_json::to_value(IngestTokensApiDoc::openapi()).unwrap();
    for schema in ["CreateIngestTokenRequest", "BindIngestTokenRequest", "UpdateInstallTokenRequest"] {
        let prop = &spec["components"]["schemas"][schema]["properties"]["source_id"];
        assert!(prop.is_object(), "{schema}.source_id missing: {prop}");
        assert!(prop.get("format").is_none(), "{schema}.source_id must not be format uuid: {prop}");
        let ty = &prop["type"];
        assert!(ty == "string" || ty.as_array().is_some_and(|t| t.contains(&"string".into())), "{schema}: {prop}");
    }
}
