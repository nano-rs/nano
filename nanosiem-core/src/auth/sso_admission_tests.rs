// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3904 / NAN-3908 / NAN-3935: SSO admission decisions against mocked
//! IdP claims (Okta, Microsoft Entra ID, Google Workspace).

use super::oidc::{fetch_entra_groups, groups_from_validated_claims};
use super::{IdTokenClaims, OidcError, SsoAccessPolicy};
use reqwest::Client;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const ENTRA_TENANT: &str = "11111111-1111-4111-8111-111111111111";
const ENTRA_ISSUER: &str = "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0";

fn claims(issuer: &str, patch: Value) -> IdTokenClaims {
    let mut value = json!({
        "iss": issuer, "sub": "subject", "aud": "client", "exp": 2_000_000_000i64,
        "iat": 1_900_000_000i64, "email": "member@example.com"
    });
    value.as_object_mut().unwrap().extend(patch.as_object().unwrap().clone());
    serde_json::from_value(value).unwrap()
}

#[test]
fn admission_matrix_per_provider() {
    let policy = SsoAccessPolicy::default();
    // (scenario, mapped group asserted, invited, membership known, admitted)
    for (scenario, mapped, invited, known, expected) in [
        ("mapped first-time user", true, false, true, true),
        ("unmapped first-time user", false, false, true, false),
        ("invited member without groups", false, true, true, true),
        ("JIT member removed from mapped group", false, false, true, false),
        ("membership lookup failed", true, false, false, false),
    ] {
        assert_eq!(policy.admits(mapped, invited, known), expected, "{scenario}");
    }
    // Invitation-only provider never JITs, even for a mapped group.
    let invitation_only = SsoAccessPolicy { mapped_groups_only: false, ..Default::default() };
    assert!(!invitation_only.admits(true, false, true));
    assert!(invitation_only.admits(false, true, true));
}

#[test]
fn group_claims_follow_each_providers_membership_source() {
    // Okta: the configured groups claim.
    let okta = claims("https://example.okta.com", json!({"groups": ["nano-analysts"], "roles": ["x"]}));
    assert_eq!(groups_from_validated_claims(&okta, Some("groups")).unwrap(), vec!["nano-analysts"]);
    assert_eq!(groups_from_validated_claims(&okta, Some("roles")).unwrap(), vec!["x"]);
    assert!(matches!(
        groups_from_validated_claims(&okta, Some("department")),
        Err(OidcError::InvalidConfig(_))
    ));
    // Entra: group object ids, regardless of a roles claim.
    let entra = claims(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT, "groups": ["22222222-2222-4222-8222-222222222222"], "roles": ["untrusted"]}));
    assert_eq!(
        groups_from_validated_claims(&entra, Some("roles")).unwrap(),
        vec!["22222222-2222-4222-8222-222222222222"]
    );
    // Google: never from the ID token (Directory lookup only).
    let google = claims("https://accounts.google.com", json!({"groups": ["forged@example.com"]}));
    assert!(groups_from_validated_claims(&google, Some("groups")).unwrap().is_empty());
}

#[test]
fn unresolved_groups_overage_is_unknown_membership() {
    for overage in [json!({"hasgroups": true}), json!({"_claim_names": {"groups": "src1"}})] {
        let mut patch = json!({"tid": ENTRA_TENANT});
        patch.as_object_mut().unwrap().extend(overage.as_object().unwrap().clone());
        let c = claims(ENTRA_ISSUER, patch);
        assert!(c.has_group_overage());
        assert!(matches!(
            groups_from_validated_claims(&c, None),
            Err(OidcError::GroupMembershipUnknown)
        ));
    }
}

#[test]
fn entra_verified_email_needs_exact_issuer_tenant_and_signal() {
    assert!(claims(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT, "xms_edov": true})).verified_email());
    assert!(!claims(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT})).verified_email());
    assert!(!claims(ENTRA_ISSUER, json!({"tid": "22222222-2222-4222-8222-222222222222", "xms_edov": true})).verified_email());
    for issuer in [
        "https://login.microsoftonline.com.evil.example/11111111-1111-4111-8111-111111111111/v2.0",
        "https://login.microsoftonline.com/common/v2.0",
        "https://issuer.example",
    ] {
        assert!(!claims(issuer, json!({"tid": ENTRA_TENANT, "xms_edov": true})).verified_email(), "{issuer}");
    }
    // Other providers still need email_verified.
    assert!(claims("https://example.okta.com", json!({"email_verified": true})).verified_email());
    assert!(!claims("https://accounts.google.com", json!({"xms_edov": true})).verified_email());
}

#[test]
fn entra_domain_fallback_requires_configured_tenant_and_exact_domain() {
    let tid = Uuid::parse_str(ENTRA_TENANT).unwrap();
    let policy = SsoAccessPolicy {
        entra_tenant_id: Some(tid),
        verified_domains: vec!["example.com".into()],
        ..Default::default()
    };
    let mut c = claims(ENTRA_ISSUER, json!({"tid": ENTRA_TENANT}));
    assert!(policy.verifies_email(&c));
    c.email = Some("member@evil.example.com".into());
    assert!(!policy.verifies_email(&c));
    c.email = Some("member@example.com".into());
    assert!(!SsoAccessPolicy::default().verifies_email(&c));
}

#[test]
fn policy_validation_rejects_malformed_settings() {
    assert!(SsoAccessPolicy::default().validate().is_ok());
    for bad in [
        SsoAccessPolicy { verified_domains: vec!["Example.com".into()], ..Default::default() },
        SsoAccessPolicy { verified_domains: vec!["com".into()], ..Default::default() },
        SsoAccessPolicy { entra_tenant_id: Some(Uuid::nil()), ..Default::default() },
        SsoAccessPolicy { google_delegated_admin: Some("not-an-email".into()), ..Default::default() },
        SsoAccessPolicy { google_delegated_admin: Some("a @example.com".into()), ..Default::default() },
    ] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
    assert!(super::validate_idp_group("nano-analysts").is_ok());
    assert!(super::validate_idp_group(" padded").is_err());
    assert!(super::validate_idp_group("").is_err());
}

#[tokio::test]
async fn entra_graph_overage_reads_complete_membership_only() {
    let server = MockServer::start().await;
    let group = "33333333-3333-4333-8333-333333333333";
    Mock::given(method("GET"))
        .and(path("/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"value": [{"id": group}]})))
        .mount(&server)
        .await;
    let result = fetch_entra_groups(&Client::new(), &format!("{}/groups", server.uri()), "t")
        .await
        .unwrap();
    assert_eq!(result, vec![group]);
}

#[tokio::test]
async fn entra_graph_failure_or_foreign_next_link_is_denied() {
    for (status, body) in [
        (403, json!({"error": "consent required"})),
        (200, json!({"value": [{"id": "not-a-guid"}]})),
        (200, json!({})),
        (200, json!({"value": [], "@odata.nextLink": "https://evil.example/groups"})),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&server)
            .await;
        assert!(matches!(
            fetch_entra_groups(&Client::new(), &format!("{}/groups", server.uri()), "t").await,
            Err(OidcError::GroupMembershipUnknown)
        ));
    }
}
