// SPDX-License-Identifier: AGPL-3.0-or-later
//! Google Workspace membership lookup fails closed (mocked Directory API).

use super::*;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn configured_directory_lookup_allows_only_positive_membership() {
    for member in [true, false] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"isMember": member})))
            .mount(&server)
            .await;
        let groups = lookup_memberships(
            &reqwest::Client::new(),
            &server.uri(),
            "fixture-token",
            &["security@example.com".to_string()],
            "user@example.com",
        )
        .await
        .unwrap();
        assert_eq!(groups, if member { vec!["security@example.com"] } else { vec![] });
    }
    assert!(google_workspace_groups(&SsoAccessPolicy::default(), "{}", "user@example.com", &[])
        .await
        .is_err());
}

#[test]
fn invalid_service_accounts_fail_closed() {
    for key in ["", "{}", "{\"token_uri\":\"https://evil.example\"}"] {
        assert!(validate_google_service_account(key).is_err());
    }
}

#[tokio::test]
async fn failed_or_unparseable_lookup_never_returns_membership() {
    for (status, body) in [(403, "{}"), (200, "{\"isMember\":\"true\"}"), (200, "{}")] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(&server)
            .await;
        let result = lookup_memberships(
            &reqwest::Client::new(),
            &server.uri(),
            "fixture-token",
            &["security@example.com".to_string()],
            "user@example.com",
        )
        .await;
        assert!(matches!(result, Err(OidcError::GroupMembershipUnknown)));
    }
}
