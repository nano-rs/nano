// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::search::lake_cell::LakeCellRoute;
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "test-router-token-0123456789abcdefghijklmnop";

struct Harness {
    server: MockServer,
    tenant: Uuid,
    client: LeanIdentityDirectoryClient,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("router.token");
    std::fs::write(&token, TOKEN).unwrap();
    let tenant = Uuid::new_v4();
    let route = Arc::new(LakeCellRoute::for_test(tenant, &server.uri(), token));
    let client = LeanIdentityDirectoryClient::from_route(route, Duration::from_secs(5)).unwrap();
    Harness {
        server,
        tenant,
        client,
        _dir: dir,
    }
}

impl Harness {
    fn route(&self, rest: &str) -> String {
        format!("/v1/tenants/{}/query{rest}", self.tenant.as_hyphenated())
    }

    fn ok(&self, result: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "ok": true,
            "schema_version": 1,
            "tenant_id": self.tenant.to_string(),
            "revision": Uuid::new_v4().to_string(),
            "result": result,
        }))
    }

    async fn mount_stats(&self, by_feed: serde_json::Value, by_status: serde_json::Value) {
        let total: u64 = by_feed
            .as_object()
            .unwrap()
            .values()
            .map(|v| v.as_u64().unwrap())
            .sum();
        Mock::given(method("POST"))
            .and(path(self.route("/v1/identity/directory/stats")))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_partial_json(
                json!({"tenant_id": self.tenant.to_string()}),
            ))
            .respond_with(self.ok(json!({
                "total": total,
                "by_feed": by_feed,
                "by_source_kind": {"pull": total},
                "by_account_status": by_status,
            })))
            .mount(&self.server)
            .await;
    }
}

fn row(feed: &str, id: &str, kind: &str, email: &str) -> serde_json::Value {
    json!({
        "feed_id": feed, "external_id": id, "source_kind": kind, "version": 1,
        "deleted": false, "snapshot_id": null, "observed_at": 1_700_000_000_000i64,
        "username": "", "upn": "", "email": email, "display_name": "",
        "first_name": "", "last_name": "", "department": "", "title": "",
        "manager_upn": "", "manager_display_name": "", "company": "",
        "office_location": "", "city": "", "country": "", "groups": [],
        "account_enabled": true, "account_status": "active", "mfa_enabled": null,
        "last_sign_in_at": null, "created_in_directory_at": null, "phone": "",
        "employee_id": "", "employee_type": "", "last_observed_at": null, "is_admin": null
    })
}

#[tokio::test]
async fn stats_count_people_not_membership_rows() {
    let h = harness().await;
    h.mount_stats(
        json!({"okta:users": 3, "okta:groups": 3, "entra:users": 2}),
        json!({"active": 4, "disabled": 1, "": 3}),
    )
    .await;
    let stats = h.client.stats().await.unwrap();
    assert_eq!(stats.total_users(), 5);
    assert_eq!(stats.provider_users("okta"), 3);
    assert_eq!(stats.provider_users("entra:users"), 2);
    // A legacy provider id degrades to zero, not an error.
    assert_eq!(stats.provider_users("8d0c5f8e-legacy"), 0);
    assert_eq!(stats.active_users(), 4);
    assert_eq!(stats.disabled_users(), 1);
}

#[tokio::test]
async fn list_pages_across_user_feeds_and_skips_membership_feeds() {
    let h = harness().await;
    h.mount_stats(
        json!({"entra:users": 2, "okta:groups": 5, "okta:users": 3}),
        json!({"active": 5}),
    )
    .await;
    // Page 2 of size 2: skips both entra rows, takes the first two okta rows.
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/users")))
        .and(body_partial_json(
            json!({"filter": {"feed_id": "entra:users"}, "offset": 2}),
        ))
        .respond_with(h.ok(json!({"total": 2, "users": []})))
        .expect(1)
        .mount(&h.server)
        .await;
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/users")))
        .and(body_partial_json(
            json!({"filter": {"feed_id": "okta:users"}, "offset": 0, "limit": 2}),
        ))
        .respond_with(h.ok(json!({"total": 3, "users": [
            row("okta:users", "u1", "pull", "a@example.com"),
            row("okta:users", "u2", "pull", "b@example.com"),
        ]})))
        .expect(1)
        .mount(&h.server)
        .await;
    let page = h
        .client
        .list(&ListUsersParams {
            provider_id: None,
            search: None,
            account_status: None,
            page: 2,
            page_size: 2,
        })
        .await
        .unwrap();
    assert_eq!(page.total, 5);
    assert_eq!(page.page, 2);
    let ids: Vec<_> = page.users.iter().map(|u| u.id.as_str()).collect();
    assert_eq!(ids, ["okta:users|u1", "okta:users|u2"]);
    assert_eq!(page.users[0].email.as_deref(), Some("a@example.com"));
    assert!(page.users[0].username.is_none(), "empty text maps to None");
}

#[tokio::test]
async fn list_for_a_legacy_provider_is_empty_not_an_error() {
    let h = harness().await;
    h.mount_stats(json!({"okta:users": 3}), json!({})).await;
    let page = h
        .client
        .list(&ListUsersParams {
            provider_id: Some("0b7c-legacy".into()),
            search: None,
            account_status: None,
            page: 1,
            page_size: 50,
        })
        .await
        .unwrap();
    assert_eq!(page.total, 0);
    assert!(page.users.is_empty());
}

#[tokio::test]
async fn lookup_prefers_pull_over_push_and_folds_groups() {
    let h = harness().await;
    let mut pushed = row("hr:users", "h1", "push", "a@example.com");
    pushed["department"] = json!("Push Dept");
    pushed["title"] = json!("Engineer");
    pushed["version"] = json!(99);
    let mut pulled = row("okta:users", "u1", "pull", "a@example.com");
    pulled["department"] = json!("Security");
    pulled["display_name"] = json!("Alice");
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/lookup")))
        .and(body_partial_json(
            json!({"tenant_id": h.tenant.to_string(), "value": "A@example.com"}),
        ))
        .respond_with(h.ok(json!({"rows": [pushed, pulled]})))
        .mount(&h.server)
        .await;
    let mut membership = row("okta:groups", "u1", "pull", "");
    membership["groups"] = json!(["admins", "soc"]);
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/users")))
        .and(body_partial_json(
            json!({"filter": {"feed_id": "okta:groups", "search": "u1"}}),
        ))
        .respond_with(h.ok(json!({"total": 1, "users": [membership]})))
        .mount(&h.server)
        .await;
    let user = h.client.lookup(" A@example.com ").await.unwrap().unwrap();
    assert_eq!(user.id, "okta:users|u1");
    assert_eq!(
        user.department.as_deref(),
        Some("Security"),
        "pull wins over push"
    );
    assert_eq!(
        user.title.as_deref(),
        Some("Engineer"),
        "empty field filled from push"
    );
    assert_eq!(user.display_name.as_deref(), Some("Alice"));
    assert_eq!(
        user.groups.unwrap(),
        vec!["admins".to_string(), "soc".to_string()]
    );
}

#[tokio::test]
async fn lookup_without_rows_is_none() {
    let h = harness().await;
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/lookup")))
        .respond_with(h.ok(json!({"rows": []})))
        .mount(&h.server)
        .await;
    assert!(h
        .client
        .lookup("nobody@example.com")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn get_user_keeps_only_the_exact_external_id() {
    let h = harness().await;
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/users")))
        .and(body_partial_json(
            json!({"filter": {"feed_id": "okta:users", "search": "u1"}}),
        ))
        .respond_with(h.ok(json!({"total": 2, "users": [
            row("okta:users", "u10", "pull", "x@example.com"),
            row("okta:users", "u1", "pull", "a@example.com"),
        ]})))
        .mount(&h.server)
        .await;
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/users")))
        .and(body_partial_json(
            json!({"filter": {"feed_id": "okta:groups"}}),
        ))
        .respond_with(h.ok(json!({"total": 0, "users": []})))
        .mount(&h.server)
        .await;
    let user = h
        .client
        .get_user("okta:users", "u1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.email.as_deref(), Some("a@example.com"));
    // An id that is not a feed id never reaches the worker.
    assert!(h.client.get_user("../x", "u1").await.unwrap().is_none());
}

#[tokio::test]
async fn worker_error_is_a_typed_request_error() {
    let h = harness().await;
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/stats")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "ok": false, "ready": true, "error": "identity manifest is unreadable", "reason": "internal"
        })))
        .mount(&h.server)
        .await;
    match h.client.stats().await {
        Err(LeanDirectoryError::Request(detail)) => {
            assert!(detail.contains("500"), "{detail}");
            assert!(
                detail.contains("identity manifest is unreadable"),
                "{detail}"
            );
        }
        other => panic!("expected a request error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_response_for_another_tenant_is_refused() {
    let h = harness().await;
    Mock::given(method("POST"))
        .and(path(h.route("/v1/identity/directory/lookup")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "schema_version": 1,
            "tenant_id": Uuid::new_v4().to_string(),
            "result": {"rows": [row("okta:users", "u1", "pull", "a@example.com")]},
        })))
        .mount(&h.server)
        .await;
    assert!(matches!(
        h.client.lookup("a@example.com").await,
        Err(LeanDirectoryError::ResponseContract)
    ));
}

#[tokio::test]
async fn invalid_input_is_refused_before_any_request() {
    let h = harness().await;
    assert!(matches!(
        h.client.lookup("   ").await,
        Err(LeanDirectoryError::Invalid(_))
    ));
    assert!(matches!(
        h.client
            .list(&ListUsersParams {
                provider_id: None,
                search: Some("a\u{0007}b".into()),
                account_status: None,
                page: 1,
                page_size: 10,
            })
            .await,
        Err(LeanDirectoryError::Invalid(_))
    ));
    assert!(h.server.received_requests().await.unwrap().is_empty());
}
