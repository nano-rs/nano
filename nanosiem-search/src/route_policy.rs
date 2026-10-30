// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authoritative registration and capability policy for the Search product router.
//! Public probes are explicit. Internal transport/metrics routers retain their
//! independent bearer boundaries and are outside this product manifest.
use crate::{handlers, middleware::AuthContext, SearchState};
use axum::{
    extract::{MatchedPath, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Router,
};
use nanosiem_core::auth::{
    permissions,
    route_policy::{RoutePolicy, RoutePolicyEntry as Entry, RoutePrincipal},
};

impl RoutePrincipal for AuthContext {
    fn is_api_key(&self) -> bool {
        self.is_api_key
    }
    fn has_permission(&self, permission: &str) -> bool {
        self.claims.has_permission(permission)
    }
}

macro_rules! method_name {
    (get) => {
        "GET"
    };
    (post) => {
        "POST"
    };
    (put) => {
        "PUT"
    };
    (delete) => {
        "DELETE"
    };
}
// A route and its policy are created by the same declaration. There is no
// OpenAPI or handler-source inference in the runtime authority.
macro_rules! define_routes {
    ($( $method:ident $path:literal => $handler:path, $policy:expr; )*) => {
        pub(crate) fn routes() -> Router<SearchState> {
            let entries = manifest();
            let mut keys = std::collections::BTreeSet::new();
            assert!(entries.iter().all(|e| keys.insert((e.method, e.path))), "duplicate Search route policy");
            Router::new()$(.route($path, axum::routing::$method($handler)))*
                .layer(axum::middleware::from_fn(enforce))
        }
        pub(crate) fn manifest() -> &'static [Entry] {
            static ENTRIES: std::sync::OnceLock<Vec<Entry>> = std::sync::OnceLock::new();
            ENTRIES.get_or_init(|| vec![$(Entry {method: method_name!($method), path: $path, policy: $policy},)*])
        }
    }
}

define_routes! {
    post "/api/search" => handlers::search, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/stream" => handlers::search_stream, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    delete "/api/search/{request_id}" => handlers::cancel_search, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/sql" => handlers::search_sql, RoutePolicy::all_of(&[permissions::SEARCH_SQL]);
    post "/api/search/explain" => handlers::explain, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/log" => handlers::fetch_log, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/prevalence-artifacts" => handlers::prevalence_artifacts, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/field-stats" => handlers::field_stats_for_query, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/field-values" => handlers::field_values, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/histogram" => handlers::search_histogram, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/retro" => handlers::retro, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/prevalence/export" => handlers::lean_prevalence_export, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE, permissions::PREVALENCE_EXPORT]);
    get "/api/search/prevalence/rare" => handlers::lean_rare_artifacts, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE, permissions::PREVALENCE_VIEW]);
    get "/api/search/trace/{trace_id}" => handlers::get_trace, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/metrics/timeseries" => handlers::get_metric_timeseries, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/traces" => handlers::list_traces, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/metrics/names" => handlers::list_metric_names, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/metrics/tags" => handlers::list_metric_tags, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/services" => handlers::list_services, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/services/{service}" => handlers::get_service_detail, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/services/{service}/security-signals" => handlers::get_service_security_signals, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/infra/hosts" => handlers::list_infra_hosts, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/rum" => handlers::get_rum_summary, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/asset-events" => handlers::get_asset_events, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/cloud-events" => handlers::get_cloud_events, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/cloud-user-timeline" => handlers::get_cloud_user_timeline, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/cloud-entity-pivot" => handlers::get_cloud_entity_pivot, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/asset-true-time-range" => handlers::get_asset_true_time_range, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/asset-artifacts" => handlers::get_asset_artifacts, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/asset-dossier" => handlers::get_asset_dossier, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/cloud-overview" => handlers::get_cloud_overview, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    post "/api/search/cloud-dossier" => handlers::get_cloud_dossier, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/identity/resolve" => handlers::resolve_identity, RoutePolicy::all_of(&[permissions::ENRICHMENTS_VIEW]);
    post "/api/search/tree-page" => handlers::get_tree_page, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/jobs" => handlers::list_search_jobs, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/jobs/{job_id}" => handlers::get_search_job, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/jobs/{job_id}/results/{page}" => handlers::get_search_job_result_page, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/jobs/{job_id}/download" => handlers::download_search_job_result, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    delete "/api/search/jobs/{job_id}" => handlers::cancel_search_job, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE]);
    get "/api/search/admin/jobs" => handlers::admin_list_search_jobs, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE, permissions::SETTINGS_SYSTEM]);
    get "/api/search/admin/stats" => handlers::admin_get_stats, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE, permissions::SETTINGS_SYSTEM]);
    delete "/api/search/admin/jobs/{job_id}" => handlers::admin_cancel_search_job, RoutePolicy::all_of(&[permissions::SEARCH_EXECUTE, permissions::SETTINGS_SYSTEM]);
    get "/api/search/saved" => handlers::list_saved_searches, RoutePolicy::all_of(&[permissions::SEARCH_VIEW]);
    post "/api/search/saved" => handlers::create_saved_search, RoutePolicy::all_of(&[permissions::SEARCH_SAVE]);
    get "/api/search/saved/shared" => handlers::list_shared_searches, RoutePolicy::all_of(&[permissions::SEARCH_VIEW]);
    get "/api/search/saved/mine" => handlers::list_my_saved_searches, RoutePolicy::all_of(&[permissions::SEARCH_VIEW]);
    get "/api/search/saved/{id}" => handlers::get_saved_search, RoutePolicy::all_of(&[permissions::SEARCH_VIEW]);
    put "/api/search/saved/{id}" => handlers::update_saved_search, RoutePolicy::all_of(&[permissions::SEARCH_SAVE]);
    delete "/api/search/saved/{id}" => handlers::delete_saved_search, RoutePolicy::all_of(&[permissions::SEARCH_SAVE]);
    post "/api/search/saved/{id}/share" => handlers::share_saved_search, RoutePolicy::all_of(&[permissions::SEARCH_SHARE]);
    get "/health" => handlers::health, RoutePolicy::public();
    get "/ready" => handlers::ready, RoutePolicy::public();
    get "/livez" => handlers::livez, RoutePolicy::public();
}

pub(crate) async fn enforce(request: Request, next: Next) -> Response {
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    // Axum supplies HEAD from a registered GET. Apply exactly its GET policy.
    let method = if request.method() == axum::http::Method::HEAD {
        "GET"
    } else {
        request.method().as_str()
    };
    let principal = request.extensions().get::<AuthContext>();
    let entry = manifest()
        .iter()
        .find(|e| Some(e.path) == matched && e.method == method);
    let Some(entry) = entry else {
        tracing::error!(method, matched_path = matched, api_key_id = ?principal.and_then(|p|p.api_key_id),
            "Search route has no authorization policy");
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error":"route_policy_missing"})),
        )
            .into_response();
    };
    if !entry.policy.evaluate(principal).is_allow() {
        tracing::warn!(method, matched_path = entry.path, api_key_id = ?principal.and_then(|p|p.api_key_id),
            "Search route capability denied");
        return (
            if principal.is_some() {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            },
            axum::Json(serde_json::json!({"error":"route_policy_denied"})),
        )
            .into_response();
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request},
        Extension,
    };
    use nanosiem_core::{
        auth::{ApiKeyInfo, TokenClaims},
        DualPool, DualPoolConfig,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn production_policy_recheck() {
        const TENANT: &str = "a0a02042-0000-4000-8000-000000000001";
        if std::env::var("NANO_LAKE_TENANT_ID").as_deref() != Ok(TENANT) {
            let dir = tempfile::tempdir().unwrap();
            let token = dir.path().join("fixture.token");
            let manifest = dir.path().join("manifest.json");
            std::fs::write(
                &manifest,
                r#"{"objects":[{"field_types":{"metadata.uid":"string"}}]}"#,
            )
            .unwrap();
            std::fs::write(&token, "route-policy-fixture-token-32-characters").unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "route_policy::tests::production_policy_recheck",
                    "--nocapture",
                ])
                .env("NANO_LAKE_TENANT_ID", TENANT)
                .env("NANO_LAKE_QUERY_URL", "http://127.0.0.1:1")
                .env("NANO_LAKE_QUERY_TOKEN_FILE", token)
                .env("NANO_LAKE_SCHEMA_MANIFEST", manifest)
                .env("NANO_SCHEMA_PROFILE", "ocsf")
                .env("NANO_IP_ALLOWLIST_DISABLED", "true")
                .env_remove("DEPLOYMENT_MODE")
                .env_remove("NANO_LOG_QUERY_BACKEND")
                .env_remove("NANO_LAKE_CELL_ROUTES_FILE")
                .env_remove("NANO_LAKE_CELL_ROUTER_TOKEN_FILE")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        production_search_routes_deny_before_extractors().await;
        production_all_of_partial_sets_deny_and_complete_sets_reach_extractors().await;
        missing_policy_never_calls_handler_and_public_probe_stays_open().await;
        identity_keeps_its_enrichment_capability().await;
        production_composition_and_path_edges().await;
    }

    async fn production_state() -> SearchState {
        let dual = DualPool::new_lake_control_plane(&DualPoolConfig::with_auth(
            "postgres://fixture@127.0.0.1:1/never_connect",
            "http://127.0.0.1:1",
            "unused",
            "unused",
            "unused",
        ))
        .await
        .unwrap();
        dual.postgres().close().await;
        SearchState::new(
            dual,
            crate::middleware::AuthState::from_jwt_secret(
                "registry-recheck-fixture-only-0123456789abcdef",
            ),
        )
        .await
    }

    async fn production_routes() -> Router {
        routes().with_state(production_state().await)
    }

    fn with_principal(app: Router, context: AuthContext) -> Router {
        app.layer(Extension(context.claims.clone()))
            .layer(Extension(context))
    }

    fn principal(api_key: bool, permissions: Vec<String>) -> AuthContext {
        if api_key {
            AuthContext::from_api_key(&ApiKeyInfo {
                id: uuid::Uuid::new_v4(),
                name: "policy-test".into(),
                user_id: Some(uuid::Uuid::new_v4()),
                permissions,
            })
        } else {
            AuthContext::from_jwt(TokenClaims {
                iss: "fixture".into(),
                aud: "nano-api".into(),
                sub: uuid::Uuid::new_v4(),
                roles: vec![],
                permissions,
                iat: 0,
                exp: i64::MAX,
                jti: uuid::Uuid::new_v4(),
                purpose: "access".into(),
            })
        }
    }
    fn uri(path: &str) -> String {
        let mut value = path.to_owned();
        while let Some(a) = value.find('{') {
            let b = value[a..].find('}').unwrap() + a;
            value.replace_range(a..=b, "invalid-id");
        }
        value
    }

    async fn production_search_routes_deny_before_extractors() {
        let app = production_routes().await;
        let mut count = 0;
        for entry in manifest().iter().filter(|e| !e.policy.is_public()) {
            for api_key in [false, true] {
                for permissions in [vec![], vec!["notebooks:view".to_owned()]] {
                    let response = with_principal(app.clone(), principal(api_key, permissions))
                        .oneshot(
                            Request::builder()
                                .method(entry.method)
                                .uri(uri(entry.path))
                                .header("content-type", "application/json")
                                .body(Body::from("{malformed"))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "{} {} api_key={api_key}",
                        entry.method,
                        entry.path
                    );
                    count += 1;
                }
            }
        }
        assert_eq!(
            count, 200,
            "every capability method/template must participate"
        );
    }

    async fn production_all_of_partial_sets_deny_and_complete_sets_reach_extractors() {
        use nanosiem_core::auth::route_policy::CapabilityRequirement;
        let app = production_routes().await;
        for entry in manifest().iter().filter(|e| !e.policy.is_public()) {
            let CapabilityRequirement::AllOf(required) = entry.policy.capability() else {
                panic!("review the new policy kind")
            };
            for api_key in [false, true] {
                for omitted in 0..required.len() {
                    let partial = required
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != omitted)
                        .map(|(_, p)| p.to_string())
                        .collect();
                    let response = with_principal(app.clone(), principal(api_key, partial))
                        .oneshot(
                            Request::builder()
                                .method(entry.method)
                                .uri(uri(entry.path))
                                .header("content-type", "application/json")
                                .body(Body::from("{malformed"))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "partial {} {}",
                        entry.method,
                        entry.path
                    );
                }
                let full = required.iter().map(|p| p.to_string()).collect();
                let response = with_principal(app.clone(), principal(api_key, full))
                    .oneshot(
                        Request::builder()
                            .method(entry.method)
                            .uri(uri(entry.path))
                            .header("content-type", "application/json")
                            .body(Body::from("{malformed"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_ne!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "complete {} {}",
                    entry.method,
                    entry.path
                );
                assert_ne!(
                    response.status(),
                    StatusCode::FORBIDDEN,
                    "complete {} {}",
                    entry.method,
                    entry.path
                );
            }
        }
    }

    async fn identity_keeps_its_enrichment_capability() {
        let app = production_routes().await;
        for api_key in [false, true] {
            for (grants, expected) in [
                (
                    vec![permissions::ENRICHMENTS_VIEW.to_owned()],
                    StatusCode::BAD_REQUEST,
                ),
                (
                    vec![permissions::SEARCH_EXECUTE.to_owned()],
                    StatusCode::FORBIDDEN,
                ),
            ] {
                // A valid query shape reaches the handler's IP validation with
                // enrichments:view alone. No DB is needed to prove the contract.
                let response = with_principal(app.clone(), principal(api_key, grants))
                    .oneshot(
                        Request::builder()
                            .uri("/api/identity/resolve?ip=invalid-ip")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), expected, "identity api_key={api_key}");
            }
        }
    }

    async fn production_composition_and_path_edges() {
        let mut state = production_state().await;
        // Real JWT verification followed by the production policy. No permission
        // resolver/PG fixture is installed: the signed token has zero grants.
        let token = state
            .auth_state
            .token_service
            .create_access_token(uuid::Uuid::new_v4(), vec![])
            .unwrap();
        let authenticated = routes()
            .layer(axum::middleware::from_fn_with_state(
                state.auth_state.clone(),
                crate::middleware::auth_middleware,
            ))
            .with_state(state.clone());
        for (credential, expected) in [
            (None, StatusCode::UNAUTHORIZED),
            (Some(format!("Bearer {token}")), StatusCode::FORBIDDEN),
        ] {
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/search")
                .header("content-type", "application/json");
            if let Some(credential) = credential {
                request = request.header("authorization", credential);
            }
            let response = authenticated
                .clone()
                .oneshot(request.body(Body::from("{malformed")).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }

        // Exercise the complete production composition, including CORS,
        // sanitization, internal merges and the tenant-alias redispatcher. Only
        // credential resolution is replaced by already-authenticated extensions.
        state.auth_state.auth_enabled = false;
        let (metrics, layer) = crate::SearchMetrics::new();
        let app = crate::create_router(
            state,
            metrics,
            layer,
            &crate::SearchConfig {
                cors_origins: vec!["https://spa.example.test".into()],
                ..Default::default()
            },
        )
        .layer(Extension(axum::extract::ConnectInfo(
            "203.0.113.5:1234".parse::<std::net::SocketAddr>().unwrap(),
        )));
        let scoped = nanosiem_api_lib::tenant_path::scoped_api_router(app.clone()).layer(
            Extension(nanosiem_core::auth::TrustedTenantContext {
                tenant_id: uuid::Uuid::from_u128(1),
                tenant_slug: "acme".into(),
            }),
        );
        for entry in manifest().iter().filter(|e| !e.policy.is_public()) {
            for api_key in [false, true] {
                for (router, prefix) in [(app.clone(), ""), (scoped.clone(), "/t/acme")] {
                    let response = with_principal(router, principal(api_key, vec![]))
                        .oneshot(
                            Request::builder()
                                .method(entry.method)
                                .uri(format!("{prefix}{}?malformed=%", uri(entry.path)))
                                .header("x-api-key", "fixture-alias-selector")
                                .header("content-type", "application/json")
                                .body(Body::from("{malformed"))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "production {prefix} {} {}",
                        entry.method,
                        entry.path
                    );
                    let body = axum::body::to_bytes(response.into_body(), 4096)
                        .await
                        .unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(
                        body["error"], "route_policy_denied",
                        "production denial must come from the policy, not another middleware"
                    );
                }
                if entry.method == "GET" {
                    let response = with_principal(app.clone(), principal(api_key, vec![]))
                        .oneshot(
                            Request::builder()
                                .method("HEAD")
                                .uri(uri(entry.path))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        StatusCode::FORBIDDEN,
                        "HEAD {}",
                        entry.path
                    );
                }
            }
        }

        // Every declared capability reaches the real production handler (rather
        // than being denied by a mismatched MatchedPath after redispatch).
        for entry in manifest().iter().filter(|e| !e.policy.is_public()) {
            let nanosiem_core::auth::route_policy::CapabilityRequirement::AllOf(required) =
                entry.policy.capability()
            else {
                panic!("review new policy kind")
            };
            for api_key in [false, true] {
                for method in [
                    Some(entry.method),
                    (entry.method == "GET").then_some("HEAD"),
                ]
                .into_iter()
                .flatten()
                {
                    let response = with_principal(
                        scoped.clone(),
                        principal(api_key, required.iter().map(|p| p.to_string()).collect()),
                    )
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(format!("/t/acme{}", uri(entry.path)))
                            .header("x-api-key", "fixture-alias-selector")
                            .header("content-type", "application/json")
                            .body(Body::from("{malformed"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                    let status = response.status();
                    if [StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN].contains(&status) {
                        let body = axum::body::to_bytes(response.into_body(), 4096)
                            .await
                            .unwrap();
                        panic!(
                            "scoped positive {method} {}: {status}: {}",
                            entry.path,
                            String::from_utf8_lossy(&body)
                        );
                    }
                }
            }
        }

        // Merged infrastructure routers retain Axum's empty 404 fallback.
        // An unmatched path reaches no handler; an unsupported method on a
        // registered product path is denied by its missing method policy.
        for (method, path, expected) in [
            ("GET", "/not-a-route", StatusCode::NOT_FOUND),
            ("POST", "/api/search/", StatusCode::NOT_FOUND),
            ("POST", "/api/search//", StatusCode::NOT_FOUND),
            ("POST", "/api/search/unknown/nested", StatusCode::NOT_FOUND),
            ("POST", "/api/search%2fstream", StatusCode::NOT_FOUND),
            ("PATCH", "/api/search", StatusCode::FORBIDDEN),
            ("HEAD", "/api/search", StatusCode::FORBIDDEN),
            ("HEAD", "/api/search/sql", StatusCode::FORBIDDEN),
            ("GET", "/livez/", StatusCode::NOT_FOUND),
            ("POST", "/livez", StatusCode::FORBIDDEN),
            ("POST", "/t/acme/api/search/", StatusCode::NOT_FOUND),
        ] {
            let response = with_principal(scoped.clone(), principal(true, vec![]))
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("x-api-key", "fixture-alias-selector")
                        .body(Body::from("{malformed"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{method} {path}");
            if expected == StatusCode::NOT_FOUND {
                assert!(axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap()
                    .is_empty());
            }
        }
        for path in ["/api/search", "/api/search/sql", "/api/search/stream"] {
            let response = with_principal(app.clone(), principal(true, vec![]))
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("x-nano-query-class", "agent")
                        .header("x-nano-agent", "fixture-agent")
                        .header("x-nano-tenant-id", uuid::Uuid::from_u128(1).to_string())
                        .header("content-type", "application/json")
                        .body(Body::from("{malformed"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "agent {path}");
        }
        let response = with_principal(
            scoped.clone(),
            principal(true, vec![permissions::SEARCH_EXECUTE.into()]),
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/t/other/api/search")
                .header("x-api-key", "fixture-alias-selector")
                .body(Body::from("{malformed"))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        // CORS deliberately terminates OPTIONS without product-handler work.
        // Browsers must still be able to preflight authenticated POST searches.
        for path in ["/api/search", "/api/search/stream", "/api/search/sql"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("OPTIONS")
                        .uri(path)
                        .header("origin", "https://spa.example.test")
                        .header("access-control-request-method", "POST")
                        .header(
                            "access-control-request-headers",
                            "authorization,content-type",
                        )
                        .body(Body::from("{malformed"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["access-control-allow-origin"],
                "https://spa.example.test"
            );
            assert!(axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty());
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/livez")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // A future nested mount changes Axum's template. It cannot inherit a
        // public probe or authorize a product route by suffix/prefix matching.
        let nested = Router::new().nest("/nested", production_routes().await);
        for path in ["/nested/livez", "/nested/api/search/jobs"] {
            let response = with_principal(
                nested.clone(),
                principal(true, vec![permissions::SEARCH_EXECUTE.into()]),
            )
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        }
    }

    async fn missing_policy_never_calls_handler_and_public_probe_stays_open() {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = called.clone();
        let fallback_flag = called.clone();
        let app = Router::new()
            .route(
                "/unclassified",
                axum::routing::post(move || {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    async { StatusCode::OK }
                }),
            )
            .fallback(move || {
                fallback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                async { StatusCode::OK }
            })
            .layer(axum::middleware::from_fn(enforce));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/unclassified")
                    .body(Body::from("malformed"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/unmatched")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
        let response = production_routes()
            .await
            .oneshot(
                Request::builder()
                    .uri("/livez")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
