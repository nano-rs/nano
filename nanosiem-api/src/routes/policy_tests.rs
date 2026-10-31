// SPDX-License-Identifier: AGPL-3.0-or-later
//! One production registration/app matrix for API, including its enterprise
//! product mounts and physically separate internal listener. Authenticated
//! extensions model the output of credential resolution; handlers are real.
use super::*;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    Extension,
};
use nanosiem_api_lib::{route_policy::Entry, AuthContext};
use nanosiem_core::{
    auth::{
        route_policy::{AuthMode, CapabilityRequirement},
        ApiKeyInfo, TokenClaims,
    },
    db::{DualPool, DualPoolConfig},
};
use tower::ServiceExt;

mod required_grants;

#[cfg(feature = "enterprise")]
#[path = "policy_tests/audit_fixture.rs"]
mod audit_fixture;

fn principal(api_key: bool, permissions: Vec<String>) -> AuthContext {
    if api_key {
        AuthContext::from_api_key(&ApiKeyInfo {
            id: uuid::Uuid::from_u128(0x2043),
            name: "matrix".into(),
            user_id: Some(uuid::Uuid::from_u128(0x2042)),
            permissions,
        })
    } else {
        AuthContext::from_jwt(TokenClaims {
            iss: "fixture".into(),
            aud: "nano-api".into(),
            sub: uuid::Uuid::from_u128(0x2042),
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
        // Deliberately malformed IDs: authorized requests stop in extractors or
        // validation and cannot perform any fixture/owner mutation.
        value.replace_range(a..=b, "invalid-id");
    }
    value
}
fn grants(policy: &RoutePolicy) -> Vec<Vec<String>> {
    let strings = |values: &[&str]| values.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    match policy.capability() {
        CapabilityRequirement::None => vec![vec![]],
        CapabilityRequirement::AllOf(perms) => vec![strings(perms)],
        CapabilityRequirement::AnyOf(perms) => perms.iter().map(|p| vec![p.to_string()]).collect(),
        CapabilityRequirement::AllOfAnyOf { all, any } => any
            .iter()
            .map(|p| {
                let mut permissions = strings(all);
                permissions.push(p.to_string());
                permissions
            })
            .collect(),
    }
}
fn admits_without_capability(policy: &RoutePolicy, api_key: bool) -> bool {
    // Independent expected-mode table; do not call the decision implementation
    // being tested to decide whether to send a negative probe.
    match policy.auth_mode() {
        AuthMode::Public => true,
        AuthMode::InteractiveOrCapability if !api_key => true,
        AuthMode::InteractiveSession if api_key => false,
        AuthMode::ServiceIdentity(_) => false,
        _ => matches!(policy.capability(), CapabilityRequirement::None),
    }
}
fn reviewed_public(row: &Entry) -> bool {
    matches!(
        (row.method, row.path.as_str()),
        (
            "GET",
            "/health"
                | "/ready"
                | "/livez"
                | "/api/capabilities"
                | "/api/setup/status"
                | "/api/auth/methods"
                | "/api/auth/oidc/providers"
                | "/api/auth/oidc/{provider}/authorize"
                | "/api/auth/shared/tenant-path-alias/{alias}"
                | "/t/{slug}/api-docs/openapi.json"
                | "/t/{slug}/swagger-ui"
                | "/t/{slug}/swagger-ui/"
                | "/t/{slug}/swagger-ui/{*asset}"
        ) | (
            "POST",
            "/api/setup/initialize"
                | "/api/auth/login"
                | "/api/auth/refresh"
                | "/api/auth/password/reset-request"
                | "/api/auth/password/reset"
                | "/api/auth/mfa/challenge"
                | "/api/auth/mfa/setup"
                | "/api/auth/mfa/verify-setup"
                | "/api/auth/oidc/{provider}/callback"
                | "/api/demo/session"
                | "/api/demo/session/{token}/claim"
                | "/api/auth/shared/activate"
                | "/api/auth/shared/oidc/entry"
                | "/api/auth/shared/oidc/callback"
                | "/api/auth/shared/oidc/providers"
                | "/api/auth/shared/oidc/start"
                | "/api/auth/shared/memberships/accept"
        )
    ) || {
        #[cfg(feature = "enterprise")]
        {
            row.method == "POST"
                && row.path == nanosiem_core::enterprise_shared_demo::DEMO_CLAIM_PATH
        }
        #[cfg(not(feature = "enterprise"))]
        {
            false
        }
    }
}
async fn response(
    app: axum::Router,
    row: &Entry,
    context: AuthContext,
    method: &str,
) -> (StatusCode, String) {
    response_at(app, row, context, method, "").await
}
async fn response_at(
    app: axum::Router,
    row: &Entry,
    context: AuthContext,
    method: &str,
    prefix: &str,
) -> (StatusCode, String) {
    // Credential resolution attaches these to the request in production.
    // Do the same here instead of rebuilding every route's middleware stack
    // for each principal. Keep the full guarded app unchanged.
    eprintln!(
        "API policy probe: {method} {prefix}{}; key={}; grants={}",
        row.path,
        context.is_api_key,
        context.claims.permissions.len()
    );
    let mut request = Request::builder()
        .method(method)
        .uri(format!("{prefix}{}?malformed=%", uri(&row.path)))
        .header("x-api-key", "fixture-alias-selector")
        .header("content-type", "application/json")
        .body(Body::from("{malformed"))
        .unwrap();
    request.extensions_mut().insert(context.claims.clone());
    request.extensions_mut().insert(context);
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), app.oneshot(request))
        .await
        .unwrap_or_else(|_| panic!("production request stalled: {method} {}", row.path))
        .unwrap();
    let status = response.status();
    // SSE is intentionally unbounded. Success proves admission; drop the body
    // without consuming tenant payloads. Policy failures are finite JSON and
    // remain fully asserted below and by the negative matrix.
    if status.is_success() {
        return (status, String::new());
    }
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024),
    )
    .await
    .unwrap_or_else(|_| panic!("production response body stalled: {method} {}", row.path))
    .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}
fn policy_denial(body: &str) {
    let value: serde_json::Value = serde_json::from_str(body).expect("policy JSON denial");
    assert_eq!(
        value["error"], "route_policy_denied",
        "denial must precede handler/body/plan work: {body}"
    );
}
// A connection failure is deliberately retried by the real lake transport.
// Supply a non-retryable semantic HTTP error instead, on an owned peer whose
// runtime stays live while the parent waits for each isolated test process.
fn fixture_http_peer() -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let app = axum::Router::new().fallback(|| async {
                    (
                        StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({
                            "error": "fixture_dependency_unavailable"
                        })),
                    )
                });
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            });
    });
    (url, stop, thread)
}

async fn production_state(shared: bool) -> AppState {
    let dual = DualPool::new_lake_control_plane(&DualPoolConfig::with_auth(
        "postgres://fixture@127.0.0.1:1/closed",
        "http://127.0.0.1:1",
        "fixture",
        "fixture",
        "fixture",
    ))
    .await
    .unwrap();
    dual.postgres().close().await;
    let mut config = ApiConfig {
        canonical_lake_ocsf: true,
        schema_id: nanosiem_core::schema::SchemaId::Ocsf,
        auth_enabled: true,
        deployment_id: Some("registry-fixture".into()),
        ..Default::default()
    };
    #[cfg(feature = "enterprise")]
    if shared {
        config.deployment_mode = crate::config::DeploymentMode::EnterpriseShared;
    }
    #[cfg(not(feature = "enterprise"))]
    assert!(!shared);
    AppState::new_with_dual_pool(
        dual,
        config,
        Arc::new(nanosiem_core::schema::OcsfProfile::lake_1_9()),
    )
    .await
}

fn matrix_app(state: AppState) -> axum::Router {
    #[cfg(feature = "enterprise")]
    let shared = state.config.deployment_mode.is_enterprise_shared();
    let app = create_router_with_auth_layer(state, |app, _auth| app)
        .layer(Extension(axum::extract::ConnectInfo(
            "203.0.113.5:1234".parse::<std::net::SocketAddr>().unwrap(),
        )))
        .layer(Extension(nanosiem_core::audit::ClientContext::new(
            Some("203.0.113.5".into()),
            Some("matrix".into()),
        )));
    // Shared credential resolution also supplies the verified tenant; audit
    // and URL admission use that exact production output on every request.
    #[cfg(feature = "enterprise")]
    let app = if shared {
        app.layer(Extension(nanosiem_core::auth::TrustedTenantContext {
            tenant_id: uuid::Uuid::from_u128(1),
            tenant_slug: "acme".into(),
        }))
    } else {
        app
    };
    app
}

#[cfg(feature = "enterprise")]
async fn audit_dependency_failure_case() {
    let state = production_state(true).await;
    assert!(state.tenant_ai_rls_runtime.is_none());
    let inventory = route_manifest(&state);
    let validate = inventory
        .iter()
        .find(|row| row.method == "GET" && row.path == "/api/auth/validate")
        .unwrap();
    let rules = inventory
        .iter()
        .find(|row| row.method == "GET" && row.path == "/api/rules")
        .unwrap();
    let app = matrix_app(state.clone());
    let anonymous = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/validate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    let scoped = nanosiem_api_lib::tenant_path::scoped_api_router(app.clone());
    for api_key in [false, true] {
        assert_eq!(
            response_at(
                scoped.clone(),
                validate,
                principal(api_key, vec![]),
                "GET",
                "/t/acme"
            )
            .await
            .0,
            StatusCode::OK,
            "an admitted identity read must remain healthy"
        );
        for (row, target, prefix) in [
            (validate, scoped.clone(), "/t/other"),
            (rules, app.clone(), ""),
        ] {
            let (status, body) =
                response_at(target, row, principal(api_key, vec![]), "GET", prefix).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap()["error"],
                "audit_unavailable"
            );
        }
    }
    state.shutdown_all_tasks().await;
    eprintln!("API separate audit-unavailable production HTTP probes: 7");
}

#[test]
#[cfg_attr(
    feature = "enterprise",
    ignore = "requires an exact-sha coordinator grant and owned farm PostgreSQL 18"
)]
fn production_api_route_policy_http_matrix() {
    // Authorized ingestion-history requests execute the real lake timechart
    // and its nested search futures. As in core's expired-window/field-list
    // tests, their debug poll frames outgrow the default 2 MiB test thread.
    // Scope this to the matrix; retain the production app and all probes.
    std::thread::Builder::new()
        .stack_size(32 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(production_api_route_policy_http_matrix_case())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn production_api_route_policy_http_matrix_case() {
    const TENANT: &str = "a0a02042-0000-4000-8000-000000000002";
    if std::env::var("NANO_LAKE_TENANT_ID").as_deref() != Ok(TENANT) {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("query.token");
        let manifest = dir.path().join("manifest.json");
        std::fs::write(&token, "fixture-lake-query-credential-32-characters").unwrap();
        std::fs::write(
            &manifest,
            r#"{"objects":[{"field_types":{"metadata.uid":"string"}}]}"#,
        )
        .unwrap();
        let (peer_url, stop_peer, peer_thread) = fixture_http_peer();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child.env_clear();
        for name in ["PATH", "HOME", "LD_LIBRARY_PATH", "RUST_BACKTRACE"] {
            if let Some(value) = std::env::var_os(name) {
                child.env(name, value);
            }
        }
        child
            .args([
                "--exact",
                "routes::policy_tests::production_api_route_policy_http_matrix",
                "--nocapture",
                "--include-ignored",
            ])
            // Fixture process cannot send ordinary HTTP(S) clients to vendors.
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("NO_PROXY", "127.0.0.1,localhost")
            // Retain production retry/health behavior; this peer returns an
            // immediate semantic failure rather than a retryable outage.
            .env("VECTOR_API_URL", &peer_url)
            .env("SEARCH_SERVICE_URL", &peer_url)
            .env("INGEST_SERVICE_URL", &peer_url)
            .env("NANO_LAKE_TENANT_ID", TENANT)
            .env("NANO_LAKE_QUERY_URL", &peer_url)
            .env("NANO_LAKE_QUERY_TOKEN_FILE", &token)
            .env("NANO_LAKE_ENRICHMENT_COORDINATOR_URL", &peer_url)
            .env("NANO_LAKE_ENRICHMENT_COORDINATOR_TOKEN_FILE", &token)
            .env("NANO_LAKE_SCHEMA_MANIFEST", manifest)
            .env("NANO_SCHEMA_PROFILE", "ocsf")
            .env("NANO_IP_ALLOWLIST_DISABLED", "true")
            .env(
                "JWT_SECRET",
                "fixture-production-registry-only-0123456789abcdef",
            )
            .env("AUTH_ENABLED", "true")
            .env(
                "NANOSIEM_ENCRYPTION_KEY",
                "fixture-production-encryption-key-32",
            )
            .env("IDENTITY_STORAGE_BACKEND", "postgres")
            .env("LOOKUP_STORAGE_BACKEND", "postgres")
            .env("VECTOR_CONFIG_DIR", dir.path())
            .env("METRICS_AUTH_TOKEN", "fixture-metrics-service-credential")
            .env("VECTOR_AUTH_TOKEN", "fixture-vector-service-credential")
            .env(
                "NANOSIEM_SOAR_EGRESS_CHECK_TOKEN",
                "fixture-soar-service-credential",
            )
            .env(
                "NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY",
                "fixture-egress-hmac-credential-32-characters",
            );
        // Environment-selected constructor branches match each deployment;
        // never mutate process-global profile configuration between requests.
        #[cfg(feature = "enterprise")]
        let mut shared_audit = None;
        for shared in [false, cfg!(feature = "enterprise")]
            .into_iter()
            .take(if cfg!(feature = "enterprise") { 2 } else { 1 })
        {
            #[cfg(feature = "enterprise")]
            if shared {
                let fixture = audit_fixture::AuditFixture::start().await;
                fixture.configure_child(&mut child);
                shared_audit = Some(fixture);
            }
            let output = child
                .env(
                    "DEPLOYMENT_MODE",
                    if shared {
                        "enterprise_shared"
                    } else {
                        "self-hosted"
                    },
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            eprintln!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        #[cfg(feature = "enterprise")]
        if let Some(fixture) = shared_audit {
            fixture.finish().await;
            // A separate child proves the production audit dependency fails
            // closed. It never substitutes for the healthy shared matrix.
            let output = child
                .env("DEPLOYMENT_MODE", "enterprise_shared")
                .env("NANOSIEM_SHARED_RLS_RUNTIME_DATABASE_URL", "")
                .env("NANOSIEM_SHARED_RLS_RUNTIME_ROLE", "")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            eprintln!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        // A further isolated production construction has no configured private
        // credentials. Previously valid service tokens must never open it.
        let missing = child
            .env("DEPLOYMENT_MODE", "self-hosted")
            .env("METRICS_AUTH_TOKEN", "")
            .env("VECTOR_AUTH_TOKEN", "")
            .env("NANOSIEM_SOAR_EGRESS_CHECK_TOKEN", "")
            .env("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY", "")
            .output()
            .unwrap();
        assert!(
            missing.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&missing.stdout),
            String::from_utf8_lossy(&missing.stderr)
        );
        eprintln!(
            "{}{}",
            String::from_utf8_lossy(&missing.stdout),
            String::from_utf8_lossy(&missing.stderr)
        );
        drop(stop_peer);
        peer_thread.join().unwrap();
        return;
    }
    let (metrics, _) = crate::metrics::AppMetrics::new();
    #[cfg(feature = "enterprise")]
    if std::env::var("DEPLOYMENT_MODE").as_deref() == Ok("enterprise_shared")
        && std::env::var("NANOSIEM_SHARED_RLS_RUNTIME_ROLE").as_deref() == Ok("")
    {
        audit_dependency_failure_case().await;
        return;
    }
    if std::env::var("VECTOR_AUTH_TOKEN").as_deref() == Ok("") {
        let state = production_state(false).await;
        let private = create_internal_router(&state, &metrics);
        let paths = [
            ("GET", "/metrics"),
            ("GET", "/internal/hosted-config"),
            ("GET", "/api/internal/vector-config/current/manifest"),
            ("GET", "/api/internal/otlp-auth"),
            ("POST", "/internal/soar/egress-check"),
            ("POST", "/internal/soar/smtp-egress-check"),
            ("POST", "/internal/egress/check"),
            ("GET", "/internal/egress/tenants"),
        ];
        for (method, path) in paths {
            let result = private
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("authorization", "Bearer fixture-metrics-service-credential")
                        .header(
                            "x-nano-service-authorization",
                            "Bearer fixture-vector-service-credential",
                        )
                        .header("content-type", "application/json")
                        .body(Body::from("{malformed"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    result.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
                ),
                "unconfigured private {method} {path}: {}",
                result.status()
            );
        }
        state.shutdown_all_tasks().await;
        eprintln!(
            "API unconfigured private production probes: {}",
            paths.len()
        );
        return;
    }
    let mut probes = 0;
    let mut minimum_probes = 0;
    for shared in [std::env::var("DEPLOYMENT_MODE").as_deref() == Ok("enterprise_shared")] {
        eprintln!("API production profile start: shared={shared}");
        let state = production_state(shared).await;
        #[cfg(feature = "enterprise")]
        if shared {
            assert!(
                state.tenant_ai_rls_runtime.is_some(),
                "healthy shared production audit runtime is required"
            );
        }
        let inventory = route_manifest(&state);
        required_grants::check(&inventory, shared);
        eprintln!(
            "API production inventory: shared={shared}; rows={}",
            inventory.len()
        );
        minimum_probes += inventory
            .iter()
            .map(|row| if row.policy.is_public() { 1 } else { 3 })
            .sum::<usize>();
        assert!(
            inventory.len() >= 400,
            "review any production registration removal: {}",
            inventory.len()
        );
        assert!(inventory.iter().all(|e| !e.path.starts_with("/internal/")
            && !e.path.starts_with("/api/internal/")
            && e.path != "/metrics"));
        // The same full production constructor builds AuthState and every
        // surrounding guard/mount. Replace only credential resolution, whose
        // database-backed integration tests own membership/revocation proof.
        let app = matrix_app(state.clone());
        let scoped = nanosiem_api_lib::tenant_path::scoped_api_router(app.clone()).layer(
            Extension(nanosiem_core::auth::TrustedTenantContext {
                tenant_id: uuid::Uuid::from_u128(1),
                tenant_slug: "acme".into(),
            }),
        );
        // Complete policy admission must still respect the authenticated
        // tenant, using the same production redispatch and URL fence.
        let validate = inventory
            .iter()
            .find(|row| row.method == "GET" && row.path == "/api/auth/validate")
            .expect("production identity validation route");
        for (slug, expected) in [
            ("/t/acme", StatusCode::OK),
            ("/t/other", StatusCode::FORBIDDEN),
        ] {
            let (status, body) = response_at(
                scoped.clone(),
                validate,
                principal(false, vec![]),
                "GET",
                slug,
            )
            .await;
            assert_eq!(status, expected, "trusted tenant fence {slug}: {body}");
            assert!(
                !body.contains("route_policy_denied") && !body.contains("route_policy_missing")
            );
            probes += 1;
        }
        if shared {
            // Tuning version numbers are integers, not resource UUIDs. Keep
            // these actual mounted templates registered. Independently check
            // unconditional shared-operation grants; the HTTP loop below
            // removes each grant to prove denial before extraction/owner work.
            for (method, path, required) in [
                (
                    "GET",
                    "/api/tuning/versions/{rule_id}/{version_id}",
                    &["detections:view"][..],
                ),
                (
                    "POST",
                    "/api/tuning/versions/{rule_id}/{version_id}/activate",
                    &["detections:edit", "detections:promote"][..],
                ),
                (
                    "POST",
                    "/api/tuning/logs/{id}/revert",
                    &["detections:edit", "detections:promote"][..],
                ),
                (
                    "GET",
                    "/api/entities/{entity_type}/{entity_value}/context",
                    &["risk:view", "alerts:view", "cases:view", "detections:view"][..],
                ),
                (
                    "GET",
                    "/api/entities/{entity_type}/{entity_value}/risk-timeline",
                    &["risk:view", "detections:view"][..],
                ),
                (
                    "GET",
                    "/api/risk/watchlists",
                    &["risk:view", "risk:watchlists"][..],
                ),
                (
                    "POST",
                    "/api/risk/watchlists",
                    &["risk:view", "risk:watchlists"][..],
                ),
                (
                    "POST",
                    "/api/playbook-repositories/{id}/sync-and-import",
                    &["playbook_repositories:sync", "playbook_repositories:import"][..],
                ),
                (
                    "POST",
                    "/api/playbook-repositories/{id}/apply-all-upstream-updates",
                    &["playbooks:manage", "playbook_repositories:view"][..],
                ),
                (
                    "POST",
                    "/api/threat-intel/indicator-lookup",
                    &["enrichments:view", "search:execute"][..],
                ),
                (
                    "PUT",
                    "/api/marketplace/collectors/{slug}",
                    &["enrichments:configure", "log_sources:deploy"][..],
                ),
                (
                    "POST",
                    "/api/marketplace/collectors/{slug}/install",
                    &["enrichments:configure", "log_sources:deploy"][..],
                ),
                (
                    "DELETE",
                    "/api/marketplace/collectors/{slug}",
                    &[
                        "enrichments:configure",
                        "log_sources:deploy",
                        "log_sources:delete",
                        "log_sources:view",
                    ][..],
                ),
                (
                    "PUT",
                    "/api/marketplace/collectors/{slug}/credentials",
                    &[
                        "enrichments:configure",
                        "log_sources:deploy",
                        "credentials:create",
                    ][..],
                ),
                (
                    "DELETE",
                    "/api/marketplace/collectors/{slug}/components/{component}",
                    &["enrichments:configure", "log_sources:deploy"][..],
                ),
            ] {
                let row = inventory
                    .iter()
                    .find(|row| row.method == method && row.path == path)
                    .expect("mounted shared operation");
                match row.policy.capability() {
                    CapabilityRequirement::AllOf(permissions) => {
                        assert_eq!(permissions.as_ref(), required, "{method} {path}");
                    }
                    other => panic!("required shared conjunction {method} {path}: {other:?}"),
                }
            }
            let preview = inventory
                .iter()
                .find(|row| row.method == "POST" && row.path == "/api/upload/preview")
                .expect("mounted shared upload preview");
            assert!(matches!(
                preview.policy.capability(),
                CapabilityRequirement::AnyOf(permissions)
                    if permissions.as_ref() == &["upload:logs", "lookup:create"][..]
            ));
        }
        for row in &inventory {
            if row.policy.is_public() {
                assert!(reviewed_public(row), "unreviewed Public row: {row:?}");
            }
            match row.policy.capability() {
                CapabilityRequirement::AllOf(perms) | CapabilityRequirement::AnyOf(perms) => {
                    assert!(!perms.is_empty(), "empty policy {row:?}");
                    for permission in perms.iter() {
                        assert!(
                            nanosiem_core::auth::permissions::is_valid_permission(permission),
                            "unknown grant {permission} in {row:?}"
                        );
                    }
                }
                CapabilityRequirement::AllOfAnyOf { all, any } => {
                    assert!(!all.is_empty() && !any.is_empty());
                    for permission in all.iter().chain(any.iter()) {
                        assert!(nanosiem_core::auth::permissions::is_valid_permission(
                            permission
                        ));
                    }
                }
                CapabilityRequirement::None => {}
            }
        }
        for row in inventory.iter().filter(|r| r.policy.is_public()) {
            let result = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(row.method)
                        .uri(uri(&row.path))
                        .header("content-type", "application/json")
                        .body(Body::from("{malformed"))
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(result.into_body(), 4 * 1024 * 1024)
                .await
                .unwrap();
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                assert!(
                    !matches!(
                        value["error"].as_str(),
                        Some("route_policy_missing" | "route_policy_denied")
                    ),
                    "explicit public route {} {}",
                    row.method,
                    row.path
                );
            }
            probes += 1;
        }
        for row in inventory.iter().filter(|r| !r.policy.is_public()) {
            let anonymous = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(row.method)
                        .uri(uri(&row.path))
                        .header("content-type", "application/json")
                        .body(Body::from("{malformed"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                anonymous.status(),
                StatusCode::UNAUTHORIZED,
                "anonymous {} {}",
                row.method,
                row.path
            );
            probes += 1;
            for api_key in [false, true] {
                for permissions in [vec![], vec!["unrelated:capability".into()]] {
                    let context = principal(api_key, permissions);
                    if admits_without_capability(&row.policy, api_key) {
                        continue;
                    }
                    let (status, body) = response(app.clone(), row, context, row.method).await;
                    assert_eq!(
                        status,
                        StatusCode::FORBIDDEN,
                        "negative shared={shared} api_key={api_key} {} {}: {body}",
                        row.method,
                        row.path
                    );
                    policy_denial(&body);
                    probes += 1;
                    if row.path.starts_with("/api/") {
                        let (status, body) = response_at(
                            scoped.clone(),
                            row,
                            principal(api_key, vec![]),
                            row.method,
                            "/t/acme",
                        )
                        .await;
                        assert_eq!(
                            status,
                            StatusCode::FORBIDDEN,
                            "tenant alias {} {}: {body}",
                            row.method,
                            row.path
                        );
                        policy_denial(&body);
                        probes += 1;
                    }
                }
                for complete in grants(&row.policy) {
                    let context = principal(api_key, complete.clone());
                    if !api_key || row.policy.auth_mode() != AuthMode::InteractiveSession {
                        let (_, body) = response(app.clone(), row, context, row.method).await;
                        assert!(
                            !body.contains("route_policy_denied")
                                && !body.contains("route_policy_missing"),
                            "full grant {} {}: {body}",
                            row.method,
                            row.path
                        );
                        probes += 1;
                    }
                    if api_key && row.policy.auth_mode() == AuthMode::InteractiveSession {
                        let (status, body) = response(
                            app.clone(),
                            row,
                            principal(true, complete.clone()),
                            row.method,
                        )
                        .await;
                        assert_eq!(
                            status,
                            StatusCode::FORBIDDEN,
                            "key with complete capabilities on human route {}: {body}",
                            row.path
                        );
                        policy_denial(&body);
                        probes += 1;
                    }
                    for omitted in 0..complete.len() {
                        let mut partial = complete.clone();
                        partial.remove(omitted);
                        let context = principal(api_key, partial);
                        if admits_without_capability(&row.policy, api_key) {
                            continue;
                        }
                        let (status, body) = response(app.clone(), row, context, row.method).await;
                        assert_eq!(
                            status,
                            StatusCode::FORBIDDEN,
                            "partial {} {}: {body}",
                            row.method,
                            row.path
                        );
                        policy_denial(&body);
                        probes += 1;
                    }
                }
                if row.method == "GET" {
                    let context = principal(api_key, vec![]);
                    if !admits_without_capability(&row.policy, api_key) {
                        assert_eq!(
                            response(app.clone(), row, context, "HEAD").await.0,
                            StatusCode::FORBIDDEN
                        );
                        probes += 1;
                    }
                }
            }
        }
        if !shared {
            // Independent caller contracts: optional sharing, assignment,
            // credential changes and persisted-alert reads must not become
            // universal AND requirements at the coarse boundary.
            let minimal: &[(&str, &str, &[&str])] = &[
                ("POST", "/api/playbooks/dry-resolve", &["playbooks:manage"]),
                ("PATCH", "/api/playbooks/{id}", &["playbooks:manage"]),
                ("PATCH", "/api/hunts/{id}", &["hunts:manage"]),
                ("PUT", "/api/dashboards/{id}", &["dashboards:edit"]),
                ("POST", "/api/dashboards/panel/query", &["dashboards:view", "search:execute"]),
                ("POST", "/api/dashboards/panel/query", &["dashboards:view", "search:sql"]),
                ("DELETE", "/api/dashboards/{id}", &["dashboards:delete"]),
                ("POST", "/api/dashboards/{id}/share", &["dashboards:edit"]),
                ("GET", "/api/audit", &["audit:view"]),
                ("POST", "/api/audit/export", &["audit:view"]),
                ("POST", "/api/alerts/bulk", &["alerts:acknowledge"]),
                ("POST", "/api/alerts/bulk", &["alerts:close"]),
                ("PATCH", "/api/connector-feeds/{id}", &["log_sources:edit"]),
                ("POST", "/api/cases/bulk/status", &["cases:close"]),
                ("POST", "/api/cases/bulk/status", &["cases:edit"]),
                ("POST", "/api/cases/{id}/status", &["cases:close"]),
                ("POST", "/api/cases/{id}/status", &["cases:edit"]),
                ("POST", "/api/cases/{id}/share", &["cases:share"]),
                ("POST", "/api/notebooks/{id}/entries", &["cases:edit"]),
                ("POST", "/api/notebooks/{id}/chat", &["melod:notebook", "cases:edit"]),
                ("POST", "/api/notebooks/{id}/chat/stream", &["melod:notebook", "cases:edit"]),
                ("POST", "/api/melod/parser", &["melod:parser", "parsers:view"]),
                ("POST", "/api/melod/parser", &["melod:parser", "log_sources:view"]),
                ("POST", "/api/melod/parser/stream", &["melod:parser", "parsers:view"]),
                ("POST", "/api/melod/parser/stream", &["melod:parser", "log_sources:view"]),
                ("POST", "/api/cases/saved-searches", &["cases:create"]),
                ("PATCH", "/api/cases/saved-searches/{id}", &["cases:edit"]),
                ("POST", "/api/log-sources/test-vrl", &["log_sources:view"]),
                (
                    "POST",
                    "/api/integrations/custom/preview",
                    &["log_sources:create", "enrichments:code"],
                ),
                ("POST", "/api/integrations/instances", &["log_sources:edit"]),
                (
                    "PUT",
                    "/api/integrations/instances/{id}",
                    &["log_sources:edit"],
                ),
            ];
            let mut examples = 0;
            for (method, path, permissions) in minimal {
                // Some product families are enterprise-only.
                let Some(row) = inventory
                    .iter()
                    .find(|row| row.method == *method && row.path == *path)
                else {
                    continue;
                };
                for key in [false, true] {
                    let (_, body) = response(
                        app.clone(),
                        row,
                        principal(key, permissions.iter().map(|p| p.to_string()).collect()),
                        method,
                    )
                    .await;
                    assert!(
                        !body.contains("route_policy_denied")
                            && !body.contains("route_policy_missing"),
                        "minimal legitimate caller {method} {path}: {body}"
                    );
                    examples += 1;
                    probes += 1;
                }
            }
            assert!(
                examples >= 10,
                "minimal caller contracts were accidentally skipped"
            );
            for (method, path, optional) in [
                ("GET", "/api/audit", "settings:system"),
                ("POST", "/api/notebooks/{id}/entries", "notebooks:view"),
                ("POST", "/api/cases/{id}/status", "cases:assign"),
                ("PATCH", "/api/cases/saved-searches/{id}", "cases:share"),
            ] {
                let Some(row) = inventory
                    .iter()
                    .find(|row| row.method == method && row.path == path)
                else {
                    continue;
                };
                let (status, body) = response(
                    app.clone(),
                    row,
                    principal(true, vec![optional.into()]),
                    method,
                )
                .await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                policy_denial(&body);
                probes += 1;
            }
        }
        let admission_dir = tempfile::tempdir().unwrap();
        let admission = admission_dir.path().join("admission.json");
        std::fs::write(&admission,serde_json::to_vec(&serde_json::json!({
            "schema":"nano-egress-admission/v1","deployment_id":"registry-fixture","cluster_id":"fixture-cluster",
            "region":"us-east-1","stage":"authority","evidence_sha256":"a".repeat(64),
            "accepted_at":"2026-10-30T00:00:00Z","app_hostname":"fixture.nano.rs"
        })).unwrap()).unwrap();
        let private_rows = registered_internal_routes(&state, &metrics, &admission)
            .manifest()
            .to_vec();
        for path in [
            "/internal/egress/check",
            "/internal/egress/acl",
            "/internal/egress/tenants",
            "/internal/egress/requirements",
        ] {
            assert!(
                private_rows.iter().any(|row| row.path == path),
                "admitted fixture silently omitted {path}"
            );
        }
        let private = internal_router_with_admission(&state, &metrics, &admission);
        for row in &private_rows {
            eprintln!("API private policy probe: {} {}", row.method, row.path);
            assert!(matches!(
                row.policy.auth_mode(),
                AuthMode::ServiceIdentity(_)
            ));
            let negative_header = match row.policy.auth_mode() {
                AuthMode::ServiceIdentity(
                    "hosted-config-reader" | "ingress-proxy" | "egress-proxy",
                ) => "x-nano-service-authorization",
                _ => "authorization",
            };
            for credential in [
                None,
                Some("Bearer customer-session"),
                Some("Bearer unrelated-service"),
            ] {
                let mut request = Request::builder()
                    .method(row.method)
                    .uri(uri(&row.path))
                    .header("content-type", "application/json");
                if let Some(value) = credential {
                    request = request.header(negative_header, value);
                }
                let response = private
                    .clone()
                    .oneshot(request.body(Body::from("{malformed")).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "private {} {}",
                    row.method,
                    row.path
                );
                probes += 1;
            }
            let egress = nanosiem_core::egress::Principal::new(
                b"fixture-egress-hmac-credential-32-characters",
                nanosiem_core::egress::LOCAL_TENANT,
                nanosiem_core::egress::Purpose::Platform,
            )
            .unwrap()
            .basic();
            let (header, credential) = match row.policy.auth_mode() {
                AuthMode::ServiceIdentity("operations-collector") => {
                    ("authorization", "Bearer fixture-metrics-service-credential")
                }
                AuthMode::ServiceIdentity("hosted-config-reader") => (
                    "x-nano-service-authorization",
                    "Bearer fixture-metrics-service-credential",
                ),
                AuthMode::ServiceIdentity("vector-config-consumer") => {
                    ("authorization", "Bearer fixture-vector-service-credential")
                }
                AuthMode::ServiceIdentity("ingress-proxy") => (
                    "x-nano-service-authorization",
                    "Bearer fixture-vector-service-credential",
                ),
                AuthMode::ServiceIdentity("soar-egress-proxy") => {
                    ("authorization", "Bearer fixture-soar-service-credential")
                }
                AuthMode::ServiceIdentity("egress-proxy") => {
                    ("x-nano-service-authorization", egress.as_str())
                }
                other => panic!("review service fixture {other:?}"),
            };
            let request = || {
                let mut request = Request::builder()
                    .method(row.method)
                    .uri(uri(&row.path))
                    .header(header, credential)
                    .header("content-type", "application/json");
                if row.path == "/api/internal/otlp-auth" {
                    // Distinct sender authority reaches the closed owner lookup;
                    // service authentication alone cannot accept ingestion.
                    request = request.header("authorization", "Bearer fixture-ingest-sender");
                }
                request.body(Body::from("{malformed")).unwrap()
            };
            let mut duplicate = request();
            duplicate
                .headers_mut()
                .append(header, credential.parse().unwrap());
            assert_eq!(
                private.clone().oneshot(duplicate).await.unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "ambiguous service credential {}",
                row.path
            );
            probes += 1;
            if row.policy.auth_mode() == AuthMode::ServiceIdentity("egress-proxy") {
                let mut proxied = request();
                proxied.headers_mut().insert(
                    "authorization",
                    "Bearer fixture-kubernetes-auth".parse().unwrap(),
                );
                let result = private.clone().oneshot(proxied).await.unwrap();
                assert!(
                    !matches!(
                        result.status(),
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                    ),
                    "Kubernetes auth must coexist with scoped proxy identity: {} {}",
                    row.path,
                    result.status()
                );
                probes += 1;
                let mut ambiguous = request();
                ambiguous
                    .headers_mut()
                    .insert("authorization", egress.parse().unwrap());
                ambiguous.headers_mut().insert(
                    "x-nano-service-authorization",
                    "Basic invalid".parse().unwrap(),
                );
                assert_eq!(
                    private.clone().oneshot(ambiguous).await.unwrap().status(),
                    StatusCode::UNAUTHORIZED,
                    "an invalid dedicated service identity must not fall back to another header"
                );
                probes += 1;
            }
            let authorized = private.clone().oneshot(request()).await.unwrap();
            assert!(
                !matches!(
                    authorized.status(),
                    StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
                ),
                "valid service must pass policy: {} {}",
                row.path,
                authorized.status()
            );
            if row.path == "/api/internal/otlp-auth" {
                assert_eq!(
                    authorized.status(),
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ingress and sender identities must reach the closed owner lookup"
                );
                let mut sender_only = request();
                sender_only
                    .headers_mut()
                    .remove("x-nano-service-authorization");
                assert_eq!(
                    private.clone().oneshot(sender_only).await.unwrap().status(),
                    StatusCode::UNAUTHORIZED
                );
                let mut service_only = request();
                service_only.headers_mut().remove("authorization");
                assert_eq!(
                    private
                        .clone()
                        .oneshot(service_only)
                        .await
                        .unwrap()
                        .status(),
                    StatusCode::UNAUTHORIZED
                );
                probes += 2;
            }
            // Valid service credentials never make an internal method reachable
            // on the public app, including when a caller supplies user grants.
            let public = app
                .clone()
                .layer(Extension(principal(true, vec!["*".into()])));
            let result = public.oneshot(request()).await.unwrap();
            assert_eq!(
                result.status(),
                StatusCode::FORBIDDEN,
                "internal route on public listener: {}",
                row.path
            );
            let body = axum::body::to_bytes(result.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
                "route_policy_missing",
                "private transport must be absent from public registration: {}",
                row.path
            );
            let mut unsupported = request();
            *unsupported.method_mut() = Method::TRACE;
            let result = private.clone().oneshot(unsupported).await.unwrap();
            assert_eq!(result.status(), StatusCode::FORBIDDEN);
            let body = axum::body::to_bytes(result.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
                "route_policy_missing",
                "undeclared private method: {}",
                row.path
            );
            probes += 3;
        }
        state.shutdown_all_tasks().await;
        eprintln!(
            "API registry profile shared={shared}: {} public rows, {} private rows",
            inventory.len(),
            private_rows.len()
        );
    }
    assert!(
        probes >= minimum_probes,
        "matrix accidentally narrowed: {probes} < {minimum_probes}"
    );
    eprintln!("API production RoutePolicy HTTP probes: {probes}");
}
