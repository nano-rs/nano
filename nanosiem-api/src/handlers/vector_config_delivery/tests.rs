// SPDX-License-Identifier: AGPL-3.0-or-later

//! Auth-gate tests for the internal delivery endpoints. Path validation is
//! covered in `nanosiem_core::parsers::vector_config::delivery::tests`.

use super::*;

#[test]
fn no_configured_token_disables_the_endpoint() {
    // Fail closed: even a "correct-looking" bearer gets 404 when no token is
    // provisioned — the feature must not exist without its shared secret.
    assert_eq!(
        authorize_delivery(Some("Bearer anything"), None),
        Err(StatusCode::NOT_FOUND)
    );
    assert_eq!(authorize_delivery(None, None), Err(StatusCode::NOT_FOUND));
}

#[test]
fn missing_or_malformed_authorization_is_401() {
    let configured = Some("s3cr3t");
    assert_eq!(
        authorize_delivery(None, configured),
        Err(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        authorize_delivery(Some("s3cr3t"), configured),
        Err(StatusCode::UNAUTHORIZED),
        "raw token without Bearer scheme must be refused"
    );
    assert_eq!(
        authorize_delivery(Some("Basic s3cr3t"), configured),
        Err(StatusCode::UNAUTHORIZED)
    );
}

#[test]
fn wrong_token_is_401_and_right_token_passes() {
    let configured = Some("s3cr3t");
    assert_eq!(
        authorize_delivery(Some("Bearer wrong"), configured),
        Err(StatusCode::UNAUTHORIZED)
    );
    // Prefix of the real token must not pass.
    assert_eq!(
        authorize_delivery(Some("Bearer s3cr3"), configured),
        Err(StatusCode::UNAUTHORIZED)
    );
    assert_eq!(authorize_delivery(Some("Bearer s3cr3t"), configured), Ok(()));
    // Surrounding whitespace after the scheme is tolerated (curl -H quirks).
    assert_eq!(
        authorize_delivery(Some("Bearer  s3cr3t"), configured),
        Ok(())
    );
}

#[test]
fn constant_time_eq_behaves() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(constant_time_eq(b"", b""));
}

/// HTTP-level path-traversal coverage for the `{*path}` wildcard delivery
/// route (NAN-1931).
///
/// The existing tests above and the core delivery tests call the validation
/// functions directly — they bypass axum's routing and percent-decoding
/// entirely. But `{*path}` is exactly the assumed-and-often-wrong layer: axum
/// 0.8 *does* percent-decode `%2f`→`/`, `%2e`→`.`, `%5c`→`\` before the
/// capture reaches the handler (verified empirically), so the handler receives
/// fully-decoded traversal strings and the Rust validation is the ONLY defense.
/// This test drives requests through a real `axum::Router` carrying the exact
/// production route pattern and the handler's own decode → `read_generation_file`
/// → `delivery_error_status` path, asserting every hostile input is rejected
/// (400/404, never a file leak) and that a legitimate path still returns 200.
///
/// The handler proper takes `State<AppState>` (a full dual-DB app state that
/// can't be built without live PG/CH). Since the only state the path-handling
/// path reads is `publications_root()`, this harness substitutes a tempdir root
/// and calls the identical, real, security-critical functions
/// (`authorize_delivery`, `read_generation_file`, `delivery_error_status`).
#[tokio::test]
async fn axum_router_rejects_path_traversal_on_wildcard_capture() {
    use axum::{
        body::Body,
        extract::Path as AxumPath,
        http::{Request, StatusCode},
        response::{IntoResponse, Response},
        routing::get,
        Router,
    };
    use std::sync::Arc;
    use tower::util::ServiceExt;

    const TOKEN: &str = "test-delivery-token";
    const GEN: i64 = 7;

    // Build a ready generation on disk: publications/<020>/configs/http.toml
    // plus the `.ready` marker the delivery reader gates on.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();
    let gen_dir = root.join(format!("{GEN:020}"));
    tokio::fs::create_dir_all(gen_dir.join("configs"))
        .await
        .expect("mkdir configs");
    tokio::fs::write(gen_dir.join("configs/http.toml"), b"# real config\n")
        .await
        .expect("write config");
    // The reader treats any generation lacking a `.ready` marker as absent
    // (404), so materialize it to make the positive control reachable.
    tokio::fs::write(gen_dir.join(".ready"), b"")
        .await
        .expect("write ready marker");

    // A handler that reproduces `get_generation_file`'s path-handling path
    // exactly (same extractor types, same auth check, same core call, same
    // status mapping), reading the tempdir root instead of AppState.
    let root = Arc::new(root);
    let app: Router = Router::new().route(
        "/api/internal/vector-config/generations/{generation}/files/{*path}",
        get({
            let root = Arc::clone(&root);
            move |AxumPath((generation, path)): AxumPath<(i64, String)>,
                  headers: axum::http::HeaderMap| {
                let root = Arc::clone(&root);
                async move {
                    // Valid bearer so we exercise path handling, not auth.
                    let authorization = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok());
                    if let Err(status) = authorize_delivery(authorization, Some(TOKEN)) {
                        return status.into_response();
                    }
                    match vector_config_delivery::read_generation_file(&root, generation, &path)
                        .await
                    {
                        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
                        Ok(None) => StatusCode::NOT_FOUND.into_response(),
                        Err(error) => delivery_error_status(error).into_response(),
                    }
                }
            }
        }),
    );

    async fn send(app: &Router, uri: &str) -> Response {
        app.clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("router response")
    }

    let base = format!("/api/internal/vector-config/generations/{GEN}/files");

    // (uri suffix, must-be-rejected). Every one of these decodes — at the axum
    // layer — into a traversal / non-canonical spelling, and must never leak a
    // file. 400 = malformed request (traversal), 404 = not found; both are
    // acceptable rejections. A 200 on any of these is a P0 file-read escape.
    let hostile = [
        // percent-encoded traversal to /etc/passwd
        "configs%2f..%2f..%2f..%2fetc%2fpasswd",
        // percent-encoded traversal into a SIBLING generation's manifest
        "..%2f..%2f_manifest.json",
        // literal ../ traversal
        "configs/../../_envelope.sig",
        // dot-segment: must be refused by the exact-spelling rule
        "configs/./http.toml",
        // double slash: non-canonical spelling
        "configs//http.toml",
        // absolute path
        "/etc/passwd",
        // backslash traversal (Unix: not a separator, but must be refused)
        "configs\\..\\..\\file",
    ];

    for suffix in hostile {
        let uri = format!("{base}/{suffix}");
        let response = send(&app, &uri).await;
        let status = response.status();
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
            "hostile input `{suffix}` was NOT rejected: got {status} (expected 400/404). \
             A non-rejection here is a path-traversal file leak — P0.",
        );
        // Belt-and-suspenders: never a 2xx.
        assert!(
            !status.is_success(),
            "hostile input `{suffix}` returned success {status} — file leak, P0",
        );
    }

    // Positive control: the real, canonical file path must return 200 with its
    // bytes. Without this the whole test could pass by rejecting everything.
    let good = send(&app, &format!("{base}/configs/http.toml")).await;
    assert_eq!(
        good.status(),
        StatusCode::OK,
        "legitimate path `configs/http.toml` must return 200 (positive control)",
    );
    let body = axum::body::to_bytes(good.into_response().into_body(), 1 << 20)
        .await
        .expect("read body");
    assert_eq!(
        &body[..],
        b"# real config\n",
        "positive control returned the wrong file bytes",
    );
}

/// Security review 2026-11-08 (NAN-5042): config delivery has its own
/// credential. Once it is provisioned, the forwarder install token, which
/// every forwarder holds, no longer opens /api/internal/vector-config/*.
mod delivery_credential {
    use super::*;
    use nanosiem_core::deployment_posture::{
        resolve_vector_config_delivery, DeliveryDisabledReason,
        VectorConfigDeliveryCredential as C,
    };

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    /// The exact role-split upgrade order: the app host is upgraded first and
    /// gets NANO_VECTOR_CONFIG_DELIVERY_TOKEN; an ingest host still runs with
    /// its older copied .env, so its consumer presents the install token.
    /// During v2.0.x that consumer must keep receiving config (parser
    /// publishes, new and REVOKED ingest tokens). An upgraded consumer uses the
    /// dedicated token. A caller with neither is refused.
    #[test]
    fn app_host_upgraded_first_still_serves_an_ingest_host_with_an_older_env() {
        let app_host =
            resolve_vector_config_delivery(None, Some("delivery-secret"), Some("install-token"), false);
        let peer: SocketAddr = "10.30.0.21:40000".parse().unwrap();
        // Ingest host not upgraded yet: consumer falls back to the install token.
        assert_eq!(
            authorize_with(&bearer("install-token"), Some(&peer), app_host.clone()),
            Ok(DeliveryAuth::InstallTokenFallback)
        );
        // Ingest host upgraded: consumer presents the dedicated token.
        assert_eq!(
            authorize_with(&bearer("delivery-secret"), Some(&peer), app_host.clone()),
            Ok(DeliveryAuth::Dedicated)
        );
        assert_eq!(
            authorize_with(&bearer("forwarder-guess"), Some(&peer), app_host),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn strict_mode_refuses_the_install_token_once_the_delivery_token_exists() {
        let credential =
            resolve_vector_config_delivery(None, Some("delivery-secret"), Some("install-token"), true);
        assert_eq!(
            authorize_with(&bearer("install-token"), None, credential.clone()),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            authorize_with(&bearer("delivery-secret"), None, credential),
            Ok(DeliveryAuth::Dedicated)
        );
    }

    #[test]
    fn delivery_switched_off_is_404_for_every_token() {
        let credential =
            resolve_vector_config_delivery(Some("off"), Some("delivery-secret"), Some("install-token"), false);
        for token in ["install-token", "delivery-secret", "anything"] {
            assert_eq!(
                authorize_with(&bearer(token), None, credential.clone()),
                Err(StatusCode::NOT_FOUND),
                "{token}"
            );
        }
        assert_eq!(
            authorize_with(
                &bearer("x"),
                None,
                C::Disabled(DeliveryDisabledReason::NoCredential)
            ),
            Err(StatusCode::NOT_FOUND)
        );
    }

    #[test]
    fn deprecated_install_token_fallback_still_serves_an_unprovisioned_deployment() {
        // v2.0.x compatibility: a deployment that has not provisioned the
        // delivery token yet (an old shared .env, an existingSecret without the
        // key) keeps its consumers working, with a warning.
        let credential = resolve_vector_config_delivery(None, None, Some("install-token"), false);
        let peer: SocketAddr = "10.20.0.7:51515".parse().unwrap();
        assert_eq!(
            authorize_with(&bearer("install-token"), Some(&peer), credential.clone()),
            Ok(DeliveryAuth::InstallTokenFallback)
        );
        assert_eq!(
            authorize_with(&bearer("wrong"), Some(&peer), credential),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    /// NAN-5148: the v2.0.x install-token fallback covers private install
    /// tokens only. A known-public install token is refused for delivery in
    /// both fallback modes, while a private install token keeps working and
    /// the dedicated token is always accepted.
    #[test]
    fn public_install_token_is_refused_for_delivery() {
        let public = "nanosiem-default-token";
        let peer: SocketAddr = "10.20.0.7:51515".parse().unwrap();
        // No dedicated token: delivery is off (404), even for the public value.
        let legacy = resolve_vector_config_delivery(None, None, Some(public), false);
        assert_eq!(
            authorize_with(&bearer(public), Some(&peer), legacy),
            Err(StatusCode::NOT_FOUND)
        );
        // Dedicated token beside a public install token: install refused,
        // dedicated accepted.
        for strict in [false, true] {
            let both =
                resolve_vector_config_delivery(None, Some("delivery-secret"), Some(public), strict);
            assert_eq!(
                authorize_with(&bearer(public), Some(&peer), both.clone()),
                Err(StatusCode::UNAUTHORIZED),
                "strict={strict}"
            );
            assert_eq!(
                authorize_with(&bearer("delivery-secret"), Some(&peer), both),
                Ok(DeliveryAuth::Dedicated),
                "strict={strict}"
            );
        }
    }

    #[test]
    fn private_install_token_fallback_is_unchanged() {
        let peer: SocketAddr = "10.20.0.7:51515".parse().unwrap();
        for credential in [
            resolve_vector_config_delivery(None, None, Some("9f2c-private-install"), false),
            resolve_vector_config_delivery(
                None,
                Some("delivery-secret"),
                Some("9f2c-private-install"),
                false,
            ),
        ] {
            assert_eq!(
                authorize_with(&bearer("9f2c-private-install"), Some(&peer), credential),
                Ok(DeliveryAuth::InstallTokenFallback)
            );
        }
    }

    // ── NAN-5042: disabling the install token revokes config delivery ───────

    /// The exploit: the install token is a semi-trusted forwarder credential.
    /// An admin disables it (Settings > Ingest tokens), which re-rendered only
    /// Vector's tokens file; the delivery fallback still matched it, so the
    /// forwarder could keep downloading rendered configs. Now refused.
    #[test]
    fn disabled_install_token_no_longer_opens_delivery() {
        for credential in [
            resolve_vector_config_delivery(None, None, Some("install-token"), false),
            resolve_vector_config_delivery(None, Some("delivery-secret"), Some("install-token"), false),
        ] {
            let auth = authorize_with(&bearer("install-token"), None, credential).unwrap();
            assert_eq!(auth, DeliveryAuth::InstallTokenFallback);
            assert_eq!(
                admit_install_token_fallback(Ok(false)),
                Err(StatusCode::UNAUTHORIZED)
            );
        }
    }

    /// Upgrade compatibility: an enabled install token still serves a consumer
    /// whose .env predates the dedicated token.
    #[test]
    fn enabled_install_token_fallback_keeps_an_upgraded_consumer_working() {
        assert_eq!(admit_install_token_fallback(Ok(true)), Ok(()));
    }

    /// Fail closed when the switch cannot be read; 503 (not 401) so the
    /// consumer keeps its current generation and retries.
    #[test]
    fn unreadable_install_token_switch_fails_closed_with_503() {
        assert_eq!(
            admit_install_token_fallback(Err(())),
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );
    }

    /// The dedicated credential never consults the install-token switch: an
    /// admin disabling forwarders' install token must not cut off a consumer
    /// that already uses its own delivery token.
    #[test]
    fn dedicated_token_is_independent_of_the_install_token_switch() {
        for strict in [false, true] {
            let credential = resolve_vector_config_delivery(
                None,
                Some("delivery-secret"),
                Some("install-token"),
                strict,
            );
            assert_eq!(
                authorize_with(&bearer("delivery-secret"), None, credential),
                Ok(DeliveryAuth::Dedicated)
            );
        }
    }
}

/// NAN-5042 end to end against a real PostgreSQL: the delivery gate reads the
/// install-token switch the admin flips, through the same service the
/// Settings page uses. Needs a disposable `NANOSIEM_TEST_DATABASE_URL`.
mod install_token_switch_db {
    use super::*;
    use nanosiem_core::deployment_posture::resolve_vector_config_delivery;
    use nanosiem_core::ingest_tokens::IngestTokenService;

    const MIGRATION: &str =
        include_str!("../../../../migrations/postgres/290_ingest_tokens.sql");

    async fn service() -> Option<(IngestTokenService, sqlx::PgPool, String)> {
        let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
        let schema = format!("nan5042_{}", uuid::Uuid::new_v4().simple());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect({
                let schema = schema.clone();
                move |conn, _| {
                    let schema = schema.clone();
                    Box::pin(async move {
                        sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str())
                            .await
                            .map(|_| ())
                    })
                }
            })
            .connect(&url)
            .await
            .expect("connect");
        // An UPGRADED install (a real user exists), so migration 290 starts the
        // install token in legacy multiplex mode, enabled: the exact state in
        // which the v2.0.x delivery fallback is in use.
        sqlx::raw_sql(&format!(
            "CREATE SCHEMA {schema};
             CREATE TABLE {schema}.users (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), status TEXT);
             INSERT INTO {schema}.users (status) VALUES ('system'), ('active');
             CREATE TABLE {schema}.log_sources (
                 id UUID PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
                 match_values TEXT[], enabled BOOLEAN NOT NULL DEFAULT TRUE,
                 deployed BOOLEAN NOT NULL DEFAULT FALSE,
                 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());"
        ))
        .execute(&pool)
        .await
        .expect("setup");
        sqlx::raw_sql(&MIGRATION.replace("SET LOCAL lock_timeout = '5s';", ""))
            .execute(&pool)
            .await
            .expect("migration 290");
        let dir = std::env::temp_dir().join(&schema);
        std::fs::create_dir_all(&dir).unwrap();
        let svc = IngestTokenService::with_paths(
            pool.clone(),
            dir.join("tokens.json"),
            String::new(),
            Some("install-token".into()),
        );
        Some((svc, pool, schema))
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[tokio::test]
    #[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
    async fn disabling_the_install_token_revokes_config_delivery() {
        let Some((svc, pool, schema)) = service().await else {
            return;
        };
        let peer: SocketAddr = "10.30.0.21:40000".parse().unwrap();
        // Compose role-split upgrade (strict pinned false) and an unprovisioned
        // deployment: the two shapes in which the fallback is live.
        let shapes = [
            resolve_vector_config_delivery(None, Some("delivery-secret"), Some("install-token"), false),
            resolve_vector_config_delivery(None, None, Some("install-token"), false),
        ];

        // Enabled (as upgraded): the older consumer keeps receiving config.
        for credential in &shapes {
            assert_eq!(
                authorize_request(&svc, &bearer("install-token"), Some(&peer), credential.clone(), DeliveryResource::Config).await,
                Ok(())
            );
        }

        // The admin disables the install token. Before NAN-5042 this changed
        // only Vector's tokens file; delivery still answered 200.
        svc.set_install_token_enabled(false, None).await.unwrap();
        for credential in &shapes {
            assert_eq!(
                authorize_request(&svc, &bearer("install-token"), Some(&peer), credential.clone(), DeliveryResource::Config).await,
                Err(StatusCode::UNAUTHORIZED),
                "a disabled install token still opened config delivery"
            );
        }
        // ...but the hashed tokens file still reaches a fallback consumer: it is
        // what makes that host refuse the disabled install token for ingest.
        // Refusing it would strand the host on a cached `fallback_enabled: true`.
        for credential in &shapes {
            assert_eq!(
                authorize_request(&svc, &bearer("install-token"), Some(&peer), credential.clone(), DeliveryResource::TokensFile).await,
                Ok(()),
                "the revocation never reaches a fallback consumer"
            );
            assert_eq!(
                authorize_request(&svc, &bearer("forwarder-guess"), Some(&peer), credential.clone(), DeliveryResource::TokensFile).await,
                Err(StatusCode::UNAUTHORIZED)
            );
        }
        // The file that fallback consumer now receives drops the install token
        // (this test service publishes it to disk, the same render).
        let rendered =
            std::fs::read_to_string(std::env::temp_dir().join(&schema).join("tokens.json")).unwrap();
        assert!(rendered.contains("\"fallback_enabled\": false"), "{rendered}");
        // A consumer on the dedicated token is unaffected.
        assert_eq!(
            authorize_request(&svc, &bearer("delivery-secret"), Some(&peer), shapes[0].clone(), DeliveryResource::Config).await,
            Ok(())
        );

        // Re-enabling restores the fallback on the next request (no cache).
        svc.set_install_token_enabled(true, None).await.unwrap();
        assert_eq!(
            authorize_request(&svc, &bearer("install-token"), Some(&peer), shapes[1].clone(), DeliveryResource::Config).await,
            Ok(())
        );

        // The switch unreadable (table gone) fails closed with 503.
        sqlx::raw_sql("DROP TABLE ingest_token_settings CASCADE").execute(&pool).await.ok();
        assert_eq!(
            authorize_request(&svc, &bearer("install-token"), Some(&peer), shapes[1].clone(), DeliveryResource::Config).await,
            Err(StatusCode::SERVICE_UNAVAILABLE)
        );

        sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&pool).await.unwrap();
    }
}
