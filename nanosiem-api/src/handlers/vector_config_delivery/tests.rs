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
