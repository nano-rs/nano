use super::*;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware as axum_middleware,
    routing::get,
    Router,
};
use chrono::Duration;
use tower::util::ServiceExt;

async fn ok() -> &'static str {
    "ok"
}

fn app(status: LicenseStatus) -> Router {
    let status = Arc::new(RwLock::new(status));
    let licensed = Router::new().route("/api/cases", get(ok)).route_layer(
        axum_middleware::from_fn_with_state(status.clone(), licensed_surface_guard),
    );

    Router::new()
        .route("/api/alerts", get(ok))
        .route("/api/license", get(ok))
        .merge(licensed)
        .layer(axum_middleware::from_fn_with_state(status, license_guard))
}

#[tokio::test]
async fn hard_stop_preserves_open_routes_and_blocks_licensed_routes() {
    let app = app(LicenseStatus::unavailable("trial hard stop"));

    let open = app
        .clone()
        .oneshot(Request::get("/api/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(open.status(), StatusCode::OK);
    assert_eq!(open.headers()["X-License-State"], "locked");

    let recovery = app
        .clone()
        .oneshot(Request::get("/api/license").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(recovery.status(), StatusCode::OK);

    let licensed = app
        .oneshot(Request::get("/api/cases").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(licensed.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn contract_expiry_remains_usable_through_exclusive_grace_boundary() {
    let now = chrono::Utc::now();
    let app = app(LicenseStatus {
        state: LicenseState::GracePeriod,
        valid: false,
        expires_at: Some(now - Duration::minutes(1)),
        grace_ends_at: Some(now + Duration::days(7)),
        ..LicenseStatus::default()
    });

    let response = app
        .oneshot(Request::get("/api/cases").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["X-License-State"], "grace_period");
}

/// Self-enforcing licensed routes get the effective state, never a denial:
/// they must keep their narrowing-only operations open at the hard stop.
#[tokio::test]
async fn license_state_extension_passes_through_with_the_effective_state() {
    async fn echo(axum::Extension(state): axum::Extension<LicenseState>) -> String {
        format!("{state:?}")
    }
    for (status, expected) in [
        (LicenseStatus::unavailable("trial hard stop"), "Locked"),
        (LicenseStatus { state: LicenseState::Active, ..LicenseStatus::default() }, "Active"),
    ] {
        let status = Arc::new(RwLock::new(status));
        let app = Router::new()
            .route("/api/self-authenticated", get(echo))
            .route_layer(axum_middleware::from_fn_with_state(status, license_state_extension));
        let response = app
            .oneshot(Request::get("/api/self-authenticated").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64).await.unwrap();
        assert_eq!(body, expected);
    }
}
