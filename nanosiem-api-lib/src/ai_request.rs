//! HTTP deadlines and async negotiation for AI wizard requests.

use axum::{
    body::Body,
    http::{HeaderMap, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::ApiError;

/// Leave headroom under the edge's 100-second response deadline, including
/// admission, database access and model execution before response headers.
pub const WIZARD_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(85);

/// Existing clients retain their result shape; updated clients request jobs.
pub fn prefers_async(headers: &HeaderMap) -> bool {
    headers
        .get_all("prefer")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| {
            v.split(',')
                .any(|preference| preference.trim().eq_ignore_ascii_case("respond-async"))
        })
}

/// SSE returns headers immediately and keeps flowing; only the wait for the
/// initial response is bounded. This also covers legacy synchronous wizards.
pub async fn wizard_request_deadline(req: Request<Body>, next: Next) -> Response {
    let path = req.uri().path();
    if !path.contains("/api/melod/")
        && !path.ends_with("/api/custom-enrichments/generate-code")
        && !path.ends_with("/api/integrations/custom/generate-code")
    {
        return next.run(req).await;
    }
    match tokio::time::timeout(WIZARD_HTTP_TIMEOUT, next.run(req)).await {
        Ok(response) => response,
        Err(_) => {
            ApiError::Timeout("AI request timed out. Retry in a moment.".into()).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::post, Json, Router};
    use tower::ServiceExt;

    #[test]
    fn nan4753_async_requires_explicit_preference() {
        let mut headers = HeaderMap::new();
        assert!(!prefers_async(&headers));
        headers.insert("prefer", "wait=5, Respond-Async".parse().unwrap());
        assert!(prefers_async(&headers));
        headers.insert("prefer", "respond-async=false".parse().unwrap());
        assert!(!prefers_async(&headers));
    }

    #[tokio::test(start_paused = true)]
    async fn nan4753_slow_wizard_returns_json_before_the_edge_deadline() {
        let app = Router::new()
            .route(
                "/api/melod/parser",
                post(|| async {
                    tokio::time::sleep(std::time::Duration::from_secs(150)).await;
                    Json(serde_json::json!({"parser": {}}))
                }),
            )
            .layer(middleware::from_fn(wizard_request_deadline));
        let started = tokio::time::Instant::now();
        let response = app
            .oneshot(
                Request::post("/api/melod/parser")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(started.elapsed(), WIZARD_HTTP_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn nan4753_slow_sse_keeps_flowing_through_both_middlewares() {
        use axum::response::sse::{Event, KeepAlive, Sse};
        use futures::StreamExt;
        use std::convert::Infallible;

        let app = Router::new()
            .route(
                "/api/melod/parser/stream",
                post(|| async {
                    Sse::new(futures::stream::pending::<Result<Event, Infallible>>())
                        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
                }),
            )
            .layer(middleware::from_fn(crate::sse::sse_unbuffered))
            .layer(middleware::from_fn(wizard_request_deadline));
        let started = tokio::time::Instant::now();
        let response = app
            .oneshot(
                Request::post("/api/melod/parser/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["x-accel-buffering"], "no");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let first = response
            .into_body()
            .into_data_stream()
            .next()
            .await
            .unwrap()
            .unwrap();
        assert!(!first.is_empty());
        assert_eq!(started.elapsed(), std::time::Duration::from_secs(15));
    }
}
