// SPDX-License-Identifier: AGPL-3.0-or-later
//! Optional platform RUM relay. No URLs, user identifiers, headers or arbitrary
//! attributes are accepted; the ingest credential never enters the browser.
use crate::middleware::AuthContext;
use axum::{Extension, Json, http::StatusCode};
use serde::Deserialize;

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrowserPage {
    Home,
    Search,
    Observability,
    Alerts,
    Cases,
    Rules,
    Dashboards,
    Settings,
    Other,
}
impl BrowserPage {
    fn path(&self) -> &'static str {
        match self {
            Self::Home => "/",
            Self::Search => "/search",
            Self::Observability => "/observability",
            Self::Alerts => "/alerts",
            Self::Cases => "/cases",
            Self::Rules => "/rules",
            Self::Dashboards => "/dashboards",
            Self::Settings => "/settings",
            Self::Other => "/other",
        }
    }
}
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserPageview {
    pub page: BrowserPage,
    /// Navigation duration in milliseconds (0..120000).
    pub duration_ms: u32,
}
#[utoipa::path(post, path = "/api/observability/browser", tag = "observability", request_body = BrowserPageview,
    responses((status = 204, description = "Pageview accepted or telemetry disabled"),
        (status = 400, description = "Invalid pageview"),
        (status = 413, description = "Pageview exceeds 1024 bytes"),
        (status = 422, description = "Invalid pageview JSON"), (status = 403, description = "Interactive session required")),
    security(("bearer_auth" = [])))]
pub async fn pageview(
    Extension(auth): Extension<AuthContext>,
    Json(input): Json<BrowserPageview>,
) -> StatusCode {
    if auth.is_api_key {
        return StatusCode::FORBIDDEN;
    }
    if input.duration_ms > 120_000 {
        return StatusCode::BAD_REQUEST;
    }
    nanosiem_core::telemetry::record_browser_pageview(input.page.path(), input.duration_ms);
    StatusCode::NO_CONTENT
}
#[derive(utoipa::OpenApi)]
#[openapi(paths(pageview), components(schemas(BrowserPage, BrowserPageview)))]
pub struct BrowserTelemetryApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pageview_contract_refuses_urls_user_data_and_unknown_attributes() {
        assert!(
            serde_json::from_value::<BrowserPageview>(
                serde_json::json!({"page": "https://example.com/private", "duration_ms": 1})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<BrowserPageview>(
                serde_json::json!({"page": "search", "duration_ms": 1, "query": "secret"})
            )
            .is_err()
        );
        assert_eq!(
            serde_json::from_value::<BrowserPageview>(
                serde_json::json!({"page": "search", "duration_ms": 1})
            )
            .unwrap()
            .page
            .path(),
            "/search"
        );
    }
}
