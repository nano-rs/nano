// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenzir-only ingest guard (NAN-3844).
//!
//! `install.sh --tenzir` (NAN-3807) runs open core with no Vector and no
//! connector runner. Mutations that render into, or deliver through, Vector
//! would otherwise "succeed" into a void or fail downstream (nginx 502,
//! a reload that never lands, a sync that never arrives). In that mode this
//! layer refuses them up front with `409 VECTOR_NOT_INSTALLED` and a message
//! that names the fix. Reads, deletes, revokes and undeploys stay open so an
//! operator who switched from a Vector install can still inspect and clean up.
//!
//! A no-op unless `ApiConfig::ingest_mode` is `TenzirOnly`.

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::config::IngestMode;
use crate::error::{ErrorDetail, ErrorResponse};

/// Stable error code the SPA keys on.
pub const VECTOR_NOT_INSTALLED: &str = "VECTOR_NOT_INSTALLED";

/// The one-line operator note, shared with the SPA copy.
pub const TENZIR_ONLY_MESSAGE: &str =
    "This install ingests via Tenzir; re-run install.sh --add-vector to enable";

/// Which Vector-dependent feature a refused route belongs to (reported in
/// `details.feature` so the caller can tell the user what is off).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorFeature {
    /// HTTP / HEC / OTLP push listeners and their ingest tokens.
    PushSources,
    /// Pull connectors (connector runner delivers over Vector HEC).
    PullConnectors,
    /// Directory / identity sync (Vector's enrichment lane).
    DirectorySync,
    /// Parser deploys (rendered into Vector's config).
    ParserDeploys,
    /// Synthetic checks (nano-jobs sends results to Vector OTLP).
    SyntheticChecks,
}

impl VectorFeature {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PushSources => "push_sources",
            Self::PullConnectors => "pull_connectors",
            Self::DirectorySync => "directory_sync",
            Self::ParserDeploys => "parser_deploys",
            Self::SyntheticChecks => "synthetic_checks",
        }
    }
}

/// One refused route: method + path pattern. `*` matches exactly one segment.
struct Rule {
    method: Method,
    pattern: &'static str,
    feature: VectorFeature,
    /// Refuse only when the JSON body turns the resource on
    /// (`{"enabled": true}`); pausing stays open for cleanup.
    enabling_only: bool,
}

const fn rule(method: Method, pattern: &'static str, feature: VectorFeature) -> Rule {
    Rule { method, pattern, feature, enabling_only: false }
}

const fn enabling(method: Method, pattern: &'static str, feature: VectorFeature) -> Rule {
    Rule { method, pattern, feature, enabling_only: true }
}

/// Toggle bodies are `{"enabled": bool}`; anything larger is not a toggle.
const TOGGLE_BODY_LIMIT: usize = 16 * 1024;

/// Vector-dependent mutations. Deliberately method + exact shape so a
/// delete, revoke or undeploy on the same resource is never caught.
static RULES: &[Rule] = &[
    // Push sources: ingest tokens (HEC / HTTP) and Vector source listeners.
    rule(Method::POST, "/api/ingest-tokens", VectorFeature::PushSources),
    rule(Method::PUT, "/api/ingest-tokens/install-token", VectorFeature::PushSources),
    rule(Method::POST, "/api/source-configurations", VectorFeature::PushSources),
    rule(Method::POST, "/api/source-configurations/deploy-all", VectorFeature::PushSources),
    rule(Method::POST, "/api/source-configurations/*/deploy", VectorFeature::PushSources),
    enabling(Method::POST, "/api/source-configurations/*/toggle", VectorFeature::PushSources),
    // Pull connectors: open-core connector feeds + enterprise collectors.
    rule(Method::POST, "/api/connector-feeds", VectorFeature::PullConnectors),
    enabling(Method::PATCH, "/api/connector-feeds/*", VectorFeature::PullConnectors),
    rule(Method::POST, "/api/integrations/custom", VectorFeature::PullConnectors),
    rule(Method::POST, "/api/integrations/instances", VectorFeature::PullConnectors),
    rule(Method::PUT, "/api/integrations/instances/*", VectorFeature::PullConnectors),
    rule(Method::POST, "/api/integrations/instances/*/run", VectorFeature::PullConnectors),
    // Directory / identity sync.
    rule(Method::POST, "/api/settings/identity-providers", VectorFeature::DirectorySync),
    rule(Method::POST, "/api/settings/identity-providers/*/sync", VectorFeature::DirectorySync),
    // Parser deploys. Drafting, validating and testing a parser stay open.
    rule(Method::POST, "/api/log-sources/deploy-all", VectorFeature::ParserDeploys),
    rule(Method::POST, "/api/log-sources/*/deploy", VectorFeature::ParserDeploys),
    rule(Method::POST, "/api/log-sources/*/publish", VectorFeature::ParserDeploys),
    // Synthetic checks.
    rule(Method::POST, "/api/observability/synthetics", VectorFeature::SyntheticChecks),
    rule(Method::PUT, "/api/observability/synthetics/*", VectorFeature::SyntheticChecks),
];

fn matches_pattern(pattern: &str, path: &str) -> bool {
    let path = path.strip_suffix('/').filter(|p| !p.is_empty()).unwrap_or(path);
    let mut want = pattern.split('/');
    let mut have = path.split('/');
    loop {
        match (want.next(), have.next()) {
            (None, None) => return true,
            (Some("*"), Some(seg)) if !seg.is_empty() => {}
            (Some(w), Some(h)) if w == h => {}
            _ => return false,
        }
    }
}

fn find_rule(method: &Method, path: &str) -> Option<&'static Rule> {
    RULES
        .iter()
        .find(|r| r.method == *method && matches_pattern(r.pattern, path))
}

/// The Vector feature a request would use, if it is a refused mutation.
/// `enabling` is the parsed `enabled` field of a toggle body, if any.
pub fn vector_dependent_mutation(
    method: &Method,
    path: &str,
    enabling: Option<bool>,
) -> Option<VectorFeature> {
    let rule = find_rule(method, path)?;
    if rule.enabling_only && enabling != Some(true) {
        return None;
    }
    Some(rule.feature)
}

fn body_enables(bytes: &[u8]) -> Option<bool> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("enabled")?
        .as_bool()
}

/// Refuse Vector-dependent mutations on a Tenzir-only install.
pub async fn vector_ingest_guard(
    State(mode): State<IngestMode>,
    request: Request,
    next: Next,
) -> Response {
    if !mode.is_tenzir_only() {
        return next.run(request).await;
    }
    let Some(rule) = find_rule(request.method(), request.uri().path()) else {
        return next.run(request).await;
    };
    if !rule.enabling_only {
        return vector_not_installed(rule.feature);
    }
    // Toggle: look at the small JSON body, then hand the same bytes on.
    let (parts, body) = request.into_parts();
    let bytes = match axum::body::to_bytes(body, TOGGLE_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    if body_enables(&bytes) == Some(true) {
        return vector_not_installed(rule.feature);
    }
    next.run(Request::from_parts(parts, axum::body::Body::from(bytes)))
        .await
}

fn vector_not_installed(feature: VectorFeature) -> Response {
    let body = ErrorResponse {
        error: ErrorDetail {
            code: VECTOR_NOT_INSTALLED.to_string(),
            message: TENZIR_ONLY_MESSAGE.to_string(),
            details: Some(serde_json::json!({
                "ingest_mode": IngestMode::TenzirOnly.as_str(),
                "feature": feature.as_str(),
            })),
        },
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        middleware::from_fn_with_state,
        routing::{delete, get, post},
        Router,
    };
    use tower::ServiceExt;

    #[test]
    fn refuses_each_vector_feature() {
        let cases = [
            (Method::POST, "/api/ingest-tokens", VectorFeature::PushSources),
            (Method::PUT, "/api/ingest-tokens/install-token", VectorFeature::PushSources),
            (Method::POST, "/api/source-configurations", VectorFeature::PushSources),
            (Method::POST, "/api/source-configurations/sc_01/deploy", VectorFeature::PushSources),
            (Method::POST, "/api/connector-feeds", VectorFeature::PullConnectors),

            (Method::POST, "/api/integrations/instances/abc/run", VectorFeature::PullConnectors),
            (Method::POST, "/api/settings/identity-providers", VectorFeature::DirectorySync),
            (Method::POST, "/api/settings/identity-providers/idp_1/sync", VectorFeature::DirectorySync),
            (Method::POST, "/api/log-sources/deploy-all", VectorFeature::ParserDeploys),
            (Method::POST, "/api/log-sources/ls_1/deploy", VectorFeature::ParserDeploys),
            (Method::POST, "/api/log-sources/ls_1/publish", VectorFeature::ParserDeploys),
            (Method::POST, "/api/observability/synthetics", VectorFeature::SyntheticChecks),
            (Method::PUT, "/api/observability/synthetics/syn_1", VectorFeature::SyntheticChecks),
            // Trailing slash is the same route.
            (Method::POST, "/api/connector-feeds/", VectorFeature::PullConnectors),
        ];
        for (method, path, feature) in cases {
            assert_eq!(vector_dependent_mutation(&method, path, None), Some(feature), "{method} {path}");
        }
    }

    #[test]
    fn toggles_are_refused_only_when_enabling() {
        for (method, path) in [
            (Method::PATCH, "/api/connector-feeds/42"),
            (Method::POST, "/api/source-configurations/sc_1/toggle"),
        ] {
            assert!(vector_dependent_mutation(&method, path, Some(true)).is_some(), "{path}");
            assert_eq!(vector_dependent_mutation(&method, path, Some(false)), None, "{path}");
            assert_eq!(vector_dependent_mutation(&method, path, None), None, "{path}");
        }
        assert_eq!(body_enables(br#"{"enabled":true}"#), Some(true));
        assert_eq!(body_enables(br#"{"enabled":false}"#), Some(false));
        assert_eq!(body_enables(b"not json"), None);
    }

    #[test]
    fn leaves_reads_and_cleanup_open() {
        let open = [
            (Method::GET, "/api/ingest-tokens"),
            (Method::POST, "/api/ingest-tokens/tok_1/revoke"),
            (Method::GET, "/api/connector-feeds"),
            (Method::DELETE, "/api/connector-feeds/42"),
            (Method::POST, "/api/log-sources"),
            (Method::PUT, "/api/log-sources/ls_1"),
            (Method::POST, "/api/log-sources/ls_1/undeploy"),
            (Method::POST, "/api/log-sources/test-vrl"),
            (Method::POST, "/api/log-sources/validate-vrl"),
            (Method::DELETE, "/api/source-configurations/sc_1"),
            (Method::POST, "/api/source-configurations/sc_1/undeploy"),
            (Method::GET, "/api/settings/identity-providers"),
            (Method::DELETE, "/api/settings/identity-providers/idp_1"),
            (Method::POST, "/api/settings/identity-providers/idp_1/test"),
            (Method::GET, "/api/observability/synthetics"),
            (Method::DELETE, "/api/observability/synthetics/syn_1"),
            (Method::GET, "/api/landing-sources"),
            // Extra segment must not match a `*` rule.
            (Method::POST, "/api/log-sources/ls_1/deploy/extra"),
            (Method::POST, "/api/log-sources//deploy"),
        ];
        for (method, path) in open {
            assert_eq!(vector_dependent_mutation(&method, path, Some(true)), None, "{method} {path}");
        }
    }

    fn app(mode: IngestMode) -> Router {
        Router::new()
            .route("/api/connector-feeds", post(|| async { "created" }).get(|| async { "list" }))
            .route(
                "/api/connector-feeds/{id}",
                delete(|| async { "deleted" }).patch(|body: String| async move { body }),
            )
            .route("/api/capabilities", get(|| async { "caps" }))
            .layer(from_fn_with_state(mode, vector_ingest_guard))
    }

    async fn call(mode: IngestMode, method: Method, path: &str) -> (StatusCode, serde_json::Value) {
        call_with(mode, method, path, "").await
    }

    async fn call_with(
        mode: IngestMode,
        method: Method,
        path: &str,
        body: &'static str,
    ) -> (StatusCode, serde_json::Value) {
        let response = app(mode)
            .oneshot(Request::builder().method(method).uri(path).body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    #[tokio::test]
    async fn tenzir_only_refuses_with_a_structured_409() {
        let (status, body) = call(IngestMode::TenzirOnly, Method::POST, "/api/connector-feeds").await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["code"], VECTOR_NOT_INSTALLED);
        assert_eq!(body["error"]["message"], TENZIR_ONLY_MESSAGE);
        assert_eq!(body["error"]["details"]["feature"], "pull_connectors");
        assert_eq!(body["error"]["details"]["ingest_mode"], "tenzir_only");

        let (status, _) = call(IngestMode::TenzirOnly, Method::GET, "/api/connector-feeds").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(IngestMode::TenzirOnly, Method::DELETE, "/api/connector-feeds/7").await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn tenzir_only_lets_a_pause_through_with_its_body_intact() {
        let (status, body) =
            call_with(IngestMode::TenzirOnly, Method::PATCH, "/api/connector-feeds/7", r#"{"enabled":false}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enabled"], false, "handler must see the original body");

        let (status, body) =
            call_with(IngestMode::TenzirOnly, Method::PATCH, "/api/connector-feeds/7", r#"{"enabled":true}"#).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"]["details"]["feature"], "pull_connectors");
    }

    #[tokio::test]
    async fn vector_mode_passes_everything_through() {
        let (status, _) = call(IngestMode::Vector, Method::POST, "/api/connector-feeds").await;
        assert_eq!(status, StatusCode::OK);
    }
}
