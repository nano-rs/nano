// SPDX-License-Identifier: AGPL-3.0-or-later

//! Capabilities handler
//!
//! Returns the build edition and capability flags so the frontend can decide
//! which surfaces to render. Public — the SPA hits it on boot before login,
//! and the answer is not sensitive (open-core deployments advertise themselves
//! anyway via the absence of enterprise routes).
//!
//! In the final architecture (post Phase 5 of NAN-744 / NAN-745), the open
//! Vite build excludes enterprise chunks at build time; capabilities is then
//! mostly observability ("which edition is this deployment running?") plus
//! a soft handle for staging environments where one bundle talks to either
//! backend.

use axum::Json;
use serde::Serialize;
use utoipa::OpenApi;

/// Per-surface capability flags.
///
/// In this commit every flag toggles with the `enterprise` Cargo feature so
/// they're effectively redundant with `edition`. The shape exists so that
/// later phases can gate individual capabilities behind license tier or
/// org-level config without changing the wire format — e.g., a "starter"
/// enterprise tier without `aiTuning`. Until that lands, treat the flags as
/// the canonical per-surface check (`capabilities.cases`) rather than reading
/// edition directly.
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Capabilities {
    /// Cases lifecycle, queues, routing, playbooks, shadow investigation.
    pub cases: bool,
    /// Investigation notebooks + chat.
    pub notebooks: bool,
    /// Risk analytics, entity drawer, RiskLeaderboard, MyCases dashboard widgets.
    pub risk: bool,
    /// meloD AI agents — chat, parser, query, detection, dashboard, summarize.
    pub melod: bool,
    /// Deno-sandbox custom enrichments + their AI codegen.
    pub custom_enrichment: bool,
    /// AI-powered IOC enrichment providers.
    pub agent_enrichment: bool,
    /// AI rule-tuning agents (rule version history stays open).
    pub ai_tuning: bool,
    /// SOC playbook authoring + repository sync.
    pub playbooks: bool,
    /// Multi-case incidents.
    pub incidents: bool,
    /// SIEM Health — basic stats live in core, but the AI narrative +
    /// ranked recommendations that anchor the page are enterprise. Hidden
    /// wholesale in open until a basic-only Health view ships.
    pub siem_health: bool,
    /// SAML / OIDC SSO providers. Local credentials still work in open builds.
    pub sso: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    /// Build edition — `"open"` or `"enterprise"`.
    pub edition: &'static str,
    /// API server semver, from `CARGO_PKG_VERSION`.
    pub version: &'static str,
    pub capabilities: Capabilities,
}

#[cfg(feature = "enterprise")]
const EDITION: &str = "enterprise";
#[cfg(not(feature = "enterprise"))]
const EDITION: &str = "open";

#[cfg(feature = "enterprise")]
const ENTERPRISE: bool = true;
#[cfg(not(feature = "enterprise"))]
const ENTERPRISE: bool = false;

/// Get build edition + capability flags.
///
/// Public endpoint — no auth required. The SPA fetches this on app boot to
/// decide which surfaces to render.
#[utoipa::path(
    get,
    path = "/api/capabilities",
    tag = "system",
    responses(
        (status = 200, description = "Build edition and capability flags", body = CapabilitiesResponse),
    ),
    security(())
)]
pub async fn get_capabilities() -> Json<CapabilitiesResponse> {
    Json(CapabilitiesResponse {
        edition: EDITION,
        version: env!("CARGO_PKG_VERSION"),
        capabilities: Capabilities {
            cases: ENTERPRISE,
            notebooks: ENTERPRISE,
            risk: ENTERPRISE,
            melod: ENTERPRISE,
            custom_enrichment: ENTERPRISE,
            agent_enrichment: ENTERPRISE,
            ai_tuning: ENTERPRISE,
            playbooks: ENTERPRISE,
            incidents: ENTERPRISE,
            siem_health: ENTERPRISE,
            sso: ENTERPRISE,
        },
    })
}

#[derive(OpenApi)]
#[openapi(paths(get_capabilities), components(schemas(CapabilitiesResponse, Capabilities)))]
pub struct CapabilitiesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_known_edition() {
        let Json(body) = get_capabilities().await;
        assert!(matches!(body.edition, "open" | "enterprise"));
        assert!(!body.version.is_empty());
    }

    #[test]
    fn capabilities_match_feature_flag() {
        if cfg!(feature = "enterprise") {
            assert_eq!(EDITION, "enterprise");
            assert!(ENTERPRISE);
        } else {
            assert_eq!(EDITION, "open");
            assert!(!ENTERPRISE);
        }
    }
}
