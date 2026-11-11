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

use axum::{extract::State, Json};
use serde::Serialize;
use utoipa::OpenApi;

use crate::state::AppState;

/// Per-surface capability flags.
///
/// Licensed-only flags require both the enterprise build and live license
/// admission. The shape exists so that
/// clients can use one canonical per-surface check (`capabilities.cases`)
/// rather than inferring code availability from commercial metadata. V2 does
/// not vary these flags by licensed capacity.
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
    /// SIEM Health. Available in BOTH editions (NAN-2357).
    ///
    /// This was `ENTERPRISE` on the reasoning that "the AI narrative + ranked
    /// recommendations anchor the page". They don't — they enrich it. The
    /// scheduler, the five dimension scores, the metrics, the findings and the
    /// recommendations are all `nanosiem-core` with no `cfg` gate, and
    /// `siem_health::analyzer` has a deterministic non-AI summary builder. A
    /// fresh open tenant with zero AI credentials produces a complete report in
    /// ~73ms, including real findings.
    ///
    /// Hiding it also never worked: the flag only suppressed the NAV ITEM, while
    /// the route (permission-gated only) and the footer status link stayed
    /// reachable — so open users found a page they were not supposed to have.
    /// The meloD-authored narrative is gated inside the page on `melod`.
    pub siem_health: bool,
    /// SAML / OIDC SSO providers. Local credentials still work in open builds.
    pub sso: bool,
    /// Observability ↔ Security convergence cross-link (NAN-1544) — the
    /// service-detail "security signals against this service's hosts/IPs"
    /// strip. Enterprise only; the FE hides the strip when false.
    pub observability_convergence: bool,
    /// Code-free IOC lists (`/api/ioc-lists`, NAN-4902 lane G): paste or upload
    /// indicators and publish them into the ClickHouse IOC store. Enterprise.
    pub ioc_lists: bool,
    /// Governed SOAR execution and approval surfaces.
    pub soar: bool,
    /// Threat-intel lookups and the Enrich flyout (`/api/threat-intel/*`,
    /// NAN-4931): external providers through the connector engine plus the
    /// install's own IOC feeds and lists. Enterprise.
    pub threat_intel: bool,
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

/// Whether the SAML/OIDC SSO surface is compiled into this build. The OIDC
/// handlers live in `nanosiem-enterprise`, so open builds never mount
/// `/api/settings/oidc` or `/api/auth/oidc/*`. Shared by `/api/capabilities`
/// and `/api/settings/tier` so the two cannot contradict each other
/// (NAN-3378).
pub(crate) const SSO_AVAILABLE: bool = ENTERPRISE;

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
pub async fn get_capabilities(State(state): State<AppState>) -> Json<CapabilitiesResponse> {
    #[cfg(feature = "enterprise")]
    let licensed = crate::license_admission::licensed_features_available(
        &*state.license_status.read().await,
        chrono::Utc::now(),
    );
    #[cfg(not(feature = "enterprise"))]
    let licensed = {
        let _ = state;
        false
    };

    Json(capabilities_response(licensed))
}

pub(crate) fn capabilities_response(licensed: bool) -> CapabilitiesResponse {
    CapabilitiesResponse {
        edition: EDITION,
        version: env!("CARGO_PKG_VERSION"),
        capabilities: Capabilities {
            cases: licensed,
            notebooks: licensed,
            risk: licensed,
            melod: licensed,
            custom_enrichment: licensed,
            agent_enrichment: licensed,
            ai_tuning: licensed,
            playbooks: licensed,
            incidents: licensed,
            // Both editions — see the field doc. Deliberately not ENTERPRISE.
            siem_health: true,
            sso: licensed,
            observability_convergence: licensed,
            ioc_lists: licensed,
            soar: licensed,
            threat_intel: licensed,
        },
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(get_capabilities),
    components(schemas(CapabilitiesResponse, Capabilities))
)]
pub struct CapabilitiesApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_known_edition() {
        let body = capabilities_response(ENTERPRISE);
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

    #[test]
    fn hard_stop_matches_open_capability_boundary() {
        let body = capabilities_response(false);
        let licensed_flags = [
            body.capabilities.cases,
            body.capabilities.notebooks,
            body.capabilities.risk,
            body.capabilities.melod,
            body.capabilities.custom_enrichment,
            body.capabilities.agent_enrichment,
            body.capabilities.ai_tuning,
            body.capabilities.playbooks,
            body.capabilities.incidents,
            body.capabilities.sso,
            body.capabilities.observability_convergence,
            body.capabilities.ioc_lists,
            body.capabilities.soar,
            body.capabilities.threat_intel,
        ];
        assert!(licensed_flags.into_iter().all(|available| !available));
        assert!(body.capabilities.siem_health);
    }
}
