// SPDX-License-Identifier: AGPL-3.0-or-later

//! Getting Started checklist probes for a dedicated deployment (open core,
//! sovereign single-host, dedicated hosted) — NAN-4779.
//!
//! Each probe answers "has the operator done this step?" from a row the
//! matching settings page or wizard actually writes, and ignores rows that
//! migrations seed on every fresh install. Before NAN-4779:
//! - `has_users` counted the seeded `system-ai` service account, so the Team
//!   step was checked on a fresh install;
//! - `has_log_sources` counted the seeded OpenTelemetry log source (migration
//!   315), so the Log Source step was checked on a fresh install;
//! - `has_parsers` read only `parser_imports`, which only a parser-repository
//!   import writes. The Add data wizard stores the parser it builds as
//!   `log_sources.parser_vrl`, and nano no longer bundles parsers, so the Log
//!   Parser step never cleared for the common path;
//! - `has_org_context` required the organization *name*; guidance saved with
//!   only industry / environment / custom notes never cleared AI Guidance.
//!
//! A probe that errors is logged and reported as "not done" — the checklist is
//! advisory and must never fail the page.

use sqlx::PgPool;
use tracing::warn;

use super::types::OnboardingStatus;

/// Log sources migrations seed on every install. They are platform plumbing,
/// not something the operator connected, so they never satisfy a step.
/// `log_sources.name` is UNIQUE, so the name pins the exact seeded row.
pub const PLATFORM_SEEDED_LOG_SOURCES: &[&str] = &[
    // migrations/postgres/315_seed_otlp_log_ocsf_parser.sql
    "OpenTelemetry Logs (OCSF)",
];

/// Any guidance field the AI Guidance tab can save counts as configured.
pub const ORG_CONTEXT_CONFIGURED_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM system_settings WHERE id = 'default' AND (\
     COALESCE(btrim(org_context_name), '') <> '' \
     OR COALESCE(btrim(org_context_industry), '') <> '' \
     OR COALESCE(btrim(org_context_environment), '') <> '' \
     OR COALESCE(btrim(org_context_attack_vectors), '') <> '' \
     OR COALESCE(cardinality(org_context_compliance), 0) > 0 \
     OR COALESCE(btrim(org_context_custom), '') <> ''))";

/// Human accounts (active, invited or disabled) — never `status = 'system'`
/// service accounts such as the seeded `system-ai` user.
pub const HUMAN_USER_COUNT_SQL: &str = "SELECT COUNT(*) FROM users WHERE status <> 'system'";

/// A log source the operator created ($1 = [`PLATFORM_SEEDED_LOG_SOURCES`]).
/// Drafts count: the Add data wizard persists the feed as a draft as soon as it
/// is named, and the operator has connected a source from that point on.
pub const USER_LOG_SOURCE_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM log_sources WHERE NOT (name = ANY($1)))";

/// A parser the operator built or imported ($1 = [`PLATFORM_SEEDED_LOG_SOURCES`]):
/// a parser-repository import, or an operator log source carrying saved VRL
/// (the Add data wizard's Save draft / Deploy, and the parser editor). Typing
/// in the browser does not update this row until Save draft or Deploy.
pub const USER_PARSER_SQL: &str = "SELECT EXISTS(SELECT 1 FROM parser_imports) \
     OR EXISTS(SELECT 1 FROM log_sources WHERE NOT (name = ANY($1)) \
        AND btrim(parser_vrl) <> '')";

/// An enabled AI provider with a credential or a direct (on-prem) endpoint.
pub const AI_PROVIDER_CONFIGURED_SQL: &str = "SELECT EXISTS(SELECT 1 FROM provider_credentials \
     WHERE enabled = true \
       AND (credentials_encrypted IS NOT NULL OR COALESCE(config->>'base_url', '') <> ''))";

pub const SSO_PROVIDER_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM oidc_providers WHERE enabled = true)";

pub const SEARCH_HISTORY_SQL: &str = "SELECT EXISTS(SELECT 1 FROM search_history)";

/// Shape-specific inputs the probe cannot read from Postgres itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct DedicatedProbeInputs {
    /// The build ships meloD (enterprise). Open core has no AI step.
    pub ai_available: bool,
    /// The in-process meloD service is loaded (AI is live right now).
    pub ai_service_loaded: bool,
    /// The build ships SSO; `oidc_providers` only exists under the enterprise overlay.
    pub sso_available: bool,
}

async fn probe_bool(pool: &PgPool, label: &'static str, sql: &'static str) -> bool {
    sqlx::query_scalar::<_, bool>(sql)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| {
            warn!(check = label, error = %e, "Onboarding status check failed");
            false
        })
}

async fn probe_bool_excluding_seeded(
    pool: &PgPool,
    label: &'static str,
    sql: &'static str,
) -> bool {
    sqlx::query_scalar::<_, bool>(sql)
        .bind(PLATFORM_SEEDED_LOG_SOURCES)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| {
            warn!(check = label, error = %e, "Onboarding status check failed");
            false
        })
}

/// Run every Getting Started probe against a dedicated deployment's database.
pub async fn probe_dedicated_onboarding_status(
    pool: &PgPool,
    inputs: DedicatedProbeInputs,
) -> OnboardingStatus {
    let has_ai_provider = inputs.ai_available
        && (inputs.ai_service_loaded
            || probe_bool(pool, "ai_provider", AI_PROVIDER_CONFIGURED_SQL).await);

    let has_org_context = probe_bool(pool, "org_context", ORG_CONTEXT_CONFIGURED_SQL).await;

    let human_users: i64 = sqlx::query_scalar(HUMAN_USER_COUNT_SQL)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| {
            warn!(check = "users", error = %e, "Onboarding status check failed");
            0
        });

    let has_sso = inputs.sso_available && probe_bool(pool, "sso", SSO_PROVIDER_SQL).await;

    let has_log_sources =
        probe_bool_excluding_seeded(pool, "log_sources", USER_LOG_SOURCE_SQL).await;
    let has_parsers = probe_bool_excluding_seeded(pool, "parsers", USER_PARSER_SQL).await;
    let has_search_history = probe_bool(pool, "search_history", SEARCH_HISTORY_SQL).await;

    OnboardingStatus {
        has_ai_provider,
        has_org_context,
        has_users: human_users > 1,
        has_sso,
        has_log_sources,
        has_parsers,
        has_search_history,
    }
}
