// SPDX-License-Identifier: AGPL-3.0-or-later

//! API request handlers

use crate::state::AppState;
use nanosiem_core::audit::AuditEvent;

// Canonical home for `AuditExt` is now `nanosiem-api-lib` (NAN-752 follow-up
// to NAN-751's OIDC lift, which had to use a fully-qualified-call workaround
// because the trait was defined here). Re-exported at the original path so
// existing handler imports (`use crate::handlers::AuditExt;`) keep resolving
// without churn, and the impl on `AppState` below stays in this crate (the
// only place that knows what an `AppState` is).
pub use nanosiem_api_lib::AuditExt;

// Agent enrichment handlers — lifted to nanosiem-enterprise in NAN-752
// (Phase 2 of the open-core split). Re-exported here so route registrations
// (`handlers::agent_enrichment::list_providers`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::agent_enrichment;
pub mod alerts;
pub mod api_keys;
pub mod audit;
pub mod auth;
pub mod capabilities;
// Cases + queues + queue-routing-rules + case-grouping settings handlers —
// lifted to nanosiem-enterprise in NAN-752 (Phase 2 of the open-core split).
// Re-exported here so route registrations (`handlers::cases::list_cases`,
// etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::cases;
pub mod credentials;
// Custom enrichment handlers — lifted to nanosiem-enterprise in NAN-752 (Phase
// 2 of the open-core split). Re-exported here so route registrations
// (`handlers::custom_enrichment::list_custom_enrichments`, etc.) continue to
// resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::custom_enrichment;
pub mod dashboards;
pub mod demo;
pub mod detections;
pub mod enrichment;
// Entity context handler — lifted to nanosiem-enterprise in NAN-752 (Phase
// 2 of the open-core split). Re-exported here so route registrations
// (`handlers::entity_context::get_entity_context`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::entity_context;
pub mod feedback;
pub mod fields;
pub mod folder_settings;
pub mod gdpr;
pub mod groups;
pub mod health;
pub mod identity;
// Incidents handlers — lifted to nanosiem-enterprise in NAN-752 (Phase 2 of
// the open-core split). Incidents group multiple cases for SOC investigations
// and ship with cases.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::incidents;
pub mod ip_allowlist;
pub mod license;
pub mod log_sources;
pub mod lookup;
pub mod marketplace;
// meloD AI handlers — lifted to nanosiem-enterprise in NAN-752 (Phase 2 of
// the open-core split). Re-exported here so route registrations
// (`handlers::melod_chat`, `handlers::melod::get_ai_failures`, etc.) continue
// to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::melod;
pub mod mfa;
pub mod mitre;
pub mod news;
// Notebooks handlers — lifted to nanosiem-enterprise in NAN-752 (Phase 2 of
// the open-core split). Re-exported here so route registrations
// (`handlers::notebooks::list_notebooks`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::notebooks;
pub mod notifications;
// OIDC handlers — lifted to nanosiem-enterprise in NAN-751 (Phase 2 of the
// open-core split). Re-exported here so route registrations
// (`handlers::oidc::list_providers`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::oidc;
pub mod onboarding;
pub mod parser_repositories;
pub mod playbook_repositories;
pub mod playbooks;
pub mod prevalence;
pub mod query_library;
pub mod recent_activity;
// Risk analytics handlers — lifted to nanosiem-enterprise in NAN-752 (Phase
// 2 of the open-core split). Re-exported here so route registrations
// (`handlers::risk::get_risky_entities`, etc.) continue to resolve.
#[cfg(feature = "enterprise")]
pub use nanosiem_enterprise::handlers::risk;
pub mod roles;
pub mod rule_repositories;
pub mod scheduler;
pub mod search;
pub mod search_history;
pub mod sessions;
pub mod settings;
pub mod setup;
pub mod siem_health;
pub mod siem_health_suppressions;
pub mod source_configs;
pub mod system;
pub mod tuning;
pub mod upload;
pub mod users;

pub use alerts::*;
pub use api_keys::*;
pub use audit::*;
pub use auth::*;
pub use capabilities::*;
pub use credentials::*;
pub use dashboards::*;
pub use detections::*;
pub use enrichment::*;
pub use feedback::*;
pub use fields::*;
pub use groups::*;
pub use health::*;
pub use lookup::*;
#[cfg(feature = "enterprise")]
pub use melod::*;
pub use news::*;
#[cfg(feature = "enterprise")]
pub use notebooks::*;
pub use notifications::*;
// `oidc` re-exported above as a module via `pub use nanosiem_enterprise::...`;
// nothing additional needed here.
pub use prevalence::*;
pub use query_library::*;
pub use recent_activity::*;
// `risk` re-exported above as a module via `pub use nanosiem_enterprise::...`;
// route bindings reference items as `handlers::risk::*` so a wildcard
// re-export here is unnecessary.
pub use roles::*;
// Scheduled job handlers kept for backwards compat but no longer routed.
// New ingestion endpoints are in handlers::lookup::ingestion.
pub use search::*;
pub use search_history::*;
pub use sessions::*;
pub use settings::*;
pub use setup::*;
pub use siem_health::*;
pub use system::*;
pub use tuning::*;
pub use upload::*;
pub use users::*;

impl AuditExt for AppState {
    fn emit_audit(&self, event: AuditEvent) {
        if let Some(ref emitter) = self.audit_emitter {
            let emitter = emitter.clone();
            let user_repo = self.user_repo.clone();
            tokio::spawn(async move {
                // Resolve actor name if we have an actor_id but no name
                let event = if event.actor_id.is_some() && event.actor_name.is_none() {
                    let mut enriched = event;
                    if let Some(actor_id) = enriched.actor_id {
                        if let Ok(user) = user_repo.get_user_by_id(actor_id).await {
                            enriched.actor_name = Some(user.name);
                        }
                    }
                    enriched
                } else {
                    event
                };

                if let Err(e) = emitter.emit(&event).await {
                    tracing::warn!(
                        source = %event.source,
                        action = %event.action,
                        error = %e,
                        "Failed to emit audit event"
                    );
                }
            });
        }
    }
}
