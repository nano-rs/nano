// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5903: the API side of pull-feed lane setup. The planning and the
//! writes are `nanosiem_core::log_sources::feed_lane_setup`; this module
//! deploys through the normal log-source deploy path (OCSF sample gate
//! included) and writes the audit trail.

use std::collections::BTreeSet;

use nano_connector::first_party::BundledSpec;
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, LOG_SOURCE_CREATED, LOG_SOURCE_DEPLOYED, LOG_SOURCE_UPDATED,
    PARSER_IMPORTED, ROUTING_RULE_CREATED,
};
use nanosiem_core::log_sources::feed_lane_setup::{
    FeedConnector, FeedLaneSetup, LaneSetupOutcome, LaneSourceAction, LaneSourceDeployer, LaneSourceOrigin,
    SetupLease,
};
use nanosiem_core::log_sources::{OcsfGateInput, OcsfGateOutcome};
use nanosiem_core::parser_repository::ParserRepositoryService;
use uuid::Uuid;

use super::repository_target_authz::held_target_grants;
use super::AuditExt;
use crate::{error::ApiError, middleware::AuthContext, state::AppState};

/// The connector's name for a message: its display name up to the first
/// parenthesis ("Google Workspace audit").
pub(crate) fn short_name(spec: &'static BundledSpec) -> &'static str {
    spec.display_name.split(" (").next().unwrap_or(spec.display_name).trim()
}

/// The connector as lane setup sees it.
pub(crate) fn feed_connector(spec: &'static BundledSpec) -> FeedConnector<'static> {
    FeedConnector { slug: spec.slug, display: short_name(spec), parsers: spec.parsers }
}

/// Deploys a lane source exactly as `POST /api/log-sources/{id}/deploy` with
/// an empty body does: the OCSF gate's admission and full check (a first
/// go-live runs the catalog parser's bundled samples), then the deploy.
struct ApiLaneDeployer {
    state: AppState,
    auth: AuthContext,
    client: ClientContext,
    connector: &'static str,
}

#[async_trait::async_trait]
impl LaneSourceDeployer for ApiLaneDeployer {
    async fn deploy(&self, id: Uuid) -> Result<(), String> {
        let service = &self.state.log_source_service;
        let gate = OcsfGateInput { samples: Vec::new(), acknowledge_unattested: false };
        service.ocsf_deploy_admission(id, &gate).await.map_err(|e| e.to_string())?;
        let checked = service.ocsf_deploy_precheck(id, &gate).await.map_err(|e| e.to_string())?;
        service.ensure_ocsf_generation_unchanged(id, &checked).await.map_err(|e| e.to_string())?;
        let result = service.deploy(id).await.map_err(|e| e.to_string())?;
        self.state.emit_audit(
            AuditEvent::builder(AuditSource::LogSource, LOG_SOURCE_DEPLOYED)
                .actor(Some(self.auth.user_id()), None)
                .api_key(self.auth.api_key_id, self.auth.api_key_name.clone())
                .resource("log_source", Some(id), None::<String>)
                .client_context(&self.client)
                .details(serde_json::json!({
                    "success": result.success,
                    "via": "connector_feed_setup",
                    "connector": self.connector,
                    "ocsf_gate": format!("{:?}", checked.outcome),
                }))
                .build(),
        );
        // A bundled-sample pass is `Attested`; nothing here acknowledges an
        // unattested go-live, so the gate refuses rather than returning it.
        debug_assert_ne!(checked.outcome, OcsfGateOutcome::Unattested);
        if result.success {
            Ok(())
        } else {
            Err(result.message)
        }
    }
}

/// The audit events of a setup run: per created source the parser import
/// and the source itself (and the routing rule the import added, if any);
/// per widened source the match values added. Deploys are audited by the
/// deployer as they happen.
pub(crate) fn setup_audit_events(
    auth: &AuthContext,
    client: &ClientContext,
    outcome: &LaneSetupOutcome,
    connector: &str,
    feed_name: &str,
) -> Vec<AuditEvent> {
    let base = |source: AuditSource, action: &str| {
        AuditEvent::builder(source, action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(client)
    };
    let mut events = Vec::new();
    for step in &outcome.steps {
        let Some(id) = step.log_source_id else { continue };
        let details = serde_json::json!({
            "source": "connector_feed_setup",
            "connector": connector,
            "feed": feed_name,
            "parser": step.parser,
            "lanes": step.lanes,
            "match_values_added": step.added_lanes,
        });
        match step.action {
            // A connector-owned pull source is a plain log source: no parser
            // import happened, so none is audited.
            LaneSourceAction::Create if step.origin == Some(LaneSourceOrigin::PullSource) => events.push(
                base(AuditSource::LogSource, LOG_SOURCE_CREATED)
                    .resource("log_source", Some(id), Some(step.log_source_name.clone()))
                    .details(serde_json::json!({
                        "source": "connector_feed_setup",
                        "origin": "pull_source",
                        "connector": connector,
                        "feed": feed_name,
                        "parser": step.parser,
                        "lanes": step.lanes,
                    }))
                    .build(),
            ),
            LaneSourceAction::Create => {
                events.push(
                    base(AuditSource::ParserRepo, PARSER_IMPORTED)
                        .resource("parser", None, step.parser.clone())
                        .details(details.clone())
                        .build(),
                );
                events.push(
                    base(AuditSource::ParserRepo, LOG_SOURCE_CREATED)
                        .resource("log_source", Some(id), Some(step.log_source_name.clone()))
                        .details(serde_json::json!({
                            "withheld_match_values": outcome.withheld_values,
                            "source": "connector_feed_setup",
                            "connector": connector,
                            "feed": feed_name,
                            "parser": step.parser,
                            "lanes": step.lanes,
                        }))
                        .build(),
                );
                if let Some(rule) = outcome.routing_rule_id {
                    events.push(
                        base(AuditSource::ParserRepo, ROUTING_RULE_CREATED)
                            .resource("routing_rule", Some(rule), Some(step.log_source_name.clone()))
                            .details(serde_json::json!({
                                "source": "connector_feed_setup",
                                "log_source_id": id.to_string(),
                            }))
                            .build(),
                    );
                }
            }
            LaneSourceAction::Extend => events.push(
                base(AuditSource::LogSource, LOG_SOURCE_UPDATED)
                    .resource("log_source", Some(id), Some(step.log_source_name.clone()))
                    .details(details)
                    .build(),
            ),
            LaneSourceAction::Reuse | LaneSourceAction::TurnOn => {}
        }
    }
    events
}

/// Set up the log sources `lanes` need, then audit what was done (also on
/// failure: whatever was created stays and is recorded).
///
/// Runs on its own task: a client that disconnects mid-way does not cut a
/// setup off between its writes and its audit.
/// The lease travels with the task: a client that disconnects mid-setup does
/// not release it while the setup is still running; it comes back to the
/// caller, who keeps it until the feed is started.
pub(crate) async fn set_up_lane_sources(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    spec: &'static BundledSpec,
    lanes: &BTreeSet<String>,
    feed_name: &str,
    lease: SetupLease,
) -> Result<(LaneSetupOutcome, SetupLease), ApiError> {
    let (state, auth, client, lanes, feed_name) =
        (state.clone(), auth.clone(), client.clone(), lanes.clone(), feed_name.to_string());
    let task = tokio::spawn(async move {
        let parsers = ParserRepositoryService::new(state.pool.clone());
        let setup = FeedLaneSetup::new(&state.pool, &parsers);
        let grants = held_target_grants(&auth);
        let deployer =
            ApiLaneDeployer { state: state.clone(), auth: auth.clone(), client: client.clone(), connector: spec.slug };
        let has = |p: &str| auth.has_permission(p);
        let (outcome, result) = setup
            .set_up(&lease, feed_connector(spec), &lanes, &has, &grants, Some(auth.user_id()), &deployer)
            .await;
        for event in setup_audit_events(&auth, &client, &outcome, spec.slug, &feed_name) {
            state.emit_audit(event);
        }
        (outcome, result, lease)
    });
    let (outcome, result, lease) = task
        .await
        .map_err(|e| ApiError::InternalError(format!("Could not set up the log sources: {e}")))?;
    if let Err(e) = result {
        lease.release().await;
        return Err(super::connector_feeds::lane_setup_error(e));
    }
    Ok((outcome, lease))
}

#[cfg(test)]
#[path = "connector_feed_setup_tests.rs"]
mod tests;
