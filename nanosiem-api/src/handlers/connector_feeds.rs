// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dedicated open-core pull feeds; specs and ingest coordinates are server-owned.
use super::AuditExt;
use crate::{
    error::ApiError,
    middleware::{ensure_permission, AuthContext},
    state::AppState,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nano_connector::service::{
    admin::{AdminError, FeedPlan, FeedSummary, NewFeed},
    pg::{PgFeedStore, Tenancy},
    TenantSlot,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

/// What a feed does: `collector` pulls events into ingest through a parser
/// lane; `identity` syncs a directory (users, group memberships) into the
/// tenant's identity directory and has no ingest token or parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpenConnectorKind {
    Collector,
    Identity,
}

impl OpenConnectorKind {
    fn of(plan: &FeedPlan) -> Self {
        if plan.spec.kind == nano_connector::spec::Kind::Identity {
            Self::Identity
        } else {
            Self::Collector
        }
    }

    /// A listed feed's kind: the store marks identity feeds `not_required`
    /// (no ingest credential); otherwise the bundled spec decides.
    fn of_feed(feed: &FeedSummary) -> Self {
        if feed.credential == "not_required" {
            return Self::Identity;
        }
        nano_connector::first_party::plan(&feed.connector)
            .map(|plan| Self::of(&plan))
            .unwrap_or(Self::Collector)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::Identity => "identity",
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct OpenConnectorSpec {
    pub name: String,
    pub kind: OpenConnectorKind,
    pub source_slug: String,
    pub config_fields: Vec<String>,
    pub credential_fields: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateOpenConnectorFeed {
    pub name: String,
    pub connector: String,
    pub config: Map<String, Value>,
    pub vendor_credentials: HashMap<String, String>,
    /// Required for collector feeds; refused for identity feeds, which
    /// write the identity directory and never ingest.
    #[serde(default)]
    pub ingest_token: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct OpenConnectorFeed {
    pub id: Uuid,
    pub name: String,
    pub connector: String,
    pub kind: OpenConnectorKind,
    pub enabled: bool,
    pub last_status: Option<String>,
    /// The last run's error, truncated (e.g. an identity runner without a
    /// coordinator reports `identity_coordinator_unconfigured: ...`).
    pub last_error: Option<String>,
    pub last_success_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Longest `last_error` the list returns.
const LAST_ERROR_MAX_CHARS: usize = 300;

fn truncate_error(error: Option<String>) -> Option<String> {
    let error = error?;
    let error = error.trim();
    if error.is_empty() {
        return None;
    }
    if error.chars().count() <= LAST_ERROR_MAX_CHARS {
        return Some(error.to_string());
    }
    let mut short: String = error.chars().take(LAST_ERROR_MAX_CHARS).collect();
    short.push('…');
    Some(short)
}

/// The ingest token a create may store: required (non-empty, at most 2048
/// bytes) for a collector, refused for an identity feed.
fn admit_ingest_token(
    kind: OpenConnectorKind,
    token: Option<&str>,
) -> Result<Option<&str>, ApiError> {
    match (kind, token) {
        (OpenConnectorKind::Identity, None) => Ok(None),
        (OpenConnectorKind::Identity, Some(_)) => Err(ApiError::BadRequest(
            "Identity feeds sync the identity directory and take no ingest token".into(),
        )),
        (OpenConnectorKind::Collector, Some(token))
            if !token.trim().is_empty() && token.len() <= 2048 =>
        {
            Ok(Some(token))
        }
        (OpenConnectorKind::Collector, _) => Err(ApiError::BadRequest(
            "An ingest token is required (at most 2048 bytes)".into(),
        )),
    }
}

#[derive(Serialize, ToSchema)]
pub struct OpenConnectorFeedCreated {
    pub id: Uuid,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct OpenConnectorFeedEnabled {
    pub enabled: bool,
}

fn admin_error(error: AdminError) -> ApiError {
    match error {
        AdminError::Backend(_) => {
            ApiError::InternalError("Connector feed storage unavailable".into())
        }
        AdminError::FeedNotFound(_) | AdminError::CatalogNotFound(_) => {
            ApiError::NotFound("Connector feed or spec not found".into())
        }
        _ => ApiError::BadRequest("Invalid connector feed input".into()),
    }
}

fn store(state: &AppState, auth: &AuthContext) -> Result<(PgFeedStore, TenantSlot), ApiError> {
    #[cfg(feature = "enterprise")]
    if state.config.deployment_mode.is_enterprise_shared() {
        return Err(ApiError::NotFound(
            "Dedicated connector feeds unavailable".into(),
        ));
    }
    Ok((
        PgFeedStore::new(
            Tenancy::Dedicated {
                pool: state.pool.clone(),
            },
            (*state.encryption_service).clone(),
        ),
        TenantSlot {
            tenant_id: nanosiem_core::reports::COMPATIBILITY_TENANT_ID,
            actor_id: auth.user_id(),
        },
    ))
}

fn hec_parser_claims(transport: &str, name: &str, values: Option<&[String]>, lane: &str) -> bool {
    matches!(transport, "splunk_hec" | "splunk" | "hec")
        && values
            .filter(|v| !v.is_empty())
            .map_or(name == lane, |v| v.iter().any(|s| s == lane))
}

async fn require_deployed_parser(state: &AppState, source_slug: &str) -> Result<(), ApiError> {
    let sources = state.log_source_service.list(None).await?;
    if !sources.iter().any(|source| {
        hec_parser_claims(
            &source.source_type,
            &source.name,
            source.match_values.as_deref(),
            source_slug,
        ) && source.enabled
            && source.deployed
            && source.lifecycle_status == "active"
    }) {
        return Err(ApiError::BadRequest(format!(
            "Deploy an enabled log source for lane `{source_slug}` before starting this feed"
        )));
    }
    Ok(())
}

fn audit(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    action: &str,
    id: Uuid,
    kind: Option<OpenConnectorKind>,
) {
    let mut event = AuditEvent::builder(AuditSource::LogSource, action)
        .actor(Some(auth.user_id()), None)
        .api_key(auth.api_key_id, auth.api_key_name.clone())
        .resource("connector_feed", Some(id), None)
        .client_context(client);
    if let Some(kind) = kind {
        event = event.details(serde_json::json!({ "kind": kind.as_str() }));
    }
    state.emit_audit(event.build());
}

#[utoipa::path(get, path = "/api/connector-specs", tag = "connector_feeds",
    responses((status = 200, body = Vec<OpenConnectorSpec>), (status = 403, description = "Forbidden")), security(("api_key" = [])))]
pub async fn list_specs(
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<OpenConnectorSpec>>, ApiError> {
    ensure_permission(&auth, "log_sources:view")?;
    let specs = nano_connector::first_party::SPECS
        .iter()
        .map(|(name, _)| {
            let plan = nano_connector::first_party::plan(name).map_err(admin_error)?;
            Ok(OpenConnectorSpec {
                name: name.to_string(),
                kind: OpenConnectorKind::of(&plan),
                source_slug: plan.source_slug.clone(),
                config_fields: nano_connector::service::admin::config_keys(&plan.spec_yaml)
                    .map_err(admin_error)?
                    .into_iter()
                    .collect(),
                credential_fields: nano_connector::service::admin::credential_fields(&plan.spec)
                    .map_err(admin_error)?
                    .into_iter()
                    .collect(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(specs))
}

#[utoipa::path(get, path = "/api/connector-feeds", tag = "connector_feeds",
    responses((status = 200, body = Vec<OpenConnectorFeed>), (status = 403, description = "Forbidden")), security(("api_key" = [])))]
pub async fn list_feeds(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<OpenConnectorFeed>>, ApiError> {
    ensure_permission(&auth, "log_sources:view")?;
    let (store, slot) = store(&state, &auth)?;
    let feeds = store.list_feeds(&slot).await.map_err(admin_error)?;
    Ok(Json(
        feeds
            .into_iter()
            .map(|feed| OpenConnectorFeed {
                kind: OpenConnectorKind::of_feed(&feed),
                id: feed.id,
                name: feed.name,
                connector: feed.connector,
                enabled: feed.enabled,
                last_status: feed.last_status,
                last_error: truncate_error(feed.last_error),
                last_success_at: feed.last_success_at,
            })
            .collect(),
    ))
}

#[utoipa::path(post, path = "/api/connector-feeds", tag = "connector_feeds", request_body = CreateOpenConnectorFeed,
    responses((status = 200, body = OpenConnectorFeedCreated), (status = 400, description = "Invalid input"), (status = 403, description = "Forbidden")), security(("api_key" = [])))]
pub async fn create_feed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateOpenConnectorFeed>,
) -> Result<Json<OpenConnectorFeedCreated>, ApiError> {
    ensure_permission(&auth, "log_sources:create")?;
    ensure_permission(&auth, "log_sources:deploy")?;
    let (store, slot) = store(&state, &auth)?;
    let plan = nano_connector::first_party::plan(&request.connector).map_err(admin_error)?;
    let kind = OpenConnectorKind::of(&plan);
    let ingest_token = admit_ingest_token(kind, request.ingest_token.as_deref())?;
    // An identity feed writes the identity directory: no ingest URL, no
    // parser lane. Vendor credentials are sealed by the store either way.
    let url = match kind {
        OpenConnectorKind::Identity => String::new(),
        OpenConnectorKind::Collector => {
            require_deployed_parser(&state, &plan.source_slug).await?;
            std::env::var("CONNECTOR_INGEST_URL")
                .unwrap_or_else(|_| "http://vector:8088/services/collector/event".into())
        }
    };
    let feed = NewFeed {
        name: request.name,
        config: request.config,
        vendor_credentials: request.vendor_credentials,
        enabled: true,
        ..Default::default()
    };
    let id = store
        .create_feed(&slot, &plan, &feed, &url, ingest_token)
        .await
        .map_err(admin_error)?;
    audit(
        &state,
        &auth,
        &client,
        "connector_feed_created",
        id,
        Some(kind),
    );
    Ok(Json(OpenConnectorFeedCreated { id }))
}

#[utoipa::path(patch, path = "/api/connector-feeds/{id}", tag = "connector_feeds", params(("id" = Uuid, Path)), request_body = OpenConnectorFeedEnabled,
    responses((status = 200, description = "Updated"), (status = 400, description = "Parser lane must be deployed"), (status = 404, description = "Not found"), (status = 403, description = "Forbidden")), security(("api_key" = [])))]
pub async fn set_enabled(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
    Json(request): Json<OpenConnectorFeedEnabled>,
) -> Result<Json<Value>, ApiError> {
    ensure_permission(&auth, "log_sources:edit")?;
    if request.enabled {
        ensure_permission(&auth, "log_sources:deploy")?;
    }
    let (store, slot) = store(&state, &auth)?;
    let feeds = store.list_feeds(&slot).await.map_err(admin_error)?;
    let feed = feeds
        .iter()
        .find(|feed| feed.id == id)
        .ok_or_else(|| ApiError::NotFound("Connector feed not found".into()))?;
    let kind = OpenConnectorKind::of_feed(feed);
    // Identity feeds have no parser lane to be ready.
    if request.enabled && kind == OpenConnectorKind::Collector {
        require_deployed_parser(&state, &feed.source_slug).await?;
    }
    store
        .set_enabled(&slot, id, request.enabled)
        .await
        .map_err(admin_error)?;
    audit(
        &state,
        &auth,
        &client,
        if request.enabled {
            "connector_feed_resumed"
        } else {
            "connector_feed_paused"
        },
        id,
        Some(kind),
    );
    Ok(Json(serde_json::json!({"ok": true})))
}

#[utoipa::path(delete, path = "/api/connector-feeds/{id}", tag = "connector_feeds", params(("id" = Uuid, Path)),
    responses((status = 200, description = "Deleted"), (status = 404, description = "Not found"), (status = 403, description = "Forbidden")), security(("api_key" = [])))]
pub async fn delete_feed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    ensure_permission(&auth, "log_sources:delete")?;
    let (store, slot) = store(&state, &auth)?;
    let kind = store
        .list_feeds(&slot)
        .await
        .map_err(admin_error)?
        .iter()
        .find(|feed| feed.id == id)
        .map(OpenConnectorKind::of_feed);
    store.delete_feed(&slot, id).await.map_err(admin_error)?;
    audit(&state, &auth, &client, "connector_feed_deleted", id, kind);
    Ok(Json(serde_json::json!({"ok": true})))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_specs, list_feeds, create_feed, set_enabled, delete_feed),
    components(schemas(
        OpenConnectorKind,
        OpenConnectorSpec,
        CreateOpenConnectorFeed,
        OpenConnectorFeed,
        OpenConnectorFeedCreated,
        OpenConnectorFeedEnabled
    ))
)]
pub struct ConnectorFeedsApiDoc;

#[cfg(test)]
mod tests {
    #[test]
    fn readiness_matches_hec_transport_and_claimed_vendor_lane() {
        let claims = vec!["okta".into()];
        assert!(super::hec_parser_claims(
            "splunk_hec",
            "Okta parser",
            Some(&claims),
            "okta"
        ));
        assert!(!super::hec_parser_claims(
            "routed",
            "okta",
            Some(&claims),
            "okta"
        ));
        assert!(!super::hec_parser_claims(
            "splunk_hec",
            "Okta parser",
            Some(&claims),
            "slack_access_log"
        ));
        assert!(super::hec_parser_claims("hec", "okta", None, "okta"));
        assert!(super::hec_parser_claims(
            "splunk",
            "okta",
            Some(&[]),
            "okta"
        ));
        assert!(!super::hec_parser_claims(
            "splunk_hec",
            "Other",
            None,
            "okta"
        ));
    }

    #[test]
    fn create_request_cannot_select_tenant_code_destination_or_backfill() {
        let body = serde_json::json!({"name": "fixture", "connector": "okta_system_log",
            "config": {"OKTA_DOMAIN": "fixture.okta.com"},
            "vendor_credentials": {"API_TOKEN": "fixture"}, "ingest_token": "fixture"});
        for forbidden in ["tenant_id", "spec_yaml", "ingest_url", "backfill_from"] {
            let mut injected = body.clone();
            injected[forbidden] = "caller-controlled".into();
            assert!(serde_json::from_value::<super::CreateOpenConnectorFeed>(injected).is_err());
        }
    }

    #[test]
    fn identity_feeds_take_no_ingest_token_and_collectors_require_one() {
        use super::{admit_ingest_token, OpenConnectorKind::*};
        // Identity: no token is the OK path; any token is refused.
        assert_eq!(admit_ingest_token(Identity, None).unwrap(), None);
        assert!(admit_ingest_token(Identity, Some("tok")).is_err());
        assert!(admit_ingest_token(Identity, Some("")).is_err());
        // Collector: still required, non-blank and bounded.
        assert_eq!(
            admit_ingest_token(Collector, Some("tok")).unwrap(),
            Some("tok")
        );
        assert!(admit_ingest_token(Collector, None).is_err());
        assert!(admit_ingest_token(Collector, Some("  ")).is_err());
        assert!(admit_ingest_token(Collector, Some("x".repeat(2049).as_str())).is_err());
    }

    #[test]
    fn identity_create_body_parses_without_an_ingest_token() {
        let body = serde_json::json!({"name": "Okta users", "connector": "okta_users",
            "config": {"OKTA_DOMAIN": "fixture.okta.com"},
            "vendor_credentials": {"API_TOKEN": "fixture"}});
        let request: super::CreateOpenConnectorFeed = serde_json::from_value(body).unwrap();
        assert!(request.ingest_token.is_none());
    }

    #[test]
    fn bundled_spec_kinds_map_to_the_api_kind() {
        for (name, _) in nano_connector::first_party::SPECS {
            let plan = nano_connector::first_party::plan(name).unwrap();
            let kind = super::OpenConnectorKind::of(&plan);
            let identity = plan.spec.kind == nano_connector::spec::Kind::Identity;
            assert_eq!(
                kind == super::OpenConnectorKind::Identity,
                identity,
                "{name}"
            );
            // Identity specs create with no token; collectors never do.
            assert_eq!(
                super::admit_ingest_token(kind, None).is_ok(),
                identity,
                "{name}"
            );
        }
        assert_eq!(
            serde_json::to_value(super::OpenConnectorKind::Identity).unwrap(),
            "identity"
        );
    }

    #[test]
    fn last_error_is_truncated_and_blank_is_none() {
        assert_eq!(super::truncate_error(Some("  ".into())), None);
        let short = "identity_coordinator_unconfigured: set NANO_LAKE_ENRICHMENT_COORDINATOR_URL";
        assert_eq!(
            super::truncate_error(Some(short.into())).as_deref(),
            Some(short)
        );
        let long = super::truncate_error(Some("é".repeat(1000))).unwrap();
        assert_eq!(long.chars().count(), super::LAST_ERROR_MAX_CHARS + 1);
    }
}
