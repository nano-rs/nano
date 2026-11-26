// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4914 phase 4: connector pull feeds (open edition; single-tenant port
//! of main's NAN-3743 dedicated feeds).
//!
//! A feed runs a reviewed bundled connector spec (selected by name, pinned by
//! sha256) on a schedule in the `nano-connector-runner` service and delivers
//! the events to the local Vector HEC listener. The caller never supplies a
//! spec, an ingest destination or a backfill start.
//!
//! The vendor secret is a credential in the credentials store
//! (`cloud_credentials`, provider per connector): binding one needs
//! `credentials:use`, and entering a new one inline also `credentials:create`.
//! Starting a feed (create, resume) needs `log_sources:deploy` and an
//! enabled, deployed parser for every lane the feed emits into, so a feed
//! never pulls into Vector's default drop path.
//!
//! NAN-5903: a create with `set_up_log_sources: true` sets up the missing
//! lane sources first, from the catalog parser that matches the connector
//! (`nanosiem_core::log_sources::feed_lane_setup`), with the permissions the
//! same setup takes by hand. `POST /api/connector-feeds/plan` says what a
//! create would set up, for the confirm step.
//!
//! G22: an identity feed (`kind: identity`, e.g. `okta_users`,
//! `entra_directory`) emits into no lane: the runner writes the user
//! directory (`user_registry`) under the feed's own identity provider row.
//! Removing it tombstones the users it synced.

use std::collections::{BTreeSet, HashMap};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nano_connector::first_party;
use nano_connector::service::admin::{self, AdminError, NewFeed};
use nano_connector::service::pg::{CheckpointSummary, FeedSummary, PgFeedStore, RunSummary};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, CONNECTOR_FEED_CHECKPOINT_RESET, CONNECTOR_FEED_CREATED, CONNECTOR_FEED_SPEC_ADOPTED,
    CONNECTOR_FEED_DELETED, CONNECTOR_FEED_PAUSED, CONNECTOR_FEED_RESUMED, CREDENTIAL_CREATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::log_sources::feed_lane_setup::{FeedLaneSetup, LaneSetupError, LaneSourceStep, SetupLease};
use nanosiem_core::parsers::{
    normalize_credential_payload, validate_credential_payload, CreateCloudCredential,
    CredentialRepository, CredentialRepositoryError,
};
use nanosiem_core::typeid::{self, TypeIdParam};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use super::AuditExt;
use crate::{
    error::ApiError,
    middleware::{ensure_permission, AuthContext},
    state::AppState,
};

const VIEW: &str = "log_sources:view";
const CREATE: &str = "log_sources:create";
const EDIT: &str = "log_sources:edit";
const DELETE: &str = "log_sources:delete";
const DEPLOY: &str = "log_sources:deploy";

/// NAN-4941: the bundled spec list is static metadata, and the connector
/// credential rotate form reads its secret fields from it. A role that manages
/// credentials (`credentials:view`) without `log_sources:view` must still be
/// able to rotate an Okta / Google Workspace / Slack / Netskope credential.
const SPECS_VIEW: [&str; 2] = [VIEW, nanosiem_core::auth::permissions::CREDENTIALS_VIEW];

pub(crate) fn ensure_specs_view(auth: &AuthContext) -> Result<(), ApiError> {
    if auth.has_any_permission(&SPECS_VIEW) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(format!("Missing permission: {} or {}", SPECS_VIEW[0], SPECS_VIEW[1])))
    }
}

/// A bundled connector spec a feed can run.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorSpecInfo {
    /// Spec slug (`okta_system_log`).
    pub name: String,
    /// `collector` (events into a parser lane) or `identity` (users and
    /// group memberships into the user directory; no lane).
    pub kind: String,
    pub display_name: String,
    /// The credentials-store provider its vendor secret lives under.
    pub credential_provider: String,
    /// The parser lane label (`okta`, or a template such as `gws_{{item}}`).
    pub source_type: String,
    /// The spec's own schedule (the fastest a feed may run), if any.
    pub schedule: Option<String>,
    pub config_fields: Vec<String>,
    /// Config fields a feed may leave out.
    pub optional_config_fields: Vec<String>,
    /// Fields the bound credential must carry.
    pub credential_fields: Vec<String>,
    /// NAN-5903: plain-English label, help and known values per config key,
    /// in form order.
    pub config_field_info: Vec<ConnectorFieldInfo>,
    /// NAN-5903: plain-English label and help per credential field.
    pub credential_field_info: Vec<ConnectorFieldInfo>,
    /// NAN-5903: the catalog parsers (in preference order) a missing lane's
    /// log source is set up from. Empty for an identity connector.
    pub parsers: Vec<String>,
}

/// How a form shows one config or credential key (NAN-5903).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFieldInfo {
    pub key: String,
    pub label: String,
    /// Tooltip text.
    pub help: String,
    /// Example value for an empty field.
    pub placeholder: Option<String>,
    /// Known values of a comma-separated list field (a multi-select); empty
    /// for free text.
    pub choices: Vec<ConnectorFieldChoice>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFieldChoice {
    pub value: String,
    pub label: String,
    /// Ticked on a new feed.
    pub default: bool,
}

fn field_info(f: &first_party::FieldInfo) -> ConnectorFieldInfo {
    ConnectorFieldInfo {
        key: f.key.to_string(),
        label: f.label.to_string(),
        help: f.help.to_string(),
        placeholder: f.placeholder.map(str::to_string),
        choices: f
            .choices
            .iter()
            .map(|c| ConnectorFieldChoice { value: c.value.to_string(), label: c.label.to_string(), default: c.default })
            .collect(),
    }
}

/// Create request. Never carries a spec, an ingest destination or a backfill.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateConnectorFeed {
    pub name: String,
    pub connector: String,
    #[serde(default)]
    pub config: Map<String, Value>,
    /// Bind an existing credential (`cred_...`) of the connector's provider.
    #[serde(default, with = "typeid::cloud_credential::opt")]
    #[schema(value_type = Option<String>)]
    pub credential_id: Option<Uuid>,
    /// Or enter a new credential: stored in the credentials store (versions,
    /// rotation) and bound to the feed. Exclusive with `credential_id`.
    #[serde(default)]
    pub credentials: Option<HashMap<String, String>>,
    /// Cron override; no faster than the spec's own schedule.
    #[serde(default)]
    pub schedule: Option<String>,
    #[serde(default)]
    pub max_run_secs: Option<i32>,
    /// NAN-5903: set up the log sources of lanes that have none (from the
    /// connector's catalog parser) before creating the feed. Without it a
    /// feed with such a lane is refused, naming the lanes.
    #[serde(default)]
    pub set_up_log_sources: bool,
}

/// What a create would set up (NAN-5903). Read only.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanConnectorFeed {
    pub connector: String,
    #[serde(default)]
    pub config: Map<String, Value>,
}

/// `POST /api/connector-feeds/plan`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedSetupPlan {
    /// The lanes the feed would emit into (none for an identity feed).
    pub lanes: Vec<String>,
    /// One entry per log source the lanes use: `reuse` (already serves
    /// them), `create`, `extend` (claims more lanes) or `turn_on`.
    pub log_sources: Vec<LaneSourceStep>,
    /// How many log sources a create would make.
    pub creates: usize,
    /// Whether a create would change any log source (the UI confirms first).
    pub changes_log_sources: bool,
    /// Permissions the setup needs beyond creating the feed.
    pub required_permissions: Vec<String>,
    /// Of those, the ones the caller lacks (a create would be refused).
    pub missing_permissions: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetConnectorFeedEnabled {
    pub enabled: bool,
    /// NAN-5903: when resuming, set up the log sources of lanes that have
    /// none (as on create). Without it such a resume is refused.
    #[serde(default)]
    pub set_up_log_sources: bool,
}

/// Optional body of `POST /api/connector-feeds/{id}/adopt-spec` (NAN-5903).
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AdoptConnectorFeedSpec {
    /// Set up the log sources of lanes the updated spec emits into that
    /// have none. Without it adopting an enabled feed onto such lanes is
    /// refused.
    #[serde(default)]
    pub set_up_log_sources: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ResetConnectorFeedStream {
    /// Stream id of a time-window stream (e.g. `system_log`).
    pub stream: String,
}

/// A feed as listed. No secret material.
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedView {
    /// `cfeed_...`
    pub id: String,
    pub name: String,
    pub connector: String,
    /// `collector` or `identity` (see [`ConnectorSpecInfo::kind`]).
    pub kind: String,
    pub source_type: String,
    pub enabled: bool,
    /// A run holds the feed's lease right now.
    pub running: bool,
    pub schedule: Option<String>,
    /// The schedule in effect (feed override, else the spec's, else every 5 min).
    pub effective_schedule: String,
    #[schema(value_type = Object)]
    pub config: Map<String, Value>,
    /// `cred_...`
    pub credential_id: Option<String>,
    pub max_run_secs: Option<i32>,
    pub next_run_at: DateTime<Utc>,
    pub consecutive_failures: i32,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_status: Option<String>,
    /// The last run's error, truncated.
    pub last_error: Option<String>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// NAN-4931: this build bundles a different spec than the one the feed is
    /// pinned to. Nothing re-pins automatically; an operator adopts it with
    /// `POST /api/connector-feeds/{id}/adopt-spec` (which resets checkpoints).
    pub spec_update_available: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedRunView {
    pub id: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub events: i64,
    pub pages: i32,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedCheckpointView {
    pub stream_id: String,
    /// The checkpoint's shape only (`window_resume`, `fanout`, ...), never
    /// its contents.
    pub kind: String,
    pub commits: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedDetail {
    pub feed: ConnectorFeedView,
    pub runs: Vec<ConnectorFeedRunView>,
    pub checkpoints: Vec<ConnectorFeedCheckpointView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedCreated {
    /// `cfeed_...`
    pub id: String,
    /// `cred_...` of the bound credential (new when entered inline).
    pub credential_id: Option<String>,
    /// NAN-5903: the log sources the feed's lanes use, and what this create
    /// did to each (`reuse`, `create`, `extend`, `turn_on`).
    pub log_sources: Vec<LaneSourceStep>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedResetResult {
    pub stream: String,
    pub prior_checkpoint: bool,
    pub prior_kind: String,
    /// Where the next run resumes (now − 5 min; never earlier). For an
    /// identity stream: the reset time.
    pub anchor: DateTime<Utc>,
    pub next_run_at: DateTime<Utc>,
    /// An identity stream was reset: the next run is a full directory resync
    /// (users it no longer returns are retired, under the shrink guard).
    pub full_resync: bool,
}

/// Longest `last_error` the list returns.
const LAST_ERROR_MAX_CHARS: usize = 300;

pub(crate) fn truncate_error(error: Option<String>) -> Option<String> {
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

fn admin_error(error: AdminError) -> ApiError {
    match error {
        AdminError::Backend(e) => {
            tracing::error!(error = %e, "connector feed storage error");
            ApiError::InternalError("Connector feed storage unavailable".into())
        }
        AdminError::FeedNotFound(_) => ApiError::NotFound("Connector feed not found".into()),
        AdminError::CatalogNotFound(name) => ApiError::NotFound(format!("Unknown connector `{name}`")),
        AdminError::DuplicateName => ApiError::Conflict("A pull feed with this name already exists".into()),
        AdminError::InvalidInput(m) => ApiError::BadRequest(m),
        AdminError::InvalidSpec(m) => ApiError::InternalError(format!("Bundled connector spec is invalid: {m}")),
    }
}

fn store(state: &AppState) -> PgFeedStore {
    PgFeedStore::new(state.pool.clone(), (*state.encryption_service).clone())
}

fn credentials_repo(state: &AppState) -> CredentialRepository {
    CredentialRepository::with_crypto(state.pool.clone(), (*state.encryption_service).clone())
}

/// `collector` or `identity`.
fn spec_kind(spec: &nano_connector::spec::ConnectorSpec) -> &'static str {
    match spec.kind {
        nano_connector::spec::Kind::Identity => "identity",
        _ => "collector",
    }
}

fn view(feed: FeedSummary) -> ConnectorFeedView {
    let plan = first_party::plan(&feed.connector).ok();
    let spec_update_available = plan.as_ref().is_some_and(|p| !p.spec_sha256.eq_ignore_ascii_case(&feed.spec_sha256));
    let kind = plan.as_ref().map_or("collector", |p| spec_kind(&p.spec)).to_string();
    let spec_schedule = plan.and_then(|p| p.spec.schedule);
    let effective = nano_connector::service::feed::effective_schedule(feed.schedule.as_deref(), spec_schedule.as_deref())
        .to_string();
    ConnectorFeedView {
        id: typeid::encode(typeid::connector_feed::PREFIX, &feed.id),
        name: feed.name,
        connector: feed.connector,
        kind,
        source_type: feed.source_type,
        enabled: feed.enabled,
        running: feed.running,
        schedule: feed.schedule,
        effective_schedule: effective,
        config: feed.config,
        credential_id: feed.credential_id.map(|c| typeid::encode(typeid::cloud_credential::PREFIX, &c)),
        max_run_secs: feed.max_run_secs,
        next_run_at: feed.next_run_at,
        consecutive_failures: feed.consecutive_failures,
        last_run_at: feed.last_run_at,
        last_status: feed.last_status,
        last_error: truncate_error(feed.last_error),
        last_success_at: feed.last_success_at,
        created_at: feed.created_at,
        spec_update_available,
    }
}

fn run_view(r: RunSummary) -> ConnectorFeedRunView {
    ConnectorFeedRunView {
        id: r.id.to_string(),
        status: r.status,
        started_at: r.started_at,
        finished_at: r.finished_at,
        events: r.events,
        pages: r.pages,
        error: truncate_error(r.error),
    }
}

fn checkpoint_view(c: CheckpointSummary) -> ConnectorFeedCheckpointView {
    ConnectorFeedCheckpointView {
        stream_id: c.stream_id,
        kind: c.kind.to_string(),
        commits: c.commits,
        updated_at: c.updated_at,
    }
}

/// G22: whether `connector` is an identity directory sync (`kind: identity`).
pub(crate) fn is_identity_connector(connector: &str) -> bool {
    first_party::plan(connector).is_ok_and(|p| p.spec.kind == nano_connector::spec::Kind::Identity)
}

/// NAN-4931 review: an identity feed writes (and, on delete or a reset full
/// run, retires) the user directory that identity enrichment reads, so every
/// identity-feed mutation also needs `enrichments:configure`, the permission
/// the identity-provider endpoints require, on top of the connector and
/// credential permissions.
pub(crate) fn ensure_identity_permission(auth: &AuthContext, connector: &str) -> Result<(), ApiError> {
    if is_identity_connector(connector) {
        ensure_permission(auth, permissions::ENRICHMENTS_CONFIGURE)?;
    }
    Ok(())
}

/// G22: tombstone the directory users of an identity feed (none for a
/// collector, or an identity feed that never ran).
async fn retire_identity_feed_users(state: &AppState, feed_id: Uuid, connector: &str) -> Result<Option<u64>, ApiError> {
    if !is_identity_connector(connector) {
        return Ok(None);
    }
    let provider_id = nanosiem_core::identity::directory_feed::provider_id_for_feed(feed_id);
    let repo = state.identity_service.repository();
    let provider = match repo.get_provider(&provider_id).await {
        Ok(p) => p,
        Err(nanosiem_core::identity::IdentityRepositoryError::ProviderNotFound(_)) => return Ok(Some(0)),
        Err(e) => return Err(ApiError::InternalError(format!("identity directory: {e}"))),
    };
    if provider.connector_feed_id != Some(feed_id) {
        return Ok(Some(0));
    }
    let retired = repo
        .mark_absent_users_by_sync_time(&provider_id, Utc::now() + chrono::Duration::days(1))
        .await
        .map_err(|e| ApiError::InternalError(format!("identity directory: {e}")))?;
    Ok(Some(retired))
}

/// The lanes no enabled, deployed, active HEC parser serves. Events of such
/// a lane fall into Vector's default drop path.
async fn unserved_lanes(state: &AppState, lanes: &BTreeSet<String>) -> Result<Vec<String>, ApiError> {
    let sources = state.log_source_service.list(None).await?;
    Ok(lanes
        .iter()
        .filter(|lane| !sources.iter().any(|s| nanosiem_core::log_sources::feed_lane_setup::serves(s, lane)))
        .cloned()
        .collect())
}

fn lane_list(lanes: &[String]) -> String {
    lanes.iter().map(|l| format!("`{l}`")).collect::<Vec<_>>().join(", ")
}

/// NAN-5903: every lane a feed starts on (create, resume, adopting a spec
/// update) needs an enabled, deployed, active HEC parser. With the caller's
/// consent (`set_up`) the missing ones are set up from the connector's catalog
/// parser; without it the start is refused, naming the lanes. Returns what
/// setup did (empty when nothing was missing).
async fn ensure_lanes_served(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    spec: &'static first_party::BundledSpec,
    lanes: &BTreeSet<String>,
    feed_name: &str,
    set_up: bool,
) -> Result<(Vec<LaneSourceStep>, Option<SetupLease>), ApiError> {
    // An identity feed has no lane.
    if lanes.is_empty() {
        return Ok((Vec::new(), None));
    }
    // Every start onto lanes runs under the setup lease, so it never sees a
    // half-done setup (a lane widened but not deployed yet reads as served).
    // The caller keeps the lease until the feed is started, then releases it.
    let lease = SetupLease::acquire(&state.pool, &format!("start {feed_name}"), SETUP_LEASE_WAIT)
        .await
        .map_err(lane_setup_error)?;
    let missing = match unserved_lanes(state, lanes).await {
        Ok(missing) => missing,
        Err(e) => {
            lease.release().await;
            return Err(e);
        }
    };
    if missing.is_empty() {
        return Ok((Vec::new(), Some(lease)));
    }
    if !set_up {
        lease.release().await;
        return Err(log_sources_missing(spec, &missing));
    }
    let (outcome, lease) =
        super::connector_feed_setup::set_up_lane_sources(state, auth, client, spec, lanes, feed_name, lease).await?;
    Ok((outcome.steps, Some(lease)))
}

/// How long a start waits for another feed's setup before a 409.
const SETUP_LEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The feed is started only while the lease is still ours (fencing: a
/// setup that stalled past its lease and was taken over starts nothing).
async fn still_held(lease: &Option<SetupLease>) -> Result<(), ApiError> {
    match lease {
        Some(lease) => lease.ensure_held().await.map_err(lane_setup_error),
        None => Ok(()),
    }
}

async fn release(lease: Option<SetupLease>) {
    if let Some(lease) = lease {
        lease.release().await;
    }
}

/// Code of the structured refusal for a start whose lanes lack a log source.
pub const LOG_SOURCES_MISSING: &str = "LOG_SOURCES_MISSING";

/// NAN-5903: the structured refusal for a start (create without consent,
/// resume, adopt) whose lanes have no log source. `details.missing_lanes`
/// names them; Pull feeds answers it with Fix setup, which repeats the call
/// with `set_up_log_sources: true`.
pub(crate) fn log_sources_missing(spec: &'static first_party::BundledSpec, missing: &[String]) -> ApiError {
    ApiError::BadRequestWithDetails {
        code: LOG_SOURCES_MISSING,
        message: format!(
            "Some log sources this feed needs are missing, so its events to {} would be dropped. \
             Set them up with Fix setup on the Pull feeds page of the nano web app (it uses the {} parser), \
             or under Log sources.",
            lane_list(missing),
            super::connector_feed_setup::short_name(spec)
        ),
        details: serde_json::json!({ "missing_lanes": missing, "connector": spec.slug }),
    }
}

pub(crate) fn lane_setup_error(error: LaneSetupError) -> ApiError {
    if error.is_forbidden() {
        ApiError::Forbidden(error.to_string())
    } else if error.is_conflict() {
        ApiError::Conflict(error.to_string())
    } else if error.is_internal() {
        tracing::error!(error = %error, "pull feed log source setup failed");
        ApiError::InternalError(error.to_string())
    } else {
        ApiError::BadRequest(error.to_string())
    }
}

/// The bound credential must be of the connector's provider and carry every
/// field the spec's auth reads.
async fn check_bound_credential(
    state: &AppState,
    spec: &first_party::BundledSpec,
    plan: &admin::FeedPlan,
    credential_id: Uuid,
) -> Result<(), ApiError> {
    let repo = credentials_repo(state);
    let credential = repo.get(credential_id).await.map_err(|e| match e {
        CredentialRepositoryError::NotFound(_) => ApiError::BadRequest("The credential does not exist".into()),
        other => ApiError::InternalError(other.to_string()),
    })?;
    if credential.provider != spec.credential_provider {
        return Err(ApiError::BadRequest(format!(
            "{} feeds need a `{}` credential, not `{}`",
            spec.display_name, spec.credential_provider, credential.provider
        )));
    }
    let payload = repo
        .get_decrypted(credential_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("The credential could not be opened: {e}")))?;
    admin::vendor_secrets(&plan.spec, &payload).map(|_| ()).map_err(ApiError::BadRequest)
}

fn audit(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    action: &str,
    id: Uuid,
    name: Option<String>,
    details: Value,
) {
    state.emit_audit(
        AuditEvent::builder(AuditSource::LogSource, action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("connector_feed", Some(id), name)
            .client_context(client)
            .details(details)
            .build(),
    );
}

#[utoipa::path(get, path = "/api/connector-specs", tag = "connector_feeds",
    responses((status = 200, description = "Available connector specs", body = Vec<ConnectorSpecInfo>), (status = 403, description = "Forbidden")),
    security(("api_key" = [])))]
pub async fn list_connector_specs(
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<ConnectorSpecInfo>>, ApiError> {
    ensure_specs_view(&auth)?;
    let specs = first_party::SPECS
        .iter()
        .map(|s| {
            let plan = first_party::plan(s.slug).map_err(admin_error)?;
            Ok(ConnectorSpecInfo {
                name: s.slug.to_string(),
                display_name: s.display_name.to_string(),
                kind: spec_kind(&plan.spec).to_string(),
                credential_provider: s.credential_provider.to_string(),
                source_type: plan.source_type.clone(),
                schedule: plan.spec.schedule.clone(),
                config_fields: admin::config_keys(&plan.spec_yaml).map_err(admin_error)?.into_iter().collect(),
                optional_config_fields: admin::optional_config_keys(&plan.spec_yaml)
                    .map_err(admin_error)?
                    .into_iter()
                    .collect(),
                credential_fields: admin::credential_fields(&plan.spec).map_err(admin_error)?.into_iter().collect(),
                config_field_info: s.config_fields.iter().map(field_info).collect(),
                credential_field_info: s.credential_fields.iter().map(field_info).collect(),
                parsers: s.parsers.iter().map(|p| (*p).to_string()).collect(),
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(Json(specs))
}

#[utoipa::path(get, path = "/api/connector-feeds", tag = "connector_feeds",
    responses((status = 200, description = "Connector feeds", body = Vec<ConnectorFeedView>), (status = 403, description = "Forbidden")),
    security(("api_key" = [])))]
pub async fn list_connector_feeds(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<ConnectorFeedView>>, ApiError> {
    ensure_permission(&auth, VIEW)?;
    let feeds = store(&state).list_feeds().await.map_err(admin_error)?;
    Ok(Json(feeds.into_iter().map(view).collect()))
}

#[utoipa::path(get, path = "/api/connector-feeds/{id}", tag = "connector_feeds",
    params(("id" = String, Path, description = "Feed ID (cfeed_...)")),
    responses((status = 200, description = "Connector feed with stream state", body = ConnectorFeedDetail), (status = 404, description = "Not found"), (status = 403, description = "Forbidden")),
    security(("api_key" = [])))]
pub async fn get_connector_feed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<ConnectorFeedDetail>, ApiError> {
    ensure_permission(&auth, VIEW)?;
    let store = store(&state);
    let feed = store.get_feed(*id).await.map_err(admin_error)?;
    let runs = store.list_runs(*id, 20).await.map_err(admin_error)?;
    let checkpoints = store.list_checkpoints(*id).await.map_err(admin_error)?;
    Ok(Json(ConnectorFeedDetail {
        feed: view(feed),
        runs: runs.into_iter().map(run_view).collect(),
        checkpoints: checkpoints.into_iter().map(checkpoint_view).collect(),
    }))
}

/// NAN-5903: what a create would do to the log sources of the feed's lanes,
/// for the confirm step ("This will also create 1 log source: ..."). Read
/// only. A refusal a create would hit before any write (no matching catalog
/// parser, a lane another source holds) is returned the same way a create
/// returns it; a missing permission is listed in `missing_permissions`.
#[utoipa::path(post, path = "/api/connector-feeds/plan", tag = "connector_feeds", request_body = PlanConnectorFeed,
    responses((status = 200, description = "What a create would set up", body = ConnectorFeedSetupPlan),
        (status = 400, description = "Invalid config, or no catalog parser matches the connector"),
        (status = 403, description = "Requires log_sources:view + log_sources:deploy + (log_sources:create or log_sources:edit) (+ enrichments:configure for an identity connector). What the plan itself needs is listed in required_permissions / missing_permissions"),
        (status = 404, description = "Unknown connector"),
        (status = 409, description = "A lane is held by a log source that is not deployed")),
    security(("api_key" = [])))]
pub async fn plan_connector_feed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<PlanConnectorFeed>,
) -> Result<Json<ConnectorFeedSetupPlan>, ApiError> {
    // It names existing log sources: as readable as the log source list.
    // Every start can ask (create needs log_sources:create, resume and adopt
    // log_sources:edit, all log_sources:deploy); what THIS plan needs is in
    // `required_permissions` / `missing_permissions`, and the setup itself
    // enforces it before any write.
    ensure_permission(&auth, VIEW)?;
    ensure_permission(&auth, DEPLOY)?;
    if !auth.has_any_permission(&[CREATE, EDIT]) {
        return Err(ApiError::Forbidden(format!("Missing permission: {CREATE} or {EDIT}")));
    }
    let spec = first_party::get(&request.connector).map_err(admin_error)?;
    ensure_identity_permission(&auth, spec.slug)?;
    let plan = first_party::plan(spec.slug).map_err(admin_error)?;
    let lanes = admin::lanes(&plan, &request.config).map_err(admin_error)?;
    let empty = ConnectorFeedSetupPlan {
        lanes: lanes.iter().cloned().collect(),
        log_sources: Vec::new(),
        creates: 0,
        changes_log_sources: false,
        required_permissions: Vec::new(),
        missing_permissions: Vec::new(),
    };
    if lanes.is_empty() {
        return Ok(Json(empty));
    }
    let parsers = nanosiem_core::parser_repository::ParserRepositoryService::new(state.pool.clone());
    let setup = FeedLaneSetup::new(&state.pool, &parsers)
        .plan(super::connector_feed_setup::feed_connector(spec), &lanes)
        .await
        .map_err(lane_setup_error)?;
    Ok(Json(ConnectorFeedSetupPlan {
        creates: setup.creates(),
        changes_log_sources: setup.changes_anything(),
        missing_permissions: setup
            .required_permissions
            .iter()
            .filter(|p| !auth.has_permission(p))
            .map(|p| (*p).to_string())
            .collect(),
        required_permissions: setup.required_permissions.iter().map(|p| (*p).to_string()).collect(),
        log_sources: setup.steps,
        ..empty
    }))
}

#[utoipa::path(post, path = "/api/connector-feeds", tag = "connector_feeds", request_body = CreateConnectorFeed,
    responses((status = 201, description = "Connector feed created (with set_up_log_sources, after setting up its lanes' log sources)", body = ConnectorFeedCreated),
        (status = 400, description = "Invalid input; a lane with no log source without set_up_log_sources; no catalog parser matches the connector; or a set-up log source did not go live"),
        (status = 403, description = "Requires log_sources:create + log_sources:deploy, credentials:use (+ credentials:create for an inline credential), and enrichments:configure for an identity feed. Setting up lane sources also needs what that takes by hand: parser_repositories:import (+ source_configs:edit when the import binds a source configuration) to create one, log_sources:edit to widen one"),
        (status = 409, description = "Name already in use, or a lane is held by a log source that is not deployed")),
    security(("api_key" = [])))]
pub async fn create_connector_feed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<CreateConnectorFeed>,
) -> Result<(StatusCode, Json<ConnectorFeedCreated>), ApiError> {
    ensure_permission(&auth, CREATE)?;
    ensure_permission(&auth, DEPLOY)?;
    let spec = first_party::get(&request.connector).map_err(admin_error)?;
    ensure_identity_permission(&auth, spec.slug)?;
    let plan = first_party::plan(spec.slug).map_err(admin_error)?;
    let needs_credential = !admin::credential_fields(&plan.spec).map_err(admin_error)?.is_empty();

    if request.credential_id.is_some() && request.credentials.is_some() {
        return Err(ApiError::BadRequest("Give either credential_id or credentials, not both".into()));
    }
    if request.credential_id.is_some() || request.credentials.is_some() {
        ensure_permission(&auth, permissions::CREDENTIALS_USE)?;
    }
    if request.credentials.is_some() {
        ensure_permission(&auth, permissions::CREDENTIALS_CREATE)?;
    }

    let name = request.name.trim().to_string();
    // Everything that can be checked before a credential is created is.
    let feed = NewFeed {
        name: name.clone(),
        config: request.config,
        credential_id: request.credential_id.or(request.credentials.as_ref().map(|_| Uuid::nil())),
        schedule: request.schedule.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        max_run_secs: request.max_run_secs,
        enabled: true,
    };
    if !needs_credential && feed.credential_id.is_some() {
        return Err(ApiError::BadRequest(format!("{} takes no credential", spec.display_name)));
    }
    admin::check_inputs(&plan, &feed).map_err(admin_error)?;
    let lanes = admin::lanes(&plan, &feed.config).map_err(admin_error)?;
    let store = store(&state);
    // NAN-5903: everything a create can refuse without a write is refused
    // before any log source is set up: a name in use, an unserved lane
    // without consent, a bad credential.
    if store.list_feeds().await.map_err(admin_error)?.iter().any(|f| f.name == name) {
        return Err(admin_error(AdminError::DuplicateName));
    }
    // A cheap early refusal without consent (re-checked under the lease below).
    let unserved = unserved_lanes(&state, &lanes).await?;
    if !unserved.is_empty() && !request.set_up_log_sources {
        return Err(log_sources_missing(spec, &unserved));
    }
    let inline_payload = match request.credentials {
        Some(fields) => {
            let mut payload = serde_json::to_value(fields).unwrap_or(Value::Null);
            normalize_credential_payload(spec.credential_provider, &mut payload)
                .and_then(|()| validate_credential_payload(spec.credential_provider, &payload))
                .map_err(ApiError::BadRequest)?;
            admin::vendor_secrets(&plan.spec, &payload)
                .map_err(|e| ApiError::BadRequest(e.replace("the bound credential", "the credential")))?;
            // The credential's name is fixed by the feed's; a clash is refused
            // now, not after the log sources were set up.
            let credential_name = format!("{name} ({})", spec.slug);
            let taken: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM cloud_credentials WHERE name = $1)")
                .bind(&credential_name)
                .fetch_one(&state.pool)
                .await
                .map_err(|e| ApiError::InternalError(e.to_string()))?;
            if taken {
                return Err(ApiError::Conflict(format!(
                    "A credential named `{credential_name}` already exists; bind it with credential_id"
                )));
            }
            Some(payload)
        }
        None => {
            if let Some(credential_id) = feed.credential_id {
                check_bound_credential(&state, spec, &plan, credential_id).await?;
            }
            None
        }
    };

    // Under the setup lease from here until the feed exists: the lanes are
    // checked (and, with consent, set up) and the feed created with no other
    // setup in between.
    let (mut log_sources, lease) =
        ensure_lanes_served(&state, &auth, &client, spec, &lanes, &name, request.set_up_log_sources).await?;
    if log_sources.is_empty() && !lanes.is_empty() {
        // Nothing was set up: report the sources the lanes already use.
        let parsers = nanosiem_core::parser_repository::ParserRepositoryService::new(state.pool.clone());
        match FeedLaneSetup::new(&state.pool, &parsers)
            .plan(super::connector_feed_setup::feed_connector(spec), &lanes)
            .await
        {
            Ok(plan) => log_sources = plan.steps,
            Err(e) => tracing::warn!(error = %e, "could not list the log sources of a pull feed's lanes"),
        }
    }
    let credential_created = inline_payload.is_some();
    let created = match still_held(&lease).await {
        Ok(()) => create_feed_with_credential(&state, &auth, &client, spec, &plan, feed, inline_payload, &name).await,
        Err(e) => Err(e),
    };
    release(lease).await;
    let (id, feed) = created?;
    audit(
        &state,
        &auth,
        &client,
        CONNECTOR_FEED_CREATED,
        id,
        Some(name),
        serde_json::json!({
            "connector": spec.slug,
            "spec_sha256": plan.spec_sha256,
            "lanes": lanes,
            "credential_created": credential_created,
            "log_sources": log_sources
                .iter()
                .map(|s| serde_json::json!({
                    "action": s.action,
                    "log_source_id": s.log_source_id.map(|i| i.to_string()),
                    "lanes": s.lanes,
                }))
                .collect::<Vec<_>>(),
        }),
    );
    Ok((
        StatusCode::CREATED,
        Json(ConnectorFeedCreated {
            id: typeid::encode(typeid::connector_feed::PREFIX, &id),
            credential_id: feed.credential_id.map(|c| typeid::encode(typeid::cloud_credential::PREFIX, &c)),
            // The steps name existing log sources: only for a caller who may list them.
            log_sources: if auth.has_permission(VIEW) { log_sources } else { Vec::new() },
        }),
    ))
}


/// Create the inline credential (if any) and the feed; a refused feed takes
/// its new credential with it. Returns the feed id and the feed as created.
#[allow(clippy::too_many_arguments)]
async fn create_feed_with_credential(
    state: &AppState,
    auth: &AuthContext,
    client: &ClientContext,
    spec: &'static first_party::BundledSpec,
    plan: &admin::FeedPlan,
    mut feed: NewFeed,
    inline_payload: Option<Value>,
    name: &str,
) -> Result<(Uuid, NewFeed), ApiError> {
    let store = store(state);
    let mut created_credential = None;
    if let Some(payload) = inline_payload {
        let credential = credentials_repo(state)
            .create(
                &CreateCloudCredential {
                    name: format!("{name} ({})", spec.slug),
                    provider: spec.credential_provider.to_string(),
                    credentials: payload,
                    external_id: None,
                    description: Some(format!("Pull feed `{name}` ({})", spec.display_name)),
                    region: None,
                    environment: None,
                    expires_at: None,
                },
                Some(auth.user_id()),
            )
            .await
            .map_err(|e| match e {
                CredentialRepositoryError::DuplicateName(n) => {
                    ApiError::Conflict(format!("A credential named `{n}` already exists; bind it with credential_id"))
                }
                other => ApiError::InternalError(other.to_string()),
            })?;
        state.emit_audit(
            AuditEvent::builder(AuditSource::Credentials, CREDENTIAL_CREATED)
                .actor(Some(auth.user_id()), None)
                .api_key(auth.api_key_id, auth.api_key_name.clone())
                .resource("credential", Some(credential.id), Some(credential.name.clone()))
                .client_context(client)
                .details(serde_json::json!({ "provider": credential.provider, "via": "connector_feed" }))
                .build(),
        );
        feed.credential_id = Some(credential.id);
        created_credential = Some(credential.id);
    }

    let id = match store.create_feed(plan, &feed, Some(auth.user_id())).await {
        Ok(id) => id,
        Err(e) => {
            // Do not leave an orphan credential behind a refused feed.
            if let Some(credential_id) = created_credential {
                if let Err(del) = credentials_repo(state).delete(credential_id).await {
                    tracing::warn!(error = %del, "could not remove the credential of a refused pull feed");
                }
            }
            return Err(admin_error(e));
        }
    };
    Ok((id, feed))
}

#[utoipa::path(patch, path = "/api/connector-feeds/{id}", tag = "connector_feeds",
    params(("id" = String, Path, description = "Feed ID (cfeed_...)")), request_body = SetConnectorFeedEnabled,
    responses((status = 200, description = "Connector feed updated", body = ConnectorFeedView), (status = 400, description = "Parser lane must be deployed"),
        (status = 404, description = "Not found"), (status = 403, description = "Forbidden")),
    security(("api_key" = [])))]
pub async fn set_connector_feed_enabled(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<SetConnectorFeedEnabled>,
) -> Result<Json<ConnectorFeedView>, ApiError> {
    ensure_permission(&auth, EDIT)?;
    let store = store(&state);
    let feed = store.get_feed(*id).await.map_err(admin_error)?;
    ensure_identity_permission(&auth, &feed.connector)?;
    if request.enabled {
        ensure_permission(&auth, DEPLOY)?;
        let spec = first_party::get(&feed.connector).map_err(admin_error)?;
        let plan = first_party::plan(spec.slug).map_err(admin_error)?;
        let lanes = admin::lanes(&plan, &feed.config).map_err(admin_error)?;
        // NAN-5903: a lane whose source was deleted or turned off since is
        // set up again with consent, as on create.
        let (_, lease) =
            ensure_lanes_served(&state, &auth, &client, spec, &lanes, &feed.name, request.set_up_log_sources).await?;
        // Started under the lease, after its lanes are verified live.
        let started = match still_held(&lease).await {
            Ok(()) => store.set_enabled(*id, true, Some(auth.user_id())).await.map_err(admin_error),
            Err(e) => Err(e),
        };
        release(lease).await;
        started?;
    } else {
        store.set_enabled(*id, false, Some(auth.user_id())).await.map_err(admin_error)?;
    }
    audit(
        &state,
        &auth,
        &client,
        if request.enabled { CONNECTOR_FEED_RESUMED } else { CONNECTOR_FEED_PAUSED },
        *id,
        Some(feed.name),
        serde_json::json!({ "connector": feed.connector }),
    );
    Ok(Json(view(store.get_feed(*id).await.map_err(admin_error)?)))
}

#[utoipa::path(delete, path = "/api/connector-feeds/{id}", tag = "connector_feeds",
    params(("id" = String, Path, description = "Feed ID (cfeed_...)")),
    responses((status = 204, description = "Removed"), (status = 404, description = "Not found"), (status = 403, description = "Forbidden")),
    security(("api_key" = [])))]
pub async fn delete_connector_feed(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, DELETE)?;
    let store = store(&state);
    let feed = store.get_feed(*id).await.map_err(admin_error)?;
    ensure_identity_permission(&auth, &feed.connector)?;
    // G22: an identity feed's users leave the directory with it. Fence the
    // feed first (pause bumps the lease generation, waiting for any directory
    // write a run holds the feed row for), so no run in flight can write
    // after the tombstones; then tombstone (the provider row goes with the
    // feed, ON DELETE CASCADE), so a removed feed never keeps enriching
    // events with its users.
    if is_identity_connector(&feed.connector) {
        store.set_enabled(*id, false, Some(auth.user_id())).await.map_err(admin_error)?;
    }
    let retired_users = retire_identity_feed_users(&state, *id, &feed.connector).await?;
    store.delete_feed(*id).await.map_err(admin_error)?;
    audit(
        &state,
        &auth,
        &client,
        CONNECTOR_FEED_DELETED,
        *id,
        Some(feed.name),
        serde_json::json!({ "connector": feed.connector, "identity_users_retired": retired_users }),
    );
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/api/connector-feeds/{id}/reset", tag = "connector_feeds",
    params(("id" = String, Path, description = "Feed ID (cfeed_...)")), request_body = ResetConnectorFeedStream,
    responses((status = 200, description = "Stream window reset", body = ConnectorFeedResetResult), (status = 400, description = "Unknown or non-window stream"),
        (status = 404, description = "Not found"), (status = 403, description = "Forbidden")),
    security(("api_key" = [])))]
pub async fn reset_connector_feed_stream(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<ResetConnectorFeedStream>,
) -> Result<Json<ConnectorFeedResetResult>, ApiError> {
    ensure_permission(&auth, EDIT)?;
    let store = store(&state);
    let feed = store.get_feed(*id).await.map_err(admin_error)?;
    ensure_identity_permission(&auth, &feed.connector)?;
    let outcome = store.reset_stream(*id, request.stream.trim()).await.map_err(admin_error)?;
    audit(
        &state,
        &auth,
        &client,
        CONNECTOR_FEED_CHECKPOINT_RESET,
        *id,
        None,
        serde_json::json!({
            "stream": outcome.stream,
            "prior_checkpoint": outcome.prior_checkpoint,
            "prior_kind": outcome.prior_kind,
            "anchor": outcome.anchor,
            "full_resync": outcome.full_resync,
        }),
    );
    Ok(Json(ConnectorFeedResetResult {
        stream: outcome.stream,
        prior_checkpoint: outcome.prior_checkpoint,
        prior_kind: outcome.prior_kind.to_string(),
        anchor: outcome.anchor,
        next_run_at: outcome.next_run_at,
        full_resync: outcome.full_resync,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorFeedAdoptResult {
    /// Whether the feed moved to this build's bundled spec (false: already on it).
    pub adopted: bool,
    pub previous_spec_sha256: Option<String>,
    pub spec_sha256: Option<String>,
    /// Streams whose checkpoints were reset (the next run starts fresh).
    pub checkpoints_reset: u64,
}

/// NAN-4931: adopt this build's bundled spec for a feed pinned to an older
/// one. Explicit, never automatic: the feed must still fit the new spec, its
/// lease generation is bumped and its checkpoints are reset (an identity
/// stream keeps its shrink-guard baseline, so its next full run is guarded).
#[utoipa::path(post, path = "/api/connector-feeds/{id}/adopt-spec", tag = "connector_feeds",
    params(("id" = String, Path, description = "Feed ID (cfeed_...)")),
    request_body(content = Option<AdoptConnectorFeedSpec>, description = "Optional: set_up_log_sources for lanes the updated spec adds"),
    responses((status = 200, description = "Feed adopted the current connector spec", body = ConnectorFeedAdoptResult),
        (status = 400, description = "The feed no longer fits the bundled spec; recreate it. Or (NAN-5903) an enabled feed would emit into a lane with no log source and set_up_log_sources was not sent"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Requires log_sources:edit + log_sources:deploy (+ enrichments:configure for an identity feed)")),
    security(("api_key" = [])))]
pub async fn adopt_connector_feed_spec(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    body: Option<Json<AdoptConnectorFeedSpec>>,
) -> Result<Json<ConnectorFeedAdoptResult>, ApiError> {
    ensure_permission(&auth, EDIT)?;
    ensure_permission(&auth, DEPLOY)?;
    let request = body.map(|Json(b)| b).unwrap_or_default();
    let store = store(&state);
    let feed = store.get_feed(*id).await.map_err(admin_error)?;
    ensure_identity_permission(&auth, &feed.connector)?;
    // NAN-5903: an updated spec may emit into lanes the current one does not
    // (a new stream). An enabled feed must not start dropping them.
    let mut lease = None;
    if feed.enabled {
        let spec = first_party::get(&feed.connector).map_err(admin_error)?;
        let bundled = first_party::plan(spec.slug).map_err(admin_error)?;
        if let Ok(lanes) = admin::lanes(&bundled, &feed.config) {
            lease = ensure_lanes_served(&state, &auth, &client, spec, &lanes, &feed.name, request.set_up_log_sources)
                .await?
                .1;
        }
    }
    // Adopted under the lease, after the new lanes are verified live.
    let adopted = match still_held(&lease).await {
        Ok(()) => store.adopt_bundled_spec(*id, Some(auth.user_id())).await.map_err(admin_error),
        Err(e) => Err(e),
    };
    release(lease).await;
    let outcome = adopted?;
    let Some(outcome) = outcome else {
        return Ok(Json(ConnectorFeedAdoptResult { adopted: false, previous_spec_sha256: None, spec_sha256: None, checkpoints_reset: 0 }));
    };
    audit(
        &state,
        &auth,
        &client,
        CONNECTOR_FEED_SPEC_ADOPTED,
        *id,
        Some(feed.name),
        serde_json::json!({
            "connector": feed.connector,
            "previous_spec_sha256": outcome.previous_sha256,
            "spec_sha256": outcome.spec_sha256,
            "checkpoints_reset": outcome.checkpoints_reset,
        }),
    );
    Ok(Json(ConnectorFeedAdoptResult {
        adopted: true,
        previous_spec_sha256: Some(outcome.previous_sha256),
        spec_sha256: Some(outcome.spec_sha256),
        checkpoints_reset: outcome.checkpoints_reset,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_connector_specs,
        list_connector_feeds,
        get_connector_feed,
        plan_connector_feed,
        create_connector_feed,
        set_connector_feed_enabled,
        delete_connector_feed,
        reset_connector_feed_stream,
        adopt_connector_feed_spec
    ),
    components(schemas(
        ConnectorSpecInfo,
        ConnectorFieldInfo,
        ConnectorFieldChoice,
        CreateConnectorFeed,
        PlanConnectorFeed,
        ConnectorFeedSetupPlan,
        LaneSourceStep,
        nanosiem_core::log_sources::feed_lane_setup::LaneSourceAction,
        SetConnectorFeedEnabled,
        AdoptConnectorFeedSpec,
        ResetConnectorFeedStream,
        ConnectorFeedView,
        ConnectorFeedRunView,
        ConnectorFeedCheckpointView,
        ConnectorFeedDetail,
        ConnectorFeedCreated,
        ConnectorFeedResetResult,
        ConnectorFeedAdoptResult
    ))
)]
pub struct ConnectorFeedsApiDoc;

#[cfg(test)]
#[path = "connector_feeds_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "connector_feeds_specs_authz_tests.rs"]
mod specs_authz_tests;
