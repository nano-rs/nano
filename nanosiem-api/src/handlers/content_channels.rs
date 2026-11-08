// SPDX-License-Identifier: AGPL-3.0-or-later

//! nano content channels (NAN-4955): every product content pull comes
//! from the app as a signed bundle, never from GitHub.
//!
//! | Method | Path                                   | Permission        |
//! |--------|----------------------------------------|-------------------|
//! | GET    | `/api/content/channels`                | `settings:view`   |
//! | POST   | `/api/content/channels/check`          | `settings:system` |
//! | POST   | `/api/content/channels/import`         | `settings:system` |
//! | PATCH  | `/api/content/channels/{channel}`      | `settings:system` |
//!
//! The jobs leader checks on a schedule (`content_bundle::consumer`); these
//! endpoints report what is installed per channel, run a check now, import a
//! `.nancontent` file (air-gap), and opt a channel out of online updates.
//! A refused or failed check never removes the installed snapshot.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, CONTENT_CHANNELS_CHECKED, CONTENT_CHANNEL_IMPORTED,
    CONTENT_CHANNEL_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::content_bundle::channels::{self, Channel, Kind};
use nanosiem_core::content_bundle::consumer::{
    repo_url_pattern, ChannelError, ChannelOutcome, ChannelsStatus, ContentApplier, ContentConfig,
    ContentConsumer, RepositoryApplier,
};
use nanosiem_core::content_bundle::contract::{VerifiedContent, MAX_CONTAINER_BYTES, MAX_IMPORT_HTTP_BYTES};
use nanosiem_core::content_bundle::store::ContentStore;
use serde::{Deserialize, Serialize};
use futures::StreamExt as _;
use tokio::io::AsyncWriteExt as _;
use utoipa::ToSchema;

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};
use super::AuditExt;

/// Body bound of the import route (container bound + slack).
pub const CONTENT_IMPORT_BODY_LIMIT: usize = MAX_IMPORT_HTTP_BYTES as usize;

const PER_PRINCIPAL_IMPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
static LAST_IMPORT: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(Default::default);

fn rate_limit_import(auth: &AuthContext) -> Result<(), ApiError> {
    let principal = match auth.api_key_id {
        Some(key) => format!("key:{key}"),
        None => format!("user:{}", auth.user_id()),
    };
    let now = std::time::Instant::now();
    let mut last = LAST_IMPORT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    last.retain(|_, at| now.duration_since(*at) < PER_PRINCIPAL_IMPORT_INTERVAL);
    if last.contains_key(&principal) {
        return Err(ApiError::TooManyRequests(format!(
            "Wait {}s between content import requests",
            PER_PRINCIPAL_IMPORT_INTERVAL.as_secs()
        )));
    }
    last.insert(principal, now);
    Ok(())
}

struct RemoveOnDrop(std::path::PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Applier used by the API and jobs: marks repository rows following a
/// first-party channel due, imports the MITRE catalog directly from its
/// snapshot, and sends extension channels to their registered applier.
pub struct AppContentApplier {
    state: AppState,
    rows: RepositoryApplier,
}

impl AppContentApplier {
    pub fn new(state: AppState) -> Self {
        let rows = RepositoryApplier::new(state.pool.clone());
        Self { state, rows }
    }

    async fn due_ids(&self, table: &str, channel: &Channel) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
        let Some((_, name)) = channel.repo.split_once('/') else { return Ok(Vec::new()) };
        sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE enabled AND last_synced_at IS NULL AND btrim(url) ~* $1 \
             AND COALESCE(NULLIF(btrim(branch), ''), 'main') = $2"
        ))
        .bind(repo_url_pattern(name))
        .bind(channel.branch)
        .fetch_all(&self.state.pool)
        .await
    }

    /// Sync the rows following `channel` now, in the background.
    async fn sync_now(&self, channel: &'static Channel) -> Result<usize, String> {
        let table = match channel.kind {
            Kind::Parsers => "parser_repositories",
            Kind::Rules => "rule_repositories",
            Kind::Playbooks => "playbook_repositories",
            Kind::MarketplaceCatalog => "enrichment_marketplace_repos",
            Kind::ModelCatalog | Kind::MitreCatalog | Kind::Extension => return Ok(0),
        };
        let ids = self.due_ids(table, channel).await.map_err(|e| e.to_string())?;
        let n = ids.len();
        let state = self.state.clone();
        tokio::spawn(async move {
            for id in ids {
                let result = match channel.kind {
                    Kind::Parsers => nanosiem_core::parser_repository::ParserRepositoryService::new(state.pool.clone())
                        .sync_repository(id)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    Kind::Rules => nanosiem_core::rule_repository::RuleRepositoryService::with_dual_pool(&state.dual_pool)
                        .sync_repository(id)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    Kind::Playbooks => nanosiem_core::playbook_repository::PlaybookRepositoryService::new(state.pool.clone())
                        .sync_repository(id)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    Kind::MarketplaceCatalog => nanosiem_core::marketplace::MarketplaceSyncService::new(state.pool.clone())
                        .sync_repository(id)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    Kind::ModelCatalog | Kind::MitreCatalog | Kind::Extension => Ok(()),
                };
                match result {
                    Ok(()) => tracing::info!(channel = channel.id, repository = %id, "repository synced from content channel"),
                    Err(error) => tracing::warn!(channel = channel.id, repository = %id, %error, "repository sync from content channel failed"),
                }
            }
        });
        Ok(n)
    }

}

#[async_trait]
impl ContentApplier for AppContentApplier {
    async fn apply(&self, channel: &'static Channel, verified: &VerifiedContent, tree_changed: bool) -> Result<String, String> {
        if channel.kind == Kind::Extension {
            return match nanosiem_core::content_bundle::consumer::extension_applier() {
                Some(applier) => applier.apply(channel, verified, tree_changed).await,
                None => Err(format!("no applier registered for channel {}", channel.id)),
            };
        }
        if channel.kind == Kind::MitreCatalog {
            if !tree_changed {
                return Ok("tree unchanged".into());
            }
            let sync = nanosiem_core::mitre::MitreSync::new(
                nanosiem_core::mitre::MitreRepository::new(self.state.pool.clone()),
            );
            return match sync.sync().await {
                Ok(nanosiem_core::mitre::MitreSyncOutcome::Synced(result)) => Ok(format!(
                        "MITRE {} applied ({} tactics, {} techniques)",
                        result.release, result.tactic_count, result.technique_count
                    )),
                Ok(nanosiem_core::mitre::MitreSyncOutcome::AlreadyCurrent) => {
                    Ok("MITRE catalog already current".into())
                }
                Ok(nanosiem_core::mitre::MitreSyncOutcome::AlreadyRunning) => Err(
                    "MITRE catalog apply is already running; retrying on the next channel check"
                        .into(),
                ),
                Ok(nanosiem_core::mitre::MitreSyncOutcome::RetryBackoff) => Err(
                    "MITRE catalog apply is in retry backoff; retrying on the next channel check"
                        .into(),
                ),
                Err(error) => Err(error.to_string()),
            };
        }
        // NAN-4955: an air-gapped install never ran the first-party catalog
        // reconcile (it lives in the egress schedulers, which do not start
        // there). Now that those rows read installed snapshots instead of
        // GitHub, register them when their channel installs (idempotent; the
        // operator's opt-outs are kept by the reconcile itself).
        if tree_changed && matches!(channel.kind, Kind::Parsers | Kind::Rules) {
            crate::state::schedulers::reconcile_first_party_catalogs(&self.state).await;
        }
        let marked = self.rows.apply(channel, verified, tree_changed).await?;
        if !tree_changed {
            return Ok(marked);
        }
        let started = self.sync_now(channel).await?;
        Ok(format!("{marked}; {started} sync(s) started"))
    }
}

/// The consumer, built from the app state and the environment.
pub(crate) fn consumer(state: &AppState) -> ContentConsumer {
    ContentConsumer::new(
        ContentStore::new(state.pool.clone()),
        ContentConfig::from_env(
            !state.config.egress_jobs_enabled(),
            state.config.schema_id,
            cfg!(feature = "enterprise"),
        ),
        Arc::new(AppContentApplier::new(state.clone())),
    )
}

fn channel_error(error: ChannelError) -> ApiError {
    match error {
        ChannelError::Refused(_) | ChannelError::Disabled => ApiError::BadRequest(error.to_string()),
        ChannelError::Busy => ApiError::Conflict(error.to_string()),
        ChannelError::Fetch(_) => ApiError::ServiceUnavailable(error.to_string()),
        ChannelError::ApplyFailed(_) => ApiError::InternalError(error.to_string()),
        ChannelError::Install(_) => {
            tracing::warn!(%error, "content channel install failed");
            ApiError::InternalError("Content bundle install failed; the installed snapshot is kept".to_string())
        }
    }
}

fn audit(state: &AppState, auth: &AuthContext, client: &ClientContext, action: &str, id: Option<String>, success: bool, details: serde_json::Value) {
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("content_channel", None, id)
            .client_context(client)
            .success(success)
            .details(details)
            .build(),
    );
}

/// Accepted check.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentCheckAccepted {
    /// The check runs in the background; poll `GET /api/content/channels`.
    pub accepted: bool,
}

/// Result of an import.
#[derive(Debug, Serialize, ToSchema)]
pub struct ContentImportResponse {
    pub result: ChannelOutcome,
    pub status: ChannelsStatus,
}

/// Opt a channel out of (or back into) online updates.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateContentChannel {
    pub enabled: bool,
}

/// Installed nano content channels
#[utoipa::path(
    get,
    path = "/api/content/channels",
    tag = "content",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Every subscribed channel: installed commit, signer, freshness and the latest check", body = ChannelsStatus),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn get_content_channels(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ChannelsStatus>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_VIEW)?;
    let status = consumer(&state)
        .status()
        .await
        .map_err(|e| ApiError::InternalError(format!("content channel status: {e}")))?;
    Ok(Json(status))
}

/// Check every content channel now
///
/// Fetches each channel's signed descriptor from app.nano.rs (or the
/// configured mirror) and installs newer bundles. Runs in the background.
#[utoipa::path(
    post,
    path = "/api/content/channels/check",
    tag = "content",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 202, description = "Check started", body = ContentCheckAccepted),
        (status = 400, description = "Online updates are disabled (air-gap): import a bundle file"),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 409, description = "Another check or import is in progress"),
    )
)]
pub async fn check_content_channels(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<(StatusCode, Json<ContentCheckAccepted>), ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    let consumer = Arc::new(consumer(&state));
    if !consumer.config().auto_update {
        return Err(channel_error(ChannelError::Disabled));
    }
    let lease = consumer.lease().await.map_err(channel_error)?;
    consumer
        .mark_checking()
        .await
        .map_err(|e| ApiError::InternalError(format!("content channel status: {e}")))?;
    let audit_state = state.clone();
    tokio::spawn(async move {
        let results = consumer.check_all_with(lease).await;
        let failed = results.iter().filter(|(_, r)| r.is_err()).count();
        let details = serde_json::json!({
            "results": results.iter().map(|(c, r)| match r {
                Ok(o) => serde_json::json!({"channel": c, "outcome": o}),
                Err(e) => serde_json::json!({"channel": c, "error": e}),
            }).collect::<Vec<_>>(),
        });
        audit(&audit_state, &auth, &client, CONTENT_CHANNELS_CHECKED, None, failed == 0, details);
    });
    Ok((StatusCode::ACCEPTED, Json(ContentCheckAccepted { accepted: true })))
}

/// Import a content bundle file (air-gap)
///
/// The request body is the signed `.nancontent` container exactly as the
/// distribution route's `bundle_url` serves it. It is verified (signature
/// against the compiled-in content key ring, payload digest and length, safe
/// unpack, tree digest, channel registry, rollback) before anything is
/// written; a refused file leaves the installed snapshot in place.
#[utoipa::path(
    post,
    path = "/api/content/channels/import",
    tag = "content",
    security(("bearer_auth" = []), ("api_key" = [])),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "Signed .nancontent bundle"),
    responses(
        (status = 200, description = "Bundle verified and installed, or already current", body = ContentImportResponse),
        (status = 400, description = "Refused: signature, untrusted signer, digest, unsafe tree, unknown channel or rollback"),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 409, description = "Another check or import is in progress"),
        (status = 413, description = "Larger than the container bound"),
        (status = 429, description = "Too many requests from this user or API key"),
    )
)]
pub async fn import_content_channel(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    body: Body,
) -> Result<Json<ContentImportResponse>, ApiError> {
    let mut received = 0u64;
    let result = import_content_channel_inner(&state, &auth, body, &mut received).await;
    let (success, details) = match &result {
        Ok(response) => (true, serde_json::json!({"outcome": &response.0.result, "source": "offline", "bytes": received})),
        Err(error) => (false, serde_json::json!({
            "error": error.to_string(),
            "code": error.code(),
            "status": error.status_code().as_u16(),
            "source": "offline",
            "bytes": received,
        })),
    };
    audit(&state, &auth, &client, CONTENT_CHANNEL_IMPORTED, None, success, details);
    result
}

async fn import_content_channel_inner(
    state: &AppState,
    auth: &AuthContext,
    body: Body,
    received: &mut u64,
) -> Result<Json<ContentImportResponse>, ApiError> {
    // Permission, principal throttle and deployment-wide lease are all
    // decided before the first body frame is polled.
    ensure_permission(auth, permissions::SETTINGS_SYSTEM)?;
    rate_limit_import(auth)?;
    let consumer = consumer(state);
    let lease = consumer.lease().await.map_err(channel_error)?;
    let (upload, file) = consumer.create_upload().map_err(channel_error)?;
    let _cleanup = RemoveOnDrop(upload.clone());
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = body.into_data_stream();
    while let Some(frame) = stream.next().await {
        let chunk = frame.map_err(|error| ApiError::BadRequest(format!("upload body: {error}")))?;
        *received = received
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| ApiError::PayloadTooLarge("Content bundle size overflow".into()))?;
        if *received > MAX_CONTAINER_BYTES {
            return Err(ApiError::PayloadTooLarge("Content bundle exceeds the container bound".into()));
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| ApiError::InternalError(format!("upload staging: {error}")))?;
    }
    file.sync_all()
        .await
        .map_err(|error| ApiError::InternalError(format!("upload staging: {error}")))?;
    drop(file);
    let result = consumer.import_staged(lease, &upload).await;
    let result = result.map_err(channel_error)?;
    let status = consumer
        .status()
        .await
        .map_err(|e| ApiError::InternalError(format!("content channel status: {e}")))?;
    Ok(Json(ContentImportResponse { result, status }))
}

/// Opt a content channel out of (or back into) online updates
#[utoipa::path(
    patch,
    path = "/api/content/channels/{channel}",
    tag = "content",
    params(("channel" = String, Path, description = "Channel id, e.g. parsers.main")),
    request_body = UpdateContentChannel,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Updated", body = ChannelsStatus),
        (status = 400, description = "Unknown channel"),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn update_content_channel(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(channel): Path<String>,
    Json(req): Json<UpdateContentChannel>,
) -> Result<Json<ChannelsStatus>, ApiError> {
    ensure_permission(&auth, permissions::SETTINGS_SYSTEM)?;
    if channels::by_id(&channel).is_none() {
        return Err(ApiError::BadRequest(format!("unknown content channel {channel}")));
    }
    let consumer = consumer(&state);
    consumer.set_enabled(&channel, req.enabled).await.map_err(channel_error)?;
    audit(&state, &auth, &client, CONTENT_CHANNEL_UPDATED, Some(channel.clone()), true, serde_json::json!({"enabled": req.enabled}));
    let status = consumer
        .status()
        .await
        .map_err(|e| ApiError::InternalError(format!("content channel status: {e}")))?;
    Ok(Json(status))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_content_channels, check_content_channels, import_content_channel, update_content_channel),
    components(schemas(
        ChannelsStatus,
        nanosiem_core::content_bundle::consumer::ChannelStatus,
        ChannelOutcome,
        ContentCheckAccepted,
        ContentImportResponse,
        UpdateContentChannel,
        nanosiem_core::content_bundle::channels::Route,
        nanosiem_core::content_bundle::channels::Kind,
    )),
    tags((name = "content", description = "nano content channels: signed first-party content from app.nano.rs (NAN-4955)"))
)]
pub struct ContentChannelsApiDoc;
