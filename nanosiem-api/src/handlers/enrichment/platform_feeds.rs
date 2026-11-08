// SPDX-License-Identifier: AGPL-3.0-or-later

//! nano's signed platform feed bundle (NAN-4948; status contract from main's
//! NAN-4759).
//!
//! IPinfo Lite geo/ASN, ThreatFox and the Tor exit list are loaded from ONE
//! signed bundle nano publishes, into the ClickHouse tables the ingest-time
//! dictionaries read. The jobs leader checks for a new bundle on a schedule
//! (`platform_enrichment::consumer`); these endpoints report what is installed,
//! run a check now, and import a bundle file for air-gapped installs.
//!
//! | Method | Path                                     | Permission              |
//! |--------|------------------------------------------|-------------------------|
//! | GET    | `/api/enrichment/platform-feeds`         | `enrichments:view`      |
//! | POST   | `/api/enrichment/platform-feeds/check`   | `enrichments:configure` |
//! | POST   | `/api/enrichment/platform-feeds/import`  | `enrichments:configure` |
//!
//! The status body ([`FeedsStatus`]) keeps main's fields (`available`,
//! `installed`, `bundle_sha256`, `source`, `installed_at`, `stale_after_days`,
//! `feeds[]`, `notice`) so main's marketplace PlatformFeedsCard reads it
//! unchanged; the remaining fields are additive. A refused or failed check
//! never removes the installed bundle: it shows in `last_check_status` /
//! `last_error`.

use std::sync::Arc;

use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, ENRICHMENT_SYNCED};
use nanosiem_core::auth::permissions;
use nanosiem_core::platform_enrichment::consumer::{
    ConsumerConfig, ConsumerError, Outcome, PlatformFeedConsumer, MAX_CONTAINER_BYTES,
};
use nanosiem_core::platform_enrichment::loader::ClickHouseLoader;
use nanosiem_core::platform_enrichment::state::{FeedsStatus, StateRepository};
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use utoipa::ToSchema;

use super::AuditExt;
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Upload body bound of the import route: the container bound plus multipart
/// framing.
pub const PLATFORM_FEED_IMPORT_BODY_LIMIT: usize = MAX_CONTAINER_BYTES as usize + 1024 * 1024;

/// The consumer, built from the app's pools and the environment.
pub(crate) fn consumer(state: &AppState) -> PlatformFeedConsumer {
    PlatformFeedConsumer::new(
        StateRepository::new(state.pool.clone()),
        ClickHouseLoader::new(
            state.dual_pool.clickhouse().clone(),
            state.dual_pool.clickhouse_admin().clone(),
        ),
        ConsumerConfig::from_env(!state.config.egress_jobs_enabled()),
    )
}

struct RemoveOnDrop(std::path::PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Result of a check or import.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlatformFeedInstallResponse {
    /// `installed` (with the sequence and rows loaded per feed) or `current`.
    pub result: Outcome,
    pub status: FeedsStatus,
}

/// Accepted check.
#[derive(Debug, Serialize, ToSchema)]
pub struct PlatformFeedCheckAccepted {
    /// The check runs in the background; poll the status endpoint
    /// (`last_check_status` is `checking` until it ends).
    pub accepted: bool,
}

/// Minimum spacing of check / import requests per principal (user or API
/// key). The install lease already allows one in flight deployment-wide; this
/// stops one caller from hammering the endpoints (NAN-4948 review P2).
const PER_PRINCIPAL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

static LAST_REQUEST: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(Default::default);

/// Per-principal limiter for the mutating platform feed endpoints.
fn rate_limit(auth: &AuthContext, endpoint: &str) -> Result<(), ApiError> {
    let principal = match auth.api_key_id {
        Some(key) => format!("{endpoint}:key:{key}"),
        None => format!("{endpoint}:user:{}", auth.user_id()),
    };
    let now = std::time::Instant::now();
    let mut last = LAST_REQUEST.lock().unwrap_or_else(|p| p.into_inner());
    last.retain(|_, at| now.duration_since(*at) < PER_PRINCIPAL_INTERVAL);
    if last.contains_key(&principal) {
        return Err(ApiError::TooManyRequests(format!(
            "Wait {}s between platform feed {endpoint} requests",
            PER_PRINCIPAL_INTERVAL.as_secs()
        )));
    }
    last.insert(principal, now);
    Ok(())
}

fn consumer_error(error: ConsumerError) -> ApiError {
    match error {
        ConsumerError::Refused(_) => ApiError::BadRequest(error.to_string()),
        ConsumerError::Busy => ApiError::Conflict(error.to_string()),
        ConsumerError::Disabled => ApiError::BadRequest(error.to_string()),
        ConsumerError::Fetch(_) => ApiError::ServiceUnavailable(error.to_string()),
        ConsumerError::Install(_) => {
            tracing::warn!(%error, "platform feed install failed");
            ApiError::InternalError("Feed bundle install failed; the installed bundle is kept".to_string())
        }
    }
}

/// Installed platform feeds and their freshness
#[utoipa::path(
    get,
    path = "/api/enrichment/platform-feeds",
    tag = "enrichment",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Installed feed bundle, per-feed revision, age, hard expiry and activity, and the latest check", body = FeedsStatus),
        (status = 403, description = "Forbidden - missing permission"),
    )
)]
pub async fn get_platform_feeds(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<FeedsStatus>, ApiError> {
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;
    let status = consumer(&state)
        .status()
        .await
        .map_err(|e| ApiError::InternalError(format!("platform feed status: {e}")))?;
    Ok(Json(status))
}

/// Check for a new platform feed bundle now
///
/// Fetches the signed descriptor from nano (the license-authenticated route
/// when this install holds a signed license artifact, else the open route),
/// and installs the bundle when it is newer. Runs in the background.
#[utoipa::path(
    post,
    path = "/api/enrichment/platform-feeds/check",
    tag = "enrichment",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 202, description = "Check started; poll GET /api/enrichment/platform-feeds", body = PlatformFeedCheckAccepted),
        (status = 400, description = "Online updates are disabled (air-gap): import a bundle file"),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 409, description = "Another check, import or reconcile is in progress"),
        (status = 429, description = "Too many requests from this user or API key"),
    )
)]
pub async fn check_platform_feeds(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
) -> Result<(StatusCode, Json<PlatformFeedCheckAccepted>), ApiError> {
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;
    let consumer = Arc::new(consumer(&state));
    if !consumer.config().auto_update {
        return Err(consumer_error(ConsumerError::Disabled));
    }
    rate_limit(&auth, "check")?;
    // Single flight: take the install lease BEFORE anything is fetched.
    let lease = consumer.lease().await.map_err(consumer_error)?;
    consumer
        .mark_checking()
        .await
        .map_err(|e| ApiError::InternalError(format!("platform feed status: {e}")))?;
    let audit_state = state.clone();
    let actor = (auth.user_id(), auth.api_key_id, auth.api_key_name.clone());
    tokio::spawn(async move {
        let result = consumer.check_online_with(lease).await;
        let (success, details) = match &result {
            Ok(outcome) => (true, serde_json::json!({"outcome": outcome})),
            Err(error) => (false, serde_json::json!({"error": error.to_string()})),
        };
        audit_state.emit_audit(
            AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_SYNCED)
                .actor(Some(actor.0), None)
                .api_key(actor.1, actor.2)
                .resource("enrichment", None, Some("platform_feeds".to_string()))
                .client_context(&client)
                .success(success)
                .details(details)
                .build(),
        );
    });
    Ok((StatusCode::ACCEPTED, Json(PlatformFeedCheckAccepted { accepted: true })))
}

/// Import a platform feed bundle file (air-gap)
///
/// Multipart form with one `file` field: the signed `.nanfeed` container,
/// exactly as `GET …/feeds/v1/open/current`'s `bundle_url` serves it. It is
/// verified (signature against the compiled-in key ring, payload digest and
/// length, format version, rollback, hard expiry) before anything is written;
/// a refused file leaves the installed bundle in place.
#[utoipa::path(
    post,
    path = "/api/enrichment/platform-feeds/import",
    tag = "enrichment",
    security(("bearer_auth" = []), ("api_key" = [])),
    request_body(
        content = inline(PlatformFeedInstallResponse),
        description = "Multipart form with a `file` field: the signed .nanfeed bundle",
        content_type = "multipart/form-data"
    ),
    responses(
        (status = 200, description = "Bundle verified and installed, or already current", body = PlatformFeedInstallResponse),
        (status = 400, description = "Refused: bad signature, untrusted signer, digest/length mismatch, unsupported format, rollback, or every feed expired"),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 409, description = "Another check, import or reconcile is in progress (nothing was uploaded)"),
        (status = 413, description = "Larger than the signed container bound"),
        (status = 429, description = "Too many requests from this user or API key"),
        (status = 500, description = "Load failed; the installed bundle is kept"),
    )
)]
pub async fn import_platform_feeds(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    mut multipart: Multipart,
) -> Result<Json<PlatformFeedInstallResponse>, ApiError> {
    ensure_permission(&auth, permissions::ENRICHMENTS_CONFIGURE)?;
    let consumer = consumer(&state);
    rate_limit(&auth, "import")?;
    // Single flight: take the install lease BEFORE accepting the body, so a
    // concurrent upload is refused instead of staged.
    let lease = consumer.lease().await.map_err(consumer_error)?;
    // Stream the upload into the private work dir (0700 dir, 0600 new file):
    // never buffer ~100 MB, never stage in a shared temp dir.
    let (upload, file) = consumer.create_upload().map_err(consumer_error)?;
    let _cleanup = RemoveOnDrop(upload.clone());
    let mut file = tokio::fs::File::from_std(file);
    let mut found = false;
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("multipart: {e}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        let mut written = 0u64;
        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|e| ApiError::BadRequest(format!("upload: {e}")))?
        {
            written += chunk.len() as u64;
            if written > MAX_CONTAINER_BYTES {
                return Err(ApiError::PayloadTooLarge(
                    "Feed bundle exceeds the container size bound".to_string(),
                ));
            }
            file.write_all(&chunk)
                .await
                .map_err(|e| ApiError::InternalError(format!("upload staging: {e}")))?;
        }
        file.sync_all()
            .await
            .map_err(|e| ApiError::InternalError(format!("upload staging: {e}")))?;
        found = true;
        break;
    }
    drop(file);
    if !found {
        return Err(ApiError::BadRequest("No `file` field in multipart body".to_string()));
    }
    let result = consumer.import_staged(lease, &upload).await;
    let (success, details) = match &result {
        Ok(outcome) => (true, serde_json::json!({"outcome": outcome, "source": "offline"})),
        Err(error) => (false, serde_json::json!({"error": error.to_string(), "source": "offline"})),
    };
    state.emit_audit(
        AuditEvent::builder(AuditSource::Enrichment, ENRICHMENT_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("enrichment", None, Some("platform_feeds".to_string()))
            .client_context(&client)
            .success(success)
            .details(details)
            .build(),
    );
    let outcome = result.map_err(consumer_error)?;
    let status = consumer
        .status()
        .await
        .map_err(|e| ApiError::InternalError(format!("platform feed status: {e}")))?;
    Ok(Json(PlatformFeedInstallResponse { result: outcome, status }))
}

// Schemas re-exported for `EnrichmentApiDoc`.
pub use nanosiem_core::platform_enrichment::consumer::Outcome as PlatformFeedOutcome;
pub use nanosiem_core::platform_enrichment::state::{
    FeedState as PlatformFeedState, FeedStatus as PlatformFeedStatus,
    FeedsStatus as PlatformFeedsStatus,
};
