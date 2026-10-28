// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-hosted platform feed freshness (NAN-4759).
//!
//! A sovereign or open-core lean install stamps IPinfo Lite geo/ASN, ThreatFox
//! and Tor at ingest from one signed feed bundle that `lean-platform-feeds`
//! installs. This endpoint reports what is installed and how old each feed is,
//! from the bundle dir mounted read-only (`PLATFORM_BUNDLE_DIR`). It
//! never opens the bundle and never changes stamped data: a feed past its
//! `hard_expiry` stops stamping new events, already stamped values stay.

use axum::{Extension, Json};
use nanosiem_core::auth::permissions;
use nanosiem_core::platform_enrichment::self_hosted::{self, FeedsStatus};

use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};

/// Env var naming the read-only bundle dir (compose sets it in the lean profile).
pub const PLATFORM_BUNDLE_DIR_ENV: &str = "PLATFORM_BUNDLE_DIR";

/// Status of the bundle dir at `dir` (None: this deployment keeps no local bundle).
pub(crate) fn platform_feeds_status(dir: Option<std::path::PathBuf>, now: chrono::DateTime<chrono::Utc>) -> Result<FeedsStatus, ApiError> {
    let Some(dir) = dir.filter(|d| d.is_absolute() && d.is_dir()) else {
        return Ok(FeedsStatus::unavailable());
    };
    self_hosted::status(&dir, now).map_err(|error| {
        tracing::warn!(error = %format!("{error:#}"), "platform feed bundle receipt unreadable");
        ApiError::ServiceUnavailable("Platform feed status is unavailable".to_string())
    })
}

/// Installed platform feeds and their freshness (self-hosted)
#[utoipa::path(
    get,
    path = "/api/enrichment/platform-feeds",
    tag = "enrichment",
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Installed feeds; `available` is false where no local bundle is kept", body = FeedsStatus),
        (status = 403, description = "Forbidden - missing permission"),
        (status = 503, description = "The bundle receipt is unreadable"),
    )
)]
pub async fn get_platform_feeds(Extension(auth): Extension<AuthContext>) -> Result<Json<FeedsStatus>, ApiError> {
    ensure_permission(&auth, permissions::ENRICHMENTS_VIEW)?;
    let dir = std::env::var_os(PLATFORM_BUNDLE_DIR_ENV).map(std::path::PathBuf::from);
    let status = tokio::task::spawn_blocking(move || platform_feeds_status(dir, chrono::Utc::now()))
        .await
        .map_err(|_| ApiError::InternalError("platform feed status task failed".to_string()))??;
    Ok(Json(status))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_dir_is_unavailable_and_an_empty_dir_is_available_but_not_installed() {
        let now = chrono::Utc::now();
        assert!(!platform_feeds_status(None, now).unwrap().available);
        assert!(!platform_feeds_status(Some("relative".into()), now).unwrap().available);
        let dir = tempfile::tempdir().unwrap();
        assert!(!platform_feeds_status(Some(dir.path().join("missing")), now).unwrap().available);
        let status = platform_feeds_status(Some(dir.path().to_path_buf()), now).unwrap();
        assert!(status.available && !status.installed && status.feeds.is_empty());
        std::fs::write(dir.path().join("current.json"), b"{not json").unwrap();
        assert!(platform_feeds_status(Some(dir.path().to_path_buf()), now).is_err());
    }
}
