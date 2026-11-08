// SPDX-License-Identifier: AGPL-3.0-or-later
//! Content channel consumer (NAN-4955): fetch → verify → accept → install →
//! apply, for the scheduled online check, "check now" and air-gap import.
//!
//! Built from the platform feed consumer's pieces (NAN-4948), not a copy of
//! them: the same HTTP seam ([`FeedHttp`]: https only, SSRF-validated and
//! DNS-pinned, no redirects, size caps), the same private work directory
//! rules ([`ensure_private_dir`]) and the same single-flight install lease
//! ([`InstallLease`]) on its own advisory lock.
//!
//! ## Online check, per subscribed channel
//!
//! 1. `GET <base>/<route>/<channel>/current` → `{descriptor, bundle_url,
//!    bundle_sha256}`. `<base>` is `https://api.nano.rs/api/content/v1` or an
//!    operator mirror (`CONTENT_CHANNELS_URL`). Open channels use the open
//!    route; enterprise channels use the license-authenticated route with
//!    the signed license artifact and are skipped without one.
//! 2. The descriptor is verified against the compiled-in content ring and must
//!    name the channel that was asked for. Identical to the installed one: done
//!    (`current`), no download.
//! 3. The container is downloaded into the private work dir, verified in full
//!    ([`contract::verify_bytes`]: signature, payload digest and length, safe
//!    unpack, tree digest), must be exactly the announced descriptor, and is
//!    accepted against the installed one (rollback, same-sequence
//!    substitution, expiry).
//! 4. One PostgreSQL transaction replaces the channel's files and state
//!    ([`ContentStore::install`]); then the [`ContentApplier`] hands it to the
//!    consumer of that kind (repository rows marked due and synced; the
//!    applier an extension registered for its own channels).
//!
//! Any failure keeps the last good snapshot and is recorded on the channel.
//! There is NO fallback to GitHub, ever.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;

use super::channels::{self, Channel, Route};
use super::contract::{self, ContentError, SignedContentDescriptor, VerifiedContent, MAX_CONTAINER_BYTES};
use super::store::{installed_from, ChannelRow, ContentStore};
use crate::leader::LeaderFence;
use crate::platform_enrichment::consumer::{ensure_private_dir, http_error, FeedHttp, InstallLease, ReqwestFeedHttp};
use crate::platform_enrichment::portable::KeyRing;
use crate::shutdown::ShutdownToken;

/// The app's content distribution base (same host as `/api/feeds/v1`).
pub const DEFAULT_BASE_URL: &str = "https://api.nano.rs/api/content/v1";
/// PostgreSQL advisory lock serializing content installs (`NSCONT`).
pub const INSTALL_LOCK_ID: i64 = 0x4e53_434f_4e54;
const PRODUCED_AT_SKEW: chrono::Duration = chrono::Duration::minutes(10);
const MAX_METADATA_BYTES: u64 = 128 * 1024;
const MAX_LICENSE_BYTES: u64 = 9216;
const DEFAULT_POLL_SECS: u64 = 3600;
const MIN_POLL_SECS: u64 = 300;
const RETRY_SECS: u64 = 300;
const FIRST_CHECK_SECS: u64 = 20;

pub const SOURCE_ONLINE: &str = "online";
pub const SOURCE_OFFLINE: &str = "offline";

/// Consumer configuration (`CONTENT_CHANNELS_*`).
#[derive(Clone)]
pub struct ContentConfig {
    pub base_url: String,
    /// `base_url` is an operator mirror (reported as route `mirror`).
    pub mirror: bool,
    pub license: Option<Vec<u8>>,
    pub work_dir: PathBuf,
    pub poll_interval: Duration,
    pub auto_update: bool,
    pub channels: Vec<&'static Channel>,
    /// Owned acceptance proof only (`nano_content_acceptance` builds): allow plain http and
    /// private addresses for the configured base and bundle URLs.
    pub insecure_http: bool,
}

impl std::fmt::Debug for ContentConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentConfig")
            .field("base_url", &self.base_url)
            .field("mirror", &self.mirror)
            .field("license", &self.license.as_ref().map(|_| "<set>"))
            .field("work_dir", &self.work_dir)
            .field("poll_interval", &self.poll_interval)
            .field("auto_update", &self.auto_update)
            .field("channels", &self.channels.iter().map(|c| c.id).collect::<Vec<_>>())
            .field("insecure_http", &self.insecure_http)
            .finish()
    }
}

impl ContentConfig {
    /// From the environment. `airgap` (AIRGAP_MODE) disables the online check.
    ///
    /// - `CONTENT_CHANNELS_AUTO_UPDATE` (default true)
    /// - `CONTENT_CHANNELS_POLL_SECS` (default 3600, min 300)
    /// - `CONTENT_CHANNELS_URL` (https mirror of `/api/content/v1`)
    /// - `CONTENT_CHANNELS_LICENSE_FILE`, else `PLATFORM_FEEDS_LICENSE_FILE`
    ///   (enterprise: signed license artifact for the enterprise route)
    /// - `CONTENT_CHANNELS_WORK_DIR` (default `$NANOSIEM_DATA_DIR/content-channels`)
    pub fn from_env(airgap: bool, profile: crate::schema::SchemaId, enterprise: bool) -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let auto_update = !airgap
            && var("CONTENT_CHANNELS_AUTO_UPDATE")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true);
        let poll = var("CONTENT_CHANNELS_POLL_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_POLL_SECS)
            .max(MIN_POLL_SECS);
        let mirror_url = var("CONTENT_CHANNELS_URL").map(|u| u.trim().trim_end_matches('/').to_string());
        let work_dir = var("CONTENT_CHANNELS_WORK_DIR").map(PathBuf::from).unwrap_or_else(|| {
            var("NANOSIEM_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("data"))
                .join("content-channels")
        });
        let work_dir = if work_dir.is_absolute() {
            work_dir
        } else {
            std::env::current_dir().map(|cwd| cwd.join(&work_dir)).unwrap_or(work_dir)
        };
        let license = read_license(var("CONTENT_CHANNELS_LICENSE_FILE").or_else(|| var("PLATFORM_FEEDS_LICENSE_FILE")));
        Self {
            base_url: mirror_url.clone().unwrap_or_else(|| DEFAULT_BASE_URL.to_string()),
            mirror: mirror_url.is_some(),
            license,
            work_dir,
            poll_interval: Duration::from_secs(poll),
            auto_update,
            channels: channels::subscribed(profile, enterprise),
            insecure_http: dev_insecure_http(),
        }
    }
}

#[cfg(nano_content_acceptance)]
fn dev_insecure_http() -> bool {
    let on = std::env::var("CONTENT_CHANNELS_DEV_INSECURE_HTTP").is_ok_and(|v| v.trim() == "1");
    if on {
        tracing::warn!("CONTENT_CHANNELS_DEV_INSECURE_HTTP=1: content channel fetches allow plain http (dev build only)");
    }
    on
}

#[cfg(not(nano_content_acceptance))]
fn dev_insecure_http() -> bool {
    if std::env::var("CONTENT_CHANNELS_DEV_INSECURE_HTTP").is_ok() {
        tracing::warn!("CONTENT_CHANNELS_DEV_INSECURE_HTTP is ignored by release builds");
    }
    false
}

#[cfg(feature = "enterprise")]
fn read_license(path: Option<String>) -> Option<Vec<u8>> {
    let path = PathBuf::from(path?);
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > MAX_LICENSE_BYTES {
        tracing::warn!(path = %path.display(), "content channel license file must be a regular file of at most 9 KiB");
        return None;
    }
    std::fs::read(&path).ok()
}

#[cfg(not(feature = "enterprise"))]
fn read_license(path: Option<String>) -> Option<Vec<u8>> {
    let _ = (path, MAX_LICENSE_BYTES);
    None
}

/// Result of a channel check or import that did not fail.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ChannelOutcome {
    Installed { sequence: u64, commit: String, files: u64, tree_changed: bool },
    Current { sequence: u64 },
    /// The installed snapshot was already current, but its earlier apply had
    /// not completed; the apply ran again now and succeeded.
    Reapplied { sequence: u64 },
    /// Nothing published on the route yet (HTTP 404).
    Unpublished,
    /// Opted out by the operator, or an enterprise channel without a license.
    Skipped { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("content bundle refused: {0}")]
    Refused(String),
    #[error("another content channel install is in progress")]
    Busy,
    #[error("online content updates are disabled on this deployment (air-gap); import a bundle file instead")]
    Disabled,
    #[error("content bundle fetch failed: {0}")]
    Fetch(String),
    #[error("content bundle install failed: {0}")]
    Install(String),
    /// Partial failure: the verified snapshot is installed, but handing it to
    /// its consumer (repository rows, an extension's applier) failed. Retried by the
    /// next check or import of the same bundle.
    #[error("content bundle installed, apply failed: {0}")]
    ApplyFailed(String),
}

impl From<ContentError> for ChannelError {
    fn from(e: ContentError) -> Self {
        ChannelError::Refused(e.to_string())
    }
}

impl From<crate::platform_enrichment::consumer::ConsumerError> for ChannelError {
    fn from(e: crate::platform_enrichment::consumer::ConsumerError) -> Self {
        use crate::platform_enrichment::consumer::ConsumerError as E;
        match e {
            E::Busy => ChannelError::Busy,
            E::Refused(m) => ChannelError::Refused(m),
            E::Disabled => ChannelError::Disabled,
            E::Fetch(m) => ChannelError::Fetch(m),
            E::Install(m) => ChannelError::Install(m),
        }
    }
}

impl ChannelError {
    fn check_status(&self) -> &'static str {
        match self {
            ChannelError::Refused(_) => "refused",
            _ => "failed",
        }
    }
}

fn db(e: sqlx::Error) -> ChannelError {
    ChannelError::Install(format!("database: {e}"))
}

/// Hands an installed snapshot to whatever consumes that channel kind.
#[async_trait]
pub trait ContentApplier: Send + Sync {
    /// `tree_changed` is false for a re-sealed descriptor over the same tree.
    /// Returns a short human summary, or an error recorded as `apply_error`
    /// (the snapshot itself stays installed).
    async fn apply(&self, channel: &'static Channel, verified: &VerifiedContent, tree_changed: bool) -> Result<String, String>;
}

static EXTENSION_APPLIER: std::sync::OnceLock<Arc<dyn ContentApplier>> = std::sync::OnceLock::new();

/// Register the applier for [`channels::Kind::Extension`] channels (once per
/// process; an open build registers none, and has no such channels).
pub fn register_extension_applier(applier: Arc<dyn ContentApplier>) {
    let _ = EXTENSION_APPLIER.set(applier);
}

/// The registered extension applier, if any.
pub fn extension_applier() -> Option<Arc<dyn ContentApplier>> {
    EXTENSION_APPLIER.get().cloned()
}

/// Open applier: marks first-party repository rows that follow this channel
/// due, so their existing sync (which now reads the snapshot) runs next.
pub struct RepositoryApplier {
    pool: sqlx::PgPool,
}

impl RepositoryApplier {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Mark every enabled row following `channel` due; returns the count.
    pub async fn mark_due(&self, channel: &Channel) -> Result<u64, sqlx::Error> {
        let Some((_, name)) = channel.repo.split_once('/') else { return Ok(0) };
        let table = match channel.kind {
            channels::Kind::Parsers => "parser_repositories",
            channels::Kind::Rules => "rule_repositories",
            channels::Kind::Playbooks => "playbook_repositories",
            channels::Kind::MarketplaceCatalog => "enrichment_marketplace_repos",
            channels::Kind::ModelCatalog
            | channels::Kind::MitreCatalog
            | channels::Kind::Extension => return Ok(0),
        };
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&self.pool)
            .await?;
        if !exists {
            return Ok(0);
        }
        let done = sqlx::query(&format!(
            "UPDATE {table} SET last_synced_at = NULL WHERE enabled \
             AND btrim(url) ~* $1 AND COALESCE(NULLIF(btrim(branch), ''), 'main') = $2"
        ))
        .bind(repo_url_pattern(name))
        .bind(channel.branch)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }
}

/// Case-insensitive pattern of a first-party repository URL (`nano-rs` or the
/// pre-rename `nanos-sh`; optional scheme, `www.`, `.git`, trailing slash).
pub fn repo_url_pattern(name: &str) -> String {
    let escaped: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_string() } else { format!("\\{c}") })
        .collect();
    format!("^(https?://)?(www[.])?github[.]com/(nano-rs|nanos-sh)/{escaped}([.]git)?/?$")
}

#[async_trait]
impl ContentApplier for RepositoryApplier {
    async fn apply(&self, channel: &'static Channel, _verified: &VerifiedContent, tree_changed: bool) -> Result<String, String> {
        if !tree_changed {
            return Ok("tree unchanged".into());
        }
        let n = self.mark_due(channel).await.map_err(|e| e.to_string())?;
        Ok(format!("{n} repository row(s) marked for sync"))
    }
}

/// The parsed, signature-verified metadata response.
#[derive(Debug, Clone)]
pub struct CurrentRelease {
    pub signed: SignedContentDescriptor,
    pub bundle_url: String,
}

/// Parse a metadata body: the descriptor verifies against `ring` and names
/// `channel`, `bundle_sha256` equals its payload digest, and `bundle_url` is a
/// plain https URL (http too only when `insecure_http`).
pub fn parse_current(body: &[u8], ring: &KeyRing, channel: &str, insecure_http: bool) -> Result<CurrentRelease, ChannelError> {
    let response: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| ChannelError::Refused("content metadata is not JSON".into()))?;
    let descriptor = serde_json::to_vec(&response["descriptor"])
        .map_err(|_| ChannelError::Refused("content metadata descriptor".into()))?;
    let signed = SignedContentDescriptor::from_json(&descriptor, ring)?;
    if signed.descriptor.channel != channel {
        return Err(ChannelError::Refused(format!(
            "asked for channel {channel}, the signed descriptor is for {}",
            signed.descriptor.channel
        )));
    }
    if response["bundle_sha256"].as_str() != Some(signed.descriptor.payload.sha256.as_str()) {
        return Err(ChannelError::Refused("content metadata digest differs from its signed descriptor".into()));
    }
    let url = response["bundle_url"]
        .as_str()
        .ok_or_else(|| ChannelError::Refused("content metadata download URL missing".into()))?;
    let parsed = url::Url::parse(url).map_err(|_| ChannelError::Refused("content download URL is not a URL".into()))?;
    let scheme_ok = parsed.scheme() == "https" || (insecure_http && parsed.scheme() == "http");
    if !scheme_ok
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ChannelError::Refused("content download URL must be plain https".into()));
    }
    Ok(CurrentRelease { signed, bundle_url: url.to_string() })
}

/// Dev-only HTTP (no SSRF pinning, http allowed); never used by release
/// builds (see [`ContentConfig::insecure_http`]).
struct DevHttp;

#[async_trait]
impl FeedHttp for DevHttp {
    async fn metadata(
        &self,
        url: &str,
        license: Option<&[u8]>,
    ) -> Result<crate::platform_enrichment::consumer::MetadataResponse, String> {
        use base64::Engine;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;
        let mut req = client.get(url).header("accept", "application/json");
        if let Some(l) = license {
            req = req.header("X-Nano-License", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(l));
        }
        let resp = req.send().await.map_err(http_error)?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.map_err(http_error)?;
        if body.len() as u64 > MAX_METADATA_BYTES {
            return Err("metadata response exceeds 128 KiB".into());
        }
        Ok(crate::platform_enrichment::consumer::MetadataResponse { status, body: body.to_vec() })
    }

    async fn download(&self, url: &str, dest: &Path, cap: u64) -> Result<String, String> {
        use sha2::Digest;
        use std::os::unix::fs::OpenOptionsExt;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client.get(url).send().await.map_err(http_error)?;
        if !resp.status().is_success() {
            return Err(format!("bundle download returned HTTP {}", resp.status()));
        }
        let body = resp.bytes().await.map_err(http_error)?;
        if body.len() as u64 > cap {
            return Err("bundle exceeds the container size bound".into());
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dest)
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(&mut f, &body).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        Ok(hex::encode(sha2::Sha256::digest(&body)))
    }
}

/// Status of one subscribed channel (`GET /api/content/channels`).
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ChannelStatus {
    pub channel: String,
    pub kind: channels::Kind,
    pub repo: String,
    pub branch: String,
    pub route: Route,
    pub enabled: bool,
    pub installed: bool,
    pub sequence: Option<i64>,
    pub upstream_commit: Option<String>,
    pub committed_at: Option<chrono::DateTime<Utc>>,
    pub produced_at: Option<chrono::DateTime<Utc>>,
    pub hard_expiry: Option<chrono::DateTime<Utc>>,
    /// Past `hard_expiry`: still in use (last good), but no newer bundle was
    /// installed in time.
    pub stale: bool,
    /// The installed snapshot's apply has not completed (see `apply_error`).
    pub apply_pending: bool,
    pub files: Option<i32>,
    pub signer_key_id: Option<String>,
    pub source: Option<String>,
    pub delivered_via: Option<String>,
    pub installed_at: Option<chrono::DateTime<Utc>>,
    pub applied_at: Option<chrono::DateTime<Utc>>,
    pub apply_error: Option<String>,
    pub last_check_at: Option<chrono::DateTime<Utc>>,
    pub last_check_status: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ChannelsStatus {
    /// Where online checks go (`https://api.nano.rs/api/content/v1` or a mirror).
    pub distribution: String,
    pub auto_update: bool,
    /// `production`, or `production+acceptance` in the non-shippable proof build.
    pub trust: String,
    pub poll_interval_secs: u64,
    pub channels: Vec<ChannelStatus>,
}

fn status_of(ch: &'static Channel, row: Option<&ChannelRow>, now: chrono::DateTime<Utc>) -> ChannelStatus {
    let signed = row.and_then(|r| installed_from(r.signed_descriptor.as_ref()));
    let d = signed.as_ref().map(|s| &s.descriptor);
    ChannelStatus {
        channel: ch.id.into(),
        kind: ch.kind,
        repo: ch.repo.into(),
        branch: ch.branch.into(),
        route: ch.route,
        enabled: row.is_none_or(|r| r.enabled),
        installed: d.is_some(),
        sequence: row.and_then(|r| r.sequence),
        upstream_commit: row.and_then(|r| r.upstream_commit.clone()),
        committed_at: d.map(|d| d.upstream.committed_at),
        produced_at: d.map(|d| d.produced_at),
        hard_expiry: d.map(|d| d.hard_expiry),
        stale: d.is_some_and(|d| d.hard_expiry <= now),
        apply_pending: row.is_some_and(needs_apply),
        files: row.and_then(|r| r.file_count),
        signer_key_id: d.map(|d| d.signer_key_id.clone()),
        source: row.and_then(|r| r.source.clone()),
        delivered_via: row.and_then(|r| r.route.clone()),
        installed_at: row.and_then(|r| r.installed_at),
        applied_at: row.and_then(|r| r.applied_at),
        apply_error: row.and_then(|r| r.apply_error.clone()),
        last_check_at: row.and_then(|r| r.last_check_at),
        last_check_status: row.and_then(|r| r.last_check_status.clone()),
        last_error: row.and_then(|r| r.last_error.clone()),
    }
}

/// The consumer.
pub struct ContentConsumer {
    store: ContentStore,
    config: ContentConfig,
    ring: KeyRing,
    http: Arc<dyn FeedHttp>,
    applier: Arc<dyn ContentApplier>,
    fence: LeaderFence,
}

impl ContentConsumer {
    pub fn new(store: ContentStore, config: ContentConfig, applier: Arc<dyn ContentApplier>) -> Self {
        let http: Arc<dyn FeedHttp> = if config.insecure_http { Arc::new(DevHttp) } else { Arc::new(ReqwestFeedHttp) };
        Self { store, config, ring: contract::content_key_ring(), http, applier, fence: LeaderFence::disabled() }
    }

    pub fn with_fence(mut self, fence: LeaderFence) -> Self {
        self.fence = fence;
        self
    }
    pub fn with_ring(mut self, ring: KeyRing) -> Self {
        self.ring = ring;
        self
    }
    pub fn with_http(mut self, http: Arc<dyn FeedHttp>) -> Self {
        self.http = http;
        self
    }
    pub fn config(&self) -> &ContentConfig {
        &self.config
    }
    pub fn store(&self) -> &ContentStore {
        &self.store
    }

    /// Status of every subscribed channel.
    pub async fn status(&self) -> Result<ChannelsStatus, sqlx::Error> {
        let rows = self.store.list().await?;
        let now = Utc::now();
        Ok(ChannelsStatus {
            distribution: self.config.base_url.clone(),
            auto_update: self.config.auto_update,
            trust: contract::trust_label().into(),
            poll_interval_secs: self.config.poll_interval.as_secs(),
            channels: self
                .config
                .channels
                .iter()
                .map(|ch| status_of(ch, rows.iter().find(|r| r.channel == ch.id), now))
                .collect(),
        })
    }

    pub async fn lease(&self) -> Result<InstallLease, ChannelError> {
        Ok(InstallLease::acquire_lock(self.store.pool(), INSTALL_LOCK_ID).await?)
    }

    /// Create a fresh 0600 upload inside the consumer's private 0700 work
    /// directory. The API takes the install lease before calling this, then
    /// streams the request into the returned file.
    pub fn create_upload(&self) -> Result<(PathBuf, std::fs::File), ChannelError> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = ensure_private_dir(&self.config.work_dir)?
            .join(format!("upload-{}.nancontent", uuid::Uuid::now_v7().simple()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| ChannelError::Install(format!("upload staging: {e}")))?;
        Ok((path, file))
    }

    /// Check every subscribed channel now (takes the lease).
    pub async fn check_all(&self) -> Result<Vec<(String, Result<ChannelOutcome, String>)>, ChannelError> {
        if !self.config.auto_update {
            return Err(ChannelError::Disabled);
        }
        let lease = self.lease().await?;
        let out = self.check_all_with(lease).await;
        Ok(out)
    }

    /// Check every subscribed channel under an already-held lease.
    pub async fn check_all_with(&self, lease: InstallLease) -> Vec<(String, Result<ChannelOutcome, String>)> {
        let mut out = Vec::new();
        for ch in self.config.channels.clone() {
            let result = self.check_channel_locked(ch).await;
            self.record(ch, &result).await;
            out.push((ch.id.to_string(), result.map_err(|e| e.to_string())));
        }
        lease.release().await;
        out
    }

    /// Mark every subscribed channel as being checked.
    pub async fn mark_checking(&self) -> Result<(), sqlx::Error> {
        for ch in &self.config.channels {
            self.store.record_check(ch.id, "checking", None, Utc::now()).await?;
        }
        Ok(())
    }

    async fn record(&self, ch: &Channel, result: &Result<ChannelOutcome, ChannelError>) {
        let now = Utc::now();
        let (status, error) = match result {
            Ok(ChannelOutcome::Installed { .. }) => return, // recorded by install
            Ok(ChannelOutcome::Current { .. }) => ("current", None),
            Ok(ChannelOutcome::Reapplied { .. }) => ("installed", None),
            Ok(ChannelOutcome::Unpublished) => ("unpublished", None),
            Ok(ChannelOutcome::Skipped { reason }) => ("skipped", Some(reason.clone())),
            Err(ChannelError::Busy) => return,
            Err(e) => {
                tracing::warn!(channel = ch.id, error = %e, "content channel not installed; the installed snapshot stays");
                (e.check_status(), Some(e.to_string()))
            }
        };
        if let Err(e) = self.store.record_check(ch.id, status, error.as_deref(), now).await {
            tracing::warn!(channel = ch.id, error = %e, "could not record the content channel check");
        }
    }

    fn metadata_url(&self, ch: &Channel) -> String {
        format!("{}/{}/{}/current", self.config.base_url, ch.route.as_str(), ch.id)
    }

    async fn check_channel_locked(&self, ch: &'static Channel) -> Result<ChannelOutcome, ChannelError> {
        let row = self.store.get(ch.id).await.map_err(db)?;
        if row.as_ref().is_some_and(|r| !r.enabled) {
            return Ok(ChannelOutcome::Skipped { reason: "opted out on this install".into() });
        }
        let license = match ch.route {
            Route::Open => None,
            Route::Enterprise => match self.config.license.as_deref() {
                Some(l) => Some(l),
                None => {
                    return Ok(ChannelOutcome::Skipped {
                        reason: "enterprise channel: no signed license artifact configured (CONTENT_CHANNELS_LICENSE_FILE)".into(),
                    })
                }
            },
        };
        let url = self.metadata_url(ch);
        let response = self.http.metadata(&url, license).await.map_err(ChannelError::Fetch)?;
        if response.status == 404 {
            return Ok(ChannelOutcome::Unpublished);
        }
        if response.status != 200 {
            let code = serde_json::from_slice::<serde_json::Value>(&response.body)
                .ok()
                .and_then(|v| v["code"].as_str().or(v["error"].as_str()).map(str::to_string))
                .unwrap_or_default();
            return Err(ChannelError::Fetch(format!("{url} returned HTTP {} {code}", response.status)));
        }
        let release = parse_current(&response.body, &self.ring, ch.id, self.config.insecure_http)?;
        let d = &release.signed.descriptor;
        let installed = row.as_ref().and_then(|r| installed_from(r.signed_descriptor.as_ref()));
        if installed.as_ref() == Some(&release.signed) && row.as_ref().is_some_and(|r| r.tree_sha256.is_some()) {
            if row.as_ref().is_some_and(needs_apply) {
                return self.reapply_installed(ch, release.signed.clone()).await;
            }
            return Ok(ChannelOutcome::Current { sequence: d.sequence });
        }
        let now = Utc::now();
        if let Some(prev) = &installed {
            if d.sequence < prev.descriptor.sequence {
                return Err(ChannelError::Refused(format!(
                    "published sequence {} is older than the installed {} (rollback)",
                    d.sequence, prev.descriptor.sequence
                )));
            }
        }
        if d.hard_expiry <= now {
            return Err(ChannelError::Refused(format!("published descriptor expired at {}", d.hard_expiry)));
        }
        let dir = ensure_private_dir(&self.config.work_dir)?;
        let dest = dir.join(format!("download-{}.{}", uuid::Uuid::now_v7().simple(), contract::FILE_EXTENSION));
        let _cleanup = RemoveOnDrop(dest.clone());
        self.http
            .download(&release.bundle_url, &dest, MAX_CONTAINER_BYTES)
            .await
            .map_err(ChannelError::Fetch)?;
        let bytes = read_bounded(&dest)?;
        let via = if self.config.mirror { "mirror" } else { ch.route.as_str() };
        self.install_bytes(bytes, SOURCE_ONLINE, via, Some(&release.signed), Some(ch)).await
    }

    /// Verify, accept, install and apply a container. Caller holds the lease.
    async fn install_bytes(
        &self,
        bytes: Vec<u8>,
        source: &str,
        via: &str,
        expected: Option<&SignedContentDescriptor>,
        expected_channel: Option<&'static Channel>,
    ) -> Result<ChannelOutcome, ChannelError> {
        let ring = self.ring.clone();
        let verified = tokio::task::spawn_blocking(move || contract::verify_bytes(&bytes, &ring))
            .await
            .map_err(|e| ChannelError::Install(e.to_string()))??;
        if let Some(expected) = expected {
            if verified.signed() != expected {
                return Err(ChannelError::Refused(
                    "downloaded bundle differs from the signed descriptor that announced it".into(),
                ));
            }
        }
        let d = verified.descriptor().clone();
        let ch = channels::by_id(&d.channel).ok_or_else(|| ChannelError::Refused("unknown channel".into()))?;
        if expected_channel.is_some_and(|e| e.id != ch.id) {
            return Err(ChannelError::Refused("bundle is for another channel".into()));
        }
        let now = Utc::now();
        let installed = self.store.installed_descriptor(ch.id).await.map_err(db)?;
        verified.accept_after(installed.as_ref().map(|s| &s.descriptor), now, source == SOURCE_OFFLINE)?;
        if d.produced_at > now + PRODUCED_AT_SKEW {
            return Err(ChannelError::Refused("bundle was produced in the future (check this host's clock)".into()));
        }
        let row = self.store.get(ch.id).await.map_err(db)?;
        let apply_pending = row.as_ref().is_some_and(needs_apply);
        if installed.as_ref() == Some(verified.signed()) && row.as_ref().is_some_and(|r| r.tree_sha256.is_some()) {
            if apply_pending {
                self.run_apply(ch, &verified, true).await?;
                return Ok(ChannelOutcome::Reapplied { sequence: d.sequence });
            }
            return Ok(ChannelOutcome::Current { sequence: d.sequence });
        }
        let tree_changed = self.store.install(&verified, source, via).await.map_err(db)?;
        tracing::info!(
            channel = ch.id, sequence = d.sequence, commit = %d.upstream.commit, files = d.tree.files,
            signer = %d.signer_key_id, source, via, tree_changed, "content channel installed"
        );
        // An unchanged tree still re-applies when the previous apply never
        // completed (e.g. a re-sealed descriptor over an extension catalog whose
        // import failed): the applier must not skip it as "unchanged".
        self.run_apply(ch, &verified, tree_changed || apply_pending).await?;
        Ok(ChannelOutcome::Installed {
            sequence: d.sequence,
            commit: d.upstream.commit.clone(),
            files: d.tree.files,
            tree_changed,
        })
    }

    /// Hand an installed snapshot to its applier and record the outcome. A
    /// failure is returned (the snapshot stays installed; `apply_error` marks
    /// it, and the next check or import of the same bundle retries it).
    async fn run_apply(&self, ch: &'static Channel, verified: &VerifiedContent, force: bool) -> Result<String, ChannelError> {
        let applied = self.applier.apply(ch, verified, force).await;
        let _ = self.store.record_apply(ch.id, applied.as_ref().err().map(String::as_str)).await;
        match applied {
            Ok(summary) => {
                tracing::info!(channel = ch.id, %summary, "content channel applied");
                Ok(summary)
            }
            Err(error) => {
                tracing::warn!(channel = ch.id, %error, "content channel installed but its apply failed");
                Err(ChannelError::ApplyFailed(format!(
                    "sequence {}: {error}; the apply is retried on the next check or import",
                    verified.descriptor().sequence
                )))
            }
        }
    }

    /// Retry the apply of the installed snapshot from the store (no download).
    async fn reapply_installed(&self, ch: &'static Channel, signed: SignedContentDescriptor) -> Result<ChannelOutcome, ChannelError> {
        let files = self.store.read_tree(ch.id, &[]).await.map_err(db)?;
        let sequence = signed.descriptor.sequence;
        let verified = contract::reverify_installed(signed, files)?;
        self.run_apply(ch, &verified, true).await?;
        Ok(ChannelOutcome::Reapplied { sequence })
    }

    /// Air-gap import of a `.nancontent` held in memory (takes the lease).
    /// Same verification as online; an expired descriptor is accepted (late
    /// import), rollback is not.
    pub async fn import_bytes(&self, bytes: Vec<u8>) -> Result<ChannelOutcome, ChannelError> {
        if bytes.len() as u64 > MAX_CONTAINER_BYTES {
            return Err(ChannelError::Refused("bundle exceeds the container size bound".into()));
        }
        let lease = self.lease().await?;
        let result = self.install_bytes(bytes, SOURCE_OFFLINE, "file", None, None).await;
        if let Err(e) = &result {
            if !matches!(e, ChannelError::Busy) {
                tracing::warn!(error = %e, "content bundle import refused or failed");
            }
        }
        lease.release().await;
        result
    }

    /// Import a file already streamed into [`Self::create_upload`] while the
    /// caller holds the install lease. The staged file is always removed.
    pub async fn import_staged(&self, lease: InstallLease, staged: &Path) -> Result<ChannelOutcome, ChannelError> {
        let _cleanup = RemoveOnDrop(staged.to_path_buf());
        let result = async {
            let dir = ensure_private_dir(&self.config.work_dir)?;
            if staged.parent() != Some(dir.as_path()) {
                return Err(ChannelError::Install("staged upload is outside the private work dir".into()));
            }
            let path = staged.to_path_buf();
            let bytes = tokio::task::spawn_blocking(move || read_bounded(&path))
                .await
                .map_err(|e| ChannelError::Install(format!("upload worker failed: {e}")))??;
            self.install_bytes(bytes, SOURCE_OFFLINE, "file", None, None).await
        }
        .await;
        if let Err(error) = &result {
            if !matches!(error, ChannelError::Busy) {
                tracing::warn!(%error, "content bundle import refused or failed");
            }
        }
        lease.release().await;
        result
    }

    /// Opt a channel out of (or back into) online updates.
    pub async fn set_enabled(&self, channel: &str, enabled: bool) -> Result<(), ChannelError> {
        if channels::by_id(channel).is_none() {
            return Err(ChannelError::Refused(format!("unknown channel {channel}")));
        }
        self.store.set_enabled(channel, enabled).await.map_err(db)
    }

    /// Leader-only loop: first check shortly after start, then every poll
    /// interval (sooner after a failure).
    pub fn start(self: Arc<Self>, shutdown: ShutdownToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!(config = ?self.config, trust = contract::trust_label(), "content channel consumer started (leader-only)");
            if contract::trust_label() != "production" {
                tracing::warn!("content bundle trust includes acceptance keys (non-shippable debug composition)");
            }
            if !self.config.auto_update {
                return;
            }
            let mut next = tokio::time::Instant::now() + Duration::from_secs(FIRST_CHECK_SECS);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep_until(next) => {
                        if !self.fence.still_leader(self.store.pool()).await {
                            next = tokio::time::Instant::now() + Duration::from_secs(RETRY_SECS);
                            continue;
                        }
                        let ok = match self.check_all().await {
                            Ok(results) => {
                                let failed = results.iter().filter(|(_, r)| r.is_err()).count();
                                tracing::info!(channels = results.len(), failed, "content channel check");
                                failed == 0
                            }
                            Err(ChannelError::Busy) => true,
                            Err(e) => {
                                tracing::warn!(error = %e, "content channel check failed");
                                false
                            }
                        };
                        let wait = if ok { self.config.poll_interval } else { self.config.poll_interval.min(Duration::from_secs(RETRY_SECS)) };
                        next = tokio::time::Instant::now() + wait;
                    }
                }
            }
        })
    }
}

/// Whether the installed snapshot's apply has not completed: it failed, or it
/// never finished after the latest install.
pub fn needs_apply(row: &ChannelRow) -> bool {
    row.installed_at.is_some()
        && (row.apply_error.is_some() || row.applied_at.is_none_or(|a| row.installed_at.is_some_and(|i| a < i)))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ChannelError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| ChannelError::Install(format!("reading the bundle: {e}")))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !meta.file_type().is_file() || meta.uid() != euid || meta.mode() & 0o077 != 0 {
        return Err(ChannelError::Install(
            "staged bundle must be a private regular file owned by this service".into(),
        ));
    }
    if meta.len() > MAX_CONTAINER_BYTES {
        return Err(ChannelError::Refused("bundle exceeds the container size bound".into()));
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| ChannelError::Install(format!("reading the bundle: {e}")))?;
    let mut out = Vec::new();
    f.take(MAX_CONTAINER_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| ChannelError::Install(format!("reading the bundle: {e}")))?;
    if out.len() as u64 > MAX_CONTAINER_BYTES {
        return Err(ChannelError::Refused("bundle exceeds the container size bound".into()));
    }
    Ok(out)
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(test)]
#[path = "consumer_tests.rs"]
mod tests;
