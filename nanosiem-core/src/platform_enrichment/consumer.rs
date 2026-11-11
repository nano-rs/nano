// SPDX-License-Identifier: AGPL-3.0-or-later
//! Platform feed bundle consumer (NAN-4948): fetch → verify → accept → load →
//! record, for the scheduled online check and the offline (air-gap) import.
//!
//! ## Online check
//!
//! 1. `GET <endpoint>` returns `{descriptor, bundle_url, bundle_sha256}`. The
//!    endpoint is an operator mirror (`PLATFORM_FEEDS_URL`), else the
//!    license-authenticated sovereign route when an enterprise build holds a
//!    signed license artifact (`PLATFORM_FEEDS_LICENSE_FILE`), else the open
//!    route. A sovereign refusal (401/403) falls back to the open route.
//! 2. The descriptor's signature is verified against the compiled-in key ring
//!    BEFORE the download capability is followed. When it equals the installed
//!    descriptor and every feed it should stamp is active, the check ends
//!    (`current`): a restart never re-downloads a current bundle.
//! 3. The container is downloaded (https, SSRF-pinned, size-capped) into a
//!    private work directory and installed like an offline import.
//!
//! ## Install (shared with the offline import)
//!
//! Serialized across every API/jobs node by a PostgreSQL advisory lock.
//! `verify_file` (signature, structure, payload digest + exact length, header
//! consistency), then `accept_after` against the installed descriptor
//! (rollback, same-sequence substitution, per-feed revision regression, an
//! entirely expired bundle) and a produced-in-the-future check. Only then is
//! anything written: each feed loads under its own generation key and the
//! commit makes all of them visible at once (see [`super::loader`]). Any
//! failure before the commit leaves the last good install stamping and is
//! recorded as `refused` (the artifact was not acceptable) or `failed`.
//!
//! Feeds past their hard expiry are not loaded, and an installed feed that
//! passes its hard expiry is withdrawn by the scheduled tick (it stops
//! stamping new events; stamped values stay). IPinfo Lite comes only from
//! this bundle: there is no bring-your-own IPinfo token or download URL
//! (NAN-4959 retired main's native BYO sync).

use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use sha2::{Digest, Sha256};

use super::loader::{self, ClickHouseLoader, CommitRow, IPINFO_FEED};
use super::payload;
use super::portable::{self, BundleError, Descriptor, KeyRing, SignedDescriptor};
use super::state::{
    build_status, FeedInstall, FeedsStatus, InstallReceipt, StateRepository, StatusContext,
    SOURCE_OFFLINE, SOURCE_ONLINE,
};
use crate::inputlookup::SsrfValidator;
use crate::leader::LeaderFence;
use crate::shutdown::ShutdownToken;

/// Open distribution route.
pub const OPEN_URL: &str = "https://api.nano.rs/api/feeds/v1/open/current";
/// License-authenticated distribution route.
pub const SOVEREIGN_URL: &str = "https://api.nano.rs/api/feeds/v1/sovereign/current";
/// PostgreSQL advisory lock serializing installs (`NSPFED`).
pub const INSTALL_LOCK_ID: i64 = 0x4e53_5046_4544;
/// Tolerated clock skew between the publisher and this host.
const PRODUCED_AT_SKEW: chrono::Duration = chrono::Duration::minutes(10);
/// Bound of the distribution metadata response.
const MAX_METADATA_BYTES: usize = 128 * 1024;
/// Bound of a signed license artifact.
const MAX_LICENSE_BYTES: u64 = 9216;
/// Bound of the container: payload + header + descriptor.
pub const MAX_CONTAINER_BYTES: u64 = portable::MAX_PAYLOAD_BYTES + 16 + 64 * 1024;
/// Default and minimum interval of the scheduled online check.
const DEFAULT_POLL_SECS: u64 = 3600;
const MIN_POLL_SECS: u64 = 300;
/// Retry delay after a failed check (bounded by the poll interval).
const RETRY_SECS: u64 = 300;
/// Expiry/ownership reconcile cadence (no network).
const RECONCILE_SECS: u64 = 300;

/// Where a bundle came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Open,
    Sovereign,
    Mirror,
    File,
}

impl Channel {
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Open => "open",
            Channel::Sovereign => "sovereign",
            Channel::Mirror => "mirror",
            Channel::File => "file",
        }
    }
}

/// Consumer configuration (`PLATFORM_FEEDS_*`).
#[derive(Clone)]
pub struct ConsumerConfig {
    pub open_url: String,
    pub sovereign_url: String,
    /// Operator mirror serving the same response contract (https only).
    pub mirror_url: Option<String>,
    /// Signed license artifact for the sovereign route (enterprise builds).
    pub license: Option<Vec<u8>>,
    /// Private directory for downloads and staged imports.
    pub work_dir: PathBuf,
    pub poll_interval: Duration,
    /// The scheduled online check runs (false in air-gap mode).
    pub auto_update: bool,
}

impl std::fmt::Debug for ConsumerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsumerConfig")
            .field("open_url", &self.open_url)
            .field("sovereign_url", &self.sovereign_url)
            .field("mirror_url", &self.mirror_url)
            .field("license", &self.license.as_ref().map(|_| "<set>"))
            .field("work_dir", &self.work_dir)
            .field("poll_interval", &self.poll_interval)
            .field("auto_update", &self.auto_update)
            .finish()
    }
}

impl ConsumerConfig {
    /// From the environment. `airgap` (AIRGAP_MODE) disables the online check.
    ///
    /// - `PLATFORM_FEEDS_AUTO_UPDATE` (default true)
    /// - `PLATFORM_FEEDS_POLL_SECS` (default 3600, min 300)
    /// - `PLATFORM_FEEDS_URL` (https mirror of the metadata route)
    /// - `PLATFORM_FEEDS_LICENSE_FILE` (enterprise: signed license artifact)
    /// - `PLATFORM_FEEDS_WORK_DIR` (default `$NANOSIEM_DATA_DIR/platform-feeds`,
    ///   else `./data/platform-feeds`; never a shared temp dir). It must be
    ///   owned by this service with no group/other access, or it is refused.
    pub fn from_env(airgap: bool) -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let auto_update = !airgap
            && var("PLATFORM_FEEDS_AUTO_UPDATE")
                .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true);
        let poll = var("PLATFORM_FEEDS_POLL_SECS")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_POLL_SECS)
            .max(MIN_POLL_SECS);
        let work_dir = var("PLATFORM_FEEDS_WORK_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                var("NANOSIEM_DATA_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("data"))
                    .join("platform-feeds")
            });
        let work_dir = if work_dir.is_absolute() {
            work_dir
        } else {
            std::env::current_dir().map(|cwd| cwd.join(&work_dir)).unwrap_or(work_dir)
        };
        Self {
            open_url: OPEN_URL.to_string(),
            sovereign_url: SOVEREIGN_URL.to_string(),
            mirror_url: var("PLATFORM_FEEDS_URL"),
            license: read_license(var("PLATFORM_FEEDS_LICENSE_FILE")),
            work_dir,
            poll_interval: Duration::from_secs(poll),
            auto_update,
        }
    }
}

/// NAN-5220: the install's signed license from the registered credential
/// source (enterprise builds; resolved on every check, so a renewal is used at
/// the next one). The sovereign feed route accepts only a signed license, so an
/// online enrollment credential is not used here: those installs take the open
/// feed route, as before.
async fn installed_signed_license() -> Option<Vec<u8>> {
    use crate::content_bundle::credential::{credential_source, CredentialLookup, DistributionCredential};
    match credential_source()?.lookup().await {
        CredentialLookup::Found { credential: DistributionCredential::SignedLicense(bytes), .. } => Some(bytes),
        _ => None,
    }
}

/// The signed license artifact, enterprise builds only. Open builds have no
/// license machinery (NAN-1193) and always use the open route.
#[cfg(feature = "enterprise")]
fn read_license(path: Option<String>) -> Option<Vec<u8>> {
    let path = PathBuf::from(path?);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "PLATFORM_FEEDS_LICENSE_FILE unreadable; using the open feed route");
            return None;
        }
    };
    if !meta.file_type().is_file() || meta.len() == 0 || meta.len() > MAX_LICENSE_BYTES {
        tracing::warn!(path = %path.display(), "PLATFORM_FEEDS_LICENSE_FILE must be a regular file of at most 9 KiB; using the open feed route");
        return None;
    }
    std::fs::read(&path).ok()
}

#[cfg(not(feature = "enterprise"))]
fn read_license(path: Option<String>) -> Option<Vec<u8>> {
    if path.is_some() {
        tracing::warn!("PLATFORM_FEEDS_LICENSE_FILE is ignored by the open edition; using the open feed route");
    }
    let _ = MAX_LICENSE_BYTES;
    None
}

/// Result of an install attempt that did not fail.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case", tag = "outcome")]
#[schema(as = PlatformFeedOutcome)]
pub enum Outcome {
    /// A new bundle (or new feed set) is now installed.
    Installed {
        sequence: u64,
        loaded: BTreeMap<String, u64>,
    },
    /// The installed bundle is already the current one.
    Current { sequence: u64 },
}

/// Why an install did not happen. The installed bundle is kept in every case.
#[derive(Debug, thiserror::Error)]
pub enum ConsumerError {
    /// The artifact is not acceptable: signature, digest, format, rollback,
    /// expiry. Retrying the same artifact will not help.
    #[error("feed bundle refused: {0}")]
    Refused(String),
    /// Another install holds the lock.
    #[error("another feed bundle install is in progress")]
    Busy,
    /// The online check is disabled on this deployment.
    #[error("online feed updates are disabled on this deployment (air-gap); import a bundle file instead")]
    Disabled,
    /// The distribution endpoint or download failed.
    #[error("feed bundle fetch failed: {0}")]
    Fetch(String),
    /// Loading into ClickHouse or recording in PostgreSQL failed.
    #[error("feed bundle install failed: {0}")]
    Install(String),
}

impl From<BundleError> for ConsumerError {
    fn from(error: BundleError) -> Self {
        match error {
            BundleError::Io(io) => ConsumerError::Install(format!("reading the bundle: {io}")),
            other => ConsumerError::Refused(other.to_string()),
        }
    }
}

impl ConsumerError {
    fn check_status(&self) -> &'static str {
        match self {
            ConsumerError::Refused(_) => "refused",
            _ => "failed",
        }
    }
}

/// A distribution metadata response.
#[derive(Debug, Clone)]
pub struct MetadataResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// HTTP seam of the online check.
#[async_trait]
pub trait FeedHttp: Send + Sync {
    /// GET the metadata route (no redirects). `license` is the raw artifact.
    async fn metadata(&self, url: &str, license: Option<&[u8]>) -> Result<MetadataResponse, String>;
    /// GET the metadata route with an online enrollment credential
    /// (`Authorization: Bearer <token>` + `X-Nano-Deployment-Id`; NAN-5220).
    /// Clients that cannot present one refuse.
    async fn metadata_enrolled(&self, url: &str, deployment_id: &str, token: &str) -> Result<MetadataResponse, String> {
        let _ = (url, deployment_id, token);
        Err("this HTTP client cannot present an enrollment credential".into())
    }
    /// Download `url` into `dest` (created 0600), at most `cap` bytes. Returns
    /// the SHA-256 of the bytes written.
    async fn download(&self, url: &str, dest: &Path, cap: u64) -> Result<String, String>;
}

/// A reqwest error as text WITHOUT its URL (NAN-4955 review): bundle URLs are
/// presigned R2 GETs whose query string is a bearer credential, and these
/// strings reach logs, the stored `last_error`, the status API and audit.
/// Covers send and body-stream errors alike.
pub fn http_error(error: reqwest::Error) -> String {
    error.without_url().to_string()
}

/// Header naming the deployment an enrollment token belongs to (NAN-5220).
pub const ENROLLMENT_DEPLOYMENT_HEADER: &str = "X-Nano-Deployment-Id";

/// Send a metadata request and read its body (at most 128 KiB).
async fn read_metadata(request: reqwest::RequestBuilder) -> Result<MetadataResponse, String> {
    let response = request.send().await.map_err(http_error)?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(http_error)?;
        if body.len() + chunk.len() > MAX_METADATA_BYTES {
            return Err("metadata response exceeds 128 KiB".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(MetadataResponse { status, body })
}

/// Production HTTP: https only, SSRF-validated and pinned, no redirects.
pub struct ReqwestFeedHttp;

impl ReqwestFeedHttp {
    async fn client(url: &str, timeout: Duration) -> Result<(reqwest::Client, url::Url), String> {
        let builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(20))
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip();
        SsrfValidator::default_secure()
            .build_pinned_client(url, builder, crate::inputlookup::ProxyPolicy::Environment)
            .await
            .map_err(|e| format!("URL refused: {e}"))
    }
}

#[async_trait]
impl FeedHttp for ReqwestFeedHttp {
    async fn metadata(&self, url: &str, license: Option<&[u8]>) -> Result<MetadataResponse, String> {
        use base64::Engine;
        let (client, url) = Self::client(url, Duration::from_secs(60)).await?;
        let mut request = client.get(url).header("accept", "application/json");
        if let Some(license) = license {
            request = request.header(
                "X-Nano-License",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(license),
            );
        }
        read_metadata(request).await
    }

    async fn metadata_enrolled(&self, url: &str, deployment_id: &str, token: &str) -> Result<MetadataResponse, String> {
        let (client, url) = Self::client(url, Duration::from_secs(60)).await?;
        let request = client
            .get(url)
            .header("accept", "application/json")
            .header(ENROLLMENT_DEPLOYMENT_HEADER, deployment_id)
            .bearer_auth(token);
        read_metadata(request).await
    }

    async fn download(&self, url: &str, dest: &Path, cap: u64) -> Result<String, String> {
        let (client, url) = Self::client(url, Duration::from_secs(900)).await?;
        let response = client.get(url).send().await.map_err(http_error)?;
        if !response.status().is_success() {
            return Err(format!("bundle download returned HTTP {}", response.status()));
        }
        if response.content_length().is_some_and(|len| len > cap) {
            return Err("bundle exceeds the container size bound".to_string());
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dest)
            .map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(http_error)?;
            written += chunk.len() as u64;
            if written > cap {
                return Err("bundle exceeds the container size bound".to_string());
            }
            hasher.update(&chunk);
            file.write_all(&chunk).map_err(|e| e.to_string())?;
        }
        file.sync_all().map_err(|e| e.to_string())?;
        Ok(hex::encode(hasher.finalize()))
    }
}

/// The parsed, signature-verified metadata response.
#[derive(Debug, Clone)]
pub struct CurrentRelease {
    pub signed: SignedDescriptor,
    pub bundle_url: String,
}

/// Parse a metadata response body: the descriptor must verify against `ring`,
/// `bundle_sha256` must equal its payload digest, and `bundle_url` must be a
/// plain https URL (main's `check_current` contract).
pub fn parse_current(body: &[u8], ring: &KeyRing) -> Result<CurrentRelease, ConsumerError> {
    let response: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| ConsumerError::Refused("feed metadata is not JSON".into()))?;
    let descriptor = serde_json::to_vec(&response["descriptor"])
        .map_err(|_| ConsumerError::Refused("feed metadata descriptor".into()))?;
    let signed = SignedDescriptor::from_json(&descriptor, ring)?;
    if response["bundle_sha256"].as_str() != Some(signed.descriptor.payload.sha256.as_str()) {
        return Err(ConsumerError::Refused(
            "feed metadata digest differs from its signed descriptor".into(),
        ));
    }
    let url = response["bundle_url"]
        .as_str()
        .ok_or_else(|| ConsumerError::Refused("feed metadata download URL missing".into()))?;
    let parsed = url::Url::parse(url)
        .map_err(|_| ConsumerError::Refused("feed download URL is not a URL".into()))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || url.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ConsumerError::Refused("feed download URL must be plain https".into()));
    }
    Ok(CurrentRelease {
        signed,
        bundle_url: url.to_string(),
    })
}

/// The installed descriptor from the stored state. It was verified when it
/// was installed; it is re-validated structurally but its signature is not
/// re-checked, so a key retired in a later release does not orphan it (main's
/// `receipt_descriptor`).
pub fn installed_descriptor(stored: Option<&serde_json::Value>) -> Option<Descriptor> {
    let signed: SignedDescriptor = serde_json::from_value(stored?.clone()).ok()?;
    signed.descriptor.validate().ok()?;
    Some(signed.descriptor)
}

/// Feeds of `d` that should stamp now, with the reason for each that should
/// not.
pub fn plan_feeds(
    d: &Descriptor,
    now: DateTime<Utc>,
) -> (BTreeMap<String, portable::FeedEntry>, BTreeMap<String, String>) {
    let mut load = BTreeMap::new();
    let mut skip = BTreeMap::new();
    for (feed, entry) in &d.feeds {
        if entry.hard_expiry <= now {
            skip.insert(feed.clone(), "Past its hard expiry when installed.".to_string());
        } else {
            load.insert(feed.clone(), entry.clone());
        }
    }
    (load, skip)
}

/// Whether the installed state already serves `d`: same descriptor, and every
/// feed that should stamp is active.
pub fn is_current(
    installed: Option<&Descriptor>,
    feeds: &BTreeMap<String, FeedInstall>,
    d: &Descriptor,
    now: DateTime<Utc>,
) -> bool {
    if installed != Some(d) {
        return false;
    }
    let (load, _) = plan_feeds(d, now);
    load.keys().all(|feed| feeds.get(feed).is_some_and(|f| f.active))
}

/// When the scheduled online check is next due, as the leader loop in
/// [`PlatformFeedConsumer::start`] schedules it: the poll interval after a
/// check, the retry delay (bounded by the interval) after a refused or failed
/// one. `None` without online updates, or before any check ran.
pub fn next_check_at(status: &FeedsStatus, poll_interval: Duration) -> Option<DateTime<Utc>> {
    if !status.auto_update {
        return None;
    }
    let last = status.last_check_at?;
    let failed = matches!(status.last_check_status.as_deref(), Some("refused" | "failed"));
    let wait = if failed {
        poll_interval.min(Duration::from_secs(RETRY_SECS))
    } else {
        poll_interval
    };
    chrono::Duration::from_std(wait).ok().map(|w| last + w)
}

/// The consumer.
pub struct PlatformFeedConsumer {
    state: StateRepository,
    loader: ClickHouseLoader,
    config: ConsumerConfig,
    ring: KeyRing,
    http: Arc<dyn FeedHttp>,
    fence: LeaderFence,
}

/// Validate (or create) the private work directory: a real directory (not a
/// symlink) owned by this process's effective user with no group/other
/// access. An existing directory that fails the check is REFUSED, never
/// repaired: someone else could have created it to swap files in it
/// (NAN-4948 review P1).
pub fn ensure_private_dir(dir: &Path) -> Result<PathBuf, ConsumerError> {
    use std::os::unix::fs::MetadataExt;
    let refuse = |why: String| ConsumerError::Install(format!("platform feed work dir {}: {why}", dir.display()));
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                std::fs::create_dir_all(parent).map_err(|e| refuse(e.to_string()))?;
            }
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| refuse(e.to_string()))?;
        }
        Err(e) => return Err(refuse(e.to_string())),
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| refuse(e.to_string()))?;
    if !meta.file_type().is_dir() {
        return Err(refuse("is not a directory (or is a symlink)".into()));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(refuse(format!("is owned by uid {}, not this service (uid {euid})", meta.uid())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(refuse(format!("has mode {:o}; it must be 0700", meta.mode() & 0o777)));
    }
    Ok(dir.to_path_buf())
}

/// The single-flight install lease: a PostgreSQL session advisory lock held on
/// a dedicated connection. It is taken BEFORE any download or upload is
/// accepted, so concurrent checks/imports fail fast with `Busy` instead of
/// each staging a full bundle (NAN-4948 review P2).
pub struct InstallLease {
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    lock_id: i64,
}

impl InstallLease {
    async fn acquire(pool: &sqlx::PgPool) -> Result<Self, ConsumerError> {
        Self::acquire_lock(pool, INSTALL_LOCK_ID).await
    }

    /// Take the single-flight lease on advisory lock `lock_id` (NAN-4955: the
    /// content channel consumer uses the same lease on its own lock).
    pub async fn acquire_lock(pool: &sqlx::PgPool, lock_id: i64) -> Result<Self, ConsumerError> {
        let mut conn = pool.acquire().await.map_err(db_error)?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(db_error)?;
        if !got {
            return Err(ConsumerError::Busy);
        }
        Ok(Self { conn: Some(conn), lock_id })
    }

    /// Release the lease (dropping it also ends the session's lock).
    pub async fn release(mut self) {
        if let Some(mut conn) = self.conn.take() {
            if sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.lock_id)
                .execute(&mut *conn)
                .await
                .is_err()
            {
                // Never return a connection that may still hold the lock.
                let _ = conn.detach();
            }
        }
    }
}

impl Drop for InstallLease {
    fn drop(&mut self) {
        // A cancelled holder never released: close the connection so the
        // session (and its lock) ends instead of returning to the pool.
        if let Some(conn) = self.conn.take() {
            drop(conn.detach());
        }
    }
}

impl PlatformFeedConsumer {
    pub fn new(state: StateRepository, loader: ClickHouseLoader, config: ConsumerConfig) -> Self {
        Self {
            state,
            loader,
            config,
            ring: KeyRing::production(),
            http: Arc::new(ReqwestFeedHttp),
            fence: LeaderFence::disabled(),
        }
    }

    /// The jobs leader's lease-epoch fence (NAN-4933): a superseded leader
    /// skips its ticks and its ClickHouse commits are refused. The API keeps
    /// the disabled fence; the install lease serializes it with the leader.
    pub fn with_fence(mut self, fence: LeaderFence) -> Self {
        self.fence = fence;
        self
    }

    /// Run a ClickHouse commit under the leader fence.
    async fn fenced_commit(&self, commits: &[CommitRow], what: &str) -> Result<(), ConsumerError> {
        self.fence
            .run_guarded(self.state.pool(), || self.loader.commit(commits))
            .await
            .map_err(|e| ConsumerError::Install(format!("{what}: {e}")))?
            .map_err(|e| ConsumerError::Install(format!("{what}: {e:#}")))
    }

    /// Replace the trust ring (tests sign with a fixture key).
    pub fn with_ring(mut self, ring: KeyRing) -> Self {
        self.ring = ring;
        self
    }

    /// Replace the HTTP seam (tests).
    pub fn with_http(mut self, http: Arc<dyn FeedHttp>) -> Self {
        self.http = http;
        self
    }

    pub fn config(&self) -> &ConsumerConfig {
        &self.config
    }

    /// Current status (PostgreSQL cache; repaired from ClickHouse by every
    /// install, reconcile and the leader's periodic tick).
    pub async fn status(&self) -> Result<FeedsStatus, sqlx::Error> {
        let row = self.state.get().await?;
        let mut status = build_status(
            row.as_ref(),
            &StatusContext {
                auto_update: self.config.auto_update,
                now: Utc::now(),
            },
        );
        status.next_check_at = next_check_at(&status, self.config.poll_interval);
        Ok(status)
    }

    /// Take the single-flight install lease (`Busy` when another check,
    /// import or reconcile holds it).
    pub async fn lease(&self) -> Result<InstallLease, ConsumerError> {
        InstallLease::acquire(self.state.pool()).await
    }

    /// Create a fresh upload file in the private work dir (`create_new`,
    /// 0600, `O_NOFOLLOW`). Call under the lease; hand the path to
    /// [`Self::import_staged`].
    pub fn create_upload(&self) -> Result<(PathBuf, std::fs::File), ConsumerError> {
        let path = ensure_private_dir(&self.config.work_dir)?
            .join(format!("upload-{}.nanfeed", uuid::Uuid::now_v7().simple()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| ConsumerError::Install(format!("upload staging: {e}")))?;
        Ok((path, file))
    }

    /// Mark a check as running (the API runs `check_online_with` in the
    /// background and the status shows `checking` until it ends).
    pub async fn mark_checking(&self) -> Result<(), sqlx::Error> {
        self.state.record_check("checking", None, Utc::now()).await
    }

    /// Run the online check now (takes the lease first).
    pub async fn check_online(&self) -> Result<Outcome, ConsumerError> {
        if !self.config.auto_update {
            return Err(ConsumerError::Disabled);
        }
        let lease = self.lease().await?;
        self.check_online_with(lease).await
    }

    /// Run the online check under an already-held lease.
    pub async fn check_online_with(&self, lease: InstallLease) -> Result<Outcome, ConsumerError> {
        if !self.config.auto_update {
            lease.release().await;
            return Err(ConsumerError::Disabled);
        }
        let result = self.check_online_locked().await;
        self.record_failure(&result).await;
        lease.release().await;
        result
    }

    async fn check_online_locked(&self) -> Result<Outcome, ConsumerError> {
        self.repair_from_clickhouse().await?;
        let (release, channel) = self.fetch_release().await?;
        let now = Utc::now();
        let d = &release.signed.descriptor;
        let row = self.state.get().await.map_err(db_error)?;
        let installed = installed_descriptor(row.as_ref().and_then(|r| r.signed_descriptor.as_ref()));
        let feeds = row.as_ref().map(|r| r.feeds.clone()).unwrap_or_default();
        if is_current(installed.as_ref(), &feeds, d, now) {
            self.retry_activation(row.as_ref().is_some_and(|r| r.activation_pending)).await;
            self.state
                .record_check("current", None, now)
                .await
                .map_err(db_error)?;
            return Ok(Outcome::Current { sequence: d.sequence });
        }
        // Refuse before downloading what accept_after would refuse anyway.
        if let Some(prev) = &installed {
            if d.sequence < prev.sequence {
                return Err(ConsumerError::Refused(format!(
                    "published sequence {} is older than the installed {} (rollback)",
                    d.sequence, prev.sequence
                )));
            }
        }
        if d.feeds.values().all(|f| f.hard_expiry <= now) {
            return Err(ConsumerError::Refused("every feed in the published bundle has expired".into()));
        }
        let dir = ensure_private_dir(&self.config.work_dir)?;
        let dest = dir.join(format!("download-{}.nanfeed", uuid::Uuid::now_v7().simple()));
        let _cleanup = RemoveOnDrop(dest.clone());
        let container_sha = self
            .http
            .download(&release.bundle_url, &dest, MAX_CONTAINER_BYTES)
            .await
            .map_err(ConsumerError::Fetch)?;
        self.install_locked(&dest, &container_sha, SOURCE_ONLINE, channel, Some(&release.signed))
            .await
    }

    /// Resolve the distribution endpoint and fetch + verify its metadata.
    async fn fetch_release(&self) -> Result<(CurrentRelease, Channel), ConsumerError> {
        let installed = if self.config.mirror_url.is_none() && self.config.license.is_none() {
            installed_signed_license().await
        } else {
            None
        };
        let mut attempts: Vec<(Channel, String, Option<&[u8]>)> = Vec::new();
        if let Some(mirror) = &self.config.mirror_url {
            attempts.push((Channel::Mirror, mirror.clone(), None));
        } else {
            if let Some(license) = self.config.license.as_deref().or(installed.as_deref()) {
                attempts.push((Channel::Sovereign, self.config.sovereign_url.clone(), Some(license)));
            }
            attempts.push((Channel::Open, self.config.open_url.clone(), None));
        }
        let mut refused = Vec::new();
        for (channel, url, license) in attempts {
            let result = self.http.metadata(&url, license).await;
            // NAN-5220 review M1: the sovereign route is an upgrade, never a
            // single point of failure. Any refusal (401/403), budget (429),
            // outage (503 license_verification_unavailable, other non-200) or
            // transport error there falls through to the open route.
            if channel == Channel::Sovereign {
                let reason = match &result {
                    Ok(response) if response.status == 200 => None,
                    Ok(response) => Some(
                        serde_json::from_slice::<serde_json::Value>(&response.body)
                            .ok()
                            .and_then(|v| v["code"].as_str().map(str::to_string))
                            .unwrap_or_else(|| format!("HTTP {}", response.status)),
                    ),
                    Err(error) => Some(format!("transport: {error}")),
                };
                if let Some(reason) = reason {
                    tracing::warn!(%reason, "sovereign feed route unavailable for this license; using the open route");
                    refused.push(reason);
                    continue;
                }
            }
            let response = result.map_err(ConsumerError::Fetch)?;
            if response.status != 200 {
                return Err(ConsumerError::Fetch(format!(
                    "{} returned HTTP {}",
                    channel.as_str(),
                    response.status
                )));
            }
            return Ok((parse_current(&response.body, &self.ring)?, channel));
        }
        Err(ConsumerError::Fetch(format!("no feed route accepted the request ({})", refused.join(", "))))
    }

    /// Import a bundle file (air-gap; takes the lease first). The file is
    /// copied into the private work directory and loaded only through the
    /// verified descriptor of that copy.
    pub async fn import_file(&self, source: &Path) -> Result<Outcome, ConsumerError> {
        let lease = self.lease().await?;
        let result = self.import_file_locked(source).await;
        self.record_failure(&result).await;
        lease.release().await;
        result
    }

    /// Import a file the caller already staged at [`Self::staging_path`]
    /// under `lease` (the API streams uploads there). Consumes the file.
    pub async fn import_staged(&self, lease: InstallLease, staged: &Path) -> Result<Outcome, ConsumerError> {
        let _cleanup = RemoveOnDrop(staged.to_path_buf());
        let result = async {
            let dir = ensure_private_dir(&self.config.work_dir)?;
            if staged.parent() != Some(dir.as_path()) {
                return Err(ConsumerError::Install("staged upload is outside the private work dir".into()));
            }
            let path = staged.to_path_buf();
            let container_sha = tokio::task::spawn_blocking(move || -> std::io::Result<String> {
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&path)?;
                use std::io::Read;
                let mut hasher = Sha256::new();
                let mut buffer = vec![0u8; 256 * 1024];
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buffer[..n]);
                }
                Ok(hex::encode(hasher.finalize()))
            })
            .await
            .map_err(|e| ConsumerError::Install(e.to_string()))?
            .map_err(|e| ConsumerError::Install(format!("staged upload: {e}")))?;
            self.install_locked(staged, &container_sha, SOURCE_OFFLINE, Channel::File, None).await
        }
        .await;
        self.record_failure(&result).await;
        lease.release().await;
        result
    }

    async fn import_file_locked(&self, source: &Path) -> Result<Outcome, ConsumerError> {
        let dir = ensure_private_dir(&self.config.work_dir)?;
        let staged = dir.join(format!("import-{}.nanfeed", uuid::Uuid::now_v7().simple()));
        let _cleanup = RemoveOnDrop(staged.clone());
        let src = source.to_path_buf();
        let dest = staged.clone();
        let container_sha = tokio::task::spawn_blocking(move || stage_copy(&src, &dest))
            .await
            .map_err(|e| ConsumerError::Install(e.to_string()))??;
        self.install_locked(&staged, &container_sha, SOURCE_OFFLINE, Channel::File, None)
            .await
    }

    /// Record a failed/refused attempt (the installed bundle stays).
    async fn record_failure(&self, result: &Result<Outcome, ConsumerError>) {
        let Err(error) = result else { return };
        if matches!(error, ConsumerError::Disabled) {
            return;
        }
        if matches!(error, ConsumerError::Busy) {
            // Another install owns the lease and records its own outcome.
            return;
        }
        tracing::warn!(%error, "platform feed bundle not installed; the installed bundle stays");
        if let Err(db) = self
            .state
            .record_check(error.check_status(), Some(&error.to_string()), Utc::now())
            .await
        {
            tracing::warn!(error = %db, "could not record the platform feed check");
        }
    }

    /// Make PostgreSQL agree with the latest ClickHouse commit (the durable
    /// record). Runs under the lease before every accept / expiry / reclaim
    /// decision, so a crash between the ClickHouse commit and the PostgreSQL
    /// write can never leave decisions made against an older generation
    /// (NAN-4948 review P1). Returns whether it repaired anything.
    pub async fn repair_from_clickhouse(&self) -> Result<bool, ConsumerError> {
        let Some((sequence, raw)) = self
            .loader
            .latest_receipt()
            .await
            .map_err(|e| ConsumerError::Install(format!("reading the committed generation: {e:#}")))?
        else {
            return Ok(false);
        };
        let receipt: InstallReceipt = serde_json::from_str(&raw)
            .map_err(|e| ConsumerError::Install(format!("committed receipt unreadable: {e}")))?;
        if receipt.sequence != sequence || installed_descriptor(Some(&receipt.signed_descriptor)).is_none() {
            return Err(ConsumerError::Install("committed receipt is inconsistent".into()));
        }
        let row = self.state.get().await.map_err(db_error)?;
        let agrees = row.as_ref().is_some_and(|r| {
            r.sequence == Some(receipt.sequence as i64)
                && r.signed_descriptor.as_ref() == Some(&receipt.signed_descriptor)
                && r.feeds == receipt.feeds
        });
        if agrees {
            return Ok(false);
        }
        tracing::warn!(sequence, "platform feed state behind the committed ClickHouse generation; repairing");
        self.state.record_install(&receipt, false).await.map_err(db_error)?;
        Ok(true)
    }

    /// Verify, accept and install the container at `path` (a private copy in
    /// the work dir). Caller holds the lease.
    async fn install_locked(
        &self,
        path: &Path,
        container_sha: &str,
        source: &str,
        channel: Channel,
        expected: Option<&SignedDescriptor>,
    ) -> Result<Outcome, ConsumerError> {
        self.repair_from_clickhouse().await?;
        // Open ONCE; every later read goes through this verified descriptor.
        let ring = self.ring.clone();
        let file_path = path.to_path_buf();
        let (file, verified) = tokio::task::spawn_blocking(move || payload::open_verified(&file_path, &ring))
            .await
            .map_err(|e| ConsumerError::Install(e.to_string()))??;
        if let Some(expected) = expected {
            if verified.signed() != expected {
                return Err(ConsumerError::Refused(
                    "downloaded bundle differs from the signed descriptor that announced it".into(),
                ));
            }
        }
        let now = Utc::now();
        let d = verified.descriptor().clone();
        let row = self.state.get().await.map_err(db_error)?;
        let installed = installed_descriptor(row.as_ref().and_then(|r| r.signed_descriptor.as_ref()));
        verified.accept_after(installed.as_ref(), now)?;
        if d.produced_at > now + PRODUCED_AT_SKEW {
            return Err(ConsumerError::Refused(
                "bundle was produced in the future (check this host's clock)".into(),
            ));
        }
        let high_water = self
            .loader
            .high_water()
            .await
            .map_err(|e| ConsumerError::Install(format!("reading revision high-water: {e:#}")))?;
        check_high_water(&d, &high_water)?;
        let previous_feeds = row.as_ref().map(|r| r.feeds.clone()).unwrap_or_default();
        if is_current(installed.as_ref(), &previous_feeds, &d, now) {
            self.retry_activation(row.as_ref().is_some_and(|r| r.activation_pending)).await;
            self.state.record_check("current", None, now).await.map_err(db_error)?;
            return Ok(Outcome::Current { sequence: d.sequence });
        }
        let (wanted, skip) = plan_feeds(&d, now);
        // Re-installing the SAME descriptor (a feed became wanted again, e.g.
        // IPinfo that an install from before NAN-4959 withdrew for a BYO
        // token): feeds already active
        // keep their committed generation and are not reloaded under it.
        let same = installed.as_ref() == Some(&d);
        let kept: BTreeMap<String, u64> = if same {
            previous_feeds
                .iter()
                .filter(|(feed, install)| install.active && wanted.contains_key(*feed))
                .map(|(feed, install)| (feed.clone(), install.loaded))
                .collect()
        } else {
            BTreeMap::new()
        };
        let load: BTreeMap<_, _> = wanted
            .iter()
            .filter(|(feed, _)| !kept.contains_key(*feed))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let sections = payload::sections(&file, &verified)
            .map_err(|e| ConsumerError::Refused(format!("payload: {e:#}")))?;

        let mut loaded = match self.load(file.clone(), &sections, &d, &load).await {
            Ok(loaded) => loaded,
            Err(error) => {
                // Nothing was committed: the uncommitted generation is invisible.
                self.loader.reclaim().await;
                return Err(error);
            }
        };
        loaded.extend(kept);

        // One commit row per feed: wanted feeds become active; skipped feeds
        // and feeds the previous install had but this bundle dropped withdraw.
        let mut installs = BTreeMap::new();
        for feed in d.feeds.keys() {
            installs.insert(
                feed.clone(),
                FeedInstall {
                    loaded: loaded.get(feed).copied().unwrap_or(0),
                    active: wanted.contains_key(feed),
                    detail: skip.get(feed).cloned(),
                },
            );
        }
        let receipt = InstallReceipt {
            signed_descriptor: serde_json::to_value(verified.signed())
                .map_err(|e| ConsumerError::Install(e.to_string()))?,
            sequence: d.sequence,
            payload_sha256: d.payload.sha256.clone(),
            container_sha256: container_sha.to_string(),
            source: source.to_string(),
            channel: channel.as_str().to_string(),
            installed_at: now,
            feeds: installs,
        };
        let receipt_json = serde_json::to_string(&receipt).map_err(|e| ConsumerError::Install(e.to_string()))?;
        let committed_at = Utc::now().timestamp_millis();
        let mut commits = Vec::new();
        for (feed, entry) in &d.feeds {
            commits.push(CommitRow {
                sequence: d.sequence,
                feed_id: feed.clone(),
                storage_key: if wanted.contains_key(feed) {
                    loader::storage_key(feed, d.sequence)
                } else {
                    String::new()
                },
                revision: entry.revision,
                hard_expiry: entry.hard_expiry.timestamp_millis(),
                committed_at,
                receipt: receipt_json.clone(),
            });
        }
        for feed in previous_feeds.keys().filter(|f| !d.feeds.contains_key(*f)) {
            commits.push(CommitRow {
                sequence: d.sequence,
                feed_id: feed.clone(),
                storage_key: String::new(),
                revision: 0,
                hard_expiry: committed_at,
                committed_at,
                receipt: receipt_json.clone(),
            });
        }
        // The commit point: one atomic ClickHouse insert carrying the receipt.
        self.fenced_commit(&commits, "commit").await?;
        // PostgreSQL is a cache of the committed receipt; if this write fails,
        // the next locked operation repairs it from ClickHouse first.
        if let Err(error) = self.state.record_install(&receipt, true).await {
            tracing::warn!(%error, "platform feed install committed but not recorded; it is repaired from ClickHouse on the next run");
        }
        tracing::info!(
            sequence = d.sequence,
            channel = channel.as_str(),
            source,
            loaded = ?loaded,
            "platform feed bundle installed"
        );
        self.loader.reclaim().await;
        let ip_changed = d.feeds.contains_key(IPINFO_FEED) || previous_feeds.contains_key(IPINFO_FEED);
        let activated = self.loader.activate(ip_changed, true).await;
        let _ = self.state.set_activation_pending(!activated).await;
        Ok(Outcome::Installed {
            sequence: d.sequence,
            loaded,
        })
    }

    /// Retry a dictionary activation that did not complete on every node.
    async fn retry_activation(&self, pending: bool) {
        if pending {
            let activated = self.loader.activate(true, true).await;
            let _ = self.state.set_activation_pending(!activated).await;
        }
    }

    async fn load(
        &self,
        file: Arc<std::fs::File>,
        sections: &payload::Sections,
        d: &Descriptor,
        load: &BTreeMap<String, portable::FeedEntry>,
    ) -> Result<BTreeMap<String, u64>, ConsumerError> {
        let mut loaded = BTreeMap::new();
        if load.contains_key(IPINFO_FEED) {
            let rows = self
                .loader
                .load_ipinfo(
                    &file,
                    sections,
                    &loader::storage_key(IPINFO_FEED, d.sequence),
                    load[IPINFO_FEED].row_count,
                )
                .await
                .map_err(|e| ConsumerError::Install(format!("IPinfo: {e:#}")))?;
            loaded.insert(IPINFO_FEED.to_string(), rows);
        }
        let ioc_feeds: BTreeMap<_, _> = load
            .iter()
            .filter(|(feed, _)| feed.as_str() != IPINFO_FEED)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if !ioc_feeds.is_empty() {
            let (counts, skipped) = self
                .loader
                .load_iocs(file, sections, d, &ioc_feeds)
                .await
                .map_err(|e| ConsumerError::Install(format!("IOC feeds: {e:#}")))?;
            if skipped > 0 {
                tracing::info!(skipped, "platform feed IOC rows not loaded (unmatchable type or already expired)");
            }
            for feed in ioc_feeds.keys() {
                loaded.insert(feed.clone(), counts.get(feed).copied().unwrap_or(0));
            }
        }
        Ok(loaded)
    }

    /// Repair from ClickHouse, withdraw installed feeds that passed their hard
    /// expiry, and retry an
    /// incomplete activation. No network. Returns whether anything changed.
    pub async fn reconcile(&self) -> Result<bool, ConsumerError> {
        let lease = self.lease().await?;
        let result = self.reconcile_locked().await;
        lease.release().await;
        result
    }

    async fn reconcile_locked(&self) -> Result<bool, ConsumerError> {
        let repaired = self.repair_from_clickhouse().await?;
        let Some(row) = self.state.get().await.map_err(db_error)? else {
            return Ok(repaired);
        };
        let Some(d) = installed_descriptor(row.signed_descriptor.as_ref()) else {
            return Ok(repaired);
        };
        let now = Utc::now();
        let (load, skip) = plan_feeds(&d, now);
        let mut feeds = row.feeds.clone();
        let mut withdrawn = Vec::new();
        for (feed, install) in feeds.iter_mut() {
            if install.active && !load.contains_key(feed) {
                install.active = false;
                install.detail = skip.get(feed).cloned();
                withdrawn.push(feed.clone());
            }
        }
        if withdrawn.is_empty() {
            self.retry_activation(row.activation_pending).await;
            return Ok(repaired);
        }
        let receipt = InstallReceipt {
            signed_descriptor: row.signed_descriptor.clone().unwrap_or_default(),
            sequence: d.sequence,
            payload_sha256: row.payload_sha256.clone().unwrap_or_default(),
            container_sha256: row.container_sha256.clone().unwrap_or_default(),
            source: row.source.clone().unwrap_or_default(),
            channel: row.channel.clone().unwrap_or_default(),
            installed_at: row.installed_at.unwrap_or(now),
            feeds,
        };
        let receipt_json = serde_json::to_string(&receipt).map_err(|e| ConsumerError::Install(e.to_string()))?;
        let committed_at = now.timestamp_millis();
        let commits: Vec<CommitRow> = withdrawn
            .iter()
            .map(|feed| CommitRow {
                sequence: d.sequence,
                feed_id: feed.clone(),
                storage_key: String::new(),
                revision: d.feeds.get(feed).map_or(0, |e| e.revision),
                hard_expiry: d.feeds.get(feed).map_or(committed_at, |e| e.hard_expiry.timestamp_millis()),
                committed_at,
                receipt: receipt_json.clone(),
            })
            .collect();
        self.fenced_commit(&commits, "withdraw").await?;
        if let Err(error) = self.state.record_install(&receipt, false).await {
            tracing::warn!(%error, "platform feed withdrawal committed but not recorded; repaired on the next run");
        }
        tracing::info!(feeds = ?withdrawn, "platform feeds withdrawn (past hard expiry)");
        self.loader.reclaim().await;
        let ip = withdrawn.iter().any(|f| f == IPINFO_FEED);
        let activated = self.loader.activate(ip, withdrawn.iter().any(|f| f != IPINFO_FEED)).await;
        let _ = self.state.set_activation_pending(!activated).await;
        Ok(true)
    }

    /// The leader-only loop: an online check at start-up and every poll
    /// interval (sooner after a failure), and a repair / expiry / activation
    /// reconcile every few minutes (also in air-gap mode).
    pub fn start(self: Arc<Self>, shutdown: ShutdownToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!(config = ?self.config, "platform feed consumer started (leader-only)");
            match self.loader.foreign_named_rows().await {
                Ok(0) => {}
                Ok(n) => tracing::warn!(
                    rows = n,
                    "custom_enrichment_results has {n} pre-existing row(s) in a `platform_feed/…` namespace not written by the \
                     feed loader; they stay visible and are never reclaimed (ownership is the platform_feed column, not the name)"
                ),
                Err(error) => tracing::warn!(%error, "could not check for pre-existing platform_feed namespaces"),
            }
            let mut next_check = tokio::time::Instant::now() + Duration::from_secs(30);
            let mut reconcile = tokio::time::interval(Duration::from_secs(RECONCILE_SECS));
            reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep_until(next_check), if self.config.auto_update => {
                        if !self.fence.still_leader(self.state.pool()).await {
                            next_check = tokio::time::Instant::now() + Duration::from_secs(RETRY_SECS);
                            continue;
                        }
                        let ok = match self.check_online().await {
                            Ok(outcome) => {
                                tracing::info!(?outcome, "platform feed check");
                                true
                            }
                            Err(ConsumerError::Busy) => true,
                            Err(_) => false,
                        };
                        let wait = if ok {
                            self.config.poll_interval
                        } else {
                            self.config.poll_interval.min(Duration::from_secs(RETRY_SECS))
                        };
                        next_check = tokio::time::Instant::now() + wait;
                    }
                    _ = reconcile.tick() => {
                        if !self.fence.still_leader(self.state.pool()).await {
                            continue;
                        }
                        match self.reconcile().await {
                            Ok(_) | Err(ConsumerError::Busy) => {}
                            Err(error) => tracing::warn!(%error, "platform feed reconcile failed"),
                        }
                        // NAN-4957: the IP geo pair has no LIFETIME; pick up a
                        // staging refresh (the feed's activation, the 6 h view
                        // cadence) by reloading both halves as one generation.
                        match self.loader.reload_ip_geo_if_stale().await {
                            Ok(true) => tracing::info!("IP geo dictionaries reloaded after a staging refresh"),
                            Ok(false) => {}
                            Err(error) => tracing::warn!(error = %format!("{error:#}"), "IP geo dictionary reload failed; retried next tick"),
                        }
                    }
                }
            }
        })
    }
}

/// Per-feed rollback fence that survives a feed being omitted for a while:
/// every feed's revision must be at least the highest revision ever committed
/// for it (NAN-4948 review P2).
pub fn check_high_water(d: &Descriptor, high_water: &BTreeMap<String, i64>) -> Result<(), ConsumerError> {
    for (feed, entry) in &d.feeds {
        if let Some(hw) = high_water.get(feed) {
            if entry.revision < *hw {
                return Err(ConsumerError::Refused(format!(
                    "{feed} revision {} is older than revision {hw} committed before (rollback)",
                    entry.revision
                )));
            }
        }
    }
    Ok(())
}

fn db_error(error: sqlx::Error) -> ConsumerError {
    ConsumerError::Install(format!("database: {error}"))
}

/// Copy `src` (a regular file, not a symlink) into `dest` (new, 0600),
/// returning its SHA-256. Bounded by the container size.
fn stage_copy(src: &Path, dest: &Path) -> Result<String, ConsumerError> {
    use std::io::Read;
    let refused = |m: &str| ConsumerError::Refused(m.to_string());
    let meta = std::fs::symlink_metadata(src)
        .map_err(|e| ConsumerError::Install(format!("bundle file: {e}")))?;
    if !meta.file_type().is_file() {
        return Err(refused("bundle file must be a regular file"));
    }
    if meta.len() > MAX_CONTAINER_BYTES {
        return Err(refused("bundle file exceeds the container size bound"));
    }
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(src)
        .map_err(|e| ConsumerError::Install(format!("bundle file: {e}")))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dest)
        .map_err(|e| ConsumerError::Install(format!("staging: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|e| ConsumerError::Install(format!("bundle file: {e}")))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_CONTAINER_BYTES {
            return Err(refused("bundle file exceeds the container size bound"));
        }
        hasher.update(&buffer[..n]);
        output
            .write_all(&buffer[..n])
            .map_err(|e| ConsumerError::Install(format!("staging: {e}")))?;
    }
    output
        .sync_all()
        .map_err(|e| ConsumerError::Install(format!("staging: {e}")))?;
    Ok(hex::encode(hasher.finalize()))
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
