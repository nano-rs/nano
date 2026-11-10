// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ingest token lifecycle + Vector file publication + "last used" sampling.

use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::known_public_secrets::{is_known_public, SecretKind};

use super::{
    generate_token, normalize_name, otlp_identity_assertion, parse_credential_request_counts,
    render_tokens_file, secret_from_env, TokenDelivery, OTLP_ASSERTION_TTL_SECS,
    OTLP_EDGE_KEY_ENV, PLATFORM_TOKEN_ENV, TOKENS_DELIVERY_ENV, sha256_hex, write_tokens_file, BindableSource, BindableSourceCredential,
    IngestToken, IngestTokenRepository, IngestTokenRepositoryError, IngestTokenSettings,
    InstallTokenMode, TokenFileEntry, DEFAULT_TOKENS_FILE, INSTALL_CREDENTIAL_ID,
    MULTIPLEX_ROUTE, PLATFORM_PULL_CREDENTIAL_ID,
};

/// How often the background task re-publishes the file (a no-op when it is
/// current) and samples Vector's per-credential counter.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_VECTOR_METRICS_URL: &str = "http://vector:9598/metrics";
/// The shipped Vector sources check their hashed-token file at most once every
/// two seconds. After removing a credential from a shared-volume file, wait a
/// full interval (plus a small scheduling margin) before reporting success so
/// no request can arrive after the API response with a pre-write snapshot.
pub(super) const SHARED_VOLUME_REMOVAL_SETTLE: Duration =
    Duration::from_millis(2_100);
/// A pending rotation replacement older than this is purged by the reconcile.
pub const ROTATION_PENDING_TTL: Duration = Duration::from_secs(600);

#[derive(Error, Debug)]
pub enum IngestTokenServiceError {
    #[error("{0}")]
    InvalidName(String),
    #[error("ingest token not found")]
    NotFound,
    #[error("ingest token is already revoked")]
    AlreadyRevoked,
    /// The requested source does not exist or cannot receive pushed events.
    #[error("{0}")]
    InvalidSource(String),
    /// The token is already bound to a source; a binding never changes (revoke
    /// and issue a new token instead).
    #[error("ingest token is already bound to a source")]
    AlreadyBound,
    /// Rotation needs an active, bound token with no rotation in flight.
    #[error("only an active, bound ingest token can be rotated")]
    NotRotatable,
    /// This deployment has no path delivering the tokens file to Vector
    /// (`NANO_INGEST_TOKENS_DELIVERY` unset), so a token would be refused.
    #[error("ingest token delivery to Vector is not configured for this deployment")]
    DeliveryNotConfigured,
    #[error(transparent)]
    Repository(#[from] IngestTokenRepositoryError),
    /// Writing Vector's tokens file failed. The message names the path only.
    #[error("could not publish the Vector ingest tokens file {path}: {error}")]
    Publish { path: String, error: String },
}

pub struct IngestTokenService {
    repo: IngestTokenRepository,
    tokens_file: PathBuf,
    metrics_url: String,
    /// The install token (`VECTOR_AUTH_TOKEN`), to list its hash. Never logged.
    install_token: Option<String>,
    /// The platform credential (`NANO_PLATFORM_INGEST_TOKEN`). Never logged.
    platform_token: Option<String>,
    /// The OTLP edge signing key (`NANO_OTLP_EDGE_KEY`). Never logged.
    edge_key: Option<String>,
    delivery: TokenDelivery,
    http: reqwest::Client,
    /// Serialises read-render-write so two writers never publish stale state.
    publish_lock: Mutex<()>,
}

impl IngestTokenService {
    /// The file path comes from `NANO_INGEST_TOKENS_FILE`, the metrics URL
    /// from `VECTOR_METRICS_URL` (both with the compose defaults).
    pub fn new(pool: PgPool) -> Self {
        let tokens_file = std::env::var("NANO_INGEST_TOKENS_FILE")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_TOKENS_FILE.to_string());
        let metrics_url = std::env::var("VECTOR_METRICS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_VECTOR_METRICS_URL.to_string());
        Self::with_paths(
            pool,
            PathBuf::from(tokens_file),
            metrics_url,
            std::env::var("VECTOR_AUTH_TOKEN").ok(),
        )
        .with_platform_token(secret_from_env(PLATFORM_TOKEN_ENV))
        .with_edge_key(secret_from_env(OTLP_EDGE_KEY_ENV))
        .with_delivery(TokenDelivery::parse(
            std::env::var(TOKENS_DELIVERY_ENV).ok().as_deref(),
        ))
    }

    /// A service writing `tokens_file` directly (delivery `shared_volume`),
    /// with no platform credential or edge key; see the `with_*` builders.
    pub fn with_paths(
        pool: PgPool,
        tokens_file: PathBuf,
        metrics_url: String,
        install_token: Option<String>,
    ) -> Self {
        Self {
            repo: IngestTokenRepository::new(pool),
            tokens_file,
            metrics_url,
            install_token: install_token.filter(|token| !token.trim().is_empty()),
            platform_token: None,
            edge_key: None,
            delivery: TokenDelivery::SharedVolume,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            publish_lock: Mutex::new(()),
        }
    }

    pub fn with_platform_token(mut self, token: Option<String>) -> Self {
        self.platform_token = token.filter(|t| !t.trim().is_empty());
        self
    }

    pub fn with_edge_key(mut self, key: Option<String>) -> Self {
        self.edge_key = key.filter(|k| !k.trim().is_empty());
        self
    }

    pub fn with_delivery(mut self, delivery: TokenDelivery) -> Self {
        self.delivery = delivery;
        self
    }

    pub fn tokens_file(&self) -> &std::path::Path {
        &self.tokens_file
    }

    pub fn delivery(&self) -> TokenDelivery {
        self.delivery
    }

    fn require_delivery(&self) -> Result<(), IngestTokenServiceError> {
        match self.delivery {
            TokenDelivery::SharedVolume | TokenDelivery::Http => Ok(()),
            TokenDelivery::None => Err(IngestTokenServiceError::DeliveryNotConfigured),
        }
    }

    /// Refuses with [`IngestTokenServiceError::DeliveryNotConfigured`] when this
    /// deployment has no path delivering the tokens file to Vector.
    pub fn ensure_delivery(&self) -> Result<(), IngestTokenServiceError> {
        self.require_delivery()
    }

    /// One token, as listed (never its value or hash).
    pub async fn get(&self, id: Uuid) -> Result<Option<IngestToken>, IngestTokenServiceError> {
        Ok(self.repo.get(id).await?)
    }

    pub async fn list(&self) -> Result<Vec<IngestToken>, IngestTokenServiceError> {
        Ok(self.repo.list().await?)
    }

    pub async fn settings(&self) -> Result<IngestTokenSettings, IngestTokenServiceError> {
        Ok(self.repo.settings().await?)
    }

    /// OTLP requires a credential bound to an enabled push source. Logs use
    /// that source's parser; traces/metrics retain their native signal types.
    /// No positive cache: revocation and the install switch apply on the next
    /// request. The install token is accepted only while enabled and bound
    /// (OTLP has no declared source type to multiplex on).
    pub async fn authenticate_otlp(
        &self,
        token: &str,
    ) -> Result<Option<BindableSourceCredential>, IngestTokenServiceError> {
        if token.is_empty() || token.len() > 4096 {
            return Ok(None);
        }
        let hash = sha256_hex(token);
        if self
            .install_token
            .as_deref()
            .is_some_and(|install| constant_time_eq(sha256_hex(install).as_bytes(), hash.as_bytes()))
        {
            // NAN-5013: a publicly known install token never authenticates.
            if self.install_token_is_public() {
                return Ok(None);
            }
            let settings = self.settings().await?;
            if settings.install_token_enabled
                && settings.install_token_mode == InstallTokenMode::Strict
            {
                if let Some(source) = self.install_token_source(&settings).await? {
                    if source.enabled {
                        return Ok(Some(BindableSourceCredential {
                            id: INSTALL_CREDENTIAL_ID,
                            route: source.route_key,
                        }));
                    }
                }
            }
            return Ok(None);
        }
        Ok(self.repo.otlp_credential(&hash).await?)
    }

    /// The signed, short-lived identity assertion the OTLP edge forwards
    /// ([`otlp_identity_assertion`]); `None` without an edge key, in which
    /// case Vector cannot verify an identity and keeps OTLP logs as `otlp_log`.
    pub fn otlp_identity_assertion(&self, credential: &BindableSourceCredential) -> Option<String> {
        let expires = Utc::now().timestamp() + OTLP_ASSERTION_TTL_SECS;
        self.edge_key
            .as_deref()
            .and_then(|key| otlp_identity_assertion(key, &credential.id, &credential.route, expires))
    }

    /// Whether an install token is configured (`VECTOR_AUTH_TOKEN` non-blank).
    pub fn install_token_configured(&self) -> bool {
        self.install_token.is_some()
    }

    /// Whether the install token is a value nano shipped as a default or
    /// example (NAN-5013). Such a token is refused on every ingest lane:
    /// it is never listed in Vector's tokens file and never authenticates OTLP.
    pub fn install_token_is_public(&self) -> bool {
        self.install_token
            .as_deref()
            .is_some_and(|token| is_known_public(SecretKind::VectorInstallToken, token))
    }

    /// The log sources a token can be bound to.
    pub async fn bindable_sources(&self) -> Result<Vec<BindableSource>, IngestTokenServiceError> {
        Ok(self.repo.bindable_sources().await?)
    }

    /// The install token's bound source, when it still exists and can receive
    /// pushed events (`None` = unbound).
    pub async fn install_token_source(
        &self,
        settings: &IngestTokenSettings,
    ) -> Result<Option<BindableSource>, IngestTokenServiceError> {
        match settings.install_token_source_id {
            Some(id) => Ok(self.repo.bindable_source(id).await?),
            None => Ok(None),
        }
    }

    async fn require_source(&self, source_id: Uuid) -> Result<BindableSource, IngestTokenServiceError> {
        self.repo.bindable_source(source_id).await?.ok_or_else(|| {
            IngestTokenServiceError::InvalidSource(
                "Source not found, or it cannot receive pushed events (pulled sources take no ingest token)"
                    .into(),
            )
        })
    }

    /// Issues a token bound to `source_id` and publishes it to Vector. Returns
    /// the token and its value; the value is not stored anywhere and cannot be
    /// read again. If the file cannot be written the token is revoked again
    /// and the call fails, so an admin never holds a value Vector would refuse.
    pub async fn create(
        &self,
        name: &str,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<(IngestToken, String), IngestTokenServiceError> {
        let name = normalize_name(name).map_err(IngestTokenServiceError::InvalidName)?;
        self.require_delivery()?;
        self.require_source(source_id).await?;
        let generated = generate_token();
        let token = self
            .repo
            .create(&name, &generated.prefix, &generated.sha256_hex, source_id, actor)
            .await?;
        if let Err(error) = self.publish().await {
            let _ = self.repo.revoke(token.credential_id, actor).await;
            return Err(error);
        }
        Ok((token, generated.value))
    }

    /// Rotates a token in two phases so a publish failure never strands a
    /// sender: (1) a pending replacement with the same name and source is
    /// inserted and published next to the still-active old token; (2) only
    /// then is the old token revoked and the replacement activated. If phase 1
    /// cannot be published the replacement is deleted and the old token keeps
    /// working. If the phase-2 publish fails, the replacement is already live
    /// in Vector and the reconcile drops the old hash. Returns
    /// `(old, new, value)`.
    pub async fn rotate(
        &self,
        id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<(IngestToken, IngestToken, String), IngestTokenServiceError> {
        self.require_delivery()?;
        let current = self.repo.get(id).await?.ok_or(IngestTokenServiceError::NotFound)?;
        match current.state.as_str() {
            "revoked" => return Err(IngestTokenServiceError::AlreadyRevoked),
            "unbound" => return Err(IngestTokenServiceError::NotRotatable),
            _ => {}
        }
        let generated = generate_token();
        let pending = self
            .repo
            .rotate_begin(id, &generated.prefix, &generated.sha256_hex, actor)
            .await?
            .ok_or(IngestTokenServiceError::NotRotatable)?;
        if let Err(error) = self.publish().await {
            let _ = self.repo.rotate_abort(pending.credential_id).await;
            // Best effort: drop the pending hash from the file if it landed.
            let _ = self.publish().await;
            return Err(error);
        }
        let (old, new) = self
            .repo
            .rotate_commit(id, pending.credential_id, actor)
            .await?
            .ok_or(IngestTokenServiceError::NotRotatable)?;
        match self.publish().await {
            Ok(_) => self.settle_shared_volume_removal().await,
            Err(error) => {
                tracing::warn!(%error, "rotation committed; the old token leaves Vector's file on the next reconcile");
            }
        }
        Ok((old, new, generated.value))
    }

    /// Revokes a token and publishes the shrunken file. On a publish failure
    /// the token stays revoked in the database and the call fails; the
    /// background reconcile retries every [`RECONCILE_INTERVAL`].
    pub async fn revoke(
        &self,
        id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<IngestToken, IngestTokenServiceError> {
        let token = match self.repo.revoke(id, actor).await? {
            Some(token) => token,
            None => {
                return Err(match self.repo.get(id).await? {
                    Some(_) => IngestTokenServiceError::AlreadyRevoked,
                    None => IngestTokenServiceError::NotFound,
                });
            }
        };
        self.publish().await?;
        self.settle_shared_volume_removal().await;
        Ok(token)
    }

    /// Vector's file cache is request-driven: a source that checked just
    /// before the atomic replace may keep that snapshot for the configured
    /// two-second interval. Waiting here makes a successful destructive API
    /// response a propagation boundary without changing Vector to stat the
    /// file on every ingest request. HTTP delivery has a separate sidecar
    /// polling contract, so this barrier applies only to the direct shared
    /// volume used by compose and local-stack.
    async fn settle_shared_volume_removal(&self) {
        if self.delivery == TokenDelivery::SharedVolume {
            tokio::time::sleep(SHARED_VOLUME_REMOVAL_SETTLE).await;
        }
    }

    /// Binds an unbound token (its source was deleted) and publishes it, so
    /// Vector accepts it from now on. A bound token is never rebound:
    /// [`IngestTokenServiceError::AlreadyBound`].
    pub async fn bind(
        &self,
        id: Uuid,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<IngestToken, IngestTokenServiceError> {
        let current = self.repo.get(id).await?.ok_or(IngestTokenServiceError::NotFound)?;
        match current.state.as_str() {
            "revoked" => return Err(IngestTokenServiceError::AlreadyRevoked),
            "active" => return Err(IngestTokenServiceError::AlreadyBound),
            _ => {}
        }
        self.require_delivery()?;
        self.require_source(source_id).await?;
        let token = self
            .repo
            .bind(id, current.source_id, source_id, actor)
            .await?
            .ok_or(IngestTokenServiceError::AlreadyBound)?;
        self.publish().await?;
        Ok(token)
    }

    /// Binds the install token (while it is unbound) and publishes it. This
    /// also leaves legacy multiplex mode: a bound install token is strict.
    pub async fn bind_install_token(
        &self,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenServiceError> {
        let settings = self.repo.settings().await?;
        if self.install_token_source(&settings).await?.is_some() {
            return Err(IngestTokenServiceError::AlreadyBound);
        }
        self.require_delivery()?;
        self.require_source(source_id).await?;
        let settings = self
            .repo
            .bind_install_token(settings.install_token_source_id, source_id, actor)
            .await?
            .ok_or(IngestTokenServiceError::AlreadyBound)?;
        self.publish().await?;
        Ok(settings)
    }

    pub async fn set_install_token_enabled(
        &self,
        enabled: bool,
        actor: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenServiceError> {
        let settings = self.repo.set_install_token_enabled(enabled, actor).await?;
        self.publish().await?;
        Ok(settings)
    }

    /// Leaves the deprecated legacy multiplex mode (one-way). An unbound
    /// install token is then refused until an admin binds it.
    pub async fn set_install_token_strict(
        &self,
        actor: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenServiceError> {
        let settings = self.repo.set_install_token_strict(actor).await?;
        self.publish().await?;
        Ok(settings)
    }

    /// Renders the current state into Vector's file. `Ok(true)` when the file
    /// changed. Never logs the content.
    pub async fn publish(&self) -> Result<bool, IngestTokenServiceError> {
        if self.delivery != TokenDelivery::SharedVolume {
            // `none`: nothing reads a file here; Vector's static fallback stays
            // closed unless the deployment opts in on the Vector side.
            // `http`: Vector pulls the rendered content per request
            // (`render_current`), there is no file to keep converged.
            return Ok(false);
        }
        let _guard = self.publish_lock.lock().await;
        let (content, entries, settings, install_source) = self.render_state().await?;
        let path = self.tokens_file.clone();
        let changed = tokio::task::spawn_blocking(move || write_tokens_file(&path, &content))
            .await
            .map_err(|error| self.publish_error(error.to_string()))?
            .map_err(|error| self.publish_error(error.to_string()))?;
        if changed {
            tracing::info!(
                path = %self.tokens_file.display(),
                listed_credentials = entries.len(),
                install_token_enabled = settings.install_token_enabled,
                install_token_mode = settings.install_token_mode.as_str(),
                install_token_bound = install_source.is_some(),
                "published ingest tokens file"
            );
        }
        Ok(changed)
    }

    /// The tokens file content for the current database state, for the
    /// `http` delivery (NAN-4973): each Vector pod's config consumer pulls it
    /// from the internal delivery endpoint. Refused unless the delivery is
    /// `http`, so a deployment that never opted in does not expose it.
    pub async fn render_current(&self) -> Result<String, IngestTokenServiceError> {
        if self.delivery != TokenDelivery::Http {
            return Err(IngestTokenServiceError::DeliveryNotConfigured);
        }
        Ok(self.render_state().await?.0)
    }

    /// Renders the file content plus what `publish` logs about it.
    async fn render_state(
        &self,
    ) -> Result<
        (String, Vec<TokenFileEntry>, IngestTokenSettings, Option<BindableSource>),
        IngestTokenServiceError,
    > {
        let mut entries = self.repo.active_entries().await?;
        let settings = self.repo.settings().await?;
        let install_source = self.install_token_source(&settings).await?;
        entries.extend(file_extra_entries(
            self.install_token.as_deref(),
            self.platform_token.as_deref(),
            &settings,
            install_source.as_ref(),
        ));
        // The sources' static install-token fallback stays on only with no
        // install token at all (the explicit VECTOR_ALLOW_UNAUTHENTICATED_INGEST
        // opt-in). Otherwise every accepted token is a listed entry, including
        // the install token in legacy multiplex mode.
        let content = render_tokens_file(&entries, self.install_token.is_none());
        Ok((content, entries, settings, install_source))
    }

    fn publish_error(&self, error: String) -> IngestTokenServiceError {
        IngestTokenServiceError::Publish {
            path: self.tokens_file.display().to_string(),
            error,
        }
    }

    /// Samples Vector's per-credential counter and records each named
    /// token's request count and "last used" (see
    /// [`IngestTokenRepository::record_usage`]). Returns how many were used.
    pub async fn sample_usage(&self) -> Result<u64, String> {
        let text = self
            .http
            .get(&self.metrics_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| error.to_string())?
            .text()
            .await
            .map_err(|error| error.to_string())?;
        let counts: Vec<(Uuid, f64)> = parse_credential_request_counts(&text)
            .into_iter()
            .filter(|(id, _)| *id != INSTALL_CREDENTIAL_ID && *id != PLATFORM_PULL_CREDENTIAL_ID)
            .collect();
        self.repo
            .record_usage(&counts, Utc::now())
            .await
            .map_err(|error| error.to_string())
    }

    /// Background loop: publish (so the file converges on the database even
    /// after a failed write or a wiped volume) and sample usage.
    pub fn spawn_reconcile(self: std::sync::Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut warned_metrics = false;
            loop {
                if let Err(error) = self.repo.purge_stale_pending(ROTATION_PENDING_TTL).await {
                    tracing::warn!(%error, "purging stale pending rotations failed");
                }
                if let Err(error) = self.publish().await {
                    tracing::warn!(%error, "ingest tokens file reconcile failed");
                }
                match self.sample_usage().await {
                    Ok(_) => warned_metrics = false,
                    Err(error) if !warned_metrics => {
                        warned_metrics = true;
                        tracing::warn!(%error, "ingest token usage sampling failed (Vector metrics)");
                    }
                    Err(_) => {}
                }
                tokio::time::sleep(RECONCILE_INTERVAL).await;
            }
        })
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The entries nano adds beside the named tokens:
/// * the install token while enabled, routed on its bound source in strict
///   mode, or listed as a multiplex credential in legacy multiplex mode. A
///   publicly known install token (`nanosiem-default-token`, a `CHANGE_ME*`
///   placeholder, ...) is never listed in either mode (NAN-5013): anyone can
///   send it. The sources' static fallback stays off too (the caller passes
///   `fallback_enabled = false` whenever an install token is set), so Vector
///   answers it with 401;
/// * the platform credential (its own random secret, never derived from the
///   install token) whenever one is configured.
pub fn file_extra_entries(
    install_token: Option<&str>,
    platform_token: Option<&str>,
    settings: &IngestTokenSettings,
    install_source: Option<&BindableSource>,
) -> Vec<TokenFileEntry> {
    let mut entries = Vec::with_capacity(2);
    let listable_install =
        install_token.filter(|token| !is_known_public(SecretKind::VectorInstallToken, token));
    if let (Some(install_token), true) = (listable_install, settings.install_token_enabled) {
        let route = match (settings.install_token_mode, install_source) {
            (InstallTokenMode::LegacyMultiplex, _) => Some(MULTIPLEX_ROUTE.to_string()),
            (InstallTokenMode::Strict, Some(source)) => Some(source.route_key.clone()),
            (InstallTokenMode::Strict, None) => None,
        };
        if let Some(route) = route {
            entries.push(TokenFileEntry {
                sha256: sha256_hex(install_token),
                id: INSTALL_CREDENTIAL_ID,
                route,
            });
        }
    }
    if let Some(platform) = platform_token.filter(|t| !t.trim().is_empty()) {
        // A platform secret equal to the install token would hand the
        // multiplex credential to every legacy sender: refuse to list it.
        if install_token != Some(platform) {
            entries.push(TokenFileEntry {
                sha256: sha256_hex(platform),
                id: PLATFORM_PULL_CREDENTIAL_ID,
                route: MULTIPLEX_ROUTE.to_string(),
            });
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn preconverged_shared_volume_removal_still_settles_but_http_does_not() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        let dir = tempfile::tempdir().unwrap();
        let tokens_file = dir.path().join("ingest-tokens/tokens.json");
        let removed_state = r#"{"version":1,"fallback_enabled":false,"tokens":[]}"#;

        // Model the reconciler winning the publish lock after the database
        // transition: the destructive API's own publication sees identical
        // bytes (`changed=false`) but must still wait out Vector's old cache.
        assert!(write_tokens_file(&tokens_file, removed_state).unwrap());
        assert!(!write_tokens_file(&tokens_file, removed_state).unwrap());

        let shared = IngestTokenService::with_paths(
            pool.clone(),
            tokens_file.clone(),
            String::new(),
            None,
        );
        let started = tokio::time::Instant::now();
        shared.settle_shared_volume_removal().await;
        assert_eq!(started.elapsed(), SHARED_VOLUME_REMOVAL_SETTLE);

        let http = IngestTokenService::with_paths(pool, tokens_file, String::new(), None)
            .with_delivery(TokenDelivery::Http);
        let started = tokio::time::Instant::now();
        http.settle_shared_volume_removal().await;
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
