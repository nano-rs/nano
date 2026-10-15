// SPDX-License-Identifier: AGPL-3.0-or-later

//! Ingest token lifecycle + Vector file publication + "last used" sampling.

use std::path::PathBuf;
use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Mutex;
use uuid::Uuid;

use super::{
    generate_token, normalize_name, parse_credential_request_counts, platform_pull_token,
    render_tokens_file, sha256_hex, write_tokens_file, BindableSource, IngestToken,
    IngestTokenRepository, IngestTokenRepositoryError, IngestTokenSettings, TokenFileEntry,
    DEFAULT_TOKENS_FILE, INSTALL_CREDENTIAL_ID, PLATFORM_PULL_CREDENTIAL_ID, PLATFORM_PULL_ROUTE,
};

/// How often the background task re-publishes the file (a no-op when it is
/// current) and samples Vector's per-credential counter.
pub const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_VECTOR_METRICS_URL: &str = "http://vector:9598/metrics";

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
    #[error(transparent)]
    Repository(#[from] IngestTokenRepositoryError),
    /// Writing Vector's tokens file failed. The message names the path only.
    #[error("could not publish the Vector ingest tokens file {path}: {error}")]
    Publish { path: String, error: String },
}

pub struct IngestTokenService {
    repo: IngestTokenRepository,
    tenant_id: Uuid,
    tokens_file: PathBuf,
    metrics_url: String,
    /// The install token (`VECTOR_AUTH_TOKEN`), to list its hash once bound and
    /// derive the platform pull credential. Never logged.
    install_token: Option<String>,
    http: reqwest::Client,
    /// Serialises read-render-write so two writers never publish stale state.
    publish_lock: Mutex<()>,
}

impl IngestTokenService {
    /// `tenant_id` is the deployment's tenant (open core: the compatibility
    /// tenant). The file path comes from `NANO_INGEST_TOKENS_FILE`, the metrics
    /// URL from `VECTOR_METRICS_URL` (both with the compose defaults).
    pub fn new(pool: PgPool, tenant_id: Uuid) -> Self {
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
            tenant_id,
            PathBuf::from(tokens_file),
            metrics_url,
            std::env::var("VECTOR_AUTH_TOKEN").ok(),
        )
    }

    pub fn with_paths(
        pool: PgPool,
        tenant_id: Uuid,
        tokens_file: PathBuf,
        metrics_url: String,
        install_token: Option<String>,
    ) -> Self {
        Self {
            repo: IngestTokenRepository::new(pool),
            tenant_id,
            tokens_file,
            metrics_url,
            install_token: install_token.filter(|token| !token.trim().is_empty()),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            publish_lock: Mutex::new(()),
        }
    }

    pub fn tokens_file(&self) -> &std::path::Path {
        &self.tokens_file
    }

    pub async fn list(&self) -> Result<Vec<IngestToken>, IngestTokenServiceError> {
        Ok(self.repo.list(self.tenant_id).await?)
    }

    pub async fn settings(&self) -> Result<IngestTokenSettings, IngestTokenServiceError> {
        Ok(self.repo.settings(self.tenant_id).await?)
    }

    /// Whether an install token is configured (`VECTOR_AUTH_TOKEN` non-blank).
    pub fn install_token_configured(&self) -> bool {
        self.install_token.is_some()
    }

    /// The log sources a token can be bound to.
    pub async fn bindable_sources(&self) -> Result<Vec<BindableSource>, IngestTokenServiceError> {
        Ok(self.repo.bindable_sources().await?)
    }

    /// The install token's bound source, when it still exists and can receive
    /// pushed events (`None` = unbound: refused).
    pub async fn install_token_source(
        &self,
        settings: &IngestTokenSettings,
    ) -> Result<Option<BindableSource>, IngestTokenServiceError> {
        match settings.install_token_source_id {
            Some(id) => Ok(self.repo.bindable_source(id).await?),
            None => Ok(None),
        }
    }

    async fn require_source(
        &self,
        source_id: Uuid,
    ) -> Result<BindableSource, IngestTokenServiceError> {
        self.repo.bindable_source(source_id).await?.ok_or_else(|| {
            IngestTokenServiceError::InvalidSource(
                "Source not found, or it cannot receive pushed events (OTLP and pulled sources take no ingest token)"
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
        self.require_source(source_id).await?;
        let generated = generate_token();
        let token = self
            .repo
            .create(
                self.tenant_id,
                &name,
                &generated.prefix,
                &generated.sha256_hex,
                source_id,
                actor,
            )
            .await?;
        if let Err(error) = self.publish().await {
            let _ = self
                .repo
                .revoke(self.tenant_id, token.credential_id, actor)
                .await;
            return Err(error);
        }
        Ok((token, generated.value))
    }

    /// Revokes a token and publishes the shrunken file. On a publish failure
    /// the token stays revoked in the database and the call fails; the
    /// background reconcile retries every [`RECONCILE_INTERVAL`].
    pub async fn revoke(
        &self,
        id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<IngestToken, IngestTokenServiceError> {
        let token = match self.repo.revoke(self.tenant_id, id, actor).await? {
            Some(token) => token,
            None => {
                return Err(match self.repo.get(self.tenant_id, id).await? {
                    Some(_) => IngestTokenServiceError::AlreadyRevoked,
                    None => IngestTokenServiceError::NotFound,
                });
            }
        };
        self.publish().await?;
        Ok(token)
    }

    /// Binds an unbound token (no source, or its source was deleted) and
    /// publishes it, so Vector accepts it from now on. A bound token is never
    /// rebound: [`IngestTokenServiceError::AlreadyBound`].
    pub async fn bind(
        &self,
        id: Uuid,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<IngestToken, IngestTokenServiceError> {
        let current = self
            .repo
            .get(self.tenant_id, id)
            .await?
            .ok_or(IngestTokenServiceError::NotFound)?;
        match current.state.as_str() {
            "revoked" => return Err(IngestTokenServiceError::AlreadyRevoked),
            "active" => return Err(IngestTokenServiceError::AlreadyBound),
            _ => {}
        }
        self.require_source(source_id).await?;
        let token = self
            .repo
            .bind(self.tenant_id, id, current.source_id, source_id, actor)
            .await?
            .ok_or(IngestTokenServiceError::AlreadyBound)?;
        self.publish().await?;
        Ok(token)
    }

    /// Binds the install token (while it is unbound) and publishes it.
    pub async fn bind_install_token(
        &self,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenServiceError> {
        let settings = self.repo.settings(self.tenant_id).await?;
        if self.install_token_source(&settings).await?.is_some() {
            return Err(IngestTokenServiceError::AlreadyBound);
        }
        self.require_source(source_id).await?;
        let settings = self
            .repo
            .bind_install_token(
                self.tenant_id,
                settings.install_token_source_id,
                source_id,
                actor,
            )
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
        let settings = self
            .repo
            .set_install_token_enabled(self.tenant_id, enabled, actor)
            .await?;
        self.publish().await?;
        Ok(settings)
    }

    /// Renders the current state into Vector's file. `Ok(true)` when the file
    /// changed. Never logs the content.
    pub async fn publish(&self) -> Result<bool, IngestTokenServiceError> {
        let _guard = self.publish_lock.lock().await;
        let mut entries = self.repo.active_entries(self.tenant_id).await?;
        let settings = self.repo.settings(self.tenant_id).await?;
        let install_source = self.install_token_source(&settings).await?;
        entries.extend(file_extra_entries(
            self.install_token.as_deref(),
            settings.install_token_enabled,
            install_source.as_ref(),
        ));
        // NAN-3806: no fallback. The install token is accepted only as a
        // listed (bound) entry; the sources' static fallback stays on only
        // with no install token at all, where it is the explicit
        // VECTOR_ALLOW_UNAUTHENTICATED_INGEST opt-in.
        let content = render_tokens_file(&entries, self.install_token.is_none());
        let path = self.tokens_file.clone();
        let changed = tokio::task::spawn_blocking(move || write_tokens_file(&path, &content))
            .await
            .map_err(|error| self.publish_error(error.to_string()))?
            .map_err(|error| self.publish_error(error.to_string()))?;
        if changed {
            tracing::info!(
                path = %self.tokens_file.display(),
                active_tokens = entries.len(),
                install_token_enabled = settings.install_token_enabled,
                install_token_bound = install_source.is_some(),
                "published ingest tokens file"
            );
        }
        Ok(changed)
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
            .record_usage(self.tenant_id, &counts, Utc::now())
            .await
            .map_err(|error| error.to_string())
    }

    /// Background loop: publish (so the file converges on the database even
    /// after a failed write or a wiped volume) and sample usage.
    pub fn spawn_reconcile(self: std::sync::Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut warned_metrics = false;
            loop {
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

/// The entries nano adds beside the named tokens: the install token while it
/// is enabled and bound, and the platform pull credential whenever an install
/// token is configured.
fn file_extra_entries(
    install_token: Option<&str>,
    install_token_enabled: bool,
    install_source: Option<&BindableSource>,
) -> Vec<TokenFileEntry> {
    let Some(install_token) = install_token else {
        return Vec::new();
    };
    let mut entries = Vec::with_capacity(2);
    if let (true, Some(source)) = (install_token_enabled, install_source) {
        entries.push(TokenFileEntry {
            sha256: sha256_hex(install_token),
            id: INSTALL_CREDENTIAL_ID,
            route: source.route_key.clone(),
        });
    }
    if let Some(pull) = platform_pull_token(install_token) {
        entries.push(TokenFileEntry {
            sha256: sha256_hex(&pull),
            id: PLATFORM_PULL_CREDENTIAL_ID,
            route: PLATFORM_PULL_ROUTE.to_string(),
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(route: &str) -> BindableSource {
        BindableSource {
            source_id: Uuid::from_u128(7),
            name: "Apache".into(),
            source_type: "routed".into(),
            route_key: route.into(),
            enabled: true,
        }
    }

    #[test]
    fn install_token_is_listed_only_while_enabled_and_bound() {
        let bound = source("apache_access");
        let entries = file_extra_entries(Some("install"), true, Some(&bound));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, INSTALL_CREDENTIAL_ID);
        assert_eq!(entries[0].sha256, sha256_hex("install"));
        assert_eq!(entries[0].route, "apache_access");
        assert_eq!(entries[1].id, PLATFORM_PULL_CREDENTIAL_ID);
        assert_eq!(entries[1].route, PLATFORM_PULL_ROUTE);
        assert_ne!(entries[1].sha256, sha256_hex("install"));

        // Unbound or disabled: refused (not listed); the platform pull stays.
        for entries in [
            file_extra_entries(Some("install"), true, None),
            file_extra_entries(Some("install"), false, Some(&bound)),
        ] {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, PLATFORM_PULL_CREDENTIAL_ID);
        }
        // No install token: nothing to list.
        assert!(file_extra_entries(None, true, Some(&bound)).is_empty());
    }
}
