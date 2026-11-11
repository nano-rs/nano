// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4936: isolate a pull source before it can reach the live topology,
//! quarantine it when it cannot build, and report the activation outcome.
//!
//! See [`crate::source_configs::isolation`] for the failure this prevents.

use super::{SourceConfigService, SourceConfigServiceError};
use crate::parsers::{redact_config_snapshot, ActivationOutcome, ReloadWatch};
use crate::source_configs::isolation::{self, IsolationOutcome, IsolationRunner};
use crate::source_configs::types::{
    DeploymentResult, SourceConfiguration, SourceConfigurationWithRules, SourceDeployStatus,
};

/// Deployment-history status of a source kept out of the topology.
pub const QUARANTINED_STATUS: &str = "quarantined";

/// Deployment-history status of a deploy whose activation Vector never
/// confirmed (written, but no evidence it is live).
pub const UNCONFIRMED_STATUS: &str = "unconfirmed";

/// Deployment-history status of a quarantine whose removal from the running
/// Vector could not be confirmed (the source may still be consuming).
pub const QUARANTINE_UNCONFIRMED_STATUS: &str = "quarantine_unconfirmed";

/// What [`SourceConfigService::settle_activation`] decided.
pub(super) enum Settlement {
    /// The deploy is over: report this result (not live, quarantined, ...).
    Final(DeploymentResult),
    /// The source is live (or published for pull delivery, with `note`
    /// saying why it is not verified): continue the success path.
    Live { note: Option<String> },
}

/// What isolation concluded about a pull source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Isolation {
    /// Nothing found it broken. `vector_built` is true when the pinned Vector
    /// itself built it in isolation (not just the in-process preflight).
    Clean { vector_built: bool },
    /// It cannot build; quarantine with this reason.
    Broken(String),
}

/// Where a render materializes a pull source's credential files.
pub(super) enum CredsTarget {
    /// The live location, through the credentials backend.
    Live,
    /// An isolation request directory: written at `host_dir/<key>`, embedded
    /// in the TOML as `runtime_dir/<key>` (the path the Vector container sees).
    Isolation { host_dir: std::path::PathBuf, runtime_dir: String },
}

/// Is `status` a removal Vector never confirmed (the source may still run)?
pub(super) fn removal_unconfirmed(status: &str) -> bool {
    status == QUARANTINE_UNCONFIRMED_STATUS || status == UNCONFIRMED_STATUS
}

impl SourceConfigService {
    /// Prove a pull source builds ON ITS OWN (see the layers in
    /// [`isolation`]).
    ///
    /// Runs BEFORE the live render, because the live render writes the
    /// source's credential file in place: rendering first would overwrite a
    /// working source's key material with the candidate that is being judged.
    pub(super) async fn isolate_pull_source(
        &self,
        config: &SourceConfigurationWithRules,
    ) -> Result<Isolation, SourceConfigServiceError> {
        let row = &config.config;

        // Layer 1: in-process, mirrors the pinned fork's credential parsing.
        if let Some(reason) = self.preflight_pull_source(config).await? {
            return Ok(Isolation::Broken(reason));
        }
        const PREFLIGHT_ONLY: Isolation = Isolation::Clean { vector_built: false };

        // Layer 2: the real pinned Vector builds the source in isolation.
        let Some(runner) = IsolationRunner::from_env() else {
            return Ok(PREFLIGHT_ONLY);
        };
        if !runner.available().await {
            tracing::info!(
                source_config = %row.name,
                "no Vector validation responder on the validation volume; isolation is in-process \
                 only and the post-activation check is the backstop (NAN-4936)"
            );
            return Ok(PREFLIGHT_ONLY);
        }

        // The candidate's credential files live inside the request directory
        // (outside Vector's watched config dirs), never over the live ones.
        let request = runner.prepare().await?;
        let target = CredsTarget::Isolation {
            host_dir: request.host_dir.clone(),
            runtime_dir: request.runtime_dir.clone(),
        };
        let outcome = match self.render_pull_source(config, &target).await {
            Ok(rendered) => {
                let route = format!("{}_route", Self::safe_name(&row.name));
                runner
                    .submit(&request, &isolation::isolation_files(&rendered, &route))
                    .await
            }
            Err(error) => {
                runner.discard(&request).await;
                return Err(error);
            }
        };
        runner.discard(&request).await;

        match outcome? {
            IsolationOutcome::Passed => {
                tracing::info!(source_config = %row.name, "pull source built in isolation by the pinned Vector");
                Ok(Isolation::Clean { vector_built: true })
            }
            IsolationOutcome::Failed(reason) => {
                // Vector's output lands in deployment history, which every
                // `source_configs:view` holder can read; never let it carry
                // credential material it may have echoed.
                let creds = match row.credential_id {
                    Some(id) => self.credential_repo.get_decrypted(id).await.ok(),
                    None => None,
                };
                Ok(Isolation::Broken(isolation::scrub_secrets(&reason, creds.as_ref())))
            }
            IsolationOutcome::TimedOut => {
                tracing::warn!(
                    source_config = %row.name,
                    "Vector validation responder did not answer in time; deploying on the \
                     in-process preflight alone (the post-activation check still applies)"
                );
                Ok(PREFLIGHT_ONLY)
            }
        }
    }

    /// Where the Vector container's cold-start guard
    /// (config/vector/.nano/vector-entrypoint.sh) moves a source file it could
    /// not build, with Vector's output beside it as `<stem>.reason`.
    fn startup_quarantine_paths(&self, row: &SourceConfiguration) -> (std::path::PathBuf, std::path::PathBuf) {
        let live = self.get_config_file_path(&row.config_type, &row.name);
        let stem = live
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dir = self.vector_config_dir.join("quarantine");
        (dir.join(format!("{stem}.toml")), dir.join(format!("{stem}.reason")))
    }

    /// NAN-4936: a quarantine the cold-start guard applied, newer than
    /// `last`, as the status the API shows.
    pub(super) async fn startup_quarantine_status(
        &self,
        row: &SourceConfiguration,
        last: Option<&SourceDeployStatus>,
    ) -> Option<SourceDeployStatus> {
        let (_, reason_path) = self.startup_quarantine_paths(row);
        let meta = tokio::fs::metadata(&reason_path).await.ok()?;
        let at: chrono::DateTime<chrono::Utc> = meta.modified().ok()?.into();
        if last.is_some_and(|l| l.at >= at) {
            return None;
        }
        let output = tokio::fs::read_to_string(&reason_path).await.unwrap_or_default();
        let creds = match row.credential_id {
            Some(id) => self.credential_repo.get_decrypted(id).await.ok(),
            None => None,
        };
        let reason = isolation::scrub_secrets(&isolation::vector_failure_reason(&output, "1"), creds.as_ref());
        Some(SourceDeployStatus {
            action: "deploy".to_string(),
            status: QUARANTINED_STATUS.to_string(),
            error_message: Some(format!(
                "quarantined when Vector started (it could not build this source): {reason}"
            )),
            at,
        })
    }

    /// Drop a stale cold-start quarantine once the source is redeployed or
    /// undeployed.
    pub(super) async fn clear_startup_quarantine(&self, row: &SourceConfiguration) {
        let (toml, reason) = self.startup_quarantine_paths(row);
        let _ = tokio::fs::remove_file(toml).await;
        let _ = tokio::fs::remove_file(reason).await;
    }

    /// Record that a generation left this source out, once per distinct reason
    /// (the reconciler re-renders on every revision change).
    pub(super) async fn record_generation_quarantine(&self, id: uuid::Uuid, reason: &str) {
        let reason = format!("left out of the published Vector configuration: {reason}");
        let latest = self.repository.latest_deployment_status(&[id]).await;
        let already = latest.ok().and_then(|mut m| m.remove(&id)).is_some_and(|last| {
            last.status == QUARANTINED_STATUS && last.error_message.as_deref() == Some(reason.as_str())
        });
        if already {
            return;
        }
        if let Err(error) = self
            .repository
            .add_deployment(id, "deploy", QUARANTINED_STATUS, Some(&reason), None)
            .await
        {
            tracing::error!(%error, "could not record a generation quarantine");
        }
    }

    /// Layer 1 alone (in-process, no Vector, no file writes). Also used by the
    /// publication renderer, which must leave a source it cannot build out of
    /// a generation rather than fail the whole generation.
    pub(super) async fn preflight_pull_source(
        &self,
        config: &SourceConfigurationWithRules,
    ) -> Result<Option<String>, SourceConfigServiceError> {
        let row = &config.config;
        let Some(cred_id) = row.credential_id else {
            return Ok(None);
        };
        let creds = self.credential_repo.get_decrypted(cred_id).await.map_err(|error| {
            SourceConfigServiceError::CredentialError(format!(
                "failed to load credential {cred_id} for source config: {error}"
            ))
        })?;
        Ok(isolation::preflight(&row.config_type, Some(&creds)).err())
    }

    /// Write one credential file for a render (see [`CredsTarget`]) and
    /// return the path Vector should embed.
    pub(super) async fn write_source_creds(
        &self,
        target: &CredsTarget,
        key: &str,
        content: &[u8],
    ) -> Result<String, SourceConfigServiceError> {
        match target {
            CredsTarget::Live => Ok(self.creds_backend().await?.write_creds(key, content).await?),
            CredsTarget::Isolation { host_dir, runtime_dir } => {
                tokio::fs::write(host_dir.join(key), content).await?;
                Ok(format!("{runtime_dir}/{key}"))
            }
        }
    }

    /// Wait for Vector's verdict on a pull source that was just written into
    /// the live tree. `Ok(None)` means it is live and the caller records the
    /// success; `Settlement::Final(result)` is the result to return instead.
    ///
    /// * Rejected, and only the in-process preflight vouched for the source:
    ///   the source we just added is the likeliest culprit (a revoked key, a
    ///   refresh token Google refuses), so it is quarantined, which also takes
    ///   Vector back to a config that builds.
    /// * Rejected, but the pinned Vector built this source in isolation: the
    ///   refusal is somewhere else in the config. Quarantining a source proven
    ///   to build would be wrong, so it stays and the deploy reports failure.
    /// * Unconfirmed: no evidence either way. Reported as not live (never as
    ///   success), left in place.
    pub(super) async fn settle_activation(
        &self,
        config: &SourceConfigurationWithRules,
        watch: ReloadWatch,
        rendered: &str,
        vector_built: bool,
    ) -> Result<Settlement, SourceConfigServiceError> {
        let row = &config.config;
        match watch.outcome().await {
            ActivationOutcome::Accepted => Ok(Settlement::Live { note: None }),
            // NAN-5267: published for the Vector pods to pull; success, with
            // the reason it is not verified here recorded on the deployment.
            ActivationOutcome::Published(note) => Ok(Settlement::Live { note: Some(note) }),
            ActivationOutcome::Rejected if !vector_built => {
                let mut fresh = config.clone();
                fresh.config.deployed = true;
                self.quarantine(
                    &fresh,
                    "Vector refused to build this source when it was activated (its                      configuration_failed counter moved); see the Vector log for the component error",
                    Some(rendered),
                )
                .await
                .map(Settlement::Final)
            }
            ActivationOutcome::Rejected => {
                let reason = "Vector refused the configuration after this source was added, but the                               source builds in isolation, so the refusal is elsewhere in the config.                               Vector is still running the previous topology.";
                let deployment = self
                    .repository
                    .add_deployment(row.id, "deploy", "failure", Some(reason), Some(&redact_config_snapshot(rendered)))
                    .await?;
                Ok(Settlement::Final(DeploymentResult {
                    success: false,
                    source_configuration_id: row.id,
                    action: "deploy".to_string(),
                    message: format!("'{}' is not live: {reason}", row.name),
                    deployment_id: Some(deployment.id),
                }))
            }
            ActivationOutcome::Unconfirmed(why) => {
                let reason = format!("written, but Vector never confirmed activation: {why}");
                let deployment = self
                    .repository
                    .add_deployment(row.id, "deploy", UNCONFIRMED_STATUS, Some(&reason), Some(&redact_config_snapshot(rendered)))
                    .await?;
                Ok(Settlement::Final(DeploymentResult {
                    success: false,
                    source_configuration_id: row.id,
                    action: "deploy".to_string(),
                    message: format!("'{}' {reason}", row.name),
                    deployment_id: Some(deployment.id),
                }))
            }
        }
    }

    /// Keep a pull source out of the live topology and say why.
    ///
    /// Removes its rendered file (and live credential material) if a previous
    /// deploy left one, marks it undeployed so neither the router nor the
    /// publication renderer includes it, rewrites the router, and records a
    /// `quarantined` deployment carrying `reason`. The returned result is a
    /// failure the caller hands straight back to the API (HTTP 200,
    /// `success: false`): the request was valid, the source is not.
    ///
    /// `enabled` is left alone on purpose: the boot-time `deploy_all` retries
    /// every enabled config, so a source quarantined for a reason that later
    /// clears (a credential fixed in the cloud console) comes back on its own.
    pub(super) async fn quarantine(
        &self,
        config: &SourceConfigurationWithRules,
        reason: &str,
        rendered: Option<&str>,
    ) -> Result<DeploymentResult, SourceConfigServiceError> {
        let row = &config.config;
        tracing::warn!(
            source_config = %row.name,
            config_type = %row.config_type,
            %reason,
            "quarantining pull source: it does not build on its own, so it is kept out of the \
             Vector topology and the rest of the config stays live (NAN-4936)"
        );

        let config_file = self.get_config_file_path(&row.config_type, &row.name);
        // NAN-4936 (codex P1): the source may still be running in Vector if it
        // is deployed, its file is still live, or an earlier removal was never
        // confirmed. The last one is persisted (a `quarantine_unconfirmed` /
        // `unconfirmed` row) precisely so a retry cannot forget it: once the row
        // is undeployed and the file gone, only that record says Vector may
        // still be consuming.
        let removal_pending = self
            .repository
            .latest_deployment_status(&[row.id])
            .await?
            .remove(&row.id)
            .is_some_and(|last| removal_unconfirmed(&last.status));
        let was_live = row.deployed
            || removal_pending
            || tokio::fs::try_exists(&config_file).await.unwrap_or(false);
        // "Quarantined" is only true once Vector has loaded a topology without
        // it. Every caller awaits that (boot reconciliation included); when
        // Vector cannot confirm, the state stays `quarantine_unconfirmed`.
        let watch = if was_live {
            Some(ReloadWatch::begin(&self.vector_config_dir).await)
        } else {
            None
        };

        if tokio::fs::try_exists(&config_file).await.unwrap_or(false) {
            tokio::fs::remove_file(&config_file).await?;
        }
        match row.config_type.as_str() {
            "gcp_pubsub" | "kafka" => {
                let key = if row.config_type == "gcp_pubsub" {
                    Self::gcp_creds_key(&row.id)
                } else {
                    Self::kafka_ca_key(&row.id)
                };
                if let Err(error) = self.creds_backend().await?.remove_creds(&key).await {
                    tracing::warn!(%error, "could not remove quarantined source's credential file");
                }
            }
            _ => {}
        }
        if row.deployed {
            self.repository.mark_undeployed(row.id).await?;
        }
        // Callers hold the deploy lock (deploy_with).
        self.update_dynamic_router_locked().await?;

        let (status, recorded_reason, removal_note) = match watch {
            None => (QUARANTINED_STATUS, reason.to_string(), String::new()),
            Some(watch) => match watch.outcome().await {
                ActivationOutcome::Accepted | ActivationOutcome::Published(_) => {
                    (QUARANTINED_STATUS, reason.to_string(), String::new())
                }
                ActivationOutcome::Rejected => {
                    let note = "Vector refused the configuration without this source, so it may \
                                still be running the previous topology (with this source)";
                    (QUARANTINE_UNCONFIRMED_STATUS, format!("{reason} ({note})"), format!(" {note}."))
                }
                ActivationOutcome::Unconfirmed(why) => {
                    let note = format!(
                        "removal from the running Vector is not confirmed: {why}"
                    );
                    (QUARANTINE_UNCONFIRMED_STATUS, format!("{reason} ({note})"), format!(" Note: {note}."))
                }
            },
        };

        let snapshot = rendered.map(redact_config_snapshot);
        let deployment = self
            .repository
            .add_deployment(row.id, "deploy", status, Some(&recorded_reason), snapshot.as_deref())
            .await?;

        Ok(DeploymentResult {
            success: false,
            source_configuration_id: row.id,
            action: "deploy".to_string(),
            message: format!(
                "Quarantined '{}': Vector cannot build this source, so it was kept out of the live \
                 pipeline (other sources are unaffected). Reason: {}{}",
                row.name, reason, removal_note
            ),
            deployment_id: Some(deployment.id),
        })
    }

    /// NAN-4936 (codex P1): finish an undeploy only once Vector has loaded a
    /// topology without the source. Caller holds the deploy lock and took
    /// `watch` before its first removal.
    pub(super) async fn finish_removal(
        &self,
        id: uuid::Uuid,
        name: &str,
        watch: ReloadWatch,
    ) -> Result<DeploymentResult, SourceConfigServiceError> {
        let (success, status, reason, message) = match watch.outcome().await {
            ActivationOutcome::Accepted => (
                true,
                "success",
                None,
                format!("Undeployed '{name}' successfully"),
            ),
            ActivationOutcome::Published(note) => (
                true,
                "success",
                Some(note.clone()),
                format!("Undeployed '{name}' successfully ({note})"),
            ),
            ActivationOutcome::Rejected => {
                let reason = "removed from the config, but Vector refused the resulting \
                              configuration and is still running the previous topology, which \
                              may include this source"
                    .to_string();
                (false, "failure", Some(reason.clone()), format!("'{name}': {reason}"))
            }
            ActivationOutcome::Unconfirmed(why) => {
                let reason = format!(
                    "removed from the config, but Vector never confirmed it stopped running: {why}"
                );
                (false, UNCONFIRMED_STATUS, Some(reason.clone()), format!("'{name}': {reason}"))
            }
        };
        let deployment = self
            .repository
            .add_deployment(id, "undeploy", status, reason.as_deref(), None)
            .await?;
        Ok(DeploymentResult {
            success,
            source_configuration_id: id,
            action: "undeploy".to_string(),
            message,
            deployment_id: Some(deployment.id),
        })
    }
}
