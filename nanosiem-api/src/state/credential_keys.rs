// SPDX-License-Identifier: AGPL-3.0-or-later

//! Credential key ring lifecycle for the api and jobs processes (NAN-4933).

use super::AppState;
use nanosiem_core::crypto::rotation::{self, CredentialKeyRepository};
use std::time::Duration;

/// Default interval between scheduled re-wrap passes on the jobs leader.
const DEFAULT_REWRAP_INTERVAL_SECS: u64 = 600;
/// Ring membership refresh (well inside `MEMBER_LIVENESS_SECS`).
const MEMBERSHIP_REFRESH: Duration = Duration::from_secs(120);

impl AppState {
    /// Record this process's ring (key ids, fingerprints, active key) at boot.
    ///
    /// Refuses to start on any failure: a key id reused for different
    /// material, an active key that is retired, or a database error.
    pub async fn register_credential_key_ring(&self, service: &str) -> anyhow::Result<()> {
        let repo = CredentialKeyRepository::new(self.pool.clone());
        // NAN-4933 (review P1): every registration failure is fatal. A
        // process that cannot prove its active key is registered and not
        // retired must not start encrypting secrets (the write fence would
        // refuse them anyway; failing at boot is the visible place).
        repo.register(self.encryption_service.as_ref(), &self.node_id, service)
            .await
            .map_err(|error| anyhow::anyhow!("refusing to start: credential key ring registration failed: {error}"))?;
        tracing::info!(
            active_key_id = %self.encryption_service.active_key_id(),
            keys = self.encryption_service.ring_keys().len(),
            "credential key ring registered"
        );
        Ok(())
    }

    /// Keep this node's ring membership fresh so a key it still writes with
    /// can never be retired underneath it. Runs on every api/jobs process.
    pub fn start_credential_key_membership(&self, service: &'static str) -> tokio::task::JoinHandle<()> {
        let repo = CredentialKeyRepository::new(self.pool.clone());
        let cipher = self.encryption_service.clone();
        let node_id = self.node_id.clone();
        let shutdown = self.shutdown_token();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MEMBERSHIP_REFRESH);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                if shutdown.run_until_cancelled(interval.tick()).await.is_none() {
                    if let Err(error) = repo.deregister(&node_id).await {
                        tracing::warn!(%error, "credential key ring membership removal failed");
                    }
                    return;
                }
                if let Err(error) = repo.register(cipher.as_ref(), &node_id, service).await {
                    tracing::warn!(%error, "credential key ring membership refresh failed");
                }
            }
        })
    }

    /// Leader-only: re-wrap stored secrets onto the active key, once shortly
    /// after election (`boot`) and then every `CREDENTIAL_REWRAP_INTERVAL_SECS`
    /// (default 600 s). A pass with nothing to do is a cheap scan.
    pub fn start_credential_key_rewrap_scheduler(&self) -> tokio::task::JoinHandle<()> {
        let repo = CredentialKeyRepository::new(self.pool.clone());
        let cipher = self.encryption_service.clone();
        let node_id = self.node_id.clone();
        let fence = self.leader_fence.clone();
        let interval_secs = std::env::var("CREDENTIAL_REWRAP_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REWRAP_INTERVAL_SECS)
            .max(10);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut trigger = "boot";
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                // NAN-4933: only the current jobs lease epoch re-wraps.
                if !fence.still_leader(repo.pool()).await {
                    continue;
                }
                let _ = rotation::run_pass_fenced(&repo, cipher.as_ref(), trigger, &node_id, fence.epoch()).await;
                trigger = "scheduled";
            }
        })
    }
}
