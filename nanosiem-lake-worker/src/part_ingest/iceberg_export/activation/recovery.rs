// SPDX-License-Identifier: AGPL-3.0-or-later
//! A degraded lane never blocks ingest. At most once per five minutes, a
//! value-free, installation-bound platform probe may request one supervised
//! restart. Only the normal startup path can attach custody and restore GC.
//!
//! The probe proves only the platform binding, not that attach will pass
//! (NAN-4543: it passed while every attach failed on storage scope). So
//! recovery restarts of one installation back off exponentially across
//! process lives (5 min, 10 min, 20 min ... capped at 6 h), recorded in the
//! catalog work dir and cleared by a successful attach or a new installation.
use super::*;
use serde::Serialize;
use tokio::time::Instant;

const INTERVAL: Duration = Duration::from_secs(300);
const DEADLINE: Duration = Duration::from_secs(20);
const MAX_BACKOFF: Duration = Duration::from_secs(6 * 3600);
const RESTARTS: &str = "recovery-restarts.json";

struct State {
    record: CatalogActivation,
    generation: u64,
    due: Instant,
    restart_requested: bool,
    restarts: u32,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
struct Restarts {
    activation_id: uuid::Uuid,
    restarts: u32,
}

/// Wait before this process may request its recovery restart, given how
/// many recovery restarts of this installation already happened.
pub(super) fn backoff(restarts: u32) -> Duration {
    INTERVAL
        .checked_mul(1u32.checked_shl(restarts).unwrap_or(u32::MAX))
        .unwrap_or(MAX_BACKOFF)
        .min(MAX_BACKOFF)
}

fn load_restarts(work: &Path, activation: uuid::Uuid) -> u32 {
    match std::fs::read(work.join(RESTARTS)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Ok(bytes) => match serde_json::from_slice::<Restarts>(&bytes) {
            // A new installation starts its own back-off.
            Ok(record) if record.activation_id != activation => 0,
            Ok(record) => record.restarts,
            // Unreadable: never reset the back-off to zero.
            Err(_) => 1,
        },
        Err(_) => 1,
    }
}

/// Successful attach: the next degraded episode starts from five minutes.
pub(super) fn clear_restarts(work: &Path) {
    match std::fs::remove_file(work.join(RESTARTS)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => tracing::warn!(reason = "catalog_recovery_record_stale", "catalog recovery back-off record could not be cleared"),
    }
}

pub(crate) struct CatalogRecovery {
    tenant: String,
    work: PathBuf,
    control_url: String,
    cell_id: String,
    trust: PlatformTrust,
    state: RwLock<State>,
    flight: tokio::sync::Mutex<()>,
}

impl CatalogRecovery {
    pub(super) fn new(
        record: &CatalogActivation,
        tenant: &str,
        work: &Path,
        control_url: &str,
        cell_id: &str,
        trust: PlatformTrust,
    ) -> Result<Self> {
        record.validate(tenant)?;
        let restarts = load_restarts(work, record.activation_id);
        Ok(Self {
            tenant: tenant.into(),
            work: work.into(),
            control_url: control_url.into(),
            cell_id: cell_id.into(),
            trust,
            state: RwLock::new(State {
                record: record.clone(),
                generation: 0,
                due: Instant::now() + backoff(restarts),
                restart_requested: false,
                restarts,
            }),
            flight: tokio::sync::Mutex::new(()),
        })
    }

    pub(super) fn refresh(&self, next: Option<&CatalogActivation>) -> Result<()> {
        let next = next.context("catalog custody withdrawn; restart required")?;
        next.validate(&self.tenant)?;
        let mut state = self.state.write().expect("catalog recovery state");
        let old = &state.record;
        ensure!(
            next.activation_id == old.activation_id
                && next.installation_sha256 == old.installation_sha256
                && next.account_id == old.account_id
                && next.bucket == old.bucket
                && next.authority == old.authority
                && next.uninstall == old.uninstall
                && next.metadata.endpoint == old.metadata.endpoint
                && next.metadata.prefix == old.metadata.prefix
                && next.metadata.region == old.metadata.region,
            "catalog custody replaced; restart required"
        );
        state.record = next.clone();
        state.generation = state.generation.wrapping_add(1);
        Ok(())
    }

    pub(super) fn clear(&self) {
        clear_restarts(&self.work);
    }

    /// Called by one independently owned task; never holds the ingestor lock.
    /// The persisted back-off bounds restarts across process lives.
    pub(crate) async fn wait_for_restart(&self) {
        loop {
            tokio::time::sleep(INTERVAL).await;
            if self.try_restart().await {
                return;
            }
        }
    }

    pub(super) async fn try_restart(&self) -> bool {
        let Ok(_flight) = self.flight.try_lock() else {
            return false;
        };
        let (record, generation) = {
            let mut state = self.state.write().expect("catalog recovery state");
            if state.restart_requested || Instant::now() < state.due {
                return false;
            }
            state.due = Instant::now() + INTERVAL;
            (state.record.clone(), state.generation)
        };
        let probe = async {
            let control = Control::new(
                &record,
                &self.tenant,
                &self.work,
                &self.control_url,
                &self.cell_id,
                self.trust.clone(),
            )?;
            // Read-only verification only: do not replay metadata, attach GC,
            // reopen reads, or claim custody from this background task.
            // /v1/config authenticates the current tenant/cell/activation and
            // warehouse before returning this fixed platform-owned shape. It
            // returns before provider IO or metadata-journal reconciliation.
            let url = format!(
                "{}/{}/{}/v1/config",
                control.endpoint, self.tenant, record.activation_id
            );
            let mut response = control
                .tls
                .client()
                .get(url)
                .bearer_auth(&record.control_token)
                .query(&[(
                    "warehouse",
                    format!("{}_{}", record.account_id, record.bucket),
                )])
                .send()
                .await?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(ControlRefused(response.status().as_u16()).into());
            }
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    body.len().saturating_add(chunk.len()) <= 4096,
                    "catalog recovery response exceeds bound"
                );
                body.extend_from_slice(&chunk);
            }
            ensure!(
                serde_json::from_slice::<Value>(&body)? == json!({"defaults":{},"overrides":{}}),
                "catalog recovery binding differs"
            );
            Ok::<_, anyhow::Error>(())
        };
        let result = match tokio::time::timeout(DEADLINE, probe).await {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        let mut state = self.state.write().expect("catalog recovery state");
        state.due = Instant::now() + INTERVAL;
        if let Err(error) = result {
            tracing::warn!(tenant = %self.tenant, reason = "catalog_reattach_pending", error_class = attachment_error_class(&error), "agent lane remains degraded; ingest continues");
            return false;
        }
        // A successful response for a credential replaced/expired during IO
        // cannot authorize a restart with stale proof.
        if state.generation != generation || state.record.validate(&self.tenant).is_err() {
            return false;
        }
        // Record the restart before requesting it: without a durable count a
        // persistent attach failure could restart ingest every five minutes.
        let restarts = state.restarts.saturating_add(1);
        let saved = std::fs::create_dir_all(&self.work).map_err(anyhow::Error::from).and_then(|()| {
            write_private(
                &self.work.join(RESTARTS),
                &serde_json::to_vec(&Restarts { activation_id: state.record.activation_id, restarts })?,
            )
        });
        if saved.is_err() {
            tracing::warn!(tenant = %self.tenant, reason = "catalog_reattach_pending", error_class = "io", "agent lane remains degraded; recovery back-off not recorded, no restart");
            return false;
        }
        state.restarts = restarts;
        state.restart_requested = true;
        tracing::info!(tenant = %self.tenant, reason = "catalog_reattach_verified", restarts, next_backoff_s = backoff(restarts).as_secs(), "catalog platform reachable; supervised restart to attach custody");
        true
    }
}

/// Fixed classes only. Never format an upstream error, URL, token or body.
pub(crate) fn attachment_error_class(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        if cause.is::<tokio::time::error::Elapsed>() {
            return "deadline";
        }
        if cause.is::<rustls::Error>() {
            return "tls";
        }
    }
    for cause in error.chain() {
        if let Some(refused) = cause.downcast_ref::<ControlRefused>() {
            return match refused.0 {
                400..=499 => "control_status_4xx",
                500..=599 => "control_status_5xx",
                _ => "control_status_other",
            };
        }
        if let Some(error) = cause.downcast_ref::<opendal::Error>() {
            return match error.kind() {
                opendal::ErrorKind::PermissionDenied => "permission_denied",
                opendal::ErrorKind::NotFound => "not_found",
                opendal::ErrorKind::RateLimited => "rate_limited",
                opendal::ErrorKind::ConfigInvalid => "storage_config",
                opendal::ErrorKind::Unexpected => "unexpected",
                _ => "storage",
            };
        }
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            if error.is_timeout() {
                return "timeout";
            }
            if error.is_connect() {
                return "connect";
            }
            return "http";
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            return if error.kind() == std::io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "io"
            };
        }
    }
    "catalog"
}
