// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5611: SIEM Health flags a Vector pipeline gate nano-api gave up on.
//!
//! On a single node the Vector entrypoint does not start Vector (ingest
//! refuses connections) until nano-api has rendered the tree for this
//! release's pipeline identity and recorded it in
//! `/etc/vector/dynamic/.nano-pipeline-identity` (NAN-5564). nano-api retries
//! a failed boot render in the background ([`BOOT_RENDER_RETRY`],
//! `nanosiem-api` `main.rs`). After `max_attempts` it logs one ERROR naming
//! the file and the error, records the stall in [`STALL_FILE`] next to the
//! identity file, and keeps retrying quietly every `slow_delay` (a database
//! outage at boot then still recovers without a restart).
//!
//! The SIEM Health scheduler runs in nano-jobs, which mounts the same dynamic
//! volume at its `VECTOR_CONFIG_DIR`, so the stall is a file, not process
//! state. The finding lasts until the identity file names the stalled
//! identity: any later render or deploy that records it clears it.
//!
//! NAN-5657: the likeliest stall is that directory being root-owned, and then
//! the stall record cannot be written beside the identity file either. It
//! then goes to the data directory (`NANOSIEM_DATA_DIR`), which nano-api and
//! nano-jobs also share, so SIEM Health still shows it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::types::{AnalysisResult, Recommendation};

/// Title of the finding (stable: suppressions key on it).
pub const VECTOR_PIPELINE_GATE_TITLE: &str =
    "nano-api could not record this release's Vector pipeline; Vector is gated or runs the previous release's config";

/// The identity file the entrypoint's gate reads, in the api's config dir.
const IDENTITY_FILE: &str = ".nano-pipeline-identity";
/// The stall record, beside it (a dotfile: no Vector config dir reads it).
pub const STALL_FILE: &str = ".nano-pipeline-stall.json";

/// What the boot retry saw when it gave up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineGateStall {
    /// The pipeline identity file the entrypoint's gate reads.
    pub marker_path: PathBuf,
    /// The identity this api renders for (`NANO_PIPELINE_IDENTITY`).
    pub identity: String,
    pub attempts: u32,
    /// The last render or marker-write error.
    pub error: String,
    /// Its OS error number, when it was an I/O error.
    pub errno: Option<i32>,
}

fn stall_path_for(marker_path: &Path) -> Option<PathBuf> {
    marker_path.parent().map(|dir| dir.join(STALL_FILE))
}

/// The shared data directory the stall record falls back to.
fn fallback_dir_from_env() -> Option<PathBuf> {
    std::env::var("NANOSIEM_DATA_DIR").ok().filter(|d| !d.trim().is_empty()).map(PathBuf::from)
}

/// Record the stall for SIEM Health, beside the identity file or else in the
/// data directory. Best effort: a failure is logged (the ERROR before it
/// already names the file and the error).
pub async fn report_stall(stall: &PipelineGateStall) {
    report_stall_to(stall, fallback_dir_from_env().as_deref()).await;
}

async fn report_stall_to(stall: &PipelineGateStall, fallback_dir: Option<&Path>) {
    let body = match serde_json::to_vec_pretty(stall) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "could not encode the Vector pipeline stall");
            return;
        }
    };
    let primary = stall_path_for(&stall.marker_path);
    let fallback = fallback_dir.map(|d| d.join(STALL_FILE));
    if let Some(path) = &primary {
        match crate::parsers::vector_tree_write::write_if_changed(path, body.clone()).await {
            Ok(_) => {
                // One live record: an older fallback one would outlive it.
                if let Some(old) = &fallback {
                    let _ = tokio::fs::remove_file(old).await;
                }
                return;
            }
            Err(error) => {
                tracing::warn!(%error, path = %path.display(), "could not record the Vector pipeline stall beside the identity file; trying the data directory");
            }
        }
    }
    if let Some(path) = &fallback {
        if let Err(error) = crate::parsers::vector_tree_write::write_if_changed(path, body).await {
            tracing::warn!(%error, path = %path.display(), "could not record the Vector pipeline stall for SIEM Health");
        }
    }
}

/// The identity was recorded: remove the stall record next to `marker_path`
/// and its data-directory fallback.
pub async fn clear_stall(marker_path: &Path) {
    clear_stall_in(marker_path, fallback_dir_from_env().as_deref()).await;
}

async fn clear_stall_in(marker_path: &Path, fallback_dir: Option<&Path>) {
    if let Some(path) = stall_path_for(marker_path) {
        let _ = tokio::fs::remove_file(path).await;
    }
    if let Some(dir) = fallback_dir {
        let _ = tokio::fs::remove_file(dir.join(STALL_FILE)).await;
    }
}

/// The stall recorded in `config_dir` (the api's and jobs'
/// `VECTOR_CONFIG_DIR`) or in the data-directory fallback, unless the
/// identity file now names its identity (then the record is removed).
pub async fn current_stall(config_dir: &Path) -> Option<PipelineGateStall> {
    current_stall_in(config_dir, fallback_dir_from_env().as_deref()).await
}

async fn current_stall_in(config_dir: &Path, fallback_dir: Option<&Path>) -> Option<PipelineGateStall> {
    let recorded = tokio::fs::read_to_string(config_dir.join(IDENTITY_FILE))
        .await
        .ok()
        .and_then(|text| text.lines().next().map(|line| line.trim().to_string()));
    // Every record is checked (NAN-5657 review): a resolved one is removed and
    // skipped, so a stale primary record that cannot be removed never hides
    // a live fallback one.
    let mut live = None;
    for path in std::iter::once(config_dir.join(STALL_FILE)).chain(fallback_dir.map(|d| d.join(STALL_FILE))) {
        let Ok(body) = tokio::fs::read(&path).await else { continue };
        let Ok(stall) = serde_json::from_slice::<PipelineGateStall>(&body) else { continue };
        if recorded.as_deref() == Some(stall.identity.as_str()) {
            let _ = tokio::fs::remove_file(&path).await;
            continue;
        }
        live.get_or_insert(stall);
    }
    live
}

/// [`current_stall`] for this process's `VECTOR_CONFIG_DIR`.
pub async fn current_stall_from_env() -> Option<PipelineGateStall> {
    let dir = std::env::var("VECTOR_CONFIG_DIR").ok().filter(|d| !d.trim().is_empty())?;
    current_stall(Path::new(&dir)).await
}

/// The finding for `stall`: `high`, score capped at 69 (ingest refused, or
/// running a config not rendered for this release).
pub fn stall_recommendation(stall: &PipelineGateStall) -> Recommendation {
    let errno = stall.errno.map(|n| format!(" (errno {n})")).unwrap_or_default();
    Recommendation {
        title: VECTOR_PIPELINE_GATE_TITLE.to_string(),
        description: format!(
            "nano-api tried {attempts} times to render the Vector config for pipeline identity '{identity}' \
             and record it in {path}, and failed (it keeps retrying every few minutes). Last error: \
             {error}{errno}. Until that file names this \
             identity, the Vector container does not start Vector (ingest refuses connections) for up to \
             NANO_VECTOR_PIPELINE_WAIT_SECS (default 900 s), and after that it runs the config the previous \
             release rendered. A 'Permission denied' error usually means the file or its directory is owned \
             by root: restart the Vector container (its entrypoint gives the dynamic tree back to nano-api), \
             then restart nano-api (`docker compose restart vector nano-api`). Otherwise fix the error in \
             `docker compose logs nano-api` and restart nano-api. This warning clears once the file names \
             the identity.",
            attempts = stall.attempts,
            identity = stall.identity,
            path = stall.marker_path.display(),
            error = stall.error,
        ),
        priority: "high".to_string(),
    }
}

/// Adds the finding to `analysis` on every report path (AI, fallback).
pub fn ensure_vector_pipeline_gate_findings(analysis: &mut AnalysisResult, stall: Option<&PipelineGateStall>) {
    let Some(stall) = stall else {
        return;
    };
    let rec = stall_recommendation(stall);
    analysis.overall_score = analysis.overall_score.min(69);
    if !analysis.recommendations.iter().any(|r| r.title == rec.title) {
        analysis.recommendations.push(rec);
    }
}

/// How the api retries a boot render that did not record the identity.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Fast retries before the loud give-up and the finding.
    pub max_attempts: u32,
    pub first_delay: std::time::Duration,
    pub max_delay: std::time::Duration,
    /// After giving up: one quiet retry this often until it records.
    pub slow_delay: std::time::Duration,
}

/// 15 fast retries, 5 s doubling to 60 s (735 s of waiting, plus each
/// render's own time), timed to end near the entrypoint's 900 s gate wait:
/// past that Vector starts on the old tree anyway. Then the loud ERROR and
/// the finding, and a quiet retry every 5 minutes so a cause that goes away
/// (a database outage at boot) still recovers without a restart.
pub const BOOT_RENDER_RETRY: RetryPolicy = RetryPolicy {
    max_attempts: 15,
    first_delay: std::time::Duration::from_secs(5),
    max_delay: std::time::Duration::from_secs(60),
    slow_delay: std::time::Duration::from_secs(300),
};

/// How [`retry_until_recorded`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryOutcome {
    /// The identity is recorded, after this many retries.
    Recorded { retries: u32 },
    /// `policy.max_attempts` fast retries failed; logged and reported for
    /// SIEM Health. Continue with [`retry_slowly_until_recorded`].
    GaveUp(PipelineGateStall),
}

/// The OS error number anywhere in `error`'s source chain.
pub fn io_errno(error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            return io.raw_os_error();
        }
        current = error.source();
    }
    None
}

/// Retry `render` (the api's boot render) while `pending` says the identity
/// is not recorded, at most `policy.max_attempts` times. On giving up, logs
/// one ERROR naming the file and the error and records the stall
/// ([`report_stall`]).
pub async fn retry_until_recorded<P, PF, R, RF, E>(
    policy: RetryPolicy,
    marker_path: PathBuf,
    identity: String,
    mut pending: P,
    mut render: R,
) -> RetryOutcome
where
    P: FnMut() -> PF,
    PF: std::future::Future<Output = bool>,
    R: FnMut() -> RF,
    RF: std::future::Future<Output = Result<(), E>>,
    E: std::error::Error + 'static,
{
    let mut delay = policy.first_delay;
    let mut last_error = "the render did not record the pipeline identity".to_string();
    let mut last_errno = None;
    for retry in 0..policy.max_attempts {
        if !pending().await {
            clear_stall(&marker_path).await;
            tracing::info!("Vector pipeline rendered for this release; a gated Vector may start");
            return RetryOutcome::Recorded { retries: retry };
        }
        tracing::error!(
            attempt = retry + 1,
            max_attempts = policy.max_attempts,
            retry_in_secs = delay.as_secs(),
            path = %marker_path.display(),
            "Vector is waiting for this release's pipeline (ingest refuses connections); retrying the render"
        );
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(policy.max_delay);
        if let Err(error) = render().await {
            last_errno = io_errno(&error);
            last_error = error.to_string();
            tracing::error!(error = %last_error, errno = last_errno, "Vector pipeline render failed; retrying");
        }
    }
    if !pending().await {
        clear_stall(&marker_path).await;
        tracing::info!("Vector pipeline rendered for this release; a gated Vector may start");
        return RetryOutcome::Recorded { retries: policy.max_attempts };
    }
    tracing::error!(
        path = %marker_path.display(),
        errno = last_errno,
        error = %last_error,
        attempts = policy.max_attempts,
        retry_every_secs = policy.slow_delay.as_secs(),
        %identity,
        "GAVE UP fast retries recording this release's Vector pipeline identity: Vector stays gated (ingest \
         refuses connections) until NANO_VECTOR_PIPELINE_WAIT_SECS, then runs the previous release's config. \
         Fix the error; nano-api retries quietly and SIEM Health reports this until it is recorded"
    );
    let stall = PipelineGateStall {
        marker_path,
        identity,
        attempts: policy.max_attempts,
        error: last_error,
        errno: last_errno,
    };
    report_stall(&stall).await;
    RetryOutcome::GaveUp(stall)
}

/// After [`RetryOutcome::GaveUp`]: retry every `policy.slow_delay`, one WARN
/// per failure, until the identity is recorded; then clear the stall.
/// Returns the number of slow retries.
pub async fn retry_slowly_until_recorded<P, PF, R, RF, E>(
    policy: RetryPolicy,
    marker_path: &Path,
    mut pending: P,
    mut render: R,
) -> u32
where
    P: FnMut() -> PF,
    PF: std::future::Future<Output = bool>,
    R: FnMut() -> RF,
    RF: std::future::Future<Output = Result<(), E>>,
    E: std::error::Error + 'static,
{
    let mut retries = 0;
    while pending().await {
        tokio::time::sleep(policy.slow_delay).await;
        retries += 1;
        if let Err(error) = render().await {
            tracing::warn!(
                %error,
                errno = io_errno(&error),
                path = %marker_path.display(),
                "Vector pipeline render still failing; Vector stays on a config not rendered for this release"
            );
        }
    }
    clear_stall(marker_path).await;
    tracing::info!(retries, "Vector pipeline rendered for this release after the slow retries");
    retries
}

#[cfg(test)]
#[path = "vector_pipeline_gate_tests.rs"]
mod tests;
