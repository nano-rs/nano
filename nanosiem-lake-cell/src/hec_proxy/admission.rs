// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admission follows native commit progress, independently of durable Bronze ACKs.
use anyhow::{ensure, Context};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_STATUS_BYTES: usize = 64 * 1024;
const MAX_COMMIT_LAG_SECS: f64 = 30.0;
const MAX_HEARTBEAT_AGE_SECS: f64 = 10.0;
const CACHE_AGE: Duration = Duration::from_secs(1);
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct CommitAdmission {
    root: PathBuf,
    client: reqwest::Client,
    cache: tokio::sync::Mutex<AdmissionState>,
}

#[derive(Default)]
struct AdmissionState {
    verdict: Option<(Instant, bool)>,
    pending: Option<PendingProgress>,
}

struct PendingProgress {
    observed_at: Instant,
    age_secs: f64,
    last_progress_unix_ms: u64,
    uptime_secs: f64,
    consumed_objects_total: u64,
}

#[derive(Deserialize)]
struct Route {
    cell_origin: String,
}
#[derive(Deserialize)]
struct Status {
    tenants: Vec<Tenant>,
}
#[derive(Deserialize)]
struct Tenant {
    tenant_id: String,
    processes: Vec<Process>,
}
#[derive(Deserialize)]
struct Process {
    role: String,
    stopping: bool,
    uptime_secs: f64,
    heartbeat_age_secs: f64,
    // Heartbeats have role-specific evidence. Decode ingest progress only
    // after selecting exactly one ingest process from the complete status.
    heartbeat: serde_json::Value,
}
#[derive(Deserialize)]
struct Progress {
    // Required: old completed-tick lag/busy cannot prove an empty input queue.
    ingest_pending_input: crate::contract::IngestPendingInput,
    last_progress_unix_ms: u64,
}

impl CommitAdmission {
    pub(super) fn new(root: PathBuf, client: reqwest::Client) -> Self {
        Self {
            root,
            client,
            cache: tokio::sync::Mutex::new(AdmissionState::default()),
        }
    }

    pub(super) async fn check(&self) -> anyhow::Result<()> {
        // One bounded status request per second across all upload connections.
        // Cache failures too: an unavailable cell must not cause a request storm.
        let mut cache = self.cache.lock().await;
        if let Some((at, allowed)) = cache.verdict {
            if at.elapsed() < CACHE_AGE {
                ensure!(allowed, "native commit admission closed");
                return Ok(());
            }
        }
        let allowed = match tokio::time::timeout(STATUS_TIMEOUT, self.refresh()).await {
            Ok(Ok(process)) => {
                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
                admit_progress(process, now_ms, &mut cache.pending).is_ok()
            }
            _ => false,
        };
        cache.verdict = Some((Instant::now(), allowed));
        ensure!(allowed, "native commit admission closed");
        Ok(())
    }

    async fn refresh(&self) -> anyhow::Result<Process> {
        let routes: BTreeMap<String, Route> =
            serde_json::from_slice(&tokio::fs::read(self.root.join("routes.json")).await?)?;
        ensure!(
            routes.len() == 1,
            "open-core admission requires one installed tenant"
        );
        let (tenant, route) = routes.into_iter().next().context("missing tenant route")?;
        crate::contract::TenantId::new(&tenant)?;
        let token = tokio::fs::read_to_string(self.root.join("router-query.token")).await?;
        ensure!(!token.trim().is_empty(), "missing status credential");
        let origin = reqwest::Url::parse(&route.cell_origin)?;
        ensure!(
            matches!(origin.scheme(), "http" | "https")
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && matches!(origin.path(), "" | "/"),
            "invalid installed cell origin"
        );
        let mut reply = self
            .client
            .get(origin.join("/v1/status")?)
            .bearer_auth(token.trim())
            .send()
            .await?;
        ensure!(reply.status().is_success(), "native status unavailable");
        let mut bytes = Vec::new();
        while let Some(chunk) = reply.chunk().await? {
            ensure!(
                chunk.len() <= MAX_STATUS_BYTES.saturating_sub(bytes.len()),
                "native status too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let status: Status = serde_json::from_slice(&bytes)?;
        ensure!(
            status.tenants.len() == 1 && status.tenants[0].tenant_id == tenant,
            "native status does not match installed tenant"
        );
        let mut ingest = status
            .tenants
            .into_iter()
            .next()
            .unwrap()
            .processes
            .into_iter()
            .filter(|p| p.role == "ingest");
        let process = ingest.next().context("native ingest unavailable")?;
        ensure!(ingest.next().is_none(), "ambiguous ingest status");
        Ok(process)
    }
}

fn admit_progress(
    process: Process,
    now_ms: u64,
    pending: &mut Option<PendingProgress>,
) -> anyhow::Result<()> {
    ensure!(
        !process.stopping
            && process.heartbeat_age_secs.is_finite()
            && (0.0..=MAX_HEARTBEAT_AGE_SECS).contains(&process.heartbeat_age_secs)
            && process.uptime_secs.is_finite()
            && process.uptime_secs >= 0.0,
        "stale ingest status"
    );
    let progress: Progress = serde_json::from_value(process.heartbeat)?;
    let input = &progress.ingest_pending_input;
    let input_age = input.oldest_age_seconds + process.heartbeat_age_secs;
    ensure!(
        input.oldest_age_seconds.is_finite()
            && input.oldest_age_seconds >= 0.0
            && (input.objects == 0 || input_age < MAX_COMMIT_LAG_SECS),
        "native commit backlog"
    );
    if input.objects == 0 {
        ensure!(input.oldest_age_seconds == 0.0, "invalid empty input age");
        ensure!(
            input
                .discovery_age_seconds
                .is_some_and(|age| age.is_finite()
                    && age >= 0.0
                    && age + process.heartbeat_age_secs <= MAX_HEARTBEAT_AGE_SECS),
            "stale input discovery"
        );
        *pending = None;
    } else {
        ensure!(
            progress.last_progress_unix_ms <= now_ms.saturating_add(5_000),
            "invalid progress time"
        );
        // The queue observes input before processing, independently of completed
        // tick health and control heartbeats. Even a zero-age pending sample
        // starts the clock. Keep it across refused reads and frozen snapshots;
        // only a verified drain, consumption/commit progress, or restart resets it.
        let now = Instant::now();
        let age = pending
            .as_ref()
            .filter(|p| {
                p.last_progress_unix_ms == progress.last_progress_unix_ms
                    && p.uptime_secs <= process.uptime_secs
                    && p.consumed_objects_total == input.consumed_objects_total
            })
            .map_or(input_age, |p| {
                (p.age_secs + now.duration_since(p.observed_at).as_secs_f64()).max(input_age)
            });
        *pending = Some(PendingProgress {
            observed_at: now,
            age_secs: age,
            last_progress_unix_ms: progress.last_progress_unix_ms,
            uptime_secs: process.uptime_secs,
            consumed_objects_total: input.consumed_objects_total,
        });
        ensure!(age < MAX_COMMIT_LAG_SECS, "native commit stalled");
    }
    Ok(())
}
