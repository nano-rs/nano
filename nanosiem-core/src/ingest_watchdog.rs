// SPDX-License-Identifier: AGPL-3.0-or-later

//! Leader-owned ClickHouse ingest watchdog (NAN-4988).
//!
//! Automatic STOP is write-ahead journalled, ownership is an exact
//! `(replica, database, view)` set, and every command uses the singular VIEW
//! form. Every replica an ingest endpoint can target is sampled: any HOT
//! replica is HOT, while CALM requires complete coverage.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::db::clickhouse_transport;
use crate::sql_hygiene::escape_sql_identifier;

const DATABASE: &str = "nanosiem";
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum IngestWatchdogError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid ingest-watchdog configuration: {0}")]
    Config(String),
    #[error("ClickHouse ingest-watchdog operation failed: {0}")]
    ClickHouse(String),
}

#[derive(Debug, Clone)]
pub struct IngestWatchdogConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub hot_consecutive: u16,
    pub calm_consecutive: u16,
    pub anti_flap: Duration,
    pub pending_async_insert_limit: u64,
    pub oldest_flush_age_limit: u64,
    pub running_query_limit: u64,
    pub memory_limit_percent: u64,
    explicit_endpoints: Vec<String>,
}

impl Default for IngestWatchdogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            hot_consecutive: 4,
            calm_consecutive: 20,
            anti_flap: Duration::from_secs(15 * 60),
            pending_async_insert_limit: 2_000,
            oldest_flush_age_limit: 60,
            running_query_limit: 1_500,
            memory_limit_percent: 50,
            explicit_endpoints: Vec::new(),
        }
    }
}

impl IngestWatchdogConfig {
    fn from_env() -> Result<Self, IngestWatchdogError> {
        let mut config = Self::default();
        config.enabled = enabled_from_env();
        if let Ok(value) = std::env::var("NANO_INGEST_WATCHDOG_INTERVAL_SECS") {
            let seconds = value.parse::<u64>().map_err(|_| {
                IngestWatchdogError::Config(format!(
                    "NANO_INGEST_WATCHDOG_INTERVAL_SECS must be an integer, got {value:?}"
                ))
            })?;
            if seconds == 0 {
                return Err(IngestWatchdogError::Config(
                    "NANO_INGEST_WATCHDOG_INTERVAL_SECS must be greater than zero".into(),
                ));
            }
            config.interval = Duration::from_secs(seconds);
        }
        if let Ok(value) = std::env::var("NANO_INGEST_WATCHDOG_NODES") {
            config.explicit_endpoints = value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect();
        }
        Ok(config)
    }
}

pub fn enabled_from_env() -> bool {
    env_flag("NANO_INGEST_WATCHDOG_ENABLED", true)
}

fn env_flag(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "false" | "0" | "no"))
        .unwrap_or(default)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WatchdogMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WatchdogSample {
    pub pending_async_inserts: u64,
    pub oldest_flush_age_seconds: u64,
    pub running_queries: u64,
    pub memory_usage_bytes: u64,
    pub memory_limit_bytes: u64,
    pub refreshes_running: u64,
    pub disabled_views: Vec<String>,
}

impl WatchdogSample {
    pub fn memory_percent(&self) -> u64 {
        if self.memory_limit_bytes == 0 {
            0
        } else {
            self.memory_usage_bytes.saturating_mul(100) / self.memory_limit_bytes
        }
    }

    pub fn hot_reasons(&self, config: &IngestWatchdogConfig) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.pending_async_inserts >= config.pending_async_insert_limit {
            reasons.push(format!(
                "pending_async_inserts={} (limit {})",
                self.pending_async_inserts, config.pending_async_insert_limit
            ));
        }
        if self.oldest_flush_age_seconds > config.oldest_flush_age_limit {
            reasons.push(format!(
                "oldest_flush_age_seconds={} (limit {})",
                self.oldest_flush_age_seconds, config.oldest_flush_age_limit
            ));
        }
        if self.memory_limit_bytes > 0
            && self.memory_usage_bytes.saturating_mul(100)
                > self
                    .memory_limit_bytes
                    .saturating_mul(config.memory_limit_percent)
        {
            reasons.push(format!(
                "memory_percent={} (limit {})",
                self.memory_percent(),
                config.memory_limit_percent
            ));
        }
        if self.running_queries >= config.running_query_limit {
            reasons.push(format!(
                "running_queries={} (limit {})",
                self.running_queries, config.running_query_limit
            ));
        }
        reasons
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogDecision {
    None,
    StopViews,
    StartViews,
    CatchUpAfterRestart,
    RecordObservedManualStop,
    ReapplyManualStopAfterRestart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub(crate) struct OwnedView {
    pub(crate) replica: String,
    pub(crate) endpoint: String,
    pub(crate) database: String,
    pub(crate) view: String,
}

#[derive(Debug, Clone)]
struct PendingTransition {
    id: Uuid,
    owned_views: Vec<OwnedView>,
}

#[derive(Debug, Clone)]
pub struct WatchdogState {
    pub mode: WatchdogMode,
    pub shedding: bool,
    pub hot_streak: u16,
    pub calm_streak: u16,
    pub last_transition: Option<DateTime<Utc>>,
    owned_views: Vec<OwnedView>,
    pending: Option<PendingTransition>,
}

impl Default for WatchdogState {
    fn default() -> Self {
        Self {
            mode: WatchdogMode::Auto,
            shedding: false,
            hot_streak: 0,
            calm_streak: 0,
            last_transition: None,
            owned_views: Vec::new(),
            pending: None,
        }
    }
}

impl WatchdogState {
    pub fn observe(
        &mut self,
        sample: &WatchdogSample,
        now: DateTime<Utc>,
        config: &IngestWatchdogConfig,
    ) -> WatchdogDecision {
        self.observe_with_coverage(sample, true, now, config)
    }

    pub fn observe_with_coverage(
        &mut self,
        sample: &WatchdogSample,
        all_replicas_reachable: bool,
        now: DateTime<Utc>,
        config: &IngestWatchdogConfig,
    ) -> WatchdogDecision {
        if self.pending.is_some() {
            return WatchdogDecision::None;
        }
        if self.mode == WatchdogMode::Manual {
            self.hot_streak = 0;
            self.calm_streak = 0;
            if all_replicas_reachable && self.shedding && sample.disabled_views.is_empty() {
                self.last_transition = Some(now);
                return WatchdogDecision::ReapplyManualStopAfterRestart;
            }
            return WatchdogDecision::None;
        }
        if all_replicas_reachable && !sample.disabled_views.is_empty() && !self.shedding {
            self.mode = WatchdogMode::Manual;
            self.shedding = true;
            self.hot_streak = 0;
            self.calm_streak = 0;
            self.last_transition = Some(now);
            return WatchdogDecision::RecordObservedManualStop;
        }
        if all_replicas_reachable && self.shedding && sample.disabled_views.is_empty() {
            self.shedding = false;
            self.hot_streak = 0;
            self.calm_streak = 0;
            self.last_transition = Some(now);
            return WatchdogDecision::CatchUpAfterRestart;
        }

        if !sample.hot_reasons(config).is_empty() {
            self.hot_streak = self.hot_streak.saturating_add(1);
            self.calm_streak = 0;
            if !self.shedding
                && self.hot_streak >= config.hot_consecutive
                && anti_flap_elapsed(self.last_transition, now, config.anti_flap)
            {
                self.shedding = true;
                self.hot_streak = 0;
                self.last_transition = Some(now);
                return WatchdogDecision::StopViews;
            }
        } else if all_replicas_reachable {
            self.calm_streak = self.calm_streak.saturating_add(1);
            self.hot_streak = 0;
            if self.shedding
                && self.calm_streak >= config.calm_consecutive
                && anti_flap_elapsed(self.last_transition, now, config.anti_flap)
            {
                self.shedding = false;
                self.calm_streak = 0;
                self.last_transition = Some(now);
                return WatchdogDecision::StartViews;
            }
        } else {
            // Missing coverage is neither hot nor calm.
            self.calm_streak = 0;
        }
        WatchdogDecision::None
    }
}

fn anti_flap_elapsed(
    last_transition: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    anti_flap: Duration,
) -> bool {
    last_transition.is_none_or(|last| {
        now.signed_duration_since(last).num_seconds() >= anti_flap.as_secs() as i64
    })
}

#[derive(Debug, Row, Deserialize)]
struct SampleRow {
    pending_async_inserts: u64,
    oldest_flush_age_seconds: u64,
    running_queries: u64,
    memory_usage_bytes: u64,
    memory_limit_bytes: u64,
    refreshes_running: u64,
    disabled_views: Vec<String>,
}

impl From<SampleRow> for WatchdogSample {
    fn from(row: SampleRow) -> Self {
        Self {
            pending_async_inserts: row.pending_async_inserts,
            oldest_flush_age_seconds: row.oldest_flush_age_seconds,
            running_queries: row.running_queries,
            memory_usage_bytes: row.memory_usage_bytes,
            memory_limit_bytes: row.memory_limit_bytes,
            refreshes_running: row.refreshes_running,
            disabled_views: row.disabled_views,
        }
    }
}

#[derive(Debug, Row, Deserialize)]
struct JournalStateRow {
    event_id: Uuid,
    transition_id: Uuid,
    action: String,
    phase: String,
    mode: String,
    event_time_ms: i64,
    owned_views: Vec<String>,
}

#[derive(Clone)]
struct WatchdogReplica {
    name: String,
    endpoint: String,
    client: Client,
}

struct WatchdogNode {
    name: String,
    replicas: Vec<WatchdogReplica>,
    state: Mutex<WatchdogState>,
    state_loaded: Mutex<bool>,
    reachable_replicas: Mutex<BTreeSet<String>>,
}

#[derive(Debug, Clone)]
struct ReplicaObservation {
    replica: String,
    endpoint: String,
    sample: Option<WatchdogSample>,
    views: Vec<(String, String)>,
    error: Option<String>,
}

impl ReplicaObservation {
    fn reachable(&self) -> bool {
        self.sample.is_some()
    }
}

#[derive(Clone)]
pub struct IngestWatchdog {
    config: IngestWatchdogConfig,
    nodes: Vec<Arc<WatchdogNode>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchdogReplicaStatus {
    pub replica: String,
    pub endpoint: String,
    pub reachable: bool,
    pub error: Option<String>,
    pub hot: bool,
    pub sample: Option<WatchdogSample>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchdogNodeStatus {
    pub node: String,
    pub mode: WatchdogMode,
    pub shedding: bool,
    pub hot_streak: u16,
    pub calm_streak: u16,
    pub coverage_degraded: bool,
    pub sample: WatchdogSample,
    pub replicas: Vec<WatchdogReplicaStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogOperatorAction {
    Status,
    ManualStop,
    ManualStart,
    Auto,
}

impl IngestWatchdog {
    pub async fn from_env() -> Result<Self, IngestWatchdogError> {
        let config = IngestWatchdogConfig::from_env()?;
        let base_url = std::env::var("CLICKHOUSE_URL")
            .map_err(|_| IngestWatchdogError::MissingEnv("CLICKHOUSE_URL"))?;
        let database = std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| DATABASE.into());
        let runtime_user = std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "nanosiem".into());
        let runtime_password = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
        let user = std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or(runtime_user);
        let password = std::env::var("CLICKHOUSE_ADMIN_PASSWORD").unwrap_or(runtime_password);
        let base_client = node_client(&base_url, &database, &user, &password);

        let groups = if config.explicit_endpoints.is_empty() {
            tokio::time::timeout(
                IO_TIMEOUT,
                discover_endpoint_groups(&base_client, &base_url),
            )
            .await
            .map_err(|_| {
                IngestWatchdogError::ClickHouse(format!(
                    "endpoint discovery timed out after {}s",
                    IO_TIMEOUT.as_secs()
                ))
            })??
        } else {
            config
                .explicit_endpoints
                .iter()
                .enumerate()
                .map(|(index, endpoint)| {
                    vec![EndpointSpec {
                        name: format!("explicit-{}", index + 1),
                        endpoint: endpoint.clone(),
                    }]
                })
                .collect()
        };
        if groups.is_empty() {
            return Err(IngestWatchdogError::Config(
                "no ClickHouse watchdog endpoints resolved".into(),
            ));
        }

        let nodes = groups
            .into_iter()
            .enumerate()
            .map(|(index, endpoints)| {
                let replicas = endpoints
                    .into_iter()
                    .map(|endpoint| WatchdogReplica {
                        client: node_client(&endpoint.endpoint, &database, &user, &password),
                        name: endpoint.name,
                        endpoint: endpoint.endpoint,
                    })
                    .collect();
                Arc::new(WatchdogNode {
                    name: format!("shard-{}", index + 1),
                    replicas,
                    state: Mutex::new(WatchdogState::default()),
                    state_loaded: Mutex::new(false),
                    reachable_replicas: Mutex::new(BTreeSet::new()),
                })
            })
            .collect();
        Ok(Self { config, nodes })
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move { self.run().await })
    }

    pub async fn run(&self) {
        futures::future::join_all(
            self.nodes
                .iter()
                .map(|node| self.run_node_loop(node.as_ref())),
        )
        .await;
    }

    pub async fn run_once(&self) {
        futures::future::join_all(
            self.nodes
                .iter()
                .map(|node| self.run_node_once(node.as_ref())),
        )
        .await;
    }

    async fn run_node_loop(&self, node: &WatchdogNode) {
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.run_node_once(node).await;
        }
    }

    async fn run_node_once(&self, node: &WatchdogNode) {
        if let Err(error) = self.tick_node(node).await {
            tracing::warn!(node = %node.name, %error, "Ingest watchdog pass failed; retrying next interval");
        }
    }

    async fn tick_node(&self, node: &WatchdogNode) -> Result<(), IngestWatchdogError> {
        let observations = sample_replicas(node).await;
        invalidate_state_when_coverage_changes(node, &observations).await;
        persist_replica_status(node, &observations, &self.config).await;
        let all_reachable = observations.iter().all(ReplicaObservation::reachable);
        let sample = aggregate_sample(&observations);
        self.ensure_state_loaded(node, &observations).await?;
        if self.reconcile_pending(node, &sample).await? {
            return Ok(());
        }
        if all_reachable
            && self
                .reconcile_process_restart(node, &observations, &sample)
                .await?
        {
            return Ok(());
        }

        let now = Utc::now();
        let (decision, snapshot, previous) = {
            let mut state = node.state.lock().await;
            let previous = state.clone();
            let decision = state.observe_with_coverage(&sample, all_reachable, now, &self.config);
            (decision, state.clone(), previous)
        };
        let reasons = hot_reasons_for_observations(&observations, &self.config).join("; ");
        match decision {
            WatchdogDecision::None => {}
            WatchdogDecision::RecordObservedManualStop => {
                let owned = disabled_owned_views(&observations);
                let mut state = snapshot;
                state.owned_views = owned.clone();
                if let Err(error) = journal(
                    node,
                    Uuid::now_v7(),
                    "observed_manual_stop",
                    "completed",
                    WatchdogMode::Manual,
                    "view disabled outside watchdog ownership",
                    &sample,
                    &state,
                    &owned,
                )
                .await
                {
                    restore_after_failed_transition(node, previous).await;
                    return Err(error);
                }
                *node.state.lock().await = state;
            }
            WatchdogDecision::ReapplyManualStopAfterRestart => {
                let owned = previous.owned_views.clone();
                let result = async {
                    apply_views(node, &owned, false).await?;
                    journal(
                        node,
                        Uuid::now_v7(),
                        "manual_stop_reapplied",
                        "completed",
                        WatchdogMode::Manual,
                        "ClickHouse restarted; exact manual set re-applied",
                        &sample,
                        &snapshot,
                        &owned,
                    )
                    .await
                }
                .await;
                if let Err(error) = result {
                    restore_after_failed_transition(node, previous).await;
                    return Err(error);
                }
            }
            WatchdogDecision::StopViews => {
                let owned = expected_owned_views(node, &observations);
                if owned.is_empty() {
                    *node.state.lock().await = previous;
                    return Ok(());
                }
                let transition_id = Uuid::now_v7();
                // The durable intent is the linearization point: no STOP may
                // precede this successful write.
                if let Err(error) = journal(
                    node,
                    transition_id,
                    "auto_stop",
                    "intent",
                    WatchdogMode::Auto,
                    &reasons,
                    &sample,
                    &snapshot,
                    &owned,
                )
                .await
                {
                    restore_after_failed_transition(node, previous).await;
                    return Err(error);
                }
                {
                    let mut state = node.state.lock().await;
                    state.owned_views = owned.clone();
                    state.pending = Some(PendingTransition {
                        id: transition_id,
                        owned_views: owned,
                    });
                }
                self.reconcile_pending(node, &sample).await?;
            }
            WatchdogDecision::StartViews | WatchdogDecision::CatchUpAfterRestart => {
                let owned = previous.owned_views.clone();
                let action = if decision == WatchdogDecision::CatchUpAfterRestart {
                    "auto_start_after_restart"
                } else {
                    "auto_start"
                };
                let result = async {
                    apply_views(node, &owned, true).await?;
                    catch_up(node, &owned).await?;
                    journal(
                        node,
                        Uuid::now_v7(),
                        action,
                        "completed",
                        WatchdogMode::Auto,
                        "exact watchdog-owned views started and refreshed",
                        &sample,
                        &snapshot,
                        &owned,
                    )
                    .await
                }
                .await;
                if let Err(error) = result {
                    restore_after_failed_transition(node, previous).await;
                    return Err(error);
                }
                let mut state = node.state.lock().await;
                state.owned_views.clear();
                state.pending = None;
            }
        }
        Ok(())
    }

    async fn ensure_state_loaded(
        &self,
        node: &WatchdogNode,
        observations: &[ReplicaObservation],
    ) -> Result<(), IngestWatchdogError> {
        if *node.state_loaded.lock().await {
            return Ok(());
        }
        let mut latest: Option<JournalStateRow> = None;
        let mut reachable_count = 0_usize;
        let mut loaded_count = 0_usize;
        for replica in &node.replicas {
            let reachable = observations
                .iter()
                .any(|observation| observation.replica == replica.name && observation.reachable());
            if !reachable {
                continue;
            }
            reachable_count += 1;
            match tokio::time::timeout(IO_TIMEOUT, load_state_row(&replica.client, &node.name))
                .await
            {
                Ok(Ok(row)) => {
                    loaded_count += 1;
                    if row.as_ref().is_some_and(|candidate| {
                        latest.as_ref().is_none_or(|current| {
                            (candidate.event_time_ms, candidate.event_id)
                                > (current.event_time_ms, current.event_id)
                        })
                    }) {
                        latest = row;
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(node = %node.name, replica = %replica.name, %error,
                    "Could not load watchdog state from replica")
                }
                Err(_) => tracing::warn!(
                    node = %node.name,
                    replica = %replica.name,
                    timeout_seconds = IO_TIMEOUT.as_secs(),
                    "Loading watchdog state timed out"
                ),
            }
        }
        if reachable_count == 0 {
            return Err(IngestWatchdogError::ClickHouse(format!(
                "no reachable replica could load durable state for {}",
                node.name
            )));
        }
        if loaded_count != reachable_count {
            return Err(IngestWatchdogError::ClickHouse(format!(
                "loaded durable state from {loaded_count} of {reachable_count} reachable replicas for {}",
                node.name
            )));
        }
        let state = latest
            .map(state_from_journal_row)
            .transpose()?
            .unwrap_or_default();
        *node.state.lock().await = state;
        *node.state_loaded.lock().await = true;
        Ok(())
    }

    async fn reconcile_pending(
        &self,
        node: &WatchdogNode,
        sample: &WatchdogSample,
    ) -> Result<bool, IngestWatchdogError> {
        let pending = node.state.lock().await.pending.clone();
        let Some(pending) = pending else {
            return Ok(false);
        };
        if pending.owned_views.is_empty() {
            let state = node.state.lock().await.clone();
            journal(
                node,
                pending.id,
                "auto_stop",
                "rolled_back",
                WatchdogMode::Auto,
                "empty intent rolled back without STOP",
                sample,
                &state,
                &[],
            )
            .await?;
            *node.state.lock().await = WatchdogState::default();
            return Ok(true);
        }

        // Singular STOP VIEW is idempotent. A crash after any subset is fixed
        // by replaying the exact durable intent, never by calling it manual.
        apply_views(node, &pending.owned_views, false).await?;
        let mut completed = node.state.lock().await.clone();
        completed.shedding = true;
        completed.pending = None;
        completed.owned_views = pending.owned_views.clone();
        journal(
            node,
            pending.id,
            "auto_stop",
            "completed",
            WatchdogMode::Auto,
            "durable stop intent fully applied",
            sample,
            &completed,
            &pending.owned_views,
        )
        .await?;
        *node.state.lock().await = completed;
        Ok(true)
    }

    async fn reconcile_process_restart(
        &self,
        node: &WatchdogNode,
        observations: &[ReplicaObservation],
        sample: &WatchdogSample,
    ) -> Result<bool, IngestWatchdogError> {
        let state = node.state.lock().await.clone();
        if !state.shedding || state.owned_views.is_empty() {
            return Ok(false);
        }
        let disabled: BTreeSet<OwnedView> =
            disabled_owned_views(observations).into_iter().collect();
        if state.owned_views.iter().all(|view| disabled.contains(view)) {
            return Ok(false);
        }

        if state.mode == WatchdogMode::Manual {
            apply_views(node, &state.owned_views, false).await?;
            journal(
                node,
                Uuid::now_v7(),
                "manual_stop_reapplied",
                "completed",
                WatchdogMode::Manual,
                "ClickHouse restart cleared part of the exact manual set",
                sample,
                &state,
                &state.owned_views,
            )
            .await?;
        } else {
            // A process restart clears STOP VIEW. Starting every owned view is
            // idempotent and avoids leaving replicas split, then catch up once.
            apply_views(node, &state.owned_views, true).await?;
            catch_up(node, &state.owned_views).await?;
            let mut completed = state.clone();
            completed.shedding = false;
            completed.owned_views.clear();
            journal(
                node,
                Uuid::now_v7(),
                "auto_start_after_restart",
                "completed",
                WatchdogMode::Auto,
                "ClickHouse restart cleared part of watchdog-owned set",
                sample,
                &completed,
                &state.owned_views,
            )
            .await?;
            *node.state.lock().await = completed;
        }
        Ok(true)
    }

    pub async fn operator(
        &self,
        action: WatchdogOperatorAction,
    ) -> Result<Vec<WatchdogNodeStatus>, IngestWatchdogError> {
        for node in &self.nodes {
            let observations = sample_replicas(node).await;
            self.ensure_state_loaded(node, &observations).await?;
            if !observations.iter().all(ReplicaObservation::reachable) {
                return Err(IngestWatchdogError::ClickHouse(format!(
                    "{} has unreachable replicas; refusing a partial operator transition",
                    node.name
                )));
            }
            let sample = aggregate_sample(&observations);
            match action {
                WatchdogOperatorAction::Status => {}
                WatchdogOperatorAction::ManualStop => {
                    let owned = expected_owned_views(node, &observations);
                    apply_views(node, &owned, false).await?;
                    let state = WatchdogState {
                        mode: WatchdogMode::Manual,
                        shedding: true,
                        last_transition: Some(Utc::now()),
                        owned_views: owned.clone(),
                        ..WatchdogState::default()
                    };
                    journal(
                        node,
                        Uuid::now_v7(),
                        "manual_stop",
                        "completed",
                        WatchdogMode::Manual,
                        "operator command",
                        &sample,
                        &state,
                        &owned,
                    )
                    .await?;
                    *node.state.lock().await = state;
                }
                WatchdogOperatorAction::ManualStart => {
                    let old = node.state.lock().await.clone();
                    apply_views(node, &old.owned_views, true).await?;
                    catch_up(node, &old.owned_views).await?;
                    let state = WatchdogState {
                        mode: WatchdogMode::Manual,
                        shedding: false,
                        last_transition: Some(Utc::now()),
                        ..WatchdogState::default()
                    };
                    journal(
                        node,
                        Uuid::now_v7(),
                        "manual_start",
                        "completed",
                        WatchdogMode::Manual,
                        "operator command",
                        &sample,
                        &state,
                        &old.owned_views,
                    )
                    .await?;
                    *node.state.lock().await = state;
                }
                WatchdogOperatorAction::Auto => {
                    let old = node.state.lock().await.clone();
                    let state = WatchdogState {
                        mode: WatchdogMode::Auto,
                        shedding: old.shedding,
                        last_transition: Some(Utc::now()),
                        owned_views: old.owned_views.clone(),
                        ..WatchdogState::default()
                    };
                    let action = if state.shedding {
                        "auto_enabled_shedding"
                    } else {
                        "auto_enabled"
                    };
                    journal(
                        node,
                        Uuid::now_v7(),
                        action,
                        "completed",
                        WatchdogMode::Auto,
                        "operator command",
                        &sample,
                        &state,
                        &state.owned_views,
                    )
                    .await?;
                    *node.state.lock().await = state;
                }
            }
        }
        self.status().await
    }

    pub async fn status(&self) -> Result<Vec<WatchdogNodeStatus>, IngestWatchdogError> {
        let mut statuses = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let observations = sample_replicas(node).await;
            let sample = aggregate_sample(&observations);
            let state = node.state.lock().await.clone();
            statuses.push(WatchdogNodeStatus {
                node: node.name.clone(),
                mode: state.mode,
                shedding: state.shedding,
                hot_streak: state.hot_streak,
                calm_streak: state.calm_streak,
                coverage_degraded: observations
                    .iter()
                    .any(|observation| !observation.reachable()),
                sample,
                replicas: observations
                    .into_iter()
                    .map(|observation| {
                        let reachable = observation.reachable();
                        let hot = observation
                            .sample
                            .as_ref()
                            .is_some_and(|sample| !sample.hot_reasons(&self.config).is_empty());
                        WatchdogReplicaStatus {
                            replica: observation.replica,
                            endpoint: observation.endpoint,
                            reachable,
                            error: observation.error,
                            hot,
                            sample: observation.sample,
                        }
                    })
                    .collect(),
            });
        }
        Ok(statuses)
    }
}

async fn restore_after_failed_transition(node: &WatchdogNode, previous: WatchdogState) {
    *node.state.lock().await = previous;
    // A timed-out journal request has an uncertain outcome. Reloading before
    // the next decision makes a late durable intent visible and prevents an
    // incomplete automatic transition from being reclassified as manual.
    *node.state_loaded.lock().await = false;
}

async fn invalidate_state_when_coverage_changes(
    node: &WatchdogNode,
    observations: &[ReplicaObservation],
) {
    let reachable: BTreeSet<String> = observations
        .iter()
        .filter(|observation| observation.reachable())
        .map(|observation| observation.replica.clone())
        .collect();
    let mut previous = node.reachable_replicas.lock().await;
    if *previous != reachable {
        *previous = reachable;
        *node.state_loaded.lock().await = false;
    }
}

fn node_client(endpoint: &str, database: &str, user: &str, password: &str) -> Client {
    let mut client = clickhouse_transport::client()
        .with_url(endpoint)
        .with_database(database)
        .with_user(user);
    if !password.is_empty() {
        client = client.with_password(password);
    }
    client
}

struct EndpointSpec {
    name: String,
    endpoint: String,
}

async fn discover_endpoint_groups(
    client: &Client,
    base_url: &str,
) -> Result<Vec<Vec<EndpointSpec>>, IngestWatchdogError> {
    let Some(cluster) = std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Ok(vec![vec![EndpointSpec {
            name: "local".into(),
            endpoint: base_url.to_owned(),
        }]]);
    };
    let hosts = client
        .query(
            // NAN-5255: remote_servers rows only; a same-named Replicated
            // database (the operator's `default`) lists the hosts again.
            &format!(
                "SELECT toUInt64(shard_num), toUInt64(replica_num), host_name \
                 FROM system.clusters WHERE {} ORDER BY shard_num, replica_num",
                crate::db::clickhouse_migrate::server_cluster_rows_predicate("?")
            ),
        )
        .bind(cluster.as_str())
        .bind(cluster.as_str())
        .fetch_all::<(u64, u64, String)>()
        .await
        .map_err(ch_error)?;
    if hosts.is_empty() {
        return Err(IngestWatchdogError::Config(
            "CLICKHOUSE_CLUSTER did not resolve any system.clusters rows".into(),
        ));
    }
    let base = url::Url::parse(base_url)
        .map_err(|error| IngestWatchdogError::Config(format!("invalid CLICKHOUSE_URL: {error}")))?;
    let mut groups: Vec<Vec<EndpointSpec>> = Vec::new();
    let mut current_shard = None;
    for (shard, replica, host) in hosts {
        if current_shard != Some(shard) {
            groups.push(Vec::new());
            current_shard = Some(shard);
        }
        let mut endpoint = base.clone();
        endpoint.set_host(Some(&host)).map_err(|_| {
            IngestWatchdogError::Config(format!("invalid ClickHouse host_name {host:?}"))
        })?;
        groups
            .last_mut()
            .expect("shard group exists")
            .push(EndpointSpec {
                name: format!("{host}/r{replica}"),
                endpoint: endpoint.to_string().trim_end_matches('/').to_owned(),
            });
    }
    Ok(groups)
}

async fn sample_replicas(node: &WatchdogNode) -> Vec<ReplicaObservation> {
    futures::future::join_all(node.replicas.iter().map(|replica| async move {
        let result = tokio::time::timeout(IO_TIMEOUT, async {
            let sample = collect_sample(&replica.client).await?;
            let views = refreshable_views(&replica.client).await?;
            Ok::<_, IngestWatchdogError>((sample, views))
        })
        .await;
        match result {
            Ok(Ok((sample, views))) => ReplicaObservation {
                replica: replica.name.clone(),
                endpoint: replica.endpoint.clone(),
                sample: Some(sample),
                views,
                error: None,
            },
            Ok(Err(error)) => ReplicaObservation {
                replica: replica.name.clone(),
                endpoint: replica.endpoint.clone(),
                sample: None,
                views: Vec::new(),
                error: Some(error.to_string()),
            },
            Err(_) => ReplicaObservation {
                replica: replica.name.clone(),
                endpoint: replica.endpoint.clone(),
                sample: None,
                views: Vec::new(),
                error: Some(format!("sample timed out after {}s", IO_TIMEOUT.as_secs())),
            },
        }
    }))
    .await
}

fn aggregate_sample(observations: &[ReplicaObservation]) -> WatchdogSample {
    let mut result = WatchdogSample::default();
    let mut disabled = BTreeSet::new();
    for observation in observations {
        let Some(sample) = &observation.sample else {
            continue;
        };
        result.pending_async_inserts = result
            .pending_async_inserts
            .max(sample.pending_async_inserts);
        result.oldest_flush_age_seconds = result
            .oldest_flush_age_seconds
            .max(sample.oldest_flush_age_seconds);
        result.running_queries = result.running_queries.max(sample.running_queries);
        // Keep usage and limit from the same replica. Independent maxima could
        // hide a hot small replica behind a larger replica's denominator, which
        // would violate the "HOT if any target is hot" contract.
        if result.memory_limit_bytes == 0
            || (sample.memory_limit_bytes > 0
                && sample
                    .memory_usage_bytes
                    .saturating_mul(result.memory_limit_bytes)
                    > result
                        .memory_usage_bytes
                        .saturating_mul(sample.memory_limit_bytes))
        {
            result.memory_usage_bytes = sample.memory_usage_bytes;
            result.memory_limit_bytes = sample.memory_limit_bytes;
        }
        result.refreshes_running = result
            .refreshes_running
            .saturating_add(sample.refreshes_running);
        for view in &sample.disabled_views {
            disabled.insert(format!("{}|{}|{}", observation.replica, DATABASE, view));
        }
    }
    result.disabled_views = disabled.into_iter().collect();
    result
}

fn hot_reasons_for_observations(
    observations: &[ReplicaObservation],
    config: &IngestWatchdogConfig,
) -> Vec<String> {
    observations
        .iter()
        .filter_map(|observation| {
            observation
                .sample
                .as_ref()
                .map(|sample| (observation, sample))
        })
        .flat_map(|(observation, sample)| {
            sample
                .hot_reasons(config)
                .into_iter()
                .map(|reason| format!("{}: {reason}", observation.replica))
        })
        .collect()
}

fn disabled_owned_views(observations: &[ReplicaObservation]) -> Vec<OwnedView> {
    let mut result = BTreeSet::new();
    for observation in observations {
        if let Some(sample) = &observation.sample {
            for view in &sample.disabled_views {
                result.insert(OwnedView {
                    replica: observation.replica.clone(),
                    endpoint: observation.endpoint.clone(),
                    database: DATABASE.into(),
                    view: view.clone(),
                });
            }
        }
    }
    result.into_iter().collect()
}

fn expected_owned_views(
    node: &WatchdogNode,
    observations: &[ReplicaObservation],
) -> Vec<OwnedView> {
    let canonical: BTreeSet<(String, String)> = observations
        .iter()
        .flat_map(|observation| observation.views.iter().cloned())
        .collect();
    let by_replica: HashMap<&str, &ReplicaObservation> = observations
        .iter()
        .map(|observation| (observation.replica.as_str(), observation))
        .collect();
    let mut result = BTreeSet::new();
    for replica in &node.replicas {
        let views = by_replica
            .get(replica.name.as_str())
            .filter(|observation| observation.reachable())
            .map(|observation| observation.views.clone())
            .unwrap_or_else(|| canonical.iter().cloned().collect());
        for (database, view) in views {
            result.insert(OwnedView {
                replica: replica.name.clone(),
                endpoint: replica.endpoint.clone(),
                database,
                view,
            });
        }
    }
    result.into_iter().collect()
}

async fn apply_views(
    node: &WatchdogNode,
    views: &[OwnedView],
    running: bool,
) -> Result<(), IngestWatchdogError> {
    let mut errors = Vec::new();
    for owned in views {
        let Some(replica) = node
            .replicas
            .iter()
            .find(|replica| replica.name == owned.replica && replica.endpoint == owned.endpoint)
        else {
            errors.push(format!("replica {} is no longer configured", owned.replica));
            continue;
        };
        let command = if running { "START" } else { "STOP" };
        let sql = format!(
            "SYSTEM {command} VIEW {}.{}",
            escape_sql_identifier(&owned.database),
            escape_sql_identifier(&owned.view)
        );
        match tokio::time::timeout(IO_TIMEOUT, replica.client.query(&sql).execute()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("{}: {error}", replica.name)),
            Err(_) => errors.push(format!("{}: command timed out", replica.name)),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(IngestWatchdogError::ClickHouse(errors.join("; ")))
    }
}

async fn catch_up(node: &WatchdogNode, views: &[OwnedView]) -> Result<(), IngestWatchdogError> {
    let mut errors = Vec::new();
    for owned in views {
        let Some(replica) = node
            .replicas
            .iter()
            .find(|replica| replica.name == owned.replica && replica.endpoint == owned.endpoint)
        else {
            errors.push(format!("replica {} is no longer configured", owned.replica));
            continue;
        };
        let sql = format!(
            "SYSTEM REFRESH VIEW {}.{}",
            escape_sql_identifier(&owned.database),
            escape_sql_identifier(&owned.view)
        );
        match tokio::time::timeout(IO_TIMEOUT, replica.client.query(&sql).execute()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("{}: {error}", replica.name)),
            Err(_) => errors.push(format!("{}: refresh timed out", replica.name)),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(IngestWatchdogError::ClickHouse(errors.join("; ")))
    }
}

async fn collect_sample(client: &Client) -> Result<WatchdogSample, IngestWatchdogError> {
    client
        .query(
            "SELECT \
             coalesce((SELECT sum(length(entries.query_id)) FROM system.asynchronous_inserts), toUInt64(0)) AS pending_async_inserts, \
             coalesce((SELECT toUInt64(if(count() = 0, 0, greatest(0, dateDiff('second', min(first_update), now64(6))))) FROM system.asynchronous_inserts), toUInt64(0)) AS oldest_flush_age_seconds, \
             coalesce((SELECT count() FROM system.processes), toUInt64(0)) AS running_queries, \
             coalesce((SELECT toUInt64(greatest(value, 0)) FROM system.metrics WHERE metric = 'MemoryTracking'), toUInt64(0)) AS memory_usage_bytes, \
             toUInt64(getServerSetting('max_server_memory_usage')) AS memory_limit_bytes, \
             coalesce((SELECT countIf(startsWith(status, 'Running')) FROM system.view_refreshes WHERE database = 'nanosiem'), toUInt64(0)) AS refreshes_running, \
             coalesce((SELECT arraySort(groupArray(view)) FROM system.view_refreshes WHERE database = 'nanosiem' AND status = 'Disabled'), CAST([], 'Array(String)')) AS disabled_views",
        )
        .fetch_one::<SampleRow>()
        .await
        .map(Into::into)
        .map_err(ch_error)
}

async fn refreshable_views(client: &Client) -> Result<Vec<(String, String)>, IngestWatchdogError> {
    client
        .query("SELECT database, view FROM system.view_refreshes WHERE database = 'nanosiem' ORDER BY database, view")
        .fetch_all::<(String, String)>()
        .await
        .map_err(ch_error)
}

async fn load_state_row(
    client: &Client,
    node: &str,
) -> Result<Option<JournalStateRow>, IngestWatchdogError> {
    let latest = client
        .query(
            "SELECT event_id, transition_id, action, phase, mode, toUnixTimestamp64Milli(event_time) AS event_time_ms, owned_views \
             FROM nanosiem.ingest_watchdog_journal WHERE node = ? \
             ORDER BY event_time DESC, event_id DESC LIMIT 1",
        )
        .bind(node)
        .fetch_optional::<JournalStateRow>()
        .await
        .map_err(ch_error)?;
    Ok(latest)
}

fn state_from_journal_row(row: JournalStateRow) -> Result<WatchdogState, IngestWatchdogError> {
    let journal_owned_views = decode_owned_views(&row.owned_views)?;
    let mode = if row.mode == "manual" {
        WatchdogMode::Manual
    } else {
        WatchdogMode::Auto
    };
    let shedding = matches!(
        (row.action.as_str(), row.phase.as_str()),
        (
            "auto_stop" | "manual_stop" | "manual_stop_reapplied" | "observed_manual_stop",
            "completed"
        ) | ("auto_stop", "intent")
            | ("auto_enabled_shedding", "completed")
    );
    let pending = (row.action == "auto_stop" && row.phase == "intent").then(|| PendingTransition {
        id: row.transition_id,
        owned_views: journal_owned_views.clone(),
    });
    // Completed START rows retain the exact set for audit, but they no longer
    // confer operational ownership when reconstructed after a process restart.
    let owned_views = if shedding || pending.is_some() {
        journal_owned_views
    } else {
        Vec::new()
    };
    Ok(WatchdogState {
        mode,
        shedding,
        hot_streak: 0,
        calm_streak: 0,
        last_transition: Utc.timestamp_millis_opt(row.event_time_ms).single(),
        owned_views,
        pending,
    })
}

fn encode_owned_views(views: &[OwnedView]) -> Result<Vec<String>, IngestWatchdogError> {
    views
        .iter()
        .map(|view| {
            serde_json::to_string(view)
                .map_err(|error| IngestWatchdogError::Config(error.to_string()))
        })
        .collect()
}

fn decode_owned_views(encoded: &[String]) -> Result<Vec<OwnedView>, IngestWatchdogError> {
    encoded
        .iter()
        .map(|view| {
            serde_json::from_str(view).map_err(|error| {
                IngestWatchdogError::Config(format!("invalid owned view in journal: {error}"))
            })
        })
        .collect()
}

/// The transition journal is also the SIEM Health state source. Intent rows
/// retain the observation made before STOP, but a completed STOP derives its
/// disabled set from the exact commands that succeeded. That makes the latest
/// row describe post-transition state without a second fallible sample.
pub(crate) fn journal_disabled_views(
    action: &str,
    phase: &str,
    sample: &WatchdogSample,
    owned_views: &[OwnedView],
) -> Vec<String> {
    if phase == "completed"
        && matches!(
            action,
            "auto_stop" | "manual_stop" | "manual_stop_reapplied" | "observed_manual_stop"
        )
    {
        return owned_views
            .iter()
            .map(|view| format!("{}|{}|{}", view.replica, view.database, view.view))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    sample.disabled_views.clone()
}

#[allow(clippy::too_many_arguments)]
async fn journal(
    node: &WatchdogNode,
    transition_id: Uuid,
    action: &str,
    phase: &str,
    mode: WatchdogMode,
    reason: &str,
    sample: &WatchdogSample,
    state: &WatchdogState,
    owned_views: &[OwnedView],
) -> Result<(), IngestWatchdogError> {
    let encoded = encode_owned_views(owned_views)?;
    let disabled_views = journal_disabled_views(action, phase, sample, owned_views);
    let mut errors = Vec::new();
    for replica in &node.replicas {
        // This is a write-ahead control record, not ordinary ingest. Force a
        // synchronous commit so a successful await really precedes STOP VIEW.
        let durable_client = replica
            .client
            .clone()
            .with_option("async_insert", "0")
            .with_option("wait_end_of_query", "1");
        let result = tokio::time::timeout(
            IO_TIMEOUT,
            durable_client
                .query(
                    "INSERT INTO nanosiem.ingest_watchdog_journal \
                 (event_id, transition_id, event_time, node, action, phase, mode, reason, \
                  pending_async_inserts, oldest_flush_age_seconds, running_queries, \
                  memory_usage_bytes, memory_limit_bytes, refreshes_running, disabled_views, \
                  owned_views, hot_streak, calm_streak) \
                 VALUES (?, ?, now64(3), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(Uuid::now_v7())
                .bind(transition_id)
                .bind(&node.name)
                .bind(action)
                .bind(phase)
                .bind(match mode {
                    WatchdogMode::Auto => "auto",
                    WatchdogMode::Manual => "manual",
                })
                .bind(reason)
                .bind(sample.pending_async_inserts)
                .bind(sample.oldest_flush_age_seconds)
                .bind(sample.running_queries)
                .bind(sample.memory_usage_bytes)
                .bind(sample.memory_limit_bytes)
                .bind(sample.refreshes_running)
                .bind(&disabled_views)
                .bind(&encoded)
                .bind(state.hot_streak)
                .bind(state.calm_streak)
                .execute(),
        )
        .await;
        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => errors.push(format!("{}: {error}", replica.name)),
            Err(_) => errors.push(format!(
                "{}: journal write timed out after {}s",
                replica.name,
                IO_TIMEOUT.as_secs()
            )),
        }
    }
    Err(IngestWatchdogError::ClickHouse(format!(
        "journal write failed on every replica: {}",
        errors.join("; ")
    )))
}

async fn persist_replica_status(
    node: &WatchdogNode,
    observations: &[ReplicaObservation],
    config: &IngestWatchdogConfig,
) {
    let Some(writer) = observations
        .iter()
        .find(|observation| observation.reachable())
        .and_then(|observation| {
            node.replicas
                .iter()
                .find(|replica| replica.name == observation.replica)
        })
    else {
        return;
    };
    for observation in observations {
        let sample = observation.sample.clone().unwrap_or_default();
        let result = tokio::time::timeout(
            IO_TIMEOUT,
            writer
                .client
                .query(
                    "INSERT INTO nanosiem.ingest_watchdog_replica_status \
                 (observed_at, node, replica, endpoint, reachable, error, hot, \
                  pending_async_inserts, oldest_flush_age_seconds, running_queries, \
                  memory_usage_bytes, memory_limit_bytes, refreshes_running, disabled_views) \
                 VALUES (now64(3), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&node.name)
                .bind(&observation.replica)
                .bind(&observation.endpoint)
                .bind(observation.reachable())
                .bind(observation.error.as_deref().unwrap_or(""))
                .bind(
                    observation
                        .sample
                        .as_ref()
                        .is_some_and(|sample| !sample.hot_reasons(config).is_empty()),
                )
                .bind(sample.pending_async_inserts)
                .bind(sample.oldest_flush_age_seconds)
                .bind(sample.running_queries)
                .bind(sample.memory_usage_bytes)
                .bind(sample.memory_limit_bytes)
                .bind(sample.refreshes_running)
                .bind(&sample.disabled_views)
                .execute(),
        )
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!(node = %node.name, replica = %observation.replica, %error,
                    "Could not persist watchdog replica status");
                return;
            }
            Err(_) => {
                tracing::warn!(
                    node = %node.name,
                    replica = %observation.replica,
                    timeout_seconds = IO_TIMEOUT.as_secs(),
                    "Persisting watchdog replica status timed out"
                );
                return;
            }
        }
    }
}

fn ch_error(error: clickhouse::error::Error) -> IngestWatchdogError {
    IngestWatchdogError::ClickHouse(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_auto_stop_remains_auto_and_reconcilable() {
        let owned = OwnedView {
            replica: "r1".into(),
            endpoint: "http://r1:8123".into(),
            database: "nanosiem".into(),
            view: "refresh_one".into(),
        };
        let row = JournalStateRow {
            event_id: Uuid::now_v7(),
            transition_id: Uuid::now_v7(),
            action: "auto_stop".into(),
            phase: "intent".into(),
            mode: "auto".into(),
            event_time_ms: 1,
            owned_views: encode_owned_views(std::slice::from_ref(&owned)).unwrap(),
        };
        let state = state_from_journal_row(row).unwrap();
        assert_eq!(state.mode, WatchdogMode::Auto);
        assert!(state.shedding);
        assert!(state.pending.is_some());
        assert_eq!(state.owned_views, vec![owned]);
    }

    #[test]
    fn completed_start_retains_audit_set_without_restoring_ownership() {
        for (action, mode) in [("auto_start", "auto"), ("manual_start", "manual")] {
            let owned = OwnedView {
                replica: "r1".into(),
                endpoint: "http://r1:8123".into(),
                database: "nanosiem".into(),
                view: "refresh_one".into(),
            };
            let row = JournalStateRow {
                event_id: Uuid::now_v7(),
                transition_id: Uuid::now_v7(),
                action: action.into(),
                phase: "completed".into(),
                mode: mode.into(),
                event_time_ms: 1,
                owned_views: encode_owned_views(&[owned]).unwrap(),
            };
            let state = state_from_journal_row(row).unwrap();
            assert!(!state.shedding, "{action}");
            assert!(state.pending.is_none(), "{action}");
            assert!(state.owned_views.is_empty(), "{action}");
        }
    }

    #[test]
    fn implementation_has_no_global_plural_view_command() {
        let source = include_str!("ingest_watchdog.rs");
        assert!(!source.contains(concat!("SYSTEM STOP ", "VIEWS")));
        assert!(!source.contains(concat!("SYSTEM START ", "VIEWS")));
        assert!(source.contains("SYSTEM {command} VIEW"));
    }

    #[test]
    fn aggregate_keeps_the_hottest_replicas_memory_denominator() {
        let observation = |replica: &str, used, limit| ReplicaObservation {
            replica: replica.into(),
            endpoint: format!("http://{replica}:8123"),
            sample: Some(WatchdogSample {
                memory_usage_bytes: used,
                memory_limit_bytes: limit,
                ..WatchdogSample::default()
            }),
            views: Vec::new(),
            error: None,
        };
        let sample = aggregate_sample(&[
            observation("small-hot", 3, 4),
            observation("large-calm", 4, 16),
        ]);
        assert_eq!(
            (sample.memory_usage_bytes, sample.memory_limit_bytes),
            (3, 4)
        );
        assert!(
            !sample
                .hot_reasons(&IngestWatchdogConfig::default())
                .is_empty()
        );
    }
}
