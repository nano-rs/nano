// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role-split deploy grading (NAN-5133).
//!
//! In the role-split topology (`NANO_VECTOR_CONFIG_DELIVERY=generation`) no
//! Vector reads the tree nano-api writes. Each ingest host's config consumer
//! pulls the published generation from the API and installs it. Sending a
//! local reload signal there can only fail, and that failure used to be the
//! verdict: every parser deploy returned `success: false` with "No reload was
//! delivered to Vector", even though the consumers installed the change.
//!
//! In this mode, a reload means: publish the database's current configuration
//! as a generation (the [`GenerationPublisher`] the API installs at boot), then
//! ask every ingest host's tap relay (`GET /v1/generation`) what it did with
//! it:
//!
//! * every host installed it (or something newer): **acknowledged**;
//! * any host refused, saw Vector reject, or rolled it back: **rejected**;
//! * otherwise, when the wait ends: **pending**. The generation is published
//!   and the remaining hosts apply it on their next sync. This is reported as
//!   a success that names the hosts that have not confirmed yet, not as a
//!   failure, as long as every host that has not confirmed answered its relay
//!   (NAN-5279). Only a host whose relay did not answer at all (unreachable, a
//!   drifted tap token) with no host confirming keeps the deploy unconfirmed.
//!
//! NAN-5279: a consumer installs one generation at a time and each install
//! waits for Vector's acknowledgement, so two back-to-back generations (an
//! import publishes one, the deploy that follows publishes the next) take two
//! install cycles. The wait is derived from the consumer's timings to cover
//! that, and a deploy that still outlasts it reports `pending` with a status
//! endpoint to re-check ([`delivery_status`], served at
//! `GET /api/log-sources/delivery-status?generation=N`).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};

use crate::parsers::pipe::tap::{MIN_TOKEN_BYTES, RELAY_TOKEN_ENV, RELAY_URLS_ENV, RELAY_URL_ENV};

/// Selects generation delivery (role split). Any other value, or unset, keeps
/// the single-host signal-and-metrics path.
pub const DELIVERY_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY";
/// How long a deploy waits for the ingest hosts' acknowledgement. When set to
/// a number it wins; unset or empty, the wait is derived from the consumer's
/// timings ([`derived_ack_timeout`]).
pub const DELIVERY_ACK_TIMEOUT_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY_ACK_TIMEOUT_SECS";
/// The ingest consumers' generation poll (their `SYNC_INTERVAL`).
pub const CONSUMER_SYNC_INTERVAL_ENV: &str = "NANO_VECTOR_CONFIG_SYNC_INTERVAL_SECS";
/// The ingest consumers' per-install Vector acknowledgement wait (their
/// `ACK_TIMEOUT_SECS`).
pub const CONSUMER_ACK_TIMEOUT_ENV: &str = "NANO_VECTOR_CONFIG_CONSUMER_ACK_TIMEOUT_SECS";
/// `vector-config-consumer.sh` defaults (`SYNC_INTERVAL`, `ACK_TIMEOUT_SECS`).
pub const DEFAULT_CONSUMER_SYNC_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_CONSUMER_ACK_TIMEOUT_SECS: u64 = 60;
/// Download, stage and reload around one install, on top of the ack wait.
const INSTALL_OVERHEAD_SECS: u64 = 10;
/// Install cycles a deploy waits for: the one a host may be in the middle of
/// (an import's generation) plus the deploy's own.
const INSTALL_CYCLES_COVERED: u64 = 2;
/// Bounds on the derived wait. The edge gives deploy routes 300 s (NAN-5131)
/// and the render plus `vector validate` before the reload can take 90 s on a
/// small host, so the wait stays well inside what is left.
const MIN_DELIVERY_ACK_TIMEOUT_SECS: u64 = 30;
const MAX_DELIVERY_ACK_TIMEOUT_SECS: u64 = 180;
/// Kept for callers that referenced the old fixed default; the effective
/// default is now [`derived_ack_timeout`].
pub const DEFAULT_DELIVERY_ACK_TIMEOUT_SECS: u64 = 90;
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Where an operator re-checks a pending deploy (relative to the API root).
pub const DELIVERY_STATUS_PATH: &str = "/api/log-sources/delivery-status";

/// Publishes the database's current Vector configuration as a generation and
/// returns its number. nano-api implements it with its publication reconcile.
pub trait GenerationPublisher: Send + Sync {
    fn publish_current(&self) -> BoxFuture<'_, Result<i64, String>>;
}

static PUBLISHER: OnceLock<Arc<dyn GenerationPublisher>> = OnceLock::new();
static LAST_NOTE: Mutex<Option<(String, GenerationDelivery)>> = Mutex::new(None);

/// Whether this process is configured for generation delivery.
pub fn generation_delivery_configured() -> bool {
    std::env::var(DELIVERY_ENV)
        .is_ok_and(|value| value.trim().eq_ignore_ascii_case("generation"))
}

/// Install the publisher. Called once at API boot, and only when
/// [`generation_delivery_configured`]. Returns false if one was already set.
pub fn install_generation_publisher(publisher: Arc<dyn GenerationPublisher>) -> bool {
    PUBLISHER.set(publisher).is_ok()
}

/// The installed publisher, when generation delivery is active.
pub(super) fn active_publisher() -> Option<Arc<dyn GenerationPublisher>> {
    if !generation_delivery_configured() {
        return None;
    }
    PUBLISHER.get().cloned()
}

/// The note the last generation-delivery reload left for the deploy result
/// ("generation 12 acknowledged by 2/2 ingest hosts"). Deploys are serialized
/// by the deploy lock, so the caller that just reloaded reads its own note.
pub fn take_delivery_note() -> Option<String> {
    take_delivery().map(|(note, _)| note)
}

/// The note and the structured delivery state the last generation-delivery
/// reload left (NAN-5279), taken together.
pub fn take_delivery() -> Option<(String, GenerationDelivery)> {
    LAST_NOTE.lock().unwrap_or_else(|p| p.into_inner()).take()
}

/// `message` plus the generation-delivery note, when the last reload left one
/// (role split: "Published generation N and acknowledged by 2/2 ...").
pub fn with_delivery_note(message: String) -> String {
    with_delivery(message).0
}

/// [`with_delivery_note`] plus the structured delivery state for the deploy
/// result's `delivery` field (NAN-5279), so a client can tell an acknowledged
/// deploy from one still being installed without parsing the message.
pub fn with_delivery(message: String) -> (String, Option<GenerationDelivery>) {
    match take_delivery() {
        Some((note, delivery)) => (format!("{message}. {note}"), Some(delivery)),
        None => (message, None),
    }
}

fn set_note(note: Option<(String, GenerationDelivery)>) {
    *LAST_NOTE.lock().unwrap_or_else(|p| p.into_inner()) = note;
}

/// Where a role-split deploy stands across the ingest hosts (NAN-5279).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Every ingest host installed the generation (or something newer).
    Acknowledged,
    /// Published; the hosts named in `pending_hosts` answered but have not
    /// installed it yet. Not an error: they apply it on their next sync.
    Pending,
    /// A host refused it, saw Vector reject it, or rolled it back.
    Rejected,
    /// No host confirmed it and at least one could not be asked.
    Unconfirmed,
    /// Single-host delivery: there are no ingest hosts to ask.
    NotApplicable,
}

/// The generation-delivery part of a deploy result (NAN-5279).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct GenerationDelivery {
    pub state: DeliveryState,
    /// The published Vector configuration generation.
    pub generation: i64,
    /// Ingest hosts asked.
    pub host_count: usize,
    /// Hosts that have not confirmed the generation yet.
    #[serde(default)]
    pub pending_hosts: Vec<String>,
    /// How often the ingest consumers poll for a new generation.
    pub sync_interval_secs: u64,
    /// Re-check here: `GET <status_path>` returns a [`GenerationDeliveryStatus`].
    pub status_path: String,
}

/// One ingest host's answer for a generation (NAN-5279 status endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct IngestHostDelivery {
    /// The host's relay URL.
    pub relay: String,
    /// Whether the relay answered (reachable and the tap token matched).
    pub reachable: bool,
    /// Installed this generation or a newer one.
    pub confirmed: bool,
    pub installed: Option<u64>,
    pub installing: Option<u64>,
    pub failed: Option<u64>,
    pub failed_reason: Option<String>,
}

/// `GET /api/log-sources/delivery-status?generation=N` (NAN-5279): one poll of
/// every ingest host, graded the way a deploy grades it, without waiting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct GenerationDeliveryStatus {
    /// False when this install delivers config locally (no ingest hosts).
    pub generation_delivery: bool,
    pub generation: i64,
    pub state: DeliveryState,
    pub host_count: usize,
    pub hosts: Vec<IngestHostDelivery>,
    pub message: String,
}

fn status_path(generation: i64) -> String {
    format!("{DELIVERY_STATUS_PATH}?generation={generation}")
}

/// What one ingest host's relay reported.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HostGeneration {
    pub installed: u64,
    #[serde(default)]
    pub installing: Option<u64>,
    #[serde(default)]
    pub failed: Option<u64>,
    #[serde(default)]
    pub failed_reason: Option<String>,
}

/// The verdict for one published generation across the ingest hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryVerdict {
    Acknowledged,
    Rejected { hosts: Vec<String> },
    /// `hosts`: every host not yet confirmed; `unanswered`: the subset whose
    /// relay did not answer at all (unreachable, wrong token, no runtime dir).
    Pending { hosts: Vec<String>, unanswered: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub generation: i64,
    pub host_count: usize,
    pub verdict: DeliveryVerdict,
}

impl DeliveryReport {
    /// The one-line message a deploy result carries. `sync_interval` is the
    /// ingest consumers' poll, named so an operator knows when to re-check.
    pub fn note(&self, timeout: Duration, sync_interval: Duration) -> String {
        let recheck = format!(
            "Re-check in a minute: GET {}.",
            status_path(self.generation)
        );
        match &self.verdict {
            DeliveryVerdict::Acknowledged => format!(
                "Published generation {} and acknowledged by {}/{} ingest host(s).",
                self.generation, self.host_count, self.host_count
            ),
            DeliveryVerdict::Pending { hosts, unanswered }
                if hosts.len() >= self.host_count && !unanswered.is_empty() =>
            {
                format!(
                    "Published generation {}, but no ingest host confirmed it within {}s (not \
                     confirmed: {}; relay did not answer: {}). It is NOT known to be live. Check \
                     that the hosts' vector-config-consumer and relay are running and that \
                     NANO_VECTOR_TAP_TOKEN matches. {recheck}",
                    self.generation,
                    timeout.as_secs(),
                    hosts.join(", "),
                    unanswered.join(", ")
                )
            }
            DeliveryVerdict::Pending { hosts, .. } if hosts.len() >= self.host_count => format!(
                "Published generation {}; ingest hosts have not confirmed it yet (delivery polls \
                 every {}s and each host installs one generation at a time, so back-to-back \
                 deploys take longer than the {}s this deploy waited). Still installing: {}. \
                 {recheck}",
                self.generation,
                sync_interval.as_secs(),
                timeout.as_secs(),
                hosts.join(", ")
            ),
            DeliveryVerdict::Pending { hosts, .. } => format!(
                "Published generation {}; {}/{} ingest host(s) acknowledged it within {}s. \
                 Not yet confirmed: {}. They apply it on their next config sync (every {}s). \
                 {recheck}",
                self.generation,
                self.host_count - hosts.len(),
                self.host_count,
                timeout.as_secs(),
                hosts.join(", "),
                sync_interval.as_secs()
            ),
            DeliveryVerdict::Rejected { hosts } => format!(
                "Published generation {}, but ingest host(s) {} refused or rolled it back; they \
                 keep serving the previous configuration. Check `vector-config-consumer` logs \
                 on those hosts.",
                self.generation,
                hosts.join(", ")
            ),
        }
    }

    /// The deploy's delivery state: [`DeliveryState::Pending`] for any host
    /// not confirmed, [`DeliveryState::Unconfirmed`] when none confirmed and
    /// one could not be asked.
    pub fn state(&self) -> DeliveryState {
        match &self.verdict {
            DeliveryVerdict::Acknowledged => DeliveryState::Acknowledged,
            DeliveryVerdict::Rejected { .. } => DeliveryState::Rejected,
            DeliveryVerdict::Pending { hosts, unanswered }
                if hosts.len() >= self.host_count && !unanswered.is_empty() =>
            {
                DeliveryState::Unconfirmed
            }
            DeliveryVerdict::Pending { .. } => DeliveryState::Pending,
        }
    }

    pub fn delivery(&self, sync_interval: Duration) -> GenerationDelivery {
        let pending_hosts = match &self.verdict {
            DeliveryVerdict::Pending { hosts, .. } => hosts.clone(),
            DeliveryVerdict::Rejected { hosts } => hosts.clone(),
            DeliveryVerdict::Acknowledged => Vec::new(),
        };
        GenerationDelivery {
            state: self.state(),
            generation: self.generation,
            host_count: self.host_count,
            pending_hosts,
            sync_interval_secs: sync_interval.as_secs(),
            status_path: status_path(self.generation),
        }
    }
}

/// Grade one poll of every host. `None` means "keep waiting".
pub fn grade(generation: i64, hosts: &[(String, Option<HostGeneration>)]) -> Option<DeliveryVerdict> {
    let target = u64::try_from(generation).unwrap_or(0);
    let rejected: Vec<String> = hosts
        .iter()
        .filter(|(_, status)| {
            status.as_ref().is_some_and(|s| s.installed < target && s.failed == Some(target))
        })
        .map(|(host, _)| host.clone())
        .collect();
    if !rejected.is_empty() {
        return Some(DeliveryVerdict::Rejected { hosts: rejected });
    }
    if hosts
        .iter()
        .all(|(_, status)| status.as_ref().is_some_and(|s| s.installed >= target))
    {
        return Some(DeliveryVerdict::Acknowledged);
    }
    None
}

fn pending_hosts(generation: i64, hosts: &[(String, Option<HostGeneration>)]) -> Vec<String> {
    let target = u64::try_from(generation).unwrap_or(0);
    hosts
        .iter()
        .filter(|(_, status)| !status.as_ref().is_some_and(|s| s.installed >= target))
        .map(|(host, _)| host.clone())
        .collect()
}

fn unanswered_hosts(hosts: &[(String, Option<HostGeneration>)]) -> Vec<String> {
    hosts
        .iter()
        .filter(|(_, status)| status.is_none())
        .map(|(host, _)| host.clone())
        .collect()
}

/// The verdict for one poll, `Pending` when [`grade`] would keep waiting.
fn verdict_now(generation: i64, hosts: &[(String, Option<HostGeneration>)]) -> DeliveryVerdict {
    grade(generation, hosts).unwrap_or_else(|| DeliveryVerdict::Pending {
        hosts: pending_hosts(generation, hosts),
        unanswered: unanswered_hosts(hosts),
    })
}

pub fn relay_urls() -> Vec<String> {
    let configured = std::env::var(RELAY_URLS_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var(RELAY_URL_ENV).ok())
        .unwrap_or_default();
    let mut urls: Vec<String> = Vec::new();
    for url in configured.split(',').map(str::trim).filter(|url| !url.is_empty()) {
        if !urls.iter().any(|existing| existing == url) {
            urls.push(url.trim_end_matches('/').to_string());
        }
    }
    urls
}

fn env_secs(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// The ingest consumers' generation poll interval.
pub fn consumer_sync_interval() -> Duration {
    Duration::from_secs(
        env_secs(CONSUMER_SYNC_INTERVAL_ENV)
            .filter(|secs| *secs > 0)
            .unwrap_or(DEFAULT_CONSUMER_SYNC_INTERVAL_SECS),
    )
}

/// NAN-5279: wait long enough for [`INSTALL_CYCLES_COVERED`] consumer
/// installs (poll + download/reload + Vector's acknowledgement each), clamped
/// to `[MIN, MAX]_DELIVERY_ACK_TIMEOUT_SECS`. With the script defaults (5 s
/// poll, 60 s ack) that is 150 s; the enterprise compose's 45 s ack gives
/// 120 s. A fixed 90 s missed two back-to-back generations (~60 s each).
pub fn derived_ack_timeout(sync_interval_secs: u64, consumer_ack_secs: u64) -> Duration {
    let per_install = sync_interval_secs
        .saturating_add(consumer_ack_secs)
        .saturating_add(INSTALL_OVERHEAD_SECS);
    Duration::from_secs(
        per_install
            .saturating_mul(INSTALL_CYCLES_COVERED)
            .clamp(MIN_DELIVERY_ACK_TIMEOUT_SECS, MAX_DELIVERY_ACK_TIMEOUT_SECS),
    )
}

/// How long a deploy waits for the ingest hosts: [`DELIVERY_ACK_TIMEOUT_ENV`]
/// when set to a number, otherwise [`derived_ack_timeout`].
pub fn ack_timeout() -> Duration {
    match env_secs(DELIVERY_ACK_TIMEOUT_ENV) {
        Some(secs) => Duration::from_secs(secs),
        None => derived_ack_timeout(
            consumer_sync_interval().as_secs(),
            env_secs(CONSUMER_ACK_TIMEOUT_ENV)
                .filter(|secs| *secs > 0)
                .unwrap_or(DEFAULT_CONSUMER_ACK_TIMEOUT_SECS),
        ),
    }
}

async fn poll_host(client: &reqwest::Client, url: &str, token: &str) -> Option<HostGeneration> {
    let response = client
        .get(format!("{url}/v1/generation"))
        .bearer_auth(token)
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<HostGeneration>().await.ok()
}

/// Wait for every ingest host to report on `generation`.
pub async fn await_hosts(generation: i64, urls: &[String], token: &str, timeout: Duration) -> DeliveryReport {
    let client = reqwest::Client::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let statuses = futures::future::join_all(urls.iter().map(|url| {
            let client = &client;
            async move { (url.clone(), poll_host(client, url, token).await) }
        }))
        .await;
        if let Some(verdict) = grade(generation, &statuses) {
            return DeliveryReport {
                generation,
                host_count: urls.len(),
                verdict,
            };
        }
        if tokio::time::Instant::now() + POLL_INTERVAL > deadline {
            return DeliveryReport {
                generation,
                host_count: urls.len(),
                verdict: verdict_now(generation, &statuses),
            };
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The generation-delivery reload: publish, then grade by the ingest hosts.
/// `Ok(note)` for acknowledged or pending, `Err(message)` for a rejection or a
/// failed publication. Leaves the note for [`take_delivery_note`].
pub(super) async fn deliver(publisher: &dyn GenerationPublisher) -> Result<Delivered, DeliveryFailure> {
    set_note(None);
    let generation = publisher
        .publish_current()
        .await
        .map_err(|error| DeliveryFailure::Publication(format!(
            "Could not publish the Vector configuration generation for the ingest hosts: {error}"
        )))?;
    let urls = relay_urls();
    let token = std::env::var(RELAY_TOKEN_ENV).unwrap_or_default();
    let result = grade_published(generation, &urls, &token, ack_timeout()).await;
    if let Ok(delivered) = &result {
        set_note(Some((delivered.note.clone(), delivered.delivery.clone())));
    }
    result
}

/// [`deliver`] after publication: ask the relays and grade their answers.
pub(super) async fn grade_published(
    generation: i64,
    urls: &[String],
    token: &str,
    timeout: Duration,
) -> Result<Delivered, DeliveryFailure> {
    if urls.is_empty() || token.len() < MIN_TOKEN_BYTES {
        let note = format!(
            "Published generation {generation}; ingest hosts apply it on their next config sync \
             (no ingest relays configured to confirm it: {RELAY_URLS_ENV} / {RELAY_TOKEN_ENV})."
        );
        tracing::warn!(generation, "{note}");
        return Err(DeliveryFailure::Unconfirmed(note));
    }
    let report = await_hosts(generation, urls, token, timeout).await;
    let sync_interval = consumer_sync_interval();
    let note = report.note(timeout, sync_interval);
    let delivery = report.delivery(sync_interval);
    match report.state() {
        DeliveryState::Rejected => {
            tracing::error!(generation, "{note}");
            Err(DeliveryFailure::Rejected(note))
        }
        // NAN-5133 review M2: with no host confirming and a relay that did not
        // answer there is no evidence the generation is live anywhere (a
        // drifted tap token, unreachable relays), so it is never a success.
        DeliveryState::Unconfirmed | DeliveryState::NotApplicable => {
            tracing::warn!(generation, "{note}");
            Err(DeliveryFailure::Unconfirmed(note))
        }
        // NAN-5279: every host that has not confirmed answered its relay and
        // reported no failure for this generation; it is still installing
        // (typically the previous generation first). In progress, not failed.
        DeliveryState::Pending => {
            tracing::warn!(generation, "{note}");
            Ok(Delivered { note, confirmed: false, delivery })
        }
        DeliveryState::Acknowledged => {
            tracing::info!(generation, "{note}");
            Ok(Delivered { note, confirmed: true, delivery })
        }
    }
}

/// A published generation every ingest host either acknowledged or answered
/// for without a failure: `confirmed` when every host installed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Delivered {
    pub(super) note: String,
    pub(super) confirmed: bool,
    pub(super) delivery: GenerationDelivery,
}

/// One poll of every ingest host for `generation`, graded without waiting
/// (NAN-5279): the re-check behind `GET /api/log-sources/delivery-status`.
pub async fn delivery_status(generation: i64) -> GenerationDeliveryStatus {
    if !generation_delivery_configured() {
        return GenerationDeliveryStatus {
            generation_delivery: false,
            generation,
            state: DeliveryState::NotApplicable,
            host_count: 0,
            hosts: Vec::new(),
            message: "This install delivers Vector configuration locally; a deploy's result \
                      is final and there are no ingest hosts to re-check."
                .to_string(),
        };
    }
    let urls = relay_urls();
    let token = std::env::var(RELAY_TOKEN_ENV).unwrap_or_default();
    status_from_relays(generation, &urls, &token).await
}

pub(super) async fn status_from_relays(
    generation: i64,
    urls: &[String],
    token: &str,
) -> GenerationDeliveryStatus {
    if urls.is_empty() || token.len() < MIN_TOKEN_BYTES {
        return GenerationDeliveryStatus {
            generation_delivery: true,
            generation,
            state: DeliveryState::Unconfirmed,
            host_count: urls.len(),
            hosts: Vec::new(),
            message: format!(
                "No ingest relays are configured to confirm generation {generation} \
                 ({RELAY_URLS_ENV} / {RELAY_TOKEN_ENV})."
            ),
        };
    }
    let client = reqwest::Client::new();
    let statuses = futures::future::join_all(urls.iter().map(|url| {
        let client = &client;
        async move { (url.clone(), poll_host(client, url, token).await) }
    }))
    .await;
    grade_status(generation, &statuses)
}

/// Pure half of [`status_from_relays`].
pub(super) fn grade_status(
    generation: i64,
    statuses: &[(String, Option<HostGeneration>)],
) -> GenerationDeliveryStatus {
    let target = u64::try_from(generation).unwrap_or(0);
    let report = DeliveryReport {
        generation,
        host_count: statuses.len(),
        verdict: verdict_now(generation, statuses),
    };
    let state = report.state();
    let hosts = statuses
        .iter()
        .map(|(relay, status)| IngestHostDelivery {
            relay: relay.clone(),
            reachable: status.is_some(),
            confirmed: status.as_ref().is_some_and(|s| s.installed >= target),
            installed: status.as_ref().map(|s| s.installed),
            installing: status.as_ref().and_then(|s| s.installing),
            failed: status.as_ref().and_then(|s| s.failed),
            failed_reason: status.as_ref().and_then(|s| s.failed_reason.clone()),
        })
        .collect();
    let (pending, unanswered) = match &report.verdict {
        DeliveryVerdict::Pending { hosts, unanswered } => (hosts.clone(), unanswered.clone()),
        _ => (Vec::new(), Vec::new()),
    };
    let message = match state {
        DeliveryState::Acknowledged => format!(
            "Generation {generation} is installed on {n}/{n} ingest host(s).",
            n = statuses.len()
        ),
        DeliveryState::Pending => format!(
            "Generation {generation} is published and installed on {}/{} ingest host(s). Still \
             installing: {}. Delivery polls every {}s; re-check in a minute.",
            statuses.len() - pending.len(),
            statuses.len(),
            pending.join(", "),
            consumer_sync_interval().as_secs()
        ),
        DeliveryState::Unconfirmed => format!(
            "No ingest host has confirmed generation {generation}; relay(s) did not answer: {}. \
             Check that the hosts' vector-config-consumer and relay are running and that \
             NANO_VECTOR_TAP_TOKEN matches.",
            unanswered.join(", ")
        ),
        _ => report.note(Duration::ZERO, consumer_sync_interval()),
    };
    GenerationDeliveryStatus {
        generation_delivery: true,
        generation,
        state,
        host_count: statuses.len(),
        hosts,
        message,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeliveryFailure {
    Publication(String),
    Rejected(String),
    /// Published, but no ingest host confirmed it (or none can be asked).
    Unconfirmed(String),
}

/// The one grading both reload paths use (NAN-5133 review M2): parser and
/// log-source deploys ([`ReloadAck`]) and source-config deploys
/// (`ActivationOutcome`) must agree on what a generation-delivery result means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Graded {
    /// At least one ingest host runs it (all, or some with the rest named).
    Live,
    /// Every host that answered refused it or rolled it back.
    Rejected(String),
    /// Published (or not) with no host confirming: not a success, no rollback.
    Unconfirmed(String),
}

pub(super) fn grade_delivery(result: &Result<Delivered, DeliveryFailure>) -> Graded {
    match result {
        Ok(_) => Graded::Live,
        Err(DeliveryFailure::Rejected(message)) => Graded::Rejected(message.clone()),
        Err(DeliveryFailure::Unconfirmed(message)) | Err(DeliveryFailure::Publication(message)) => {
            Graded::Unconfirmed(message.clone())
        }
    }
}

#[cfg(test)]
#[path = "remote_delivery_tests.rs"]
mod tests;

pub mod install_lease;
