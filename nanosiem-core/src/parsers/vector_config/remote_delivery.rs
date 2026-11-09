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
//!   failure.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures::future::BoxFuture;
use serde::Deserialize;

use crate::parsers::pipe::tap::{MIN_TOKEN_BYTES, RELAY_TOKEN_ENV, RELAY_URLS_ENV, RELAY_URL_ENV};

/// Selects generation delivery (role split). Any other value, or unset, keeps
/// the single-host signal-and-metrics path.
pub const DELIVERY_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY";
/// How long a deploy waits for the ingest hosts' acknowledgement.
pub const DELIVERY_ACK_TIMEOUT_ENV: &str = "NANO_VECTOR_CONFIG_DELIVERY_ACK_TIMEOUT_SECS";
/// Default wait. A consumer polls every 5 s, and Vector's ack needs two
/// internal-metrics scrapes (10 s apart) after the reload, so an install takes
/// ~20-40 s and longer when a previous generation is still installing. 90 s
/// sees a definitive answer in practice and stays under the app edge's 120 s
/// `/api/` read timeout (the web client waits 115 s for deploys).
pub const DEFAULT_DELIVERY_ACK_TIMEOUT_SECS: u64 = 90;
// The enterprise compose sets the consumer's ack timeout to 45 s, so a host
// that rolls back (sync 5 s + download + 45 s + poll) answers inside this wait.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Publishes the database's current Vector configuration as a generation and
/// returns its number. nano-api implements it with its publication reconcile.
pub trait GenerationPublisher: Send + Sync {
    fn publish_current(&self) -> BoxFuture<'_, Result<i64, String>>;
}

static PUBLISHER: OnceLock<Arc<dyn GenerationPublisher>> = OnceLock::new();
static LAST_NOTE: Mutex<Option<String>> = Mutex::new(None);

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
    LAST_NOTE.lock().unwrap_or_else(|p| p.into_inner()).take()
}

/// `message` plus the generation-delivery note, when the last reload left one
/// (role split: "Published generation N and acknowledged by 2/2 ...").
pub fn with_delivery_note(message: String) -> String {
    match take_delivery_note() {
        Some(note) => format!("{message}. {note}"),
        None => message,
    }
}

fn set_note(note: Option<String>) {
    *LAST_NOTE.lock().unwrap_or_else(|p| p.into_inner()) = note;
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
    Pending { hosts: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub generation: i64,
    pub host_count: usize,
    pub verdict: DeliveryVerdict,
}

impl DeliveryReport {
    /// The one-line message a deploy result carries.
    pub fn note(&self, timeout: Duration) -> String {
        match &self.verdict {
            DeliveryVerdict::Acknowledged => format!(
                "Published generation {} and acknowledged by {}/{} ingest host(s).",
                self.generation, self.host_count, self.host_count
            ),
            DeliveryVerdict::Pending { hosts } if hosts.len() >= self.host_count => format!(
                "Published generation {}, but no ingest host confirmed it within {}s (not \
                 confirmed: {}). It is NOT known to be live. Check that the hosts' \
                 vector-config-consumer is running and that NANO_VECTOR_TAP_TOKEN matches.",
                self.generation,
                timeout.as_secs(),
                hosts.join(", ")
            ),
            DeliveryVerdict::Pending { hosts } => format!(
                "Published generation {}; {}/{} ingest host(s) acknowledged it within {}s. \
                 Not yet confirmed: {}. They apply it on their next config sync.",
                self.generation,
                self.host_count - hosts.len(),
                self.host_count,
                timeout.as_secs(),
                hosts.join(", ")
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

pub fn ack_timeout() -> Duration {
    Duration::from_secs(
        std::env::var(DELIVERY_ACK_TIMEOUT_ENV)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_DELIVERY_ACK_TIMEOUT_SECS),
    )
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
                verdict: DeliveryVerdict::Pending {
                    hosts: pending_hosts(generation, &statuses),
                },
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
        set_note(Some(delivered.note.clone()));
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
    let note = report.note(timeout);
    match report.verdict {
        DeliveryVerdict::Rejected { .. } => {
            tracing::error!(generation, "{note}");
            Err(DeliveryFailure::Rejected(note))
        }
        // NAN-5133 review M2: with no host confirming there is no evidence the
        // generation is live anywhere (a drifted tap token, unreachable relays,
        // a host that rolled back after the window), so it is never a success.
        DeliveryVerdict::Pending { ref hosts } if hosts.len() >= report.host_count => {
            tracing::warn!(generation, "{note}");
            Err(DeliveryFailure::Unconfirmed(note))
        }
        DeliveryVerdict::Pending { .. } => {
            tracing::warn!(generation, "{note}");
            Ok(Delivered { note, confirmed: false })
        }
        DeliveryVerdict::Acknowledged => {
            tracing::info!(generation, "{note}");
            Ok(Delivered { note, confirmed: true })
        }
    }
}

/// A published generation at least one ingest host acknowledged: `confirmed`
/// when every host did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Delivered {
    pub(super) note: String,
    pub(super) confirmed: bool,
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
