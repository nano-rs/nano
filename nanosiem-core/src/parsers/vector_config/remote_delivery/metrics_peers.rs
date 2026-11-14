// SPDX-License-Identifier: AGPL-3.0-or-later

//! Kubernetes acknowledgement source for generation delivery (NAN-5399).
//!
//! On Helm every Vector pod runs its own config consumer, which installs a
//! published generation and proves it with a reload sentinel: a `demo_logs`
//! source named `__nano_ack_<generation, 20 digits>_<reload sequence>` that only
//! runs in a topology Vector built from that generation. Before this, a Helm
//! deploy did not wait for any pod (`NANO_VECTOR_LOCAL_RELOAD=off` turned
//! verification off) and then logged "Deploy verified" because the
//! load-balanced metrics Service answered. With two pods installing one at a
//! time under the install lease, the second pod applied the change 77 s after
//! the deploy said it was verified.
//!
//! Here nano-api resolves a headless Service that publishes every Vector pod
//! (ready or not) and reads each pod's own Prometheus exporter. A pod's
//! installed generation is the generation of its newest live sentinel (the
//! highest reload sequence with events sent: a consumer rollback writes a new
//! sentinel for the older generation, so the sequence decides, not the
//! generation number). The answers feed the same grading as the role-split
//! relays ([`super::grade`]): every pod on the generation is acknowledged, and
//! otherwise the deploy reports "N of M" pending with the pods that have not
//! confirmed it.
//!
//! A consumer that rolls a generation back (Vector rejected it, or never
//! acknowledged it) adds a failure marker to the rollback's sentinel,
//! `__nano_failed_<candidate>_<same sequence>`, so that pod reports the
//! generation as failed and the deploy grades rejected. A generation the
//! escaping gate refused never reloads Vector and shows no marker; it stays
//! unconfirmed, and a wait that ends with no pod confirming is never a success
//! (see `grade_published_peers`).
//!
//! Membership: DNS can briefly return a subset of the pods (a scale-up, a pod
//! just created). The chart passes the expected replica count
//! ([`EXPECTED_PEERS_ENV`], the HPA's minReplicas when autoscaling); a poll
//! that resolves fewer pods is padded with unanswered entries, and an
//! acknowledgement must hold over an unchanged pod set for
//! [`MEMBERSHIP_STABLE_FOR`].

use std::net::SocketAddr;
use std::time::Duration;

use super::HostGeneration;

/// `host:port` of a headless Service selecting every Vector pod's metrics port
/// (`publishNotReadyAddresses`). When set, generation delivery is graded by
/// each pod's metrics instead of the ingest hosts' tap relays.
pub const METRICS_PEERS_ENV: &str = "NANO_VECTOR_ACK_METRICS_PEERS";
/// The number of Vector pods the chart expects (replicas, or the HPA's
/// minReplicas). A poll that resolves fewer is padded with unanswered pods.
pub const EXPECTED_PEERS_ENV: &str = "NANO_VECTOR_ACK_EXPECTED_PEERS";
/// The consumer's reload sentinel source (`vector-config-consumer.sh`).
const ACK_COMPONENT_PREFIX: &str = "__nano_ack_";
/// The failure marker a consumer adds to a rollback's sentinel.
const FAILED_COMPONENT_PREFIX: &str = "__nano_failed_";
/// One pod's exporter page is ~2 MB; this is per pod and per poll. The whole
/// poll is also bounded by the deploy's deadline.
const SCRAPE_TIMEOUT: Duration = Duration::from_secs(5);
/// Resolving the peer Service must not hold a deploy past its window.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
/// An acknowledgement must hold over an unchanged pod set this long: at least
/// CoreDNS's default record TTL (5 s), so a stale subset answer has expired.
pub const MEMBERSHIP_STABLE_FOR: Duration = Duration::from_secs(6);

/// The configured peer Service, when this install grades by pod metrics.
pub fn configured_target() -> Option<String> {
    target_from(std::env::var(METRICS_PEERS_ENV).ok().as_deref())
}

/// The expected pod count, when the chart set one.
pub fn expected_peers() -> usize {
    expected_from(std::env::var(EXPECTED_PEERS_ENV).ok().as_deref())
}

/// Pure form of [`expected_peers`]; 0 (no floor) when unset or malformed.
pub fn expected_from(value: Option<&str>) -> usize {
    value.and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0)
}

/// Pure form of [`configured_target`].
pub fn target_from(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// What one pod's metrics say about its configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PodGeneration {
    /// The generation of its newest live reload sentinel.
    pub loaded: Option<u64>,
    /// The generation its consumer rolled back from in that same reload.
    pub failed: Option<u64>,
}

/// The generation the Vector behind this metrics page is running, from its
/// newest live reload sentinel. `None` when no sentinel has sent an event yet
/// (a pod still on its bootstrap generation).
pub fn loaded_generation(metrics: &str) -> Option<u64> {
    pod_generation(metrics).loaded
}

/// [`loaded_generation`] plus the failure marker carried by the same reload.
pub fn pod_generation(metrics: &str) -> PodGeneration {
    let mut newest: Option<(u64, u64)> = None; // (sequence, generation)
    let mut failures: Vec<(u64, u64)> = Vec::new();
    for line in metrics.lines().map(str::trim) {
        if line.starts_with('#') || !line.contains("__nano_") {
            continue;
        }
        let Some((series, value)) = line.rsplit_once('}') else {
            continue;
        };
        let name = series.split('{').next().unwrap_or(series);
        if !name.ends_with("component_sent_events_total") {
            continue;
        }
        let sent = value
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or(0.0);
        if sent <= 0.0 {
            continue;
        }
        let Some(component) = component_id(series) else {
            continue;
        };
        if let Some(parsed) = sentinel_ids(component, ACK_COMPONENT_PREFIX) {
            if newest.is_none_or(|current| parsed > current) {
                newest = Some(parsed);
            }
        } else if let Some(parsed) = sentinel_ids(component, FAILED_COMPONENT_PREFIX) {
            failures.push(parsed);
        }
    }
    let failed = newest.and_then(|(sequence, _)| {
        failures
            .iter()
            .find(|(failed_sequence, _)| *failed_sequence == sequence)
            .map(|(_, generation)| *generation)
    });
    PodGeneration {
        loaded: newest.map(|(_, generation)| generation),
        failed,
    }
}

fn component_id(series: &str) -> Option<&str> {
    let start = series.find("component_id=\"")? + "component_id=\"".len();
    let rest = &series[start..];
    Some(&rest[..rest.find('"')?])
}

/// `<prefix><generation>_<sequence>` to `(sequence, generation)`. The
/// markers' sinks (`__nano_ack_sink_...`) do not parse and are skipped.
fn sentinel_ids(component: &str, prefix: &str) -> Option<(u64, u64)> {
    let ids = component.strip_prefix(prefix)?;
    let (generation, sequence) = ids.split_once('_')?;
    let all_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !all_digits(generation) || !all_digits(sequence) {
        return None;
    }
    Some((sequence.parse().ok()?, generation.parse().ok()?))
}

/// The pods' scrape targets for a resolution, sorted and deduplicated.
pub fn peer_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<String> {
    let mut peers: Vec<String> = addresses.into_iter().map(|address| address.to_string()).collect();
    peers.sort();
    peers.dedup();
    peers
}

/// One pod's answer: `Some` with its loaded generation (0 before its first
/// install) when its exporter answered, `None` when it did not.
pub fn host_generation(metrics: Option<&str>) -> Option<HostGeneration> {
    metrics.map(|body| {
        let pod = pod_generation(body);
        HostGeneration {
            installed: pod.loaded.unwrap_or(0),
            installing: None,
            failed: pod.failed,
            failed_reason: pod.failed.map(|_| "rolled back by the pod's config consumer".to_string()),
        }
    })
}

/// Pad a poll that resolved fewer pods than expected with unanswered entries,
/// so a partial DNS answer can never read as "every pod".
pub fn pad_to_expected(
    mut statuses: Vec<(String, Option<HostGeneration>)>,
    expected: usize,
) -> Vec<(String, Option<HostGeneration>)> {
    let resolved = statuses.len();
    for missing in resolved..expected {
        statuses.push((format!("unresolved Vector pod {} of {expected}", missing + 1), None));
    }
    statuses
}

async fn scrape(client: &reqwest::Client, peer: &str) -> Option<String> {
    let response = client
        .get(format!("http://{peer}/metrics"))
        .timeout(SCRAPE_TIMEOUT)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}

/// Resolve the peer Service now (pods come and go during a rollout) and ask
/// every pod. A resolution that finds no pod is one unanswered entry named
/// after the Service, so it can never grade as acknowledged.
pub async fn poll_peers(client: &reqwest::Client, target: &str) -> Vec<(String, Option<HostGeneration>)> {
    poll_peers_expecting(client, target, expected_peers()).await
}

/// [`poll_peers`] with an explicit expected pod count.
pub async fn poll_peers_expecting(
    client: &reqwest::Client,
    target: &str,
    expected: usize,
) -> Vec<(String, Option<HostGeneration>)> {
    let peers = match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(target)).await {
        Ok(Ok(addresses)) => peer_addresses(addresses),
        Ok(Err(error)) => {
            tracing::warn!(target, %error, "could not resolve the Vector metrics peers");
            Vec::new()
        }
        Err(_) => {
            tracing::warn!(target, "resolving the Vector metrics peers timed out");
            Vec::new()
        }
    };
    if peers.is_empty() {
        return pad_to_expected(vec![(target.to_string(), None)], expected);
    }
    let statuses = futures::future::join_all(peers.into_iter().map(|peer| async move {
        let body = scrape(client, &peer).await;
        (peer, host_generation(body.as_deref()))
    }))
    .await;
    pad_to_expected(statuses, expected)
}

#[cfg(test)]
#[path = "metrics_peers_tests.rs"]
mod tests;
