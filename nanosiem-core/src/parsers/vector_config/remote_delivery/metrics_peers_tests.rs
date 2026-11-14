// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5399: Kubernetes deploys are verified by EVERY Vector pod's reload
//! sentinel, not by whichever pod a ClusterIP Service picks.

use super::*;
use crate::parsers::vector_config::remote_delivery::{
    DeliveryFailure, DeliveryReport, DeliveryState, DeliveryVerdict, Graded, await_polls, conclude,
    grade, grade_delivery, peers_outcome,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const GEN_41: &str = "00000000000000000041";
const GEN_42: &str = "00000000000000000042";

fn sentinel(generation: &str, sequence: u64, sent: f64) -> String {
    format!(
        "vector_component_sent_events_total{{component_id=\"__nano_ack_{generation}_{sequence}\",\
         component_kind=\"source\",component_type=\"demo_logs\",host=\"vector-0\",output=\"_default\"}} {sent} 1731585048000\n"
    )
}

fn page(series: &[String]) -> String {
    let mut body = String::from(
        "# HELP vector_component_sent_events_total sent events\n\
         # TYPE vector_component_sent_events_total counter\n\
         vector_component_sent_events_total{component_id=\"nano_router\",component_kind=\"transform\"} 9000\n",
    );
    for line in series {
        body.push_str(line);
    }
    body
}

/// What the pod with this page answers.
fn pod(name: &str, metrics: &str) -> (String, Option<HostGeneration>) {
    (name.to_string(), host_generation(Some(metrics)))
}

fn unreachable(name: &str) -> (String, Option<HostGeneration>) {
    (name.to_string(), None)
}

#[test]
fn the_newest_live_sentinel_names_the_loaded_generation() {
    let body = page(&[sentinel(GEN_41, 1, 30.0), sentinel(GEN_42, 2, 4.0)]);
    assert_eq!(loaded_generation(&body), Some(42));
}

/// A consumer rollback writes a NEW sentinel for the older generation: the
/// reload sequence decides, not the larger generation number.
#[test]
fn a_rollback_sentinel_wins_over_a_higher_generation() {
    let body = page(&[sentinel(GEN_42, 2, 12.0), sentinel(GEN_41, 3, 2.0)]);
    assert_eq!(loaded_generation(&body), Some(41));
}

/// A sentinel that never sent an event was not built into a running topology
/// (Vector rejected the reload), and the sentinel's sink is not a sentinel.
#[test]
fn unsent_sentinels_sinks_and_comments_are_ignored() {
    let sink = format!(
        "vector_component_sent_events_total{{component_id=\"__nano_ack_sink_{GEN_42}_2\",component_kind=\"sink\"}} 50\n"
    );
    let comment = format!("# vector_component_sent_events_total{{component_id=\"__nano_ack_{GEN_42}_9\"}} 5\n");
    let body = page(&[sentinel(GEN_41, 1, 30.0), sentinel(GEN_42, 2, 0.0), sink, comment]);
    assert_eq!(loaded_generation(&body), Some(41));
}

#[test]
fn a_pod_on_its_bootstrap_generation_answers_zero() {
    let body = page(&[]);
    assert_eq!(loaded_generation(&body), None);
    assert_eq!(host_generation(Some(&body)).map(|h| h.installed), Some(0));
    assert_eq!(host_generation(None), None);
}

#[test]
fn peer_target_and_addresses_are_normalised() {
    assert_eq!(target_from(None), None);
    assert_eq!(target_from(Some("  ")), None);
    assert_eq!(
        target_from(Some(" nano-vector-metrics-peers.nano.svc.cluster.local:9598 ")).as_deref(),
        Some("nano-vector-metrics-peers.nano.svc.cluster.local:9598")
    );
    let peers = peer_addresses([
        "10.0.0.2:9598".parse().unwrap(),
        "10.0.0.1:9598".parse().unwrap(),
        "10.0.0.2:9598".parse().unwrap(),
    ]);
    assert_eq!(peers, vec!["10.0.0.1:9598".to_string(), "10.0.0.2:9598".to_string()]);
}

/// The NAN-5399 timeline: two pods install one at a time under the lease. The
/// first poll sees one pod on the new generation; the deploy must keep
/// waiting, and only a poll where BOTH run it is acknowledged.
#[tokio::test]
async fn multi_replica_waits_for_every_pod() {
    let old = page(&[sentinel(GEN_41, 1, 30.0)]);
    let new = page(&[sentinel(GEN_41, 1, 30.0), sentinel(GEN_42, 2, 3.0)]);
    let first = vec![pod("10.0.0.1:9598", &new), pod("10.0.0.2:9598", &old)];
    assert_eq!(grade(42, &first), None, "one of two pods is not verified");

    let polls = Arc::new(AtomicU64::new(0));
    let counter = polls.clone();
    let report = await_polls(42, Duration::from_secs(5), Duration::from_millis(10), Duration::ZERO, || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let (old, new) = (old.clone(), new.clone());
        async move {
            let second = if n < 3 { old } else { new.clone() };
            vec![pod("10.0.0.1:9598", &new), pod("10.0.0.2:9598", &second)]
        }
    })
    .await;
    assert_eq!(report.verdict, DeliveryVerdict::Acknowledged);
    assert_eq!(report.host_count, 2);
    assert!(polls.load(Ordering::SeqCst) >= 4, "acknowledged before the second pod installed");
    let delivered = conclude(&report, Duration::from_secs(5)).expect("acknowledged");
    assert!(delivered.confirmed);
    assert_eq!(delivered.delivery.state, DeliveryState::Acknowledged);
    assert!(delivered.note.contains("2/2"), "{}", delivered.note);
}

/// A pod that has not installed by the end of the wait is an explicit
/// "1 of 2" pending result naming it: not verified, and not a rollback.
#[tokio::test]
async fn multi_replica_partial_rollout_is_pending_n_of_m() {
    let old = page(&[sentinel(GEN_41, 1, 30.0)]);
    let new = page(&[sentinel(GEN_42, 2, 3.0)]);
    let report = await_polls(42, Duration::from_millis(50), Duration::from_millis(10), Duration::ZERO, || {
        let (old, new) = (old.clone(), new.clone());
        async move { vec![pod("10.0.0.1:9598", &new), pod("10.0.0.2:9598", &old)] }
    })
    .await;
    let result = peers_outcome(conclude(&report, Duration::from_millis(50)), &report);
    let delivered = result.as_ref().expect("partial rollout is live, not failed");
    assert!(!delivered.confirmed);
    assert_eq!(delivered.delivery.state, DeliveryState::Pending);
    assert_eq!(delivered.delivery.host_count, 2);
    assert_eq!(delivered.delivery.pending_hosts, vec!["10.0.0.2:9598".to_string()]);
    assert!(delivered.note.contains("1/2"), "{}", delivered.note);
    assert_eq!(grade_delivery(&result), Graded::Live);
}

/// No pod reachable and none confirming is never a success.
#[tokio::test]
async fn unreachable_pods_are_unconfirmed() {
    let old = page(&[sentinel(GEN_41, 1, 30.0)]);
    let report = await_polls(42, Duration::from_millis(30), Duration::from_millis(10), Duration::ZERO, || {
        let old = old.clone();
        async move { vec![pod("10.0.0.1:9598", &old), unreachable("10.0.0.2:9598")] }
    })
    .await;
    let result = conclude(&report, Duration::from_millis(30));
    assert!(matches!(result, Err(DeliveryFailure::Unconfirmed(_))), "{result:?}");
}

/// Single replica: one pod on the generation is the whole fleet.
#[tokio::test]
async fn single_replica_is_acknowledged_by_its_one_pod() {
    let new = page(&[sentinel(GEN_42, 1, 1.0)]);
    let report = await_polls(42, Duration::from_secs(1), Duration::from_millis(10), Duration::ZERO, || {
        let new = new.clone();
        async move { vec![pod("10.0.0.1:9598", &new)] }
    })
    .await;
    assert_eq!(report.verdict, DeliveryVerdict::Acknowledged);
    assert_eq!(report.host_count, 1);
}

/// An empty poll (a peer Service with no pods) can never be acknowledged.
#[test]
fn no_pods_is_not_acknowledged() {
    assert_eq!(grade(42, &[]), None);
}

/// The scrape end to end against a stub exporter, resolved through the same
/// `host:port` path the peer Service uses; a dead target answers `None` and an
/// unresolvable Service is one unanswered entry.
#[tokio::test]
async fn poll_peers_reads_each_pods_exporter() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = page(&[sentinel(GEN_42, 1, 2.0)]);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    let client = reqwest::Client::new();
    let statuses = poll_peers_expecting(&client, &address.to_string(), 0).await;
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].0, address.to_string());
    assert_eq!(statuses[0].1.as_ref().map(|h| h.installed), Some(42));

    let padded = poll_peers_expecting(&client, &address.to_string(), 2).await;
    assert_eq!(padded.len(), 2, "one resolved pod of two expected");
    assert_eq!(padded[1].1, None);

    let dead = poll_peers_expecting(&client, "127.0.0.1:9", 0).await;
    assert_eq!(dead, vec![("127.0.0.1:9".to_string(), None)]);

    let missing = poll_peers_expecting(&client, "nano-vector-metrics-peers.invalid:9598", 0).await;
    assert_eq!(missing, vec![("nano-vector-metrics-peers.invalid:9598".to_string(), None)]);
}

fn failed_marker(generation: &str, sequence: u64, sent: f64) -> String {
    format!(
        "vector_component_sent_events_total{{component_id=\"__nano_failed_{generation}_{sequence}\",\
         component_kind=\"source\"}} {sent}\n"
    )
}

/// What a pod looks like after its consumer rolled 42 back to 41: the newest
/// sentinel names 41, and the same reload carries the failure marker for 42.
fn rolled_back_page() -> String {
    page(&[
        sentinel(GEN_41, 1, 30.0),
        sentinel(GEN_41, 3, 2.0),
        failed_marker(GEN_42, 3, 2.0),
    ])
}

#[test]
fn a_rollback_failure_marker_names_the_failed_generation() {
    let pod = pod_generation(&rolled_back_page());
    assert_eq!(pod, PodGeneration { loaded: Some(41), failed: Some(42) });
    // A marker from an older reload (another sequence) is history, not now.
    let later = page(&[sentinel(GEN_42, 4, 1.0), failed_marker(GEN_42, 3, 9.0)]);
    assert_eq!(pod_generation(&later), PodGeneration { loaded: Some(42), failed: None });
}

/// Codex P1: 42 rejected and rolled back on EVERY pod. Rejected, not live.
#[tokio::test]
async fn all_pods_rolled_back_grades_rejected() {
    let body = rolled_back_page();
    let report = await_polls(42, Duration::from_secs(2), Duration::from_millis(10), Duration::ZERO, || {
        let body = body.clone();
        async move { vec![pod("10.0.0.1:9598", &body), pod("10.0.0.2:9598", &body)] }
    })
    .await;
    assert!(matches!(report.verdict, DeliveryVerdict::Rejected { .. }), "{:?}", report.verdict);
    let result = peers_outcome(conclude(&report, Duration::from_secs(2)), &report);
    assert!(matches!(result, Err(DeliveryFailure::Rejected(_))), "{result:?}");
    assert!(matches!(grade_delivery(&result), Graded::Rejected(_)));
}

/// Codex P1: one pod installed 42, the other rolled it back. Rejected (the
/// rolling-back pod is named), never acknowledged or pending.
#[tokio::test]
async fn partially_rolled_back_grades_rejected() {
    let good = page(&[sentinel(GEN_42, 2, 3.0)]);
    let bad = rolled_back_page();
    let report = await_polls(42, Duration::from_secs(2), Duration::from_millis(10), Duration::ZERO, || {
        let (good, bad) = (good.clone(), bad.clone());
        async move { vec![pod("10.0.0.1:9598", &good), pod("10.0.0.2:9598", &bad)] }
    })
    .await;
    assert_eq!(
        report.verdict,
        DeliveryVerdict::Rejected { hosts: vec!["10.0.0.2:9598".to_string()] }
    );
    let result = peers_outcome(conclude(&report, Duration::from_secs(2)), &report);
    assert!(matches!(grade_delivery(&result), Graded::Rejected(_)), "{result:?}");
}

/// Codex P1: every pod answers but none runs 42 at the deadline (e.g. a
/// gate refusal, which leaves no marker). Never live on the peer source.
#[tokio::test]
async fn zero_confirmed_at_the_deadline_is_never_live() {
    let old = page(&[sentinel(GEN_41, 1, 30.0)]);
    let report = await_polls(42, Duration::from_millis(40), Duration::from_millis(10), Duration::ZERO, || {
        let old = old.clone();
        async move { vec![pod("10.0.0.1:9598", &old), pod("10.0.0.2:9598", &old)] }
    })
    .await;
    // The shared grading would call this pending; the peer outcome refuses.
    assert!(conclude(&report, Duration::from_millis(40)).is_ok());
    let result = peers_outcome(conclude(&report, Duration::from_millis(40)), &report);
    assert!(matches!(result, Err(DeliveryFailure::Unconfirmed(_))), "{result:?}");
    assert!(matches!(grade_delivery(&result), Graded::Unconfirmed(_)));
}

/// Codex P2: the window is a hard bound even when a poll never returns.
#[tokio::test]
async fn a_poll_that_never_resolves_cannot_outlast_the_window() {
    let started = std::time::Instant::now();
    let report: DeliveryReport = await_polls(
        42,
        Duration::from_millis(300),
        Duration::from_millis(10),
        Duration::ZERO,
        || std::future::pending::<Vec<(String, Option<HostGeneration>)>>(),
    )
    .await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(800), "waited {elapsed:?} on a 300 ms window");
    let result = peers_outcome(conclude(&report, Duration::from_millis(300)), &report);
    assert!(matches!(result, Err(DeliveryFailure::Unconfirmed(_))), "{result:?}");
}

/// Codex P2: a stalled poll after a good one ends at the deadline with the
/// last answer, not the poll's own timeout.
#[tokio::test]
async fn a_poll_stalled_mid_wait_ends_at_the_deadline() {
    let old = page(&[sentinel(GEN_41, 1, 30.0)]);
    let calls = Arc::new(AtomicU64::new(0));
    let counter = calls.clone();
    let started = std::time::Instant::now();
    let report = await_polls(42, Duration::from_millis(300), Duration::from_millis(10), Duration::ZERO, || {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let old = old.clone();
        async move {
            if n > 0 {
                std::future::pending::<()>().await;
            }
            vec![pod("10.0.0.1:9598", &old)]
        }
    })
    .await;
    assert!(started.elapsed() < Duration::from_millis(800));
    assert_eq!(report.host_count, 1);
    assert!(matches!(report.verdict, DeliveryVerdict::Pending { .. }));
}

/// Codex P2: DNS first answers only pod A (on 42) while pod B (on 41) is being
/// created. With a stability window, the next poll's larger set resets it and
/// the deploy cannot acknowledge 1/1.
#[tokio::test]
async fn a_transient_dns_subset_cannot_acknowledge_early() {
    let new = page(&[sentinel(GEN_42, 2, 3.0)]);
    let old = page(&[sentinel(GEN_41, 1, 30.0)]);
    let calls = Arc::new(AtomicU64::new(0));
    let counter = calls.clone();
    let report = await_polls(
        42,
        Duration::from_millis(400),
        Duration::from_millis(20),
        Duration::from_millis(100),
        || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let (new, old) = (new.clone(), old.clone());
            async move {
                if n == 0 {
                    vec![pod("10.0.0.1:9598", &new)]
                } else {
                    vec![pod("10.0.0.1:9598", &new), pod("10.0.0.2:9598", &old)]
                }
            }
        },
    )
    .await;
    assert_eq!(report.host_count, 2);
    assert_eq!(
        report.verdict,
        DeliveryVerdict::Pending { hosts: vec!["10.0.0.2:9598".to_string()], unanswered: vec![] }
    );
}

/// An acknowledgement that holds over the same pod set for the window is
/// returned; one that never gets the time to hold is not.
#[tokio::test]
async fn a_stable_acknowledgement_is_returned_after_its_window() {
    let new = page(&[sentinel(GEN_42, 2, 3.0)]);
    let report = await_polls(
        42,
        Duration::from_secs(2),
        Duration::from_millis(10),
        Duration::from_millis(60),
        || {
            let new = new.clone();
            async move { vec![pod("10.0.0.1:9598", &new), pod("10.0.0.2:9598", &new)] }
        },
    )
    .await;
    assert_eq!(report.verdict, DeliveryVerdict::Acknowledged);

    let short = await_polls(42, Duration::from_millis(50), Duration::from_millis(10), Duration::from_secs(5), || {
        let new = new.clone();
        async move { vec![pod("10.0.0.1:9598", &new)] }
    })
    .await;
    assert!(matches!(short.verdict, DeliveryVerdict::Pending { .. }), "{:?}", short.verdict);
}

/// The expected replica count pads a short DNS answer with unanswered pods.
#[test]
fn a_short_dns_answer_is_padded_to_the_expected_pods() {
    let new = page(&[sentinel(GEN_42, 2, 3.0)]);
    let padded = pad_to_expected(vec![pod("10.0.0.1:9598", &new)], 2);
    assert_eq!(padded.len(), 2);
    assert_eq!(padded[1], ("unresolved Vector pod 2 of 2".to_string(), None));
    assert_eq!(grade(42, &padded), None, "1 of 2 expected pods is not every pod");
    assert_eq!(pad_to_expected(vec![pod("a", &new), pod("b", &new)], 1).len(), 2);
    assert_eq!(expected_from(Some(" 3 ")), 3);
    assert_eq!(expected_from(Some("x")), 0);
    assert_eq!(expected_from(None), 0);
}
