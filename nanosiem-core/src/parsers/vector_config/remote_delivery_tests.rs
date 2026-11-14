// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn host(name: &str, installed: u64, failed: Option<u64>) -> (String, Option<HostGeneration>) {
    (
        name.to_string(),
        Some(HostGeneration {
            installed,
            installing: None,
            failed,
            failed_reason: failed.map(|_| "rejected".to_string()),
        }),
    )
}

#[test]
fn every_host_at_or_past_the_generation_is_acknowledged() {
    let hosts = [host("a", 12, None), host("b", 13, None)];
    assert_eq!(grade(12, &hosts), Some(DeliveryVerdict::Acknowledged));
}

#[test]
fn a_host_still_on_the_previous_generation_keeps_waiting() {
    let hosts = [host("a", 12, None), host("b", 11, None)];
    assert_eq!(grade(12, &hosts), None);
    assert_eq!(pending_hosts(12, &hosts), vec!["b".to_string()]);
}

#[test]
fn an_unreachable_relay_is_pending_never_acknowledged() {
    let hosts = [host("a", 12, None), ("b".to_string(), None)];
    assert_eq!(grade(12, &hosts), None);
    assert_eq!(pending_hosts(12, &hosts), vec!["b".to_string()]);
}

#[test]
fn a_host_that_rolled_this_generation_back_rejects_it() {
    let hosts = [host("a", 12, None), host("b", 11, Some(12))];
    assert_eq!(
        grade(12, &hosts),
        Some(DeliveryVerdict::Rejected { hosts: vec!["b".to_string()] })
    );
}

#[test]
fn an_older_failure_does_not_reject_a_newer_generation() {
    let hosts = [host("a", 11, Some(10))];
    assert_eq!(grade(12, &hosts), None);
    // ...and a failure later healed by a retry that installed it is no rejection.
    let healed = [host("a", 12, Some(12))];
    assert_eq!(grade(12, &healed), Some(DeliveryVerdict::Acknowledged));
}

#[test]
fn notes_name_the_generation_and_the_unconfirmed_hosts() {
    let timeout = Duration::from_secs(75);
    let acked = DeliveryReport {
        generation: 7,
        host_count: 2,
        verdict: DeliveryVerdict::Acknowledged,
    };
    assert_eq!(
        acked.note(timeout, Duration::from_secs(5)),
        "Published generation 7 and acknowledged by 2/2 ingest host(s)."
    );
    let pending = DeliveryReport {
        generation: 7,
        host_count: 2,
        verdict: DeliveryVerdict::Pending {
            hosts: vec!["http://nano-3:8687".into()],
            unanswered: vec![],
        },
    };
    let note = pending.note(timeout, Duration::from_secs(5));
    assert!(note.contains("1/2 ingest host(s) acknowledged it within 75s"), "{note}");
    assert!(note.contains("http://nano-3:8687"), "{note}");
    assert!(note.contains("GET /api/log-sources/delivery-status?generation=7"), "{note}");
    assert_eq!(pending.state(), DeliveryState::Pending);
}

#[test]
fn relay_status_document_parses_without_optional_fields() {
    let status: HostGeneration = serde_json::from_str(r#"{"installed":5}"#).unwrap();
    assert_eq!(status.installed, 5);
    assert_eq!(status.failed, None);
}

use std::sync::atomic::{AtomicU64, Ordering};

/// Minimal HTTP/1.1 responder: `body(n)` answers the n-th request.
async fn serve(body: Arc<dyn Fn(u64) -> String + Send + Sync>) -> (String, Arc<AtomicU64>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let counter = calls.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let payload = body(n);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = socket.read(&mut buffer).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (format!("http://{address}"), calls)
    }
}

/// End to end against stub relays: two hosts, one installs after a poll, the
/// other is already there.
#[tokio::test]
async fn await_hosts_waits_for_the_slow_host() {
    let (slow, slow_calls) = serve(Arc::new(|n| {
        format!(r#"{{"installed":{}}}"#, if n == 0 { 3 } else { 4 })
    }))
    .await;
    let (fast, _) = serve(Arc::new(|_| r#"{"installed":4}"#.to_string())).await;
    let token = "t".repeat(MIN_TOKEN_BYTES);
    let report = await_hosts(4, &[slow, fast], &token, Duration::from_secs(20)).await;
    assert_eq!(report.verdict, DeliveryVerdict::Acknowledged);
    assert!(slow_calls.load(Ordering::SeqCst) >= 2);
}

fn token() -> String {
    "t".repeat(MIN_TOKEN_BYTES)
}

/// Review M2: no host confirming is never a success. A drifted tap token or
/// unreachable relays (here: a port nothing listens on) must not read as live.
#[tokio::test]
async fn zero_of_n_confirmed_is_unconfirmed_not_success() {
    let (stale, _) = serve(Arc::new(|_| r#"{"installed":3}"#.to_string())).await;
    let dead = "http://127.0.0.1:9".to_string();
    let result = grade_published(4, &[stale, dead], &token(), Duration::from_secs(3)).await;
    match &result {
        Err(DeliveryFailure::Unconfirmed(note)) => {
            assert!(note.contains("no ingest host confirmed"), "{note}")
        }
        other => panic!("expected Unconfirmed, got {other:?}"),
    }
    assert!(matches!(grade_delivery(&result), Graded::Unconfirmed(_)));
}

#[tokio::test]
async fn no_relays_configured_is_unconfirmed() {
    let result = grade_published(4, &[], &token(), Duration::from_secs(1)).await;
    assert!(matches!(result, Err(DeliveryFailure::Unconfirmed(_))), "{result:?}");
    let short = grade_published(4, &["http://127.0.0.1:9".into()], "short", Duration::from_secs(1)).await;
    assert!(matches!(short, Err(DeliveryFailure::Unconfirmed(_))), "{short:?}");
}

/// Some hosts confirmed, the rest are named: live, with a warning note.
#[tokio::test]
async fn partial_confirmation_is_live_with_the_rest_named() {
    let (done, _) = serve(Arc::new(|_| r#"{"installed":4}"#.to_string())).await;
    let (behind, _) = serve(Arc::new(|_| r#"{"installed":3}"#.to_string())).await;
    let result = grade_published(4, &[done, behind.clone()], &token(), Duration::from_secs(3)).await;
    match &result {
        Ok(delivered) => {
            assert!(!delivered.confirmed);
            assert!(delivered.note.contains(&behind), "{}", delivered.note);
        }
        other => panic!("expected partial success, got {other:?}"),
    }
    assert_eq!(grade_delivery(&result), Graded::Live);
}

/// A host that rolled the generation back is a rejection on both paths.
#[tokio::test]
async fn a_rolled_back_host_grades_rejected() {
    let (bad, _) = serve(Arc::new(|_| {
        r#"{"installed":3,"failed":4,"failed_reason":"unacknowledged"}"#.to_string()
    }))
    .await;
    let result = grade_published(4, &[bad], &token(), Duration::from_secs(3)).await;
    assert!(matches!(grade_delivery(&result), Graded::Rejected(_)), "{result:?}");
}

/// NAN-5279: two back-to-back generations (import, then deploy) outlast the
/// wait while every host answers and is still installing. That is in
/// progress, not a failure: live (no rollback), not confirmed, state pending,
/// with the hosts and a way to re-check named.
#[tokio::test]
async fn every_host_answering_but_still_installing_is_pending_not_failure() {
    let (a, _) = serve(Arc::new(|_| r#"{"installed":35,"installing":35}"#.to_string())).await;
    let (b, _) = serve(Arc::new(|_| r#"{"installed":35}"#.to_string())).await;
    let result = grade_published(36, &[a.clone(), b.clone()], &token(), Duration::from_secs(3)).await;
    let delivered = match &result {
        Ok(delivered) => delivered.clone(),
        other => panic!("expected pending success, got {other:?}"),
    };
    assert!(!delivered.confirmed);
    assert_eq!(delivered.delivery.state, DeliveryState::Pending);
    assert_eq!(delivered.delivery.generation, 36);
    assert_eq!(delivered.delivery.host_count, 2);
    assert_eq!(delivered.delivery.pending_hosts, vec![a.clone(), b.clone()]);
    assert_eq!(
        delivered.delivery.status_path,
        "/api/log-sources/delivery-status?generation=36"
    );
    let note = &delivered.note;
    assert!(note.contains("ingest hosts have not confirmed it yet"), "{note}");
    assert!(note.contains("delivery polls every"), "{note}");
    assert!(note.contains("Re-check in a minute"), "{note}");
    assert!(!note.contains("NOT known to be live"), "{note}");
    assert_eq!(grade_delivery(&result), Graded::Live);
}

#[tokio::test]
async fn acknowledged_delivery_carries_the_acknowledged_state() {
    let (a, _) = serve(Arc::new(|_| r#"{"installed":9}"#.to_string())).await;
    let result = grade_published(9, &[a], &token(), Duration::from_secs(3)).await;
    let delivered = result.expect("acknowledged");
    assert!(delivered.confirmed);
    assert_eq!(delivered.delivery.state, DeliveryState::Acknowledged);
    assert!(delivered.delivery.pending_hosts.is_empty());
}

#[test]
fn the_wait_covers_two_consumer_install_cycles() {
    // Script defaults: 2 x (5 s poll + 60 s ack + 10 s overhead).
    assert_eq!(derived_ack_timeout(5, 60), Duration::from_secs(150));
    // Enterprise compose consumer (45 s ack): the observed ~60 s per
    // generation twice over fits, where the old fixed 90 s did not.
    assert_eq!(derived_ack_timeout(5, 45), Duration::from_secs(120));
    assert!(derived_ack_timeout(5, 45) > Duration::from_secs(2 * 58));
    // Clamped both ways.
    assert_eq!(derived_ack_timeout(1, 1), Duration::from_secs(30));
    assert_eq!(derived_ack_timeout(60, 600), Duration::from_secs(180));
}

#[test]
fn status_grades_one_poll_without_waiting() {
    let installing = [host("a", 36, None), host("b", 35, None)];
    let status = grade_status(36, &installing);
    assert_eq!(status.state, DeliveryState::Pending);
    assert!(status.generation_delivery);
    assert_eq!(status.host_count, 2);
    assert!(status.hosts[0].confirmed && !status.hosts[1].confirmed);
    assert!(status.message.contains("1/2 ingest host(s)"), "{}", status.message);
    assert!(status.message.contains("Still installing: b"), "{}", status.message);

    let done = [host("a", 36, None), host("b", 37, None)];
    assert_eq!(grade_status(36, &done).state, DeliveryState::Acknowledged);

    let rolled_back = [host("a", 36, None), host("b", 35, Some(36))];
    let status = grade_status(36, &rolled_back);
    assert_eq!(status.state, DeliveryState::Rejected);
    assert_eq!(status.hosts[1].failed, Some(36));

    let unreachable = [host("a", 35, None), ("b".to_string(), None)];
    let status = grade_status(36, &unreachable);
    assert_eq!(status.state, DeliveryState::Unconfirmed);
    assert!(!status.hosts[1].reachable);
    assert!(status.message.contains("did not answer: b"), "{}", status.message);
}

#[tokio::test]
async fn status_without_relays_is_unconfirmed() {
    let status = status_from_relays(4, &[], &token()).await;
    assert_eq!(status.state, DeliveryState::Unconfirmed);
    assert!(status.hosts.is_empty());
}

#[test]
fn delivery_state_serializes_snake_case() {
    assert_eq!(serde_json::to_string(&DeliveryState::Pending).unwrap(), r#""pending""#);
    assert_eq!(
        serde_json::to_string(&DeliveryState::NotApplicable).unwrap(),
        r#""not_applicable""#
    );
}

/// NAN-5298 (review): the API's host wait follows the consumers' longest
/// install (their size-stretched ACK_MAX_SECS), not their 45-60 s floor, so a
/// host that needs 60+ s to compile is waited for as long as the edge allows.
#[test]
fn the_host_wait_follows_the_consumers_install_ceiling() {
    // Defaults and the enterprise compose (floor 45, ceiling 180).
    assert_eq!(install_wait_secs(None, None), DEFAULT_CONSUMER_ACK_MAX_SECS);
    assert_eq!(install_wait_secs(Some(45), Some(180)), 180);
    // A floor above the ceiling wins.
    assert_eq!(install_wait_secs(Some(240), Some(180)), 240);
    let wait = derived_ack_timeout(DEFAULT_CONSUMER_SYNC_INTERVAL_SECS, install_wait_secs(Some(45), None));
    // One 67 s install (the Sysmon compile) plus a poll fits; the edge clamp holds.
    assert!(wait >= Duration::from_secs(67 + DEFAULT_CONSUMER_SYNC_INTERVAL_SECS), "{wait:?}");
    assert!(wait <= Duration::from_secs(180), "{wait:?}");
    // Before: derived from the 45 s floor alone.
    assert!(wait > derived_ack_timeout(DEFAULT_CONSUMER_SYNC_INTERVAL_SECS, 45));
}
