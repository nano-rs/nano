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
        acked.note(timeout),
        "Published generation 7 and acknowledged by 2/2 ingest host(s)."
    );
    let pending = DeliveryReport {
        generation: 7,
        host_count: 2,
        verdict: DeliveryVerdict::Pending { hosts: vec!["http://nano-3:8687".into()] },
    };
    let note = pending.note(timeout);
    assert!(note.contains("1/2 ingest host(s) acknowledged it within 75s"), "{note}");
    assert!(note.contains("http://nano-3:8687"), "{note}");
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
