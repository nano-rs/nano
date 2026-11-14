// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5298 — the acknowledgement window fits the reload actually in progress.
//!
//! A fixed 45 s window rolled back configs Vector went on to accept: with the
//! OCSF library deployed, one reload takes ~20 s and a publish queues two or
//! three of them. These pin the two halves of the fix: the quiet window is
//! restarted by every reload Vector completes while ours is still queued (up
//! to a hard ceiling), and it is sized from the reloads this process measured.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn body(reloads: usize, marker_live: bool) -> String {
    let mut body = format!(
        "nanosiem_vector_reloaded_total{{host=\"h\"}} {reloads}\n\
         nanosiem_vector_component_errors_total{{error_type=\"configuration_failed\"}} 0\n"
    );
    if marker_live {
        body.push_str(
            "nanosiem_vector_component_sent_events_total{component_id=\"nano_activation_mine\",component_kind=\"source\"} 1\n",
        );
    }
    body
}

/// Vector working through a reload queue: every `per_reload` scrapes one more
/// reload completes; the marker goes live at scrape `marker_at` (never when
/// `None`).
struct Queue {
    scrapes: Arc<AtomicUsize>,
    per_reload: usize,
    marker_at: Option<usize>,
}

impl Respond for Queue {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.scrapes.fetch_add(1, Ordering::SeqCst);
        let live = self.marker_at.is_some_and(|at| n >= at);
        ResponseTemplate::new(200).set_body_string(body(1 + n / self.per_reload, live))
    }
}

async fn server(per_reload: usize, marker_at: Option<usize>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(Queue {
            scrapes: Arc::new(AtomicUsize::new(0)),
            per_reload,
            marker_at,
        })
        .mount(&server)
        .await;
    server
}

/// Like [`Queue`] but on wall time, so a loaded test runner (slow scrapes)
/// cannot stretch the gap between reloads past the quiet window: one reload
/// completes every `period`, and the marker goes live after `marker_after`.
struct Timed {
    started: std::sync::Mutex<Option<std::time::Instant>>,
    period: Duration,
    marker_after: Duration,
}

impl Respond for Timed {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let started = *self
            .started
            .lock()
            .expect("lock")
            .get_or_insert_with(std::time::Instant::now);
        let elapsed = started.elapsed();
        let reloads = 1 + (elapsed.as_millis() / self.period.as_millis()) as usize;
        ResponseTemplate::new(200).set_body_string(body(reloads, elapsed >= self.marker_after))
    }
}

async fn timed_server(period: Duration, marker_after: Duration) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(Timed {
            started: std::sync::Mutex::new(None),
            period,
            marker_after,
        })
        .mount(&server)
        .await;
    server
}

fn probe(server: &MockServer, quiet: Duration, max_wait: Duration) -> ReloadAckProbe {
    ReloadAckProbe {
        url: format!("{}/metrics", server.uri()),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        timeout: quiet,
        base: quiet,
        unreadable_grace: std::time::Duration::from_secs(60),
        max_wait,
        durations: Box::leak(Box::new(ReloadDurations::new())),
        loaded_bytes: 0,
        expect_outcome: false,
        poll_interval: Duration::from_millis(10),
    }
}

const BEFORE: ReloadCounters = ReloadCounters {
    reloads: 1.0,
    config_failures: 0.0,
};

/// Our reload is queued behind others: Vector completes reloads (without our
/// marker) for well past the quiet window, then applies ours. That is an
/// acceptance, not a rollback.
#[tokio::test]
async fn completed_reloads_restart_the_quiet_window() {
    // A reload completes every 50 ms; the marker appears at 900 ms, three
    // quiet windows in.
    let server = timed_server(Duration::from_millis(50), Duration::from_millis(900)).await;
    let probe = probe(&server, Duration::from_millis(300), Duration::from_secs(10));
    assert_eq!(probe.await_marker(BEFORE, "nano_activation_mine").await, ReloadAck::Accepted);
}

/// Silence is still silence: no reload completes and the marker never shows,
/// so the verdict comes after ONE quiet window, not the ceiling.
#[tokio::test]
async fn a_silent_vector_still_times_out_after_the_quiet_window() {
    let server = server(usize::MAX, None).await;
    let probe = probe(&server, Duration::from_millis(150), Duration::from_secs(30));
    let started = std::time::Instant::now();
    assert_eq!(
        probe.await_marker(BEFORE, "nano_activation_mine").await,
        ReloadAck::NotAcknowledged
    );
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

/// Progress never extends past the ceiling: a Vector reloading forever
/// without our change is not acknowledged.
#[tokio::test]
async fn progress_never_extends_past_the_ceiling() {
    let server = server(2, None).await;
    let probe = probe(&server, Duration::from_millis(100), Duration::from_millis(400));
    let started = std::time::Instant::now();
    assert_eq!(
        probe.await_marker(BEFORE, "nano_activation_mine").await,
        ReloadAck::NotAcknowledged
    );
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(390), "stopped before the ceiling: {took:?}");
    assert!(took < Duration::from_secs(5), "ignored the ceiling: {took:?}");
}

#[test]
fn the_window_is_the_configured_one_until_a_reload_was_measured() {
    let durations = ReloadDurations::new();
    let base = Duration::from_secs(45);
    let cap = Duration::from_secs(600);
    assert_eq!(durations.window(base, cap), base);
    durations.record(Duration::from_secs(10));
    assert_eq!(durations.window(base, cap), base, "fast reloads never shrink it below the base");
}

#[test]
fn the_window_grows_with_measured_reloads_and_is_capped() {
    let durations = ReloadDurations::new();
    let base = Duration::from_secs(45);
    let cap = Duration::from_secs(600);
    durations.record(Duration::from_secs(40));
    assert_eq!(durations.window(base, cap), Duration::from_secs(80));
    durations.record(Duration::from_secs(900));
    assert_eq!(durations.window(base, cap), cap);
    // A cap below the configured base never undercuts the base.
    assert_eq!(durations.window(base, Duration::from_secs(5)), base);
}

#[test]
fn one_slow_reload_decays_instead_of_pinning_every_later_window() {
    let durations = ReloadDurations::new();
    let base = Duration::from_secs(45);
    let cap = Duration::from_secs(600);
    durations.record(Duration::from_secs(200));
    assert_eq!(durations.window(base, cap), Duration::from_secs(400));
    for _ in 0..10 {
        durations.record(Duration::from_secs(5));
    }
    assert!(durations.window(base, cap) < Duration::from_secs(60), "{:?}", durations.window(base, cap));
}

/// The watcher rejected a half-written tree, then Vector kept completing
/// reloads without our marker until the ceiling: still a rejection.
#[tokio::test]
async fn a_rejection_with_no_marker_is_still_rejected_after_extensions() {
    struct Rejecting(Arc<AtomicUsize>);
    impl Respond for Rejecting {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_string(format!(
                "nanosiem_vector_reloaded_total {}\n\
                 nanosiem_vector_component_errors_total{{error_type=\"configuration_failed\"}} 1\n",
                1 + n / 2
            ))
        }
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(Rejecting(Arc::new(AtomicUsize::new(0))))
        .mount(&server)
        .await;
    let probe = probe(&server, Duration::from_millis(100), Duration::from_millis(400));
    assert_eq!(probe.await_marker(BEFORE, "nano_activation_mine").await, ReloadAck::Rejected);
}

/// The measured duration is OUR reload (since the last foreign reload
/// completed), not the whole queued wait: the queue is covered by the
/// progress extensions, and counting it would stretch the next quiet window
/// so a rejecting or dead Vector takes many times longer to roll back.
#[tokio::test]
async fn a_queued_wait_records_only_our_reload_not_the_queue() {
    // Foreign reloads every 50 ms until the marker at 900 ms: the whole
    // wait is ~900 ms, our own reload at most ~50 ms plus poll jitter.
    let server = timed_server(Duration::from_millis(50), Duration::from_millis(900)).await;
    let probe = probe(&server, Duration::from_millis(300), Duration::from_secs(10));
    let started = std::time::Instant::now();
    assert_eq!(probe.await_marker(BEFORE, "nano_activation_mine").await, ReloadAck::Accepted);
    let total = started.elapsed();
    let base = Duration::from_millis(1);
    let recorded_window = probe.durations.window(base, Duration::from_secs(60));
    assert!(
        recorded_window < total,
        "recorded the whole queued wait: window {recorded_window:?} vs wait {total:?}"
    );
}
