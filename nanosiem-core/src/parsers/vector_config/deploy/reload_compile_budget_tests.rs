// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5298 follow-up — the acknowledgement window covers the compile cost of
//! the tree Vector is about to load.
//!
//! A reload compiles every remap program in the tree, so one large parser on a
//! small host can take longer than the 45 s quiet window with NO intermediate
//! progress for the window to extend on: the v2.0.20 Compose upgrade lane
//! (6 cores, 5 OCSF sources) rolled back Microsoft Sysmon at 45 s while Vector
//! reported "Vector has reloaded" at 67 s. These pin the size-aware window.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const BASE: Duration = Duration::from_secs(45);
const CAP: Duration = Duration::from_secs(600);
const KIB: u64 = 1024;
const MIB_BYTES: u64 = 1024 * 1024;

/// The lane's tree: about 340 KiB of rendered parsers for 5 OCSF sources.
#[test]
fn before_any_measurement_the_lane_tree_gets_more_than_its_67s_reload() {
    let durations = ReloadDurations::new();
    let window = durations.window_for(BASE, CAP, 340 * KIB);
    assert!(window > Duration::from_secs(67), "{window:?}");
    assert!(window < CAP, "a 340 KiB tree must not need the ceiling: {window:?}");
}

#[test]
fn an_unknown_or_small_tree_keeps_the_configured_window() {
    let durations = ReloadDurations::new();
    assert_eq!(durations.window_for(BASE, CAP, 0), BASE);
    assert_eq!(durations.window_for(BASE, CAP, 64 * KIB), BASE);
    assert_eq!(durations.window(BASE, CAP), durations.window_for(BASE, CAP, 0));
}

/// A measured rate replaces the default, with headroom, and scales with the
/// tree the next reload compiles rather than the tree the last one did.
#[test]
fn a_measured_rate_scales_with_the_next_tree() {
    let durations = ReloadDurations::new();
    // 10 s for 1 MiB on this host.
    durations.record_reload(Duration::from_secs(10), MIB_BYTES);
    // Duration alone: 2 x 10 s = 20 s < base.
    assert_eq!(durations.window(BASE, CAP), BASE);
    // A 4 MiB tree: 2 x 40 s.
    assert_eq!(durations.window_for(BASE, CAP, 4 * MIB_BYTES), Duration::from_secs(80));
    // Ceiling, which never undercuts the base.
    assert_eq!(durations.window_for(BASE, CAP, 1024 * MIB_BYTES), CAP);
    assert_eq!(durations.window_for(BASE, Duration::from_secs(5), 1024 * MIB_BYTES), BASE);
}

#[test]
fn a_slow_rate_decays_instead_of_pinning_later_windows() {
    let durations = ReloadDurations::new();
    durations.record_reload(Duration::from_secs(100), MIB_BYTES);
    assert_eq!(durations.window_for(BASE, CAP, MIB_BYTES), Duration::from_secs(200));
    for _ in 0..10 {
        durations.record_reload(Duration::from_secs(5), MIB_BYTES);
    }
    assert!(durations.window_for(BASE, CAP, MIB_BYTES) < Duration::from_secs(60));
}

#[test]
fn loaded_config_bytes_counts_what_vector_loads_and_nothing_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    for sub in ["sources/parsers", "sources/configs", "sinks", "backup", "staging/sources/parsers"] {
        std::fs::create_dir_all(root.join(sub)).expect("mkdir");
    }
    std::fs::write(root.join("00-base.toml"), vec![b'a'; 100]).expect("write");
    std::fs::write(root.join("sources/parsers/sysmon.toml"), vec![b'a'; 1000]).expect("write");
    std::fs::write(root.join("sources/configs/http.toml"), vec![b'a'; 10]).expect("write");
    std::fs::write(root.join("sinks/ch.toml"), vec![b'a'; 1]).expect("write");
    // Not loaded by Vector: in-flight dotfiles, backups, staging, other files.
    std::fs::write(root.join("sources/parsers/.sysmon.toml.tmp"), vec![b'a'; 5000]).expect("write");
    std::fs::write(root.join("backup/sysmon.toml"), vec![b'a'; 5000]).expect("write");
    std::fs::write(root.join("staging/sources/parsers/sysmon.toml"), vec![b'a'; 5000]).expect("write");
    std::fs::write(root.join("README.md"), vec![b'a'; 5000]).expect("write");
    assert_eq!(loaded_config_bytes(root), 1111);
    assert_eq!(loaded_config_bytes(&root.join("missing")), 0);
}

/// Vector loads the marker on one long reload, with no reload completing in
/// between to extend the quiet window. The size-aware window waits for it;
/// the configured window alone rolls back a config Vector was about to accept.
struct LateMarker {
    started: std::sync::Mutex<Option<std::time::Instant>>,
    after: Duration,
}

impl Respond for LateMarker {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let started = *self
            .started
            .lock()
            .expect("lock")
            .get_or_insert_with(std::time::Instant::now);
        let live = started.elapsed() >= self.after;
        let mut body = String::from(
            "nanosiem_vector_reloaded_total{host=\"h\"} 1\n\
             nanosiem_vector_component_errors_total{error_type=\"configuration_failed\"} 0\n",
        );
        if live {
            body.push_str(
                "nanosiem_vector_component_sent_events_total{component_id=\"nano_activation_mine\",component_kind=\"source\"} 1\n",
            );
        }
        ResponseTemplate::new(200).set_body_string(body)
    }
}

async fn late_marker_probe(loaded_bytes: u64) -> ReloadAckProbe {
    late_marker_probe_with(loaded_bytes, false).await
}

async fn late_marker_probe_with(loaded_bytes: u64, expect_outcome: bool) -> ReloadAckProbe {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(LateMarker {
            started: std::sync::Mutex::new(None),
            after: Duration::from_millis(500),
        })
        .mount(&server)
        .await;
    let durations: &'static ReloadDurations = Box::leak(Box::new(ReloadDurations::new()));
    let base = Duration::from_millis(150);
    let max_wait = Duration::from_secs(5);
    let probe = ReloadAckProbe {
        url: format!("{}/metrics", server.uri()),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        timeout: durations.window_for(base, max_wait, loaded_bytes),
        base,
        unreadable_grace: std::time::Duration::from_secs(60),
        max_wait,
        durations,
        loaded_bytes,
        expect_outcome,
        poll_interval: Duration::from_millis(10),
    };
    // Keep the mock server alive for the probe's lifetime.
    Box::leak(Box::new(server));
    probe
}

#[tokio::test]
async fn one_long_reload_is_accepted_when_the_tree_estimate_covers_it() {
    // 8 KiB at the default 512 s/MiB: a 4 s window, the marker at 0.5 s.
    let probe = late_marker_probe(8 * KIB).await;
    let before = ReloadCounters {
        reloads: 1.0,
        config_failures: 0.0,
    };
    assert_eq!(probe.await_marker(before, "nano_activation_mine").await, ReloadAck::Accepted);
    // The accepted reload became this host's per-size rate.
    let measured = probe.durations.window_for(Duration::from_millis(1), Duration::from_secs(60), 8 * KIB);
    assert!(measured < Duration::from_secs(4), "rate not recorded: {measured:?}");
}

#[tokio::test]
async fn without_a_size_the_same_reload_is_still_unacknowledged() {
    let probe = late_marker_probe(0).await;
    let before = ReloadCounters {
        reloads: 1.0,
        config_failures: 0.0,
    };
    assert_eq!(
        probe.await_marker(before, "nano_activation_mine").await,
        ReloadAck::NotAcknowledged
    );
}

/// A delivered signal guarantees Vector an outcome: with no size estimate and
/// no intermediate reload, the wait still runs until Vector applies the change.
#[tokio::test]
async fn a_delivered_signal_waits_for_the_outcome_past_the_quiet_window() {
    let probe = late_marker_probe_with(0, true).await;
    let before = ReloadCounters {
        reloads: 1.0,
        config_failures: 0.0,
    };
    assert_eq!(probe.await_marker(before, "nano_activation_mine").await, ReloadAck::Accepted);
}

/// ...but a refusal ends the open-ended wait: one quiet window for a reload
/// already in flight, then Rejected, long before the ceiling.
#[tokio::test]
async fn a_delivered_signal_that_vector_refuses_still_rolls_back_promptly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "nanosiem_vector_reloaded_total{host=\"h\"} 1\n\
             nanosiem_vector_component_errors_total{error_type=\"configuration_failed\"} 1\n",
        ))
        .mount(&server)
        .await;
    let mut probe = ReloadAckProbe {
        url: format!("{}/metrics", server.uri()),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        timeout: Duration::from_millis(150),
        base: Duration::from_millis(150),
        unreadable_grace: std::time::Duration::from_secs(60),
        max_wait: Duration::from_secs(30),
        durations: Box::leak(Box::new(ReloadDurations::new())),
        loaded_bytes: 0,
        expect_outcome: false,
        poll_interval: Duration::from_millis(10),
    };
    probe.expect_outcome();
    let before = ReloadCounters {
        reloads: 1.0,
        config_failures: 0.0,
    };
    let started = std::time::Instant::now();
    assert_eq!(probe.await_marker(before, "nano_activation_mine").await, ReloadAck::Rejected);
    assert!(started.elapsed() < Duration::from_secs(5), "waited for the ceiling: {:?}", started.elapsed());
    let started = std::time::Instant::now();
    assert_eq!(probe.await_ack(before).await, ReloadAck::Rejected);
    assert!(started.elapsed() < Duration::from_secs(5), "waited for the ceiling: {:?}", started.elapsed());
}

// ---------------------------------------------------------------------------
// NAN-5298 review round: budgets, rejection, expiry, dead Vector, breaker.
// ---------------------------------------------------------------------------


const BEFORE: ReloadCounters = ReloadCounters {
    reloads: 1.0,
    config_failures: 0.0,
};

#[allow(clippy::too_many_arguments)]
fn probe_at(
    url: String,
    base: Duration,
    timeout: Duration,
    max_wait: Duration,
    unreadable_grace: Duration,
    loaded_bytes: u64,
) -> ReloadAckProbe {
    ReloadAckProbe {
        url,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .expect("client"),
        base,
        timeout,
        max_wait,
        durations: Box::leak(Box::new(ReloadDurations::new())),
        loaded_bytes,
        expect_outcome: false,
        unreadable_grace,
        poll_interval: Duration::from_millis(10),
    }
}

/// Answers `bodies[i]` for the i-th scrape (the last one repeats).
struct Script(Arc<AtomicUsize>, Vec<(u16, String)>);

impl Respond for Script {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.0.fetch_add(1, Ordering::SeqCst).min(self.1.len() - 1);
        let (status, body) = &self.1[n];
        ResponseTemplate::new(*status).set_body_string(body.clone())
    }
}

async fn scripted(bodies: Vec<(u16, String)>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(Script(Arc::new(AtomicUsize::new(0)), bodies))
        .mount(&server)
        .await;
    server
}

fn counters(reloads: u64, failure_series: &[(&str, u64)]) -> String {
    let mut body = format!("nanosiem_vector_reloaded_total{{host=\"h\"}} {reloads}\n");
    for (component, value) in failure_series {
        body.push_str(&format!(
            "nanosiem_vector_component_errors_total{{component_id=\"{component}\",error_type=\"configuration_failed\"}} {value}\n"
        ));
    }
    body
}

/// A refusal after a long silence on a LARGE tree: the size window would be
/// minutes; the verdict comes one BASE window after the refusal.
#[tokio::test]
async fn a_rejection_after_silence_on_a_large_tree_waits_only_the_base_window() {
    let mut bodies = vec![(200, counters(1, &[])); 20];
    bodies.push((200, counters(1, &[("t", 1)])));
    let server = scripted(bodies).await;
    let mut probe = probe_at(
        format!("{}/metrics", server.uri()),
        Duration::from_millis(150),
        Duration::from_secs(30), // the size window of a large tree
        Duration::from_secs(60),
        Duration::from_secs(60),
        8 * MIB_BYTES,
    );
    probe.expect_outcome();
    let started = std::time::Instant::now();
    assert_eq!(probe.await_marker(BEFORE, "nano_activation_mine").await, ReloadAck::Rejected);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
    let started = std::time::Instant::now();
    let server = scripted(vec![(200, counters(1, &[])), (200, counters(1, &[("t", 1)]))]).await;
    probe.url = format!("{}/metrics", server.uri());
    assert_eq!(probe.await_ack(BEFORE).await, ReloadAck::Rejected);
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

/// `configuration_failed` series expire: the summed counter FALLS mid-wait
/// with no new refusal. That is not a rejection; the delivered wait goes on
/// to the marker.
#[tokio::test]
async fn an_expiring_failure_series_is_not_a_rejection() {
    let before = ReloadCounters {
        reloads: 1.0,
        config_failures: 3.0,
    };
    let mut bodies = vec![(200, counters(1, &[("old", 3)])), (200, counters(1, &[]))];
    bodies.extend(std::iter::repeat_n((200, counters(1, &[])), 10));
    bodies.push((
        200,
        "nanosiem_vector_reloaded_total{host=\"h\"} 2\n\
         nanosiem_vector_component_sent_events_total{component_id=\"nano_activation_mine\",component_kind=\"source\"} 1\n"
            .to_string(),
    ));
    let server = scripted(bodies).await;
    let mut probe = probe_at(
        format!("{}/metrics", server.uri()),
        Duration::from_millis(50),
        Duration::from_millis(50),
        Duration::from_secs(10),
        Duration::from_secs(60),
        0,
    );
    probe.expect_outcome();
    assert_eq!(probe.await_marker(before, "nano_activation_mine").await, ReloadAck::Accepted);

    // ...but a series that restarted from 1 below an expired baseline IS a
    // new refusal (it rose between two scrapes of the wait).
    let server = scripted(vec![
        (200, counters(1, &[("old", 3)])),
        (200, counters(1, &[])),
        (200, counters(1, &[("new", 1)])),
    ])
    .await;
    probe.url = format!("{}/metrics", server.uri());
    assert_eq!(probe.await_ack(before).await, ReloadAck::Rejected);
}

#[test]
fn rejection_watch_ignores_decreases_and_sees_new_series() {
    let mut watch = RejectionWatch::new(ReloadCounters {
        reloads: 0.0,
        config_failures: 2.0,
    });
    assert!(!watch.observe(&counters(0, &[("a", 2)])));
    assert!(!watch.observe(&counters(0, &[])), "expiry is not a refusal");
    assert!(watch.observe(&counters(0, &[("b", 1)])), "a new series is a refusal");
    assert!(!watch.observe(&counters(0, &[("b", 1)])));
    assert!(watch.observe(&counters(0, &[("b", 2)])), "a rising series is a refusal");
}

/// A delivered wait on a Vector that dies: 200, then the endpoint fails.
/// The wait ends after the unreadable grace, not at the ceiling, in both
/// acknowledgement modes, for an error status and for a refused connection.
#[tokio::test]
async fn a_dead_vector_ends_a_delivered_wait_after_the_unreadable_grace() {
    for status in [500u16, 0] {
        let server = scripted(vec![(200, counters(1, &[])), (200, counters(1, &[])), (500, String::new())]).await;
        let url = if status == 0 {
            // A refused connection: the endpoint goes away entirely.
            "http://127.0.0.1:1/metrics".to_string()
        } else {
            format!("{}/metrics", server.uri())
        };
        for marker_mode in [true, false] {
            let mut probe = probe_at(
                url.clone(),
                Duration::from_millis(100),
                Duration::from_millis(100),
                Duration::from_secs(30),
                Duration::from_millis(400),
                0,
            );
            probe.expect_outcome();
            let started = std::time::Instant::now();
            let ack = if marker_mode {
                probe.await_marker(BEFORE, "nano_activation_mine").await
            } else {
                probe.await_ack(BEFORE).await
            };
            assert_eq!(ack, ReloadAck::NotAcknowledged, "status {status} marker {marker_mode}");
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "status {status} marker {marker_mode}: {:?}",
                started.elapsed()
            );
            assert!(!probe.durations.outcome_wait_tripped(), "a dead Vector is not a wedge");
        }
    }
}

/// Delivered, answering, silent to the ceiling: the breaker trips, the next
/// delivered reload gets only the quiet window, and any outcome resets it.
#[tokio::test]
async fn a_wedged_vector_trips_the_outcome_wait_breaker_until_it_answers_again() {
    let server = scripted(vec![(200, counters(1, &[]))]).await;
    let mut probe = probe_at(
        format!("{}/metrics", server.uri()),
        Duration::from_millis(50),
        Duration::from_millis(50),
        Duration::from_millis(300),
        Duration::from_secs(60),
        0,
    );
    probe.arm_for_delivery(true, ReloadMode::Forward);
    assert!(probe.expect_outcome);
    assert_eq!(probe.await_marker(BEFORE, "nano_activation_mine").await, ReloadAck::NotAcknowledged);
    assert!(probe.durations.outcome_wait_tripped());

    let mut next = probe_at(probe.url.clone(), probe.base, probe.timeout, probe.max_wait, probe.unreadable_grace, 0);
    next.durations = probe.durations;
    next.arm_for_delivery(true, ReloadMode::Forward);
    assert!(!next.expect_outcome, "tripped: quiet window only");

    let live = scripted(vec![(200, counters(2, &[]))]).await;
    next.url = format!("{}/metrics", live.uri());
    assert_eq!(next.await_ack(BEFORE).await, ReloadAck::Accepted);
    assert!(!next.durations.outcome_wait_tripped(), "an outcome resets the breaker");
}

#[test]
fn the_outcome_wait_is_armed_only_for_a_delivered_forward_reload() {
    for (delivered, mode, armed) in [
        (true, ReloadMode::Forward, true),
        (false, ReloadMode::Forward, false),
        (true, ReloadMode::Rollback, false),
        (false, ReloadMode::Rollback, false),
    ] {
        let mut probe = probe_at(
            "http://127.0.0.1:1/metrics".into(),
            BASE,
            BASE,
            CAP,
            Duration::from_secs(60),
            0,
        );
        probe.arm_for_delivery(delivered, mode);
        assert_eq!(probe.expect_outcome, armed, "{delivered} {mode:?}");
    }
}

/// A rollback's reload waits only the base window, however large the tree.
#[tokio::test]
async fn a_rollback_reload_waits_only_the_base_window() {
    let server = scripted(vec![(200, counters(1, &[]))]).await;
    let mut probe = probe_at(
        format!("{}/metrics", server.uri()),
        Duration::from_millis(150),
        Duration::from_secs(30),
        Duration::from_secs(30),
        Duration::from_secs(60),
        8 * MIB_BYTES,
    );
    // What `for_rollback` does to an environment probe.
    probe.timeout = probe.base;
    probe.max_wait = probe.base;
    probe.arm_for_delivery(true, ReloadMode::Rollback);
    let started = std::time::Instant::now();
    assert_eq!(probe.await_marker(BEFORE, "nano_activation_mine").await, ReloadAck::NotAcknowledged);
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
}

/// No counter baseline (the pre-reload scrape failed), but the marker goes
/// live: still an acceptance.
#[tokio::test]
async fn a_marker_without_a_baseline_is_still_accepted() {
    let server = scripted(vec![
        (500, String::new()),
        (200, counters(1, &[])),
        (200, counters(1, &[])),
        (
            200,
            "nanosiem_vector_reloaded_total{host=\"h\"} 2\n\
             nanosiem_vector_component_sent_events_total{component_id=\"nano_activation_mine\",component_kind=\"source\"} 1\n"
                .to_string(),
        ),
    ])
    .await;
    let probe = probe_at(
        format!("{}/metrics", server.uri()),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(10),
        Duration::from_secs(60),
        0,
    );
    assert_eq!(probe.await_marker_unbaselined("nano_activation_mine").await, ReloadAck::Accepted);
}

/// The window is sized from the tree AFTER the change is written: a large
/// file added to a small tree stretches it.
#[test]
fn the_window_is_resized_for_the_tree_as_written() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sources/parsers")).expect("mkdir");
    std::fs::write(dir.path().join("00-base.toml"), vec![b'a'; 1024]).expect("write");
    let mut probe = probe_at("http://127.0.0.1:1/metrics".into(), BASE, BASE, CAP, Duration::from_secs(60), 0);
    probe.resize_for(dir.path());
    assert_eq!(probe.timeout, BASE, "a 1 KiB tree keeps the base window");
    std::fs::write(dir.path().join("sources/parsers/sysmon.toml"), vec![b'a'; 400 * 1024]).expect("write");
    probe.resize_for(dir.path());
    assert!(probe.loaded_bytes > 400 * 1024);
    assert!(probe.timeout > Duration::from_secs(150), "{:?}", probe.timeout);
}

/// The fixed budgets the reload wait has to fit inside.
#[test]
fn the_reload_wait_fits_every_synchronous_and_lock_budget() {
    const EDGE_PROXY_READ_TIMEOUT: u64 = 300;
    const ISOLATION_VALIDATE_BOUND: u64 = 90;
    const ENTRYPOINT_FLOCK_WAIT: u64 = 120;
    const WEB_DEPLOY_JOB_POLL: u64 = 15 * 60;
    let forward = DEFAULT_RELOAD_ACK_MAX_SECS;
    let rollback = DEFAULT_RELOAD_ACK_TIMEOUT_SECS;
    // A synchronous source-config deploy: isolation validate, then the
    // forward wait (a refusal ends it early, so no full rollback follows).
    assert!(ISOLATION_VALIDATE_BOUND + forward < EDGE_PROXY_READ_TIMEOUT);
    // The deploy lock: forward plus a rollback, inside config_lock's give-up.
    assert!(forward + rollback <= super::super::config_lock::MAX_WAIT.as_secs());
    // A Vector that died and restarts waits on the lock: the dead-Vector
    // grace plus a rollback must end inside the entrypoint's flock wait.
    assert!(DEFAULT_RELOAD_ACK_UNREADABLE_SECS + rollback < ENTRYPOINT_FLOCK_WAIT);
    // The web follows a deploy job for 15 minutes.
    assert!(forward + rollback < WEB_DEPLOY_JOB_POLL);
    // And the entrypoint really waits 120 s.
    let entrypoint = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../config/vector/.nano/vector-entrypoint.sh");
    if let Ok(text) = std::fs::read_to_string(entrypoint) {
        assert!(text.contains(&format!("flock -w {ENTRYPOINT_FLOCK_WAIT} 9")));
    }
}
