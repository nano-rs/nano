// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2305 — a reload is only "done" when Vector says it is.
//!
//! Every test here pins one half of the same rule: a deploy may report success
//! only on EVIDENCE that Vector loaded the config, never on the assumption that
//! it probably did. Before this, `reload_vector` ended in an unconditional
//! `Ok(())` — so a Vector that rejected the new graph, or that never saw the
//! reload at all, was indistinguishable from one running it.

use super::*;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A Prometheus exposition as Vector's exporter renders it, with the
/// `nanosiem_vector_` namespace from config/vector/92-metrics.toml.
fn metrics_body(reloads: u64, config_failures: u64) -> String {
    format!(
        "# HELP nanosiem_vector_reloaded_total reloaded_total\n\
         # TYPE nanosiem_vector_reloaded_total counter\n\
         nanosiem_vector_reloaded_total{{config_paths=\"/etc/vector\"}} {reloads}\n\
         # TYPE nanosiem_vector_component_errors_total counter\n\
         nanosiem_vector_component_errors_total{{error_type=\"configuration_failed\",stage=\"processing\"}} {config_failures}\n\
         nanosiem_vector_component_errors_total{{error_type=\"writer_failed\",stage=\"sending\"}} 17\n\
         nanosiem_vector_started_total 1\n"
    )
}

/// Probe pointed at a mock server, with timings compressed so a test that has
/// to reach the deadline still finishes in well under a second.
fn probe_for(server: &MockServer) -> ReloadAckProbe {
    probe_at(format!("{}/metrics", server.uri()))
}

fn probe_at(url: String) -> ReloadAckProbe {
    ReloadAckProbe {
        url,
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("client"),
        timeout: std::time::Duration::from_millis(300),
        poll_interval: std::time::Duration::from_millis(25),
    }
}

// ---------------------------------------------------------------------------
// Counter parsing
// ---------------------------------------------------------------------------

/// The exporter prefixes the `internal_metrics` namespace, so the names are
/// `nanosiem_vector_*`, not `vector_*`. Matching on the full name would make
/// the counters permanently invisible — which reads exactly like "Vector never
/// acknowledged" and would turn every deploy into a rollback.
#[test]
fn counters_are_matched_by_suffix_under_the_configured_namespace() {
    let counters = parse_reload_counters(&metrics_body(4, 2));
    assert_eq!(counters.reloads, 4.0);
    assert_eq!(counters.config_failures, 2.0);
}

/// Stock Vector (no `namespace =`) exports the same counters unprefixed. Both
/// spellings have to work: the api does not know how the collector it is
/// talking to was configured.
#[test]
fn counters_are_matched_without_a_namespace_prefix() {
    let body = "vector_reloaded_total 9\n\
                vector_component_errors_total{error_type=\"configuration_failed\"} 3\n";
    let counters = parse_reload_counters(body);
    assert_eq!(counters.reloads, 9.0);
    assert_eq!(counters.config_failures, 3.0);
}

/// `component_errors_total` is emitted for every kind of component failure.
/// Only `error_type="configuration_failed"` means "I refused this config" —
/// counting a sink's send errors as a config rejection would roll back healthy
/// deploys whenever ClickHouse hiccuped.
#[test]
fn only_configuration_failures_count_as_a_rejection() {
    let body = "nanosiem_vector_component_errors_total{error_type=\"writer_failed\"} 400\n\
                nanosiem_vector_component_errors_total{error_type=\"parser_failed\"} 12\n";
    let counters = parse_reload_counters(body);
    assert_eq!(counters.config_failures, 0.0);
}

/// `# HELP` / `# TYPE` metadata lines start with the metric name too. Reading a
/// value off them would either panic on the parse or, worse, sum garbage.
#[test]
fn metadata_lines_and_trailing_timestamps_do_not_corrupt_the_counts() {
    let body = "# HELP vector_reloaded_total reloaded_total\n\
                # TYPE vector_reloaded_total counter\n\
                vector_reloaded_total 2 1717171717000\n";
    assert_eq!(parse_reload_counters(body).reloads, 2.0);
}

/// A Vector that has never reloaded exports no `reloaded_total` at all, so the
/// baseline for a first deploy is an absent counter, not a zero one. Reading
/// that as anything but zero breaks the 0 → 1 comparison, which is the ONLY
/// comparison a first-ever deploy gets to make.
#[tokio::test]
async fn the_first_ever_reload_registers_against_an_absent_counter() {
    let fresh = "nanosiem_vector_started_total 1\n";
    let before = parse_reload_counters(fresh);
    assert_eq!(before.reloads, 0.0);
    assert_eq!(before.config_failures, 0.0);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(1, 0)))
        .mount(&server)
        .await;

    assert_eq!(probe_for(&server).await_ack(before).await, ReloadAck::Accepted);
}

// ---------------------------------------------------------------------------
// Acknowledgement
// ---------------------------------------------------------------------------

/// The success counter passing its pre-reload value is the ONLY positive proof
/// that the config we just published is the one Vector is running.
#[tokio::test]
async fn a_moved_success_counter_is_an_acceptance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(5, 0)))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 4.0,
        config_failures: 0.0,
    };
    assert_eq!(probe_for(&server).await_ack(before).await, ReloadAck::Accepted);
}

/// Vector answering, staying up, and doing nothing is the exact failure this
/// issue is about: the reload never reached it (or its watcher is not watching
/// what we wrote), and every liveness probe stays green throughout.
#[tokio::test]
async fn silence_from_both_counters_is_not_an_acceptance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(4, 0)))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 4.0,
        config_failures: 0.0,
    };
    assert_eq!(
        probe_for(&server).await_ack(before).await,
        ReloadAck::NotAcknowledged
    );
}

/// A moved `configuration_failed` counter means Vector read the config and
/// refused it — it is still serving the PREVIOUS topology, so whatever this
/// deploy added is receiving nothing.
#[tokio::test]
async fn a_moved_failure_counter_is_a_rejection() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(4, 1)))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 4.0,
        config_failures: 0.0,
    };
    assert_eq!(probe_for(&server).await_ack(before).await, ReloadAck::Rejected);
}

/// One promotion writes many files, and a `--watch-config` Vector can fire on a
/// half-written tree, reject it, then fire again on the complete one. The
/// counters are cumulative, so the later success is the authoritative statement
/// about what is running — treating the earlier rejection as final would roll
/// back a config Vector had already accepted.
#[tokio::test]
async fn a_success_after_a_rejection_wins() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(4, 1)))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(5, 1)))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 4.0,
        config_failures: 0.0,
    };
    assert_eq!(probe_for(&server).await_ack(before).await, ReloadAck::Accepted);
}

/// Vector ages out counters that stop being updated, and these tick once per
/// reload, so the series disappears and comes back FROM 1 instead of resuming.
/// Measured on a live collector: six days up, five-plus reloads in the log, no
/// `reloaded_total` exported at all; one SIGHUP later,
/// `nanosiem_vector_reloaded_total{host="…"} 1`.
///
/// A snapshot taken just before the series ages out therefore holds a number
/// HIGHER than everything that follows it. Comparing with a plain `>` calls
/// that "never acknowledged" and rolls back a config Vector accepted.
#[tokio::test]
async fn a_counter_that_aged_out_and_restarted_is_still_an_acceptance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(1, 0)))
        .mount(&server)
        .await;

    // Snapshot caught the old series at 3; the reload restarted it at 1.
    let before = ReloadCounters {
        reloads: 3.0,
        config_failures: 0.0,
    };
    assert_eq!(probe_for(&server).await_ack(before).await, ReloadAck::Accepted);
}

/// The other half: a series that is alive and unchanged is NOT an
/// acknowledgement. Without this, "any positive value" would accept a stale
/// counter that has not moved since the previous deploy — which is the blind
/// spot this whole gate exists to close.
#[tokio::test]
async fn a_live_unchanged_counter_is_still_not_an_acceptance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(3, 0)))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 3.0,
        config_failures: 0.0,
    };
    assert_eq!(
        probe_for(&server).await_ack(before).await,
        ReloadAck::NotAcknowledged
    );
}

/// The counters are only *exported* when `internal_metrics` next scrapes (10s
/// in 92-metrics.toml), so the acknowledgement routinely arrives several polls
/// late. Giving up on the first unchanged read would report a rollback-worthy
/// failure for a reload that succeeded.
#[tokio::test]
async fn acknowledgement_is_awaited_across_scrape_lag() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(4, 0)))
        .up_to_n_times(3)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(200).set_body_string(metrics_body(5, 0)))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 4.0,
        config_failures: 0.0,
    };
    assert_eq!(probe_for(&server).await_ack(before).await, ReloadAck::Accepted);
}

/// An endpoint that stops answering mid-window (Vector died applying the
/// config) is not an acceptance either.
#[tokio::test]
async fn an_endpoint_that_stops_answering_is_not_an_acceptance() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/metrics"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let before = ReloadCounters {
        reloads: 4.0,
        config_failures: 0.0,
    };
    assert_eq!(
        probe_for(&server).await_ack(before).await,
        ReloadAck::NotAcknowledged
    );
}

/// A pre-reload snapshot is the baseline the whole comparison rests on, so an
/// endpoint that cannot be reached has to report "no evidence" rather than hand
/// back zeroes. Zeroes would be worse than useless: a baseline of 0/0 against a
/// Vector we cannot see turns every deploy into `NotAcknowledged`, i.e. into a
/// rollback of a config that was probably fine.
#[tokio::test]
async fn an_unreachable_endpoint_reads_as_no_evidence() {
    // Port 1 is reserved and never listening — a deterministic connect refusal,
    // unlike a shut-down mock server, which answers 404 for a moment first.
    let probe = probe_at("http://127.0.0.1:1/metrics".to_string());
    assert!(probe.read().await.is_none());
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// THE regression this issue exists for. `reload_vector` used to fall out of
/// the bottom with `Ok(())` after every explicit method failed, on the theory
/// that `--watch-config` would cover it. Nothing was sent, nothing was
/// observed, and the deploy was recorded live — which is why the rollback
/// branch in log-source deploy was unreachable in practice.
#[test]
fn nothing_delivered_and_nothing_observed_is_a_failure() {
    let outcome = reload_outcome(None, ReloadAck::Unverifiable);
    let err = outcome.expect_err("a reload with no delivery and no evidence must not report success");
    assert!(
        matches!(err, VectorConfigError::ReloadFailed(_)),
        "expected ReloadFailed, got {err:?}"
    );
}

/// Vector saying "no" has to reach the caller, or the rollback it triggers
/// never runs.
#[test]
fn a_rejected_config_is_a_failure() {
    assert!(reload_outcome(Some("docker exec SIGHUP"), ReloadAck::Rejected).is_err());
}

/// "The signal went out and nothing happened" is a failure too — the config on
/// disk is not the config being run.
#[test]
fn an_unacknowledged_reload_is_a_failure() {
    assert!(reload_outcome(Some("local SIGHUP"), ReloadAck::NotAcknowledged).is_err());
}

/// The open-edition compose topology delivers no explicit signal at all (the
/// api image has no docker CLI); Vector reloads from its own config watcher.
/// The acknowledgement is the proof there, and it must stand on its own.
#[test]
fn a_watcher_driven_reload_that_is_acknowledged_succeeds() {
    assert!(reload_outcome(None, ReloadAck::Accepted).is_ok());
}

/// The one best-effort case that survives: a SIGHUP demonstrably reached Vector
/// but its metrics endpoint is unreadable. Failing here would roll back working
/// deploys on every host that cannot reach the metrics port, so it stays a
/// success — the warning is the mitigation, not the verdict.
#[test]
fn a_delivered_but_unverifiable_reload_still_succeeds() {
    assert!(reload_outcome(Some("docker exec SIGHUP"), ReloadAck::Unverifiable).is_ok());
}

/// The kill switch has to actually switch the gate off, including in the case
/// the gate was added for — otherwise an operator who hits an unforeseen
/// topology has no way to keep deploying.
#[test]
fn the_kill_switch_restores_best_effort_behaviour() {
    assert!(reload_outcome(None, ReloadAck::VerificationDisabled).is_ok());
}

/// `VECTOR_RELOAD_ACK_TIMEOUT_SECS=0` is the documented off switch, and it is
/// the only value that disables the gate — a missing or malformed setting must
/// leave verification ON, since silently degrading to best-effort is the
/// behaviour being removed.
#[test]
fn only_an_explicit_zero_disables_verification() {
    // Serialized against the other env-reading test in this file; the vars are
    // process-global.
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let restore = EnvRestore::capture(&["VECTOR_RELOAD_ACK_TIMEOUT_SECS", "VECTOR_METRICS_URL"]);

    std::env::set_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS", "0");
    assert!(
        ReloadAckProbe::from_env().is_none(),
        "0 must disable acceptance checking"
    );

    std::env::set_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS", "not-a-number");
    let probe = ReloadAckProbe::from_env().expect("a malformed timeout must not disable the gate");
    assert_eq!(
        probe.timeout,
        std::time::Duration::from_secs(DEFAULT_RELOAD_ACK_TIMEOUT_SECS)
    );

    std::env::remove_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS");
    let probe = ReloadAckProbe::from_env().expect("verification is on by default");
    assert_eq!(
        probe.timeout,
        std::time::Duration::from_secs(DEFAULT_RELOAD_ACK_TIMEOUT_SECS)
    );

    drop(restore);
}

/// The default endpoint has to be the one the shipped topologies actually
/// serve: `vector` is the compose service name in all three compose files and
/// 9598 is the `prometheus_exporter` address in 92-metrics.toml. A wrong
/// default is not a cosmetic mistake here — it makes every deploy unverifiable.
#[test]
fn the_default_metrics_url_matches_the_shipped_exporter() {
    let _guard = env_lock().lock().unwrap_or_else(|e| e.into_inner());
    let restore = EnvRestore::capture(&["VECTOR_RELOAD_ACK_TIMEOUT_SECS", "VECTOR_METRICS_URL"]);

    std::env::remove_var("VECTOR_METRICS_URL");
    std::env::remove_var("VECTOR_RELOAD_ACK_TIMEOUT_SECS");
    let probe = ReloadAckProbe::from_env().expect("probe");
    assert_eq!(probe.url, "http://vector:9598/metrics");

    std::env::set_var("VECTOR_METRICS_URL", "http://elsewhere:1234/m");
    let probe = ReloadAckProbe::from_env().expect("probe");
    assert_eq!(probe.url, "http://elsewhere:1234/m");

    drop(restore);
}

fn env_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// Puts the captured vars back exactly as they were, including "was not set".
struct EnvRestore(Vec<(String, Option<String>)>);

impl EnvRestore {
    fn capture(keys: &[&str]) -> Self {
        Self(
            keys.iter()
                .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                .collect(),
        )
    }
}

impl Drop for EnvRestore {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
