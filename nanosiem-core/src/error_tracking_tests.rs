// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5798: error tracking stays inert without a DSN, scrubs what it sends,
//! and caps volume per issue and per process.

use super::*;
use sentry::protocol::{Context, Exception, LogEntry, Value};
use std::collections::HashMap as Map;
use tracing_subscriber::layer::SubscriberExt;

// A syntactically valid DSN for a host that does not exist. Tests that build
// a client use a capturing transport, so nothing is ever sent.
const FAKE_DSN: &str = "https://public@example.invalid/1";

fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: Map<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    move |k| map.get(k).cloned()
}

fn settings(pairs: &[(&str, &str)]) -> Settings {
    let mut all = vec![("NANO_SENTRY_DSN", FAKE_DSN)];
    all.extend_from_slice(pairs);
    Settings::from_lookup("nanosiem-test", lookup(&all)).expect("dsn set")
}

fn message_event(message: &str) -> Event<'static> {
    Event {
        message: Some(message.to_string()),
        logger: Some("nanosiem_core::jobs".into()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------- no DSN

#[test]
fn no_dsn_initializes_nothing() {
    for env in [
        vec![],
        vec![("NANO_SENTRY_DSN", "   ")],
        vec![("NANO_SENTRY_ENVIRONMENT", "e2e"), ("NANO_E2E_RUN_ID", "r1"), ("NANO_SENTRY_TEST_TRIGGER", "1")],
    ] {
        assert!(Settings::from_lookup("svc", lookup(&env)).is_none(), "{env:?}");
        assert!(init_from_lookup("svc", lookup(&env)).is_none(), "{env:?}");
    }
    // Nothing was bound: no client, so no transport and no network.
    assert!(sentry::Hub::main().client().is_none());
    // And flushing without a client is a no-op.
    flush(Duration::from_millis(1));
}

#[test]
fn an_unparseable_dsn_initializes_nothing() {
    let s = Settings::from_lookup("svc", lookup(&[("NANO_SENTRY_DSN", "not a dsn")])).unwrap();
    assert!(client_options(&s, Arc::new(Arc::new(CaptureTransport::default()))).is_none());
    assert!(init(s).is_none());
    assert!(sentry::Hub::main().client().is_none());
}

// ---------------------------------------------------------------- settings

#[test]
fn generic_sentry_env_vars_are_never_read() {
    // Customers set these namespace-wide for their own apps.
    let generic = [
        ("SENTRY_DSN", FAKE_DSN),
        ("SENTRY_ENVIRONMENT", "customer-prod"),
        ("SENTRY_RELEASE", "customer-app@9"),
    ];
    assert!(Settings::from_lookup("svc", lookup(&generic)).is_none());
    assert!(init_from_lookup("svc", lookup(&generic)).is_none());
    assert!(sentry::Hub::main().client().is_none());

    let mut with_nano = generic.to_vec();
    with_nano.push(("NANO_SENTRY_DSN", "https://nano@example.invalid/2"));
    let s = Settings::from_lookup("svc", lookup(&with_nano)).unwrap();
    assert_eq!(s.dsn, "https://nano@example.invalid/2");
    assert_eq!(s.environment, "local");
    assert!(s.release.starts_with("nano@"));
    // The options handed to the SDK carry all three explicitly, so its own
    // env defaults never fill them in.
    let opts = client_options(&s, Arc::new(Arc::new(CaptureTransport::default()))).unwrap();
    let dsn = opts.dsn.as_ref().unwrap();
    assert_eq!((dsn.public_key(), dsn.host()), ("nano", "example.invalid"));
    assert_eq!(opts.environment.as_deref(), Some("local"));
    assert!(opts.release.as_deref().unwrap().starts_with("nano@"));
}

#[test]
fn the_real_process_env_has_no_dsn_in_tests() {
    // `init_from_env` reads only NANO_SENTRY_DSN, even if the developer's
    // shell exports SENTRY_DSN.
    if std::env::var("NANO_SENTRY_DSN").map(|v| v.trim().is_empty()).unwrap_or(true) {
        assert!(init_from_env("svc").is_none());
        assert!(sentry::Hub::main().client().is_none());
    }
}

#[test]
fn defaults_and_tags() {
    let s = settings(&[]);
    assert_eq!(s.environment, "local");
    assert_eq!(s.release, format!("nano@{}", env!("CARGO_PKG_VERSION")));
    assert_eq!(s.traces_sample_rate, 1.0, "local samples every trace");
    assert_eq!(s.log_level, Some(tracing::Level::WARN));
    assert_eq!((s.max_events_per_issue, s.max_events), (5, 100));
    assert!(!s.test_trigger);

    let s = settings(&[
        ("NANO_SENTRY_ENVIRONMENT", "e2e"),
        ("NANO_SENTRY_RELEASE", "0123abcd"),
        ("NANO_E2E_RUN_ID", "20261121-abc"),
        ("NANO_E2E_TEST_NAME", "tests/test_base.py::test_x"),
    ]);
    assert_eq!((s.environment.as_str(), s.release.as_str()), ("e2e", "0123abcd"));
    assert_eq!(s.run_id.as_deref(), Some("20261121-abc"));
    assert_eq!(s.test_name.as_deref(), Some("tests/test_base.py::test_x"));
    assert_eq!(s.traces_sample_rate, 1.0);
}

#[test]
fn trace_rate_is_low_outside_local_and_e2e_and_overridable() {
    assert_eq!(settings(&[("NANO_SENTRY_ENVIRONMENT", "path")]).traces_sample_rate, 0.1);
    assert_eq!(settings(&[("NANO_SENTRY_TRACES_SAMPLE_RATE", "0")]).traces_sample_rate, 0.0);
    assert_eq!(settings(&[("NANO_SENTRY_TRACES_SAMPLE_RATE", "7")]).traces_sample_rate, 1.0);
    assert_eq!(settings(&[("NANO_SENTRY_TRACES_SAMPLE_RATE", "NaN")]).traces_sample_rate, 1.0);
    assert_eq!(settings(&[("NANO_SENTRY_LOG_LEVEL", "off")]).log_level, None);
    assert_eq!(settings(&[("NANO_SENTRY_LOG_LEVEL", "INFO")]).log_level, Some(tracing::Level::INFO));
}

#[test]
fn names_are_sanitized_and_caps_bounded() {
    let s = settings(&[
        ("NANO_SENTRY_ENVIRONMENT", "my env/x\n"),
        ("NANO_SENTRY_RELEASE", ".."),
        ("NANO_SENTRY_MAX_EVENTS", "0"),
        ("NANO_SENTRY_MAX_EVENTS_PER_ISSUE", "999999"),
    ]);
    assert_eq!(s.environment, "my-env-x");
    assert!(s.release.starts_with("nano@"));
    assert_eq!((s.max_events, s.max_events_per_issue), (1, 10_000));
}

#[test]
fn test_trigger_is_debug_only() {
    let s = settings(&[("NANO_SENTRY_TEST_TRIGGER", "1")]);
    assert_eq!(s.test_trigger, cfg!(debug_assertions));
    assert!(!settings(&[("NANO_SENTRY_TEST_TRIGGER", "true")]).test_trigger);
    assert!(test_error_message("api").starts_with("Sentry test error api "));
}

// ---------------------------------------------------------------- scrubbing

#[test]
fn hashed_user_ids_are_stable_and_opaque() {
    assert_eq!(hashed_user_id("42"), hashed_user_id("42"));
    assert_ne!(hashed_user_id("42"), hashed_user_id("43"));
    assert_eq!(hashed_user_id("42").len(), 16);
    assert!(!hashed_user_id("analyst@example.com").contains("analyst"));
}

// ---------------------------------------------------------------- gate

#[test]
fn benign_errors_are_dropped() {
    let gate = EventGate::new(&settings(&[("NANO_SENTRY_IGNORE", "flaky upstream, other")]));
    assert!(gate.process(message_event("write failed: Broken pipe (os error 32)")).is_none());
    let mut exc = Event::default();
    exc.exception.values.push(Exception {
        ty: "io::Error".into(),
        value: Some("Connection reset by peer (os error 54)".into()),
        ..Default::default()
    });
    assert!(gate.process(exc).is_none());
    assert!(gate.process(message_event("flaky upstream timed out")).is_none());
    assert!(gate.process(message_event("detection run failed")).is_some());
}

#[test]
fn nothing_but_panics_is_sent_once_shutdown_starts() {
    static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let gate = EventGate::new(&settings(&[])).with_shutdown_clock(&STARTED, Duration::from_secs(60));
    assert!(gate.process(message_event("rule execution failed before shutdown")).is_some());

    STARTED.set(std::time::Instant::now()).unwrap();
    assert!(gate.process(message_event("Error reading ClickHouse response chunk")).is_none());
    let mut panic = Event::default();
    panic.exception.values.push(Exception {
        ty: "panic".into(),
        value: Some("worker panicked during drain".into()),
        mechanism: Some(sentry::protocol::Mechanism { ty: "panic".into(), ..Default::default() }),
        ..Default::default()
    });
    assert!(gate.process(panic).is_some(), "panics are still real bugs during shutdown");
}

#[test]
fn a_hung_shutdown_reports_again_after_the_quiet_window() {
    // A zero-length window: shutdown already outlasted it (no dependence on
    // machine uptime).
    static STARTED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    STARTED.set(std::time::Instant::now()).unwrap();
    let gate = EventGate::new(&settings(&[])).with_shutdown_clock(&STARTED, Duration::ZERO);
    assert!(gate.process(message_event("release claims still stuck")).is_some());
}

#[test]
fn the_quiet_window_is_bounded() {
    let now = std::time::Instant::now();
    let window = Duration::from_secs(60);
    assert!(!in_quiet_window(None, window, now));
    assert!(in_quiet_window(Some(&now), window, now + Duration::from_secs(59)));
    assert!(!in_quiet_window(Some(&now), window, now + Duration::from_secs(60)));
}

#[test]
fn per_issue_cap_groups_by_normalized_message() {
    let gate = EventGate::new(&settings(&[]));
    let sent = (0..20)
        .filter(|i| gate.process(message_event(&format!("job {i} failed for 0198f7a2-1c3e-7d4b-9a10-3b5c7e9f0a12"))).is_some())
        .count();
    assert_eq!(sent, 5, "same issue, numbers and ids normalized");
    assert!(gate.process(message_event("a different failure")).is_some());
}

#[test]
fn global_cap_bounds_the_process() {
    let gate = EventGate::new(&settings(&[("NANO_SENTRY_MAX_EVENTS", "3")]));
    let sent = (0..10).filter(|i| gate.process(message_event(&format!("distinct-{}", "x".repeat(*i)))).is_some()).count();
    assert_eq!(sent, 3);
}

#[test]
fn exceptions_key_on_type_and_value() {
    let exc = |ty: &str, value: &str| {
        let mut e = Event::default();
        e.exception.values.push(Exception { ty: ty.into(), value: Some(value.into()), ..Default::default() });
        e
    };
    assert_eq!(issue_key(&exc("Panic", "index 3 out of range")), issue_key(&exc("Panic", "index 9 out of range")));
    assert_ne!(issue_key(&exc("Panic", "boom")), issue_key(&exc("Other", "boom")));
    let mut with_entry = Event::default();
    with_entry.logentry = Some(LogEntry { message: "x 1".into(), params: vec![] });
    assert_eq!(issue_key(&with_entry), {
        let mut e = Event::default();
        e.logentry = Some(LogEntry { message: "x 2".into(), params: vec![] });
        issue_key(&e)
    });
}

#[test]
fn events_are_tagged_with_run_and_current_test() {
    let dir = std::env::temp_dir().join(format!("nan5798-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("current-test");
    std::fs::write(&file, "tests/ui/test_search.py::test_tail\n").unwrap();
    let gate = EventGate::new(&settings(&[
        ("NANO_E2E_RUN_ID", "run-7"),
        ("NANO_E2E_TEST_NAME", "fallback"),
        ("NANO_E2E_CURRENT_TEST_FILE", file.to_str().unwrap()),
    ]));
    let e = gate.process(message_event("boom")).unwrap();
    assert_eq!(e.tags["run_id"], "run-7");
    assert_eq!(e.tags["service"], "nanosiem-test");
    assert_eq!(e.tags["test"], "tests/ui/test_search.py::test_tail");
    std::fs::write(&file, "").unwrap();
    assert_eq!(gate.process(message_event("boom two")).unwrap().tags["test"], "fallback");
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------- end to end

#[derive(Default)]
struct CaptureTransport(Mutex<Vec<Envelope>>);

impl Transport for CaptureTransport {
    fn send_envelope(&self, envelope: Envelope) {
        self.0.lock().unwrap().push(envelope);
    }
}

/// Run `f` with a client built exactly as production builds it, sending to a
/// capturing transport, and the tracing layer installed. Returns the events.
fn capture(s: &Settings, f: impl FnOnce()) -> Vec<Event<'static>> {
    capture_with(s, false, None, f)
}

fn capture_with(
    s: &Settings,
    traces: bool,
    logs: Option<tracing::Level>,
    f: impl FnOnce(),
) -> Vec<Event<'static>> {
    capture_envelopes(s, traces, logs, f).iter().filter_map(|e| e.event().cloned()).collect()
}

/// Every envelope the production client would send (events, transactions,
/// logs), through the production gate and transport wrapper.
fn capture_envelopes(
    s: &Settings,
    traces: bool,
    logs: Option<tracing::Level>,
    f: impl FnOnce(),
) -> Vec<Envelope> {
    let transport = Arc::new(CaptureTransport::default());
    let mut options = client_options(s, Arc::new(transport.clone())).unwrap();
    // No global panic hook in tests; the stack integrations production gets.
    options.default_integrations = false;
    options.integrations.push(Arc::new(sentry::integrations::backtrace::AttachStacktraceIntegration));
    options.integrations.push(Arc::new(sentry::integrations::backtrace::ProcessStacktraceIntegration));
    let client = Arc::new(sentry::Client::from(options));
    let hub = Arc::new(sentry::Hub::new(Some(client.clone()), Arc::new(Default::default())));
    sentry::Hub::run(hub, || {
        let subscriber = tracing_subscriber::registry().with(tracing_layer(traces, logs));
        tracing::subscriber::with_default(subscriber, f);
    });
    client.flush(Some(Duration::from_secs(1)));
    let envelopes = std::mem::take(&mut *transport.0.lock().unwrap());
    envelopes
}

fn envelope_text(envelopes: &[Envelope]) -> String {
    envelopes
        .iter()
        .map(|e| {
            let mut buf = Vec::new();
            e.to_writer(&mut buf).unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn spans_keep_names_and_fields_but_lose_secrets() {
    // A root span becomes a transaction whose `trace` context carries the
    // span's fields; a child span carries its own data.
    let s = settings(&[]);
    let env = capture_envelopes(&s, true, None, || {
        let root = tracing::info_span!(
            "search",
            query = "user=alice | stats count by src_ip",
            api_key = "sk-live-123",
            url = "/api/search?q=alice&token=tok-456",
            status = 200u64,
        );
        let _r = root.enter();
        let child = tracing::info_span!("execute", host = "dc01.corp.example", password = "hunter2");
        let _c = child.enter();
        tracing::info!("not an event");
    });
    let text = envelope_text(&env);
    assert!(text.contains("\"transaction\""), "expected a transaction: {text}");
    for kept in ["search", "execute", "user=alice | stats count by src_ip", "dc01.corp.example", "/api/search?q=alice&token="] {
        assert!(text.contains(kept), "{kept:?} should be kept: {text}");
    }
    for secret in ["sk-live-123", "tok-456", "hunter2"] {
        assert!(!text.contains(secret), "{secret:?} leaked: {text}");
    }
}

#[test]
fn errors_logs_and_breadcrumbs_keep_text_but_lose_secrets() {
    let s = settings(&[]);
    let env = capture_envelopes(&s, false, Some(tracing::Level::WARN), || {
        tracing::warn!(user = "alice", "login throttled for 10.20.30.40, Authorization: Bearer abcdefghijklmnop");
        tracing::error!(
            token = "nit_ABCDEFGHIJ0123456789",
            "search failed for alice: Code: 27. DB::Exception: Cannot parse 'dc01' (CANNOT_PARSE_INPUT_ASSERTION_FAILED), password=hunter2"
        );
    });
    let text = envelope_text(&env);
    for kept in ["search failed for alice: Code: 27. DB::Exception: Cannot parse 'dc01'", "login throttled for 10.20.30.40", "alice"] {
        assert!(text.contains(kept), "{kept:?} should be kept: {text}");
    }
    for secret in ["abcdefghijklmnop", "nit_ABCDEFGHIJ", "hunter2"] {
        assert!(!text.contains(secret), "{secret:?} leaked: {text}");
    }
    let events: Vec<_> = env.iter().filter_map(|e| e.event()).collect();
    assert_eq!(events.len(), 1);
}

#[test]
fn logs_are_capped_and_tagged() {
    let gate = EventGate::new(&settings(&[("NANO_SENTRY_MAX_LOGS", "2"), ("NANO_E2E_RUN_ID", "run-9")]));
    let log = |body: &str| Log {
        level: sentry::protocol::LogLevel::Warn,
        body: body.into(),
        trace_id: None,
        timestamp: std::time::SystemTime::now(),
        severity_number: None,
        attributes: [("query".to_string(), Value::from("select 1").into()), ("api_key".to_string(), Value::from("sk-1").into())].into_iter().collect(),
    };
    let out = gate.process_log(log("first")).unwrap();
    assert_eq!(out.attributes["query"].0, Value::from("select 1"));
    assert_eq!(out.attributes["api_key"].0, Value::from(FILTERED));
    assert_eq!(out.attributes["run_id"].0, Value::from("run-9"));
    assert!(gate.process_log(log("second")).is_some());
    assert!(gate.process_log(log("third")).is_none(), "cap of 2");
}

#[test]
fn transactions_are_capped_in_the_transport() {
    let gate = EventGate::new(&settings(&[("NANO_SENTRY_MAX_TRANSACTIONS", "1")]));
    let mut envelope = Envelope::new();
    envelope.add_item(EnvelopeItem::Transaction(Box::new(Transaction::default())));
    assert!(ScrubbingTransport::gate_envelope(&gate, envelope).is_some());
    let mut again = Envelope::new();
    again.add_item(EnvelopeItem::Transaction(Box::new(Transaction::default())));
    assert!(ScrubbingTransport::gate_envelope(&gate, again).is_none(), "cap of 1, nothing left to send");
    let mut events = Envelope::new();
    events.add_item(EnvelopeItem::Event(Box::new(message_event("x"))));
    assert_eq!(ScrubbingTransport::gate_envelope(&gate, events).unwrap().items().count(), 1);
}

#[test]
fn error_events_are_sent_warnings_become_breadcrumbs() {
    let s = settings(&[("NANO_E2E_RUN_ID", "run-e2e")]);
    let events = capture(&s, || {
        tracing::info!("ignored");
        tracing::warn!("cache miss storm");
        tracing::error!(password = "hunter2", "detection run failed for rule 12");
        // The supervision panic event is a breadcrumb: the panic integration
        // reports the panic itself.
        tracing::error!(target: "nanosiem_core::process_supervision", panic = "boom", "panic");
        for i in 0..10 {
            tracing::error!("job {i} failed");
        }
    });
    // 1 detection error + 5 of the 10 job errors (per-issue cap); the
    // panic event is a breadcrumb.
    let messages: Vec<String> = events.iter().filter_map(|e| e.message.clone()).collect();
    assert_eq!(messages.iter().filter(|m| m.starts_with("detection run failed for rule 12")).count(), 1);
    assert_eq!(messages.iter().filter(|m| m.starts_with("job ")).count(), 5, "per-issue cap");
    assert!(!messages.iter().any(|m| m == "panic" || m == "ignored" || m == "cache miss storm"));
    let first = events.iter().find(|e| e.message.as_deref().is_some_and(|m| m.starts_with("detection"))).unwrap();
    assert_eq!(first.tags["run_id"], "run-e2e");
    assert_eq!(first.environment.as_deref(), Some("local"));
    assert!(first.breadcrumbs.values.iter().any(|b| b.message.as_deref() == Some("cache miss storm")));
    match first.contexts.get("Rust Tracing Location") {
        Some(Context::Other(loc)) => assert!(loc.contains_key("file"), "{loc:?}"),
        other => panic!("location lost: {other:?}"),
    }
    assert!(!serde_json::to_string(first).unwrap().contains("hunter2"));
    // A stack is attached (trial 1 got bare messages), frames carry no locals.
    let stack = first.threads.values.iter().find_map(|t| t.stacktrace.as_ref()).expect("attached stacktrace");
    assert!(!stack.frames.is_empty());
    assert!(stack.frames.iter().all(|f| f.vars.is_empty() && f.context_line.is_none()));
}

#[test]
fn every_layer_combination_still_sends_errors() {
    // Regression: an absent optional layer once disabled its siblings.
    for (traces, logs) in [(false, None), (true, None), (false, Some(tracing::Level::WARN)), (true, Some(tracing::Level::INFO))] {
        let events = capture_with(&settings(&[]), traces, logs, || tracing::error!("combo failure"));
        assert_eq!(events.len(), 1, "traces={traces} logs={logs:?}");
    }
}

#[test]
fn without_a_dsn_the_off_layer_leaves_logging_untouched() {
    // init_tracing's stack with error tracking off: every other layer still
    // sees INFO and above (a `None` Option layer would have reported OFF).
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Count(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> Layer<S> for Count {
        fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let seen = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry()
        .with(Count(seen.clone()))
        .with(crate::telemetry::sentry_layer(&None))
        .with(tracing_subscriber::EnvFilter::new("info"));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("info line");
        tracing::warn!("warn line");
        tracing::debug!("filtered out");
    });
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    assert!(sentry::Hub::main().client().is_none());
}

// ---------------------------------------------------------------- grouping (NAN-5837)

fn fingerprint(event: &Event<'_>) -> Vec<String> {
    event.fingerprint.iter().map(|p| p.to_string()).collect()
}

#[test]
fn distinct_error_sites_get_distinct_fingerprints() {
    // NANO-SERVER-7: every ERROR grouped on the shared worker-thread stack.
    let s = settings(&[]);
    let events = capture(&s, || {
        for (rule, id) in [("lookup ui a1", "669c26eb-0d5d-43ea-a04e-dfa88c8a7ffd"), ("brute force b2", "11111111-2222-3333-4444-555555555555")] {
            tracing::error!(rule_id = id, "Scheduled rule '{rule}' has no schedule_cron, it will never run");
        }
        tracing::error!(target: "nanosiem_api_lib::api_error", status = 503u64, "request failed with a server error");
        tracing::error!(error = "Unknown eval function 'nosuchfn'", "Streaming chunk SQL generation failed");
    });
    assert_eq!(events.len(), 4, "{events:?}");
    let fps: Vec<Vec<String>> = events.iter().map(fingerprint).collect();
    for fp in &fps {
        assert_eq!(fp.len(), 3, "{fp:?}");
        assert_eq!(fp[0], TRACING_FINGERPRINT_PREFIX);
        assert!(fp[2].starts_with("nanosiem-core/src/error_tracking_tests.rs:"), "{fp:?}");
        // Nothing interpolated: no rule names, ids or messages.
        let joined = fp.join(" ");
        for value in ["lookup ui", "brute force", "669c26eb", "11111111", "nosuchfn", "Scheduled rule", "503"] {
            assert!(!joined.contains(value), "{value:?} in fingerprint {fp:?}");
        }
    }
    // Same call site, different values: one issue.
    assert_eq!(fps[0], fps[1]);
    // Three distinct sites: three issues.
    assert_ne!(fps[0], fps[2]);
    assert_ne!(fps[0], fps[3]);
    assert_ne!(fps[2], fps[3]);
    assert_eq!(fps[2][1], "nanosiem_api_lib::api_error", "logger is the target");
    // Sentry still titles the issue from the message.
    assert!(events[0].message.as_deref().unwrap().contains("lookup ui a1"));
}

#[test]
fn per_issue_cap_counts_per_call_site() {
    // One site interpolating many names is one Sentry issue: capped at 5,
    // not 5 per name.
    let s = settings(&[]);
    let events = capture(&s, || {
        for name in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta"] {
            tracing::error!("rule '{name}' has no schedule");
        }
        tracing::error!("relay unreachable");
    });
    assert_eq!(events.iter().filter(|e| e.message.as_deref().unwrap().starts_with("rule ")).count(), 5);
    assert_eq!(events.iter().filter(|e| e.message.as_deref() == Some("relay unreachable")).count(), 1);
}

#[test]
fn fingerprint_survives_the_wire_and_the_scrubber() {
    let s = settings(&[]);
    let env = capture_envelopes(&s, false, None, || {
        tracing::error!(password = "hunter2", "login failed");
    });
    let text = envelope_text(&env);
    assert!(text.contains("\"fingerprint\":[\"nano-tracing\""), "{text}");
    assert!(!text.contains("hunter2"));
}

fn located_event(file: &str, line: u64) -> Event<'static> {
    let mut event = message_event("boom");
    let location: BTreeMap<String, Value> =
        [("file".to_string(), Value::from(file)), ("line".to_string(), Value::from(line))].into_iter().collect();
    event.contexts.insert(TRACING_LOCATION_CONTEXT.into(), Context::Other(location));
    event
}

#[test]
fn panics_and_custom_fingerprints_keep_their_grouping() {
    // The panic integration's event has no tracing call site.
    let mut panic = Event {
        exception: vec![Exception {
            ty: "panic".into(),
            value: Some("index 3 out of range".into()),
            mechanism: Some(sentry::protocol::Mechanism { ty: "panic".into(), ..Default::default() }),
            ..Default::default()
        }]
        .into(),
        ..Default::default()
    };
    apply_tracing_fingerprint(&mut panic);
    assert_eq!(fingerprint(&panic), ["{{ default }}"]);

    // A panic exception is never re-grouped, even with a call site.
    let mut located_panic = located_event("nanosiem-core/src/x.rs", 7);
    located_panic.exception = panic.exception.clone();
    apply_tracing_fingerprint(&mut located_panic);
    assert_eq!(fingerprint(&located_panic), ["{{ default }}"]);

    let mut custom = located_event("nanosiem-core/src/x.rs", 7);
    custom.fingerprint = Cow::Owned(vec![Cow::Borrowed("mine")]);
    apply_tracing_fingerprint(&mut custom);
    assert_eq!(fingerprint(&custom), ["mine"]);

    let mut plain = located_event("nanosiem-core/src/x.rs", 7);
    apply_tracing_fingerprint(&mut plain);
    assert_eq!(fingerprint(&plain), ["nano-tracing", "nanosiem_core::jobs", "nanosiem-core/src/x.rs:7"]);
}

#[test]
fn dependency_call_sites_ignore_the_builders_cargo_home() {
    let a = "/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tower-http-0.7.1/src/trace/on_failure.rs";
    let b = "/home/runner/.cargo/registry/src/index.crates.io-0000000000000000/tower-http-0.7.1/src/trace/on_failure.rs";
    let mut ea = located_event(a, 93);
    let mut eb = located_event(b, 93);
    apply_tracing_fingerprint(&mut ea);
    apply_tracing_fingerprint(&mut eb);
    assert_eq!(fingerprint(&ea), fingerprint(&eb));
    assert_eq!(fingerprint(&ea)[2], "tower-http-0.7.1/src/trace/on_failure.rs:93");
}

/// Live check against a real Sentry project (never in CI: ignored, and the
/// test environment has no DSN). Sends two distinct error sites plus a repeat
/// of the first with a different value, tagged `run_id=$NANO_E2E_RUN_ID`;
/// Sentry should show exactly two issues for that run. Run with the DSN in
/// the environment (never argv), for example:
/// `doppler run -p nano-platform -c dev -- sh -c 'NANO_SENTRY_DSN="$SENTRY_DSN_BACKEND"
///  NANO_SENTRY_ENVIRONMENT=test NANO_E2E_RUN_ID=<id> cargo test -p nanosiem-core --lib
///  live_distinct_sites_group_separately -- --ignored'`
#[test]
#[ignore = "sends to a real Sentry project; needs NANO_SENTRY_DSN"]
fn live_distinct_sites_group_separately() {
    let Some(tracking) = init_from_env("nanosiem-grouping-check") else {
        panic!("NANO_SENTRY_DSN not set");
    };
    let run = std::env::var("NANO_E2E_RUN_ID").unwrap_or_default();
    let subscriber = tracing_subscriber::registry().with(tracking.tracing_layer());
    tracing::subscriber::with_default(subscriber, || {
        for rule in ["alpha", "beta"] {
            tracing::error!(rule, "grouping check {run}: rule '{rule}' has no schedule");
        }
        tracing::error!("grouping check {run}: relay unreachable");
    });
    flush(Duration::from_secs(10));
    drop(tracking);
}
