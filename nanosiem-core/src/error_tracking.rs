// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in error tracking (Sentry) for local and e2e stacks (NAN-5798).
//!
//! Nothing here runs unless `NANO_SENTRY_DSN` is set. Without it,
//! [`init_from_env`] returns `None` before touching the SDK: no client, no
//! transport thread, no tracing layer, no network calls. nano ships no DSN in
//! any config, chart or compose file, so customer installs send nothing.
//!
//! The generic `SENTRY_DSN`, `SENTRY_ENVIRONMENT` and `SENTRY_RELEASE` are
//! never read: customers often set them namespace-wide for their own apps.
//! The SDK's own env defaults (`sentry::apply_defaults`) are never applied
//! either: `sentry::init` only ever sees options with the DSN, release and
//! environment already set from the `NANO_*` variables.
//!
//! With a DSN:
//! - ERROR-level tracing events become Sentry events, WARN-level events become
//!   breadcrumbs, and panics are captured by the panic integration.
//! - Tracing events at `NANO_SENTRY_LOG_LEVEL` and above (default `warn`) are
//!   also sent as Sentry logs.
//! - Spans are sent as traces at `NANO_SENTRY_TRACES_SAMPLE_RATE` (default 1.0
//!   for the `local` and `e2e` environments, 0.1 otherwise).
//! - Every event passes [`EventGate::process`] before it leaves the process:
//!   known-benign errors are dropped, secrets and PII are scrubbed, and a
//!   per-issue plus a global per-process cap stop a hot loop from using up the
//!   quota. Logs and transactions are scrubbed and capped the same way (logs
//!   in `before_send_log`, transactions in [`ScrubbingTransport`], since the
//!   SDK has no `before_send_transaction`).
//! - Each tracing ERROR event is fingerprinted by its call site (logger plus
//!   `file:line`, see [`apply_tracing_fingerprint`]) so every distinct error
//!   site is its own Sentry issue; panics keep stack-based grouping.
//!
//! Environment:
//! - `NANO_SENTRY_DSN`: the DSN (the only switch)
//! - `NANO_SENTRY_ENVIRONMENT`: `local` (default), `e2e`, `path`, ...
//! - `NANO_SENTRY_RELEASE`: release name (default `nano@<crate version>`);
//!   the e2e harness passes the git SHA
//! - `NANO_E2E_RUN_ID`: tagged as `run_id`
//! - `NANO_E2E_TEST_NAME`: tagged as `test` (static), or
//!   `NANO_E2E_CURRENT_TEST_FILE`: a file holding the running test's name,
//!   read when an event is sent
//! - `NANO_SENTRY_TRACES_SAMPLE_RATE`: 0.0 to 1.0 (0 turns tracing off)
//! - `NANO_SENTRY_LOG_LEVEL`: `error`, `warn` (default), `info` or `off`
//! - `NANO_SENTRY_MAX_EVENTS_PER_ISSUE` (default 5), `NANO_SENTRY_MAX_EVENTS`
//!   (default 100), `NANO_SENTRY_MAX_LOGS` (default 2000) and
//!   `NANO_SENTRY_MAX_TRANSACTIONS` (default 2000): the per-process caps
//! - `NANO_SENTRY_IGNORE`: extra comma-separated substrings to drop as benign
//! - `NANO_TRANSIENT_OUTAGE_REPORT_SECS` (default 300): how long a transient
//!   backend outage lasts before a background worker reports it at ERROR
//!   (NAN-5886, see [`crate::transient_outage`])
//!
//! NAN-5886: once the process received SIGTERM / SIGINT
//! ([`mark_shutting_down`]), events are not sent for the graceful-drain
//! window (`NANO_SENTRY_SHUTDOWN_QUIET_SECS`, default 60): backends going away
//! during a planned shutdown is expected. Panics are still sent, and a
//! shutdown still running after the window is hung, so events resume.
//! - `NANO_SENTRY_TEST_TRIGGER=1`: debug builds only, emit one
//!   "Sentry test error" at boot (and the API serves `/api/_sentry-test`).
//!   Compiled out of release builds.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use sentry::protocol::{EnvelopeItem, Event, Log, Transaction, Value};
use sentry::{Envelope, Transport, TransportFactory, TransportOptions};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// The only variable that turns error tracking on.
pub const DSN_VAR: &str = "NANO_SENTRY_DSN";

/// Substrings of errors that are expected noise, never worth an issue.
/// Kept deliberately small; extend per run with `NANO_SENTRY_IGNORE`.
pub const BENIGN_ERRORS: &[&str] = &[
    // A client hung up mid-response.
    "Broken pipe (os error",
    "Connection reset by peer (os error",
];

const DEFAULT_ENVIRONMENT: &str = "local";
const DEFAULT_MAX_EVENTS_PER_ISSUE: u32 = 5;
const DEFAULT_MAX_EVENTS: u32 = 100;
const DEFAULT_MAX_LOGS: u32 = 2_000;
const DEFAULT_MAX_TRANSACTIONS: u32 = 2_000;
/// Environments where every trace is sampled by default.
const FULL_TRACE_ENVIRONMENTS: &[&str] = &["local", "e2e"];
const DEFAULT_TRACES_SAMPLE_RATE: f32 = 0.1;
/// Sentry rejects tag values over 200 characters.
const MAX_TAG_LEN: usize = 200;

/// Settings resolved from the environment. `None` from
/// [`Settings::from_lookup`] means error tracking is off.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub dsn: String,
    pub service: String,
    pub environment: String,
    pub release: String,
    pub run_id: Option<String>,
    pub test_name: Option<String>,
    pub test_name_file: Option<PathBuf>,
    pub traces_sample_rate: f32,
    /// Least severe level sent as a Sentry log; `None` sends no logs.
    pub log_level: Option<tracing::Level>,
    pub max_events_per_issue: u32,
    pub max_events: u32,
    pub max_logs: u32,
    pub max_transactions: u32,
    pub extra_ignores: Vec<String>,
    /// `NANO_SENTRY_TEST_TRIGGER=1` in a debug build. Always false in release.
    pub test_trigger: bool,
}

impl Settings {
    /// Resolve settings through `get` (the process environment in
    /// production, a map in tests). Returns `None` when no DSN is set.
    pub fn from_lookup(service: &str, get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let non_empty = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let dsn = non_empty(DSN_VAR)?;
        let environment = non_empty("NANO_SENTRY_ENVIRONMENT")
            .map(|v| sanitize_name(&v, 64))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_ENVIRONMENT.to_string());
        let release = non_empty("NANO_SENTRY_RELEASE")
            .map(|v| sanitize_name(&v, MAX_TAG_LEN))
            .filter(|v| !v.is_empty() && v != "." && v != "..")
            .unwrap_or_else(|| format!("nano@{}", env!("CARGO_PKG_VERSION")));
        let default_rate = if FULL_TRACE_ENVIRONMENTS.contains(&environment.as_str()) {
            1.0
        } else {
            DEFAULT_TRACES_SAMPLE_RATE
        };
        let traces_sample_rate = non_empty("NANO_SENTRY_TRACES_SAMPLE_RATE")
            .and_then(|v| v.parse::<f32>().ok())
            .filter(|v| v.is_finite())
            .map(|v| v.clamp(0.0, 1.0))
            .unwrap_or(default_rate);
        let log_level = match non_empty("NANO_SENTRY_LOG_LEVEL").map(|v| v.to_ascii_lowercase()).as_deref() {
            Some("off") | Some("none") => None,
            Some("error") => Some(tracing::Level::ERROR),
            Some("info") => Some(tracing::Level::INFO),
            _ => Some(tracing::Level::WARN),
        };
        let cap = |k: &str, default: u32| {
            non_empty(k)
                .and_then(|v| v.parse::<u32>().ok())
                .map(|v| v.clamp(1, 10_000))
                .unwrap_or(default)
        };
        Some(Self {
            dsn,
            service: service.to_string(),
            environment,
            release,
            run_id: non_empty("NANO_E2E_RUN_ID").map(|v| tag_value(&v)),
            test_name: non_empty("NANO_E2E_TEST_NAME").map(|v| tag_value(&v)),
            test_name_file: non_empty("NANO_E2E_CURRENT_TEST_FILE").map(PathBuf::from),
            traces_sample_rate,
            log_level,
            max_events_per_issue: cap("NANO_SENTRY_MAX_EVENTS_PER_ISSUE", DEFAULT_MAX_EVENTS_PER_ISSUE),
            max_events: cap("NANO_SENTRY_MAX_EVENTS", DEFAULT_MAX_EVENTS),
            max_logs: cap("NANO_SENTRY_MAX_LOGS", DEFAULT_MAX_LOGS),
            max_transactions: cap("NANO_SENTRY_MAX_TRANSACTIONS", DEFAULT_MAX_TRANSACTIONS),
            extra_ignores: non_empty("NANO_SENTRY_IGNORE")
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            test_trigger: cfg!(debug_assertions) && non_empty("NANO_SENTRY_TEST_TRIGGER").as_deref() == Some("1"),
        })
    }
}

/// Keeps the Sentry client alive; dropping it flushes pending events.
pub struct ErrorTracking {
    _guard: sentry::ClientInitGuard,
    traces: bool,
    log_level: Option<tracing::Level>,
    test_trigger: bool,
}

impl ErrorTracking {
    /// The tracing layer that feeds Sentry: ERROR events (except the
    /// process-supervision "panic" event, which the panic integration already
    /// captures with a better stack) become events, WARN events become
    /// breadcrumbs, events at the log level become logs. Spans are only
    /// recorded when traces are sampled, and never the process-long root
    /// `service` span (it would hold one transaction open for the whole run).
    pub fn tracing_layer<S>(&self) -> Box<dyn Layer<S> + Send + Sync + 'static>
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
    {
        tracing_layer(self.traces, self.log_level)
    }

    /// Debug builds with `NANO_SENTRY_TEST_TRIGGER=1`: emit one test error so
    /// a trial can see each service reach Sentry. Release builds: never.
    pub fn emit_boot_test_error(&self, service: &str) {
        if cfg!(debug_assertions) && self.test_trigger {
            tracing::error!(service, "{}", test_error_message("boot"));
        }
    }

    pub fn test_trigger_enabled(&self) -> bool {
        cfg!(debug_assertions) && self.test_trigger
    }
}

/// See [`ErrorTracking::tracing_layer`].
pub fn tracing_layer<S>(traces: bool, log_level: Option<tracing::Level>) -> Box<dyn Layer<S> + Send + Sync + 'static>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a> + Send + Sync,
{
    // A Vec, not `Option` layers: a `None` layer reports a max level of OFF,
    // which under per-layer filters disabled every sibling (caught by
    // `error_events_are_sent_warnings_become_breadcrumbs`).
    let mut layers: Vec<Box<dyn Layer<S> + Send + Sync + 'static>> = vec![
        Box::new(
            sentry::integrations::tracing::ErrorLayer::new()
                .with_filter(filter_fn(|m| m.is_event() && is_error_event(m))),
        ),
        Box::new(
            sentry::integrations::tracing::BreadcrumbLayer::new()
                .with_filter(filter_fn(|m| m.is_event() && is_breadcrumb_event(m))),
        ),
    ];
    if traces {
        layers.push(Box::new(sentry::integrations::tracing::SpanLayer::new().with_filter(filter_fn(|m| {
            m.is_span() && m.name() != ROOT_SPAN_NAME && *m.level() <= tracing::Level::INFO
        }))));
    }
    if let Some(least) = log_level {
        layers.push(Box::new(
            sentry::integrations::tracing::LogLayer::new()
                .with_filter(filter_fn(move |m| m.is_event() && *m.level() <= least)),
        ));
    }
    Box::new(layers)
}

/// True only in a debug build, with `NANO_SENTRY_TEST_TRIGGER=1`, after error
/// tracking initialized. Gates the API's `/api/_sentry-test` route.
pub fn test_trigger_requested() -> bool {
    cfg!(debug_assertions)
        && std::env::var("NANO_SENTRY_TEST_TRIGGER").as_deref() == Ok("1")
        && sentry::Hub::main().client().is_some_and(|c| c.is_enabled())
}

/// The root span `telemetry::init_tracing` enters for the process lifetime.
pub const ROOT_SPAN_NAME: &str = "service";

/// `Sentry test error <what> <unix ts>`: the marker the trial searches for.
pub fn test_error_message(what: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("Sentry test error {what} {ts}")
}

fn is_panic_event(m: &tracing::Metadata<'_>) -> bool {
    m.fields().field("panic").is_some() && m.target().starts_with("nanosiem_core::process_supervision")
}

fn is_error_event(m: &tracing::Metadata<'_>) -> bool {
    *m.level() == tracing::Level::ERROR && !is_panic_event(m)
}

fn is_breadcrumb_event(m: &tracing::Metadata<'_>) -> bool {
    *m.level() == tracing::Level::WARN || (*m.level() == tracing::Level::ERROR && is_panic_event(m))
}

/// Initialize from the process environment. `None` (and nothing initialized)
/// when no DSN is set.
pub fn init_from_env(service: &str) -> Option<ErrorTracking> {
    init_from_lookup(service, |k| std::env::var(k).ok())
}

/// [`init_from_env`] over an arbitrary lookup (tests).
pub fn init_from_lookup(service: &str, get: impl Fn(&str) -> Option<String>) -> Option<ErrorTracking> {
    Settings::from_lookup(service, get).and_then(init)
}

/// Client options for `settings`, sending through `transport` wrapped in the
/// transaction gate. `None` when the DSN does not parse.
pub fn client_options(settings: &Settings, transport: Arc<dyn TransportFactory>) -> Option<sentry::ClientOptions> {
    let Ok(dsn) = settings.dsn.parse::<sentry::types::Dsn>() else {
        // Never echo the value: it is a credential.
        eprintln!("error tracking disabled: the Sentry DSN does not parse");
        return None;
    };
    let gate = Arc::new(EventGate::new(settings));
    let log_gate = gate.clone();
    let transport_gate = gate.clone();
    // ClientOptions is non-exhaustive: start from the defaults.
    let mut options = sentry::ClientOptions::default().traces_sample_rate(settings.traces_sample_rate);
    options.dsn = Some(dsn);
    options.release = Some(Cow::Owned(settings.release.clone()));
    options.environment = Some(Cow::Owned(settings.environment.clone()));
    options.server_name = Some(Cow::Owned(settings.service.clone()));
    options.send_default_pii = false;
    // Trial 1: ERROR events arrived as bare messages. Attach the thread's
    // stack (function, file, line only: frames are scrubbed of locals and
    // source lines) so a logged error shows where it came from.
    options.attach_stacktrace = true;
    options.max_breadcrumbs = 50;
    options.before_send = Some(Arc::new(move |event| gate.process(event)));
    options.before_breadcrumb = Some(Arc::new(|mut crumb| {
        scrub_breadcrumb(&mut crumb);
        Some(crumb)
    }));
    #[allow(deprecated)] // still gates the tracing LogLayer capture
    {
        options.enable_logs = settings.log_level.is_some();
    }
    options.before_send_log = Some(Arc::new(move |log| log_gate.process_log(log)));
    options.transport = Some(Arc::new(ScrubbingTransportFactory { gate: transport_gate, inner: transport }));
    Some(options)
}

/// Initialize the Sentry client with `settings`.
pub fn init(settings: Settings) -> Option<ErrorTracking> {
    // NAN-5441: under NANO_EGRESS_PROXY_REQUIRED, no direct egress to Sentry.
    if let Err(error) = crate::egress_proxy::require_env_proxy(&settings.dsn) {
        eprintln!("error tracking disabled: {error}");
        return None;
    }
    let options = client_options(&settings, Arc::new(sentry::transports::DefaultTransportFactory))?;
    let guard = sentry::init(options);
    if !guard.is_enabled() {
        return None;
    }
    Some(ErrorTracking {
        _guard: guard,
        traces: settings.traces_sample_rate > 0.0,
        log_level: settings.log_level,
        test_trigger: settings.test_trigger,
    })
}

/// Flush pending events (before `process::exit`, which skips destructors).
/// A no-op when error tracking is off.
pub fn flush(timeout: Duration) {
    if let Some(client) = sentry::Hub::main().client() {
        client.flush(Some(timeout));
    }
}

// ---------------------------------------------------------------------------
// Gate: benign filter, scrubbing, caps, run tags
// ---------------------------------------------------------------------------

/// NAN-5886: set once a shutdown signal arrived.
static SHUTDOWN_STARTED: OnceLock<Instant> = OnceLock::new();

/// Default graceful-drain window: the 30 s task-shutdown deadline plus slack.
const DEFAULT_SHUTDOWN_QUIET_SECS: u64 = 60;

/// `NANO_SENTRY_SHUTDOWN_QUIET_SECS`, clamped to 1..=600.
fn shutdown_quiet_window() -> Duration {
    static WINDOW: LazyLock<Duration> = LazyLock::new(|| {
        let secs = std::env::var("NANO_SENTRY_SHUTDOWN_QUIET_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|v| v.clamp(1, 600))
            .unwrap_or(DEFAULT_SHUTDOWN_QUIET_SECS);
        Duration::from_secs(secs)
    });
    *WINDOW
}

/// Record that the process is shutting down gracefully: from now on only
/// panics are sent to Sentry. Called by
/// [`crate::shutdown::wait_for_shutdown_signal`]; never cleared.
pub fn mark_shutting_down() {
    let _ = SHUTDOWN_STARTED.set(Instant::now());
}

/// True once [`mark_shutting_down`] ran.
pub fn is_shutting_down() -> bool {
    SHUTDOWN_STARTED.get().is_some()
}

/// True while inside the graceful-drain window after `started`.
fn in_quiet_window(started: Option<&Instant>, window: Duration, now: Instant) -> bool {
    started.is_some_and(|t| now.saturating_duration_since(*t) < window)
}

/// A panic captured by the panic integration (mechanism `panic`).
fn is_panic_capture(event: &Event<'_>) -> bool {
    event
        .exception
        .values
        .iter()
        .any(|e| e.mechanism.as_ref().is_some_and(|m| m.ty == "panic"))
}

/// The `before_send` pipeline.
pub struct EventGate {
    shutdown_started: &'static OnceLock<Instant>,
    shutdown_quiet: Duration,
    ignores: Vec<String>,
    max_per_issue: u32,
    max_total: u32,
    max_logs: u32,
    max_transactions: u32,
    service: String,
    environment: String,
    release: String,
    run_id: Option<String>,
    test_name: Option<String>,
    test_name_file: Option<PathBuf>,
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    total: u32,
    per_issue: HashMap<u64, u32>,
    logs: u32,
    transactions: u32,
}

impl EventGate {
    pub fn new(settings: &Settings) -> Self {
        let mut ignores: Vec<String> = BENIGN_ERRORS.iter().map(|s| s.to_string()).collect();
        ignores.extend(settings.extra_ignores.iter().cloned());
        Self {
            shutdown_started: &SHUTDOWN_STARTED,
            shutdown_quiet: shutdown_quiet_window(),
            ignores,
            max_per_issue: settings.max_events_per_issue,
            max_total: settings.max_events,
            max_logs: settings.max_logs,
            max_transactions: settings.max_transactions,
            environment: settings.environment.clone(),
            release: settings.release.clone(),
            service: settings.service.clone(),
            run_id: settings.run_id.clone(),
            test_name: settings.test_name.clone(),
            test_name_file: settings.test_name_file.clone(),
            state: Mutex::new(GateState::default()),
        }
    }

    /// Read the shutdown state from `flag` instead of the process-wide one
    /// (tests).
    pub fn with_shutdown_clock(mut self, started: &'static OnceLock<Instant>, quiet: Duration) -> Self {
        self.shutdown_started = started;
        self.shutdown_quiet = quiet;
        self
    }

    /// Drop benign errors, scrub, enforce the caps and add the run tags.
    pub fn process(&self, mut event: Event<'static>) -> Option<Event<'static>> {
        // NAN-5886: errors logged while the service stops (backends already
        // gone, in-flight work cancelled) are expected, not issues.
        if in_quiet_window(self.shutdown_started.get(), self.shutdown_quiet, Instant::now())
            && !is_panic_capture(&event)
        {
            return None;
        }
        let text = event_text(&event);
        if self.ignores.iter().any(|needle| text.contains(needle.as_str())) {
            return None;
        }
        // Before the cap key (so the cap counts per Sentry issue) and before
        // scrubbing (so the fingerprint passes the scrubber too).
        apply_tracing_fingerprint(&mut event);
        // The cap key comes from the RAW event (it never leaves the process):
        // after scrubbing, messages are `<redacted>` and would all collide.
        let key = issue_key(&event);
        if !self.admit(key) {
            return None;
        }
        scrub_event(&mut event);
        self.tag(&mut event.tags);
        Some(event)
    }

    /// `before_send_log`: scrub, cap, tag.
    pub fn process_log(&self, mut log: Log) -> Option<Log> {
        if self.ignores.iter().any(|needle| log.body.contains(needle.as_str())) {
            return None;
        }
        if !self.bump(|s| &mut s.logs, self.max_logs) {
            return None;
        }
        scrub_log(&mut log);
        log.attributes.insert("sentry.environment".into(), Value::String(self.environment.clone()).into());
        log.attributes.insert("sentry.release".into(), Value::String(self.release.clone()).into());
        let mut tags = BTreeMap::new();
        self.tag(&mut tags);
        for (k, v) in tags {
            log.attributes.insert(k, Value::String(v).into());
        }
        Some(log)
    }

    /// Transactions (no SDK hook): scrub, cap, tag.
    pub fn process_transaction(&self, mut tx: Transaction<'static>) -> Option<Transaction<'static>> {
        if !self.bump(|s| &mut s.transactions, self.max_transactions) {
            return None;
        }
        scrub_transaction(&mut tx);
        self.tag(&mut tx.tags);
        Some(tx)
    }

    fn tag(&self, tags: &mut BTreeMap<String, String>) {
        tags.insert("service".into(), tag_value(&self.service));
        if let Some(run_id) = &self.run_id {
            tags.insert("run_id".into(), run_id.clone());
        }
        if let Some(test) = self.current_test() {
            tags.insert("test".into(), test);
        }
    }

    fn bump(&self, counter: impl FnOnce(&mut GateState) -> &mut u32, max: u32) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let n = counter(&mut state);
        if *n >= max {
            return false;
        }
        *n += 1;
        true
    }

    /// Count one event against its issue and the process total. A capped
    /// event is dropped without counting, so the map never grows past
    /// `max_total` keys.
    fn admit(&self, key: u64) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.total >= self.max_total {
            return false;
        }
        let seen = state.per_issue.get(&key).copied().unwrap_or(0);
        if seen >= self.max_per_issue {
            return false;
        }
        state.per_issue.insert(key, seen + 1);
        state.total += 1;
        true
    }

    fn current_test(&self) -> Option<String> {
        if let Some(path) = &self.test_name_file {
            let mut buf = [0u8; 512];
            let n = std::fs::File::open(path)
                .and_then(|mut f| std::io::Read::read(&mut f, &mut buf))
                .unwrap_or(0);
            let name = tag_value(String::from_utf8_lossy(&buf[..n]).trim());
            if !name.is_empty() {
                return Some(name);
            }
        }
        self.test_name.clone()
    }
}

/// Every human-readable string of the event the benign filter looks at.
fn event_text(event: &Event<'_>) -> String {
    let mut out = String::new();
    if let Some(m) = &event.message {
        out.push_str(m);
        out.push('\n');
    }
    if let Some(entry) = &event.logentry {
        out.push_str(&entry.message);
        out.push('\n');
    }
    for exc in &event.exception.values {
        out.push_str(&exc.ty);
        out.push_str(": ");
        out.push_str(exc.value.as_deref().unwrap_or(""));
        out.push('\n');
    }
    out
}

/// The per-process dedup key: logger + exception types + message with
/// numbers, hex and UUIDs normalized, so `job 12 failed` and `job 13 failed`
/// count as one issue.
///
/// An event with a custom fingerprint (every tracing ERROR, see
/// [`apply_tracing_fingerprint`]) keys on that fingerprint instead, so the
/// per-issue cap counts exactly what Sentry groups into one issue.
pub fn issue_key(event: &Event<'_>) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    if !is_default_fingerprint(&event.fingerprint) {
        "fingerprint".hash(&mut hasher);
        for part in event.fingerprint.iter() {
            part.hash(&mut hasher);
        }
        return hasher.finish();
    }
    event.logger.hash(&mut hasher);
    if event.exception.values.is_empty() {
        let message = event
            .message
            .as_deref()
            .or(event.logentry.as_ref().map(|e| e.message.as_str()))
            .unwrap_or("");
        normalize_message(message).hash(&mut hasher);
    } else {
        for exc in &event.exception.values {
            exc.ty.hash(&mut hasher);
            normalize_message(exc.value.as_deref().unwrap_or("")).hash(&mut hasher);
        }
    }
    hasher.finish()
}

static UUID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").expect("uuid regex")
});
static NUMBERISH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{8,}\b|\d+").expect("number regex"));

pub fn normalize_message(message: &str) -> String {
    let message = UUID_RE.replace_all(message, "#");
    NUMBERISH_RE.replace_all(&message, "#").into_owned()
}

// ---------------------------------------------------------------------------
// Grouping: one Sentry issue per tracing call site (NAN-5837)
// ---------------------------------------------------------------------------

/// The context `sentry-tracing` stores the event's call site in.
pub const TRACING_LOCATION_CONTEXT: &str = "Rust Tracing Location";
/// First fingerprint part of every tracing event, so these issues can never
/// collide with an SDK-grouped one.
pub const TRACING_FINGERPRINT_PREFIX: &str = "nano-tracing";

/// Give a tracing ERROR event a fingerprint of its call site:
/// `["nano-tracing", <logger/target>, <file>:<line>]`.
///
/// Without it, Sentry groups these events by the attached thread stack
/// (`attach_stacktrace`). That stack is the same tokio worker frames for
/// every logged error, so every ERROR from every service landed in one issue
/// (NANO-SERVER-7). The call site is the static identity of the
/// `tracing::error!` invocation and so of its format string (tracing erases
/// the template itself: only the formatted message reaches the layer). The
/// fingerprint holds nothing interpolated, so the same site with different
/// ids, names or timestamps stays one issue.
///
/// Left alone: an event that already has a custom fingerprint, one with no
/// tracing call site (the panic integration's events, which keep stack-based
/// grouping) and any event carrying a panic exception.
pub fn apply_tracing_fingerprint(event: &mut Event<'_>) {
    if !is_default_fingerprint(&event.fingerprint) {
        return;
    }
    if event
        .exception
        .values
        .iter()
        .any(|e| e.mechanism.as_ref().is_some_and(|m| m.ty == "panic"))
    {
        return;
    }
    let Some(sentry::protocol::Context::Other(location)) = event.contexts.get(TRACING_LOCATION_CONTEXT) else {
        return;
    };
    let (Some(file), Some(line)) = (
        location.get("file").and_then(Value::as_str),
        location.get("line").and_then(Value::as_u64),
    ) else {
        return;
    };
    let site = format!("{}:{line}", stable_source_path(file));
    let logger = event.logger.clone().unwrap_or_default();
    event.fingerprint = Cow::Owned(vec![
        Cow::Borrowed(TRACING_FINGERPRINT_PREFIX),
        Cow::Owned(logger),
        Cow::Owned(site),
    ]);
}

/// The SDK's `{{ default }}` fingerprint (its own helper is private).
fn is_default_fingerprint(fp: &[Cow<'_, str>]) -> bool {
    fp.len() == 1 && matches!(fp[0].as_ref(), "{{ default }}" | "{{default}}")
}

/// `file` without the build host's cargo home, so a dependency's call site
/// (`/usr/local/cargo/registry/src/index.crates.io-<hash>/tower-http-0.7.1/...`)
/// fingerprints the same on every builder. Workspace paths are already
/// relative and pass through.
fn stable_source_path(file: &str) -> &str {
    for marker in ["/registry/src/", "/git/checkouts/"] {
        if let Some(idx) = file.find(marker) {
            let rest = &file[idx + marker.len()..];
            // Skip the index / checkout directory: `<crate>-<version>/...` stays.
            return rest.split_once('/').map_or(rest, |(_, tail)| tail);
        }
    }
    file
}

// ---------------------------------------------------------------------------
// Scrubbing: an allowlist, in its own module
// ---------------------------------------------------------------------------

#[path = "error_tracking_scrub.rs"]
pub mod scrub;
pub use scrub::{
    hashed_user_id, safe_message, scrub_breadcrumb, scrub_event, scrub_log, scrub_text, scrub_transaction,
    template_message, FILTERED,
};

// ---------------------------------------------------------------------------
// Transport: the transaction gate
// ---------------------------------------------------------------------------

/// Wraps the SDK's default HTTP transport so transactions get the same
/// scrubbing, caps and tags as events. Envelopes without a transaction pass
/// through untouched (events were already gated in `before_send`).
pub struct ScrubbingTransportFactory {
    gate: Arc<EventGate>,
    inner: Arc<dyn TransportFactory>,
}

impl TransportFactory for ScrubbingTransportFactory {
    fn create_transport_with_options(&self, mut options: TransportOptions) -> Arc<dyn Transport> {
        // `sentry::init` applies the SDK's env defaults, including
        // `SSL_VERIFY=false`. Sentry traffic always verifies TLS.
        options.accept_invalid_certs = false;
        let inner = self.inner.create_transport_with_options(options);
        Arc::new(ScrubbingTransport { inner, gate: self.gate.clone() })
    }
}

pub struct ScrubbingTransport {
    inner: Arc<dyn Transport>,
    gate: Arc<EventGate>,
}

impl ScrubbingTransport {
    /// `envelope` with every transaction gated; `None` when nothing is left.
    pub fn gate_envelope(gate: &EventGate, envelope: Envelope) -> Option<Envelope> {
        if !envelope.items().any(|i| matches!(i, EnvelopeItem::Transaction(_))) {
            return Some(envelope);
        }
        let mut out = Envelope::new().with_headers(envelope.headers().clone());
        let mut kept = 0usize;
        for item in envelope.into_items() {
            match item {
                EnvelopeItem::Transaction(tx) => {
                    if let Some(tx) = gate.process_transaction(*tx) {
                        out.add_item(EnvelopeItem::Transaction(Box::new(tx)));
                        kept += 1;
                    }
                }
                other => {
                    out.add_item(other);
                    kept += 1;
                }
            }
        }
        (kept > 0).then_some(out)
    }
}

impl Transport for ScrubbingTransport {
    fn send_envelope(&self, envelope: Envelope) {
        if let Some(envelope) = Self::gate_envelope(&self.gate, envelope) {
            self.inner.send_envelope(envelope);
        }
    }

    fn flush(&self, timeout: Duration) -> bool {
        self.inner.flush(timeout)
    }

    fn shutdown(&self, timeout: Duration) -> bool {
        self.inner.shutdown(timeout)
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Printable, bounded tag value.
fn tag_value(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).take(MAX_TAG_LEN).collect()
}

/// Environment / release names: no whitespace, slashes or control characters.
fn sanitize_name(raw: &str, max: usize) -> String {
    raw.chars()
        .map(|c| if c.is_whitespace() || c == '/' || c == '\\' || c.is_control() { '-' } else { c })
        .take(max)
        .collect()
}

#[cfg(test)]
#[path = "error_tracking_tests.rs"]
mod tests;
