// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5886: transient backend outages log WARN first and reach Sentry only
//! once they last.
//!
//! Background workers (signal processor, rule scheduler, post-migration
//! refresh) retry on their own. Before this module, each retry of a ClickHouse,
//! PostgreSQL or search-service connection drop logged at ERROR, and every
//! ERROR becomes a Sentry event: a one-minute ClickHouse restart produced about
//! 48 of them. Now:
//!
//! - [`is_transient_error`] / [`is_transient_anyhow`] decide, by error TYPE
//!   (never message text, as in NAN-5424), whether a failure is a transport
//!   blip: connection refused / reset, client timeout, pool exhaustion, a
//!   backend marked unavailable. Bad SQL, schema mismatches and data errors are
//!   not transient and keep logging at ERROR right away.
//! - [`OutageTracker`] counts one outage (first transient failure to the next
//!   success). The caller logs WARN for each failure and ERROR exactly once,
//!   when the outage has lasted [`report_after`] (default 5 minutes,
//!   `NANO_TRANSIENT_OUTAGE_REPORT_SECS`), with the failure count and duration.
//!   Recovery is logged at INFO.
//!
//! The tracker does not log itself: each caller logs from its own call site so
//! Sentry (which groups ERROR events by `file:line`) keeps one issue per
//! worker instead of folding them all together.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// Env var for the outage length (seconds) before one ERROR is logged.
pub const REPORT_AFTER_ENV: &str = "NANO_TRANSIENT_OUTAGE_REPORT_SECS";
const DEFAULT_REPORT_AFTER_SECS: u64 = 300;
const MAX_REPORT_AFTER_SECS: u64 = 86_400;

static REPORT_AFTER: LazyLock<Duration> =
    LazyLock::new(|| parse_report_after(std::env::var(REPORT_AFTER_ENV).ok().as_deref()));

/// How long an outage lasts before it is reported at ERROR (process-wide).
pub fn report_after() -> Duration {
    *REPORT_AFTER
}

/// `NANO_TRANSIENT_OUTAGE_REPORT_SECS`: whole seconds, clamped to one day.
/// `0` reports on the first failure (the old behavior). Unset or unparsable
/// means the default (5 minutes).
fn parse_report_after(raw: Option<&str>) -> Duration {
    let secs = raw
        .map(str::trim)
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.min(MAX_REPORT_AFTER_SECS))
        .unwrap_or(DEFAULT_REPORT_AFTER_SECS);
    Duration::from_secs(secs)
}

/// True when `error` (or the first recognised error in its `source()` chain)
/// is a transport-level failure that a retry is expected to fix.
///
/// Transient: connection refused / reset / aborted, broken pipe, timeouts,
/// unreachable host or network, a connect-level failure with no more specific
/// cause (DNS lookups land here: std gives no typed code that tells a
/// temporary failure from an unknown name), pool exhaustion, PostgreSQL
/// connection-class SQLSTATEs, and a backend nano marked unavailable.
///
/// Never transient (NAN-5886 review P1-1): TLS / certificate failures,
/// authentication and permission errors, and every other `io::ErrorKind`
/// (`PermissionDenied`, `InvalidData`, `NotFound`, ...). Those are
/// configuration faults and report at once.
pub fn is_transient_error(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(e) = current {
        if let Some(verdict) = classify_one(e) {
            return verdict;
        }
        current = e.source();
    }
    false
}

/// [`is_transient_error`] over an `anyhow` chain (context layers included).
pub fn is_transient_anyhow(error: &anyhow::Error) -> bool {
    for cause in error.chain() {
        if let Some(verdict) = classify_one(cause) {
            return verdict;
        }
    }
    false
}

/// How a connection-level failure should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    /// A retry is expected to work.
    Transient,
    /// TLS / certificate, or an IO error kind that is not transport
    /// (permission, invalid data, ...): a configuration fault.
    Rejected,
}

/// Classify the cause chain of a CONNECT-level failure (ClickHouse
/// `Network`, a `reqwest` connect error): `Rejected` when anything below it
/// is TLS or a non-transport IO kind, `Transient` otherwise (a bare connect
/// error, DNS, refused, reset, timeout).
pub fn connect_failure(error: &(dyn std::error::Error + 'static)) -> ConnectFailure {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(e) = current {
        if e.downcast_ref::<rustls::Error>().is_some() {
            return ConnectFailure::Rejected;
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            // `io::Error::source` skips the wrapped error itself, so look at
            // it directly (rustls reports through `io::Error` this way).
            if io.get_ref().is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some()) {
                return ConnectFailure::Rejected;
            }
            if io_kind_is_rejected(io.kind()) {
                return ConnectFailure::Rejected;
            }
        }
        current = e.source();
    }
    ConnectFailure::Transient
}

/// IO kinds a retry is expected to fix.
fn io_kind_is_transport(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind as K;
    matches!(
        kind,
        K::ConnectionRefused
            | K::ConnectionReset
            | K::ConnectionAborted
            | K::BrokenPipe
            | K::TimedOut
            | K::UnexpectedEof
            | K::NotConnected
            | K::HostUnreachable
            | K::NetworkUnreachable
            | K::NetworkDown
            | K::AddrNotAvailable
            | K::Interrupted
            | K::WouldBlock
    )
}

/// IO kinds that are known configuration / data faults. `Other` and the
/// uncategorized kind (how std reports a DNS lookup failure) are neither:
/// inside a connect failure they count as transport.
fn io_kind_is_rejected(kind: std::io::ErrorKind) -> bool {
    use std::io::ErrorKind as K;
    matches!(
        kind,
        K::PermissionDenied
            | K::NotFound
            | K::InvalidData
            | K::InvalidInput
            | K::Unsupported
            | K::AlreadyExists
            | K::StorageFull
            | K::ReadOnlyFilesystem
            | K::QuotaExceeded
            | K::FileTooLarge
            | K::OutOfMemory
            | K::AddrInUse
    )
}

/// PostgreSQL failures a retry is expected to fix. Narrower than
/// [`crate::detection::error::sqlx_error_is_transient`] (which the detection
/// catch-up keeps): TLS and a crashed pool worker are real faults here.
fn sqlx_is_transient(error: &sqlx::Error) -> bool {
    match error {
        // A sqlx IO error is connection-level: transport unless TLS or a
        // real IO kind (a DNS failure, like ClickHouse's, is transport).
        sqlx::Error::Io(io) => connect_failure(io) == ConnectFailure::Transient,
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => true,
        sqlx::Error::Tls(_) | sqlx::Error::WorkerCrashed => false,
        sqlx::Error::Database(db) => db.code().is_some_and(|code| {
            ["08", "40", "53", "57", "58"].iter().any(|class| code.starts_with(class))
        }),
        _ => false,
    }
}

/// `Some(verdict)` for an error type we recognise, `None` to keep walking.
fn classify_one(e: &(dyn std::error::Error + 'static)) -> Option<bool> {
    if let Some(ch) = e.downcast_ref::<clickhouse::error::Error>() {
        return Some(match ch {
            clickhouse::error::Error::TimedOut => true,
            clickhouse::error::Error::Network(_) => connect_failure(e) == ConnectFailure::Transient,
            _ => false,
        });
    }
    if let Some(sqlx_error) = e.downcast_ref::<sqlx::Error>() {
        return Some(sqlx_is_transient(sqlx_error));
    }
    if let Some(http) = e.downcast_ref::<reqwest::Error>() {
        return Some(
            (http.is_connect() || http.is_timeout()) && connect_failure(e) == ConnectFailure::Transient,
        );
    }
    if let Some(detection) = e.downcast_ref::<crate::detection::DetectionError>() {
        return Some(match detection {
            crate::detection::DetectionError::BackendUnavailable(_) => true,
            crate::detection::DetectionError::BackendRejected(_) => false,
            crate::detection::DetectionError::DatabaseError(db) => sqlx_is_transient(db),
            _ => false,
        });
    }
    if let Some(search) = e.downcast_ref::<crate::search::SearchError>() {
        // `ConnectionRejected` (TLS / permission) is not.
        return Some(matches!(search, crate::search::SearchError::Unavailable(_)));
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        return Some(io_kind_is_transport(io.kind()) && connect_failure(e) == ConnectFailure::Transient);
    }
    if e.downcast_ref::<rustls::Error>().is_some() {
        return Some(false);
    }
    None
}

/// What the caller should log for one transient failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutageStep {
    /// Log at WARN: the outage is still short (or was already reported).
    Warn { failures: u64, elapsed: Duration },
    /// Log at ERROR, once: the outage just passed the report threshold.
    Report { failures: u64, elapsed: Duration },
}

impl OutageStep {
    pub fn failures(&self) -> u64 {
        match self {
            Self::Warn { failures, .. } | Self::Report { failures, .. } => *failures,
        }
    }

    pub fn elapsed(&self) -> Duration {
        match self {
            Self::Warn { elapsed, .. } | Self::Report { elapsed, .. } => *elapsed,
        }
    }

    pub fn is_report(&self) -> bool {
        matches!(self, Self::Report { .. })
    }
}

/// An outage that just ended (first success after failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutageEnded {
    pub failures: u64,
    pub elapsed: Duration,
    /// The outage had been reported at ERROR.
    pub reported: bool,
}

/// One outage: from the first transient failure to the next success.
#[derive(Debug, Clone)]
pub struct OutageTracker {
    report_after: Duration,
    /// Consecutive NON-transient failures before they report (see
    /// [`OutageTracker::record_error`]).
    persistent_after_failures: u64,
    // The transient outage.
    started: Option<Instant>,
    failures: u64,
    reported: bool,
    // NAN-5886 review P1-2: the non-transient streak, kept apart from the
    // outage so a reported outage never absorbs a real error.
    persistent_started: Option<Instant>,
    persistent_failures: u64,
}

impl Default for OutageTracker {
    fn default() -> Self {
        Self::new(report_after())
    }
}

impl OutageTracker {
    pub const fn new(report_after: Duration) -> Self {
        Self {
            report_after,
            persistent_after_failures: 1,
            started: None,
            failures: 0,
            reported: false,
            persistent_started: None,
            persistent_failures: 0,
        }
    }

    /// For retried work: a non-transient failure reports only once it has
    /// failed `n` times in a row (default 1: right away).
    pub const fn with_persistent_after_failures(mut self, n: u64) -> Self {
        self.persistent_after_failures = if n == 0 { 1 } else { n };
        self
    }

    /// Count a failure of either kind.
    ///
    /// - Transient: see [`Self::record_failure`] (WARN, then one report once
    ///   the outage has lasted the time threshold). It also breaks a
    ///   non-transient streak.
    /// - Non-transient: the backend answered, so any transient outage is over.
    ///   It warns until `persistent_after_failures` non-transient failures in
    ///   a row, then EVERY further one reports: a real error is never absorbed
    ///   by an earlier report (Sentry's per-issue cap bounds the volume).
    pub fn record_error(&mut self, now: Instant, transient: bool) -> OutageStep {
        if transient {
            return self.record_failure(now);
        }
        self.started = None;
        self.failures = 0;
        self.reported = false;
        let started = *self.persistent_started.get_or_insert(now);
        self.persistent_failures = self.persistent_failures.saturating_add(1);
        let failures = self.persistent_failures;
        let elapsed = now.saturating_duration_since(started);
        if failures >= self.persistent_after_failures {
            OutageStep::Report { failures, elapsed }
        } else {
            OutageStep::Warn { failures, elapsed }
        }
    }

    /// Count a transient failure at `now`.
    pub fn record_failure(&mut self, now: Instant) -> OutageStep {
        self.persistent_started = None;
        self.persistent_failures = 0;
        let started = *self.started.get_or_insert(now);
        self.failures = self.failures.saturating_add(1);
        let elapsed = now.saturating_duration_since(started);
        if !self.reported && elapsed >= self.report_after {
            self.reported = true;
            return OutageStep::Report { failures: self.failures, elapsed };
        }
        OutageStep::Warn { failures: self.failures, elapsed }
    }

    /// Count a success at `now`; `Some` when it ends a transient outage.
    /// Clears a non-transient streak too.
    pub fn record_success(&mut self, now: Instant) -> Option<OutageEnded> {
        self.persistent_started = None;
        self.persistent_failures = 0;
        let started = self.started.take()?;
        let ended = OutageEnded {
            failures: self.failures,
            elapsed: now.saturating_duration_since(started),
            reported: self.reported,
        };
        self.failures = 0;
        self.reported = false;
        Some(ended)
    }

    pub fn in_outage(&self) -> bool {
        self.started.is_some()
    }

    /// Nothing is being tracked (no outage, no non-transient streak).
    pub fn is_idle(&self) -> bool {
        self.started.is_none() && self.persistent_started.is_none()
    }
}

/// NAN-5886 review P1-3: one [`OutageTracker`] per key (a rule), so a rule
/// that keeps failing escalates even while other rules succeed, and a
/// partial outage is not reset by the rules that still get through.
///
/// Memory stays bounded: an entry is removed on its key's success or on a
/// non-transient error, and at most [`KeyedOutages::MAX_KEYS`] keys are kept
/// (the least recently seen goes; ~1 MB worst case). There is no idle
/// eviction (review round 2): an hourly, daily or weekly rule must keep its
/// outage start between runs or it could never escalate. A deleted rule's
/// entry lingers until the cap pushes it out.
#[derive(Debug)]
pub struct KeyedOutages<K> {
    report_after: Duration,
    entries: std::collections::HashMap<K, (OutageTracker, Instant)>,
}

impl<K: std::hash::Hash + Eq + Clone> KeyedOutages<K> {
    pub const MAX_KEYS: usize = 10_000;

    pub fn new(report_after: Duration) -> Self {
        Self { report_after, entries: std::collections::HashMap::new() }
    }

    /// Count a transient failure of `key`.
    pub fn record_failure(&mut self, key: &K, now: Instant) -> OutageStep {
        if !self.entries.contains_key(key) {
            self.evict();
        }
        let report_after = self.report_after;
        let entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| (OutageTracker::new(report_after), now));
        entry.1 = now;
        entry.0.record_failure(now)
    }

    /// `key` succeeded (or failed for a non-transient reason, which ends its
    /// outage too): forget it. `Some` when that ended an outage.
    pub fn record_success(&mut self, key: &K, now: Instant) -> Option<OutageEnded> {
        self.entries.remove(key).and_then(|(mut tracker, _)| tracker.record_success(now))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict(&mut self) {
        while self.entries.len() >= Self::MAX_KEYS {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn one_rule_failing_escalates_while_others_succeed() {
        let t0 = Instant::now();
        let minute = Duration::from_secs(60);
        let mut rules = KeyedOutages::new(FIVE_MIN);
        let mut reports = 0;
        for i in 0..=6u32 {
            // The healthy rule succeeding does not reset the stuck one.
            rules.record_success(&"healthy", t0 + i * minute);
            if rules.record_failure(&"stuck", t0 + i * minute).is_report() {
                reports += 1;
            }
        }
        assert_eq!(reports, 1);
        assert_eq!(rules.len(), 1, "the healthy rule holds no entry");
        let ended = rules.record_success(&"stuck", t0 + 7 * minute).unwrap();
        assert!(ended.reported);
        assert!(rules.is_empty());
    }

    #[test]
    fn a_short_restart_reports_nothing_for_any_rule() {
        let t0 = Instant::now();
        let mut rules = KeyedOutages::new(FIVE_MIN);
        for rule in 0..50u32 {
            for s in 0..60u64 {
                assert!(!rules.record_failure(&rule, t0 + Duration::from_secs(s)).is_report());
            }
        }
        for rule in 0..50u32 {
            rules.record_success(&rule, t0 + Duration::from_secs(61));
        }
        assert!(rules.is_empty());
    }

    #[test]
    fn a_daily_rule_keeps_its_outage_between_runs_and_escalates() {
        let t0 = Instant::now();
        let day = Duration::from_secs(86_400);
        let mut rules = KeyedOutages::new(FIVE_MIN);
        assert!(!rules.record_failure(&"daily", t0).is_report());
        // Other rules fail and recover in between; that must not evict it.
        for h in 1..24u32 {
            let at = t0 + Duration::from_secs(3_600) * h;
            rules.record_failure(&"hourly", at);
            rules.record_success(&"hourly", at + Duration::from_secs(1));
        }
        // Its next run a day later is still the same outage: it reports.
        assert!(rules.record_failure(&"daily", t0 + day).is_report());
    }

    #[test]
    fn the_map_is_capped_by_dropping_the_least_recently_seen() {
        let t0 = Instant::now();
        let mut rules = KeyedOutages::new(FIVE_MIN);
        let max = KeyedOutages::<u32>::MAX_KEYS as u32;
        for k in 0..(max + 50) {
            rules.record_failure(&k, t0 + Duration::from_millis(u64::from(k)));
        }
        assert!(rules.len() <= KeyedOutages::<u32>::MAX_KEYS);
        // The newest keys stay; the oldest went.
        assert!(rules.record_success(&(max + 49), t0 + Duration::from_secs(60)).is_some());
        assert!(rules.record_success(&0, t0 + Duration::from_secs(60)).is_none());
    }

    #[test]
    fn sqlx_io_follows_the_connect_rules() {
        // DNS failure (untyped IO kind) on a PostgreSQL connect: transport.
        assert!(is_transient_error(&sqlx::Error::Io(io::Error::other("failed to lookup address information"))));
        // TLS under a transport kind: real.
        assert!(!is_transient_error(&sqlx::Error::Io(io::Error::new(io::ErrorKind::ConnectionReset, bad_cert()))));
    }

    const FIVE_MIN: Duration = Duration::from_secs(300);

    #[test]
    fn report_after_defaults_to_five_minutes_and_clamps() {
        assert_eq!(parse_report_after(None), FIVE_MIN);
        assert_eq!(parse_report_after(Some("nope")), FIVE_MIN);
        assert_eq!(parse_report_after(Some(" 60 ")), Duration::from_secs(60));
        assert_eq!(parse_report_after(Some("0")), Duration::ZERO);
        assert_eq!(parse_report_after(Some("999999999")), Duration::from_secs(MAX_REPORT_AFTER_SECS));
    }

    #[test]
    fn connection_failures_are_transient() {
        for kind in [
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(is_transient_error(&io::Error::from(kind)), "{kind:?}");
        }
        assert!(is_transient_error(&clickhouse::error::Error::TimedOut));
        assert!(is_transient_error(&sqlx::Error::PoolTimedOut));
        assert!(is_transient_error(&sqlx::Error::PoolClosed));
        assert!(is_transient_error(&crate::detection::DetectionError::BackendUnavailable(
            "connection refused".into()
        )));
        assert!(is_transient_error(&crate::search::SearchError::Unavailable("x".into())));
    }

    #[test]
    fn real_errors_are_not_transient() {
        // Bad SQL / unknown column / schema mismatch: ClickHouse answered.
        assert!(!is_transient_error(&clickhouse::error::Error::BadResponse(
            "Code: 47. DB::Exception: Unknown identifier".into()
        )));
        assert!(!is_transient_error(&clickhouse::error::Error::SchemaMismatch("x".into())));
        assert!(!is_transient_error(&sqlx::Error::RowNotFound));
        assert!(!is_transient_error(&crate::detection::DetectionError::InvalidQuery("x".into())));
        assert!(!is_transient_error(&crate::search::SearchError::ParseError("x".into())));
        // Message text never decides: an unrecognised error quoting
        // "Connection refused" is still a real error.
        assert!(!is_transient_anyhow(&anyhow::anyhow!("Connection refused (os error 111)")));
    }

    fn bad_cert() -> rustls::Error {
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
    }

    #[test]
    fn tls_failures_are_real_errors() {
        // PostgreSQL TLS and a crashed pool worker.
        assert!(!is_transient_error(&sqlx::Error::Tls(Box::new(bad_cert()))));
        assert!(!is_transient_error(&sqlx::Error::WorkerCrashed));
        // rustls reports through io::Error(InvalidData).
        let tls_io = io::Error::new(io::ErrorKind::InvalidData, bad_cert());
        assert!(!is_transient_error(&tls_io));
        // ...also when wrapped with a transport kind.
        let tls_reset = io::Error::new(io::ErrorKind::ConnectionReset, bad_cert());
        assert!(!is_transient_error(&tls_reset));
        // ClickHouse `Network` whose cause is a TLS failure.
        let ch_tls = clickhouse::error::Error::Network(Box::new(io::Error::new(io::ErrorKind::Other, bad_cert())));
        assert!(!is_transient_error(&ch_tls));
        assert_eq!(connect_failure(&ch_tls), ConnectFailure::Rejected);
        // A bare rustls error.
        assert!(!is_transient_error(&bad_cert()));
        // DetectionError carrying a PostgreSQL TLS failure.
        assert!(!is_transient_error(&crate::detection::DetectionError::DatabaseError(sqlx::Error::Tls(
            Box::new(bad_cert())
        ))));
    }

    #[test]
    fn a_rejected_clickhouse_connection_is_typed_and_not_transient() {
        let ch_tls = clickhouse::error::Error::Network(Box::new(io::Error::new(io::ErrorKind::Other, bad_cert())));
        let parsed = crate::search::classify_clickhouse_failure(&ch_tls);
        assert!(matches!(parsed, crate::search::SearchError::ConnectionRejected(_)), "{parsed:?}");
        assert!(!is_transient_error(&parsed));
        let refused = clickhouse::error::Error::Network(Box::new(io::Error::from(io::ErrorKind::ConnectionRefused)));
        assert!(matches!(
            crate::search::classify_clickhouse_failure(&refused),
            crate::search::SearchError::Unavailable(_)
        ));
        let rejected = crate::detection::DetectionError::BackendRejected("tls".into());
        assert!(!is_transient_error(&rejected));
        // Catch-up still keeps the window.
        assert!(rejected.is_transient_infrastructure());
    }

    #[test]
    fn non_transport_io_kinds_are_real_errors() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::InvalidData,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NotFound,
            io::ErrorKind::StorageFull,
            io::ErrorKind::ReadOnlyFilesystem,
            io::ErrorKind::Other,
        ] {
            assert!(!is_transient_error(&io::Error::from(kind)), "{kind:?}");
            // A sqlx IO error is connection-level, where an untyped kind
            // (DNS) is transport; every other real kind stays real.
            if kind != io::ErrorKind::Other {
                assert!(!is_transient_error(&sqlx::Error::Io(io::Error::from(kind))), "sqlx {kind:?}");
            }
        }
        // Inside a ClickHouse connect failure, a non-transport kind is real.
        let denied = clickhouse::error::Error::Network(Box::new(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(!is_transient_error(&denied));
    }

    #[test]
    fn connect_level_failures_without_a_real_cause_are_transient() {
        // Refused / reset under ClickHouse `Network`.
        for kind in [io::ErrorKind::ConnectionRefused, io::ErrorKind::ConnectionReset, io::ErrorKind::ConnectionAborted] {
            let ch = clickhouse::error::Error::Network(Box::new(io::Error::from(kind)));
            assert!(is_transient_error(&ch), "{kind:?}");
            assert!(is_transient_error(&sqlx::Error::Io(io::Error::from(kind))), "sqlx {kind:?}");
        }
        // DNS: std reports a lookup failure as an untyped io error, which
        // inside a connect failure is transport.
        let dns = clickhouse::error::Error::Network(Box::new(io::Error::other("failed to lookup address information")));
        assert!(is_transient_error(&dns));
        // A bare connect error with no cause at all.
        let bare = clickhouse::error::Error::Network("connect".into());
        assert!(is_transient_error(&bare));
        for kind in [io::ErrorKind::HostUnreachable, io::ErrorKind::NetworkUnreachable, io::ErrorKind::BrokenPipe] {
            assert!(is_transient_error(&io::Error::from(kind)), "{kind:?}");
        }
    }

    #[test]
    fn auth_errors_are_real_errors() {
        // ClickHouse auth failure (Code 516) arrives as a server response.
        assert!(!is_transient_error(&clickhouse::error::Error::BadResponse(
            "Code: 516. DB::Exception: default: Authentication failed".into()
        )));
    }

    #[test]
    fn anyhow_context_layers_are_walked() {
        let wrapped = anyhow::Error::from(io::Error::from(io::ErrorKind::ConnectionRefused))
            .context("reading nanosiem.migration_refresh")
            .context("post-migration pass");
        assert!(is_transient_anyhow(&wrapped));

        let bad_sql = anyhow::Error::from(clickhouse::error::Error::BadResponse(
            "Code: 62. DB::Exception: Syntax error".into(),
        ))
        .context("reading table");
        assert!(!is_transient_anyhow(&bad_sql));
    }

    #[test]
    fn short_outage_only_warns() {
        let t0 = Instant::now();
        let mut tracker = OutageTracker::new(FIVE_MIN);
        // A one-minute ClickHouse restart: 48 failures, all WARN.
        for i in 0..48u64 {
            let step = tracker.record_failure(t0 + Duration::from_millis(i * 1_250));
            assert!(!step.is_report(), "failure {i} must not report");
            assert_eq!(step.failures(), i + 1);
        }
        let ended = tracker.record_success(t0 + Duration::from_secs(61)).expect("outage ended");
        assert_eq!(ended.failures, 48);
        assert!(!ended.reported);
        assert_eq!(ended.elapsed, Duration::from_secs(61));
        assert!(!tracker.in_outage());
    }

    #[test]
    fn long_outage_reports_exactly_once_with_count_and_duration() {
        let t0 = Instant::now();
        let mut tracker = OutageTracker::new(FIVE_MIN);
        let mut reports = Vec::new();
        for s in (0..=900).step_by(30) {
            if let OutageStep::Report { failures, elapsed } =
                tracker.record_failure(t0 + Duration::from_secs(s))
            {
                reports.push((failures, elapsed));
            }
        }
        assert_eq!(reports, vec![(11, FIVE_MIN)]);
        let ended = tracker.record_success(t0 + Duration::from_secs(930)).unwrap();
        assert!(ended.reported);
        assert_eq!(ended.failures, 31);
    }

    #[test]
    fn a_new_outage_after_recovery_starts_fresh() {
        let t0 = Instant::now();
        let mut tracker = OutageTracker::new(FIVE_MIN);
        tracker.record_failure(t0);
        assert!(tracker.record_failure(t0 + FIVE_MIN).is_report());
        tracker.record_success(t0 + FIVE_MIN + Duration::from_secs(1));

        let t1 = t0 + Duration::from_secs(1_000);
        let step = tracker.record_failure(t1);
        assert_eq!(step, OutageStep::Warn { failures: 1, elapsed: Duration::ZERO });
        assert!(tracker.record_failure(t1 + FIVE_MIN).is_report());
    }

    #[test]
    fn a_real_error_after_a_reported_outage_still_reports() {
        let t0 = Instant::now();
        let minute = Duration::from_secs(60);
        // Default tracker: a real error reports at once, even right after a
        // transient outage was reported.
        let mut tracker = OutageTracker::new(FIVE_MIN);
        for i in 0..=5u32 {
            tracker.record_error(t0 + i * minute, true);
        }
        assert!(tracker.in_outage());
        assert!(tracker.record_error(t0 + 6 * minute, false).is_report());
        assert!(tracker.record_error(t0 + 7 * minute, false).is_report(), "never absorbed");
        assert!(!tracker.in_outage(), "the backend answered: the outage is over");

        // Retried work: the real errors still report after their own 3.
        let mut retried = OutageTracker::new(FIVE_MIN).with_persistent_after_failures(3);
        for i in 0..=5u32 {
            retried.record_error(t0 + i * minute, true);
        }
        let steps: Vec<bool> =
            (6..10u32).map(|i| retried.record_error(t0 + i * minute, false).is_report()).collect();
        assert_eq!(steps, vec![false, false, true, true]);
    }

    #[test]
    fn transient_failures_do_not_count_toward_the_real_error_streak() {
        let t0 = Instant::now();
        let s = Duration::from_secs(1);
        let mut tracker = OutageTracker::new(FIVE_MIN).with_persistent_after_failures(3);
        tracker.record_error(t0, true);
        tracker.record_error(t0 + s, true);
        assert!(!tracker.record_error(t0 + 2 * s, false).is_report(), "1st real error of 3");
        tracker.record_error(t0 + 3 * s, false);
        // A transient failure breaks the streak.
        tracker.record_error(t0 + 4 * s, true);
        assert_eq!(
            tracker.record_error(t0 + 5 * s, false),
            OutageStep::Warn { failures: 1, elapsed: Duration::ZERO }
        );
        tracker.record_success(t0 + 6 * s);
        assert!(tracker.is_idle());
    }

    #[test]
    fn retried_work_reports_a_real_error_only_after_its_retries() {
        let t0 = Instant::now();
        let mut tracker = OutageTracker::new(FIVE_MIN).with_persistent_after_failures(3);
        let minute = Duration::from_secs(60);
        assert!(!tracker.record_error(t0, false).is_report());
        assert!(!tracker.record_error(t0 + minute, false).is_report());
        assert_eq!(
            tracker.record_error(t0 + 2 * minute, false),
            OutageStep::Report { failures: 3, elapsed: 2 * minute }
        );
        // Every real error past the retries reports.
        assert!(tracker.record_error(t0 + 3 * minute, false).is_report());
        tracker.record_success(t0 + 4 * minute);
        // Transient failures follow the time threshold, not the count.
        for i in 0..5u32 {
            assert!(!tracker.record_error(t0 + (5 + i) * minute, true).is_report());
        }
        assert!(tracker.record_error(t0 + 10 * minute, true).is_report());
    }

    #[test]
    fn default_tracker_reports_a_real_error_at_once() {
        let mut tracker = OutageTracker::new(FIVE_MIN);
        assert!(tracker.record_error(Instant::now(), false).is_report());
    }

    #[test]
    fn success_without_outage_is_silent() {
        let mut tracker = OutageTracker::new(FIVE_MIN);
        assert!(tracker.record_success(Instant::now()).is_none());
    }

    #[test]
    fn zero_threshold_reports_the_first_failure() {
        let mut tracker = OutageTracker::new(Duration::ZERO);
        assert!(tracker.record_failure(Instant::now()).is_report());
        assert!(!tracker.record_failure(Instant::now()).is_report());
    }
}
