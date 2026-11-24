// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5428: failure classification (shared NAN-5424 rules: error type,
//! ClickHouse `Code: N`, SQLSTATE class) and the disposition of a failed
//! real-time signal.

use std::borrow::Cow;

use chrono::TimeZone;

use super::*;

/// A PostgreSQL error with a given SQLSTATE, as sqlx surfaces it.
#[derive(Debug)]
struct FakePgError(&'static str);

impl std::fmt::Display for FakePgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fake postgres error {} with event text p\u{0}q", self.0)
    }
}

impl std::error::Error for FakePgError {}

impl sqlx::error::DatabaseError for FakePgError {
    fn message(&self) -> &str {
        "fake"
    }
    fn code(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed(self.0))
    }
    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }
    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }
    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::Other
    }
}

fn pg(code: &'static str) -> sqlx::Error {
    sqlx::Error::Database(Box::new(FakePgError(code)))
}

/// The alert write as `process_signal` propagates it.
fn alert_error(code: &'static str) -> anyhow::Error {
    anyhow::Error::new(AlertRepositoryError::DatabaseError(pg(code)))
        .context("Failed to create alert")
}

fn ch(error: clickhouse::error::Error) -> anyhow::Error {
    anyhow::Error::new(error)
}

fn bad_response(message: &str) -> anyhow::Error {
    ch(clickhouse::error::Error::BadResponse(message.to_string()))
}

use SignalFailureClass::{BadData, Infrastructure, Unrecognised};

fn class_of(e: &anyhow::Error) -> SignalFailureClass {
    classify_signal_error(e).class
}

#[test]
fn postgres_data_exceptions_are_bad_data() {
    // 22P05 / 22021: U+0000 in jsonb / text; 22001 too long; 54000 index row too large.
    for code in ["22P05", "22021", "22001", "54000"] {
        let failure = classify_signal_error(&alert_error(code));
        assert_eq!(failure.class, BadData, "{code}");
        assert_eq!(failure.key, format!("pg:{code}"));
    }
}

#[test]
fn postgres_infrastructure_and_races_hold() {
    // 08006 connection, 53300 too many connections, 57014 statement timeout,
    // 40P01 deadlock, 40001 serialization, 23505 concurrent-write race.
    for code in ["08006", "53300", "57014", "40P01", "40001", "23505"] {
        assert_eq!(class_of(&alert_error(code)), Infrastructure, "{code}");
    }
    let pool = anyhow::Error::new(AlertRepositoryError::DatabaseError(sqlx::Error::PoolTimedOut));
    assert_eq!(class_of(&pool), Infrastructure);
    let rule = anyhow::Error::new(DetectionRuleRepositoryError::DatabaseError(sqlx::Error::PoolClosed))
        .context("Transient error fetching rule");
    assert_eq!(class_of(&rule), Infrastructure);
}

#[test]
fn other_integrity_errors_are_not_bad_data() {
    // A check violation is not positively the signal's content: unrecognised
    // (bounded retry, then the systemic breaker).
    assert_eq!(class_of(&alert_error("23514")), Unrecognised);
}

#[test]
fn clickhouse_transport_and_pressure_hold() {
    let network = ch(clickhouse::error::Error::Network(Box::new(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "refused",
    ))));
    let failure = classify_signal_error(&network);
    assert_eq!((failure.class, failure.key.as_str()), (Infrastructure, "ch:network"));
    assert_eq!(class_of(&ch(clickhouse::error::Error::TimedOut)), Infrastructure);
    assert_eq!(
        class_of(&bad_response(
            "Code: 241. DB::Exception: Memory limit (for query) exceeded. (MEMORY_LIMIT_EXCEEDED)"
        )),
        Infrastructure
    );
}

#[test]
fn clickhouse_data_codes_and_undecodable_rows_are_bad_data() {
    let parse = classify_signal_error(&bad_response(
        "Code: 41. DB::Exception: Cannot read DateTime: zz. (CANNOT_PARSE_DATETIME)",
    ));
    assert_eq!((parse.class, parse.key.as_str()), (BadData, "ch:41"));
    let bytes = [0xED_u8, 0xA0, 0x80];
    let utf8 = std::str::from_utf8(std::hint::black_box(&bytes)).unwrap_err();
    assert_eq!(class_of(&ch(clickhouse::error::Error::InvalidUtf8Encoding(utf8))), BadData);
}

#[test]
fn clickhouse_query_and_schema_errors_are_unrecognised() {
    // Fails the same way on any data: never dead-lettered as bad data.
    for (message, key) in [
        ("Code: 47. DB::Exception: Unknown expression identifier `x`. (UNKNOWN_IDENTIFIER)", "ch:47"),
        ("Code: 43. DB::Exception: Illegal type String. (ILLEGAL_TYPE_OF_ARGUMENT)", "ch:43"),
        ("Code: 427. DB::Exception: cannot compile re2. (CANNOT_COMPILE_REGEXP)", "ch:427"),
    ] {
        let failure = classify_signal_error(&bad_response(message));
        assert_eq!((failure.class, failure.key.as_str()), (Unrecognised, key), "{message}");
    }
    let skew = classify_signal_error(&ch(clickhouse::error::Error::SchemaMismatch("x".into())));
    assert_eq!((skew.class, skew.key.as_str()), (Unrecognised, "ch:schema-mismatch"));
    assert_eq!(class_of(&ch(clickhouse::error::Error::Custom("x".into()))), Unrecognised);
}

#[test]
fn clickhouse_exception_text_never_selects_the_class() {
    // The exception text quotes event data; only the code counts.
    let failure = classify_signal_error(&bad_response(
        "Code: 47. DB::Exception: CANNOT_PARSE_DATETIME MEMORY_LIMIT_EXCEEDED in value. (UNKNOWN_IDENTIFIER)",
    ));
    assert_eq!((failure.class, failure.key.as_str()), (Unrecognised, "ch:47"));
}

#[test]
fn unrecognised_errors_default_to_the_bounded_class() {
    assert_eq!(class_of(&anyhow::anyhow!("something else")), Unrecognised);
}

#[test]
fn infrastructure_holds_without_a_cap() {
    let failure = SignalFailure::new(Infrastructure, "ch:network");
    for attempts in [1, MAX_UNRECOGNISED_ATTEMPTS, 50, 10_000] {
        assert_eq!(disposition(&failure, attempts, 0), SignalDisposition::HoldAndAlarm);
    }
}

#[test]
fn bad_data_is_dead_lettered_at_once_even_in_a_streak() {
    let failure = SignalFailure::new(BadData, "pg:22P05");
    assert_eq!(disposition(&failure, 1, 0), SignalDisposition::DeadLetter);
    // No breaker for attacker-controlled data.
    assert_eq!(disposition(&failure, 1, 100), SignalDisposition::DeadLetter);
}

#[test]
fn unrecognised_retries_then_dead_letters_then_trips_the_breaker() {
    let failure = SignalFailure::new(Unrecognised, "ch:47");
    for attempts in 1..MAX_UNRECOGNISED_ATTEMPTS {
        assert_eq!(disposition(&failure, attempts, 0), SignalDisposition::Retry);
    }
    for streak in 0..SYSTEMIC_BREAKER_THRESHOLD {
        assert_eq!(
            disposition(&failure, MAX_UNRECOGNISED_ATTEMPTS, streak),
            SignalDisposition::DeadLetter
        );
    }
    assert_eq!(
        disposition(&failure, MAX_UNRECOGNISED_ATTEMPTS, SYSTEMIC_BREAKER_THRESHOLD),
        SignalDisposition::HoldAndAlarm,
        "the same error across several signals is systemic: hold, don't drop"
    );
}

#[test]
fn dropped_signal_gap_is_redacted_to_class_and_key() {
    let signal_id = Uuid::nil();
    let rule_id = Uuid::from_u128(7);
    let ts = Utc.with_ymd_and_hms(2026, 11, 14, 20, 8, 43).unwrap();
    let failure = classify_signal_error(&alert_error("22P05"));
    let gap = DroppedSignalGap::new(signal_id, rule_id, ts, 1, &failure);
    assert_eq!(gap.rule_id, rule_id);
    assert_eq!(gap.window_start, ts);
    assert_eq!(gap.window_end, ts + chrono::Duration::seconds(1));
    assert_eq!(gap.attempts, 1);
    assert_eq!(
        gap.error_message,
        format!("[data] real-time signal {signal_id} dropped after 1 attempt(s) (pg:22P05)")
    );
    assert!(!gap.error_message.contains('\0'));
}

/// NAN-5817 review round 2: classifying a real-time signal failure is pure.
/// It must not report "ClickHouse rejected nano-generated search SQL" at
/// ERROR (with the raw, possibly event-quoting text) for a data or
/// query-shape failure; the signal processor logs its own redacted line.
#[test]
fn clickhouse_classification_emits_no_log_events() {
    use crate::search::log_capture::levels_logged;
    for (message, class) in [
        ("Code: 6. DB::Exception: Cannot parse text 'evil\nline' (CANNOT_PARSE_TEXT)", BadData),
        ("Code: 46. DB::Exception: Unknown function nosuchfn. (UNKNOWN_FUNCTION)", Unrecognised),
        ("Code: 47. DB::Exception: Unknown expression identifier `srcip`. (UNKNOWN_IDENTIFIER)", Unrecognised),
    ] {
        let err = bad_response(message);
        let (got, levels) = levels_logged(|| class_of(&err));
        assert_eq!(got, class, "{message}");
        assert!(levels.is_empty(), "{message}: classification logged {levels:?}");
    }
}
