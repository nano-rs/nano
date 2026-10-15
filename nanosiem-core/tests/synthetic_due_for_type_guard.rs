// SPDX-License-Identifier: AGPL-3.0-or-later

//! Type guard for the synthetic-check scheduler's "when did this last run?"
//! read (NAN-2381).
//!
//! `synthetic_check_results.timestamp` is `DateTime64(3, 'UTC')`, and ClickHouse
//! refuses to multiply a `DateTime64` by an integer:
//!
//! ```text
//! Code: 43. DB::Exception: Illegal types DateTime64(3, 'UTC') and UInt16 of
//! arguments of function multiply … (ILLEGAL_TYPE_OF_ARGUMENT)
//! ```
//!
//! `due_for` shipped as `toInt64(max(timestamp) * 1000)`, so every scheduling
//! tick errored. The caller logs-and-skips per check (NAN-1102), so the feature
//! did not crash — it silently never probed, on every tenant, from 2026-07-06
//! until this guard was added. The only external symptom was a perfectly flat
//! CH failure rate (240/hr on therange, one per 15s).
//!
//! A mocked-client unit test cannot catch this: the defect is in how ClickHouse
//! types the expression, not in the Rust.
//!
//! NAN-2361 moved scheduling out of ClickHouse entirely: the runner now claims
//! due checks atomically from the PostgreSQL watermark
//! (`SyntheticCheckRepository::claim_due_enabled`), so the ClickHouse
//! `max(timestamp)` read — and the bug with it — no longer exists. Main's
//! NAN-2381 fix to that read is therefore subsumed. The guard below keeps the
//! lesson: scheduling must stay on the PG claim, and nothing in the runner may
//! do arithmetic on the DateTime64 column again.

const SYNTHETIC_RUNNER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/observability/synthetic_runner.rs"
));
const MIGRATION_142: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/142_synthetic_check_results.sql"
));

/// The column really is `DateTime64` — the premise the rest of this file rests
/// on. If the schema ever migrates to a plain integer epoch, this fails first
/// and tells the next reader why the guard below exists.
#[test]
fn synthetic_timestamp_column_is_datetime64() {
    let normalized = MIGRATION_142.replace(['`', ' '], "");
    assert!(
        normalized.contains("timestampDateTime64(3,'UTC')"),
        "synthetic_check_results.timestamp is no longer DateTime64(3, 'UTC'). \
         If that is deliberate, revisit any timestamp conversion in \
         nanosiem-core/src/observability/synthetic_runner.rs and this guard."
    );
}

/// Scheduling is the PostgreSQL claim, not a ClickHouse last-run read.
#[test]
fn scheduling_uses_pg_claim_not_clickhouse_last_run_read() {
    assert!(
        SYNTHETIC_RUNNER.contains("claim_due_enabled("),
        "the synthetic runner no longer claims due checks from PostgreSQL. If \
         scheduling moves back to a ClickHouse last-run read, it must convert the \
         DateTime64 with toUnixTimestamp64Milli (NAN-2381), and this guard must \
         be updated to pin that."
    );
}

/// Nothing in the runner may multiply the DateTime64 column (Code 43).
#[test]
fn runner_never_does_arithmetic_on_datetime64_timestamp() {
    for bad in ["max(timestamp) * 1000", "max(timestamp)*1000", "timestamp * 1000"] {
        assert!(
            !SYNTHETIC_RUNNER.contains(bad),
            "synthetic_runner.rs contains `{bad}`. ClickHouse rejects arithmetic on a \
             DateTime64 with Code 43 ILLEGAL_TYPE_OF_ARGUMENT on every tick, and \
             because run_tick logs-and-skips per check (NAN-1102) the failure is \
             silent: checks simply never probe. Use toUnixTimestamp64Milli."
        );
    }
}
