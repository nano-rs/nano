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
//! types the expression, not in the Rust. So this guard pins the two facts that
//! together make the query legal, and fails if either drifts.

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
         If that is deliberate, revisit due_for's conversion in \
         nanosiem-core/src/observability/synthetic_runner.rs and this guard."
    );
}

/// `due_for` must convert with `toUnixTimestamp64Milli`, never with arithmetic.
#[test]
fn due_for_converts_datetime64_without_arithmetic() {
    assert!(
        SYNTHETIC_RUNNER.contains("toUnixTimestamp64Milli(max(timestamp))"),
        "due_for must read the last-run time with \
         toUnixTimestamp64Milli(max(timestamp)) — ClickHouse rejects arithmetic \
         on a DateTime64 (Code 43), which silently disabled every synthetic \
         check between 2026-07-06 and NAN-2381."
    );
    assert!(
        !SYNTHETIC_RUNNER.contains("max(timestamp) * 1000"),
        "due_for has regressed to multiplying a DateTime64 by 1000. That query \
         fails with Code 43 ILLEGAL_TYPE_OF_ARGUMENT on every tick, and because \
         run_tick logs-and-skips per check (NAN-1102) the failure is silent: \
         checks simply never probe."
    );
}

/// Both the single-node and clustered table names flow through the same
/// `due_for` string, so the conversion must be built once and shared. A
/// `Distributed` table needs no `REMOTE` grant here (verified against saturn),
/// so the clustered path is legal as soon as the type conversion is.
#[test]
fn due_for_query_is_shared_by_local_and_distributed_paths() {
    assert!(
        SYNTHETIC_RUNNER.contains("nanosiem.synthetic_check_results_distributed"),
        "the clustered read target disappeared; NAN-1721 O1 requires the \
         last-run time to reflect every shard"
    );
    assert_eq!(
        SYNTHETIC_RUNNER
            .matches("toUnixTimestamp64Milli(max(timestamp))")
            .count(),
        1,
        "the last-run conversion should be built once and shared by the local \
         and _distributed paths — a second copy is how one of them drifts back \
         to an illegal expression"
    );
}
