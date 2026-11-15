// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one way nano starts a typed ClickHouse `INSERT` (NAN-5412).
//!
//! clickhouse-rs 0.14.3+ backtick-escapes the WHOLE argument of
//! `Client::insert(table)` as a single identifier, so a qualified
//! `nanosiem.logs` becomes `` `nanosiem.logs` ``: a table literally named
//! `nanosiem.logs` in the client's default database, which does not exist.
//! 0.14.2 (what nano ran before) spliced the name in raw. Every writer here
//! passes `db.table`, so a straight bump would have failed every audit,
//! search-result and platform-feed insert at runtime with UNKNOWN_TABLE.
//!
//! [`insert`] keeps the 0.14.2 statement byte-identical for nano's bareword
//! names (`INSERT INTO nanosiem.logs(...)`) and safely quotes any part that is
//! not a bareword. `tests/clickhouse_insert_guard.rs` keeps every production
//! writer on this seam.

use crate::sql_hygiene::quote_identifier;

/// The `INSERT INTO` target for `table`, which may be `db.table` qualified.
/// Each dot-separated part is quoted on its own, so the dots stay structural.
pub fn insert_target(table: &str) -> String {
    table
        .split('.')
        .map(quote_identifier)
        .collect::<Vec<_>>()
        .join(".")
}

/// Start a typed `INSERT` into `table` (bare or `db.table`).
pub async fn insert<T: clickhouse::Row>(
    client: &clickhouse::Client,
    table: &str,
) -> Result<clickhouse::insert::Insert<T>, clickhouse::error::Error> {
    client.insert_unescaped::<T>(&insert_target(table)).await
}

#[cfg(test)]
#[path = "clickhouse_insert_tests.rs"]
mod tests;
