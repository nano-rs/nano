// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5817: who wrote the SQL ClickHouse rejected.
//!
//! [`parse_clickhouse_error`](crate::search::parse_clickhouse_error) turns a
//! ClickHouse query-shape rejection (syntax error, unknown function, wrong
//! arity, missing column, bad stored value) into the same caller-facing
//! variants the nPL validator uses (`SqlValidationError`, `FieldNotFound`,
//! `DataError`). Those variants log at WARN (see
//! [`SearchError::is_internal`]), which is right when the validator or parser
//! rejected the query BEFORE any SQL ran.
//!
//! When ClickHouse rejects SQL that nano generated from nPL, the user did not
//! write that SQL: it is a generator bug or schema drift and must reach Sentry.
//! [`report`] logs it at ERROR at the one point every ClickHouse client error
//! passes ([`search_error_from_error`](crate::search::search_error_from_error)),
//! unless the SQL is the caller's own (raw SQL search, SQL dashboard panels),
//! which runs inside [`user_authored`].
//!
//! Fail-safe: a raw-SQL query that loses the scope (spawned work) logs at
//! ERROR, never the other way round.

use std::future::Future;

use crate::search::SearchError;

tokio::task_local! {
    static USER_AUTHORED_SQL: ();
}

/// Run `future` as SQL the caller wrote themselves: ClickHouse rejections of it
/// are the caller's mistake and are not reported at ERROR.
pub async fn user_authored<F: Future>(future: F) -> F::Output {
    USER_AUTHORED_SQL.scope((), future).await
}

/// Whether the current task runs caller-written SQL.
pub fn is_user_authored() -> bool {
    USER_AUTHORED_SQL.try_with(|_| ()).is_ok()
}

/// Whether `parsed` is a ClickHouse rejection of the query's SQL or of the
/// values it read, mapped to a variant that otherwise logs at WARN.
///
/// Internal variants (database, unavailable, timeout) already log at ERROR
/// wherever they surface; size limits (`ResourceLimit`, `ResponseTooLarge`)
/// come from an oversized query and stay at WARN; a cancel is deliberate.
fn is_query_rejection(parsed: &SearchError) -> bool {
    matches!(
        parsed,
        SearchError::SqlValidationError(_)
            | SearchError::FieldNotFound { .. }
            | SearchError::DataError { .. }
    )
}

/// Log a ClickHouse rejection of nano-generated SQL at ERROR (see the module
/// docs). Returns whether it logged, for tests.
pub(crate) fn report(parsed: &SearchError, raw: &dyn std::fmt::Display) -> bool {
    if !is_query_rejection(parsed) || is_user_authored() {
        return false;
    }
    // NAN-5432: raw ClickHouse text can quote stored values byte for byte;
    // log it as one inert line.
    let raw = crate::db::pg_text::pg_safe_error_text(&raw.to_string());
    tracing::error!(
        error = %parsed,
        raw = %raw,
        "ClickHouse rejected nano-generated search SQL"
    );
    true
}
