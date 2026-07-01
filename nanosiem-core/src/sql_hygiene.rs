//! Shared SQL-literal hygiene helpers (NAN-1616).
//!
//! Consolidates the escaping/formatting logic that was previously copy-pasted
//! across the query SQL generator, search service, prevalence, lookup, and
//! field-stats paths. Centralising it keeps the ClickHouse string-literal
//! escaping rules in one auditable place — these functions are
//! security-relevant (SQL-injection surface), so divergent copies are a
//! liability.
//!
//! The single string-literal escaper is [`escape_sql_string`]: it escapes
//! backslashes *and* doubles single quotes. Backslash is itself an escape
//! character inside a ClickHouse string literal, so any value embedded in a
//! `'…'` literal MUST have its backslashes escaped — otherwise a value such as
//! a Windows path (`C:\Users`) or a `\'` sequence corrupts/breaks the literal
//! (a correctness bug and an injection-adjacent surface).
//!
//! NAN-1620 removed the historical quote-only escaper (`escape_sql_quotes`):
//! there is no legitimate reason to skip backslash escaping for a value going
//! into a CH string literal. Every former caller (prevalence hashes/IPs/domains,
//! search free-text, query ids, field-stats table names) now routes through
//! [`escape_sql_string`]. For constrained tokens (hashes, IPs) a backslash can
//! never legitimately appear, so escaping it is a harmless no-op; for free-text
//! search values it is the actual fix.
//!
//! LIKE/ILIKE *pattern* escaping (the `%`/`_` wildcard semantics) is a
//! separate concern handled by [`escape_like_pattern`] and is unchanged.

use chrono::{DateTime, Utc};

/// Escape a string for a ClickHouse string literal: backslashes first, then
/// single quotes (`\` → `\\`, then `'` → `''`).
///
/// The backslash pass MUST run before the quote pass, otherwise `\'` would
/// become `''''` instead of `\\''`.
pub fn escape_sql_string(s: impl AsRef<str>) -> String {
    s.as_ref().replace('\\', "\\\\").replace('\'', "''")
}

/// Escape a raw string for use in a ClickHouse `LIKE`/`ILIKE` pattern.
///
/// Escapes the LIKE wildcards (`%` and `_`) and backslashes, then doubles
/// single quotes for the surrounding string literal. Takes a RAW (un-escaped)
/// string. (The query SQL generator has a separate second-layer LIKE escaper
/// in `clickhouse_sql_gen::helpers` that operates on already-SQL-escaped input
/// — they are intentionally different and not merged; see NAN-1157.)
pub(crate) fn escape_like_pattern(s: impl AsRef<str>) -> String {
    s.as_ref()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''")
}

/// Format a UTC instant as a ClickHouse `timestamp BETWEEN`/comparison bound
/// with microsecond precision (`%Y-%m-%d %H:%M:%S%.6f`).
pub(crate) fn format_ch_bound_micros(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

/// Format a UTC instant as a ClickHouse bound with second precision
/// (`%Y-%m-%d %H:%M:%S`).
pub(crate) fn format_ch_bound(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_string_escapes_backslash_then_quote() {
        assert_eq!(escape_sql_string("it's"), "it''s");
        assert_eq!(escape_sql_string(r"a\b"), r"a\\b");
        // backslash escaped before quote: `\'` -> `\\''`
        assert_eq!(escape_sql_string("\\'"), "\\\\''");
    }

    #[test]
    fn sql_string_escapes_backslash_only_inputs() {
        // No backslash / no quote: identical to the old quote-only behaviour,
        // so existing SQL-asserting tests are unaffected.
        assert_eq!(escape_sql_string("plain"), "plain");
        // Windows path: each backslash is doubled (NAN-1620 fix).
        assert_eq!(escape_sql_string(r"C:\Users\admin"), r"C:\\Users\\admin");
        // Mixed backslash + single quote in one value.
        assert_eq!(escape_sql_string(r"O'Brien\path"), r"O''Brien\\path");
    }

    #[test]
    fn like_pattern_escapes_wildcards_and_quotes() {
        assert_eq!(escape_like_pattern("100%_x"), "100\\%\\_x");
        assert_eq!(escape_like_pattern(r"a\b"), r"a\\b");
        assert_eq!(escape_like_pattern("o'k"), "o''k");
    }

    #[test]
    fn ch_bounds_format() {
        let dt = DateTime::parse_from_rfc3339("2026-06-30T12:34:56.123456Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(format_ch_bound_micros(&dt), "2026-06-30 12:34:56.123456");
        assert_eq!(format_ch_bound(&dt), "2026-06-30 12:34:56");
    }
}
