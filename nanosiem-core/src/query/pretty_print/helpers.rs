// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for pretty-printing.

/// Strip the only characters that can break out of an nPL double-quoted string
/// literal when serializing an AST back to query text.
///
/// Every attacker-controlled string the pretty-printer emits (keyword, field
/// name, filter value, `rex` pattern, eval literal) is written inside `"…"`.
/// The parser's `double_quoted_string` is `take_while(|c| c != '"')` with NO
/// working backslash escape (deliberate — NAN-1157): the FIRST `"` always
/// terminates the literal and every other character (`|`, `(`, `)`, backtick,
/// `[`, `]`, …) is inert *inside* the quotes. The lone breakout character is
/// therefore `"`; removing it (plus newlines, so the serialized query stays a
/// single line) makes `parse(pretty_print(x))` structure-preserving and closes
/// the source-scope round-trip bypass (NAN-2006 / F1,F2,F4,F5,F6,F7,F9).
///
/// This deliberately KEEPS `|`, backtick and parentheses — unlike the
/// unquoted-context [`crate::query::sanitize_npl_quoted_value`] — so legitimate
/// values (`cmd|powershell`) and `rex` regexes (`(foo|bar)`) round-trip
/// faithfully. `enforce_source_scope`'s fail-closed structural re-check is the
/// backstop for anything this leaves.
///
/// Callers MUST wrap the result in double quotes.
pub(crate) fn npl_quoted_body(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '"' | '\n' | '\r')).collect()
}

/// Canonical `dataset=` selector string for a cross-dataset subsearch (NAN-1562).
/// Round-trips through [`Dataset::from_selector`].
pub(crate) fn dataset_selector_str(
    ds: crate::query::clickhouse_sql_gen::otel::Dataset,
) -> &'static str {
    use crate::query::clickhouse_sql_gen::otel::Dataset;
    match ds {
        Dataset::Logs => "logs",
        Dataset::Spans => "spans",
        Dataset::Metrics => "metrics",
        Dataset::Risk => "risk",
    }
}

/// Format duration as a human-readable string (1h, 5m, 30s, etc.)
pub(crate) fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs % 86400 == 0 {
        format!("{}d", secs / 86400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}
