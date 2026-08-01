// SPDX-License-Identifier: AGPL-3.0-or-later

//! Helper functions for pretty-printing.

/// Serialize `s` as a COMPLETE nPL string literal — delimiters included —
/// choosing the quote style that carries the value without altering it.
///
/// Every attacker-controlled string the pretty-printer emits (keyword, field
/// name, filter value, `rex` pattern, eval literal) is written as a quoted
/// literal. nPL has TWO interchangeable literal forms and the parser accepts
/// either everywhere it accepts a quoted string (`values::quoted_string` is
/// `alt((double_quoted_string, single_quoted_string))`):
///
///  * `"…"` — `take_while(|c| c != '"')`, so `"` is the ONLY terminator;
///  * `'…'` — `take_while(|c| c != '\'')`, so `'` is the ONLY terminator.
///
/// Neither has a working backslash escape (deliberate — NAN-1157: `\"` is not
/// an escape, which is what lets `"C:\Windows\System32\"` parse). Every other
/// character (`|`, `(`, `)`, backtick, `[`, `]`, newline, and the *other* quote
/// character) is inert INSIDE the literal.
///
/// So the delimiter is picked from the content:
///
///  * no `"` in the value → `"…"`. This is the overwhelmingly common case and
///    is byte-identical to what this helper has always emitted.
///  * value contains `"` but no `'` → `'…'`. The `"` is inert inside a
///    single-quoted literal, so it survives VERBATIM and still cannot break
///    out. This is NAN-2241: the previous unconditional `"`-strip silently
///    rewrote a user's `rex` pattern — `[^"]+` became `[^]+`, a different
///    regex that matches nothing — and the query then ran and returned empty
///    results with no error.
///  * value contains BOTH `"` and `'` → not representable in nPL at all.
///    UNREACHABLE from a parsed query: every string in the AST comes from
///    `quoted_string` (one delimiter, so the other quote can appear but never
///    the delimiter itself), `unquoted_string` / `unquoted_keyword` /
///    `field_name` (no quote characters at all), or codegen. See the
///    `both_quote_kinds_*` tests. Handled as the pre-NAN-2241 behaviour —
///    double-quote and drop the `"` — which is safe (no breakout) though
///    lossy; it cannot be reached by user input.
///
/// Keeping `|`, backtick and parentheses — unlike the unquoted-context
/// [`crate::query::sanitize_npl_quoted_value`] — is what lets legitimate values
/// (`cmd|powershell`) and `rex` regexes (`(foo|bar)`) round-trip faithfully.
/// Structure preservation across `parse(pretty_print(x))` is the property that
/// closes the source-scope round-trip bypass (NAN-2006 / F1,F2,F4,F5,F6,F7,F9);
/// `enforce_source_scope`'s fail-closed structural re-check is the backstop.
///
/// Newlines are dropped so the serialized query stays a single line (they are
/// inert inside a literal, so this is presentational, not a security measure).
///
/// Backslashes are doubled (NAN-2184). The parser collapses `\\` → `\` after
/// taking the literal, so a value carrying CONSECUTIVE backslashes otherwise
/// loses one on the way back in: `\\fileserver\share` re-parsed as
/// `\fileserver\share`, and a `rex` pattern matching a literal backslash
/// (`\\.`) re-parsed as `\.`. A lone backslash is unaffected either way —
/// which is why Windows paths looked fine and this went unnoticed.
///
/// Callers must NOT add their own quotes — the result already carries them.
pub(crate) fn npl_quoted_literal(s: &str) -> String {
    let delimiter = if !s.contains('"') {
        '"'
    } else if !s.contains('\'') {
        '\''
    } else {
        // Unrepresentable (see the doc comment) — keep the historical shape.
        '"'
    };

    let mut out = String::with_capacity(s.len() + 2);
    out.push(delimiter);
    for c in s.chars() {
        match c {
            // The chosen delimiter is absent from `s` except in the
            // unrepresentable both-quote-kinds case, where dropping it is the
            // pre-existing behaviour and keeps the literal un-breakable-out-of.
            c if c == delimiter => {}
            '\n' | '\r' => {}
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push(delimiter);
    out
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
