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
//!
//! # Identifiers are not values (NAN-1992 / NAN-2158)
//!
//! Everything above is about VALUES — text that lands inside a `'…'` literal.
//! A column or table NAME lands *outside* any literal, so value escaping does
//! nothing for it: `escape_sql_string("source_type) = 'audit' --")` is a no-op,
//! and the result still closes the surrounding expression and comments out
//! whatever follows — including a security predicate appended to the same line.
//! This module offered only value escaping, which is exactly why the identifier
//! class kept recurring. Use [`is_safe_sql_identifier`] to reject, or
//! [`escape_sql_identifier`] to quote, ANY identifier that is not a
//! compile-time constant.

use chrono::{DateTime, Utc};

/// Escape a string for a ClickHouse string literal: backslashes first, then
/// single quotes (`\` → `\\`, then `'` → `''`).
///
/// The backslash pass MUST run before the quote pass, otherwise `\'` would
/// become `''''` instead of `\\''`.
pub fn escape_sql_string(s: impl AsRef<str>) -> String {
    s.as_ref().replace('\\', "\\\\").replace('\'', "''")
}

/// Maximum length accepted for a SQL identifier by [`is_safe_sql_identifier`].
///
/// ClickHouse itself is far more permissive; this is a sanity bound so a
/// pathological stored value cannot balloon generated SQL.
const MAX_IDENTIFIER_LEN: usize = 128;

/// Is `s` usable as a BARE (unquoted) ClickHouse column/table identifier in
/// generated SQL? (NAN-1992 / NAN-2158)
///
/// Deliberately strict: ASCII alphanumerics, `_`, and the `.` that OCSF nested
/// columns need (`metadata.product.name`). No quotes, no backticks, no
/// parentheses, no whitespace, no `-`, and therefore no `--`/`/*` comment
/// introducer — so an interpolated value can neither terminate the surrounding
/// expression nor comment out what follows it.
///
/// This is an ALLOWLIST, not an escaper: prefer rejecting a bad identifier at
/// the write boundary and again at the sink. [`escape_sql_identifier`] exists
/// for the cases where a legitimately exotic name must be preserved.
///
/// Callers must apply this to anything that is not a compile-time constant —
/// including values read back out of PostgreSQL, which are attacker-influenced
/// whenever a user can write the row (the NAN-2158 second-order case).
pub fn is_safe_sql_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_IDENTIFIER_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Quote `s` as a ClickHouse identifier, escaping the quoting character.
///
/// ClickHouse quotes identifiers with backticks; a literal backtick inside is
/// escaped with a backslash, and a literal backslash is doubled. Backslash is
/// processed FIRST for the same reason as [`escape_sql_string`] — otherwise an
/// escaped backtick would be re-escaped into a broken sequence.
///
/// Prefer [`is_safe_sql_identifier`] + a bare identifier where the surrounding
/// SQL already expects one. Reach for this only where an identifier must be
/// preserved verbatim, and note that backtick-quoting CHANGES SEMANTICS for
/// dotted names: bare `a.b.c` is a compound/nested reference, whereas
/// `` `a.b.c` `` is a single column literally named `a.b.c`. Those are different
/// columns in ClickHouse, so do not swap one form for the other in existing SQL
/// without checking which the schema actually has.
pub fn escape_sql_identifier(s: impl AsRef<str>) -> String {
    format!(
        "`{}`",
        s.as_ref().replace('\\', "\\\\").replace('`', "\\`")
    )
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

/// Expand Grafana-style time macros in a raw SQL panel query against a dashboard
/// window (DSH60 / NAN-1719). This is the safe, opt-in alternative to rewriting
/// arbitrary user SQL: the author places a macro where a predicate/literal
/// belongs, so it works in any clause (WHERE/HAVING/JOIN) and with aggregate or
/// projection panels alike — unlike wrapping the query in an outer
/// `WHERE timestamp …`, which breaks the moment the inner SELECT projects no
/// `timestamp` column.
///
/// Recognised macros (case-sensitive, `$__` prefix per Grafana convention):
/// - `$__timeFilter(col)` → `(col BETWEEN '<start>' AND '<end>')`
/// - `$__timeFilter`      → `(timestamp BETWEEN '<start>' AND '<end>')` (bare form
///   defaults to the canonical `timestamp` column)
/// - `$__timeFrom`        → `'<start>'`
/// - `$__timeTo`          → `'<end>'`
///
/// Substitution is QUOTE-AWARE: a macro inside a `'…'`, `"…"`, or `` `…` `` literal
/// is left untouched, so a query that legitimately searches for the literal text
/// `$__timeFrom` is never corrupted. SQL containing none of these tokens is
/// returned byte-for-byte unchanged. An unrecognised `$__time…` sequence is left
/// as-is (it is invalid SQL and fails loudly rather than silently mis-filtering).
///
/// The injected timestamp literals come from the dashboard window, never from
/// user input, so there is no injection surface here.
pub fn expand_sql_time_macros(sql: &str, start: &DateTime<Utc>, end: &DateTime<Utc>) -> String {
    // Fast path: no macro token present -> return the input unchanged.
    if !sql.contains("$__time") {
        return sql.to_string();
    }
    let start_lit = format_ch_bound_micros(start);
    let end_lit = format_ch_bound_micros(end);

    let mut out = String::with_capacity(sql.len() + 64);
    let mut chars = sql.char_indices().peekable();
    let mut quote: Option<char> = None;

    while let Some((i, c)) = chars.next() {
        // Inside a string / quoted-identifier literal: copy verbatim, never
        // substitute, and track the closing delimiter (handling `\x` backslash
        // escapes and doubled-quote `''`/`""` escapes).
        if let Some(q) = quote {
            out.push(c);
            if c == '\\' {
                if let Some((_, n)) = chars.next() {
                    out.push(n);
                }
            } else if c == q {
                if chars.peek().map(|&(_, n)| n) == Some(q) {
                    let (_, n) = chars.next().unwrap();
                    out.push(n);
                } else {
                    quote = None;
                }
            }
            continue;
        }

        if c == '\'' || c == '"' || c == '`' {
            quote = Some(c);
            out.push(c);
            continue;
        }

        if c == '$' {
            if let Some((consumed, replacement)) = match_time_macro(&sql[i..], &start_lit, &end_lit)
            {
                out.push_str(&replacement);
                let target = i + consumed;
                while let Some(&(j, _)) = chars.peek() {
                    if j < target {
                        chars.next();
                    } else {
                        break;
                    }
                }
                continue;
            }
        }

        out.push(c);
    }
    out
}

/// Match a single `$__time*` macro at the start of `rest` (which begins with
/// `$`). Returns `(bytes_consumed, replacement)`, or `None` when it is not a
/// recognised macro.
fn match_time_macro(rest: &str, start_lit: &str, end_lit: &str) -> Option<(usize, String)> {
    const FILTER: &str = "$__timeFilter";
    const FROM: &str = "$__timeFrom";
    const TO: &str = "$__timeTo";

    if let Some(after) = rest.strip_prefix(FILTER) {
        if let Some(arg) = after.strip_prefix('(') {
            // Balanced-paren scan so a function-call column arg
            // (e.g. `toDateTime(ts)`) is captured whole. QUOTE-AWARE: a paren
            // inside a string / quoted-identifier literal in the arg (e.g.
            // `JSONExtractString(ext, 'a)b')`) must NOT be treated as the macro's
            // closing paren — same quote handling as the outer scanner.
            let mut depth = 1usize;
            let mut close = None;
            let mut quote: Option<char> = None;
            let mut it = arg.char_indices().peekable();
            while let Some((bi, ch)) = it.next() {
                if let Some(q) = quote {
                    if ch == '\\' {
                        it.next();
                    } else if ch == q {
                        if it.peek().map(|&(_, n)| n) == Some(q) {
                            it.next();
                        } else {
                            quote = None;
                        }
                    }
                    continue;
                }
                match ch {
                    '\'' | '"' | '`' => quote = Some(ch),
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(bi);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let close = close?;
            let col = arg[..close].trim();
            let col = if col.is_empty() { "timestamp" } else { col };
            // consumed = "$__timeFilter" + "(" + arg + ")"
            let consumed = FILTER.len() + 1 + close + 1;
            return Some((
                consumed,
                format!("({} BETWEEN '{}' AND '{}')", col, start_lit, end_lit),
            ));
        }
        if !starts_with_ident_char(after) {
            return Some((
                FILTER.len(),
                format!("(timestamp BETWEEN '{}' AND '{}')", start_lit, end_lit),
            ));
        }
        return None;
    }

    if let Some(after) = rest.strip_prefix(FROM) {
        if !starts_with_ident_char(after) {
            return Some((FROM.len(), format!("'{}'", start_lit)));
        }
        return None;
    }

    if let Some(after) = rest.strip_prefix(TO) {
        if !starts_with_ident_char(after) {
            return Some((TO.len(), format!("'{}'", end_lit)));
        }
        return None;
    }

    None
}

/// True when the next char would extend an identifier, so a longer token like
/// `$__timeFromX` is NOT treated as the `$__timeFrom` macro.
fn starts_with_ident_char(s: &str) -> bool {
    s.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
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

    // ---- NAN-2158: identifier hygiene ------------------------------------

    #[test]
    fn safe_identifier_accepts_real_column_names() {
        for ok in [
            "source_type",
            "host",
            "metadata.product.name",
            "src_endpoint.ip",
            "ext",
            "a1_B2",
        ] {
            assert!(is_safe_sql_identifier(ok), "should accept {ok}");
        }
    }

    #[test]
    fn safe_identifier_rejects_every_expression_breakout() {
        for bad in [
            // The NAN-2158 payload: closes `lower(` and comments out the rest
            // of the line, including any appended security predicate.
            "source_type) = 'audit' --",
            "source_type)/*",
            "source_type; DROP TABLE logs",
            "source_type OR 1=1",
            "`source_type`",
            "'source_type'",
            "source type",
            "source\ttype",
            "source\ntype",
            "source-type",
            "",
        ] {
            assert!(!is_safe_sql_identifier(bad), "should reject {bad:?}");
        }
        // Length bound.
        assert!(!is_safe_sql_identifier(&"a".repeat(MAX_IDENTIFIER_LEN + 1)));
        assert!(is_safe_sql_identifier(&"a".repeat(MAX_IDENTIFIER_LEN)));
    }

    #[test]
    fn identifier_escaping_neutralizes_the_backtick_breakout() {
        assert_eq!(escape_sql_identifier("source_type"), "`source_type`");
        // A backtick in the input must not close the quoting early — that is
        // the identifier-side equivalent of an unescaped `'` in a literal.
        assert_eq!(
            escape_sql_identifier("a`) = 'audit' --"),
            "`a\\`) = 'audit' --`"
        );
        // Backslash is doubled, and processed BEFORE the backtick pass.
        assert_eq!(escape_sql_identifier(r"a\b"), r"`a\\b`");
        assert_eq!(escape_sql_identifier("a\\`b"), "`a\\\\\\`b`");
    }

    #[test]
    fn value_escaping_does_nothing_for_the_identifier_payload() {
        // The regression that motivated splitting the two: the value escaper
        // leaves the identifier payload completely intact, which is why it was
        // never a defense here.
        let payload = "source_type) = 'x' --";
        assert!(escape_sql_string(payload).contains("--"));
        assert!(escape_sql_string(payload).contains(')'));
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

    fn win() -> (DateTime<Utc>, DateTime<Utc>) {
        let s = DateTime::parse_from_rfc3339("2026-07-06T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let e = DateTime::parse_from_rfc3339("2026-07-06T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        (s, e)
    }

    #[test]
    fn time_macros_macro_free_sql_is_unchanged() {
        let (s, e) = win();
        // No token at all: byte-for-byte identical (and no `$__time` anywhere).
        let sql = "SELECT src_ip, count(*) FROM logs WHERE dest_port = 443 GROUP BY src_ip";
        assert_eq!(expand_sql_time_macros(sql, &s, &e), sql);
    }

    #[test]
    fn time_macros_filter_with_column_and_bare_and_from_to() {
        let (s, e) = win();
        let lo = "2026-07-06 00:00:00.000000";
        let hi = "2026-07-06 01:00:00.000000";

        assert_eq!(
            expand_sql_time_macros("SELECT 1 FROM logs WHERE $__timeFilter(timestamp)", &s, &e),
            format!("SELECT 1 FROM logs WHERE (timestamp BETWEEN '{lo}' AND '{hi}')")
        );
        // Bare form defaults to the canonical `timestamp` column.
        assert_eq!(
            expand_sql_time_macros("SELECT 1 FROM logs WHERE $__timeFilter", &s, &e),
            format!("SELECT 1 FROM logs WHERE (timestamp BETWEEN '{lo}' AND '{hi}')")
        );
        assert_eq!(
            expand_sql_time_macros("SELECT $__timeFrom, $__timeTo", &s, &e),
            format!("SELECT '{lo}', '{hi}'")
        );
        // Works in the exact aggregate case the outer-wrapper approach breaks.
        assert_eq!(
            expand_sql_time_macros(
                "SELECT src_ip, count(*) FROM logs WHERE $__timeFilter(timestamp) GROUP BY src_ip",
                &s,
                &e
            ),
            format!("SELECT src_ip, count(*) FROM logs WHERE (timestamp BETWEEN '{lo}' AND '{hi}') GROUP BY src_ip")
        );
    }

    #[test]
    fn time_macros_column_arg_allows_function_calls() {
        let (s, e) = win();
        let lo = "2026-07-06 00:00:00.000000";
        let hi = "2026-07-06 01:00:00.000000";
        // Balanced-paren scan keeps a function-call column arg whole.
        assert_eq!(
            expand_sql_time_macros("WHERE $__timeFilter(toDateTime(timestamp))", &s, &e),
            format!("WHERE (toDateTime(timestamp) BETWEEN '{lo}' AND '{hi}')")
        );
        // A ')' inside a string literal in the arg must NOT close the macro early.
        assert_eq!(
            expand_sql_time_macros("WHERE $__timeFilter(f(x, ')'))", &s, &e),
            format!("WHERE (f(x, ')') BETWEEN '{lo}' AND '{hi}')")
        );
    }

    #[test]
    fn time_macros_are_not_substituted_inside_string_literals() {
        let (s, e) = win();
        // A query hunting for the LITERAL text `$__timeFrom` must be preserved.
        let sql = "SELECT * FROM logs WHERE message = '$__timeFrom'";
        assert_eq!(expand_sql_time_macros(sql, &s, &e), sql);
        // Doubled-quote escape inside the literal must not end the string early.
        let sql2 = "SELECT * FROM logs WHERE message = 'it''s $__timeTo here'";
        assert_eq!(expand_sql_time_macros(sql2, &s, &e), sql2);
    }

    #[test]
    fn time_macros_respect_identifier_boundary() {
        let (s, e) = win();
        // `$__timeFromm` is a longer token, not the `$__timeFrom` macro.
        let sql = "SELECT $__timeFromm FROM logs";
        assert_eq!(expand_sql_time_macros(sql, &s, &e), sql);
    }
}
