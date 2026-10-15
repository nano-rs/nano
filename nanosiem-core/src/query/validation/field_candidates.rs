// SPDX-License-Identifier: AGPL-3.0-or-later

//! Text-level field-name candidates for the rule validators.
//!
//! `/api/rules/validate` (dedicated and shared) flags every `name` followed by a
//! comparator (`=`, `!`, `<`, `>`) that the active schema does not know. That
//! scan runs over the raw query text, so it must not look inside string or
//! regex literals: `process.cmd_line CONTAINS "/LogFile="` put `LogFile` on the
//! unknown-field list (installutil_execution), and so would a regex literal such
//! as `f=/user=admin/`.

use std::sync::OnceLock;

/// Replace the contents of every string literal (`"…"`, `'…'`, honoring `\`
/// escapes) and every regex literal (`/…/` that opens right after a comparator,
/// `(` or `,`) with spaces. Delimiters are kept and byte offsets are preserved.
pub fn mask_query_literals(query: &str) -> String {
    let bytes = query.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0;
    // The last significant (non-whitespace) byte outside any literal: decides
    // whether a `/` opens a regex literal or is a division / path operator.
    let mut last_significant: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        let opens_regex = b == b'/' && matches!(last_significant, Some(b'=' | b'(' | b',' | b'~'));
        if b == b'"' || b == b'\'' || opens_regex {
            let close = b;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != close {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    // Mask the escape and the escaped byte together, but never
                    // split a UTF-8 sequence: only ASCII bytes become spaces.
                    if bytes[j].is_ascii() {
                        out[j] = b' ';
                    }
                    j += 1;
                }
                if bytes[j].is_ascii() {
                    out[j] = b' ';
                }
                j += 1;
            }
            i = j + 1;
            last_significant = Some(b'"');
            continue;
        }
        if !b.is_ascii_whitespace() {
            last_significant = Some(b);
        }
        i += 1;
    }
    // Only ASCII bytes were replaced (by ASCII), so the result stays UTF-8.
    String::from_utf8(out).unwrap_or_else(|_| query.to_string())
}

/// Every `name` / `dotted.name` directly followed by a comparator, in first-seen
/// order, ignoring anything inside string and regex literals.
pub fn extract_comparator_field_candidates(query: &str) -> Vec<String> {
    static FIELD_REGEX: OnceLock<regex::Regex> = OnceLock::new();
    let field_regex = FIELD_REGEX.get_or_init(|| {
        regex::Regex::new(r#"(?:^|[^\w.])([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)*)\s*[=!<>]"#)
            .expect("field extraction regex is valid")
    });
    let masked = mask_query_literals(query);
    let mut out: Vec<String> = Vec::new();
    for cap in field_regex.captures_iter(&masked) {
        if let Some(field) = cap.get(1) {
            let name = field.as_str().to_string();
            if !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_literal_contents_are_not_fields() {
        let query = r#"| where process.cmd_line CONTAINS "Temp" OR process.cmd_line CONTAINS "/U" OR process.cmd_line CONTAINS "/LogFile=""#;
        assert!(extract_comparator_field_candidates(query).is_empty());
        let query = r#"class_uid=1007 | where process.name="InstallUtil.exe" | where process.cmd_line CONTAINS "/LogFile=""#;
        assert_eq!(
            extract_comparator_field_candidates(query),
            vec!["class_uid", "process.name"]
        );
    }

    #[test]
    fn single_quotes_escapes_and_regex_literals_are_masked() {
        assert_eq!(
            extract_comparator_field_candidates(r#"a='x=1' b="say \"k=v\"" c=/user=admin/i d>2"#),
            vec!["a", "b", "c", "d"]
        );
        assert_eq!(
            extract_comparator_field_candidates(
                r#"| eval x=if(match(p, "k=v"), 1, 0) | where n > 2/3"#
            ),
            vec!["x", "n"]
        );
    }

    #[test]
    fn masking_keeps_offsets_and_utf8() {
        let query = r#"user="é=ü" AND host="h""#;
        let masked = mask_query_literals(query);
        assert_eq!(masked.len(), query.len());
        assert_eq!(
            extract_comparator_field_candidates(query),
            vec!["user", "host"]
        );
    }
}
