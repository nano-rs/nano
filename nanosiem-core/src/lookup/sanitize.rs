// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identifier sanitization for lookup-table column names.
//!
//! CSV/JSON headers from real-world files (Salesforce exports, Excel saves,
//! etc.) routinely contain spaces, capitalization, and punctuation that the
//! strict `is_valid_identifier` validator in `repository` rejects. We can't
//! relax that validator — nPL queries reference columns by unquoted
//! identifier, so a column named `Customer Id` would be unaddressable.
//!
//! Instead, we normalize headers on upload: lowercase, replace runs of
//! non-alphanumeric chars with `_`, trim, and disambiguate collisions.
//! The resulting identifier is what gets persisted; the original header is
//! returned to the client so it can surface what was renamed.
//!
//! See NAN-513.

use std::collections::HashMap;

/// Postgres identifier limit; matches the cap in `is_valid_identifier`.
const MAX_IDENT_LEN: usize = 63;

/// Sanitize a single raw header into a safe SQL identifier.
///
/// Rules:
/// - Lowercase
/// - Non-alphanumeric runs collapse to a single `_`
/// - Leading non-letter chars get a `col_` prefix
/// - Trailing `_` stripped
/// - Truncated to 63 chars
/// - Empty result becomes `col`
///
/// This produces a valid identifier per `is_valid_identifier`; collision
/// handling is the caller's responsibility — see [`sanitize_identifiers`].
pub fn sanitize_identifier(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut prev_separator = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_separator = false;
        } else if ch == '_' {
            // Underscores are valid identifier chars; collapse runs but keep them
            // (`_internal` should stay `_internal`, not become `internal`).
            if !prev_separator {
                out.push('_');
                prev_separator = true;
            }
        } else if !prev_separator && !out.is_empty() {
            // Other non-alnum chars become separators, but skip leading ones so
            // `  foo` doesn't pick up a spurious leading `_`.
            out.push('_');
            prev_separator = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        return "col".to_string();
    }
    let first = out.chars().next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        out.insert_str(0, "col_");
    }
    if out.len() > MAX_IDENT_LEN {
        out.truncate(MAX_IDENT_LEN);
        while out.ends_with('_') {
            out.pop();
        }
    }
    out
}

/// Sanitize a list of raw headers, returning a map `original → sanitized` with
/// collision-disambiguation suffixes (`_2`, `_3`, …) applied stably in input
/// order. Order matters: the same `raw` always maps to the same sanitized
/// name *given the same neighbors*.
pub fn sanitize_identifiers<I, S>(raw_names: I) -> HashMap<String, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut taken: HashMap<String, usize> = HashMap::new();
    let mut out: HashMap<String, String> = HashMap::new();
    for raw in raw_names {
        let raw_owned: String = raw.into();
        if out.contains_key(&raw_owned) {
            continue;
        }
        let base = sanitize_identifier(&raw_owned);
        let next = match taken.get(&base).copied() {
            None => {
                taken.insert(base.clone(), 1);
                base
            }
            Some(n) => {
                let mut candidate;
                let mut i = n + 1;
                loop {
                    candidate = format!("{}_{}", base, i);
                    if !taken.contains_key(&candidate) {
                        break;
                    }
                    i += 1;
                }
                taken.insert(base.clone(), i);
                taken.insert(candidate.clone(), 1);
                candidate
            }
        };
        out.insert(raw_owned, next);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercase_simple() {
        assert_eq!(sanitize_identifier("City"), "city");
        assert_eq!(sanitize_identifier("Email"), "email");
    }

    #[test]
    fn spaces_become_underscores() {
        assert_eq!(sanitize_identifier("Customer Id"), "customer_id");
        assert_eq!(sanitize_identifier("First Name"), "first_name");
        assert_eq!(sanitize_identifier("Phone 1 (Mobile)"), "phone_1_mobile");
    }

    #[test]
    fn collapses_runs_of_punctuation() {
        assert_eq!(sanitize_identifier("foo  bar"), "foo_bar");
        assert_eq!(sanitize_identifier("foo--bar"), "foo_bar");
        assert_eq!(sanitize_identifier("a.b.c"), "a_b_c");
    }

    #[test]
    fn strips_trailing_separators() {
        assert_eq!(sanitize_identifier("foo "), "foo");
        assert_eq!(sanitize_identifier("foo___"), "foo");
        assert_eq!(sanitize_identifier("foo!"), "foo");
    }

    #[test]
    fn prefixes_leading_non_letter() {
        assert_eq!(sanitize_identifier("2nd Address"), "col_2nd_address");
        assert_eq!(sanitize_identifier("123"), "col_123");
        assert_eq!(sanitize_identifier("_internal"), "_internal");
    }

    #[test]
    fn empty_becomes_col() {
        assert_eq!(sanitize_identifier(""), "col");
        assert_eq!(sanitize_identifier("!!!"), "col");
        assert_eq!(sanitize_identifier("   "), "col");
    }

    #[test]
    fn truncates_to_63_chars() {
        let long = "a".repeat(80);
        let result = sanitize_identifier(&long);
        assert!(result.len() <= 63);
        assert!(result.starts_with('a'));
    }

    #[test]
    fn collision_disambiguation() {
        let map = sanitize_identifiers(vec!["Customer Id", "customer_id", "Customer  Id"]);
        let v1 = &map["Customer Id"];
        let v2 = &map["customer_id"];
        let v3 = &map["Customer  Id"];
        let mut all: Vec<&String> = vec![v1, v2, v3];
        all.sort();
        assert_eq!(
            all,
            vec![
                &"customer_id".to_string(),
                &"customer_id_2".to_string(),
                &"customer_id_3".to_string(),
            ],
        );
    }

    #[test]
    fn passes_validator() {
        // Sanitized names must satisfy the same constraints as is_valid_identifier:
        // non-empty, ≤ 63 chars, leading letter/underscore, alphanumeric/underscore body.
        for raw in [
            "City",
            "Customer Id",
            "First Name",
            "2nd Address",
            "phone (mobile)",
            "",
            "!!!",
            "weird@name#with$chars",
        ] {
            let s = sanitize_identifier(raw);
            assert!(!s.is_empty());
            assert!(s.len() <= 63);
            let first = s.chars().next().unwrap();
            assert!(
                first.is_ascii_alphabetic() || first == '_',
                "leading char invalid for {:?} → {:?}",
                raw,
                s
            );
            assert!(
                s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "body invalid for {:?} → {:?}",
                raw,
                s
            );
        }
    }

    #[test]
    fn idempotent_on_clean_input() {
        for raw in ["city", "customer_id", "_internal", "foo123"] {
            assert_eq!(sanitize_identifier(raw), raw);
        }
    }
}
