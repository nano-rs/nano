// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bare keywords carrying `*` / `?`: term semantics (NAN-3041).
//!
//! Kept out of `helpers.rs`; this module only composes its helpers (the
//! single nPL lowercase match `ci_like`, NAN-4943).

use super::helpers::{
    bare_keyword_predicate, ch_lower, ci_like, escape_regex_pattern, wildcard_to_like_pattern,
};

/// The predicate for a bare keyword over the profile's body columns.
///
/// A keyword with `*`/`?` follows Splunk TERM semantics: `svch*` matches any
/// term that STARTS with `svch` (`svchost.exe` anywhere in the body),
/// `*host.exe` any term that ends with it, `svc*exe` a term that starts `svc`
/// and ends `exe`. The plain lowering was a whole-value `iLike 'svch%'`, which
/// only matched when the ENTIRE message/raw_data began with `svch`.
///
/// Every other keyword (no wildcard, or `*kw*` substring form) keeps
/// [`bare_keyword_predicate`] unchanged.
pub(crate) fn keyword_predicate(kw: &str, cols: &[&str]) -> String {
    // ClickHouse `lower()` semantics (ASCII only), as everywhere in nPL.
    let lowered = ch_lower(kw);
    if !lowered.contains(['*', '?']) {
        return bare_keyword_predicate(kw, cols);
    }
    let legs: Vec<String> = cols
        .iter()
        .map(|col| wildcard_keyword_predicate_for_column(&lowered, col))
        .collect();
    match legs.as_slice() {
        [one] => one.clone(),
        _ => format!("({})", legs.join(" OR ")),
    }
}

/// Emitted as `<lower(col) LIKE '%<pieces>%'> AND match(col, <term regex>)`:
/// - the guard is the substring form ([`ci_like`], `lower(col) LIKE`),
///   implied by the term match (so it never drops a row), and keeps the
///   `lower(col)` text index serving it;
/// - NAN-4943: the term regex runs on `lower(col)` WITHOUT `(?i)`, so its case
///   folding is ClickHouse `lower()`'s (ASCII only) — the same lowercase match
///   as every other nPL pattern, and the `[a-z0-9]` boundary class sees only
///   lowered ASCII (RE2 `(?i)` would also fold U+212A KELVIN SIGN into it);
/// - the regex adds the term boundaries. A boundary is a character outside
///   `[a-z0-9]` (the `splitByNonAlpha` token rule) and is only required on a
///   side that does not end in `*` and whose needle character is alphanumeric
///   or `?`. Inside the term, `*` spans any non-whitespace run and `?` one
///   term character.
///
/// `*kw*` (wildcards on both ends only) needs no boundary and stays the plain
/// substring form (NAN-3034).
fn wildcard_keyword_predicate_for_column(lowered: &str, col: &str) -> String {
    let like = wildcard_to_like_pattern(lowered);
    let Some(term_regex) = term_regex(lowered) else {
        // `*kw*` / `*-enc*` / all-wildcard: substring semantics already.
        return ci_like(&format!("lower({col})"), &like, false);
    };

    // Substring guard: the needle unanchored on both ends.
    let guard_like = format!(
        "{}{}{}",
        if lowered.starts_with('*') { "" } else { "%" },
        like,
        if lowered.ends_with('*') { "" } else { "%" }
    );
    format!(
        "({} AND match(lower({col}), '{}'))",
        ci_like(&format!("lower({col})"), &guard_like, false),
        escape_regex_pattern(&term_regex)
    )
}

/// The RE2 term regex for a lowered wildcard keyword, or `None` for the plain
/// whole-value substring form (`*kw*`). Shared by the SQL emitter and the
/// post-stage evaluator ([`keyword_matches`]) so both apply the same terms.
fn term_regex(lowered: &str) -> Option<String> {
    let first = lowered.chars().next();
    let last = lowered.chars().last();
    // NAN-4933: only `*` (any run) removes a term boundary. `?` is exactly
    // one character INSIDE the term, so `?ost` is a four-character term
    // (`host`, never the tail of `xxhost`) and keeps both boundaries.
    let bounded = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '?');
    let needs_start = first != Some('*') && bounded(first);
    let needs_end = last != Some('*') && bounded(last);
    let body = lowered.trim_matches('*');
    if !needs_start && !needs_end && !body.contains(['*', '?']) {
        return None;
    }
    let mut term_regex = String::new();
    if needs_start {
        term_regex.push_str("(?:^|[^a-z0-9])");
    }
    let mut literal = String::new();
    for c in body.chars() {
        match c {
            '*' | '?' => {
                term_regex.push_str(&regex::escape(&literal));
                literal.clear();
                term_regex.push_str(if c == '*' { r"\S*" } else { "[a-z0-9]" });
            }
            other => literal.push(other),
        }
    }
    term_regex.push_str(&regex::escape(&literal));
    if needs_end {
        term_regex.push_str("(?:$|[^a-z0-9])");
    }
    Some(term_regex)
}

/// NAN-4943: the post-stage (Nano-side) twin of [`keyword_predicate`] for ONE
/// body value: the same token search for a bare keyword (`hasAllTokens` over
/// `splitByNonAlpha`), the same whole-value substring for `*kw*`, and the same
/// term regex for one-sided / inner wildcards — all on the ClickHouse-`lower()`
/// (ASCII-only) folded text.
pub(crate) fn keyword_matches(kw: &str, text: &str) -> bool {
    let lowered = ch_lower(kw);
    let text = ch_lower(text);
    if !lowered.contains(['*', '?']) {
        // `splitByNonAlpha`: ASCII non-alphanumerics separate tokens;
        // non-ASCII characters stay inside a token.
        let tokens = |s: &str| -> Vec<String> {
            s.split(|c: char| c.is_ascii() && !c.is_ascii_alphanumeric())
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect()
        };
        let needle = tokens(&lowered);
        if needle.is_empty() {
            // All-separator needle: the substring fallback.
            return text.contains(&lowered);
        }
        let have = tokens(&text);
        return needle.iter().all(|t| have.contains(t));
    }
    let pattern = match term_regex(&lowered) {
        // RE2 `\S` is ASCII whitespace only; spell it out for the Rust engine.
        Some(term) => term.replace(r"\S", r"[^\t\n\x0C\r ]"),
        None => {
            let mut whole = String::from("(?s)^");
            for c in lowered.chars() {
                match c {
                    '*' => whole.push_str(".*"),
                    '?' => whole.push('.'),
                    other => whole.push_str(&regex::escape(&other.to_string())),
                }
            }
            whole.push('$');
            whole
        }
    };
    regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&text))
}
