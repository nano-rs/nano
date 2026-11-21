// SPDX-License-Identifier: AGPL-3.0-or-later

//! UTF-8-safe truncation for text that did not originate in this process
//! (security review 2026-11-08).
//!
//! `&s[..n]` and `String::truncate(n)` panic when byte `n` falls inside a
//! multi-byte character. On text from a remote server, a tenant, an ingested
//! log or an AI provider that is a reachable panic, and inside a supervised
//! background loop a panic exits the whole process
//! ([`crate::process_supervision`]). Every bounded preview / log excerpt of
//! such text goes through these helpers instead.
//!
//! All limits are in BYTES (the same unit the old slices used) and the result
//! is always a prefix of at most `max_bytes` bytes that ends on a character
//! boundary, so callers keep their existing size budgets.

/// The longest prefix of `s` that is at most `max_bytes` bytes and ends on a
/// character boundary. Never panics.
#[inline]
pub fn prefix_at_most(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    &s[..s.floor_char_boundary(max_bytes)]
}

/// [`prefix_at_most`] followed by `ellipsis` when (and only when) `s` was
/// actually shortened.
pub fn truncate_with(s: &str, max_bytes: usize, ellipsis: &str) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes + ellipsis.len());
    out.push_str(prefix_at_most(s, max_bytes));
    out.push_str(ellipsis);
    out
}

/// In-place [`prefix_at_most`]: shortens `s` to at most `max_bytes` bytes on a
/// character boundary. A drop-in replacement for `String::truncate` on
/// external text.
#[inline]
pub fn truncate_in_place(s: &mut String, max_bytes: usize) {
    if s.len() > max_bytes {
        let end = s.floor_char_boundary(max_bytes);
        s.truncate(end);
    }
}

/// Collapse `s` to one line of plain text: every control character (CR, LF,
/// tab, NUL, ...) and every run of whitespace becomes a single space, and the
/// ends are trimmed. For external text that lands in a one-line field such as
/// a case title, an email subject or a card header (NAN-5720).
pub fn single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if invisible_format(c) {
            continue;
        }
        if c.is_whitespace() || c.is_control() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        out.push(c);
    }
    out
}

/// Bidi overrides, isolates and marks, zero-width characters and the BOM:
/// they render nothing but can reorder or disguise the visible text
/// (NAN-5737 review), so [`single_line`] drops them.
fn invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// At most `max_chars` CHARACTERS of `s`; when it is cut, the last kept
/// character is replaced by `…` so the result is still `max_chars` long.
pub fn truncate_chars_ellipsis(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        None => s.to_string(),
        Some(_) => {
            let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
            out.push('…');
            out
        }
    }
}

/// Backslash-escape the ASCII punctuation that has INLINE meaning in
/// CommonMark/GFM (links, images, autolinks, emphasis, code, tables,
/// strikethrough), so `s` renders as literal text when interpolated inside a
/// Markdown line, e.g. link text or a heading. CommonMark allows a backslash
/// before any ASCII punctuation, so the rendered text reads unchanged.
/// Line-start syntax (`#`, `-`, `1.`) is not escaped: call
/// [`single_line`] first and interpolate mid-line. Use it where external text
/// (case titles, entity values) lands in Markdown (NAN-5720).
pub fn escape_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '!' | '<' | '>' | '|' | '~'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
#[path = "text_bounds_tests.rs"]
mod tests;
