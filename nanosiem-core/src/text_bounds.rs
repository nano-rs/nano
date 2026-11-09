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

#[cfg(test)]
#[path = "text_bounds_tests.rs"]
mod tests;
