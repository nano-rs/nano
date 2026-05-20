// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encoding for SilentRule proposal apply actions (NAN-880 phase 3c).
//!
//! `SilentRule` proposals carry a *recommendation* for how the analyst
//! should respond to a silent rule. Some recommendations correspond to a
//! query rewrite (lower a threshold, change a referenced field) — those
//! flow through the existing query-tuning apply path naturally because
//! `proposed_query` differs from `original_query`.
//!
//! "Disable the rule" doesn't fit that shape — the rule's query is fine,
//! we just want to pause it. To avoid plumbing a separate `apply_action`
//! column through the proposal table (and a migration), we encode the
//! pause directive as a sentinel comment at the head of `proposed_query`:
//!
//! ```text
//! // __NANOSIEM_SILENT_ACTION:pause__
//! source_type=windows_event | …
//! ```
//!
//! The nPL parser strips `//` comments before parsing, so this never
//! affects rule evaluation — it's purely a marker the approve handler
//! reads back out of the raw `proposed_query` string.
//!
//! Both the enterprise detector (writes) and the api approve handler
//! (reads) live in separate crates; this module is shared in core so
//! both sides can build / parse the same sentinel without one importing
//! the other.

/// Sentinel comment used in `proposed_query` for "pause this rule"
/// recommendations. Must be the first non-whitespace content; the parser
/// is intentionally strict so we don't false-positive on user-authored
/// comments in the rule query.
pub const SILENT_ACTION_PAUSE: &str = "// __NANOSIEM_SILENT_ACTION:pause__";

/// `true` iff the proposed_query carries the pause-action sentinel.
pub fn is_pause_action(proposed_query: &str) -> bool {
    proposed_query.trim_start().starts_with(SILENT_ACTION_PAUSE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pause_at_head_of_query() {
        let q = format!("{SILENT_ACTION_PAUSE}\nsource_type=apache");
        assert!(is_pause_action(&q));
    }

    #[test]
    fn detects_pause_with_leading_whitespace() {
        let q = format!("   \n{SILENT_ACTION_PAUSE}\nsource_type=apache");
        assert!(is_pause_action(&q));
    }

    #[test]
    fn does_not_match_user_comment_with_different_text() {
        let q = "// a user comment\nsource_type=apache";
        assert!(!is_pause_action(q));
    }

    #[test]
    fn does_not_match_sentinel_in_middle_of_query() {
        // Strict: only sentinel at the head counts. A spurious occurrence
        // inside a string literal or partway through must not pause the rule.
        let q = format!("source_type=apache\n{SILENT_ACTION_PAUSE}");
        assert!(!is_pause_action(&q));
    }

    #[test]
    fn empty_query_is_not_pause() {
        assert!(!is_pause_action(""));
        assert!(!is_pause_action("   "));
    }
}
