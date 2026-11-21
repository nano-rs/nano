// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// 199 ASCII bytes then a 3-byte character straddling byte 200: the shape
/// that panicked `&body[..200]` in the lookup-feed scheduler.
fn straddling_200() -> String {
    format!("{}€tail", "a".repeat(199))
}

#[test]
fn byte_slice_on_straddling_char_panics_but_helpers_do_not() {
    let s = straddling_200();
    assert!(!s.is_char_boundary(200));
    assert!(std::panic::catch_unwind(|| s[..200].to_string()).is_err());

    assert_eq!(prefix_at_most(&s, 200), "a".repeat(199));
    assert_eq!(truncate_with(&s, 200, "..."), format!("{}...", "a".repeat(199)));
    let mut owned = s.clone();
    truncate_in_place(&mut owned, 200);
    assert_eq!(owned, "a".repeat(199));
}

#[test]
fn ascii_behaviour_is_unchanged() {
    let s = "x".repeat(300);
    assert_eq!(prefix_at_most(&s, 200), &s[..200]);
    assert_eq!(truncate_with(&s, 200, "..."), format!("{}...", &s[..200]));
    assert_eq!(truncate_with("short", 200, "..."), "short");
    assert_eq!(prefix_at_most("", 0), "");
    assert_eq!(prefix_at_most("é", 0), "");
}

#[test]
fn never_exceeds_the_byte_budget_for_any_cut() {
    let s = "aé€😀".repeat(20);
    for max in 0..=s.len() + 2 {
        let p = prefix_at_most(&s, max);
        assert!(p.len() <= max, "max={max}");
        assert!(s.starts_with(p));
        // Longest such prefix: the next char would overflow the budget.
        if p.len() < s.len() {
            let next = s[p.len()..].chars().next().unwrap();
            assert!(p.len() + next.len_utf8() > max, "max={max}");
        }
    }
}

// --- NAN-5720: one-line / Markdown-safe external text ----------------------

#[test]
fn single_line_collapses_control_chars_and_whitespace() {
    assert_eq!(single_line("  a\r\nb\t\tc\u{0}d  \u{7}"), "a b c d");
    assert_eq!(single_line("one   two\n\nthree"), "one two three");
    assert_eq!(single_line(" \t\r\n "), "");
    assert_eq!(single_line(""), "");
    assert_eq!(single_line("plain"), "plain");
}

#[test]
fn truncate_chars_ellipsis_keeps_char_budget() {
    assert_eq!(truncate_chars_ellipsis("short", 10), "short");
    assert_eq!(truncate_chars_ellipsis("exactly10!", 10), "exactly10!");
    let cut = truncate_chars_ellipsis(&"é".repeat(50), 10);
    assert_eq!(cut.chars().count(), 10);
    assert!(cut.ends_with('…'));
}

#[test]
fn escape_markdown_neutralises_link_injection() {
    let raw = "admin](https://attacker.example/login) [x";
    let esc = escape_markdown(raw);
    assert_eq!(esc, r"admin\]\(https://attacker.example/login\) \[x");
    // Every bracket/paren the attacker supplied is now escaped.
    assert!(!esc.contains("](") && !esc.contains(" ["));
    assert_eq!(escape_markdown("![img](x) *b* `c` <https://e> a|b ~s~ \\"), r"\!\[img\]\(x\) \*b\* \`c\` \<https://e\> a\|b \~s\~ \\");
    // Hostnames, IPs and ordinary words are untouched.
    assert_eq!(escape_markdown("deep-host 10.0.0.1 CASE-42 #1"), "deep-host 10.0.0.1 CASE-42 #1");
}

#[test]
fn single_line_drops_bidi_zero_width_and_bom() {
    assert_eq!(single_line("\u{FEFF}- list"), "- list");
    assert_eq!(single_line("host \u{202E}moc-live\u{202C}"), "host moc-live");
    assert_eq!(single_line("a\u{200B}b\u{2066}c\u{2069}d\u{061C}"), "abcd");
    assert_eq!(single_line("Title\u{2028}- bullet"), "Title - bullet");
}
