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
