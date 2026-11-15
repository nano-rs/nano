// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5432: the ClickHouse error stored on an outbox row is PostgreSQL-safe.

use super::truncate_error;

#[test]
fn stored_error_has_no_nul_or_line_breaks() {
    let stored = truncate_error("Code: 27. Cannot parse input: zz\u{0}\nFAKE\r\u{1b}x");
    assert!(crate::db::pg_text::is_pg_safe_str(&stored));
    assert!(!stored.contains('\n') && !stored.contains('\r') && !stored.contains('\u{1b}'));
    assert!(stored.starts_with("Code: 27. Cannot parse input: zz"));
}

#[test]
fn stored_error_is_capped_on_a_char_boundary() {
    let stored = truncate_error(&"é".repeat(3000));
    assert!(stored.ends_with('…'));
    assert!(stored.len() <= 2000 + '…'.len_utf8());
}
