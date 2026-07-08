// SPDX-License-Identifier: AGPL-3.0-or-later

use super::splice_query;
use crate::rule_repository::parse_npl;

const EXISTING: &str = "---\ntitle: Failed Logins\nseverity: high\ncustom_field: keepme\nmitre_tactics:\n  - TA0006\n---\nsource_type=windows | stats count by user | where count > 5\n";

#[test]
fn splice_preserves_frontmatter_and_swaps_query() {
    let new_query = "source_type=windows | stats count by user | where count > 20";
    let out = splice_query(EXISTING, new_query).expect("valid frontmatter should splice");

    // Frontmatter is kept verbatim — including a field nano doesn't model.
    assert!(out.contains("title: Failed Logins"));
    assert!(out.contains("severity: high"));
    assert!(out.contains("custom_field: keepme"));
    assert!(out.contains("mitre_tactics:"));

    // Only the query body changed.
    assert!(out.contains("where count > 20"));
    assert!(!out.contains("where count > 5"));
}

#[test]
fn spliced_file_reparses_cleanly() {
    let new_query = "source_type=windows | stats count by user | where count > 20";
    let out = splice_query(EXISTING, new_query).unwrap();

    let parsed = parse_npl(&out).expect("spliced output must re-parse as nPL");
    assert_eq!(parsed.title, "Failed Logins");
    assert_eq!(parsed.severity.as_deref(), Some("high"));
    assert_eq!(parsed.query, new_query);
}

#[test]
fn splice_rejects_non_frontmatter_input() {
    assert!(splice_query("just a query, no frontmatter", "q").is_none());
    // Opening delimiter but no closing one.
    assert!(splice_query("---\ntitle: x\nno closing delimiter", "q").is_none());
}
