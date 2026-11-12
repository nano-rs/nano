// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5308: audit search is a server-side filter over every matching row.

use super::*;

/// NAN-5308: the search box filters server-side; blank input is no filter
/// and the needle is a bound parameter, never spliced into SQL.
#[test]
fn search_adds_one_bound_condition() {
    let q = ClickHouseAuditQuery {
        search: Some("  pa-probe-key ".into()),
        ..Default::default()
    };
    let f = resolve_filters(&q);
    assert_eq!(f.search.as_deref(), Some("pa-probe-key"));
    assert!(f.where_clause.contains(AUDIT_SEARCH_CONDITION));
    assert!(!f.where_clause.contains("pa-probe-key"));

    let blank = ClickHouseAuditQuery {
        search: Some("   ".into()),
        ..Default::default()
    };
    assert!(resolve_filters(&blank).where_clause.is_empty());
}

#[test]
fn search_combines_with_other_filters() {
    let q = ClickHouseAuditQuery {
        action: Some("apikey_created".into()),
        search: Some("probe".into()),
        ..Default::default()
    };
    let f = resolve_filters(&q);
    assert_eq!(
        f.where_clause,
        format!("WHERE action = ? AND {AUDIT_SEARCH_CONDITION}")
    );
}

#[test]
fn search_needle_is_capped() {
    let long = "x".repeat(1000);
    assert_eq!(
        normalize_audit_search(Some(&long)).map(|s| s.chars().count()),
        Some(AUDIT_SEARCH_MAX_CHARS)
    );
}


/// The clickhouse client treats every `?` in the template as a placeholder;
/// the search condition must carry exactly the one for the needle.
#[test]
fn search_condition_has_exactly_one_placeholder() {
    assert_eq!(AUDIT_SEARCH_CONDITION.matches('?').count(), 1);
}

#[test]
fn search_strips_nul() {
    assert_eq!(normalize_audit_search(Some("a\0b")).as_deref(), Some("ab"));
    assert_eq!(normalize_audit_search(Some("\0")), None);
}
