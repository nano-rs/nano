// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5043: shown SQL never names a source the caller is denied.

use std::collections::BTreeSet;

use super::*;
use crate::auth::{compose_viewer_scope, ScopeSet};

fn analyst() -> ScopeSet {
    compose_viewer_scope(
        &ScopeSet::from_denied(BTreeSet::from(["hr_payroll".to_string(), "legal_hold".to_string()])),
        false,
    )
}

#[test]
fn the_injected_deny_list_is_rendered_opaquely() {
    let sql = "SELECT * FROM logs WHERE (x) AND lower(source_type) NOT IN ('audit', 'hr_payroll', 'legal_hold')";
    let shown = DisplaySql::for_scope(sql, &analyst());
    assert!(!shown.as_str().contains("hr_payroll"));
    assert!(!shown.as_str().contains("legal_hold"));
    assert!(shown.as_str().contains("NOT IN (/* source scope */)"), "{shown}");
}

#[test]
fn single_value_and_mixed_forms_are_redacted_too() {
    let deny = BTreeSet::from(["hr_payroll".to_string()]);
    let scope = ScopeSet::from_denied(deny);
    let shown = DisplaySql::for_scope("WHERE lower(source_type) != 'hr_payroll'", &scope);
    assert_eq!(shown.as_str(), "WHERE lower(source_type) != '<restricted source>'");
    // A user's own IN list that happens to include a denied name keeps its
    // other values; only the secret literal is masked.
    let shown = DisplaySql::for_scope("WHERE host NOT IN ('web1', 'hr_payroll')", &scope);
    assert_eq!(shown.as_str(), "WHERE host NOT IN ('web1', '<restricted source>')");
}

#[test]
fn audit_only_and_unrestricted_scopes_are_verbatim() {
    let sql = "WHERE source_type != 'audit' AND user = 'bob'";
    let audit_only = compose_viewer_scope(&ScopeSet::unrestricted(), false);
    assert_eq!(DisplaySql::for_scope(sql, &audit_only).as_str(), sql);
    assert_eq!(DisplaySql::for_scope(sql, &ScopeSet::unrestricted()).as_str(), sql);
}

#[test]
fn ordinary_literals_are_untouched() {
    let sql = "WHERE lower(source_type) NOT IN ('audit', 'hr_payroll') AND message ILIKE '%payroll%'";
    let shown = DisplaySql::for_scope(sql, &analyst());
    assert!(shown.as_str().ends_with("AND message ILIKE '%payroll%'"), "{shown}");
}

#[test]
fn serializes_as_a_plain_string() {
    let shown = DisplaySql::user_authored("SELECT 1");
    assert_eq!(serde_json::to_string(&shown).unwrap(), "\"SELECT 1\"");
}
