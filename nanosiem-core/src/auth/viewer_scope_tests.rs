// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for typed read principals (NAN-5019 / NAN-5028).

use super::viewer_scope::*;
use crate::auth::ScopeSet;
use std::collections::BTreeSet;
use uuid::Uuid;

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn unrestricted_viewer_binds_nothing() {
    let v = ViewerScope::new(Uuid::nil(), ScopeSet::unrestricted());
    assert_eq!(v.deny_bind(), None);
    assert_eq!(v.deny_param(4), None);
}

#[test]
fn restricted_viewer_binds_normalized_deny_with_sentinel() {
    let v = ViewerScope::new(Uuid::nil(), ScopeSet::from_denied(set(&[" HR_Payroll "])));
    let bound = v.deny_bind().expect("restricted");
    assert!(bound.contains(&"hr_payroll".to_string()));
    assert!(bound.contains(&crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string()));
    assert_eq!(v.deny_param(4), Some(4));
}

#[test]
fn audit_only_viewer_is_restricted_for_case_reads() {
    // The audit gate is part of the LIVE-data deny set, which is what case
    // visibility evaluates (mirrors `effective_source_deny_set`).
    let v = ViewerScope::new(
        Uuid::nil(),
        crate::auth::compose_viewer_scope(&ScopeSet::unrestricted(), false),
    );
    assert!(v.deny_bind().is_some());
}

#[test]
fn system_scope_is_unrestricted_and_named() {
    let s = SystemScope::new(SystemReason::ShadowInvestigation);
    assert!(!s.scope().is_restricted());
    assert_eq!(s.reason().as_str(), "shadow_investigation");
}
