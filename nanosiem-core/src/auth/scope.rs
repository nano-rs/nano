// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-scope value type for per-source RBAC (NAN-1789 / NAN-1797).
//!
//! `ScopeSet` is a PURE value type — no database or service dependencies —
//! so it can be used from query manipulation and SQL generation without
//! pulling in auth infrastructure.
//!
//! Semantics:
//! - An EMPTY denied set means UNRESTRICTED: the caller sees everything.
//!   This is the SYSTEM-caller / back-compat default (`Default` == unrestricted).
//! - A non-empty denied set lists `source_type` values the caller must never
//!   see; the query injector excludes them at every base-table scan.
//! - This type carries SOURCE-scope ONLY. The `audit` source gate is unioned
//!   into the deny set by the handler (based on the `audit:view` permission),
//!   not here.

use std::collections::BTreeSet;

/// Set of `source_type` values denied to a caller.
///
/// Empty denied set = unrestricted = SYSTEM caller. Carries SOURCE-scope only;
/// the audit gate is unioned in by the handler, not by this type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeSet {
    denied: BTreeSet<String>,
}

impl ScopeSet {
    /// An unrestricted scope (empty denied set) — sees everything.
    /// Use for SYSTEM callers (schedulers, internal jobs) only.
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Build a scope from an explicit denied set of `source_type` values.
    pub fn from_denied(denied: BTreeSet<String>) -> Self {
        Self { denied }
    }

    /// The `source_type` values this caller must never see.
    pub fn deny_set(&self) -> &BTreeSet<String> {
        &self.denied
    }

    /// True when at least one source is denied. `false` means unrestricted.
    pub fn is_restricted(&self) -> bool {
        !self.denied.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_is_unrestricted() {
        let scope = ScopeSet::default();
        assert!(!scope.is_restricted());
        assert!(scope.deny_set().is_empty());
        assert_eq!(scope, ScopeSet::unrestricted());
    }

    #[test]
    fn unrestricted_equals_from_empty_denied() {
        assert_eq!(
            ScopeSet::unrestricted(),
            ScopeSet::from_denied(BTreeSet::new())
        );
    }

    #[test]
    fn from_denied_is_restricted_and_exposes_deny_set() {
        let scope = ScopeSet::from_denied(set(&["insider_threat", "audit"]));
        assert!(scope.is_restricted());
        assert_eq!(scope.deny_set(), &set(&["audit", "insider_threat"]));
    }

    #[test]
    fn equality_is_order_independent() {
        let a = ScopeSet::from_denied(set(&["b", "a"]));
        let b = ScopeSet::from_denied(set(&["a", "b"]));
        assert_eq!(a, b);
    }
}
