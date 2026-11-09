// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generated SQL as shown to a caller (NAN-5043).
//!
//! The executed SQL carries the caller's per-source deny set as literals:
//! `lower(source_type) NOT IN ('audit', 'hr_payroll', …)`. Returning it
//! verbatim (explain, `include_sql`, retro, streaming metadata) told a caller
//! the names of the very sources it is denied. `/api/source-types` was fixed for
//! the same leak in NAN-2055; this is the SQL-echo counterpart.
//!
//! [`DisplaySql`] is the only type a response may carry generated SQL in, and
//! its only general constructor, [`DisplaySql::for_scope`], redacts the deny
//! literals. The executed SQL is never altered — this is a rendering of it.
//!
//! An `audit`-only deny is shown verbatim: every caller without `audit:view`
//! carries it, and `source_type != 'audit'` names nothing secret.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::auth::{ScopeSet, UNRESOLVED_SOURCE_SENTINEL};

/// Placeholder for a redacted deny list.
pub const REDACTED_SOURCE_SCOPE: &str = "/* source scope */";
/// Placeholder for a single redacted denied source literal.
pub const REDACTED_SOURCE: &str = "'<restricted source>'";

/// Generated SQL, safe to show to the caller it was rendered for.
///
/// Serializes as a plain string; response fields annotate it with
/// `#[schema(value_type = String)]` so the published API is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisplaySql(String);

impl DisplaySql {
    /// Render `sql` for a caller with `scope`: the deny literals of every
    /// restricted source are replaced, the rest is unchanged. An unrestricted
    /// or `audit`-only scope returns `sql` verbatim.
    pub fn for_scope(sql: impl Into<String>, scope: &ScopeSet) -> Self {
        Self(redact_scope_literals(&sql.into(), scope.deny_set()))
    }

    /// SQL the caller wrote themselves (raw SQL mode). Contains no injected
    /// scope, so it is echoed as is.
    pub fn user_authored(sql: impl Into<String>) -> Self {
        Self(sql.into())
    }

    /// Crate-internal: a builder that redacts before the value leaves the
    /// service (see `build_retro_view`). Never returned unredacted.
    pub(crate) fn pending_redaction(sql: impl Into<String>) -> Self {
        Self(sql.into())
    }

    /// Re-apply [`Self::for_scope`] (idempotent).
    pub fn redacted_for(self, scope: &ScopeSet) -> Self {
        Self::for_scope(self.0, scope)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for DisplaySql {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Values whose appearance in shown SQL would disclose a restricted source.
fn secret_values(deny: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = deny
        .iter()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty() && v != "audit")
        .collect();
    if !out.is_empty() {
        out.insert(UNRESOLVED_SOURCE_SENTINEL.to_string());
    }
    out
}

static NOT_IN_LIST: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)NOT\s+IN\s*\(\s*('(?:[^'\\]|\\.)*'(?:\s*,\s*'(?:[^'\\]|\\.)*')*)\s*\)")
        .expect("static regex")
});
static STRING_LITERAL: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"'((?:[^'\\]|\\.)*)'").expect("static regex"));

/// The pure redaction (see [`DisplaySql::for_scope`]).
///
/// 1. A `NOT IN ( … )` list made ONLY of deny values (the injected gate, in
///    either the nPL InList or the hand-built `source_scope_sql_predicate`
///    form) becomes `NOT IN (/* source scope */)`.
/// 2. Any remaining string literal equal to a restricted deny value (the
///    single-value `!= 'x'` form, or a deny value inside a mixed list) becomes
///    `'<restricted source>'`.
pub fn redact_scope_literals(sql: &str, deny: &BTreeSet<String>) -> String {
    let secrets = secret_values(deny);
    if secrets.is_empty() {
        return sql.to_string();
    }
    let mut allowed = secrets.clone();
    allowed.insert("audit".to_string());

    let step1 = NOT_IN_LIST.replace_all(sql, |caps: &regex::Captures<'_>| {
        let list = &caps[1];
        let values: Vec<String> = STRING_LITERAL
            .captures_iter(list)
            .map(|c| c[1].to_lowercase())
            .collect();
        let only_deny = !values.is_empty() && values.iter().all(|v| allowed.contains(v));
        let names_secret = values.iter().any(|v| secrets.contains(v));
        if only_deny && names_secret {
            format!("NOT IN ({REDACTED_SOURCE_SCOPE})")
        } else {
            caps[0].to_string()
        }
    });
    STRING_LITERAL
        .replace_all(&step1, |caps: &regex::Captures<'_>| {
            if secrets.contains(&caps[1].to_lowercase()) {
                REDACTED_SOURCE.to_string()
            } else {
                caps[0].to_string()
            }
        })
        .into_owned()
}

#[cfg(test)]
#[path = "display_sql_tests.rs"]
mod display_sql_tests;
