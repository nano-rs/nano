// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ONE canonical case-visibility definition (NAN-2073 / 2074 / 2075 / 2077 /
//! 2079 / 2082).
//!
//! Before this module the same predicate existed as nine hand-copied SQL blobs
//! (`CaseRepository::{list, count, list_my_cases, get_stats, list_linked_case_refs,
//! can_view_case}`, `PlaybookRepository::case_visible_to`,
//! `NotebookRepository::user_can_access_case`, and the inbox-counts handler).
//! They had already drifted: only some of them were source-scope aware, so
//! `GET /api/cases/{id}` could 404 a case while `GET /api/cases` listed its
//! title, AI summary and alert count.
//!
//! # The two halves of "visible"
//!
//! 1. **Case ACL** — `public`, or the caller created it / is assigned to it, or
//!    it is `group`-visible and the caller shares one of its groups.
//! 2. **Source scope** (per-source RBAC, NAN-1799) — the case has NO linked
//!    alerts at all, OR at least one linked alert whose `alerts.source_types`
//!    does not overlap the caller's effective deny set.
//!
//! Half 2 mirrors `CaseRepository::get_case_alerts` exactly, which is what makes
//! the list/detail/aggregate surfaces agree: a case is listable iff `get_case_full`
//! would return at least one alert for the same caller (or the case is genuinely
//! alert-less). `alerts.source_types` is `TEXT[] NOT NULL DEFAULT '{}'`
//! (migration 246), and an empty stamp never overlaps anything — so an
//! unstamped alert counts as visible, matching every other read path.
//!
//! # Why not `search::service::source_scope_sql_predicate`?
//!
//! That builder renders a ClickHouse `lower(col) NOT IN (…)` over a SCALAR
//! column, with the deny values inlined as escaped literals. Cases live in
//! Postgres and the scope key is a `text[]` compared with the `&&` overlap
//! operator against a BOUND array parameter. Different engine, different
//! operator, no string interpolation of caller data at all — the two are not
//! interchangeable. This module is the Postgres-side counterpart, and it is
//! deliberately the only place the `case_alerts`/`alerts` overlap shape is
//! written down.
//!
//! # Open-core reachability
//!
//! `CaseRepository` is `#[cfg(feature = "enterprise")]` (NAN-1298), so anything
//! open-core code needs must live OUTSIDE that module. This file is not gated —
//! same precedent as `PlaybookRepository::case_visible_to`, which already
//! queries `cases` / `case_groups` / `user_groups` from open-core code.

use std::collections::BTreeSet;

use sqlx::PgPool;
use uuid::Uuid;

/// Normalize a viewer's per-source deny set into the `Option<Vec<String>>` the
/// case queries bind.
///
/// Returns `None` for an EMPTY deny set (unrestricted viewer / SYSTEM caller) so
/// the emitted SQL stays byte-identical to the pre-scoping form; otherwise the
/// trimmed + lowercased deny values, matching the `alerts.source_types` stamp
/// normalization (`AlertRepository::distinct_source_types`).
pub fn normalize_deny(deny: &BTreeSet<String>) -> Option<Vec<String>> {
    // NAN-2155: use the shared fail-closed bind normalizer so unresolved
    // provenance is denied consistently across every case visibility surface.
    let denied = crate::auth::deny_bind_values(deny);
    if denied.is_empty() {
        None
    } else {
        Some(denied)
    }
}

/// Fail-closed sanitizer for the SQL alias these builders interpolate.
///
/// Every call site passes a compile-time literal (`"c"`, `"ce"`, …), so this can
/// never fire in practice. It exists because NAN-2158 was exactly this class:
/// an identifier interpolated verbatim into generated SQL, with only the VALUES
/// escaped. Anything outside `[A-Za-z0-9_]` is dropped, and an alias that
/// sanitizes to nothing falls back to `c` — the result is always a bare
/// identifier, so no input can close the expression or start a comment.
fn safe_alias(alias: &str) -> String {
    let cleaned: String = alias
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if cleaned.is_empty() {
        "c".to_string()
    } else {
        cleaned
    }
}

/// Half 1: the canonical case ACL predicate over the `cases` row aliased
/// `alias`, with the viewer's user id bound at `$user_param`.
///
/// Emits a parenthesized boolean expression; safe to `AND` into any WHERE.
pub fn case_acl_predicate(alias: &str, user_param: u16) -> String {
    let a = safe_alias(alias);
    format!(
        "(\n    {a}.visibility = 'public'\n    \
         OR {a}.created_by = ${user_param}\n    \
         OR {a}.assigned_to = ${user_param}\n    \
         OR ({a}.visibility = 'group' AND EXISTS (\n        \
             SELECT 1 FROM case_groups cg\n        \
             JOIN user_groups ug ON ug.group_id = cg.group_id\n        \
             WHERE cg.case_id = {a}.id AND ug.user_id = ${user_param}\n    \
         ))\n)"
    )
}

/// Half 2: the canonical per-source case visibility predicate over the `cases`
/// row aliased `alias`, with the normalized deny array bound at `$deny_param`
/// (`text[]`).
///
/// TRUE when the case has no linked alerts at all, or at least one linked alert
/// the viewer may see. Callers MUST only emit this when the deny set is
/// non-empty — for an unrestricted viewer the predicate is a tautology and the
/// SQL should stay byte-identical to the pre-scoping form.
pub fn case_source_predicate(alias: &str, deny_param: u16) -> String {
    let a = safe_alias(alias);
    format!(
        "(\n    NOT EXISTS (SELECT 1 FROM case_alerts ca WHERE ca.case_id = {a}.id)\n    \
         OR EXISTS (\n        \
             SELECT 1 FROM case_alerts ca\n        \
             JOIN alerts al ON al.id = ca.alert_id\n        \
             WHERE ca.case_id = {a}.id\n          \
               AND NOT (al.source_types && ${deny_param}::text[])\n    \
         )\n)"
    )
}

/// Both halves, ANDed. `deny_param` is `None` for an unrestricted viewer, in
/// which case only the ACL half is emitted.
///
/// This is the predicate every case enumeration / aggregate / by-id lookup must
/// use. Passing `None` when the caller IS restricted is the bug class this
/// module exists to remove — prefer [`case_visible_predicate_for`], which takes
/// the deny set itself and cannot be given a mismatched pair.
pub fn case_visible_predicate(alias: &str, user_param: u16, deny_param: Option<u16>) -> String {
    match deny_param {
        Some(d) => format!(
            "{acl}\n  AND {src}",
            acl = case_acl_predicate(alias, user_param),
            src = case_source_predicate(alias, d)
        ),
        None => case_acl_predicate(alias, user_param),
    }
}

/// Per-source visibility predicate for a `case_entities` row aliased `alias`,
/// with the normalized deny array bound at `$deny_param` (NAN-2079).
///
/// The old rule inferred provenance by substring-searching serialized alert JSON
/// for the stored entity value. That fails OPEN under any normalization skew —
/// an entity stored defanged (`10.23.45[.]67`) never matches the raw event, so
/// the "came from a denied alert" `EXISTS` is false and the entity is returned.
/// It also left `%`, `_` and `\` unescaped in the LIKE needle.
///
/// Provenance is now RECORDED (`case_entity_alerts`, migration 9000041):
///
/// - `provenance_recorded = TRUE` → exact: visible iff at least one contributing
///   alert is STILL LINKED to the entity's case and survives the deny filter.
///   Mirrors `get_case_alerts`, so an entity seen in both an allowed and a denied
///   alert stays visible, and an unstamped (`'{}'`) contributing alert counts as
///   visible.
///
///   The `case_alerts` join is load-bearing: `remove_alert` deletes the
///   `case_alerts` link but leaves the alert row and its `case_entity_alerts`
///   rows intact. Without the join a DETACHED allowed alert would keep
///   un-redacting an entity whose only still-linked provenance is denied.
/// - `provenance_recorded = FALSE` → rows written before the migration, plus any
///   future non-alert-derived entity. Ambiguous, so FAIL CLOSED: visible only
///   when the case has NO denied alert at all, because then no denied alert
///   exists for the entity to have come from. On a case whose alerts are all
///   visible to this viewer (the overwhelmingly common shape, including the
///   implicit `audit` deny every caller without `audit:view` carries) this is
///   identical to the old behaviour — the tightening lands exactly on the
///   mixed-source case that NAN-2079 demonstrates.
pub fn case_entity_source_predicate(alias: &str, deny_param: u16) -> String {
    let a = safe_alias(alias);
    format!(
        "(\n    ({a}.provenance_recorded AND EXISTS (\n        \
             SELECT 1 FROM case_entity_alerts cea\n        \
             JOIN case_alerts cea_ca\n             \
               ON cea_ca.alert_id = cea.alert_id AND cea_ca.case_id = {a}.case_id\n        \
             JOIN alerts cea_al ON cea_al.id = cea.alert_id\n        \
             WHERE cea.case_entity_id = {a}.id\n          \
               AND NOT (cea_al.source_types && ${deny_param}::text[])\n    \
         ))\n    \
         OR (NOT {a}.provenance_recorded AND NOT EXISTS (\n        \
             SELECT 1 FROM case_alerts lca\n        \
             JOIN alerts lca_al ON lca_al.id = lca.alert_id\n        \
             WHERE lca.case_id = {a}.case_id\n          \
               AND (lca_al.source_types && ${deny_param}::text[])\n    \
         ))\n)"
    )
}

/// [`case_visible_predicate`] driven by the deny set itself: the source half is
/// emitted iff `deny` normalizes to a non-empty array. Returns the predicate
/// plus the normalized array the caller must bind at `$deny_param` (`None` =
/// bind nothing).
pub fn case_visible_predicate_for(
    alias: &str,
    user_param: u16,
    deny_param: u16,
    deny: &BTreeSet<String>,
) -> (String, Option<Vec<String>>) {
    let deny_vec = normalize_deny(deny);
    let sql = case_visible_predicate(alias, user_param, deny_vec.as_ref().map(|_| deny_param));
    (sql, deny_vec)
}

/// Runtime probe: can `user_id` see case `case_id` under `deny`?
///
/// The yes/no gate for hot paths (presence heartbeat) and for open-core callers
/// that cannot depend on the enterprise-gated `CaseRepository`. Returns `false`
/// for a missing case as well as a hidden one — callers must render both
/// identically (404), never an existence oracle.
pub async fn case_visible_to(
    pool: &PgPool,
    case_id: Uuid,
    user_id: Uuid,
    deny: &BTreeSet<String>,
) -> Result<bool, sqlx::Error> {
    let (predicate, deny_vec) = case_visible_predicate_for("c", 2, 3, deny);
    let sql = format!("SELECT TRUE FROM cases c WHERE c.id = $1 AND {predicate} LIMIT 1");
    let mut query = sqlx::query_scalar::<_, bool>(&sql)
        .bind(case_id)
        .bind(user_id);
    if let Some(denied) = &deny_vec {
        query = query.bind(denied);
    }
    Ok(query.fetch_optional(pool).await?.is_some())
}

/// Runtime probe for the SOURCE half only — "does this case have at least one
/// alert this deny set permits (or no alerts at all)?"
///
/// For callers that deliberately bypass the case ACL and must NOT have it
/// re-imposed: `share_as_admin` exists precisely so an admin can re-share a case
/// they do not own. The per-source boundary still applies to them, so the two
/// halves have to be separable. Returns `false` for a missing case as well as a
/// hidden one.
pub async fn case_source_visible_to(
    pool: &PgPool,
    case_id: Uuid,
    deny: &BTreeSet<String>,
) -> Result<bool, sqlx::Error> {
    let deny_vec = normalize_deny(deny);
    let Some(denied) = deny_vec else {
        // Unrestricted viewer: the source half is a tautology. Still confirm the
        // case exists so the caller cannot act on a phantom id.
        return Ok(
            sqlx::query_scalar::<_, bool>("SELECT TRUE FROM cases c WHERE c.id = $1")
                .bind(case_id)
                .fetch_optional(pool)
                .await?
                .is_some(),
        );
    };
    let sql = format!(
        "SELECT TRUE FROM cases c WHERE c.id = $1 AND {} LIMIT 1",
        case_source_predicate("c", 2)
    );
    Ok(sqlx::query_scalar::<_, bool>(&sql)
        .bind(case_id)
        .bind(&denied)
        .fetch_optional(pool)
        .await?
        .is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_predicate_binds_the_requested_parameter() {
        let sql = case_acl_predicate("c", 9);
        assert!(sql.contains("c.created_by = $9"));
        assert!(sql.contains("c.assigned_to = $9"));
        assert!(sql.contains("ug.user_id = $9"));
        assert!(sql.contains("c.visibility = 'public'"));
        // No other positional parameter may sneak in.
        assert_eq!(sql.matches('$').count(), 3);
    }

    #[test]
    fn source_predicate_allows_alertless_and_partially_visible_cases() {
        let sql = case_source_predicate("c", 4);
        assert!(sql.contains("NOT EXISTS (SELECT 1 FROM case_alerts ca WHERE ca.case_id = c.id)"));
        assert!(sql.contains("NOT (al.source_types && $4::text[])"));
    }

    #[test]
    fn visible_predicate_omits_the_source_half_for_an_unrestricted_viewer() {
        let unrestricted = case_visible_predicate("c", 1, None);
        assert!(!unrestricted.contains("case_alerts"));
        let restricted = case_visible_predicate("c", 1, Some(2));
        assert!(restricted.contains("case_alerts"));
    }

    #[test]
    fn predicate_for_drives_the_source_half_off_the_deny_set() {
        let empty = BTreeSet::new();
        let (sql, bind) = case_visible_predicate_for("c", 1, 2, &empty);
        assert!(bind.is_none());
        assert!(!sql.contains("case_alerts"));

        let deny: BTreeSet<String> = ["  Audit ".to_string()].into_iter().collect();
        let (sql, bind) = case_visible_predicate_for("c", 1, 2, &deny);
        assert_eq!(
            bind.as_deref(),
            Some(
                &[
                    crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string(),
                    "audit".to_string(),
                ][..]
            )
        );
        assert!(sql.contains("case_alerts"));
        assert!(sql.contains("$2::text[]"));
    }

    #[test]
    fn normalize_deny_trims_lowercases_and_drops_blanks() {
        let deny: BTreeSet<String> = [
            "  AUDIT  ".to_string(),
            "   ".to_string(),
            "Windows_Event_Log".to_string(),
        ]
        .into_iter()
        .collect();
        let mut normalized = normalize_deny(&deny).expect("non-empty");
        normalized.sort();
        assert_eq!(
            normalized,
            vec![
                crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string(),
                "audit".to_string(),
                "windows_event_log".to_string(),
            ]
        );

        let blanks: BTreeSet<String> = ["".to_string(), "  ".to_string()].into_iter().collect();
        assert!(normalize_deny(&blanks).is_none());
    }

    #[test]
    fn alias_is_sanitized_to_a_bare_identifier() {
        // A hostile alias cannot close the expression, start a comment, or
        // introduce a new predicate — every non-identifier character is dropped.
        let sql = case_acl_predicate("c) OR TRUE --", 1);
        assert!(!sql.contains("--"));
        assert!(!sql.contains("OR TRUE"));
        assert!(sql.contains("cORTRUE.visibility = 'public'"));
        assert_eq!(safe_alias("!!!"), "c");
    }
}
