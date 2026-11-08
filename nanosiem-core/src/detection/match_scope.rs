// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-source RBAC scoping for the `detection_matches` surface (NAN-2071).
//!
//! NAN-1808 stamped every match row with the DISTINCT normalized `source_type`
//! values of its matched events and filtered ONE read path
//! (`GET /api/rules/{id}/matches`). Its siblings — the disposition rollup, the
//! per-rule "today" firing counts, and the two by-id MUTATIONS (review /
//! disposition) — kept operating on the raw table, so a principal denied every
//! source represented by a match could still count it, mark it reviewed, and
//! reclassify it. That is a source-scope bypass plus an IDOR on the mutations.
//!
//! This module is the single place the predicate lives, so the read paths,
//! the count paths, and the write paths cannot drift apart again.
//!
//! # Semantics
//!
//! Identical to `alerts.source_types` and `detection_matches.source_types`
//! (migrations 246 / 247), and DELIBERATELY the opposite of the frozen-artifact
//! `report_runs` gate: a row is visible iff NONE of its stamped source types is
//! denied. An empty stamp (`'{}'`) is a pre-feature row or a producer whose
//! events carry no `source_type` (retro-hunt indicator summaries), never
//! overlaps a deny set, and stays visible to everyone. Detection matches are
//! ROW-attributed — unlike a report artifact's frozen bytes, an unstamped match
//! is known not to be source-derived rather than unknown.
//!
//! NAN-2155 removed the one case where that reasoning did not hold. `'{}'` used
//! to be written on BOTH "known to have no source" and "failed to determine the
//! source", so a transient registry failure at match time published a restricted
//! match to everyone, permanently. The producer now stamps
//! [`crate::auth::UNRESOLVED_SOURCE_SENTINEL`] for the failure case and every
//! deny bind carries that value, so `'{}'` once again means only what this
//! module's contract says it means.
//!
//! # Mutations are conditional, never check-then-act
//!
//! Every write here carries the visibility predicate INSIDE the mutating
//! statement (`UPDATE … AND NOT (source_types && $deny)`, or a CTE whose
//! `DELETE`/`INSERT` selects from a visible-rows sub-select). There is no probe
//! followed by a write, so there is no TOCTOU window and no path on which a
//! denied row is touched before authorization is decided.
//!
//! # No existence oracle
//!
//! Each mutation reports only "affected an owned/visible row" vs "did not".
//! Callers MUST render "denied" and "missing" identically (404) so the routes
//! cannot be used to probe for the existence of denied-source matches.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// A caller's effective per-source deny scope, normalized for comparison
/// against `detection_matches.source_types`.
///
/// Build it from [`crate::auth::ScopeSet::deny_set`] unioned with the implicit
/// `audit` deny (the API layer composes that via
/// `AuthContext::effective_source_deny_set`). An EMPTY scope means unrestricted
/// and keeps the emitted SQL byte-identical to the pre-scoping form — the
/// predicate is not appended at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchScope {
    /// The values to BIND as the `text[]` parameter: the caller's normalized
    /// deny set plus, for a restricted caller,
    /// [`UNRESOLVED_SOURCE_SENTINEL`](crate::auth::UNRESOLVED_SOURCE_SENTINEL).
    /// Empty means unrestricted.
    deny: Vec<String>,
}

impl MatchScope {
    /// Unrestricted scope — sees every match row.
    pub fn unrestricted() -> Self {
        Self { deny: Vec::new() }
    }

    /// Normalize (trim + lowercase, drop empties) a caller's effective deny set.
    ///
    /// Normalization must match the stamping side (`store_detection_match`
    /// lowercases and trims before writing `source_types`), otherwise a
    /// differently-cased deny value would silently fail to overlap.
    ///
    /// NAN-2155: a RESTRICTED caller additionally denies the
    /// unresolved-provenance sentinel — see [`crate::auth::deny_bind_values`].
    pub fn from_denied(denied: &BTreeSet<String>) -> Self {
        Self {
            deny: crate::auth::deny_bind_values(denied),
        }
    }

    /// `true` when the caller may see every row (no predicate is emitted).
    pub fn is_unrestricted(&self) -> bool {
        self.deny.is_empty()
    }

    /// The values to bind as the `text[]` parameter of [`Self::sql_predicate`].
    ///
    /// Deliberately NOT named `denied()`: this is the BIND payload, which for a
    /// restricted caller is a superset of the caller's own denied sources (it
    /// also carries the NAN-2155 unresolved-provenance sentinel). Every bind
    /// site must use this, so there is no accessor returning the bare deny set
    /// that could be bound by mistake.
    pub fn deny_bind_values(&self) -> &[String] {
        &self.deny
    }

    /// SQL fragment restricting a row set to what this scope may see, or an
    /// empty string when unrestricted.
    ///
    /// `column` is a compile-time literal naming the (optionally alias-
    /// qualified) `source_types` column — never caller-controlled, so no
    /// identifier escaping is required. `param` is the 1-based placeholder
    /// index the deny array will be bound to.
    ///
    /// The `$n::text[] = '{}'` arm is belt-and-braces: callers only append the
    /// fragment for a non-empty scope, but an empty bind must never widen into
    /// "deny everything".
    pub fn sql_predicate(column: &'static str, param: usize) -> String {
        format!(" AND (${param}::text[] = '{{}}' OR NOT ({column} && ${param}::text[]))")
    }
}

/// Per-disposition rollup over a rule's matches within a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DispositionStats {
    pub total: i64,
    pub unclassified: i64,
    pub true_positive: i64,
    pub false_positive: i64,
    pub benign: i64,
}

/// Review state returned after a successful scoped review write.
#[derive(Debug, Clone)]
pub struct MatchReview {
    pub reviewed_at: DateTime<Utc>,
    pub reviewed_by: Option<Uuid>,
    pub note: Option<String>,
}

/// Source-scoped data access for `detection_matches` and `match_reviews`.
///
/// Cheap to construct — `PgPool` is an `Arc` internally — so handlers build one
/// per request instead of threading another field through `AppState`.
#[derive(Debug, Clone)]
pub struct DetectionMatchRepository {
    pool: PgPool,
}

impl DetectionMatchRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Disposition rollup for one rule over `[start, end]`, counting only the
    /// matches `scope` may see.
    ///
    /// NAN-2071: an unscoped rollup is a count oracle — it reveals how much
    /// denied-source activity a rule saw, when, and how analysts classified it,
    /// even though the row-level read path correctly hides those rows.
    pub async fn disposition_stats(
        &self,
        rule_id: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope: &MatchScope,
    ) -> Result<DispositionStats, sqlx::Error> {
        // One pass, FILTER per disposition. Avoids 4 round trips and uses the
        // composite index (rule_id, disposition, detected_at).
        let mut sql = String::from(
            r#"
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE disposition = 'unclassified')   AS unclassified,
            COUNT(*) FILTER (WHERE disposition = 'true_positive')  AS true_positive,
            COUNT(*) FILTER (WHERE disposition = 'false_positive') AS false_positive,
            COUNT(*) FILTER (WHERE disposition = 'benign')         AS benign
        FROM detection_matches
        WHERE rule_id = $1
          AND detected_at >= $2
          AND detected_at <= $3
        "#,
        );
        if !scope.is_unrestricted() {
            sql.push_str(&MatchScope::sql_predicate("source_types", 4));
        }

        let mut q = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(&sql)
            .bind(rule_id)
            .bind(start)
            .bind(end);
        if !scope.is_unrestricted() {
            q = q.bind(scope.deny_bind_values());
        }

        let row = q.fetch_one(&self.pool).await?;
        Ok(DispositionStats {
            total: row.0,
            unclassified: row.1,
            true_positive: row.2,
            false_positive: row.3,
            benign: row.4,
        })
    }

    /// Per-rule firing counts since `since`, counting only visible matches.
    pub async fn firing_counts_since(
        &self,
        since: DateTime<Utc>,
        scope: &MatchScope,
    ) -> Result<Vec<(Uuid, i64)>, sqlx::Error> {
        let mut sql = String::from(
            r#"
        SELECT rule_id, COUNT(*)::bigint AS firings
        FROM detection_matches
        WHERE detected_at >= $1
        "#,
        );
        if !scope.is_unrestricted() {
            sql.push_str(&MatchScope::sql_predicate("source_types", 2));
        }
        sql.push_str(" GROUP BY rule_id");

        let mut q = sqlx::query_as::<_, (Uuid, i64)>(&sql).bind(since);
        if !scope.is_unrestricted() {
            q = q.bind(scope.deny_bind_values());
        }
        q.fetch_all(&self.pool).await
    }

    /// Set a match's disposition, conditional on the row being visible.
    ///
    /// Returns the stored disposition, or `None` when no VISIBLE match with
    /// that id exists — the caller renders that identically to "missing".
    /// The predicate is part of the `UPDATE`, so a denied row is never written.
    pub async fn set_disposition(
        &self,
        match_id: Uuid,
        disposition: &str,
        scope: &MatchScope,
    ) -> Result<Option<String>, sqlx::Error> {
        let mut sql = String::from("UPDATE detection_matches SET disposition = $2 WHERE id = $1");
        if !scope.is_unrestricted() {
            sql.push_str(&MatchScope::sql_predicate("source_types", 3));
        }
        sql.push_str(" RETURNING disposition");

        let mut q = sqlx::query_as::<_, (String,)>(&sql)
            .bind(match_id)
            .bind(disposition);
        if !scope.is_unrestricted() {
            q = q.bind(scope.deny_bind_values());
        }
        Ok(q.fetch_optional(&self.pool).await?.map(|r| r.0))
    }

    /// Upsert the review row for a match, conditional on the match being
    /// visible.
    ///
    /// `INSERT … SELECT … WHERE <visible>` — when the match is denied or absent
    /// the `SELECT` yields no rows, so nothing is inserted and `None` comes
    /// back. No separate existence probe, so no check-then-act window.
    pub async fn mark_reviewed(
        &self,
        match_id: Uuid,
        reviewed_at: DateTime<Utc>,
        reviewed_by: Uuid,
        note: Option<&str>,
        scope: &MatchScope,
    ) -> Result<Option<MatchReview>, sqlx::Error> {
        let mut sql = String::from(
            r#"
        INSERT INTO match_reviews (match_id, reviewed_at, reviewed_by, note)
        SELECT dm.id, $2, $3, $4
        FROM detection_matches dm
        WHERE dm.id = $1
        "#,
        );
        if !scope.is_unrestricted() {
            sql.push_str(&MatchScope::sql_predicate("dm.source_types", 5));
        }
        sql.push_str(
            r#"
        ON CONFLICT (match_id) DO UPDATE
        SET reviewed_at = EXCLUDED.reviewed_at,
            reviewed_by = EXCLUDED.reviewed_by,
            note        = EXCLUDED.note
        RETURNING reviewed_at, reviewed_by, note
        "#,
        );

        let mut q = sqlx::query_as::<_, (DateTime<Utc>, Option<Uuid>, Option<String>)>(&sql)
            .bind(match_id)
            .bind(reviewed_at)
            .bind(reviewed_by)
            .bind(note);
        if !scope.is_unrestricted() {
            q = q.bind(scope.deny_bind_values());
        }

        Ok(q.fetch_optional(&self.pool).await?.map(|r| MatchReview {
            reviewed_at: r.0,
            reviewed_by: r.1,
            note: r.2,
        }))
    }

    /// Clear the review flag on a match, conditional on the match being visible.
    ///
    /// Returns `true` when a VISIBLE match with that id exists (whether or not
    /// it had a review row — clearing is idempotent), `false` when it is denied
    /// or absent. The `DELETE` lives in a CTE fed by the visible-rows
    /// sub-select, so the visibility test and the write are one statement.
    pub async fn clear_review(
        &self,
        match_id: Uuid,
        scope: &MatchScope,
    ) -> Result<bool, sqlx::Error> {
        let mut visible = String::from("SELECT dm.id FROM detection_matches dm WHERE dm.id = $1");
        if !scope.is_unrestricted() {
            visible.push_str(&MatchScope::sql_predicate("dm.source_types", 2));
        }
        // A data-modifying CTE always runs to completion even when the outer
        // query does not read its output, so `deleted` executes exactly once.
        let sql = format!(
            r#"
        WITH visible AS ({visible}),
        deleted AS (
            DELETE FROM match_reviews
            WHERE match_id IN (SELECT id FROM visible)
            RETURNING match_id
        )
        SELECT id FROM visible
        "#
        );

        let mut q = sqlx::query_as::<_, (Uuid,)>(&sql).bind(match_id);
        if !scope.is_unrestricted() {
            q = q.bind(scope.deny_bind_values());
        }
        Ok(q.fetch_optional(&self.pool).await?.is_some())
    }
}

#[cfg(test)]
#[path = "match_scope_tests.rs"]
mod match_scope_tests;
