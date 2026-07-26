// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2071 — DB-backed matrix for the `detection_matches` source scope.
//!
//! NAN-1808 scoped ONE read path (`GET /api/rules/{id}/matches`); its siblings
//! — the disposition rollup, the per-rule "today" firing counts, and the two
//! by-id MUTATIONS — kept operating on the raw table. A principal denied every
//! source on a match could count it, mark it reviewed, and reclassify it, and
//! the 200-vs-404 split on the review route was an existence oracle.
//!
//! These assertions run the REAL SQL (array overlap, the conditional
//! `UPDATE`/`INSERT … SELECT`/CTE `DELETE`) against a migrated Postgres, which
//! is the only way to catch a predicate that compiles but does not filter.
//! `#[ignore]`d like the sibling DB suites: the `pg-integration-tests` lane runs
//! them with `-- --ignored` (locally `docker compose up -d postgres`).

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::detection::match_scope::{DetectionMatchRepository, MatchScope};
use sqlx::PgPool;
use std::collections::BTreeSet;
use uuid::Uuid;

fn deny(values: &[&str]) -> MatchScope {
    let set: BTreeSet<String> = values.iter().map(|s| s.to_string()).collect();
    MatchScope::from_denied(&set)
}

async fn insert_rule(pool: &PgPool) -> Uuid {
    let rule_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO detection_rules (id, name, description, query, severity, mode)
        VALUES ($1, $2, 'NAN-2071 scope test', 'source_type=apache', 'medium', 'alerting')
        "#,
    )
    .bind(rule_id)
    .bind(format!("NAN-2071-{rule_id}"))
    .execute(pool)
    .await
    .expect("insert rule");
    rule_id
}

async fn insert_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Match Scope Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("nan2071-{id}@example.com"))
    .execute(pool)
    .await
    .expect("insert user");
    id
}

/// One detection match stamped with `source_types`, `detected_at` today so it
/// lands in the `firing_counts_since` window.
async fn insert_match(pool: &PgPool, rule_id: Uuid, source_types: &[&str]) -> Uuid {
    let id = Uuid::now_v7();
    let stamps: Vec<String> = source_types.iter().map(|s| s.to_string()).collect();
    sqlx::query(
        r#"
        INSERT INTO detection_matches
            (id, rule_id, rule_name, severity, matched_events, event_count, detected_at, source_types)
        VALUES ($1, $2, 'nan2071', 'medium', '[{"message":"secret"}]'::jsonb, 1, NOW(), $3)
        "#,
    )
    .bind(id)
    .bind(rule_id)
    .bind(&stamps)
    .execute(pool)
    .await
    .expect("insert detection match");
    id
}

async fn disposition_of(pool: &PgPool, match_id: Uuid) -> String {
    sqlx::query_scalar::<_, String>("SELECT disposition FROM detection_matches WHERE id = $1")
        .bind(match_id)
        .fetch_one(pool)
        .await
        .expect("read disposition")
}

async fn review_count(pool: &PgPool, match_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM match_reviews WHERE match_id = $1")
        .bind(match_id)
        .fetch_one(pool)
        .await
        .expect("count reviews")
}

// ---------------------------------------------------------------------------
// Reads / rollups
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Postgres"]
async fn disposition_stats_exclude_denied_matches_and_keep_granted_ones() {
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;

    insert_match(&pool, rule_id, &["apache"]).await;
    insert_match(&pool, rule_id, &["insider_threat"]).await;
    // Multi-source row: denied because ONE of its stamps is denied.
    insert_match(&pool, rule_id, &["apache", "insider_threat"]).await;
    // Unstamped row: never overlaps, stays visible (NAN-1808 back-compat).
    insert_match(&pool, rule_id, &[]).await;

    let start = Utc::now() - Duration::days(1);
    let end = Utc::now() + Duration::days(1);

    // Unrestricted caller sees everything.
    let all = repo
        .disposition_stats(rule_id, start, end, &MatchScope::unrestricted())
        .await
        .expect("unrestricted stats");
    assert_eq!(all.total, 4);
    assert_eq!(all.unclassified, 4);

    // Restricted WITH a grant for the source in play (it is simply not in the
    // deny set) still sees the apache rows.
    let granted = repo
        .disposition_stats(rule_id, start, end, &deny(&["something_else"]))
        .await
        .expect("granted stats");
    assert_eq!(granted.total, 4);

    // Restricted WITHOUT a grant loses both the pure and the mixed row.
    let restricted = repo
        .disposition_stats(rule_id, start, end, &deny(&["insider_threat"]))
        .await
        .expect("restricted stats");
    assert_eq!(
        restricted.total, 2,
        "denied-source and mixed-source matches must not be counted"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn disposition_stats_honour_case_and_whitespace_normalization() {
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    insert_match(&pool, rule_id, &["insider_threat"]).await;

    let stats = repo
        .disposition_stats(
            rule_id,
            Utc::now() - Duration::days(1),
            Utc::now() + Duration::days(1),
            &deny(&["  Insider_Threat "]),
        )
        .await
        .expect("stats");
    assert_eq!(stats.total, 0);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn firing_counts_exclude_denied_matches() {
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    insert_match(&pool, rule_id, &["apache"]).await;
    insert_match(&pool, rule_id, &["insider_threat"]).await;

    let since = Utc::now() - Duration::hours(1);

    let count_for = |rows: Vec<(Uuid, i64)>| {
        rows.into_iter()
            .find(|(rid, _)| *rid == rule_id)
            .map(|(_, n)| n)
            .unwrap_or(0)
    };

    let all = repo
        .firing_counts_since(since, &MatchScope::unrestricted())
        .await
        .expect("unrestricted counts");
    assert_eq!(count_for(all), 2);

    let restricted = repo
        .firing_counts_since(since, &deny(&["insider_threat"]))
        .await
        .expect("restricted counts");
    assert_eq!(count_for(restricted), 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn implicit_audit_deny_hides_audit_derived_matches() {
    // A caller without `audit:view` arrives with "audit" in its deny set.
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let audit_match = insert_match(&pool, rule_id, &["audit"]).await;

    let scope = deny(&["audit"]);
    let stats = repo
        .disposition_stats(
            rule_id,
            Utc::now() - Duration::days(1),
            Utc::now() + Duration::days(1),
            &scope,
        )
        .await
        .expect("stats");
    assert_eq!(stats.total, 0);

    assert!(repo
        .set_disposition(audit_match, "benign", &scope)
        .await
        .expect("set disposition")
        .is_none());
}

// ---------------------------------------------------------------------------
// Mutations — the IDOR half
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires Postgres"]
async fn set_disposition_is_refused_and_writes_nothing_for_a_denied_match() {
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let denied_match = insert_match(&pool, rule_id, &["insider_threat"]).await;
    let mixed_match = insert_match(&pool, rule_id, &["apache", "insider_threat"]).await;
    let visible_match = insert_match(&pool, rule_id, &["apache"]).await;
    let unstamped = insert_match(&pool, rule_id, &[]).await;

    let scope = deny(&["insider_threat"]);

    assert!(repo
        .set_disposition(denied_match, "false_positive", &scope)
        .await
        .expect("call")
        .is_none());
    assert_eq!(disposition_of(&pool, denied_match).await, "unclassified");

    assert!(
        repo.set_disposition(mixed_match, "false_positive", &scope)
            .await
            .expect("call")
            .is_none(),
        "a row stamped with ANY denied source must be immutable"
    );
    assert_eq!(disposition_of(&pool, mixed_match).await, "unclassified");

    assert_eq!(
        repo.set_disposition(visible_match, "false_positive", &scope)
            .await
            .expect("call")
            .as_deref(),
        Some("false_positive")
    );
    assert_eq!(disposition_of(&pool, visible_match).await, "false_positive");

    assert_eq!(
        repo.set_disposition(unstamped, "benign", &scope)
            .await
            .expect("call")
            .as_deref(),
        Some("benign"),
        "unstamped matches are not source-derived and stay writable"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_missing_match_and_a_denied_match_are_indistinguishable() {
    // No existence oracle: the caller cannot tell "denied" from "never existed".
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let user_id = insert_user(&pool).await;
    let denied_match = insert_match(&pool, rule_id, &["insider_threat"]).await;
    let ghost = Uuid::now_v7();

    let scope = deny(&["insider_threat"]);

    assert_eq!(
        repo.set_disposition(denied_match, "benign", &scope)
            .await
            .expect("call"),
        repo.set_disposition(ghost, "benign", &scope)
            .await
            .expect("call")
    );
    assert!(repo
        .mark_reviewed(denied_match, Utc::now(), user_id, None, &scope)
        .await
        .expect("call")
        .is_none());
    assert!(repo
        .mark_reviewed(ghost, Utc::now(), user_id, None, &scope)
        .await
        .expect("call")
        .is_none());
    assert!(!repo.clear_review(denied_match, &scope).await.expect("call"));
    assert!(!repo.clear_review(ghost, &scope).await.expect("call"));
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn mark_reviewed_never_inserts_a_review_for_a_denied_match() {
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let user_id = insert_user(&pool).await;
    let denied_match = insert_match(&pool, rule_id, &["insider_threat"]).await;
    let visible_match = insert_match(&pool, rule_id, &["apache"]).await;

    let scope = deny(&["insider_threat"]);

    assert!(repo
        .mark_reviewed(denied_match, Utc::now(), user_id, Some("note"), &scope)
        .await
        .expect("call")
        .is_none());
    assert_eq!(
        review_count(&pool, denied_match).await,
        0,
        "the write must not have happened before authorization"
    );

    let review = repo
        .mark_reviewed(visible_match, Utc::now(), user_id, Some("note"), &scope)
        .await
        .expect("call")
        .expect("visible match is reviewable");
    assert_eq!(review.note.as_deref(), Some("note"));
    assert_eq!(review_count(&pool, visible_match).await, 1);

    // Idempotent upsert on a visible match.
    let again = repo
        .mark_reviewed(visible_match, Utc::now(), user_id, Some("second"), &scope)
        .await
        .expect("call")
        .expect("still reviewable");
    assert_eq!(again.note.as_deref(), Some("second"));
    assert_eq!(review_count(&pool, visible_match).await, 1);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn clear_review_leaves_a_denied_matchs_review_row_intact() {
    let pool = common::migrated_pool().await;
    let repo = DetectionMatchRepository::new(pool.clone());
    let rule_id = insert_rule(&pool).await;
    let user_id = insert_user(&pool).await;
    let denied_match = insert_match(&pool, rule_id, &["insider_threat"]).await;

    // An unrestricted analyst reviews it first.
    repo.mark_reviewed(
        denied_match,
        Utc::now(),
        user_id,
        Some("legit"),
        &MatchScope::unrestricted(),
    )
    .await
    .expect("call")
    .expect("reviewable unrestricted");
    assert_eq!(review_count(&pool, denied_match).await, 1);

    // A restricted caller must not be able to erase it.
    let scope = deny(&["insider_threat"]);
    assert!(!repo.clear_review(denied_match, &scope).await.expect("call"));
    assert_eq!(
        review_count(&pool, denied_match).await,
        1,
        "the DELETE must not have run for a denied match"
    );

    // The unrestricted caller still can.
    assert!(repo
        .clear_review(denied_match, &MatchScope::unrestricted())
        .await
        .expect("call"));
    assert_eq!(review_count(&pool, denied_match).await, 0);

    // Clearing a visible match with no review row is idempotent, not an error.
    assert!(repo
        .clear_review(denied_match, &MatchScope::unrestricted())
        .await
        .expect("call"));
}
