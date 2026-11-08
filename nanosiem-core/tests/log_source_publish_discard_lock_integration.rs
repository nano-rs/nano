// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4919: publish and discard-draft hold the source row lock through the
//! revision check and the version change, so a release review publishes
//! exactly the reviewed revision (or nothing) and a discard never resets the
//! working copy to a version a concurrent publish just replaced.

mod common;

use std::time::Duration;

use chrono::{DateTime, Utc};
use nanosiem_core::log_sources::{DiscardOutcome, LogSourceVersionRepository};
use uuid::Uuid;

async fn source(pool: &sqlx::PgPool, parser_vrl: &str) -> (Uuid, DateTime<Utc>) {
    let id = Uuid::now_v7();
    let updated_at: DateTime<Utc> = sqlx::query_scalar(
        "INSERT INTO log_sources (id, name, source_type, parser_vrl)
         VALUES ($1, $2, 'routed', $3) RETURNING updated_at",
    )
    .bind(id)
    .bind(format!("nan-4919-{id}"))
    .bind(parser_vrl)
    .fetch_one(pool)
    .await
    .expect("create log source");
    (id, updated_at)
}

async fn save(pool: &sqlx::PgPool, id: Uuid, parser_vrl: &str) -> DateTime<Utc> {
    // The trigger stamps transaction-start NOW(); keep revisions distinct.
    tokio::time::sleep(Duration::from_millis(2)).await;
    sqlx::query_scalar("UPDATE log_sources SET parser_vrl = $2 WHERE id = $1 RETURNING updated_at")
        .bind(id)
        .bind(parser_vrl)
        .fetch_one(pool)
        .await
        .expect("save working copy")
}

async fn active(pool: &sqlx::PgPool, id: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT parser_vrl FROM log_source_versions WHERE log_source_id = $1 AND is_active",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn publish_refuses_a_revision_that_moved_and_creates_nothing() {
    let pool = common::migrated_pool().await;
    let versions = LogSourceVersionRepository::new(pool.clone());
    let (id, reviewed) = source(&pool, ".reviewed = true").await;
    save(&pool, id, ".edited_after_review = true").await;
    assert!(versions
        .publish_revision(id, reviewed, None)
        .await
        .unwrap()
        .is_none());
    assert_eq!(active(&pool, id).await, None, "a stale publish must create no version");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn publish_waits_for_and_then_rejects_a_save_holding_the_row() {
    let pool = common::migrated_pool().await;
    let versions = LogSourceVersionRepository::new(pool.clone());
    let (id, reviewed) = source(&pool, ".reviewed = true").await;
    // A concurrent editor's save is mid-transaction when publish arrives.
    let mut editor = pool.begin().await.unwrap();
    sqlx::query("UPDATE log_sources SET parser_vrl = '.racing = true' WHERE id = $1")
        .bind(id)
        .execute(&mut *editor)
        .await
        .unwrap();
    let publish = tokio::spawn({
        let versions = versions.clone();
        async move { versions.publish_revision(id, reviewed, None).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!publish.is_finished(), "publish must wait for the row lock");
    editor.commit().await.unwrap();
    assert!(publish.await.unwrap().unwrap().is_none());
    assert_eq!(active(&pool, id).await, None);
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn discard_resets_to_the_active_version_under_the_same_lock() {
    let pool = common::migrated_pool().await;
    let versions = LogSourceVersionRepository::new(pool.clone());
    let (id, first) = source(&pool, ".v1 = true").await;
    assert!(versions.publish_revision(id, first, None).await.unwrap().is_some());
    let draft = save(&pool, id, ".draft = true").await;
    // A stale expected revision is refused without touching the row.
    assert_eq!(
        versions.discard_to_active(id, Some(first)).await.unwrap(),
        DiscardOutcome::Stale
    );
    // Race a publish of the draft against a discard many times: whichever
    // wins, the working copy must end equal to the ACTIVE version.
    for round in 0..20 {
        let draft_vrl = format!(".round = {round}");
        let revision = save(&pool, id, &draft_vrl).await;
        let (published, discarded) = tokio::join!(
            versions.publish_revision(id, revision, None),
            versions.discard_to_active(id, None)
        );
        published.unwrap();
        assert_eq!(discarded.unwrap(), DiscardOutcome::Discarded);
        let working: String =
            sqlx::query_scalar("SELECT parser_vrl FROM log_sources WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(Some(working), active(&pool, id).await, "round {round}");
    }
    let _ = draft;
}
