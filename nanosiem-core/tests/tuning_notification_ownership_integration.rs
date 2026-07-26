// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2087 — the tuning notification mark-read must not mutate before it
//! authorizes.
//!
//! `POST /api/tuning/notifications/{id}/read` used to run
//! `UPDATE notifications SET read_at = NOW() WHERE id = $1 AND read_at IS NULL`
//! — no `user_id` predicate — and only AFTERWARDS search the caller's own
//! notifications, returning a plausible 404 while the foreign row had already
//! been marked read. Any `detections:view` principal could therefore suppress
//! other users' (including admins') tuning notifications.
//!
//! The regression that matters is a DATABASE state assertion: "did the foreign
//! row stay unread", which only a real Postgres can answer. `#[ignore]`d like
//! the sibling DB suites; the `pg-integration-tests` lane runs them with
//! `-- --ignored`.

mod common;

use chrono::{DateTime, Utc};
use nanosiem_core::tuning::notifications::NotificationService;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'NAN-2087 Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("nan2087-{id}@example.com"))
    .execute(pool)
    .await
    .expect("insert user");
    id
}

async fn create_notification(pool: &PgPool, user_id: Uuid, notification_type: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO notifications (user_id, notification_type, title, message, link, metadata)
        VALUES ($1, $2, 'NAN-2087', 'fixture', '/rules/tuning/x', '{}'::jsonb)
        RETURNING id
        "#,
    )
    .bind(user_id)
    .bind(notification_type)
    .fetch_one(pool)
    .await
    .expect("insert notification")
}

async fn read_at(pool: &PgPool, id: Uuid) -> Option<DateTime<Utc>> {
    sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT read_at FROM notifications WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read notification")
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn owner_can_mark_their_own_tuning_notification_read() {
    let pool = common::migrated_pool().await;
    let service = NotificationService::new(pool.clone());
    let owner = create_user(&pool).await;
    let id = create_notification(&pool, owner, "tuning_triggered").await;

    assert!(service
        .mark_as_read(id, owner)
        .await
        .expect("mark")
        .is_some());
    assert!(read_at(&pool, id).await.is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn a_non_owner_cannot_mark_the_notification_read_and_leaves_it_unread() {
    // The live repro from the finding: the response was a 404 but the row had
    // already flipped to read.
    let pool = common::migrated_pool().await;
    let service = NotificationService::new(pool.clone());
    let owner = create_user(&pool).await;
    let attacker = create_user(&pool).await;
    let id = create_notification(&pool, owner, "tuning_triggered").await;

    assert!(service
        .mark_as_read(id, attacker)
        .await
        .expect("mark")
        .is_none());
    assert!(
        read_at(&pool, id).await.is_none(),
        "a non-owner's call must not have mutated the row"
    );

    // …and the owner is still able to mark it read afterwards.
    assert!(service
        .mark_as_read(id, owner)
        .await
        .expect("mark")
        .is_some());
    assert!(read_at(&pool, id).await.is_some());
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn an_unknown_id_has_no_side_effect_and_is_indistinguishable_from_a_foreign_one() {
    let pool = common::migrated_pool().await;
    let service = NotificationService::new(pool.clone());
    let owner = create_user(&pool).await;
    let attacker = create_user(&pool).await;
    let foreign = create_notification(&pool, owner, "tuning_triggered").await;

    let ghost_result = service
        .mark_as_read(Uuid::now_v7(), attacker)
        .await
        .expect("mark");
    let foreign_result = service.mark_as_read(foreign, attacker).await.expect("mark");
    assert!(
        ghost_result.is_none() && foreign_result.is_none(),
        "denied and missing must be indistinguishable — no existence oracle"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn marking_an_already_read_owned_notification_is_idempotent() {
    let pool = common::migrated_pool().await;
    let service = NotificationService::new(pool.clone());
    let owner = create_user(&pool).await;
    let id = create_notification(&pool, owner, "tuning_triggered").await;

    assert!(service
        .mark_as_read(id, owner)
        .await
        .expect("mark")
        .is_some());
    let first = read_at(&pool, id).await.expect("read");

    assert!(
        service
            .mark_as_read(id, owner)
            .await
            .expect("mark")
            .is_some(),
        "an already-read owned notification must still report success"
    );
    assert_eq!(
        read_at(&pool, id).await.expect("read"),
        first,
        "re-marking must not move the original read timestamp"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn the_tuning_route_cannot_mutate_a_non_tuning_notification() {
    // Every read path on this service filters `notification_type LIKE
    // 'tuning_%'`; the write now matches, so the tuning route can only touch
    // rows it can also list. The generic notification handler owns the rest.
    let pool = common::migrated_pool().await;
    let service = NotificationService::new(pool.clone());
    let owner = create_user(&pool).await;
    let id = create_notification(&pool, owner, "alert_assigned").await;

    assert!(service
        .mark_as_read(id, owner)
        .await
        .expect("mark")
        .is_none());
    assert!(read_at(&pool, id).await.is_none());
}
