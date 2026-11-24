// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5770: the Log Sources "Unassigned" list stops offering a just-deleted
//! source's route key as a new stream.
//!
//! Against migrated PostgreSQL: a deleted, deployed (or token-bound) source's
//! key whose activity stopped by the delete moves to `removed_sources`; a key
//! that keeps arriving after the delete, a draft that never had a live claim,
//! and a key a live source took back stay where they were. Ignored in ordinary
//! unit runs; executed by the pg-integration lane.

mod common;

use chrono::{Duration, Utc};
use nanosiem_core::log_sources::connect::{
    removed_unassigned_keys, set_aside_removed, unassigned_sources, SourceActivity,
};
use sqlx::PgPool;
use uuid::Uuid;

async fn create(pool: &PgPool, name: &str, key: &str, deployed: bool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO log_sources (id, name, source_type, parser_vrl, match_values, deployed, deployed_at)
         VALUES ($1, $2, 'routed', '.', $3, $4, CASE WHEN $4 THEN now() END)",
    )
    .bind(id)
    .bind(name)
    .bind(vec![key.to_string()])
    .bind(deployed)
    .execute(pool)
    .await
    .expect("create log source");
    id
}

async fn bind_token(pool: &PgPool, source_id: Uuid) -> Uuid {
    let hex = format!("{}{}", Uuid::now_v7().simple(), Uuid::now_v7().simple());
    sqlx::query_scalar(
        "INSERT INTO ingest_tokens (name, token_prefix, token_sha256, source_id)
         VALUES ($1, 'nit_ABCDEFGH', $2, $3) RETURNING id",
    )
    .bind(format!("nan5770-{}", &hex[..12]))
    .bind(&hex)
    .bind(source_id)
    .fetch_one(pool)
    .await
    .expect("bind token")
}

async fn delete(pool: &PgPool, ids: &[Uuid]) {
    sqlx::query("DELETE FROM log_sources WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await
        .expect("delete log sources");
}

fn seen(key: &str, minutes_ago_first: i64, minutes_ago_last: i64) -> SourceActivity {
    let now = Utc::now();
    SourceActivity {
        route_key: key.into(),
        events_24h: 2,
        first_seen: Some(now - Duration::minutes(minutes_ago_first)),
        last_seen: Some(now - Duration::minutes(minutes_ago_last)),
    }
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn deleted_sources_quiet_keys_leave_the_unassigned_list() {
    let pool = common::migrated_pool().await;
    let s = Uuid::now_v7().simple().to_string();
    let (single, bulk_a, bulk_b, loud, draft, retaken) = (
        format!("single_{s}"),
        format!("bulk_a_{s}"),
        format!("bulk_b_{s}"),
        format!("loud_{s}"),
        format!("draft_{s}"),
        format!("retaken_{s}"),
    );
    let ids = [
        create(&pool, &format!("single {s}"), &single, true).await,
        create(&pool, &format!("bulk a {s}"), &bulk_a, true).await,
        create(&pool, &format!("bulk b {s}"), &bulk_b, false).await,
        create(&pool, &format!("loud {s}"), &loud, true).await,
        create(&pool, &format!("draft {s}"), &draft, false).await,
        create(&pool, &format!("retaken old {s}"), &retaken, true).await,
    ];
    // bulk b is a never-deployed draft with a bound token: still a live claim.
    let token = bind_token(&pool, ids[2]).await;
    delete(&pool, &ids[..1]).await;
    delete(&pool, &ids[1..]).await;
    // A new source claims the retaken key again.
    let retaker = create(&pool, &format!("retaken new {s}"), &retaken, false).await;

    // Events stopped 10 minutes BEFORE the delete for the quiet keys; the loud
    // key is still arriving (last event in the future of the delete + grace).
    let activity = vec![
        seen(&single, 60, 10),
        seen(&bulk_a, 60, 10),
        seen(&bulk_b, 60, 10),
        seen(&draft, 60, 10),
        seen(&retaken, 60, 10),
        SourceActivity { last_seen: Some(Utc::now() + Duration::minutes(10)), ..seen(&loud, 60, 0) },
    ];
    let live = nanosiem_core::log_sources::LogSourceRepository::new(pool.clone())
        .list(&nanosiem_core::log_sources::ListParams { limit: Some(10_000), ..Default::default() })
        .await
        .expect("live sources");

    let removed = removed_unassigned_keys(&pool, &activity).await;
    let (offered, set_aside) = set_aside_removed(unassigned_sources(&live, &activity), &removed);
    let offered: Vec<&str> = offered.iter().map(|o| o.route_key.as_str()).collect();
    let mut gone: Vec<&str> = set_aside.iter().map(|r| r.route_key.as_str()).collect();
    gone.sort();

    let mut want = vec![bulk_a.as_str(), bulk_b.as_str(), single.as_str()];
    want.sort();
    assert_eq!(gone, want, "the deleted sources' quiet keys are set aside as removed");
    assert!(offered.contains(&loud.as_str()), "a key still arriving after the delete stays offered");
    assert!(offered.contains(&draft.as_str()), "a never-claimed draft leaves no tombstone: nothing hidden");
    assert!(!offered.contains(&retaken.as_str()) && !gone.contains(&retaken.as_str()), "a live source claims it");
    let single_row = set_aside.iter().find(|r| r.route_key == single).unwrap();
    assert_eq!(single_row.log_source_name, format!("single {s}"));

    delete(&pool, &[retaker]).await;
    // The source delete set the token's source_id to NULL: remove the orphan.
    sqlx::query("DELETE FROM ingest_tokens WHERE id = $1")
        .bind(token)
        .execute(&pool)
        .await
        .expect("clean token");
    sqlx::query("DELETE FROM log_source_tombstones WHERE log_source_id = ANY($1)")
        .bind(&ids[..])
        .execute(&pool)
        .await
        .expect("clean tombstones");
}
