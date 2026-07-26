// SPDX-License-Identifier: AGPL-3.0-or-later
//! Regression coverage for NAN-2150 optimistic concurrency.
//!
//! Source-config and log-source updates merge redacted secret placeholders
//! against a freshly read stored document before writing. The final write must
//! still be a compare-and-swap so a credential rotation that lands inside that
//! read/merge/write window cannot be silently reverted.

mod common;

use std::time::Duration;

use chrono::{DateTime, Utc};
use nanosiem_core::{
    LogSourceRepository, LogSourceRepositoryError, SourceConfigRepository,
    SourceConfigRepositoryError, UpdateLogSource, UpdateSourceConfiguration,
};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn source_config_expected_updated_at_allows_exactly_one_concurrent_writer() {
    let pool = common::migrated_pool().await;
    let id = Uuid::now_v7();
    let name = format!("nan-2150-source-config-{id}");
    let original_updated_at: DateTime<Utc> = sqlx::query_scalar(
        r#"
        INSERT INTO source_configurations
            (id, name, config_type, connection_config)
        VALUES ($1, $2, 'kafka', '{"password":"original"}')
        RETURNING updated_at
        "#,
    )
    .bind(id)
    .bind(&name)
    .fetch_one(&pool)
    .await
    .expect("create source configuration");

    // The trigger uses transaction-start NOW(). Ensure the winning update's
    // timestamp differs from the INSERT timestamp even on a fast local DB.
    tokio::time::sleep(Duration::from_millis(2)).await;

    let first = UpdateSourceConfiguration {
        description: Some("first writer".to_string()),
        expected_updated_at: Some(original_updated_at),
        ..Default::default()
    };
    let second = UpdateSourceConfiguration {
        description: Some("second writer".to_string()),
        expected_updated_at: Some(original_updated_at),
        ..Default::default()
    };
    let repo_a = SourceConfigRepository::new(pool.clone());
    let repo_b = SourceConfigRepository::new(pool.clone());
    let (result_a, result_b) = tokio::join!(repo_a.update(id, first), repo_b.update(id, second));

    let results = [result_a, result_b];
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one compare-and-swap must win"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(SourceConfigRepositoryError::StaleVersion(v)) if *v == id))
            .count(),
        1,
        "the losing writer must receive StaleVersion"
    );

    // Backwards compatibility: omitting expected_updated_at remains an
    // unconditional update.
    SourceConfigRepository::new(pool.clone())
        .update(
            id,
            UpdateSourceConfiguration {
                description: Some("legacy unconditional writer".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("unconditional source-config update");

    sqlx::query("DELETE FROM source_configurations WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("cleanup source configuration");
}

#[tokio::test]
#[ignore = "requires a live Postgres (DATABASE_URL); run with --ignored"]
async fn log_source_expected_updated_at_allows_exactly_one_concurrent_writer() {
    let pool = common::migrated_pool().await;
    let id = Uuid::now_v7();
    let name = format!("nan-2150-log-source-{id}");
    let original_updated_at: DateTime<Utc> = sqlx::query_scalar(
        r#"
        INSERT INTO log_sources
            (id, name, source_type, source_config, parser_vrl)
        VALUES ($1, $2, 'syslog', '{"password":"original"}', '.')
        RETURNING updated_at
        "#,
    )
    .bind(id)
    .bind(&name)
    .fetch_one(&pool)
    .await
    .expect("create log source");

    tokio::time::sleep(Duration::from_millis(2)).await;

    let first = UpdateLogSource {
        description: Some("first writer".to_string()),
        expected_updated_at: Some(original_updated_at),
        ..Default::default()
    };
    let second = UpdateLogSource {
        description: Some("second writer".to_string()),
        expected_updated_at: Some(original_updated_at),
        ..Default::default()
    };
    let repo_a = LogSourceRepository::new(pool.clone());
    let repo_b = LogSourceRepository::new(pool.clone());
    let (result_a, result_b) = tokio::join!(repo_a.update(id, &first), repo_b.update(id, &second),);

    let results = [result_a, result_b];
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        1,
        "exactly one compare-and-swap must win"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(LogSourceRepositoryError::StaleVersion(v)) if *v == id))
            .count(),
        1,
        "the losing writer must receive StaleVersion"
    );

    LogSourceRepository::new(pool.clone())
        .update(
            id,
            &UpdateLogSource {
                description: Some("legacy unconditional writer".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("unconditional log-source update");

    sqlx::query("DELETE FROM log_sources WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .expect("cleanup log source");
}
