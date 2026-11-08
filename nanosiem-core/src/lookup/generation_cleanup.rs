// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable reconciliation for staged and retired lookup generations.

use sqlx::{FromRow, PgPool};

use super::{ClickHouseLookupRepository, LookupRepositoryError, LookupStore};
use crate::system_health::{
    HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
};

const HEALTH_DEDUP_KEY: &str = "lookup:generation_cleanup_failed";
const MAX_BATCH: i64 = 100;

#[derive(Debug, Clone, FromRow)]
struct CleanupGeneration {
    physical_name: String,
    logical_name: String,
    storage_backend: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LookupCleanupReport {
    pub examined: usize,
    pub purged: usize,
    pub live_journal_entries_cleared: usize,
    pub busy: usize,
    pub failed: usize,
}

/// One bounded pass over the PostgreSQL cleanup journal. The jobs process owns
/// this reconciler only while it holds leadership; a per-lookup advisory lock
/// also keeps a pass from deleting a generation that is actively being staged.
#[derive(Clone)]
pub struct LookupGenerationReconciler {
    pool: PgPool,
    clickhouse: ClickHouseLookupRepository,
    health: SystemHealthRepository,
}

impl LookupGenerationReconciler {
    pub fn new(pool: PgPool, clickhouse: clickhouse::Client) -> Self {
        Self {
            clickhouse: ClickHouseLookupRepository::new(pool.clone(), clickhouse),
            health: SystemHealthRepository::new(pool.clone()),
            pool,
        }
    }

    pub async fn run_once(&self, limit: i64) -> Result<LookupCleanupReport, LookupRepositoryError> {
        let generations = sqlx::query_as::<_, CleanupGeneration>(
            r#"
            SELECT physical_name, logical_name, storage_backend
            FROM lookup_generation_cleanup
            WHERE next_attempt_at <= NOW()
            ORDER BY next_attempt_at, created_at
            LIMIT $1
            "#,
        )
        .bind(limit.clamp(1, MAX_BATCH))
        .fetch_all(&self.pool)
        .await?;

        let mut report = LookupCleanupReport::default();
        for generation in generations {
            report.examined += 1;
            match self.reconcile_generation(&generation).await? {
                ReconcileResult::Purged => report.purged += 1,
                ReconcileResult::LiveEntryCleared => report.live_journal_entries_cleared += 1,
                ReconcileResult::Busy => report.busy += 1,
                ReconcileResult::Failed => report.failed += 1,
            }
        }

        self.update_health(&report).await;
        Ok(report)
    }

    async fn reconcile_generation(
        &self,
        generation: &CleanupGeneration,
    ) -> Result<ReconcileResult, LookupRepositoryError> {
        let mut transaction = self.pool.begin().await?;
        let locked: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtextextended('nanosiem.lookup:' || $1, 0))",
        )
        .bind(&generation.logical_name)
        .fetch_one(&mut *transaction)
        .await?;
        if !locked {
            transaction.rollback().await?;
            return Ok(ReconcileResult::Busy);
        }

        let referenced: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM lookup_tables_registry WHERE table_name = $1)",
        )
        .bind(&generation.physical_name)
        .fetch_one(&mut *transaction)
        .await?;
        if referenced {
            sqlx::query("DELETE FROM lookup_generation_cleanup WHERE physical_name = $1")
                .bind(&generation.physical_name)
                .execute(&mut *transaction)
                .await?;
            transaction.commit().await?;
            return Ok(ReconcileResult::LiveEntryCleared);
        }

        let cleanup = match generation.storage_backend.as_str() {
            "clickhouse" => {
                LookupStore::drop_dynamic_table(&self.clickhouse, &generation.physical_name).await
            }
            "postgres" => {
                let postgres = super::PostgresLookupRepository::new(self.pool.clone());
                LookupStore::drop_dynamic_table(&postgres, &generation.physical_name).await
            }
            other => Err(LookupRepositoryError::DatabaseError(sqlx::Error::Protocol(
                format!("unsupported lookup cleanup backend: {other}"),
            ))),
        };

        match cleanup {
            Ok(()) => {
                sqlx::query("DELETE FROM lookup_generation_cleanup WHERE physical_name = $1")
                    .bind(&generation.physical_name)
                    .execute(&mut *transaction)
                    .await?;
                transaction.commit().await?;
                Ok(ReconcileResult::Purged)
            }
            Err(error) => {
                let message: String = error.to_string().chars().take(2_000).collect();
                // Each pass is bounded, and exponential retry delay is capped at
                // fifteen minutes so a transient failure is never abandoned.
                sqlx::query(
                    r#"
                    UPDATE lookup_generation_cleanup
                    SET attempt_count = attempt_count + 1,
                        next_attempt_at = NOW() + make_interval(
                            secs => LEAST(900, 5 * (1 << LEAST(attempt_count, 8)))
                        ),
                        last_error = $2,
                        updated_at = NOW()
                    WHERE physical_name = $1
                    "#,
                )
                .bind(&generation.physical_name)
                .bind(message)
                .execute(&mut *transaction)
                .await?;
                transaction.commit().await?;
                Ok(ReconcileResult::Failed)
            }
        }
    }

    async fn update_health(&self, report: &LookupCleanupReport) {
        let failed_backlog = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lookup_generation_cleanup WHERE last_error IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await;
        let Ok(failed_backlog) = failed_backlog else {
            tracing::warn!("Failed to read lookup cleanup backlog for SIEM Health");
            return;
        };

        if failed_backlog == 0 {
            if let Err(error) = self.health.resolve_by_dedup_key(HEALTH_DEDUP_KEY).await {
                tracing::warn!(%error, "Failed to resolve lookup cleanup SIEM Health event");
            }
            return;
        }
        if report.failed == 0 {
            return;
        }

        let mut event = PublishHealthEvent::new(
            HEALTH_DEDUP_KEY,
            HealthCategory::Storage,
            HealthSeverity::Medium,
            "Lookup generation cleanup is retrying",
            format!(
                "{failed_backlog} staged or retired lookup generation(s) could not be purged; the leader reconciler will retry automatically"
            ),
            "lookup_generation_cleanup",
            "lookup_generation_reconciler",
        );
        event.diagnostic_context = serde_json::json!({
            "failed_backlog": failed_backlog,
            "failed_this_pass": report.failed,
        });
        event.remediation = Some(
            "Check PostgreSQL/ClickHouse availability and ALTER DELETE permissions; cleanup retries are automatic."
                .to_string(),
        );
        if let Err(error) = self.health.publish(&event).await {
            tracing::warn!(%error, "Failed to publish lookup cleanup SIEM Health event");
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileResult {
    Purged,
    LiveEntryCleared,
    Busy,
    Failed,
}
