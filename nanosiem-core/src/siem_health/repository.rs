// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository for SIEM health check reports

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::SourceProvenance;

use super::types::{SiemHealthReport, SiemHealthReportSummary};

#[derive(Error, Debug)]
pub enum SiemHealthRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Report not found: {0}")]
    NotFound(String),
}

#[derive(Clone)]
pub struct SiemHealthRepository {
    pool: PgPool,
}

impl SiemHealthRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Insert a new health report
    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        overall_score: i32,
        overall_status: &str,
        ingestion_score: i32,
        parsing_score: i32,
        enrichment_score: i32,
        detection_score: i32,
        alerting_score: i32,
        summary: &str,
        metrics: &serde_json::Value,
        recommendations: &serde_json::Value,
        dimension_details: &serde_json::Value,
        provenance: &SourceProvenance,
        triggered_by: Option<Uuid>,
        duration_ms: Option<i32>,
    ) -> Result<SiemHealthReport, SiemHealthRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO siem_health_reports
                (overall_score, overall_status, ingestion_score, parsing_score, detection_score,
                 enrichment_score, alerting_score,
                 summary, metrics, recommendations, dimension_details,
                 source_types, source_types_complete, triggered_by, duration_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING id, overall_score, overall_status, ingestion_score, parsing_score,
                      detection_score, enrichment_score, alerting_score,
                      summary, metrics, recommendations, dimension_details,
                      triggered_by, created_at, duration_ms,
                      source_types, source_types_complete
            "#,
        )
        .bind(overall_score)
        .bind(overall_status)
        .bind(ingestion_score)
        .bind(parsing_score)
        .bind(detection_score)
        .bind(enrichment_score)
        .bind(alerting_score)
        .bind(summary)
        .bind(metrics)
        .bind(recommendations)
        .bind(dimension_details)
        .bind(provenance.source_types())
        .bind(provenance.is_complete())
        .bind(triggered_by)
        .bind(duration_ms)
        .fetch_one(&self.pool)
        .await?;

        Ok(Self::row_to_report(&row))
    }

    /// Get the most recent report
    pub async fn get_latest(&self) -> Result<Option<SiemHealthReport>, SiemHealthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, overall_score, overall_status, ingestion_score, parsing_score,
                   detection_score, enrichment_score, alerting_score,
                   summary, metrics, recommendations, dimension_details,
                   triggered_by, created_at, duration_ms,
                   source_types, source_types_complete
            FROM siem_health_reports
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.as_ref().map(Self::row_to_report))
    }

    /// Get a report by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<SiemHealthReport, SiemHealthRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT id, overall_score, overall_status, ingestion_score, parsing_score,
                   detection_score, enrichment_score, alerting_score,
                   summary, metrics, recommendations, dimension_details,
                   triggered_by, created_at, duration_ms,
                   source_types, source_types_complete
            FROM siem_health_reports
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SiemHealthRepositoryError::NotFound(id.to_string()))?;

        Ok(Self::row_to_report(&row))
    }

    /// List report summaries (without full metrics/details), newest first
    pub async fn list_summaries(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SiemHealthReportSummary>, i64), SiemHealthRepositoryError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM siem_health_reports")
            .fetch_one(&self.pool)
            .await?;

        let rows = sqlx::query(
            r#"
            SELECT id, overall_score, overall_status, ingestion_score, parsing_score,
                   detection_score, enrichment_score, alerting_score,
                   summary, triggered_by, created_at, duration_ms
            FROM siem_health_reports
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let summaries = rows
            .iter()
            .map(|r| SiemHealthReportSummary {
                id: r.get("id"),
                overall_score: r.get("overall_score"),
                overall_status: r.get("overall_status"),
                ingestion_score: r.get("ingestion_score"),
                parsing_score: r.get("parsing_score"),
                detection_score: r.get("detection_score"),
                enrichment_score: r.get("enrichment_score"),
                alerting_score: r.get("alerting_score"),
                summary: r.get("summary"),
                triggered_by: r.get("triggered_by"),
                created_at: r.get("created_at"),
                duration_ms: r.get("duration_ms"),
            })
            .collect();

        Ok((summaries, count.0))
    }

    fn row_to_report(row: &sqlx::postgres::PgRow) -> SiemHealthReport {
        SiemHealthReport {
            id: row.get("id"),
            overall_score: row.get("overall_score"),
            overall_status: row.get("overall_status"),
            ingestion_score: row.get("ingestion_score"),
            parsing_score: row.get("parsing_score"),
            detection_score: row.get("detection_score"),
            enrichment_score: row.get("enrichment_score"),
            alerting_score: row.get("alerting_score"),
            summary: row.get("summary"),
            metrics: row.get("metrics"),
            recommendations: row.get("recommendations"),
            dimension_details: row.get("dimension_details"),
            triggered_by: row.get("triggered_by"),
            created_at: row.get("created_at"),
            duration_ms: row.get("duration_ms"),
            source_types: row.get("source_types"),
            source_types_complete: row.get("source_types_complete"),
        }
    }
}
