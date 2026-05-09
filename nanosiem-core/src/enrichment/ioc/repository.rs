// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC database repository operations
//!
//! Handles all IOC-related database operations including:
//! - IOC lookups (single and bulk)
//! - Staged inserts for zero-downtime updates
//! - TTL cleanup of expired IOCs
//! - Statistics queries

use super::parser::calculate_expires_at;
use super::types::{IocLookupResult, IocStats, IocType, ParsedIoc};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use thiserror::Error;
use tracing::{info, instrument};

#[derive(Error, Debug)]
pub enum IocRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Source not found: {0}")]
    SourceNotFound(String),
}

/// Repository for IOC enrichment data operations
#[derive(Clone)]
pub struct IocRepository {
    pool: PgPool,
}

impl IocRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the underlying pool (for use by service layer)
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // ========================================================================
    // IOC Lookup Operations
    // ========================================================================

    /// Lookup a single IOC value
    #[instrument(skip(self))]
    pub async fn lookup_ioc(
        &self,
        value: &str,
        ioc_type: Option<IocType>,
    ) -> Result<Option<IocLookupResult>, IocRepositoryError> {
        if value.is_empty() {
            return Ok(None);
        }

        let normalized_value = value.to_lowercase();

        let row = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                Option<String>,
                Option<i32>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                Vec<String>,
            ),
        >(
            r#"
            SELECT
                ie.source_id,
                ie.ioc_type::text,
                ie.threat_type,
                ie.malware,
                ie.confidence_level,
                ie.first_seen_at,
                ie.last_seen_at,
                ie.tags
            FROM ioc_enrichments ie
            JOIN enrichment_sources es ON ie.source_id = es.id
            WHERE ie.ioc_value = $1
              AND ($2::text IS NULL OR ie.ioc_type::text = $2)
              AND es.enabled = true
              AND ie.expires_at > NOW()
            ORDER BY ie.confidence_level DESC NULLS LAST
            LIMIT 1
            "#,
        )
        .bind(&normalized_value)
        .bind(ioc_type.map(|t| t.as_str()))
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(
                source_id,
                ioc_type,
                threat_type,
                malware,
                confidence,
                first_seen,
                last_seen,
                tags,
            )| {
                IocLookupResult {
                    found: true,
                    source_id: Some(source_id),
                    ioc_type: Some(ioc_type),
                    threat_type,
                    malware,
                    confidence_level: confidence,
                    first_seen_at: first_seen.map(|t| t.to_rfc3339()),
                    last_seen_at: last_seen.map(|t| t.to_rfc3339()),
                    tags,
                }
            },
        ))
    }

    /// Bulk lookup IOCs (for batch ingestion enrichment)
    /// Returns a map of ioc_value -> lookup result
    #[instrument(skip(self, values))]
    pub async fn lookup_iocs_bulk(
        &self,
        values: &[&str],
    ) -> Result<HashMap<String, IocLookupResult>, IocRepositoryError> {
        let mut results = HashMap::new();

        if values.is_empty() {
            return Ok(results);
        }

        // Normalize and deduplicate
        let unique_values: Vec<String> = values
            .iter()
            .filter(|v| !v.is_empty())
            .map(|v| v.to_lowercase())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if unique_values.is_empty() {
            return Ok(results);
        }

        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<i32>,
                Vec<String>,
            ),
        >(
            r#"
            SELECT DISTINCT ON (ie.ioc_value)
                ie.ioc_value,
                ie.source_id,
                ie.ioc_type::text,
                ie.threat_type,
                ie.malware,
                ie.confidence_level,
                ie.tags
            FROM ioc_enrichments ie
            JOIN enrichment_sources es ON ie.source_id = es.id
            WHERE ie.ioc_value = ANY($1::text[])
              AND es.enabled = true
              AND ie.expires_at > NOW()
            ORDER BY ie.ioc_value, ie.confidence_level DESC NULLS LAST
            "#,
        )
        .bind(&unique_values)
        .fetch_all(&self.pool)
        .await?;

        for (ioc_value, source_id, ioc_type, threat_type, malware, confidence, tags) in rows {
            results.insert(
                ioc_value,
                IocLookupResult {
                    found: true,
                    source_id: Some(source_id),
                    ioc_type: Some(ioc_type),
                    threat_type,
                    malware,
                    confidence_level: confidence,
                    first_seen_at: None,
                    last_seen_at: None,
                    tags,
                },
            );
        }

        Ok(results)
    }

    // ========================================================================
    // IOC Insert Operations (Staged for zero-downtime)
    // ========================================================================

    /// Insert IOCs into staging table, then atomically swap to production
    ///
    /// This method:
    /// 1. Clears staging table for this source
    /// 2. Bulk inserts parsed IOCs into staging
    /// 3. Atomically swaps staging to production
    #[instrument(skip(self, iocs), fields(source_id, ioc_count = iocs.len()))]
    pub async fn insert_iocs_staged(
        &self,
        source_id: &str,
        iocs: &[ParsedIoc],
        ttl_days: i64,
    ) -> Result<u64, IocRepositoryError> {
        if iocs.is_empty() {
            return Ok(0);
        }

        info!(
            source_id,
            ioc_count = iocs.len(),
            "Starting staged IOC load"
        );

        // Step 1: Clear staging table for this source
        sqlx::query("DELETE FROM ioc_enrichments_staging WHERE source_id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await?;

        let expires_at = calculate_expires_at(ttl_days);

        // Step 2: Batch insert into staging
        let mut inserted = 0u64;

        for chunk in iocs.chunks(500) {
            // Build dynamic INSERT query
            let mut query = String::from(
                r#"INSERT INTO ioc_enrichments_staging (
                    source_id, ioc_value, ioc_type, original_value,
                    threat_type, threat_type_desc, malware, malware_alias, malware_printable,
                    confidence_level, first_seen_at, last_seen_at, expires_at,
                    tags, reference_url, reporter
                ) VALUES "#,
            );

            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                let base = i * 16;
                query.push_str(&format!(
                    "(${}, ${}, ${}::ioc_type, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    base + 1, base + 2, base + 3, base + 4, base + 5, base + 6,
                    base + 7, base + 8, base + 9, base + 10, base + 11, base + 12,
                    base + 13, base + 14, base + 15, base + 16
                ));
            }

            let mut q = sqlx::query(&query);
            for ioc in chunk {
                q = q
                    .bind(source_id)
                    .bind(&ioc.ioc_value)
                    .bind(ioc.ioc_type.as_str())
                    .bind(&ioc.original_value)
                    .bind(&ioc.threat_type)
                    .bind(&ioc.threat_type_desc)
                    .bind(&ioc.malware)
                    .bind(&ioc.malware_alias)
                    .bind(&ioc.malware_printable)
                    .bind(ioc.confidence_level)
                    .bind(ioc.first_seen_at)
                    .bind(ioc.last_seen_at)
                    .bind(expires_at)
                    .bind(&ioc.tags)
                    .bind(&ioc.reference_url)
                    .bind(&ioc.reporter);
            }

            let result = q.execute(&self.pool).await?;
            inserted += result.rows_affected();

            if inserted % 5000 == 0 && inserted > 0 {
                info!(inserted, "Staging progress...");
            }
        }

        info!(inserted, "Staging complete, swapping to production");

        // Step 3: Atomic swap from staging to production
        let swapped: (i64,) = sqlx::query_as("SELECT swap_ioc_enrichment_staging($1)")
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;

        info!(swapped = swapped.0, "IOC swap complete");

        Ok(swapped.0 as u64)
    }

    // ========================================================================
    // TTL Cleanup Operations
    // ========================================================================

    /// Cleanup expired IOCs
    /// Returns the number of IOCs deleted
    #[instrument(skip(self))]
    pub async fn cleanup_expired(&self) -> Result<u64, IocRepositoryError> {
        let result = sqlx::query("DELETE FROM ioc_enrichments WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            info!(deleted, "Cleaned up expired IOCs");
        }

        Ok(deleted)
    }

    // ========================================================================
    // Statistics Operations
    // ========================================================================

    /// Get IOC statistics for a source
    #[instrument(skip(self))]
    pub async fn get_stats(&self, source_id: &str) -> Result<IocStats, IocRepositoryError> {
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE ioc_type = 'ip') as ip_count,
                COUNT(*) FILTER (WHERE ioc_type = 'domain') as domain_count,
                COUNT(*) FILTER (WHERE ioc_type IN ('md5_hash', 'sha256_hash')) as hash_count,
                COUNT(*) FILTER (WHERE ioc_type = 'url') as url_count,
                COUNT(*) as total
            FROM ioc_enrichments
            WHERE source_id = $1 AND expires_at > NOW()
            "#,
        )
        .bind(source_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(IocStats {
            ip_count: row.0,
            domain_count: row.1,
            hash_count: row.2,
            url_count: row.3,
            total: row.4,
        })
    }

    /// Get total IOC statistics across all sources
    #[instrument(skip(self))]
    pub async fn get_total_stats(&self) -> Result<IocStats, IocRepositoryError> {
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE ioc_type = 'ip') as ip_count,
                COUNT(*) FILTER (WHERE ioc_type = 'domain') as domain_count,
                COUNT(*) FILTER (WHERE ioc_type IN ('md5_hash', 'sha256_hash')) as hash_count,
                COUNT(*) FILTER (WHERE ioc_type = 'url') as url_count,
                COUNT(*) as total
            FROM ioc_enrichments ie
            JOIN enrichment_sources es ON ie.source_id = es.id
            WHERE es.enabled = true AND ie.expires_at > NOW()
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(IocStats {
            ip_count: row.0,
            domain_count: row.1,
            hash_count: row.2,
            url_count: row.3,
            total: row.4,
        })
    }
}
