// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment repository for database operations

use sqlx::PgPool;
use thiserror::Error;
use tracing::instrument;

use super::types::*;

#[derive(Error, Debug)]
pub enum EnrichmentRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Source not found: {0}")]
    SourceNotFound(String),
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    #[error("IOC repository error: {0}")]
    IocError(String),
}

impl From<super::ioc::IocRepositoryError> for EnrichmentRepositoryError {
    fn from(e: super::ioc::IocRepositoryError) -> Self {
        EnrichmentRepositoryError::IocError(e.to_string())
    }
}

/// Repository for enrichment data operations
#[derive(Clone)]
pub struct EnrichmentRepository {
    pool: PgPool,
}

impl EnrichmentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the underlying database pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // ========================================================================
    // Enrichment Source Operations
    // ========================================================================

    /// List all enrichment sources
    #[instrument(skip(self))]
    pub async fn list_sources(&self) -> Result<Vec<EnrichmentSource>, EnrichmentRepositoryError> {
        let sources =
            sqlx::query_as::<_, EnrichmentSource>("SELECT * FROM enrichment_sources ORDER BY name")
                .fetch_all(&self.pool)
                .await?;

        Ok(sources)
    }

    /// Get an enrichment source by ID
    #[instrument(skip(self))]
    pub async fn get_source(
        &self,
        id: &str,
    ) -> Result<EnrichmentSource, EnrichmentRepositoryError> {
        sqlx::query_as::<_, EnrichmentSource>("SELECT * FROM enrichment_sources WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| EnrichmentRepositoryError::SourceNotFound(id.to_string()))
    }

    /// Create or update an enrichment source
    #[instrument(skip(self))]
    pub async fn upsert_source(
        &self,
        config: &EnrichmentSourceConfig,
    ) -> Result<EnrichmentSource, EnrichmentRepositoryError> {
        let source = sqlx::query_as::<_, EnrichmentSource>(
            r#"
            INSERT INTO enrichment_sources (id, name, source_type, description, download_url, config, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                source_type = EXCLUDED.source_type,
                description = EXCLUDED.description,
                download_url = EXCLUDED.download_url,
                config = EXCLUDED.config,
                enabled = EXCLUDED.enabled,
                updated_at = NOW()
            RETURNING *
            "#
        )
        .bind(&config.id)
        .bind(&config.name)
        .bind(&config.source_type)
        .bind(&config.description)
        .bind(&config.download_url)
        .bind(&config.config)
        .bind(config.enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(source)
    }

    /// Update sync status for a source
    #[instrument(skip(self))]
    pub async fn update_sync_status(
        &self,
        source_id: &str,
        status: SyncStatus,
        error: Option<&str>,
        record_count: Option<i64>,
        file_hash: Option<&str>,
    ) -> Result<(), EnrichmentRepositoryError> {
        sqlx::query(
            r#"
            UPDATE enrichment_sources SET
                last_sync_at = CASE WHEN $2 = 'success' THEN NOW() ELSE last_sync_at END,
                last_sync_status = $2,
                last_sync_error = $3,
                record_count = COALESCE($4, record_count),
                file_hash = COALESCE($5, file_hash),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(source_id)
        .bind(status.to_string())
        .bind(error)
        .bind(record_count)
        .bind(file_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Enable or disable an enrichment source
    #[instrument(skip(self))]
    pub async fn set_source_enabled(
        &self,
        source_id: &str,
        enabled: bool,
    ) -> Result<(), EnrichmentRepositoryError> {
        let result = sqlx::query(
            "UPDATE enrichment_sources SET enabled = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(source_id)
        .bind(enabled)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(EnrichmentRepositoryError::SourceNotFound(
                source_id.to_string(),
            ));
        }

        Ok(())
    }

    /// Update source configuration (for auto-sync settings, etc.)
    #[instrument(skip(self, config))]
    pub async fn update_source_config(
        &self,
        source_id: &str,
        config: serde_json::Value,
    ) -> Result<(), EnrichmentRepositoryError> {
        let result = sqlx::query(
            "UPDATE enrichment_sources SET config = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(source_id)
        .bind(config)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(EnrichmentRepositoryError::SourceNotFound(
                source_id.to_string(),
            ));
        }

        Ok(())
    }

    /// Update source download URL
    #[instrument(skip(self))]
    pub async fn update_source_url(
        &self,
        source_id: &str,
        url: &str,
    ) -> Result<(), EnrichmentRepositoryError> {
        let result = sqlx::query(
            "UPDATE enrichment_sources SET download_url = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(source_id)
        .bind(url)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(EnrichmentRepositoryError::SourceNotFound(
                source_id.to_string(),
            ));
        }

        Ok(())
    }

    // ========================================================================
    // IP Enrichment Operations
    // ========================================================================

    /// Lookup IP enrichment for a single IP address
    #[instrument(skip(self))]
    pub async fn lookup_ip(
        &self,
        ip: &str,
    ) -> Result<Option<IpEnrichmentResult>, EnrichmentRepositoryError> {
        // Validate IP format first
        if ip.is_empty() {
            return Ok(None);
        }

        let result = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            ),
        >("SELECT * FROM lookup_ip_enrichment($1)")
        .bind(ip)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(
            |(country, country_code, continent, continent_code, asn, as_name, as_domain)| {
                IpEnrichmentResult {
                    source_id: Some("ipinfo_lite".to_string()),
                    network: None,
                    country,
                    country_code,
                    continent,
                    continent_code,
                    asn,
                    as_name,
                    as_domain,
                }
            },
        ))
    }

    /// Bulk lookup IP enrichments (for batch ingestion)
    /// Returns a map of IP -> enrichment result
    #[instrument(skip(self, ips))]
    pub async fn lookup_ips_bulk(
        &self,
        ips: &[&str],
    ) -> Result<std::collections::HashMap<String, IpEnrichmentResult>, EnrichmentRepositoryError>
    {
        use std::collections::HashMap;

        let mut results = HashMap::new();

        // Filter out empty IPs and deduplicate
        let unique_ips: Vec<&str> = ips
            .iter()
            .filter(|ip| !ip.is_empty())
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if unique_ips.is_empty() {
            return Ok(results);
        }

        // Batch query - lookup all IPs at once using LATERAL join
        let rows = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>(
            r#"
            SELECT 
                ip_addr,
                e.country,
                e.country_code,
                e.continent,
                e.continent_code,
                e.asn,
                e.as_name,
                e.as_domain
            FROM UNNEST($1::text[]) AS ip_addr
            LEFT JOIN LATERAL (
                SELECT ie.country, ie.country_code, ie.continent, ie.continent_code, ie.asn, ie.as_name, ie.as_domain
                FROM ip_enrichments ie
                JOIN enrichment_sources es ON ie.source_id = es.id
                WHERE ip_addr::inet <<= ie.network AND es.enabled = true
                ORDER BY masklen(ie.network) DESC
                LIMIT 1
            ) e ON true
            "#
        )
        .bind(&unique_ips)
        .fetch_all(&self.pool)
        .await?;

        for (ip, country, country_code, continent, continent_code, asn, as_name, as_domain) in rows
        {
            if country.is_some() || asn.is_some() {
                results.insert(
                    ip,
                    IpEnrichmentResult {
                        source_id: Some("ipinfo_lite".to_string()),
                        network: None,
                        country,
                        country_code,
                        continent,
                        continent_code,
                        asn,
                        as_name,
                        as_domain,
                    },
                );
            }
        }

        Ok(results)
    }

    /// Clear all IP enrichments for a source (before re-sync)
    /// DEPRECATED: Use insert_ip_enrichments_staged for zero-downtime updates
    #[instrument(skip(self))]
    pub async fn clear_ip_enrichments(
        &self,
        source_id: &str,
    ) -> Result<u64, EnrichmentRepositoryError> {
        let result = sqlx::query("DELETE FROM ip_enrichments WHERE source_id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Bulk insert IP enrichments using staging table + COPY for zero-downtime updates
    ///
    /// This method:
    /// 1. Clears the staging table for this source
    /// 2. Uses COPY to bulk load data into staging (much faster than INSERT)
    /// 3. Atomically swaps staging data into production
    ///
    /// Lookups continue to work against production during the entire process.
    #[instrument(skip(self, records))]
    pub async fn insert_ip_enrichments_staged(
        &self,
        source_id: &str,
        records: &[IpInfoLiteRecord],
    ) -> Result<u64, EnrichmentRepositoryError> {
        use std::io::Write;

        if records.is_empty() {
            return Ok(0);
        }

        tracing::info!(
            record_count = records.len(),
            "Starting staged enrichment load"
        );

        // Step 1: Clear staging table for this source
        sqlx::query("DELETE FROM ip_enrichments_staging WHERE source_id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await?;

        // Step 2: Build CSV data for COPY
        let mut csv_data = Vec::new();
        for record in records {
            // Format: source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain
            writeln!(
                csv_data,
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                source_id,
                record.network,
                record.country,
                record.country_code,
                record.continent,
                record.continent_code,
                record.asn,
                record.as_name,
                record.as_domain,
            )
            .map_err(|e| EnrichmentRepositoryError::DatabaseError(sqlx::Error::Io(e)))?;
        }

        tracing::info!(
            csv_bytes = csv_data.len(),
            "CSV data prepared, starting COPY"
        );

        // Step 3: Use COPY to bulk load into staging
        // Note: sqlx doesn't support COPY directly, so we use raw SQL with chunked inserts
        // For true COPY performance, we'd need tokio-postgres directly
        // For now, use larger batch sizes with the staging table
        let mut inserted = 0u64;

        for chunk in records.chunks(5000) {
            let mut query = String::from(
                "INSERT INTO ip_enrichments_staging (source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain) VALUES "
            );

            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                let base = i * 9;
                query.push_str(&format!(
                    "(${}, ${}::cidr, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4,
                    base + 5,
                    base + 6,
                    base + 7,
                    base + 8,
                    base + 9
                ));
            }

            let mut q = sqlx::query(&query);
            for record in chunk {
                q = q
                    .bind(source_id)
                    .bind(&record.network)
                    .bind(&record.country)
                    .bind(&record.country_code)
                    .bind(&record.continent)
                    .bind(&record.continent_code)
                    .bind(&record.asn)
                    .bind(&record.as_name)
                    .bind(&record.as_domain);
            }

            let result = q.execute(&self.pool).await?;
            inserted += result.rows_affected();

            if inserted % 100000 == 0 {
                tracing::info!(inserted, "Staging progress...");
            }
        }

        tracing::info!(inserted, "Staging complete, swapping to production");

        // Step 4: Atomic swap from staging to production
        let swapped: (i64,) = sqlx::query_as("SELECT swap_enrichment_staging($1)")
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;

        tracing::info!(swapped = swapped.0, "Swap complete");

        Ok(swapped.0 as u64)
    }

    // ========================================================================
    // Streaming Staged Insert (bounded memory)
    // ========================================================================

    /// Clear the staging table for a source — call once before streaming batches
    #[instrument(skip(self))]
    pub async fn clear_staging(&self, source_id: &str) -> Result<(), EnrichmentRepositoryError> {
        sqlx::query("DELETE FROM ip_enrichments_staging WHERE source_id = $1")
            .bind(source_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Insert a batch of records into the staging table
    #[instrument(skip(self, records))]
    pub async fn insert_staging_batch(
        &self,
        source_id: &str,
        records: &[IpInfoLiteRecord],
    ) -> Result<u64, EnrichmentRepositoryError> {
        if records.is_empty() {
            return Ok(0);
        }

        let mut inserted = 0u64;

        for chunk in records.chunks(5000) {
            let mut query = String::from(
                "INSERT INTO ip_enrichments_staging (source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain) VALUES "
            );

            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                let base = i * 9;
                query.push_str(&format!(
                    "(${}, ${}::cidr, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4,
                    base + 5,
                    base + 6,
                    base + 7,
                    base + 8,
                    base + 9
                ));
            }

            let mut q = sqlx::query(&query);
            for record in chunk {
                q = q
                    .bind(source_id)
                    .bind(&record.network)
                    .bind(&record.country)
                    .bind(&record.country_code)
                    .bind(&record.continent)
                    .bind(&record.continent_code)
                    .bind(&record.asn)
                    .bind(&record.as_name)
                    .bind(&record.as_domain);
            }

            let result = q.execute(&self.pool).await?;
            inserted += result.rows_affected();
        }

        Ok(inserted)
    }

    /// Swap staging data into production — call once after all batches inserted
    #[instrument(skip(self))]
    pub async fn swap_staging(&self, source_id: &str) -> Result<u64, EnrichmentRepositoryError> {
        let swapped: (i64,) = sqlx::query_as("SELECT swap_enrichment_staging($1)")
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;

        tracing::info!(swapped = swapped.0, "Staging swap complete");
        Ok(swapped.0 as u64)
    }

    /// Bulk insert IP enrichments (for sync) - legacy method
    /// DEPRECATED: Use insert_ip_enrichments_staged for zero-downtime updates
    #[instrument(skip(self, records))]
    pub async fn insert_ip_enrichments_bulk(
        &self,
        source_id: &str,
        records: &[IpInfoLiteRecord],
    ) -> Result<u64, EnrichmentRepositoryError> {
        if records.is_empty() {
            return Ok(0);
        }

        let mut inserted = 0u64;

        // Insert in batches of 1000
        for chunk in records.chunks(1000) {
            let mut query = String::from(
                "INSERT INTO ip_enrichments (source_id, network, country, country_code, continent, continent_code, asn, as_name, as_domain) VALUES "
            );

            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                let base = i * 9;
                query.push_str(&format!(
                    "(${}, ${}::cidr, ${}, ${}, ${}, ${}, ${}, ${}, ${})",
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4,
                    base + 5,
                    base + 6,
                    base + 7,
                    base + 8,
                    base + 9
                ));
            }

            query.push_str(" ON CONFLICT (source_id, network) DO UPDATE SET country = EXCLUDED.country, country_code = EXCLUDED.country_code, continent = EXCLUDED.continent, continent_code = EXCLUDED.continent_code, asn = EXCLUDED.asn, as_name = EXCLUDED.as_name, as_domain = EXCLUDED.as_domain");

            let mut q = sqlx::query(&query);
            for record in chunk {
                q = q
                    .bind(source_id)
                    .bind(&record.network)
                    .bind(&record.country)
                    .bind(&record.country_code)
                    .bind(&record.continent)
                    .bind(&record.continent_code)
                    .bind(&record.asn)
                    .bind(&record.as_name)
                    .bind(&record.as_domain);
            }

            let result = q.execute(&self.pool).await?;
            inserted += result.rows_affected();
        }

        Ok(inserted)
    }

    /// Get enrichment statistics
    #[instrument(skip(self))]
    pub async fn get_stats(&self) -> Result<EnrichmentStats, EnrichmentRepositoryError> {
        let row = sqlx::query_as::<_, (i64, i64)>(
            r#"
            SELECT 
                (SELECT COUNT(*) FROM enrichment_sources WHERE enabled = true) as enabled_sources,
                (SELECT COUNT(*) FROM ip_enrichments) as total_ip_records
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(EnrichmentStats {
            enabled_sources: row.0,
            total_ip_records: row.1,
        })
    }
}

/// Enrichment statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct EnrichmentStats {
    pub enabled_sources: i64,
    pub total_ip_records: i64,
}
