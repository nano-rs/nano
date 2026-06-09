// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;

impl AppState {
    /// Start the job store cleanup task
    ///
    /// This spawns a background task that periodically cleans up old jobs
    /// from the PostgreSQL melod_jobs table.
    #[cfg(feature = "enterprise")]
    pub fn start_job_store_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let repo = self.melod_job_repo.clone();

        tokio::spawn(async move {
            // Cleanup every 15 minutes
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match repo.cleanup_old_jobs().await {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::debug!("meloD job cleanup removed {} old jobs", removed);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("meloD job cleanup failed: {}", e);
                    }
                }
            }
        })
    }

    /// Start the wizard session cleanup task
    ///
    /// This spawns a background task that periodically cleans up stale wizard
    /// sessions (older than 12 hours) from the PostgreSQL wizard_sessions table.
    #[cfg(feature = "enterprise")]
    pub fn start_wizard_session_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let repo = self.wizard_session_repo.clone();

        tokio::spawn(async move {
            // Cleanup every 15 minutes
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match repo.cleanup_old_sessions().await {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::debug!(
                                "Wizard session cleanup removed {} old sessions",
                                removed
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Wizard session cleanup failed: {}", e);
                    }
                }
            }
        })
    }

    /// Start the meloD session cleanup task
    ///
    /// This spawns a background task that periodically cleans up expired
    /// meloD sessions (based on per-session ttl_days) from the database.
    #[cfg(feature = "enterprise")]
    pub fn start_melod_session_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let repo = self.melod_session_repo.clone();

        tokio::spawn(async move {
            // Cleanup every 15 minutes
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match repo.cleanup_expired().await {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::debug!(
                                "meloD session cleanup removed {} expired sessions",
                                removed
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("meloD session cleanup failed: {}", e);
                    }
                }
            }
        })
    }

    /// Start the agent enrichment cache cleanup task
    ///
    /// This spawns a background task that periodically cleans up expired
    /// enrichment cache entries from the database. Enterprise only after
    /// Phase 3.3 of NAN-744 (agent_enrichment module lifted).
    #[cfg(feature = "enterprise")]
    pub fn start_enrichment_cache_cleanup(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_enterprise::agent_enrichment::AgentEnrichmentRepository;

        let pool = self.pool.clone();

        tokio::spawn(async move {
            // Cleanup every hour
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60 * 60));
            interval.tick().await; // Skip initial tick

            let repo = AgentEnrichmentRepository::new(pool);
            let mut consecutive_errors: u32 = 0;

            loop {
                interval.tick().await;

                match repo.cleanup_expired_cache().await {
                    Ok(deleted) => {
                        consecutive_errors = 0;
                        if deleted > 0 {
                            tracing::info!(
                                "Enrichment cache cleanup: removed {} expired entries",
                                deleted
                            );
                        } else {
                            tracing::debug!("Enrichment cache cleanup: no expired entries");
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_secs = std::cmp::min(
                            (2_u64).saturating_pow(consecutive_errors) * 60,
                            1800, // Max 30 minutes backoff
                        );
                        tracing::warn!(
                            "Enrichment cache cleanup failed (attempt {}, backoff {}s): {}",
                            consecutive_errors,
                            backoff_secs,
                            e
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
                    }
                }
            }
        })
    }

    /// Start the detection finding-emission dedup cleanup task (NAN-1305).
    ///
    /// Live-mode and aggregate rules write a `detection_finding_emissions` row
    /// per entity per execution to dedup findings across overlapping
    /// re-evaluations. Nothing else sweeps that table on a timer, so this purges
    /// rows past the 7-day dedup retention (via `cleanup_old_finding_emissions()`)
    /// every hour to keep it bounded.
    pub fn start_finding_emission_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();

        tokio::spawn(async move {
            // Cleanup every hour
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match sqlx::query_scalar::<_, i64>("SELECT cleanup_old_finding_emissions()")
                    .fetch_one(&pool)
                    .await
                {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::info!(
                                "Finding-emission cleanup removed {} expired dedup rows",
                                removed
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Finding-emission cleanup failed: {}", e);
                    }
                }
            }
        })
    }

    /// Start the rate limit bucket cleanup task
    ///
    /// Removes expired rate limit buckets from PostgreSQL every 15 minutes.
    pub fn start_rate_limit_cleanup(&self) -> tokio::task::JoinHandle<()> {
        use nanosiem_core::db::repository::RateLimitRepository;

        let repo = RateLimitRepository::new(self.pool.clone());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match repo.cleanup_expired().await {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::debug!(
                                "Rate limit cleanup removed {} expired buckets",
                                removed
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Rate limit cleanup failed: {}", e);
                    }
                }
            }
        })
    }

    /// Start the audit log cleanup task
    ///
    /// Deletes audit logs older than the configured retention period (default 90 days).
    /// Runs every hour, deletes in batches to avoid long transactions.
    pub fn start_audit_log_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let audit_repo = (*self.audit_repo).clone();

        tokio::spawn(async move {
            let retention_days: i64 = std::env::var("AUDIT_LOG_RETENTION_DAYS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(90);

            // Cleanup every hour
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match audit_repo.delete_old_logs(retention_days).await {
                    Ok(removed) => {
                        if removed > 0 {
                            tracing::info!(
                                "Audit log cleanup removed {} old logs (retention: {} days)",
                                removed,
                                retention_days
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Audit log cleanup failed: {}", e);
                    }
                }
            }
        })
    }

    /// Start the query tracker stale entry cleanup task
    ///
    /// Removes QueryTracker entries older than 1 hour (queries that failed to unregister).
    /// Runs every 15 minutes.
    pub fn start_query_tracker_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let search_service = self.search_service.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                let removed = search_service
                    .query_tracker()
                    .cleanup_stale(std::time::Duration::from_secs(3600));
                if removed > 0 {
                    tracing::info!("Query tracker cleanup removed {} stale entries", removed);
                }
            }
        })
    }

    /// Start the in-memory search job store cleanup task
    ///
    /// Removes expired search jobs every 5 minutes. Only relevant for InMemoryJobStore;
    /// RedisJobStore uses native TTL.
    pub fn start_search_job_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let search_service = self.search_service.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;
                search_service.job_store().cleanup().await;
            }
        })
    }
}
