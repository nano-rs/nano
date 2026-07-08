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

    /// Start the detection dedup/hygiene cleanup task (NAN-1305, audit D18).
    ///
    /// Sweeps the three unbounded-by-default detection PG tables every hour so
    /// they can't grow without limit on the hot metadata DB, independent of
    /// whether data retention is enabled (the manual retention endpoint is
    /// retention-gated):
    /// - `detection_finding_emissions` — per-entity/execution finding dedup
    ///   (7-day retention via `cleanup_old_finding_emissions()`).
    /// - `detection_matched_events` — per-event lookback dedup (7-day, via
    ///   `cleanup_old_matched_events()`, which previously had NO caller — D18).
    /// - `detection_matches` — full matched-events JSONB per firing (30-day, via
    ///   `cleanup_old_detection_matches()`; it had no cleanup at all — D18).
    pub fn start_detection_dedup_cleanup(&self) -> tokio::task::JoinHandle<()> {
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
                    Ok(removed) if removed > 0 => tracing::info!(
                        "Finding-emission cleanup removed {} expired dedup rows",
                        removed
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("Finding-emission cleanup failed: {}", e),
                }

                // Audit D18: `cleanup_old_matched_events()` (7-day) previously had
                // no caller — wire it here so lookback dedup is bounded without
                // requiring the retention policy to be enabled. Returns void.
                if let Err(e) = sqlx::query("SELECT cleanup_old_matched_events()")
                    .execute(&pool)
                    .await
                {
                    tracing::warn!("Matched-events cleanup failed: {}", e);
                }

                // Audit D18: `detection_matches` had no cleanup anywhere.
                match sqlx::query_scalar::<_, i64>("SELECT cleanup_old_detection_matches()")
                    .fetch_one(&pool)
                    .await
                {
                    Ok(removed) if removed > 0 => tracing::info!(
                        "Detection-matches cleanup removed {} old matches",
                        removed
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::warn!("Detection-matches cleanup failed: {}", e),
                }
            }
        })
    }

    /// Start the prevalence-dictionary health monitor (audit D4, fail-loud).
    ///
    /// Prevalence-filtered detection rules ride the dict pushdown, which returns
    /// the `9999` sentinel — i.e. "match nothing" for every row — when the
    /// prevalence dicts are cold/degraded/FAILED. That is silent: the rule just
    /// stops alerting, with no error. This surfaces it: every 5 minutes, if any
    /// prevalence dictionary is FAILED or throwing, log a prominent WARN so a
    /// silent zero-match run has a visible cause. Keyed on FAILED status /
    /// exception only (matching `siem_health::dict_is_unhealthy`) — a healthy
    /// CACHE dict reporting LOADED with `element_count 0` is normal (lazy).
    pub fn start_prevalence_dict_health_monitor(&self) -> tokio::task::JoinHandle<()> {
        let dual_pool = self.dual_pool.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                // NAN-1728 (M-4): on a cluster, `system.dictionaries` on the
                // LB-connected node only sees that node's dicts — a FAILED
                // prevalence dict on another shard (the exact fail-closed D4
                // hazard) would report healthy. Read across all replicas via
                // `clusterAllReplicas` and prefix each row with `hostName()` so
                // the WARN names the affected shard. `CLICKHOUSE_CLUSTER` is set
                // only on clustered ClickHouse; unset → the bare `system.
                // dictionaries` probe, byte-identical on single-node.
                let cluster = if dual_pool.is_clustered() {
                    std::env::var("CLICKHOUSE_CLUSTER")
                        .ok()
                        .filter(|c| !c.trim().is_empty())
                } else {
                    None
                };
                let sql = match &cluster {
                    Some(cl) => format!(
                        "SELECT concat(hostName(), ' ', database, '.', name), toString(status), \
                         substring(last_exception, 1, 200) \
                         FROM clusterAllReplicas('{cl}', system.dictionaries) \
                         WHERE name LIKE '%prevalence%'"
                    ),
                    None => "SELECT concat(database, '.', name), toString(status), \
                             substring(last_exception, 1, 200) \
                             FROM system.dictionaries WHERE name LIKE '%prevalence%'"
                        .to_string(),
                };

                match dual_pool
                    .clickhouse()
                    .query(&sql)
                    .fetch_all::<(String, String, String)>()
                    .await
                {
                    Ok(rows) => {
                        let degraded: Vec<String> = rows
                            .into_iter()
                            .filter(|(_, status, exc)| {
                                status.starts_with("FAILED") || !exc.is_empty()
                            })
                            .map(|(name, status, exc)| {
                                if exc.is_empty() {
                                    format!("{name} (status={status})")
                                } else {
                                    format!("{name} (status={status}, exception={exc})")
                                }
                            })
                            .collect();

                        if !degraded.is_empty() {
                            tracing::warn!(
                                "Prevalence dictionaries DEGRADED — prevalence-filtered detection rules are silently matching NOTHING (fail-closed, audit D4). Affected: {}",
                                degraded.join("; ")
                            );
                        }
                    }
                    Err(e) => {
                        // Grant missing / probe unavailable — don't spam at warn.
                        tracing::debug!("Prevalence-dict health probe unavailable: {}", e);
                    }
                }
            }
        })
    }

    /// Start the ungrouped-alert reconciliation sweep (G2, NAN-1749).
    ///
    /// Grouping is fire-once: a transient PG error during
    /// `process_alert_for_grouping`, or the rule-execution `tokio::time::timeout`
    /// cancelling `process_alert_post_create` mid-flight, permanently orphans the
    /// alert (`case_id IS NULL`) with no case, no queue, and no retry. This sweep
    /// re-runs grouping for those alerting-mode orphans every 5 minutes.
    ///
    /// Bounded + idempotent (see `DetectionService::reconcile_ungrouped_alerts`):
    /// only detection alerts from still-`alerting` rules, older than 10 min (so
    /// it never races the inline grouping that runs right after alert creation),
    /// within a 7-day lookback, capped at 200 per pass. A successful re-group
    /// stamps `alerts.case_id`, so the alert drops out of the next pass. In
    /// open-core (no-op grouping hook) this is a harmless no-op.
    pub fn start_ungrouped_alert_reconciliation(&self) -> tokio::task::JoinHandle<()> {
        let detection_service = self.detection_service.clone();

        tokio::spawn(async move {
            // 5-minute cadence — well clear of the 10-minute min-age so a swept
            // alert has had ample time for its inline grouping to have landed.
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5 * 60));
            interval.tick().await; // Skip initial tick

            loop {
                interval.tick().await;

                match detection_service
                    .reconcile_ungrouped_alerts(10, 7 * 24, 200)
                    .await
                {
                    Ok(reconciled) if reconciled > 0 => tracing::info!(
                        "Ungrouped-alert reconciliation grouped {} previously-orphaned alert(s) into cases",
                        reconciled
                    ),
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("Ungrouped-alert reconciliation sweep failed: {}", e)
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
