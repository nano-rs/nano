// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Cancel a running query by its request ID
    ///
    /// Stateless cancellation: the frontend request_id IS used as the ClickHouse
    /// query_id (see search() below), so we can issue KILL QUERY directly without
    /// needing to look up the mapping on the correct instance. This works in
    /// active/active deployments because KILL QUERY is global to the ClickHouse cluster.
    ///
    /// The local QueryTracker is still maintained for metrics/debugging but is not
    /// required for correctness.
    pub async fn cancel_query(&self, request_id: &str) -> Result<bool, SearchError> {
        // Only ClickHouse supports query cancellation
        let ch_executor = match &self.ch_executor {
            Some(executor) => executor,
            None => {
                tracing::warn!("Query cancellation not supported for PostgreSQL backend");
                return Ok(false);
            }
        };

        // Issue KILL QUERY directly using the request_id as query_id.
        // This works regardless of which instance started the query.
        let cancelled = ch_executor.cancel_query(request_id).await?;

        // Clean up local tracker if this instance happened to be tracking it
        self.query_tracker.unregister(request_id);

        if cancelled {
            tracing::info!("Cancelled query via KILL QUERY: request_id={}", request_id);
        } else {
            tracing::debug!(
                "No running query found for request_id: {} (may have already completed)",
                request_id
            );
        }

        Ok(cancelled)
    }

    // =========================================================================
    // Async Search Job Methods
    // =========================================================================

    /// Execute a search asynchronously, returning a job ID immediately
    ///
    /// The search runs in the background. Use get_job_status() to poll for
    /// completion and retrieve results.
    pub async fn search_async(&self, request: SearchRequest) -> Result<String, SearchError> {
        // Create job in store
        let job_id = self
            .job_store
            .create(request.clone())
            .await
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "Maximum concurrent async jobs limit reached. Try again later.".to_string(),
                )
            })?;

        // Generate ClickHouse query_id for this job
        let query_id = uuid::Uuid::now_v7().to_string();
        self.job_store.set_query_id(&job_id, query_id.clone()).await;

        // Clone what we need for the spawned task
        let service = self.clone();
        let job_id_clone = job_id.clone();

        // Modify request to use our query_id for progress tracking
        let mut request_with_id = request;
        request_with_id.request_id = Some(query_id);

        // Spawn background task to execute the search
        tokio::spawn(async move {
            tracing::info!("Async job {} starting search execution", job_id_clone);

            // Execute the search (reuse existing search logic)
            let result = service.search(request_with_id).await;

            // Update job with result
            match result {
                Ok(response) => {
                    tracing::info!(
                        "Async job {} completed: {} results, {} histogram buckets",
                        job_id_clone,
                        response.results.len(),
                        response.histogram.as_ref().map(|h| h.len()).unwrap_or(0)
                    );
                    service.job_store.complete(&job_id_clone, response).await;
                }
                Err(e) => {
                    tracing::error!("Async job {} failed: {}", job_id_clone, e);
                    service.job_store.fail(&job_id_clone, e.to_string()).await;
                }
            }
        });

        tracing::info!("Started async search job: {}", job_id);
        Ok(job_id)
    }

    /// Execute a search asynchronously with admission control.
    ///
    /// Creates a job in Queued state, then spawns a background task that:
    /// 1. Acquires an admission permit (may wait in queue)
    /// 2. Transitions job to Running
    /// 3. Executes the search with per-priority CH settings
    /// 4. Completes or fails the job
    /// 5. Drops the permit (freeing the slot for the next queued search)
    pub async fn search_async_with_admission(
        &self,
        request: SearchRequest,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
    ) -> Result<String, SearchError> {
        // Create job in Queued state
        let job_id = self
            .job_store
            .create_queued(request.clone(), user_id, priority)
            .await
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "Maximum concurrent async jobs limit reached. Try again later.".to_string(),
                )
            })?;

        // Generate ClickHouse query_id for this job
        let query_id = uuid::Uuid::now_v7().to_string();
        self.job_store.set_query_id(&job_id, query_id.clone()).await;

        let mut service = self.clone();
        // Set per-query ClickHouse settings based on priority
        service.active_ch_settings = Some(priority.to_ch_settings());
        let job_id_clone = job_id.clone();

        let mut request_with_id = request;
        request_with_id.request_id = Some(query_id);

        tokio::spawn(async move {
            // Step 1: Acquire admission permit
            let _permit = if let Some(ref controller) = service.admission_controller {
                match controller.acquire(&job_id_clone, user_id, priority).await {
                    Ok(permit) => Some(permit),
                    Err(e) => {
                        tracing::warn!("Job {} admission denied: {}", job_id_clone, e);
                        service.job_store.fail(&job_id_clone, e.to_string()).await;
                        return;
                    }
                }
            } else {
                None
            };

            // Step 2: Transition to Running
            service.job_store.start(&job_id_clone).await;
            tracing::info!(
                "Async job {} starting search execution (priority={})",
                job_id_clone,
                priority
            );

            // Step 3: Execute search
            let result = service.search(request_with_id).await;

            // Step 4: Complete or fail
            match result {
                Ok(response) => {
                    let result_count = response.results.len();
                    tracing::info!(
                        "Async job {} completed: {} results",
                        job_id_clone,
                        result_count,
                    );
                    service.job_store.complete(&job_id_clone, response).await;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    tracing::error!("Async job {} failed: {}", job_id_clone, error_msg);
                    service.job_store.fail(&job_id_clone, error_msg).await;
                }
            }
            // Step 5: _permit drops here, freeing the admission slot
        });

        tracing::info!(
            "Created admission-controlled async search job: {} (user={}, priority={})",
            job_id,
            user_id,
            priority
        );
        Ok(job_id)
    }

    /// Execute a search synchronously, gated by the admission controller.
    ///
    /// NAN-701: Sibling of `search_async_with_admission` for callers that
    /// need the response inline (search handler sync path, dashboard panel
    /// queries) instead of a job_id to poll. Acquires an admission permit
    /// (waiting in queue if needed), runs `search`, and releases the permit
    /// on return via RAII drop.
    ///
    /// When `admission_controller` is `None` (e.g. tests, single-tenant
    /// deployments), behaves identically to `search`.
    pub async fn search_with_admission(
        &self,
        request: SearchRequest,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
    ) -> Result<SearchResponse, SearchError> {
        // NAN-709: lower-priority requests yield briefly before claiming a
        // slot. Without this, the initial admit burst when a dashboard fires
        // all panels simultaneously is a network-timing race — 1-2 Analytics
        // panels can sneak into the per-user cap alongside Interactive ones.
        // The delay (a few hundred ms, see `admit_delay`) gives Interactive
        // requests a deterministic head start so cheap panels render first.
        // Detection/NRT priorities bypass admission entirely and never reach
        // here.
        if let Some(delay) = priority.admit_delay() {
            tokio::time::sleep(delay).await;
        }

        // No controller wired up → no gating, run directly. Preserves the
        // pre-NAN-701 behavior for code paths that haven't been migrated.
        let Some(controller) = self.admission_controller.clone() else {
            return self.search(request).await;
        };

        let job_id = uuid::Uuid::now_v7().to_string();
        let _permit = controller
            .acquire(&job_id, user_id, priority)
            .await
            .map_err(|e| SearchError::AdmissionDenied(e.to_string()))?;

        let mut service = self.clone();
        service.active_ch_settings = Some(priority.to_ch_settings());
        // _permit drops at end of scope, freeing the slot.
        service.search(request).await
    }

    /// Get the status of an async search job
    ///
    /// Returns job status, progress (if running), results (if completed),
    /// or error (if failed). When queued, includes queue position and estimated wait.
    pub async fn get_job_status(
        &self,
        job_id: &str,
    ) -> Option<super::jobs::SearchJobStatusResponse> {
        // Get basic status from store
        let mut status = self.job_store.get_status(job_id).await?;

        tracing::debug!("Job {} status: {:?}", job_id, status.status);

        // If job is queued, populate queue position and estimated wait
        if status.status == super::jobs::SearchJobStatus::Queued {
            if let Some(ref controller) = self.admission_controller {
                if let Some(position) = controller.queue_position(job_id).await {
                    status.queue_position = Some(position);
                    // Estimate wait: ~5 seconds per position (rough heuristic)
                    status.estimated_wait_seconds = Some(position * 5);
                    self.job_store.set_queue_position(job_id, position).await;
                }
            }
        }

        // If job is running, fetch progress from ClickHouse
        if status.status == super::jobs::SearchJobStatus::Running {
            if let Some(query_id) = self.job_store.get_query_id(job_id).await {
                tracing::debug!("Fetching progress for query_id: {}", query_id);
                if let Some(progress) = self.get_query_progress(&query_id).await {
                    tracing::debug!(
                        "Got progress: {}% ({} of {} rows)",
                        progress.percent,
                        progress.rows_scanned,
                        progress.rows_total
                    );
                    status.progress = Some(progress);
                } else {
                    tracing::debug!("No progress found for query_id: {}", query_id);
                }
            } else {
                tracing::debug!("No query_id found for job: {}", job_id);
            }
        }

        Some(status)
    }

    /// Cancel an async search job
    ///
    /// Returns Ok(true) if the job was found and cancelled.
    /// Works for both queued and running jobs.
    /// Stateless: issues KILL QUERY directly using the job's query_id,
    /// so it works from any instance in an active/active deployment.
    pub async fn cancel_job(&self, job_id: &str) -> Result<bool, SearchError> {
        // Get the job to check status and get query_id
        let job = match self.job_store.get(job_id).await {
            Some(j) => j,
            None => return Ok(false),
        };

        // Cancel queued jobs by removing from admission queue
        if job.status == super::jobs::SearchJobStatus::Queued {
            if let Some(ref controller) = self.admission_controller {
                controller.cancel_queued(job_id).await;
            }
            self.job_store.cancel(job_id).await;
            tracing::info!("Cancelled queued search job: {}", job_id);
            return Ok(true);
        }

        // Only cancel if still running
        if job.status != super::jobs::SearchJobStatus::Running {
            return Ok(false);
        }

        // Kill the ClickHouse query — works from any instance
        if let Some(ref executor) = self.ch_executor {
            let _ = executor.cancel_query(&job.query_id).await;
        }

        // Mark as cancelled in the (potentially Redis-backed) store
        self.job_store.cancel(job_id).await;

        tracing::info!("Cancelled async search job: {}", job_id);
        Ok(true)
    }

    /// Get query progress from ClickHouse system.processes
    async fn get_query_progress(&self, query_id: &str) -> Option<super::jobs::SearchJobProgress> {
        let ch_executor = self.ch_executor.as_ref()?;

        match ch_executor.get_query_progress(query_id).await {
            Ok(progress) => progress,
            Err(e) => {
                tracing::debug!("Failed to get query progress: {}", e);
                None
            }
        }
    }

    /// Execute a piped query and return structured results
    #[instrument(skip(self), fields(query = %request.query))]
    pub async fn search(&self, request: SearchRequest) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        // Read query safety limits (hot-reloadable from DB settings)
        let query_limits = self.query_limits.read().await.clone();

        // Generate query_id for cancellation support
        // Use request_id if provided (from frontend), otherwise generate a new UUID
        let query_id = request
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());

        // Register with tracker for cancellation support (if request_id was provided)
        // Note: We don't unregister on error - stale entries are harmless since cancel_query
        // checks ClickHouse directly if the query is still running
        if request.request_id.is_some() {
            self.query_tracker
                .register(request.request_id.clone().unwrap(), query_id.clone());
        }

        // Validate time range
        request.time_range.validate()?;

        // Extract time modifiers (earliest=-24h, latest=now, etc.) and clean the query
        let (cleaned_query, earliest_offset, latest_offset) =
            extract_time_modifiers(&request.query);

        // Adjust time range based on modifiers
        let mut adjusted_time_range = request.time_range.clone();
        if let Some(offset_secs) = earliest_offset {
            // earliest=-24h means start = now + offset (offset is negative)
            adjusted_time_range.start = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        }
        if let Some(offset_secs) = latest_offset {
            // latest=now means end = now + offset (offset is 0 for now)
            adjusted_time_range.end = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        }

        // Parse the cleaned query
        let query = match parse_query(&cleaned_query) {
            Ok(q) => q,
            Err(e) => return Err(convert_parse_error(e)),
        };

        // Pre-execution guardrail: reject queries that would cause unbounded memory usage (OOM)
        // Covers: eventstats/streamstats, dedup, reverse, transaction, values()/list(), high-cardinality GROUP BY
        if let Some(risk) = detect_oom_risk(&query) {
            return Err(SearchError::SqlValidationError(risk.message()));
        }

        // Extract lookup commands for post-processing
        let lookup_commands = extract_lookup_commands(&query);

        // Extract inputlookup commands for URL-based enrichment
        let inputlookup_commands = extract_inputlookup_commands(&query);

        // Extract commands that come after inputlookup (need post-processing)
        let post_inputlookup_commands = extract_post_inputlookup_commands(&query);
        let has_inputlookup = !inputlookup_commands.is_empty();

        // Extract prevalence commands for post-processing
        let prevalence_commands = extract_prevalence_commands(&query);

        // Extract commands that come after prevalence enrichment
        let post_prevalence = extract_post_prevalence_commands(&query);

        // Check if we can use JOIN-based prevalence filtering (ClickHouse only)
        // This is more efficient than post-processing for large datasets.
        //
        // NAN-701: Previously also required `has_prevalence_field_filter` —
        // i.e. the JOIN path only engaged when the user had a `WHERE` on a
        // prevalence field like `host_count`. Pure-enrich queries (sort by
        // host_count + head, no WHERE) silently fell through to the slow
        // post-processing path. With dict-based enrichment now handling both
        // paths, JOIN is strictly cheaper for any `enrich=true` query, so the
        // field-filter gate is dropped.
        let is_clickhouse = self.backend == SearchBackend::ClickHouse;
        let has_prevalence_svc = self.prevalence_service.is_some();
        let has_prevalence_cmds = !prevalence_commands.is_empty();
        let has_enrich = prevalence_commands.iter().any(|cmd| cmd.enrich);

        // Check if there's aggregation (stats, timechart, etc.) before prevalence
        // If so, we can't use JOIN-based prevalence because the result structure is different
        let has_aggregation_before = has_aggregation_before_prevalence(&query);

        // Check if post-prevalence commands are safe for JOIN optimization.
        // Only simple commands (where, sort, head, tail, table, fields, dedup, rename) are safe.
        // Complex commands (stats, eval, rex, lookup, etc.) create new fields that won't exist
        // in the JOIN query, causing "identifier cannot be resolved" errors.
        let safe_post_commands =
            has_only_simple_post_prevalence_commands(&post_prevalence.commands);

        tracing::debug!(
            "Prevalence JOIN check: clickhouse={}, prevalence_svc={}, prevalence_cmds={}, enrich={}, has_aggregation_before={}, safe_post_commands={}",
            is_clickhouse, has_prevalence_svc, has_prevalence_cmds, has_enrich, has_aggregation_before, safe_post_commands
        );
        tracing::debug!(
            "Post-prevalence commands count: {}",
            post_prevalence.commands.len()
        );
        tracing::debug!("Post-prevalence commands: {:?}", post_prevalence.commands);
        tracing::debug!("Prevalence commands: {:?}", prevalence_commands);

        let use_prevalence_join = is_clickhouse
            && has_prevalence_svc
            && has_prevalence_cmds
            && has_enrich
            && !has_aggregation_before   // Can't use JOIN approach with aggregation before prevalence
            && safe_post_commands; // Only use JOIN if post-prevalence commands are simple filters/sorts

        // Check if this is a tree visualization query BEFORE setting limit
        // Tree queries need ALL events to properly build parent-child relationships
        let tree_command = extract_tree_command(&query);
        let is_tree_query = tree_command.is_some();

        // Check if this is an asset view query
        // Asset queries need events to build identity resolution and activity aggregation
        let asset_command = extract_asset_command(&query);
        let is_asset_query = asset_command.is_some();

        // Check if this is a cloud investigation query
        // Cloud queries re-query ClickHouse for facets, resources, and paginated events
        let cloud_command = extract_cloud_command(&query);
        let is_cloud_query = cloud_command.is_some();

        // Check if this is a funnel query — captured early so post-processing
        // can convert the `_droppers_<field>` sample arrays emitted by
        // generate_funnel_sql into top-K dropper attribution.
        let funnel_command = extract_funnel_command(&query);

        // Check if this is a lateral movement query
        let lateral_command = extract_lateral_command(&query);
        let post_lateral_commands = extract_post_lateral_commands(&query);
        let is_lateral_query = lateral_command.is_some();

        // Check if this is an AI pipe query
        // AI queries send results to an LLM for inline classification
        let ai_command = extract_ai_command(&query);
        let post_ai_commands = extract_post_ai_commands(&query);
        let has_ai = ai_command.is_some();

        // Check if query has aggregations (stats, timechart, top, rare, etc.)
        // Aggregations need all data to produce correct results
        let is_aggregation_query = query_has_aggregation(&query);

        // Check if query has prevalence filtering commands - these need all data for proper filtering
        // Enrich-only prevalence (no conditions) just decorates existing results, so normal limits apply
        let has_prevalence_filtering = prevalence_commands
            .iter()
            .any(|cmd| !cmd.conditions.is_empty());

        // Apply limit and offset
        // For queries that transform/aggregate data, use higher limits since they need more events.
        // Only simple event listing queries should use pagination limits.
        // - Tree: needs events for parent-child relationship building (but cap at 10k for performance)
        // - Asset: needs events for identity resolution and activity aggregation (cap at 100k)
        // - Stats/Timechart/Top/Rare: needs all events for accurate counts
        // - Prevalence: needs all events to properly filter by prevalence scores
        let limit = if is_tree_query {
            // Tree visualizations cap at 10k events - more than this makes the tree unusable anyway
            // and causes performance issues with tree building algorithm
            10_000
        } else if is_asset_query || is_cloud_query || is_lateral_query {
            // Asset/cloud/lateral initial fetch is only used for identifier detection (first 10 rows).
            // build_*_view re-queries ClickHouse for the actual data.
            10
        } else if is_aggregation_query || has_prevalence_filtering {
            1_000_000 // Stats/prevalence filtering need all events for correct results
        } else {
            request
                .limit
                .unwrap_or(self.config.default_limit)
                .min(self.config.max_limit)
        };
        let offset = request.offset.unwrap_or(0);

        // For raw event queries, cap offset so users can't page past max_limit.
        // Aggregation queries are uncapped since they process all events and return
        // a manageable number of grouped rows.
        let is_raw_event_query = !is_aggregation_query
            && !is_tree_query
            && !is_asset_query
            && !is_cloud_query
            && !is_lateral_query
            && !has_prevalence_filtering;
        let offset = if is_raw_event_query && offset >= self.config.max_limit {
            self.config.max_limit.saturating_sub(limit)
        } else {
            offset
        };

        let time_range = TimeRange::new(adjusted_time_range.start, adjusted_time_range.end);

        // Fast path: if this is an asset query and the identifier is directly in the search
        // expression (e.g. `src_host="workstation03" | asset`), skip the initial SQL query
        // entirely and call build_asset_view directly with the pre-extracted identifier.
        if let Some(ref asset_info) = asset_command {
            if let Some(pre_id) = extract_asset_identifier_from_query(&query, asset_info) {
                tracing::info!(
                    "Asset fast path: extracted identifier {}={} from query AST, skipping initial search",
                    pre_id.0, pre_id.1
                );
                let results = self
                    .build_asset_view(Vec::new(), asset_info, &time_range, Some(pre_id))
                    .await?;
                let execution_time_ms = start_time.elapsed().as_millis() as u64;
                let display_type = determine_display_type(&query);
                let column_order = get_column_order(&query);

                if let Some(ref req_id) = request.request_id {
                    self.query_tracker.unregister(req_id);
                }

                // Asset view is a single result containing nested _asset_pagination with the real count
                return Ok(SearchResponse {
                    results,
                    total_count: 1,
                    execution_time_ms,
                    fields: Vec::new(),
                    generated_sql: None,
                    histogram: None,
                    warnings: None,
                    cost_score: None,
                    display_type: Some(display_type),
                    column_order,
                });
            }
        }

        // Use JOIN-based approach for prevalence filtering when possible
        if use_prevalence_join {
            tracing::debug!("Using JOIN-based prevalence filtering for efficiency");
            return self
                .search_with_prevalence_join(
                    &query,
                    &prevalence_commands,
                    &post_prevalence.commands,
                    &lookup_commands,
                    &inputlookup_commands,
                    &post_inputlookup_commands,
                    &time_range,
                    &request,
                    &cleaned_query,
                    &adjusted_time_range,
                    limit,
                    offset,
                    start_time,
                )
                .await;
        }

        // Strip commands that need post-processing from the query for SQL generation
        // This includes: post-prevalence commands and inputlookup + post-inputlookup commands
        let query_for_sql = {
            let mut q = query.clone();

            // Strip prevalence and post-prevalence commands from SQL generation
            // Prevalence is handled entirely in Rust post-processing (enrichment/filtering),
            // so the SQL generator's no-op `SELECT * FROM source` wrapper is unnecessary
            if has_prevalence_cmds {
                tracing::debug!("Stripping prevalence command and {} post-prevalence commands for post-processing",
                    post_prevalence.commands.len());
                q = strip_prevalence_and_after(&q);
            }

            // Strip inputlookup and post-inputlookup commands if any
            if has_inputlookup {
                tracing::debug!(
                    "Found {} inputlookup commands and {} post-inputlookup commands",
                    inputlookup_commands.len(),
                    post_inputlookup_commands.len()
                );
                q = strip_inputlookup_and_after(&q);
            }

            // Strip lateral and post-lateral commands if any (movement tracing happens in post-processing)
            if is_lateral_query {
                q = strip_lateral_and_after(&q);
            }

            // Strip ai and post-ai commands if any (LLM enrichment happens in post-processing)
            if has_ai {
                q = strip_ai_and_after(&q);
            }

            q
        };

        // Generate SQL based on backend
        let sql = match self.backend {
            SearchBackend::ClickHouse => {
                use crate::query::QueryOptions;
                let options = QueryOptions {
                    use_cache: request.use_cache,
                    table_view: request.table_view,
                    limit: Some(limit),
                };
                // Apply current query safety limits to the SQL generator
                let ch_gen = self
                    .ch_sql_generator
                    .clone()
                    .with_max_group_array_size(query_limits.max_group_array_size as usize)
                    .with_max_mvexpand_rows(query_limits.max_mvexpand_rows as usize);
                ch_gen
                    .generate_with_options(&query_for_sql, &time_range, &options)
                    .map_err(|e| SearchError::SqlGenError(e.to_string()))?
            }
            SearchBackend::PostgreSQL => self
                .pg_sql_generator
                .generate(&query_for_sql, &time_range)
                .map_err(|e| SearchError::SqlGenError(e.to_string()))?,
        };

        debug!("Generated SQL (backend={:?}): {}", self.backend, sql);

        // Start histogram query in parallel with data execution — it only needs
        // the base search expression and time range, independent of data results.
        let histogram_handle = if !request.skip_histogram && !is_tree_query && !is_asset_query {
            let search_service = self.clone();
            let histogram_query = cleaned_query.clone();
            let histogram_time_range = adjusted_time_range.clone();
            Some(tokio::spawn(async move {
                match search_service
                    .generate_histogram(&histogram_query, &histogram_time_range)
                    .await
                {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("Parallel histogram query failed: {}", e);
                        None
                    }
                }
            }))
        } else {
            None
        };

        // Execute the query based on backend
        // For ClickHouse non-aggregation queries, also run field stats query in parallel
        let should_run_server_field_stats = self.backend == SearchBackend::ClickHouse
            && !is_aggregation_query
            && !is_tree_query
            && !is_asset_query
            && !request.skip_field_stats;

        let (mut results, total_count, server_field_stats) = match self.backend {
            SearchBackend::ClickHouse => {
                if should_run_server_field_stats {
                    let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
                        SearchError::DatabaseError(sqlx::Error::Configuration(
                            "ClickHouse client not configured".into(),
                        ))
                    })?;

                    // Get column list dynamically (run in parallel with data query)
                    let columns = ch_executor.get_table_columns().await.unwrap_or_else(|e| {
                        warn!("Failed to get table columns, using defaults: {}", e);
                        vec![
                            "user",
                            "src_ip",
                            "dest_ip",
                            "src_host",
                            "dest_host",
                            "action",
                            "status",
                            "source_type",
                            "process_name",
                            "file_name",
                            "protocol",
                            "auth_type",
                            "auth_result",
                            "category",
                            "duration",
                        ]
                        .into_iter()
                        .map(String::from)
                        .collect()
                    });

                    // Run data query and field stats query in parallel
                    // Use no sampling for inline field stats (async endpoint handles large datasets)
                    let field_stats_sql =
                        ClickHouseExecutor::build_field_stats_sql(&sql, None, &columns);
                    debug!("Generated field stats SQL: {}", field_stats_sql);

                    let (data_result, field_stats_result) = tokio::join!(
                        self.execute_clickhouse_sql_with_query_id(
                            &sql,
                            limit,
                            offset,
                            Some(&query_id),
                            None
                        ),
                        ch_executor.execute_field_stats_query(&field_stats_sql, &columns)
                    );

                    let (results, total_count) = data_result?;
                    let field_stats = match field_stats_result {
                        Ok(stats) => {
                            debug!("Server field stats returned {} fields", stats.len());
                            Some(stats)
                        }
                        Err(e) => {
                            // Graceful degradation: log warning and fall back to client-side stats
                            warn!(
                                "Field stats query failed, falling back to client-side: {}",
                                e
                            );
                            None
                        }
                    };

                    (results, total_count, field_stats)
                } else {
                    let (results, total_count) = self
                        .execute_clickhouse_sql_with_query_id(
                            &sql,
                            limit,
                            offset,
                            Some(&query_id),
                            None,
                        )
                        .await?;
                    (results, total_count, None)
                }
            }
            SearchBackend::PostgreSQL => {
                let (results, total_count) = self.execute_postgres_sql(&sql, limit, offset).await?;
                (results, total_count, None)
            }
        };

        tracing::debug!(
            "Initial SQL query returned {} results (total_count={})",
            results.len(),
            total_count
        );

        // Collect runtime warnings from post-processing (e.g. group cap reached)
        let mut runtime_warnings: Vec<String> = Vec::new();

        // Strip internal lookup fields used for SQL JOINs (these are implementation details)
        strip_internal_lookup_fields(&mut results);

        // Apply lookup enrichment if there are lookup commands
        if !lookup_commands.is_empty() {
            results =
                apply_lookup_enrichment(results, &lookup_commands, self.lookup_service.as_ref())
                    .await?;
        }

        // Apply inputlookup enrichment if there are inputlookup commands
        if !inputlookup_commands.is_empty() {
            tracing::debug!(
                "Applying {} inputlookup commands (service configured: {})",
                inputlookup_commands.len(),
                self.inputlookup_service.is_some()
            );
            results = apply_inputlookup_enrichment(
                results,
                &inputlookup_commands,
                self.inputlookup_service.as_ref(),
            )
            .await?;
            tracing::debug!("After inputlookup enrichment: {} results", results.len());
        }

        // Apply post-inputlookup commands (like table, where on inputlookup_* fields)
        if !post_inputlookup_commands.is_empty() {
            tracing::debug!(
                "Applying {} post-inputlookup commands to {} results",
                post_inputlookup_commands.len(),
                results.len()
            );
            let pp = apply_post_prevalence_commands_with_limit(
                results,
                &post_inputlookup_commands,
                query_limits.max_post_processing_groups as usize,
            )?;
            results = pp.results;
            runtime_warnings.extend(pp.warnings);
            tracing::debug!("After post-inputlookup commands: {} results", results.len());
        }

        // Apply prevalence filtering and enrichment if there are prevalence commands
        if !prevalence_commands.is_empty() {
            tracing::debug!("Applying {} prevalence commands", prevalence_commands.len());
            results = self
                .apply_prevalence_processing(results, &prevalence_commands)
                .await?;
            tracing::debug!("After prevalence processing: {} results", results.len());
        }

        // Apply post-prevalence commands (like where clauses on enriched fields)
        if !post_prevalence.commands.is_empty() {
            tracing::debug!(
                "Applying {} post-prevalence commands to {} results",
                post_prevalence.commands.len(),
                results.len()
            );
            let pp = apply_post_prevalence_commands_with_limit(
                results,
                &post_prevalence.commands,
                query_limits.max_post_processing_groups as usize,
            )?;
            results = pp.results;
            runtime_warnings.extend(pp.warnings);
            tracing::debug!("After post-prevalence commands: {} results", results.len());
        }

        // NAN-366: Strip the nested `_prevalence` object from enriched results (legacy path).
        // Top-level flat fields (host_count, first_seen, ...) already expose the same data.
        if !prevalence_commands.is_empty() {
            for row in &mut results {
                if let Some(obj) = row.as_object_mut() {
                    obj.remove("_prevalence");
                }
            }
        }

        // Build tree visualization if this is a tree query (tree_command extracted earlier)
        if let Some(ref tree_info) = tree_command {
            tracing::debug!(
                "Building tree structure with config: parent={}, child={}, label={}",
                tree_info.parent_field,
                tree_info.child_field,
                tree_info.label_field
            );
            results = self.build_tree_visualization(results, tree_info).await?;
            tracing::debug!("After tree building: {} top-level results", results.len());
        }

        // Build funnel view if this is a funnel query. Converts the raw
        // `_droppers_<field>` arrays emitted by the SQL layer into a compact
        // `dropper_top_attrs` JSON structure per stage row.
        if let Some(ref funnel_info) = funnel_command {
            tracing::debug!(
                "Building funnel view: group_by={:?}, step_count={}",
                funnel_info.group_by,
                funnel_info.step_count
            );
            results = self.build_funnel_view(results, funnel_info);
            tracing::debug!("After funnel view building: {} stage rows", results.len());
        }

        // Build asset view if this is an asset query (asset_command extracted earlier)
        if let Some(ref asset_info) = asset_command {
            tracing::debug!(
                "Building asset view with config: identifier_field={:?}, sections={:?}",
                asset_info.identifier_field,
                asset_info.sections
            );
            results = self
                .build_asset_view(results, asset_info, &time_range, None)
                .await?;
            tracing::debug!("After asset view building: {} results", results.len());
        }

        // Build cloud investigation view if this is a cloud query
        if let Some(ref cloud_info) = cloud_command {
            tracing::debug!(
                "Building cloud view with config: group_by={:?}, show_mfa={}",
                cloud_info.group_by,
                cloud_info.show_mfa
            );
            results = self
                .build_cloud_view(results, cloud_info, &time_range, &cleaned_query)
                .await?;
            tracing::debug!("After cloud view building: {} results", results.len());
        }

        // Build lateral movement view if this is a lateral query
        if let Some(ref lateral_info) = lateral_command {
            tracing::debug!(
                "Building lateral movement view: seed_type={:?}, max_hops={}",
                lateral_info.seed_type,
                lateral_info.max_hops
            );
            results = self
                .build_lateral_view(results, lateral_info, &time_range)
                .await?;
            tracing::debug!("After lateral view building: {} results", results.len());

            // Apply post-lateral commands (e.g., | where method_detail="rdp" | stats count by dest_host)
            // Preserve the metadata row (first row with _display_type) — only filter edge rows.
            if !post_lateral_commands.is_empty() {
                tracing::debug!(
                    "Applying {} post-lateral commands",
                    post_lateral_commands.len()
                );
                let metadata_row = results
                    .iter()
                    .position(|r| r.get("_display_type").is_some())
                    .map(|i| results.remove(i));
                let pp = apply_post_prevalence_commands_with_limit(
                    results,
                    &post_lateral_commands,
                    query_limits.max_post_processing_groups as usize,
                )?;
                results = pp.results;
                runtime_warnings.extend(pp.warnings);
                if let Some(meta) = metadata_row {
                    results.insert(0, meta);
                }
            }
        }

        // AI pipe enrichment: send results to LLM for inline classification.
        // The `ai_client` is always present — open-core builds wire
        // `NoopAiClient`, which tags overflow / disabled rows with
        // `ai_verdict = "SKIPPED"` so the table shape is preserved.
        if let Some(ref ai_info) = ai_command {
            tracing::debug!(
                "Running AI pipe enrichment: prompt={}, max_rows={}",
                ai_info.prompt,
                ai_info.max_rows
            );
            match self
                .ai_client
                .enrich_rows(results.clone(), &ai_info.prompt, ai_info.max_rows)
                .await
            {
                Ok(enriched) => {
                    results = enriched;
                    tracing::debug!("AI pipe enrichment complete: {} results", results.len());
                }
                Err(e) => {
                    tracing::warn!("AI pipe enrichment failed: {}", e);
                    // Non-fatal: mark all rows with error
                    for row in results.iter_mut() {
                        if let Some(obj) = row.as_object_mut() {
                            obj.insert(
                                "ai_verdict".to_string(),
                                serde_json::Value::String("ERROR".to_string()),
                            );
                            obj.insert(
                                "ai_confidence".to_string(),
                                serde_json::Value::Number(
                                    serde_json::Number::from_f64(0.0).unwrap(),
                                ),
                            );
                            obj.insert(
                                "ai_reasoning".to_string(),
                                serde_json::Value::String(format!(
                                    "AI enrichment failed: {}",
                                    e
                                )),
                            );
                        }
                    }
                }
            }
            // Apply post-ai commands (e.g., | where ai_verdict="TP")
            if !post_ai_commands.is_empty() {
                tracing::debug!("Applying {} post-ai commands", post_ai_commands.len());
                let pp = apply_post_prevalence_commands_with_limit(
                    results,
                    &post_ai_commands,
                    query_limits.max_post_processing_groups as usize,
                )?;
                results = pp.results;
                runtime_warnings.extend(pp.warnings);
            }
        }

        // Calculate field statistics (after enrichment so lookup fields are included)
        // Skip for tree/asset/cloud queries (visualization is the data) or if explicitly requested
        // Prefer server-side stats (computed across ALL matching events) over client-side stats (from sampled results)
        let fields = if request.skip_field_stats
            || is_tree_query
            || is_asset_query
            || is_cloud_query
            || is_lateral_query
        {
            Vec::new()
        } else if let Some(stats) = server_field_stats {
            // Use server-side field stats (topK across all matching events)
            debug!("Using server-side field stats ({} fields)", stats.len());
            stats
        } else {
            // Fall back to client-side stats from sampled results
            debug!(
                "Using client-side field stats from {} results",
                results.len()
            );
            let mut stats = FieldStatistics::new();
            for row in &results {
                stats.process_row(row);
            }
            stats.get_field_info(self.config.top_values_count)
        };

        // Collect histogram from the parallel task spawned before data execution.
        // The histogram runs the base filter independently — no dependency on data results.
        let histogram = if let Some(handle) = histogram_handle {
            handle.await.ok().flatten()
        } else {
            None
        };

        // Analyze query cost and generate warnings (query cost analysis)
        let cost_analysis = analyze_query_cost(&query);

        // Optionally block queries that trigger Error-severity cost warnings
        if query_limits.block_on_cost_errors && cost_analysis.has_errors() {
            let error_messages: Vec<String> = cost_analysis
                .warnings
                .iter()
                .filter(|w| w.severity == WarningSeverity::Error)
                .map(|w| {
                    let mut msg = format!("[{}] {}", w.code, w.message);
                    if let Some(ref suggestion) = w.suggestion {
                        msg.push_str(&format!(" — {}", suggestion));
                    }
                    msg
                })
                .collect();
            return Err(SearchError::SqlValidationError(format!(
                "Query blocked by cost analysis: {}",
                error_messages.join("; ")
            )));
        }

        // Merge cost analysis warnings with runtime post-processing warnings
        let mut all_warnings: Vec<QueryWarningOutput> = cost_analysis
            .warnings
            .iter()
            .map(|w| QueryWarningOutput {
                severity: match w.severity {
                    WarningSeverity::Info => "info".to_string(),
                    WarningSeverity::Warning => "warning".to_string(),
                    WarningSeverity::Error => "error".to_string(),
                },
                code: w.code.clone(),
                message: w.message.clone(),
                suggestion: w.suggestion.clone(),
                impact: w.impact.clone(),
            })
            .collect();

        // Add runtime warnings (e.g. stats group cap reached)
        for msg in &runtime_warnings {
            all_warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "POST_PROCESSING_TRUNCATED".to_string(),
                message: msg.clone(),
                suggestion: Some("Add filters or reduce the time range to lower cardinality".to_string()),
                impact: Some("Some results may be missing from the output".to_string()),
            });
        }

        let (warnings, cost_score) = if all_warnings.is_empty() {
            (None, None)
        } else {
            (Some(all_warnings), Some(cost_analysis.estimated_cost))
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Determine display type from the query AST
        let display_type = determine_display_type(&query);

        // Extract column order from table command if present
        let column_order = get_column_order(&query);

        // Unregister from tracker now that query is complete
        if let Some(ref req_id) = request.request_id {
            self.query_tracker.unregister(req_id);
        }

        // Cap reported total_count at max_limit for raw event queries so the
        // frontend knows pagination stops there. Aggregation queries report the
        // real count since their output is already grouped/reduced.
        let capped_total = if is_raw_event_query {
            total_count.min(self.config.max_limit as u64)
        } else {
            total_count
        };

        Ok(SearchResponse {
            results,
            total_count: capped_total,
            execution_time_ms,
            fields,
            generated_sql: if request.include_sql.unwrap_or(false) {
                Some(sql)
            } else {
                None
            },
            histogram,
            warnings,
            cost_score,
            display_type: Some(display_type),
            column_order,
        })
    }
}
