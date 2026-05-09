// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Ingestion Service
//!
//! Provides batch log ingestion with field normalization, enrichment, and storage.
//! Logs are stored in ClickHouse. PostgreSQL is used for metadata (parsers, detection rules)
//! and error logging (ingestion_errors table).
//!
//! Requirements: 1.1, 1.3, 2.6, 3.1, 3.2, 3.3, 3.4, 3.5, 11.1, 11.3, 11.4

use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

use super::{LogParser, ParsedLog, ParserError};
use crate::db::DualPool;
use crate::models::NewLog;
use crate::parsers::{AutoDetectResult, AutoDetector};

/// Errors that can occur during log ingestion
#[derive(Error, Debug)]
pub enum IngestionError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),

    #[error("Parse error: {0}")]
    ParseError(#[from] ParserError),

    #[error("Batch insert failed: {0}")]
    BatchInsertFailed(String),

    #[error("Service not initialized")]
    NotInitialized,

    #[error("Auto-detection error: {0}")]
    AutoDetectionError(String),

    #[error("Retry exhausted after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },
}

/// Configuration for the ingestion service
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Maximum number of logs to batch before flushing
    pub batch_size: usize,
    /// Maximum buffer size before dropping logs (memory protection)
    /// When the buffer exceeds this size and flush fails, oldest logs are dropped
    pub max_buffer_size: usize,
    /// Maximum time to wait before flushing a partial batch (in milliseconds)
    pub flush_interval_ms: u64,
    /// Whether to enable deduplication (handled by Vector, but can be double-checked)
    pub enable_dedup: bool,
    /// Whether to enable auto-detection of source types
    pub enable_auto_detection: bool,
    /// Confidence threshold for auto-detection (0.0 to 1.0)
    pub auto_detection_threshold: f32,
    /// Maximum retry attempts for failed ClickHouse inserts
    pub max_retry_attempts: u32,
    /// Base delay for exponential backoff (in milliseconds)
    pub retry_base_delay_ms: u64,
    /// Maximum delay for exponential backoff (in milliseconds)
    pub retry_max_delay_ms: u64,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_buffer_size: 100_000, // Max 100k logs in buffer (~100MB at ~1KB/log)
            flush_interval_ms: 5000,
            enable_dedup: false,           // Vector handles dedup
            enable_auto_detection: true,   // Enable auto-detection by default
            auto_detection_threshold: 0.5, // Default confidence threshold
            max_retry_attempts: 3,
            retry_base_delay_ms: 100,
            retry_max_delay_ms: 5000,
        }
    }
}

/// Statistics for the ingestion service
#[derive(Debug, Default)]
pub struct IngestionStats {
    /// Total logs received
    pub logs_received: AtomicU64,
    /// Total logs successfully stored
    pub logs_stored: AtomicU64,
    /// Total logs that failed to parse
    pub parse_errors: AtomicU64,
    /// Total logs that failed to store
    pub storage_errors: AtomicU64,
    /// Total batches processed
    pub batches_processed: AtomicU64,
    /// Total logs dropped due to buffer overflow
    pub logs_dropped: AtomicU64,
}

impl IngestionStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> IngestionStatsSnapshot {
        IngestionStatsSnapshot {
            logs_received: self.logs_received.load(Ordering::Relaxed),
            logs_stored: self.logs_stored.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            storage_errors: self.storage_errors.load(Ordering::Relaxed),
            batches_processed: self.batches_processed.load(Ordering::Relaxed),
            logs_dropped: self.logs_dropped.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of ingestion statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct IngestionStatsSnapshot {
    pub logs_received: u64,
    pub logs_stored: u64,
    pub parse_errors: u64,
    pub storage_errors: u64,
    pub batches_processed: u64,
    pub logs_dropped: u64,
}

/// Log ingestion service
///
/// Receives logs from Vector (or other sources), applies field normalization,
/// and stores them in ClickHouse (logs) and PostgreSQL (errors, metadata).
/// GeoIP/ASN enrichment is handled by ClickHouse DEFAULT expressions via ip_enrichment_dict.
///
/// Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 11.1, 11.3, 11.4
pub struct IngestionService {
    /// PostgreSQL pool for error logging and metadata
    pg_pool: PgPool,
    /// Optional DualPool for ClickHouse access
    dual_pool: Option<DualPool>,
    parser: LogParser,
    config: IngestionConfig,
    stats: Arc<IngestionStats>,
    buffer: Arc<Mutex<Vec<ParsedLog>>>,
    auto_detector: Arc<RwLock<AutoDetector>>,
}

/// ClickHouse row structure for log insertion
/// This struct maps to the ClickHouse logs table schema
///
/// Note: We use i64 timestamps (microseconds since epoch) for compatibility
/// with ClickHouse's DateTime64(6) type.
/// Note: The `id` field uses a content-based UUID computed from (source_type + timestamp + message)
/// to ensure idempotent inserts - retrying the same batch produces the same IDs.
#[derive(Debug, Clone, Row, Serialize)]
pub struct ClickHouseLogRow {
    /// Content-based UUID for idempotent inserts (derived from source_type + timestamp + message hash)
    #[serde(with = "clickhouse::serde::uuid")]
    pub id: Uuid,
    pub timestamp: i64, // Microseconds since epoch for DateTime64(6)
    pub message: String,
    pub metadata: String,
    pub source_type: String,
    pub source: String,
    pub src_ip: String,
    pub dest_ip: String,
    pub src_host: String,
    pub dest_host: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub protocol: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub user: String,
    pub action: String,
    pub status: String,
    pub severity: String,
    pub auth_type: String,
    pub auth_result: String,
    pub session_id: String,
    pub process_name: String,
    pub process_id: u32,
    /// Full command line (command_line = path + exe + args)
    pub command_line: String,
    /// Parent exe filename only
    pub parent_process_name: String,
    /// Full parent command line (parent_command_line = path + exe + args)
    pub parent_command_line: String,
    pub file_path: String,
    pub file_name: String,
    pub file_hash: String,
    pub file_action: String,
    pub user_agent: String,
    pub ingest_time: i64, // Microseconds since epoch for DateTime64(6)
}

impl ClickHouseLogRow {
    /// Convert a chrono DateTime to microseconds since epoch
    fn datetime_to_micros(dt: DateTime<Utc>) -> i64 {
        dt.timestamp_micros()
    }

    /// Compute a content-based UUID for idempotent inserts
    ///
    /// The UUID is derived from SHA256(source_type + timestamp_micros + message), using
    /// the first 16 bytes as a UUID. This ensures:
    /// - Same log content always produces the same UUID
    /// - Retrying failed batches doesn't create duplicate entries with different IDs
    /// - Logs with identical content (true duplicates) get the same ID
    fn compute_content_uuid(source_type: &str, timestamp_micros: i64, message: &str) -> Uuid {
        let mut hasher = Sha256::new();
        hasher.update(source_type.as_bytes());
        hasher.update(b"|");
        hasher.update(timestamp_micros.to_le_bytes());
        hasher.update(b"|");
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        // Use first 16 bytes of SHA256 as UUID (version 8, variant 2)
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        // Set version to 8 (custom) and variant to RFC 4122
        bytes[6] = (bytes[6] & 0x0f) | 0x80; // Version 8
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant RFC 4122
        Uuid::from_bytes(bytes)
    }

    /// Convert a ParsedLog to a ClickHouseLogRow
    pub fn from_parsed_log(log: &ParsedLog, ingest_time: DateTime<Utc>) -> Self {
        let timestamp_micros = Self::datetime_to_micros(log.timestamp);
        let id = Self::compute_content_uuid(&log.source_type, timestamp_micros, &log.message);

        Self {
            id,
            timestamp: timestamp_micros,
            message: log.message.clone(),
            metadata: log.metadata.to_string(),
            source_type: log.source_type.clone(),
            source: log.source.clone().unwrap_or_default(),
            src_ip: log.src_ip.clone().unwrap_or_default(),
            dest_ip: log.dest_ip.clone().unwrap_or_default(),
            src_host: log.src_host.clone().unwrap_or_default(),
            dest_host: log.dest_host.clone().unwrap_or_default(),
            src_port: log.src_port.map(|p| p as u16).unwrap_or(0),
            dest_port: log.dest_port.map(|p| p as u16).unwrap_or(0),
            protocol: log.protocol.clone().unwrap_or_default(),
            bytes_in: log.bytes_in.map(|b| b as u64).unwrap_or(0),
            bytes_out: log.bytes_out.map(|b| b as u64).unwrap_or(0),
            user: log.user.clone().unwrap_or_default(),
            action: log.action.clone().unwrap_or_default(),
            status: log.status.clone().unwrap_or_default(),
            severity: log.severity.clone().unwrap_or_default(),
            auth_type: log.auth_type.clone().unwrap_or_default(),
            auth_result: log.auth_result.clone().unwrap_or_default(),
            session_id: log.session_id.clone().unwrap_or_default(),
            process_name: log.process_name.clone().unwrap_or_default(),
            process_id: log.process_id.map(|p| p as u32).unwrap_or(0),
            command_line: log.command_line.clone().unwrap_or_default(),
            parent_process_name: log.parent_process_name.clone().unwrap_or_default(),
            parent_command_line: log.parent_command_line.clone().unwrap_or_default(),
            file_path: log.file_path.clone().unwrap_or_default(),
            file_name: log.file_name.clone().unwrap_or_default(),
            file_hash: log.file_hash.clone().unwrap_or_default(),
            file_action: log.file_action.clone().unwrap_or_default(),
            user_agent: log.user_agent.clone().unwrap_or_default(),
            ingest_time: Self::datetime_to_micros(ingest_time),
        }
    }
}

impl IngestionService {
    /// Create a new ingestion service with DualPool (ClickHouse + PostgreSQL)
    ///
    /// This is the preferred constructor for production use with ClickHouse.
    /// PostgreSQL is used for error logging and metadata.
    ///
    /// Requirements: 3.1
    pub fn new_with_dual_pool(dual_pool: DualPool, config: IngestionConfig) -> Self {
        let pg_pool = dual_pool.postgres().clone();
        let auto_detector = AutoDetector::with_threshold(config.auto_detection_threshold);

        Self {
            pg_pool,
            dual_pool: Some(dual_pool),
            parser: LogParser::new(),
            config,
            stats: Arc::new(IngestionStats::new()),
            buffer: Arc::new(Mutex::new(Vec::new())),
            auto_detector: Arc::new(RwLock::new(auto_detector)),
        }
    }

    /// Create a new ingestion service with PostgreSQL only (degraded mode)
    ///
    /// WARNING: This constructor creates an ingestion service without ClickHouse.
    /// Log storage will fail with NotInitialized error. Use new_with_dual_pool() for production.
    pub fn new(pool: PgPool, config: IngestionConfig) -> Self {
        tracing::warn!(
            "Creating IngestionService without ClickHouse - log storage will be disabled"
        );
        let auto_detector = AutoDetector::with_threshold(config.auto_detection_threshold);

        Self {
            pg_pool: pool,
            dual_pool: None,
            parser: LogParser::new(),
            config,
            stats: Arc::new(IngestionStats::new()),
            buffer: Arc::new(Mutex::new(Vec::new())),
            auto_detector: Arc::new(RwLock::new(auto_detector)),
        }
    }

    /// Create with default configuration (degraded mode without ClickHouse)
    pub fn with_defaults(pool: PgPool) -> Self {
        Self::new(pool, IngestionConfig::default())
    }

    /// Create with default configuration using DualPool
    pub fn with_defaults_dual_pool(dual_pool: DualPool) -> Self {
        Self::new_with_dual_pool(dual_pool, IngestionConfig::default())
    }

    /// Get a reference to the PostgreSQL pool
    pub fn pg_pool(&self) -> &PgPool {
        &self.pg_pool
    }

    /// Load auto-detection patterns from the database
    ///
    /// This should be called during service initialization to load
    /// detection patterns for auto-detecting source types.
    ///
    /// Requirements: 11.2
    pub async fn load_auto_detection_patterns(&self) -> Result<usize, IngestionError> {
        if !self.config.enable_auto_detection {
            return Ok(0);
        }

        let mut detector = self.auto_detector.write().await;
        let count = detector
            .load_patterns(&self.pg_pool)
            .await
            .map_err(|e| IngestionError::AutoDetectionError(e.to_string()))?;

        tracing::info!("Loaded {} auto-detection patterns", count);
        Ok(count)
    }

    /// Auto-detect the source type for a log message
    ///
    /// Returns the detected source type if confidence is above threshold,
    /// otherwise returns None.
    ///
    /// Requirements: 11.1, 11.3
    pub async fn auto_detect_source_type(&self, log_content: &str) -> Option<AutoDetectResult> {
        if !self.config.enable_auto_detection {
            return None;
        }

        let detector = self.auto_detector.read().await;
        if !detector.has_patterns() {
            return None;
        }

        Some(detector.detect(log_content))
    }

    /// Apply auto-detection to a parsed log if source type is unknown
    ///
    /// Requirements: 11.3, 11.4
    async fn apply_auto_detection(&self, log: &mut ParsedLog) {
        // Only apply auto-detection if source type is unknown or generic
        if !self.config.enable_auto_detection {
            return;
        }

        let needs_detection = log.source_type == "unknown"
            || log.source_type == "generic"
            || log.source_type.is_empty();

        if !needs_detection {
            return;
        }

        let detector = self.auto_detector.read().await;
        if !detector.has_patterns() {
            return;
        }

        let result = detector.detect(&log.message);

        // Update metadata with detection info
        if let Some(ref mut metadata) = log.metadata.as_object_mut() {
            metadata.insert(
                "auto_detection_confidence".to_string(),
                serde_json::json!(result.confidence),
            );
            metadata.insert(
                "auto_detection_threshold".to_string(),
                serde_json::json!(result.threshold),
            );
        }

        // Apply detected source type if confident
        if result.is_confident {
            if let Some(detected_type) = result.detected_source_type {
                tracing::debug!(
                    "Auto-detected source type '{}' with confidence {:.2}",
                    detected_type,
                    result.confidence
                );
                log.source_type = detected_type;

                // Mark as auto-detected in metadata
                if let Some(ref mut metadata) = log.metadata.as_object_mut() {
                    metadata.insert("auto_detected".to_string(), serde_json::json!(true));
                }
            }
        } else {
            // Flag for review if uncertain
            // Requirement 11.4: Flag the log for review when uncertain
            if let Some(ref mut metadata) = log.metadata.as_object_mut() {
                metadata.insert(
                    "needs_source_type_review".to_string(),
                    serde_json::json!(true),
                );
                metadata.insert("auto_detected".to_string(), serde_json::json!(false));
            }
            tracing::debug!(
                "Auto-detection uncertain (confidence {:.2} < threshold {:.2}), flagging for review",
                result.confidence,
                result.threshold
            );
        }
    }

    /// Get ingestion statistics
    pub fn stats(&self) -> IngestionStatsSnapshot {
        self.stats.snapshot()
    }

    /// Ingest a single log entry (raw string)
    pub async fn ingest_raw(&self, raw: &str) -> Result<(), IngestionError> {
        self.stats.logs_received.fetch_add(1, Ordering::Relaxed);

        let parsed = match self.parser.parse(raw) {
            Ok(p) => p,
            Err(e) => {
                self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                // Log parse error
                self.log_parse_error(None, raw, &e.to_string()).await;
                return Err(e.into());
            }
        };

        self.add_to_buffer(parsed).await
    }

    /// Ingest a single log entry (JSON from Vector)
    pub async fn ingest_json(&self, json: serde_json::Value) -> Result<(), IngestionError> {
        self.stats.logs_received.fetch_add(1, Ordering::Relaxed);

        let message = json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(); // Clone the string before moving json

        let mut parsed = match self.parser.parse_json(json) {
            Ok(p) => p,
            Err(e) => {
                self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                // Log parse error
                self.log_parse_error(None, &message, &e.to_string()).await;
                return Err(e.into());
            }
        };

        // Apply auto-detection if source type is unknown
        // Requirements: 11.3, 11.4
        self.apply_auto_detection(&mut parsed).await;

        // Store immediately for single log ingestion (no buffering)
        self.store_batch(&[parsed]).await?;
        Ok(())
    }

    /// Ingest a batch of log entries (JSON array from Vector)
    pub async fn ingest_batch(
        &self,
        logs: Vec<serde_json::Value>,
    ) -> Result<usize, IngestionError> {
        let count = logs.len();
        self.stats
            .logs_received
            .fetch_add(count as u64, Ordering::Relaxed);

        let mut parsed_logs = Vec::with_capacity(count);
        let mut parse_errors = 0;

        for json in logs {
            let message = json
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(); // Clone the string before moving json

            match self.parser.parse_json(json) {
                Ok(p) => parsed_logs.push(p),
                Err(e) => {
                    parse_errors += 1;
                    // Log parse error
                    self.log_parse_error(None, &message, &e.to_string()).await;
                }
            }
        }

        if parse_errors > 0 {
            self.stats
                .parse_errors
                .fetch_add(parse_errors, Ordering::Relaxed);
        }

        // Apply auto-detection to logs with unknown source types
        // Requirements: 11.3, 11.4
        for log in &mut parsed_logs {
            self.apply_auto_detection(log).await;
        }

        // Store directly without buffering for batch ingestion
        let stored = self.store_batch(&parsed_logs).await?;

        Ok(stored)
    }

    /// Add a parsed log to the buffer, flushing if necessary
    ///
    /// If the buffer exceeds max_buffer_size, oldest logs are dropped to make room.
    async fn add_to_buffer(&self, log: ParsedLog) -> Result<(), IngestionError> {
        let mut buffer = self.buffer.lock().await;

        // Check if we need to drop logs to make room
        if buffer.len() >= self.config.max_buffer_size {
            // Drop oldest 10% of buffer to make room
            let drop_count = std::cmp::max(1, self.config.max_buffer_size / 10);
            buffer.drain(0..drop_count);
            self.stats
                .logs_dropped
                .fetch_add(drop_count as u64, Ordering::Relaxed);
            tracing::warn!(
                "Ingestion buffer overflow: dropped {} oldest logs (buffer at max {})",
                drop_count,
                self.config.max_buffer_size
            );
        }

        buffer.push(log);

        if buffer.len() >= self.config.batch_size {
            let logs: Vec<ParsedLog> = buffer.drain(..).collect();
            drop(buffer); // Release lock before storing
            self.store_batch(&logs).await?;
        }

        Ok(())
    }

    /// Flush any buffered logs
    ///
    /// Requirements: 3.3
    pub async fn flush(&self) -> Result<usize, IngestionError> {
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(0);
        }

        let logs: Vec<ParsedLog> = buffer.drain(..).collect();
        drop(buffer);

        self.store_batch(&logs).await
    }

    /// Get the current number of buffered logs
    pub async fn buffer_size(&self) -> usize {
        self.buffer.lock().await.len()
    }

    /// Get the configured flush interval in milliseconds
    pub fn flush_interval_ms(&self) -> u64 {
        self.config.flush_interval_ms
    }

    /// Get the configured batch size
    pub fn batch_size(&self) -> usize {
        self.config.batch_size
    }

    /// Start a background flush task that periodically flushes buffered logs
    ///
    /// This method spawns a tokio task that will flush the buffer at the configured
    /// interval. The task runs until the returned handle is dropped or aborted.
    ///
    /// Requirements: 3.3
    ///
    /// # Example
    /// ```ignore
    /// let service = IngestionService::new_with_dual_pool(dual_pool, config);
    /// let flush_handle = service.start_background_flush();
    /// // ... use service ...
    /// flush_handle.abort(); // Stop the background flush task
    /// ```
    pub fn start_background_flush(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = Duration::from_millis(self.config.flush_interval_ms);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            interval_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            let mut consecutive_errors: u32 = 0;
            const MAX_BACKOFF_MS: u64 = 60_000; // 1 minute max backoff

            loop {
                interval_timer.tick().await;

                match self.flush().await {
                    Ok(count) => {
                        consecutive_errors = 0;
                        if count > 0 {
                            tracing::debug!("Background flush: stored {} logs", count);
                        }
                    }
                    Err(e) => {
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        let backoff_ms = std::cmp::min(
                            (2_u64)
                                .saturating_pow(consecutive_errors)
                                .saturating_mul(self.config.flush_interval_ms),
                            MAX_BACKOFF_MS,
                        );
                        tracing::error!(
                            "Background flush failed (attempt {}, backoff {}ms): {}",
                            consecutive_errors,
                            backoff_ms,
                            e
                        );
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    }
                }
            }
        })
    }

    /// Store a batch of parsed logs to ClickHouse
    ///
    /// ClickHouse is required for log storage. Returns NotInitialized error if DualPool
    /// is not available.
    /// Requirements: 3.1, 3.2
    async fn store_batch(&self, logs: &[ParsedLog]) -> Result<usize, IngestionError> {
        if logs.is_empty() {
            return Ok(0);
        }

        // ClickHouse is required for log storage
        if self.dual_pool.is_none() {
            return Err(IngestionError::NotInitialized);
        }

        self.store_batch_clickhouse(logs).await
    }

    /// Store a batch of parsed logs to ClickHouse
    ///
    /// Uses batch INSERT for efficient ingestion with retry logic.
    /// Requirements: 3.1, 3.2, 3.4
    async fn store_batch_clickhouse(&self, logs: &[ParsedLog]) -> Result<usize, IngestionError> {
        let dual_pool = self
            .dual_pool
            .as_ref()
            .ok_or_else(|| IngestionError::ClickHouseError("DualPool not available".to_string()))?;

        let ingest_time = Utc::now();

        // Convert logs to ClickHouse rows
        let rows: Vec<ClickHouseLogRow> = logs
            .iter()
            .map(|log| ClickHouseLogRow::from_parsed_log(log, ingest_time))
            .collect();

        // Attempt insert with retry logic
        let result = self.insert_clickhouse_with_retry(dual_pool, &rows).await;

        match result {
            Ok(count) => {
                self.stats
                    .logs_stored
                    .fetch_add(count as u64, Ordering::Relaxed);
                self.stats.batches_processed.fetch_add(1, Ordering::Relaxed);
                Ok(count)
            }
            Err(e) => {
                // Log all failed logs to PostgreSQL ingestion_errors table
                let error_msg = e.to_string();
                for log in logs {
                    self.log_storage_error(&log.source_type, &log.message, &error_msg)
                        .await;
                }
                self.stats
                    .storage_errors
                    .fetch_add(logs.len() as u64, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Insert rows into ClickHouse with exponential backoff retry
    ///
    /// Requirements: 3.4
    async fn insert_clickhouse_with_retry(
        &self,
        dual_pool: &DualPool,
        rows: &[ClickHouseLogRow],
    ) -> Result<usize, IngestionError> {
        let mut attempt = 0;
        let mut last_error = String::new();

        while attempt < self.config.max_retry_attempts {
            attempt += 1;

            match self.do_clickhouse_insert(dual_pool, rows).await {
                Ok(count) => return Ok(count),
                Err(e) => {
                    last_error = e.to_string();
                    tracing::warn!(
                        "ClickHouse insert attempt {}/{} failed: {}",
                        attempt,
                        self.config.max_retry_attempts,
                        last_error
                    );

                    if attempt < self.config.max_retry_attempts {
                        // Calculate exponential backoff delay
                        let delay_ms = std::cmp::min(
                            self.config.retry_base_delay_ms * (2_u64.pow(attempt - 1)),
                            self.config.retry_max_delay_ms,
                        );
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                }
            }
        }

        Err(IngestionError::RetryExhausted {
            attempts: self.config.max_retry_attempts,
            last_error,
        })
    }

    /// Perform the actual ClickHouse insert
    async fn do_clickhouse_insert(
        &self,
        dual_pool: &DualPool,
        rows: &[ClickHouseLogRow],
    ) -> Result<usize, IngestionError> {
        let client = dual_pool.clickhouse();

        let mut insert = client
            .insert::<ClickHouseLogRow>("logs")
            .await
            .map_err(|e| IngestionError::ClickHouseError(e.to_string()))?;

        for row in rows {
            insert
                .write(row)
                .await
                .map_err(|e| IngestionError::ClickHouseError(e.to_string()))?;
        }

        insert
            .end()
            .await
            .map_err(|e| IngestionError::ClickHouseError(e.to_string()))?;

        Ok(rows.len())
    }

    /// Log a parsing error to the ingestion_errors table (PostgreSQL)
    ///
    /// Requirements: 3.5
    async fn log_parse_error(&self, source_type: Option<&str>, message: &str, error_message: &str) {
        let _ = sqlx::query(
            r#"
            INSERT INTO ingestion_errors (timestamp, error_type, source_type, message, error_message)
            VALUES (NOW(), 'parse_error', $1, $2, $3)
            "#
        )
        .bind(source_type)
        .bind(message)
        .bind(error_message)
        .execute(&self.pg_pool)
        .await;
    }

    /// Log a storage error to the ingestion_errors table (PostgreSQL)
    ///
    /// Requirements: 3.5
    async fn log_storage_error(&self, source_type: &str, message: &str, error_message: &str) {
        let _ = sqlx::query(
            r#"
            INSERT INTO ingestion_errors (timestamp, error_type, source_type, message, error_message)
            VALUES (NOW(), 'storage_error', $1, $2, $3)
            "#
        )
        .bind(source_type)
        .bind(message)
        .bind(error_message)
        .execute(&self.pg_pool)
        .await;
    }
}

/// Convert ParsedLog to NewLog for repository compatibility
impl From<ParsedLog> for NewLog {
    fn from(parsed: ParsedLog) -> Self {
        NewLog {
            timestamp: Some(parsed.timestamp),
            message: parsed.message,
            metadata: parsed.metadata,
            source_type: Some(parsed.source_type),
            src_ip: parsed.src_ip,
            dest_ip: parsed.dest_ip,
            src_host: parsed.src_host,
            dest_host: parsed.dest_host,
            src_port: parsed.src_port,
            dest_port: parsed.dest_port,
            protocol: parsed.protocol,
            user: parsed.user,
            action: parsed.action,
            status: parsed.status,
            severity: parsed.severity,
            auth_type: parsed.auth_type,
            auth_result: parsed.auth_result,
            session_id: parsed.session_id,
            process_name: parsed.process_name,
            process_id: parsed.process_id,
            command_line: parsed.command_line,
            parent_process_name: parsed.parent_process_name,
            parent_command_line: parsed.parent_command_line,
            file_path: parsed.file_path,
            file_name: parsed.file_name,
            file_hash: parsed.file_hash,
            file_action: parsed.file_action,
            bytes_in: parsed.bytes_in,
            bytes_out: parsed.bytes_out,
            user_agent: parsed.user_agent,
            ext: parsed.ext,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingestion_config_default() {
        let config = IngestionConfig::default();
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.flush_interval_ms, 5000);
        assert!(!config.enable_dedup);
    }

    #[test]
    fn test_ingestion_stats() {
        let stats = IngestionStats::new();
        stats.logs_received.fetch_add(10, Ordering::Relaxed);
        stats.logs_stored.fetch_add(8, Ordering::Relaxed);
        stats.parse_errors.fetch_add(2, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.logs_received, 10);
        assert_eq!(snapshot.logs_stored, 8);
        assert_eq!(snapshot.parse_errors, 2);
    }
}
