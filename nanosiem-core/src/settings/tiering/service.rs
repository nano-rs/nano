// SPDX-License-Identifier: AGPL-3.0-or-later

//! TieringService implementation for managing S3-compatible storage tiering.

use super::types::*;
use super::validation::*;
use crate::crypto::{EncryptedData, EncryptionService};
use chrono::Utc;
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use std::path::PathBuf;

/// Service for managing storage tiering
pub struct TieringService {
    pg_pool: PgPool,
    ch_client: ClickHouseClient,
    crypto: EncryptionService,
    config_dir: PathBuf,
}

impl TieringService {
    /// Create a new tiering service
    pub fn new(pg_pool: PgPool, ch_client: ClickHouseClient, config_dir: PathBuf) -> Self {
        Self {
            pg_pool,
            ch_client,
            crypto: EncryptionService::from_env(),
            config_dir,
        }
    }

    /// Get current tiering configuration
    pub async fn get_config(&self) -> Result<TieringConfig, TieringError> {
        let row = sqlx::query_as::<_, TieringConfigRow>(
            r#"
            SELECT
                COALESCE(tiering_enabled, false) as enabled,
                tiering_s3_endpoint as s3_endpoint,
                tiering_s3_bucket as s3_bucket,
                COALESCE(tiering_s3_region, 'us-east-1') as s3_region,
                COALESCE(tiering_s3_path_style, false) as s3_path_style,
                tiering_s3_credentials_encrypted IS NOT NULL as has_credentials,
                COALESCE(retention_days, 365) as retention_days,
                COALESCE(tiering_move_factor, 0)::real as move_factor,
                COALESCE(tiering_status, 'unconfigured') as status,
                tiering_status_message as status_message,
                tiering_last_applied_at as last_applied_at
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pg_pool)
        .await?;

        match row {
            Some(r) => Ok(r.into()),
            None => Ok(TieringConfig::default()),
        }
    }

    /// Update tiering configuration
    ///
    /// This updates PostgreSQL but does NOT apply to ClickHouse.
    /// Call `apply_config()` to apply changes to ClickHouse.
    pub async fn update_config(
        &self,
        request: UpdateTieringRequest,
    ) -> Result<TieringConfig, TieringError> {
        let current = self.get_config().await?;

        // Validate S3 input fields to prevent XML injection in storage config
        if let Some(ref bucket) = request.s3_bucket {
            validate_s3_bucket(bucket)?;
        }
        if let Some(ref region) = request.s3_region {
            validate_s3_region(region)?;
        }
        if let Some(ref endpoint) = request.s3_endpoint {
            // Syntactic check first, then SSRF check with DNS resolution. The
            // SSRF check rejects loopback, RFC1918, link-local, IPv6 ULA, and
            // cloud metadata destinations — both as literal IPs and as
            // hostnames that resolve to them.
            validate_s3_endpoint(endpoint)?;
            validate_s3_endpoint_ssrf(endpoint).await?;
        }

        // Validate constraints
        let retention_days = request.retention_days.unwrap_or(current.retention_days);

        if !(1..=3650).contains(&retention_days) {
            return Err(TieringError::Config(
                "retention_days must be between 1 and 3650".to_string(),
            ));
        }

        if let Some(move_factor) = request.move_factor {
            if !(0.0..=1.0).contains(&move_factor) {
                return Err(TieringError::Config(
                    "move_factor must be between 0 and 1".to_string(),
                ));
            }
        }

        // Update configuration
        sqlx::query(
            r#"
            UPDATE system_settings SET
                tiering_enabled = COALESCE($1, tiering_enabled),
                tiering_s3_endpoint = COALESCE($2, tiering_s3_endpoint),
                tiering_s3_bucket = COALESCE($3, tiering_s3_bucket),
                tiering_s3_region = COALESCE($4, tiering_s3_region),
                tiering_s3_path_style = COALESCE($5, tiering_s3_path_style),
                retention_days = COALESCE($6, retention_days),
                tiering_move_factor = COALESCE($7, tiering_move_factor),
                tiering_status = 'pending',
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(request.enabled)
        .bind(&request.s3_endpoint)
        .bind(&request.s3_bucket)
        .bind(&request.s3_region)
        .bind(request.s3_path_style)
        .bind(request.retention_days.map(|d| d as i32))
        .bind(request.move_factor)
        .execute(&self.pg_pool)
        .await?;

        self.get_config().await
    }

    /// Set S3 credentials (encrypted)
    pub async fn set_credentials(&self, creds: S3Credentials) -> Result<(), TieringError> {
        // Validate credentials don't contain XML-unsafe content (defense in depth)
        if creds.access_key_id.is_empty() || creds.access_key_id.len() > 128 {
            return Err(TieringError::Config(
                "Invalid access key ID length".to_string(),
            ));
        }
        if creds.secret_access_key.is_empty() || creds.secret_access_key.len() > 128 {
            return Err(TieringError::Config(
                "Invalid secret access key length".to_string(),
            ));
        }
        if creds.access_key_id.contains('<') || creds.secret_access_key.contains('<') {
            return Err(TieringError::Config(
                "Credentials contain invalid characters".to_string(),
            ));
        }

        let encrypted = self
            .crypto
            .encrypt_json(&creds)
            .map_err(|e| TieringError::Encryption(e.to_string()))?;

        sqlx::query(
            r#"
            UPDATE system_settings SET
                tiering_s3_credentials_encrypted = $1,
                tiering_s3_credentials_nonce = $2,
                tiering_status = 'pending',
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(encrypted.ciphertext.as_bytes())
        .bind(&encrypted.nonce)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    /// Get decrypted S3 credentials (internal use only)
    async fn get_credentials(&self) -> Result<Option<S3Credentials>, TieringError> {
        let row: Option<(Option<Vec<u8>>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT
                tiering_s3_credentials_encrypted,
                tiering_s3_credentials_nonce
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pg_pool)
        .await?;

        match row {
            Some((Some(ciphertext), Some(nonce))) => {
                let encrypted = EncryptedData {
                    ciphertext: String::from_utf8_lossy(&ciphertext).to_string(),
                    nonce,
                };

                let creds: S3Credentials = self
                    .crypto
                    .decrypt_json(&encrypted)
                    .map_err(|e| TieringError::Encryption(e.to_string()))?;

                Ok(Some(creds))
            }
            _ => Ok(None),
        }
    }

    /// Test S3 connection with current configuration
    pub async fn test_connection(&self) -> Result<ConnectionTestResult, TieringError> {
        let config = self.get_config().await?;
        let creds = self.get_credentials().await?;

        let bucket = config
            .s3_bucket
            .as_ref()
            .ok_or(TieringError::Config("S3 bucket not configured".to_string()))?;

        // Verify credentials exist (we don't use them for the connectivity test,
        // but they're required for the actual S3 operations)
        let _creds = creds.ok_or(TieringError::Config(
            "S3 credentials not configured".to_string(),
        ))?;

        // Build S3 endpoint URL for bucket HEAD request.
        // SSRF re-validation happens just before the fetch (below) — we do not
        // translate Docker-internal hostnames to localhost; that translation
        // was an SSRF bypass and `validate_s3_endpoint` now rejects them.
        let endpoint = config.s3_endpoint.as_ref().map_or_else(
            || format!("https://s3.{}.amazonaws.com", config.s3_region),
            |e| e.trim_end_matches('/').to_string(),
        );

        // Re-validate the configured endpoint up front. The save-time check
        // in `update_config` may not have been exercised (e.g. legacy rows,
        // direct DB writes).
        if let Some(ref configured) = config.s3_endpoint {
            validate_s3_endpoint_ssrf(configured).await?;
        }

        // Build the URL based on path-style or virtual-hosted style
        let url = if config.s3_path_style {
            format!("{}/{}", endpoint, bucket)
        } else {
            // Virtual-hosted style: bucket.endpoint
            let endpoint_without_scheme = endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let scheme = if endpoint.starts_with("https://") {
                "https"
            } else {
                "http"
            };
            format!("{}://{}.{}", scheme, bucket, endpoint_without_scheme)
        };

        let start = std::time::Instant::now();

        // Create AWS signature for the request (simplified - just test basic connectivity)
        // For a proper test, we'll do a GET on the bucket with max-keys=0
        let list_url = format!("{}?list-type=2&max-keys=0", url);

        // Validate the FINAL request URL (not just `endpoint`). With
        // virtual-hosted-style addressing the actual host is `{bucket}.{endpoint_host}`,
        // and an attacker controlling DNS for a public-looking domain could
        // make `bucket.attacker.com` resolve to a private IP. Resolving here
        // and pinning the resulting IPs into the reqwest client below also
        // closes the DNS-rebinding window between this lookup and the
        // connect-time lookup — reqwest will dial these exact addresses.
        let (parsed_list_url, pinned_addrs) = validate_and_resolve_s3_endpoint(&list_url).await?;
        let pin_host = parsed_list_url
            .host_str()
            .ok_or_else(|| TieringError::Config("List URL has no host".to_string()))?
            .to_string();

        // Use reqwest to test connectivity with a GET request to the bucket.
        // Redirects are disabled so an attacker cannot use a public-IP endpoint
        // that 302s to a private destination — we'd otherwise need to
        // re-validate every Location target.
        //
        // `resolve_to_addrs` pins ALL validated IPs at once; reqwest tries
        // them in order. (The single-arg `resolve` overwrites for the same
        // domain, so a multi-A-record host would only pin the last addr.)
        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if !pinned_addrs.is_empty() {
            client_builder = client_builder.resolve_to_addrs(&pin_host, &pinned_addrs);
        }
        let client = client_builder
            .build()
            .map_err(|e| TieringError::S3Connection(e.to_string()))?;

        // Add date header for S3 compatibility
        let now = chrono::Utc::now();
        let date_str = now.format("%Y%m%dT%H%M%SZ").to_string();

        // For testing, we'll use unsigned request first to check endpoint reachability,
        // then rely on ClickHouse's actual S3 connection during apply.
        // The Host header matches `pin_host` so it reflects what reqwest dials
        // post resolve-pinning.
        match client
            .get(&list_url)
            .header("Host", &pin_host)
            .header("x-amz-date", &date_str)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let latency = start.elapsed().as_millis() as u64;

                // 200 = success, 403 = auth issue but endpoint reachable, 404 = bucket not found
                if status.is_success() || status.as_u16() == 403 {
                    // 403 means we reached S3 but need proper auth - that's actually good for a connectivity test
                    if status.as_u16() == 403 {
                        Ok(ConnectionTestResult {
                            success: true,
                            message: format!("Endpoint reachable. Credentials will be verified when applying config."),
                            latency_ms: Some(latency),
                        })
                    } else {
                        Ok(ConnectionTestResult {
                            success: true,
                            message: format!("Successfully connected to s3://{}", bucket),
                            latency_ms: Some(latency),
                        })
                    }
                } else if status.as_u16() == 404 {
                    Ok(ConnectionTestResult {
                        success: false,
                        message: format!("Bucket '{}' not found", bucket),
                        latency_ms: Some(latency),
                    })
                } else {
                    Ok(ConnectionTestResult {
                        success: false,
                        message: format!("S3 returned status {}", status),
                        latency_ms: Some(latency),
                    })
                }
            }
            Err(e) => {
                let latency = start.elapsed().as_millis() as u64;
                let message = if e.is_connect() {
                    format!("Cannot connect to endpoint: {}", endpoint)
                } else if e.is_timeout() {
                    "Connection timed out".to_string()
                } else {
                    format!("Connection failed: {}", e)
                };

                Ok(ConnectionTestResult {
                    success: false,
                    message,
                    latency_ms: Some(latency),
                })
            }
        }
    }

    /// Apply tiering configuration to ClickHouse
    ///
    /// This generates the storage.xml config file and applies TTL rules.
    pub async fn apply_config(&self) -> Result<(), TieringError> {
        let config = self.get_config().await?;

        // Update status to applying
        self.set_status(TieringStatus::Applying, None).await?;

        if !config.enabled {
            // Disable tiering - remove storage config and revert TTL
            return self.disable_tiering().await;
        }

        // Validate required fields
        let bucket = config
            .s3_bucket
            .as_ref()
            .ok_or(TieringError::Config("S3 bucket is required".to_string()))?;

        // Re-validate the endpoint against SSRF rules before writing it into
        // ClickHouse storage config (defense in depth — `update_config`
        // validates on save, but apply_config can be reached from legacy/
        // pre-fix rows).
        if let Some(ref endpoint) = config.s3_endpoint {
            validate_s3_endpoint_ssrf(endpoint).await?;
        }

        // Refuse to apply tiering with move_factor=0. The TTL is DELETE-only
        // (see apply_ttl_rules); moves rely entirely on move_factor. With 0,
        // parts would never leave local disk — silently breaking the bleed
        // and filling local storage until DELETE TTL kicks in.
        if config.move_factor <= 0.0 {
            return Err(TieringError::Config(
                "move_factor must be > 0 when tiering is enabled (e.g. 0.2 to \
                 start moving parts when local disk is ~80% full). \
                 ClickHouse uses move_factor to bleed parts to warm storage; \
                 the TTL is delete-only and will not move data on its own."
                    .to_string(),
            ));
        }

        let creds = self.get_credentials().await?.ok_or(TieringError::Config(
            "S3 credentials are required".to_string(),
        ))?;

        // Generate and write storage.xml
        let xml = self.generate_storage_xml(&config, &creds)?;
        self.write_storage_config(&xml)?;

        // Reload ClickHouse config
        if let Err(e) = self.reload_clickhouse_config().await {
            self.set_status(
                TieringStatus::Error,
                Some(format!("Config reload failed: {}", e)),
            )
            .await?;
            return Err(e);
        }

        // Apply TTL rules
        if let Err(e) = self.apply_ttl_rules(&config).await {
            self.set_status(
                TieringStatus::Error,
                Some(format!("TTL update failed: {}", e)),
            )
            .await?;
            return Err(e);
        }

        // Success
        self.set_status(TieringStatus::Active, None).await?;

        // Update last_applied_at
        sqlx::query(
            "UPDATE system_settings SET tiering_last_applied_at = NOW() WHERE id = 'default'",
        )
        .execute(&self.pg_pool)
        .await?;

        tracing::info!(
            bucket = %bucket,
            retention_days = config.retention_days,
            move_factor = config.move_factor,
            "Storage tiering applied successfully"
        );

        Ok(())
    }

    /// Disable tiering and revert to default storage
    async fn disable_tiering(&self) -> Result<(), TieringError> {
        // First, modify the TTL to remove any volume references
        // This must happen BEFORE removing the storage config
        self.ch_client
            .query("ALTER TABLE nanosiem.logs MODIFY TTL timestamp + INTERVAL 90 DAY DELETE")
            .execute()
            .await
            .map_err(|e| TieringError::ClickHouse(e.to_string()))?;

        // Instead of removing storage.xml entirely (which would break ClickHouse
        // since the table still has storage_policy='tiered'), we replace it with
        // a minimal config that defines the tiered policy using only local disk.
        // This allows ClickHouse to continue operating normally.
        let minimal_config = r#"<?xml version="1.0"?>
<!-- Minimal tiered policy using local disk only (S3 tiering disabled) -->
<clickhouse>
    <storage_configuration>
        <disks>
            <default>
                <keep_free_space_bytes>1073741824</keep_free_space_bytes>
            </default>
            <warm_disk>
                <path>/var/lib/clickhouse/warm/</path>
                <keep_free_space_bytes>1073741824</keep_free_space_bytes>
            </warm_disk>
        </disks>
        <policies>
            <tiered>
                <volumes>
                    <hot>
                        <disk>default</disk>
                    </hot>
                    <warm>
                        <disk>warm_disk</disk>
                    </warm>
                </volumes>
            </tiered>
        </policies>
    </storage_configuration>
</clickhouse>
"#;
        self.write_storage_config(minimal_config)?;

        // Reload ClickHouse to pick up the new config
        if let Err(e) = self.reload_clickhouse_config().await {
            tracing::warn!("Failed to reload ClickHouse config: {}", e);
            // Continue anyway - the config is updated
        }

        self.set_status(TieringStatus::Unconfigured, None).await?;

        tracing::info!("Storage tiering disabled - reverted to local disk only");
        Ok(())
    }

    /// Generate ClickHouse storage.xml configuration
    ///
    /// All user-supplied values are XML-escaped to prevent injection.
    fn generate_storage_xml(
        &self,
        config: &TieringConfig,
        creds: &S3Credentials,
    ) -> Result<String, TieringError> {
        let bucket = config
            .s3_bucket
            .as_ref()
            .ok_or(TieringError::Config("S3 bucket is required".to_string()))?;

        // Validate before generating XML (defense in depth — update_config also validates)
        validate_s3_bucket(bucket)?;
        validate_s3_region(&config.s3_region)?;
        if let Some(ref ep) = config.s3_endpoint {
            validate_s3_endpoint(ep)?;
        }

        // Build endpoint URL
        let endpoint = config.s3_endpoint.as_ref().map_or_else(
            || format!("https://s3.{}.amazonaws.com", config.s3_region),
            |e| e.clone(),
        );

        // Ensure endpoint doesn't have trailing slash
        let endpoint = endpoint.trim_end_matches('/');

        // XML-escape ALL interpolated values to prevent XML injection
        let xml = format!(
            r#"<?xml version="1.0"?>
<clickhouse>
    <storage_configuration>
        <disks>
            <default>
                <keep_free_space_bytes>1073741824</keep_free_space_bytes>
            </default>
            <s3_warm>
                <type>s3</type>
                <endpoint>{endpoint}/{bucket}/warm/</endpoint>
                <access_key_id>{access_key}</access_key_id>
                <secret_access_key>{secret_key}</secret_access_key>
                <region>{region}</region>
                <use_environment_credentials>false</use_environment_credentials>
                <metadata_path>/var/lib/clickhouse/disks/s3_warm/</metadata_path>
                <cache_enabled>true</cache_enabled>
                <data_cache_enabled>true</data_cache_enabled>
                <cache_path>/var/lib/clickhouse/disks/s3_warm_cache/</cache_path>
            </s3_warm>
        </disks>
        <policies>
            <tiered>
                <!-- move_factor: 0 = TTL-only, 0.1 = auto-move when disk 90% full -->
                <move_factor>{move_factor}</move_factor>
                <volumes>
                    <!-- Must be named 'default' to be compatible with existing data on default policy -->
                    <default>
                        <disk>default</disk>
                    </default>
                    <warm>
                        <disk>s3_warm</disk>
                    </warm>
                </volumes>
            </tiered>
        </policies>
    </storage_configuration>
</clickhouse>
"#,
            endpoint = xml_escape(endpoint),
            bucket = xml_escape(bucket),
            access_key = xml_escape(&creds.access_key_id),
            secret_key = xml_escape(&creds.secret_access_key),
            region = xml_escape(&config.s3_region),
            move_factor = config.move_factor,
        );

        Ok(xml)
    }

    /// Write storage.xml to config directory, creating it if necessary.
    fn write_storage_config(&self, content: &str) -> Result<(), TieringError> {
        // Ensure the config directory exists
        if !self.config_dir.exists() {
            std::fs::create_dir_all(&self.config_dir).map_err(|e| {
                TieringError::Config(format!(
                    "Cannot create config directory {}: {}",
                    self.config_dir.display(),
                    e
                ))
            })?;
        }
        let config_path = self.config_dir.join("storage.xml");
        std::fs::write(&config_path, content)?;
        tracing::info!(path = %config_path.display(), "Wrote ClickHouse storage configuration");
        Ok(())
    }

    /// Signal ClickHouse to reload configuration
    /// Note: Storage policy changes require a full restart, SYSTEM RELOAD CONFIG is not sufficient
    async fn reload_clickhouse_config(&self) -> Result<(), TieringError> {
        // First try SYSTEM RELOAD CONFIG for basic config changes
        self.ch_client
            .query("SYSTEM RELOAD CONFIG")
            .execute()
            .await
            .map_err(|e| TieringError::ClickHouse(format!("Config reload failed: {}", e)))?;

        // For storage policy changes, we need to restart ClickHouse
        // Use docker restart via command execution
        let output = std::process::Command::new("docker")
            .args(["restart", "nanosiem-clickhouse"])
            .output()
            .map_err(|e| {
                TieringError::ClickHouse(format!("Failed to restart ClickHouse: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TieringError::ClickHouse(format!(
                "Failed to restart ClickHouse: {}",
                stderr
            )));
        }

        // Wait for ClickHouse to come back up
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Verify ClickHouse is responding
        for _ in 0..10 {
            if self.ch_client.query("SELECT 1").execute().await.is_ok() {
                tracing::info!("ClickHouse restarted and responding");
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        Err(TieringError::ClickHouse(
            "ClickHouse did not respond after restart".to_string(),
        ))
    }

    /// Apply TTL rules for tiered storage.
    ///
    /// Movement of parts from hot to warm is driven by the
    /// `<move_factor>` element on the `<tiered>` policy in storage.xml
    /// (written by `generate_storage_xml`), not by a time-based TTL. The
    /// TTL set here is the DELETE compliance cap only — `apply_config`
    /// refuses to apply with `move_factor=0` so the storage policy is
    /// guaranteed to be doing the moves.
    async fn apply_ttl_rules(&self, config: &TieringConfig) -> Result<(), TieringError> {
        // First, update the storage policy
        self.ch_client
            .query("ALTER TABLE logs MODIFY SETTING storage_policy = 'tiered'")
            .execute()
            .await
            .map_err(|e| {
                TieringError::ClickHouse(format!("Failed to set storage policy: {}", e))
            })?;

        // DELETE TTL only — moves are handled by move_factor on the policy.
        let ttl_query = format!(
            "ALTER TABLE logs MODIFY TTL timestamp + INTERVAL {} DAY DELETE",
            config.retention_days
        );

        self.ch_client
            .query(&ttl_query)
            .execute()
            .await
            .map_err(|e| TieringError::ClickHouse(format!("Failed to set TTL rules: {}", e)))?;

        tracing::info!(
            retention_days = config.retention_days,
            "TTL rules applied"
        );

        Ok(())
    }

    /// Update tiering status
    async fn set_status(
        &self,
        status: TieringStatus,
        message: Option<String>,
    ) -> Result<(), TieringError> {
        sqlx::query(
            r#"
            UPDATE system_settings SET
                tiering_status = $1,
                tiering_status_message = $2,
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(status.as_str())
        .bind(message)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    /// Get storage statistics per tier
    pub async fn get_tier_stats(&self) -> Result<TierStats, TieringError> {
        // Query ClickHouse for per-volume statistics
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct VolumeStats {
            disk_name: String,
            total_bytes: u64,
            total_rows: u64,
        }

        // Get stats grouped by disk
        let stats: Vec<VolumeStats> = self
            .ch_client
            .query(
                r#"
                SELECT
                    disk_name,
                    sum(bytes_on_disk) as total_bytes,
                    sum(rows) as total_rows
                FROM system.parts
                WHERE database = currentDatabase()
                  AND table = 'logs'
                  AND active = 1
                GROUP BY disk_name
                "#,
            )
            .fetch_all()
            .await
            .map_err(|e| TieringError::ClickHouse(e.to_string()))?;

        let mut hot = TierInfo {
            size_bytes: 0,
            size_pretty: "0 bytes".to_string(),
            row_count: 0,
        };

        let mut warm = TierInfo {
            size_bytes: 0,
            size_pretty: "0 bytes".to_string(),
            row_count: 0,
        };

        for stat in stats {
            if stat.disk_name == "default" {
                hot.size_bytes = stat.total_bytes;
                hot.row_count = stat.total_rows;
                hot.size_pretty = format_bytes(stat.total_bytes);
            } else if stat.disk_name == "s3_warm" {
                warm.size_bytes = stat.total_bytes;
                warm.row_count = stat.total_rows;
                warm.size_pretty = format_bytes(stat.total_bytes);
            }
        }

        let total_size_bytes = hot.size_bytes + warm.size_bytes;
        let total_row_count = hot.row_count + warm.row_count;

        Ok(TierStats {
            hot,
            warm,
            total_size_bytes,
            total_size_pretty: format_bytes(total_size_bytes),
            total_row_count,
            last_updated: Utc::now(),
        })
    }
}
