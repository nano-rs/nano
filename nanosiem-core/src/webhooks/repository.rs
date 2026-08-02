// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook Repository
//!
//! Database operations for webhook configurations and delivery logs.
//! Handles encrypted header/secret storage via EncryptionService.

use sqlx::PgPool;
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;

use super::models::*;
use crate::crypto::{CryptoError, EncryptedData, EncryptionService};

#[derive(Error, Debug)]
pub enum WebhookRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Webhook not found: {0}")]
    NotFound(Uuid),
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

#[derive(Clone)]
pub struct WebhookRepository {
    pool: PgPool,
    encryption: EncryptionService,
}

impl WebhookRepository {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            encryption: EncryptionService::from_env(),
        }
    }

    pub fn with_encryption(pool: PgPool, encryption: EncryptionService) -> Self {
        Self { pool, encryption }
    }

    /// The PG pool backing this repository. Lets `WebhookService::new` self-build
    /// a `SourceScopeResolver` so restricted-source redaction is active at every
    /// construction site without per-site wiring (NAN-1800).
    pub fn pool(&self) -> PgPool {
        self.pool.clone()
    }

    // ========================================================================
    // Webhook CRUD
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn list(&self) -> Result<Vec<Webhook>, WebhookRepositoryError> {
        // API read path: builds `WebhookResponse` (url_host + has_url) — it does
        // NOT need the decrypted delivery URL, so no hydrate here (F-39).
        let webhooks = sqlx::query_as::<_, Webhook>(
            r#"
            SELECT id, name, url, url_encrypted, url_host, headers_encrypted, secret_encrypted,
                   severity_filter, event_types, channel_type, channel_config,
                   rule_filter, health_category_filter, health_resource_filter,
                   enabled, created_at, updated_at
            FROM webhooks
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(webhooks)
    }

    #[instrument(skip(self))]
    pub async fn list_enabled(&self) -> Result<Vec<Webhook>, WebhookRepositoryError> {
        let mut webhooks = sqlx::query_as::<_, Webhook>(
            r#"
            SELECT id, name, url, url_encrypted, url_host, headers_encrypted, secret_encrypted,
                   severity_filter, event_types, channel_type, channel_config,
                   rule_filter, health_category_filter, health_resource_filter,
                   enabled, created_at, updated_at
            FROM webhooks
            WHERE enabled = true
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        // F-39: delivery read path — hydrate `Webhook.url` from `url_encrypted`
        // (lazy-encrypting any legacy plaintext row) so `service.rs` delivery is
        // unchanged and never depends on the plaintext column.
        for webhook in webhooks.iter_mut() {
            self.hydrate_delivery_url(webhook).await;
        }

        Ok(webhooks)
    }

    #[instrument(skip(self))]
    pub async fn get(&self, id: Uuid) -> Result<Webhook, WebhookRepositoryError> {
        let mut webhook = sqlx::query_as::<_, Webhook>(
            r#"
            SELECT id, name, url, url_encrypted, url_host, headers_encrypted, secret_encrypted,
                   severity_filter, event_types, channel_type, channel_config,
                   rule_filter, health_category_filter, health_resource_filter,
                   enabled, created_at, updated_at
            FROM webhooks
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(WebhookRepositoryError::NotFound(id))?;

        // F-39: `get` backs the single-webhook delivery path (`send_test`), so
        // hydrate the delivery URL here too. Harmless for the API read path,
        // which only reads url_host/has_url off the same struct.
        self.hydrate_delivery_url(&mut webhook).await;
        Ok(webhook)
    }

    #[instrument(skip(self, request))]
    pub async fn create(
        &self,
        request: &CreateWebhookRequest,
    ) -> Result<Webhook, WebhookRepositoryError> {
        let headers_encrypted = if let Some(ref headers) = request.headers {
            if !headers.is_empty() {
                Some(self.encrypt_json(headers)?)
            } else {
                None
            }
        } else {
            None
        };

        let secret_encrypted = if let Some(ref secret) = request.secret {
            if !secret.is_empty() {
                Some(self.encrypt_string(secret)?)
            } else {
                None
            }
        } else {
            None
        };

        let enabled = request.enabled.unwrap_or(true);
        // Omitted subscription set falls back to the shared default so the Rust
        // and SQL defaults stay in lockstep (migration 217).
        let event_types = request
            .event_types
            .clone()
            .unwrap_or_else(default_event_types);

        // Channel type / config / rule filter (NAN-1790). Omitted → generic / {}.
        let channel_type = request
            .channel_type
            .clone()
            .unwrap_or_else(|| "generic".to_string());
        let channel_config = request
            .channel_config
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let rule_filter = request
            .decoded_rule_filter()
            .map_err(WebhookRepositoryError::SerializationError)?;

        // F-39: store the URL encrypted (bearer credential for Slack/Teams) plus
        // a non-secret host label. The plaintext `url` column is still written as
        // a transitional rollback seam (it is NOT NULL, and an older binary reads
        // it); the API never returns it.
        let url_encrypted = self.encrypt_string(&request.url)?;
        let url_host_label = url_host(&request.url);

        let webhook = sqlx::query_as::<_, Webhook>(
            r#"
            INSERT INTO webhooks (name, url, url_encrypted, url_host, headers_encrypted, secret_encrypted, severity_filter, event_types, channel_type, channel_config, rule_filter, health_category_filter, health_resource_filter, enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id, name, url, url_encrypted, url_host, headers_encrypted, secret_encrypted,
                      severity_filter, event_types, channel_type, channel_config,
                      rule_filter, health_category_filter, health_resource_filter,
                      enabled, created_at, updated_at
            "#
        )
        .bind(&request.name)
        .bind(&request.url)
        .bind(url_encrypted.as_slice())
        .bind(url_host_label.as_deref())
        .bind(headers_encrypted.as_deref())
        .bind(secret_encrypted.as_deref())
        .bind(&request.severity_filter)
        .bind(&event_types)
        .bind(&channel_type)
        .bind(&channel_config)
        .bind(rule_filter.as_deref())
        .bind(&request.health_category_filter)
        .bind(&request.health_resource_filter)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await?;

        Ok(webhook)
    }

    #[instrument(skip(self, request))]
    pub async fn update(
        &self,
        id: Uuid,
        request: &UpdateWebhookRequest,
    ) -> Result<Webhook, WebhookRepositoryError> {
        // Handle headers encryption
        let headers_encrypted: Option<Option<Vec<u8>>> = if let Some(ref headers) = request.headers
        {
            if headers.is_empty() {
                Some(None) // Clear headers
            } else {
                Some(Some(self.encrypt_json(headers)?))
            }
        } else {
            None // Don't update
        };

        // Handle secret encryption
        let secret_encrypted: Option<Option<Vec<u8>>> = if let Some(ref secret) = request.secret {
            if secret.is_empty() {
                Some(None) // Clear secret
            } else {
                Some(Some(self.encrypt_string(secret)?))
            }
        } else {
            None // Don't update
        };

        // Rule filter (NAN-1790): None = no change; Some([]) = clear to NULL;
        // Some([ids]) = replace. Modeled with a should-update flag like secrets.
        let rule_filter_decoded = request
            .decoded_rule_filter()
            .map_err(WebhookRepositoryError::SerializationError)?;
        let rule_filter_should_update = rule_filter_decoded.is_some();
        let rule_filter_value: Option<Vec<Uuid>> = match rule_filter_decoded {
            Some(v) if v.is_empty() => None, // explicit clear
            other => other,
        };

        // F-39: when the caller supplies a new URL, re-encrypt it and refresh the
        // display host together; otherwise leave both encrypted-URL columns
        // untouched. Modeled with a should-update flag like secrets/headers.
        // (`request.url` = None still means "keep" — the COALESCE on the legacy
        // plaintext column, and this CASE, both no-op.)
        let (url_should_update, url_encrypted_value, url_host_value): (
            bool,
            Option<Vec<u8>>,
            Option<String>,
        ) = match request.url.as_deref() {
            Some(u) => (true, Some(self.encrypt_string(u)?), url_host(u)),
            None => (false, None, None),
        };

        // Build dynamic update - use raw SQL to handle optional fields
        let webhook = sqlx::query_as::<_, Webhook>(
            r#"
            UPDATE webhooks SET
                name = COALESCE($2, name),
                url = COALESCE($3, url),
                headers_encrypted = CASE WHEN $4 THEN $5 ELSE headers_encrypted END,
                secret_encrypted = CASE WHEN $6 THEN $7 ELSE secret_encrypted END,
                severity_filter = COALESCE($8, severity_filter),
                enabled = COALESCE($9, enabled),
                event_types = COALESCE($10, event_types),
                -- Explicit casts: these params appear only inside COALESCE/CASE,
                -- so pin their types rather than leaning on PG inference.
                channel_type = COALESCE($11::text, channel_type),
                channel_config = COALESCE($12::jsonb, channel_config),
                rule_filter = CASE WHEN $13 THEN $14::uuid[] ELSE rule_filter END,
                -- F-39: encrypted URL + display host move together with the URL.
                url_encrypted = CASE WHEN $15 THEN $16::bytea ELSE url_encrypted END,
                url_host = CASE WHEN $15 THEN $17::text ELSE url_host END,
                health_category_filter = COALESCE($18::text[], health_category_filter),
                health_resource_filter = COALESCE($19::text[], health_resource_filter),
                updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, url, url_encrypted, url_host, headers_encrypted, secret_encrypted,
                      severity_filter, event_types, channel_type, channel_config,
                      rule_filter, health_category_filter, health_resource_filter,
                      enabled, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&request.name)
        .bind(&request.url)
        .bind(headers_encrypted.is_some()) // $4: should update headers?
        .bind(headers_encrypted.as_ref().and_then(|h| h.as_deref())) // $5: new headers value
        .bind(secret_encrypted.is_some()) // $6: should update secret?
        .bind(secret_encrypted.as_ref().and_then(|s| s.as_deref())) // $7: new secret value
        .bind(&request.severity_filter)
        .bind(request.enabled)
        .bind(&request.event_types) // $10: replace subscription set (None = no change)
        .bind(&request.channel_type) // $11: channel type (None = no change)
        .bind(&request.channel_config) // $12: provider config (None = no change)
        .bind(rule_filter_should_update) // $13: should update rule filter?
        .bind(rule_filter_value.as_deref()) // $14: new rule filter (NULL = clear)
        .bind(url_should_update) // $15: should update the URL columns?
        .bind(url_encrypted_value.as_deref()) // $16: new encrypted URL
        .bind(url_host_value) // $17: new display host
        .bind(&request.health_category_filter) // $18: health category routing
        .bind(&request.health_resource_filter) // $19: health resource routing
        .fetch_optional(&self.pool)
        .await?
        .ok_or(WebhookRepositoryError::NotFound(id))?;

        Ok(webhook)
    }

    #[instrument(skip(self))]
    pub async fn delete(&self, id: Uuid) -> Result<(), WebhookRepositoryError> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(WebhookRepositoryError::NotFound(id));
        }

        Ok(())
    }

    // ========================================================================
    // Notification settings (deep-link base URL) — NAN-1790
    // ========================================================================

    /// The admin-configured external base URL used to build notification deep
    /// links, or `None` when unset (callers then fall back to the
    /// `NANOSIEM_HOSTNAME` env var). Blank values are normalized to `None`.
    #[instrument(skip(self))]
    pub async fn notification_base_url(&self) -> Result<Option<String>, WebhookRepositoryError> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT notification_base_url FROM system_settings WHERE id = 'default'")
                .fetch_optional(&self.pool)
                .await?;
        Ok(row
            .and_then(|(v,)| v)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()))
    }

    /// Set (or clear, with `None`/blank) the notification deep-link base URL.
    #[instrument(skip(self))]
    pub async fn set_notification_base_url(
        &self,
        base_url: Option<&str>,
    ) -> Result<(), WebhookRepositoryError> {
        let normalized = base_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('/').to_string());
        sqlx::query(
            "UPDATE system_settings SET notification_base_url = $1, updated_at = NOW() WHERE id = 'default'",
        )
        .bind(normalized)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ========================================================================
    // Encryption helpers
    // ========================================================================

    fn encrypt_json<T: serde::Serialize>(
        &self,
        value: &T,
    ) -> Result<Vec<u8>, WebhookRepositoryError> {
        let json_bytes = serde_json::to_vec(value)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))?;
        let encrypted = self.encryption.encrypt(&json_bytes)?;
        let storage = serde_json::json!({
            "ciphertext": encrypted.ciphertext,
            "nonce": encrypted.nonce
        });
        serde_json::to_vec(&storage)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))
    }

    /// Encrypt a string into the `{ciphertext, nonce}` envelope stored in the
    /// `*_encrypted` BYTEA columns. `pub(crate)` (mirroring the public
    /// `decrypt_string`) so the encrypt→decrypt round-trip is unit-testable.
    pub(crate) fn encrypt_string(&self, value: &str) -> Result<Vec<u8>, WebhookRepositoryError> {
        let encrypted = self.encryption.encrypt(value.as_bytes())?;
        let storage = serde_json::json!({
            "ciphertext": encrypted.ciphertext,
            "nonce": encrypted.nonce
        });
        serde_json::to_vec(&storage)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))
    }

    /// F-39: populate a loaded webhook's internal delivery `url` from the
    /// encrypted column, lazy-encrypting legacy plaintext rows on read.
    ///
    /// - `url_encrypted` present → decrypt into `Webhook.url` (authoritative
    ///   delivery URL). A decrypt failure is logged and leaves the plaintext
    ///   fallback in place rather than sending to a wrong/empty target.
    /// - `url_encrypted` NULL but plaintext `url` present (a pre-migration-254
    ///   row) → encrypt-and-persist it so the next read uses the encrypted
    ///   column, and keep using the plaintext meanwhile.
    ///
    /// Called only on the delivery read paths (`list_enabled` / `get`), never on
    /// the API `list` path (which needs only `url_host` / `has_url`).
    async fn hydrate_delivery_url(&self, webhook: &mut Webhook) {
        // Prefer the encrypted column (authoritative delivery URL). Clone the
        // small envelope first so the immutable borrow is released before we
        // mutate `webhook.url`.
        if let Some(enc) = webhook.url_encrypted.clone().filter(|e| !e.is_empty()) {
            match self.decrypt_string(&enc) {
                Ok(url) => webhook.url = url,
                Err(e) => tracing::error!(
                    webhook_id = %webhook.id,
                    "F-39: url_encrypted could not be decrypted, falling back to stored plaintext: {e}"
                ),
            }
            return;
        }

        // Legacy plaintext row (pre-254): lazy-migrate to the encrypted column
        // and keep using the plaintext meanwhile.
        if webhook.url.is_empty() {
            return;
        }
        match self.encrypt_string(&webhook.url) {
            Ok(enc) => {
                let host = url_host(&webhook.url);
                if let Err(e) = self
                    .persist_lazy_url_encryption(webhook.id, &enc, host.as_deref())
                    .await
                {
                    tracing::warn!(
                        webhook_id = %webhook.id,
                        "F-39: lazy URL encryption persist failed: {e}"
                    );
                }
                webhook.url_encrypted = Some(enc);
                if webhook.url_host.is_none() {
                    webhook.url_host = host;
                }
            }
            Err(e) => tracing::warn!(
                webhook_id = %webhook.id,
                "F-39: lazy URL encryption failed: {e}"
            ),
        }
    }

    /// F-39: persist a lazily-encrypted URL for a legacy plaintext row. Guarded
    /// by `url_encrypted IS NULL` so a concurrent hydrate can't clobber an
    /// already-migrated value; idempotent (same plaintext → valid ciphertext).
    async fn persist_lazy_url_encryption(
        &self,
        id: Uuid,
        url_encrypted: &[u8],
        url_host: Option<&str>,
    ) -> Result<(), WebhookRepositoryError> {
        sqlx::query(
            "UPDATE webhooks SET url_encrypted = $2, url_host = $3 \
             WHERE id = $1 AND url_encrypted IS NULL",
        )
        .bind(id)
        .bind(url_encrypted)
        .bind(url_host)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<T, WebhookRepositoryError> {
        let json: serde_json::Value = serde_json::from_slice(encrypted_bytes)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))?;
        let encrypted = EncryptedData {
            ciphertext: json["ciphertext"]
                .as_str()
                .ok_or_else(|| {
                    WebhookRepositoryError::SerializationError("Missing ciphertext".to_string())
                })?
                .to_string(),
            nonce: json["nonce"]
                .as_str()
                .ok_or_else(|| {
                    WebhookRepositoryError::SerializationError("Missing nonce".to_string())
                })?
                .to_string(),
        };
        let decrypted = self.encryption.decrypt(&encrypted)?;
        serde_json::from_slice(&decrypted)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))
    }

    pub fn decrypt_string(&self, encrypted_bytes: &[u8]) -> Result<String, WebhookRepositoryError> {
        let json: serde_json::Value = serde_json::from_slice(encrypted_bytes)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))?;
        let encrypted = EncryptedData {
            ciphertext: json["ciphertext"]
                .as_str()
                .ok_or_else(|| {
                    WebhookRepositoryError::SerializationError("Missing ciphertext".to_string())
                })?
                .to_string(),
            nonce: json["nonce"]
                .as_str()
                .ok_or_else(|| {
                    WebhookRepositoryError::SerializationError("Missing nonce".to_string())
                })?
                .to_string(),
        };
        let decrypted = self.encryption.decrypt(&encrypted)?;
        String::from_utf8(decrypted)
            .map_err(|e| WebhookRepositoryError::SerializationError(e.to_string()))
    }

    // ========================================================================
    // Delivery Log
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn log_delivery(
        &self,
        webhook_id: Uuid,
        alert_id: Option<Uuid>,
        event_type: &str,
        status_code: Option<i32>,
        response_body: Option<&str>,
        success: bool,
        error_message: Option<&str>,
        duration_ms: Option<i32>,
    ) -> Result<WebhookDeliveryLog, WebhookRepositoryError> {
        // Truncate response body to 1KB
        let truncated_body = response_body.map(|b| {
            if b.len() > 1024 {
                format!("{}...(truncated)", &b[..1024])
            } else {
                b.to_string()
            }
        });

        let log = sqlx::query_as::<_, WebhookDeliveryLog>(
            r#"
            INSERT INTO webhook_delivery_log
                (webhook_id, alert_id, event_type, status_code, response_body, success, error_message, duration_ms)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, webhook_id, alert_id, event_type, status_code, response_body,
                      success, error_message, duration_ms, delivered_at
            "#
        )
        .bind(webhook_id)
        .bind(alert_id)
        .bind(event_type)
        .bind(status_code)
        .bind(truncated_body.as_deref())
        .bind(success)
        .bind(error_message)
        .bind(duration_ms)
        .fetch_one(&self.pool)
        .await?;

        Ok(log)
    }

    #[instrument(skip(self))]
    pub async fn list_deliveries(
        &self,
        webhook_id: Uuid,
        limit: i64,
    ) -> Result<Vec<WebhookDeliveryLog>, WebhookRepositoryError> {
        let logs = sqlx::query_as::<_, WebhookDeliveryLog>(
            r#"
            SELECT id, webhook_id, alert_id, event_type, status_code, response_body,
                   success, error_message, duration_ms, delivered_at
            FROM webhook_delivery_log
            WHERE webhook_id = $1
            ORDER BY delivered_at DESC
            LIMIT $2
            "#,
        )
        .bind(webhook_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }
}
