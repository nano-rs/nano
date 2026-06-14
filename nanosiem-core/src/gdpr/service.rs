// SPDX-License-Identifier: AGPL-3.0-or-later

//! GDPR Anonymization Service
//!
//! Executes PII anonymization across ClickHouse and PostgreSQL tables.
//! Uses SHA256(salt || lower(value)) for deterministic, irreversible hashing.
//! This matches ClickHouse's `lower(hex(SHA256(concat(salt, lower(value))))` and
//! PostgreSQL's `encode(digest(salt || lower(value), 'sha256'), 'hex')`.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

use super::{
    AnonymizationError, AnonymizationPreview, AnonymizationRequest, AnonymizationStatus,
    IdentifierType,
};
use std::sync::Arc;

use crate::db::dual_pool::TableNames;
use crate::db::DualPool;
use crate::schema::{SchemaId, SchemaProfile};

/// Service for GDPR data subject anonymization
#[derive(Clone)]
pub struct AnonymizationService {
    pool: PgPool,
    dual_pool: DualPool,
    table_names: TableNames,
    /// Active schema profile (NAN-1259). Under OCSF, subject data lives in
    /// `ocsf_logs` and PII is inside the `event` JSON (the promoted columns are
    /// MATERIALIZED, hence not directly updatable) — so erasure rewrites `event`
    /// and the promoted columns re-derive. UDM path is byte-identical.
    profile: Arc<dyn SchemaProfile>,
}

impl AnonymizationService {
    pub fn new(pool: PgPool, dual_pool: DualPool) -> Self {
        let table_names = dual_pool.table_names();
        let profile = crate::schema::active_profile_from_env()
            .unwrap_or_else(|_| Arc::new(crate::schema::UdmProfile::new()));
        Self {
            pool,
            dual_pool,
            table_names,
            profile,
        }
    }

    /// The active ingested-events table key ("ocsf_logs" under OCSF, else "logs").
    fn logs_key(&self) -> &'static str {
        crate::schema::active_logs_table()
    }

    /// Quote a column for the anonymization SQL: dotted OCSF columns
    /// (`user.name`) get double-quoted (else CH reads them as `table.column`);
    /// the UDM `user` reserved word keeps its backticks; everything else is bare
    /// — so UDM output is byte-identical.
    fn quote_anon_col(col: &str) -> String {
        if col.contains('.') {
            format!("\"{}\"", col.replace('"', "\"\""))
        } else if col == "user" {
            "`user`".to_string()
        } else {
            col.to_string()
        }
    }

    /// Build the salted-hash WHERE match (`... = '<hash>' OR ...`) over a set of
    /// identity columns. Mirrors the per-column check used in the UDM mutations.
    fn build_hash_match_where(columns: &[&str], salt_escaped: &str, anon_hash: &str) -> String {
        columns
            .iter()
            .map(|col| {
                let q = Self::quote_anon_col(col);
                format!("lower(hex(SHA256(concat('{salt_escaped}', lower({q}))))) = '{anon_hash}'")
            })
            .collect::<Vec<_>>()
            .join(" OR ")
    }

    /// Compute SHA256(salt || lower(value)) — matches ClickHouse and PostgreSQL
    fn salted_hash(value: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(salt.as_bytes());
        hasher.update(value.to_lowercase().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Load the GDPR anonymization salt from system_settings
    async fn load_salt(&self) -> Result<String, AnonymizationError> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            "SELECT gdpr_anonymization_salt FROM system_settings WHERE id = 'default'",
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((Some(salt),)) if !salt.is_empty() => Ok(salt),
            _ => Err(AnonymizationError::SaltNotConfigured),
        }
    }

    /// Get the ClickHouse client for read-only queries (estimates)
    fn clickhouse(&self) -> &clickhouse::Client {
        self.dual_pool.clickhouse()
    }

    /// Get the ClickHouse admin client for DDL operations (ALTER TABLE UPDATE/DELETE)
    fn clickhouse_admin(&self) -> &clickhouse::Client {
        self.dual_pool.clickhouse_admin()
    }

    /// Submit a new anonymization request.
    ///
    /// Computes the HMAC hash of the identifier, estimates affected row counts,
    /// creates a pending job record, and returns a preview. The plaintext
    /// identifier is never persisted.
    pub async fn submit_request(
        &self,
        user_id: Uuid,
        identifier_type: IdentifierType,
        identifier_value: &str,
        justification: Option<&str>,
    ) -> Result<AnonymizationPreview, AnonymizationError> {
        let trimmed = identifier_value.trim();
        if trimmed.is_empty() {
            return Err(AnonymizationError::InvalidIdentifier(
                "Identifier cannot be empty".into(),
            ));
        }
        Self::validate_identifier(identifier_type, trimmed)?;

        let salt = self.load_salt().await?;
        let identifier_hash = Self::salted_hash(trimmed, &salt);
        let ch = self.clickhouse();

        // Estimate affected rows per table
        let logs_affected = self.estimate_logs(ch, identifier_type, trimmed).await?;
        let identity_obs_affected = self
            .estimate_identity_observations(ch, identifier_type, trimmed)
            .await?;
        let cloud_activity_affected = self
            .estimate_cloud_activity(ch, identifier_type, trimmed)
            .await?;
        let user_registry_affected = self
            .estimate_user_registry(identifier_type, trimmed)
            .await?;

        // Insert pending job (plaintext never stored)
        let request_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO gdpr_anonymization_requests
                (identifier_type, identifier_hash, status, logs_affected,
                 identity_observations_affected, cloud_activity_affected,
                 user_registry_affected, justification, requested_by)
            VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7, $8)
            RETURNING id
            "#,
        )
        .bind(identifier_type.to_string())
        .bind(&identifier_hash)
        .bind(logs_affected)
        .bind(identity_obs_affected)
        .bind(cloud_activity_affected)
        .bind(user_registry_affected)
        .bind(justification)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        info!(
            request_id = %request_id.0,
            identifier_type = %identifier_type,
            logs_affected,
            "GDPR anonymization request submitted"
        );

        Ok(AnonymizationPreview {
            request_id: request_id.0,
            identifier_type,
            status: AnonymizationStatus::Pending,
            estimated_logs: logs_affected,
            estimated_identity_observations: identity_obs_affected,
            estimated_cloud_activity: cloud_activity_affected,
            estimated_user_registry: user_registry_affected,
            limitations: vec![
                "Process GUIDs are derived from host+pid, not user data — unaffected".into(),
            ],
        })
    }

    /// Execute a pending anonymization request.
    ///
    /// Runs ClickHouse ALTER TABLE UPDATE mutations and PostgreSQL updates.
    /// Uses an atomic UPDATE ... WHERE status = 'pending' to prevent double-execution.
    pub async fn execute_request(
        &self,
        request_id: Uuid,
    ) -> Result<AnonymizationRequest, AnonymizationError> {
        let ch = self.clickhouse_admin();
        let salt = self.load_salt().await?;

        // Atomically claim the request — only one caller can transition pending → running
        let claimed: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE gdpr_anonymization_requests \
             SET status = 'running', started_at = NOW() \
             WHERE id = $1 AND status = 'pending' \
             RETURNING id",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;

        if claimed.is_none() {
            // Either not found or not pending — check which
            let _exists = self.get_request(request_id).await?;
            return Err(AnonymizationError::NotPending);
        }

        let request = self.get_request(request_id).await?;

        let anon_value = &request.identifier_hash;
        let mut mutation_ids: Vec<String> = Vec::new();

        // Execute mutations based on identifier type
        let result = match request.identifier_type {
            IdentifierType::Username | IdentifierType::Email => {
                self.anonymize_user_fields(ch, &salt, anon_value, &mut mutation_ids)
                    .await
            }
            IdentifierType::Ip => {
                self.anonymize_ip_fields(ch, &salt, anon_value, &mut mutation_ids)
                    .await
            }
        };

        // Also anonymize the user_registry directory feed if applicable
        // (NAN-1117: moved PG -> ClickHouse).
        if result.is_ok() {
            if let Err(e) = self
                .anonymize_user_registry(ch, &salt, &request, &mut mutation_ids)
                .await
            {
                warn!(error = %e, "Failed to anonymize user_registry (non-fatal)");
            }
        }

        match result {
            Ok(()) => {
                sqlx::query(
                    r#"
                    UPDATE gdpr_anonymization_requests
                    SET status = 'completed', completed_at = NOW(), mutation_ids = $2
                    WHERE id = $1
                    "#,
                )
                .bind(request_id)
                .bind(serde_json::json!(mutation_ids))
                .execute(&self.pool)
                .await?;

                info!(request_id = %request_id, mutations = ?mutation_ids, "GDPR anonymization completed");
                self.get_request(request_id).await
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!(request_id = %request_id, error = %err_msg, "GDPR anonymization failed");

                sqlx::query(
                    r#"
                    UPDATE gdpr_anonymization_requests
                    SET status = 'failed', error_message = $2, mutation_ids = $3
                    WHERE id = $1
                    "#,
                )
                .bind(request_id)
                .bind(&err_msg)
                .bind(serde_json::json!(mutation_ids))
                .execute(&self.pool)
                .await?;

                Err(e)
            }
        }
    }

    /// Get a single anonymization request by ID
    pub async fn get_request(&self, id: Uuid) -> Result<AnonymizationRequest, AnonymizationError> {
        let row = sqlx::query_as::<_, AnonymizationRow>(
            r#"
            SELECT id, identifier_type, identifier_hash, status,
                   logs_affected, identity_observations_affected,
                   cloud_activity_affected, user_registry_affected,
                   mutation_ids, justification, error_message,
                   requested_by, created_at, started_at, completed_at
            FROM gdpr_anonymization_requests
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AnonymizationError::NotFound(id))?;

        Ok(row.into())
    }

    /// List anonymization requests with pagination
    pub async fn list_requests(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AnonymizationRequest>, i64), AnonymizationError> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM gdpr_anonymization_requests")
            .fetch_one(&self.pool)
            .await?;

        let rows = sqlx::query_as::<_, AnonymizationRow>(
            r#"
            SELECT id, identifier_type, identifier_hash, status,
                   logs_affected, identity_observations_affected,
                   cloud_activity_affected, user_registry_affected,
                   mutation_ids, justification, error_message,
                   requested_by, created_at, started_at, completed_at
            FROM gdpr_anonymization_requests
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        Ok((rows.into_iter().map(Into::into).collect(), total.0))
    }

    // =========================================================================
    // Input validation
    // =========================================================================

    /// Validate identifier value to prevent SQL injection in ClickHouse queries.
    /// Since estimation queries use string interpolation (ClickHouse client
    /// limitations), we enforce strict character whitelists per identifier type.
    fn validate_identifier(id_type: IdentifierType, value: &str) -> Result<(), AnonymizationError> {
        let valid = match id_type {
            IdentifierType::Ip => {
                // IPv4 or IPv6 characters only
                value
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':')
            }
            IdentifierType::Email => {
                // Standard email characters — no quotes, semicolons, or backslashes
                value.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(
                            c,
                            '@' | '.'
                                | '+'
                                | '-'
                                | '_'
                                | '!'
                                | '#'
                                | '$'
                                | '%'
                                | '&'
                                | '*'
                                | '/'
                                | '='
                                | '?'
                                | '^'
                                | '{'
                                | '}'
                                | '|'
                                | '~'
                        )
                })
            }
            IdentifierType::Username => {
                // Alphanumeric + common username characters — no quotes or SQL metacharacters
                value.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | '+' | ' ')
                })
            }
        };

        if !valid {
            return Err(AnonymizationError::InvalidIdentifier(format!(
                "Identifier contains invalid characters for type {}",
                id_type
            )));
        }
        Ok(())
    }

    /// Escape a value for safe interpolation in a ClickHouse single-quoted string.
    /// Escapes backslashes and single quotes.
    fn escape_ch_string(value: &str) -> String {
        value.replace('\\', "\\\\").replace('\'', "\\'")
    }

    // =========================================================================
    // Row count estimation helpers
    // =========================================================================

    async fn estimate_logs(
        &self,
        ch: &clickhouse::Client,
        id_type: IdentifierType,
        value: &str,
    ) -> Result<i64, AnonymizationError> {
        let escaped = Self::escape_ch_string(&value.to_lowercase());
        // NAN-1259: read the active ingested-events table; under OCSF match the
        // subject on the OCSF identity columns (dotted, double-quoted).
        let logs_table = self.table_names.read(self.logs_key());
        let sql = if self.profile.id() == SchemaId::Ocsf {
            match id_type {
                IdentifierType::Username | IdentifierType::Email => format!(
                    "SELECT count() FROM {logs_table} WHERE \
                     lower(\"user.name\") = '{escaped}' OR lower(\"actor.user.name\") = '{escaped}'"
                ),
                IdentifierType::Ip => format!(
                    "SELECT count() FROM {logs_table} WHERE \
                     \"src_endpoint.ip\" = '{escaped}' OR \"dst_endpoint.ip\" = '{escaped}'"
                ),
            }
        } else {
            match id_type {
                IdentifierType::Username | IdentifierType::Email => format!(
                    "SELECT count() FROM {logs_table} WHERE \
                     lower(user) = '{escaped}' OR lower(src_user) = '{escaped}' OR lower(dest_user) = '{escaped}' \
                     OR lower(user_id) = '{escaped}' OR lower(user_name) = '{escaped}' \
                     OR lower(sender) = '{escaped}' OR lower(recipient) = '{escaped}'"
                ),
                IdentifierType::Ip => format!(
                    "SELECT count() FROM {logs_table} WHERE \
                     src_ip = '{escaped}' OR dest_ip = '{escaped}' OR dvc_ip = '{escaped}'"
                ),
            }
        };

        self.ch_count(ch, &sql).await
    }

    async fn estimate_identity_observations(
        &self,
        ch: &clickhouse::Client,
        id_type: IdentifierType,
        value: &str,
    ) -> Result<i64, AnonymizationError> {
        let escaped = Self::escape_ch_string(&value.to_lowercase());
        let identity_obs_table = self.table_names.read("identity_observations");
        let sql = match id_type {
            IdentifierType::Username | IdentifierType::Email => {
                format!("SELECT count() FROM {identity_obs_table} WHERE lower(user) = '{escaped}'")
            }
            IdentifierType::Ip => {
                format!("SELECT count() FROM {identity_obs_table} WHERE ip = '{escaped}'")
            }
        };

        self.ch_count(ch, &sql).await
    }

    async fn estimate_cloud_activity(
        &self,
        ch: &clickhouse::Client,
        id_type: IdentifierType,
        value: &str,
    ) -> Result<i64, AnonymizationError> {
        if matches!(id_type, IdentifierType::Ip) {
            return Ok(0); // cloud_user_activity_agg only has user field
        }
        let escaped = Self::escape_ch_string(&value.to_lowercase());
        let cloud_table = self.table_names.read("cloud_user_activity_agg");
        let sql = format!("SELECT count() FROM {cloud_table} WHERE lower(user) = '{escaped}'");
        self.ch_count(ch, &sql).await
    }

    async fn estimate_user_registry(
        &self,
        id_type: IdentifierType,
        value: &str,
    ) -> Result<i64, AnonymizationError> {
        // NAN-1117: user_registry payload moved PG -> ClickHouse. Count over the
        // deduped (FINAL) set using the materialized lowercase lookup columns.
        let ch = self.clickhouse();
        let escaped = Self::escape_ch_string(&value.to_lowercase());
        let sql = match id_type {
            IdentifierType::Username => format!(
                "SELECT count() FROM nanosiem.user_registry FINAL \
                 WHERE username_lc = '{escaped}' OR upn_lc = '{escaped}'"
            ),
            IdentifierType::Email => format!(
                "SELECT count() FROM nanosiem.user_registry FINAL WHERE email_lc = '{escaped}'"
            ),
            IdentifierType::Ip => {
                // user_registry doesn't contain IP addresses
                return Ok(0);
            }
        };
        self.ch_count(ch, &sql).await
    }

    async fn ch_count(
        &self,
        ch: &clickhouse::Client,
        sql: &str,
    ) -> Result<i64, AnonymizationError> {
        let row = ch
            .query(sql)
            .fetch_one::<CountRow>()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        Ok(row.count as i64)
    }

    // =========================================================================
    // Mutation execution
    // =========================================================================

    /// Build a SQL expression that replaces PII in a free-text field (`message` or `ext`).
    ///
    /// Uses `multiIf` to find which source column matches the salted hash, then
    /// `replaceRegexpAll` with `(?i)` for case-insensitive replacement. An outer
    /// `if` guard prevents empty-pattern regex (which would be destructive).
    ///
    /// For `ext` (JSON column), wraps the input in `toString(ext)` — ClickHouse
    /// casts the resulting String back to JSON on assignment.
    fn build_freetext_replace(
        target_field: &str,
        columns: &[&str],
        salt_escaped: &str,
        anon_hash: &str,
    ) -> String {
        // The read expression: toString(...) for the JSON columns (`ext` under
        // UDM, `event` under OCSF — CH casts the String result back to JSON on
        // assignment), plain field name otherwise.
        let read_expr = if target_field == "ext" || target_field == "event" {
            format!("toString({target_field})")
        } else {
            format!("`{target_field}`")
        };

        // Build the multiIf arms: each column checks if its hash matches, returns 1
        let mut match_arms = String::new();
        for col in columns {
            let quoted = Self::quote_anon_col(col);
            let arm = format!(
                "{quoted} != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower({quoted}))))) = '{anon_hash}', 1, "
            );
            match_arms.push_str(&arm);
        }

        // multiIf that returns 1 if any column matches, 0 otherwise
        let match_check = format!("multiIf({match_arms}0)");

        // multiIf that returns the original plaintext value from the matching column
        let mut value_arms = String::new();
        for col in columns {
            let quoted = Self::quote_anon_col(col);
            let arm = format!(
                "{quoted} != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower({quoted}))))) = '{anon_hash}', {quoted}, "
            );
            value_arms.push_str(&arm);
        }
        let value_expr = format!("multiIf({value_arms}'')");

        // Escape regex metacharacters in the plaintext value (dots for IPs/emails, plus for email+addressing)
        let escaped_value =
            format!("replaceAll(replaceAll({value_expr}, '.', '\\\\.'), '+', '\\\\+')");

        // Full expression: guarded replaceRegexpAll
        format!(
            "{target_field} = if(\
                {match_check} = 1, \
                replaceRegexpAll(\
                    {read_expr}, \
                    concat(char(40, 63, 105, 41), {escaped_value}), \
                    '{anon_hash}'\
                ), \
                {read_expr}\
            )"
        )
    }

    /// Anonymize user-related fields in ClickHouse logs table
    async fn anonymize_user_fields(
        &self,
        ch: &clickhouse::Client,
        salt: &str,
        anon_hash: &str,
        mutation_ids: &mut Vec<String>,
    ) -> Result<(), AnonymizationError> {
        // At execute time we only have the salted hash (plaintext was discarded).
        // ClickHouse computes lower(hex(SHA256(concat(salt, lower(column)))) per row to
        // find matches — same function as Rust's salted_hash().
        let mutation_id = format!("gdpr_user_{}", Uuid::now_v7().simple());
        let salt_escaped = salt.replace('\'', "\\'");
        let user_columns: &[&str] = &[
            "user",
            "src_user",
            "dest_user",
            "user_id",
            "user_name",
            "sender",
            "recipient",
        ];
        let sql = if self.profile.id() == SchemaId::Ocsf {
            // OCSF (NAN-1443): the full `event` column is EPHEMERAL (never
            // stored) and every PII-bearing column (`message`, `unmapped`, the
            // promoted identity columns) is MATERIALIZED from it — so there is no
            // stored `event` to rewrite, and a mutation cannot recompute the
            // derived columns. Erasure therefore DELETEs the subject's rows: the
            // strongest GDPR right-to-erasure outcome, and the same approach the
            // `cloud_user_activity_agg` rollup below already uses. Match the
            // subject on the OCSF user identity columns.
            let ocsf_user_cols: &[&str] = &["user.name", "actor.user.name"];
            let where_match =
                Self::build_hash_match_where(ocsf_user_cols, &salt_escaped, anon_hash);
            let ocsf_local = self.table_names.local(self.logs_key());
            format!(
                "ALTER TABLE {ocsf_local} DELETE WHERE {where_match} SETTINGS mutations_sync = 0"
            )
        } else {
            let message_expr =
                Self::build_freetext_replace("message", user_columns, &salt_escaped, anon_hash);
            let ext_expr =
                Self::build_freetext_replace("ext", user_columns, &salt_escaped, anon_hash);
            let logs_local = self.table_names.local("logs");
            format!(
            "ALTER TABLE {logs_local} \
             UPDATE \
                `user` = if(`user` != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(`user`))))) = '{anon_hash}', '{anon_hash}', `user`), \
                src_user = if(src_user != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(src_user))))) = '{anon_hash}', '{anon_hash}', src_user), \
                dest_user = if(dest_user != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(dest_user))))) = '{anon_hash}', '{anon_hash}', dest_user), \
                user_id = if(user_id != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(user_id))))) = '{anon_hash}', '{anon_hash}', user_id), \
                user_name = if(user_name != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(user_name))))) = '{anon_hash}', '{anon_hash}', user_name), \
                sender = if(sender != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(sender))))) = '{anon_hash}', '{anon_hash}', sender), \
                recipient = if(recipient != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(recipient))))) = '{anon_hash}', '{anon_hash}', recipient), \
                user_identity_department = '', \
                user_identity_title = '', \
                user_identity_groups = '', \
                user_identity_account_status = '', \
                user_identity_employee_type = '', \
                user_identity_mfa_enabled = 0, \
                user_identity_country = '', \
                user_identity_display_name = '', \
                src_user_identity_department = '', \
                src_user_identity_title = '', \
                src_user_identity_groups = '', \
                src_user_identity_account_status = '', \
                src_user_identity_employee_type = '', \
                src_user_identity_mfa_enabled = 0, \
                src_user_identity_country = '', \
                src_user_identity_display_name = '', \
                dest_user_identity_department = '', \
                dest_user_identity_title = '', \
                dest_user_identity_groups = '', \
                dest_user_identity_account_status = '', \
                dest_user_identity_employee_type = '', \
                dest_user_identity_mfa_enabled = 0, \
                dest_user_identity_country = '', \
                dest_user_identity_display_name = '', \
                {message_expr}, \
                {ext_expr} \
             WHERE lower(hex(SHA256(concat('{salt_escaped}', lower(`user`))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(src_user))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(dest_user))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(user_id))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(user_name))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(sender))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(recipient))))) = '{anon_hash}' \
             SETTINGS mutations_sync = 0",
            )
        };

        ch.query(&sql)
            .execute()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        mutation_ids.push(mutation_id.clone());

        // identity_observations — UPDATE user field
        let obs_mutation_id = format!("gdpr_obs_user_{}", Uuid::now_v7().simple());
        let identity_obs_local = self.table_names.local("identity_observations");
        let obs_sql = format!(
            "ALTER TABLE {identity_obs_local} \
             UPDATE `user` = '{anon_hash}' \
             WHERE lower(hex(SHA256(concat('{salt_escaped}', lower(`user`))))) = '{anon_hash}' \
             SETTINGS mutations_sync = 0",
        );
        ch.query(&obs_sql)
            .execute()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        mutation_ids.push(obs_mutation_id);

        // cloud_user_activity_agg — DELETE (can't UPDATE sorting key columns)
        let cloud_mutation_id = format!("gdpr_cloud_user_{}", Uuid::now_v7().simple());
        let cloud_local = self.table_names.local("cloud_user_activity_agg");
        let cloud_sql = format!(
            "ALTER TABLE {cloud_local} \
             DELETE WHERE lower(hex(SHA256(concat('{salt_escaped}', lower(`user`))))) = '{anon_hash}' \
             SETTINGS mutations_sync = 0",
        );
        ch.query(&cloud_sql)
            .execute()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        mutation_ids.push(cloud_mutation_id);

        Ok(())
    }

    /// Anonymize IP-related fields in ClickHouse logs table
    async fn anonymize_ip_fields(
        &self,
        ch: &clickhouse::Client,
        salt: &str,
        anon_hash: &str,
        mutation_ids: &mut Vec<String>,
    ) -> Result<(), AnonymizationError> {
        let mutation_id = format!("gdpr_ip_{}", Uuid::now_v7().simple());
        let salt_escaped = salt.replace('\'', "\\'");
        let ip_columns: &[&str] = &["src_ip", "dest_ip", "dvc_ip"];
        let sql = if self.profile.id() == SchemaId::Ocsf {
            // OCSF (NAN-1443): `event` is EPHEMERAL and the IP columns are
            // MATERIALIZED from it, so there is nothing to rewrite in place —
            // DELETE the subject's rows (see anonymize_user_fields for the full
            // rationale). Match on the OCSF endpoint IP columns.
            let ocsf_ip_cols: &[&str] = &["src_endpoint.ip", "dst_endpoint.ip"];
            let where_match =
                Self::build_hash_match_where(ocsf_ip_cols, &salt_escaped, anon_hash);
            let ocsf_local = self.table_names.local(self.logs_key());
            format!(
                "ALTER TABLE {ocsf_local} DELETE WHERE {where_match} SETTINGS mutations_sync = 0"
            )
        } else {
            let message_expr =
                Self::build_freetext_replace("message", ip_columns, &salt_escaped, anon_hash);
            let ext_expr =
                Self::build_freetext_replace("ext", ip_columns, &salt_escaped, anon_hash);
            let logs_local = self.table_names.local("logs");
            format!(
            "ALTER TABLE {logs_local} \
             UPDATE \
                src_ip = if(src_ip != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '{anon_hash}', src_ip), \
                dest_ip = if(dest_ip != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '{anon_hash}', dest_ip), \
                dvc_ip = if(dvc_ip != '' AND lower(hex(SHA256(concat('{salt_escaped}', lower(dvc_ip))))) = '{anon_hash}', '{anon_hash}', dvc_ip), \
                enriched_src_country = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_country), \
                enriched_src_country_code = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_country_code), \
                enriched_src_continent = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_continent), \
                enriched_src_continent_code = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_continent_code), \
                enriched_src_asn = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_asn), \
                enriched_src_as_name = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_as_name), \
                enriched_src_as_domain = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', enriched_src_as_domain), \
                enriched_dest_country = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_country), \
                enriched_dest_country_code = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_country_code), \
                enriched_dest_continent = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_continent), \
                enriched_dest_continent_code = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_continent_code), \
                enriched_dest_asn = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_asn), \
                enriched_dest_as_name = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_as_name), \
                enriched_dest_as_domain = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', enriched_dest_as_domain), \
                ioc_src_ip_threat_type = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', ioc_src_ip_threat_type), \
                ioc_src_ip_malware = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', '', ioc_src_ip_malware), \
                ioc_src_ip_confidence = if(lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}', toUInt8(0), ioc_src_ip_confidence), \
                ioc_dest_ip_threat_type = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', ioc_dest_ip_threat_type), \
                ioc_dest_ip_malware = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', '', ioc_dest_ip_malware), \
                ioc_dest_ip_confidence = if(lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}', toUInt8(0), ioc_dest_ip_confidence), \
                {message_expr}, \
                {ext_expr} \
             WHERE lower(hex(SHA256(concat('{salt_escaped}', lower(src_ip))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(dest_ip))))) = '{anon_hash}' \
                OR lower(hex(SHA256(concat('{salt_escaped}', lower(dvc_ip))))) = '{anon_hash}' \
             SETTINGS mutations_sync = 0",
            )
        };

        ch.query(&sql)
            .execute()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        mutation_ids.push(mutation_id);

        // identity_observations — UPDATE ip field
        let obs_mutation_id = format!("gdpr_obs_ip_{}", Uuid::now_v7().simple());
        let identity_obs_local = self.table_names.local("identity_observations");
        let obs_sql = format!(
            "ALTER TABLE {identity_obs_local} \
             UPDATE ip = '{anon_hash}' \
             WHERE lower(hex(SHA256(concat('{salt_escaped}', lower(ip))))) = '{anon_hash}' \
             SETTINGS mutations_sync = 0",
        );
        ch.query(&obs_sql)
            .execute()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        mutation_ids.push(obs_mutation_id);

        Ok(())
    }

    /// Anonymize user_registry entries in ClickHouse (NAN-1117: payload moved
    /// PG -> CH ReplacingMergeTree).
    ///
    /// At execute time we only have the salted hash (plaintext discarded). We
    /// reproduce the same salt-hash CH-side — lower(hex(SHA256(concat(salt,
    /// lower(field))))) — exactly as the logs/observations anonymizers do, so
    /// the WHERE matches the right rows. ReplacingMergeTree has no in-place
    /// UPDATE, so this is an `ALTER TABLE ... UPDATE` mutation: rare/low-volume
    /// for GDPR, acceptable per the same approach used for the logs table. The
    /// mutation rewrites every matching part (including any superseded
    /// versions), guaranteeing erasure regardless of merge state.
    async fn anonymize_user_registry(
        &self,
        ch: &clickhouse::Client,
        salt: &str,
        request: &AnonymizationRequest,
        mutation_ids: &mut Vec<String>,
    ) -> Result<(), AnonymizationError> {
        let anon = &request.identifier_hash;
        let salt_escaped = salt.replace('\'', "\\'");

        // Anonymized identifiers are hex SHA256 — safe to splice, but escape
        // defensively to be uniform with the rest of this module.
        let anon_escaped = Self::escape_ch_string(anon);

        let (set_clause, where_clause) = match request.identifier_type {
            IdentifierType::Username => (
                format!(
                    "username = '{anon_escaped}', upn = '{anon_escaped}', \
                     display_name = '{anon_escaped}', first_name = '', last_name = '', \
                     account_status = 'anonymized'"
                ),
                format!(
                    "lower(hex(SHA256(concat('{salt_escaped}', lower(username))))) = '{anon_escaped}' \
                     OR lower(hex(SHA256(concat('{salt_escaped}', lower(upn))))) = '{anon_escaped}'"
                ),
            ),
            IdentifierType::Email => (
                format!(
                    "email = '{anon_escaped}', display_name = '{anon_escaped}', \
                     first_name = '', last_name = '', account_status = 'anonymized'"
                ),
                format!(
                    "lower(hex(SHA256(concat('{salt_escaped}', lower(email))))) = '{anon_escaped}'"
                ),
            ),
            IdentifierType::Ip => return Ok(()),
        };

        let mutation_id = format!("gdpr_user_registry_{}", Uuid::now_v7().simple());
        let sql = format!(
            "ALTER TABLE nanosiem.user_registry UPDATE {set_clause} \
             WHERE {where_clause} SETTINGS mutations_sync = 0"
        );
        ch.query(&sql)
            .execute()
            .await
            .map_err(|e| AnonymizationError::ClickHouse(e.to_string()))?;
        mutation_ids.push(mutation_id);

        Ok(())
    }
}

// =========================================================================
// Internal row types
// =========================================================================

#[derive(Debug, clickhouse::Row, serde::Deserialize)]
struct CountRow {
    #[serde(rename = "count()")]
    count: u64,
}

#[derive(Debug, sqlx::FromRow)]
struct AnonymizationRow {
    id: Uuid,
    identifier_type: String,
    identifier_hash: String,
    status: String,
    logs_affected: i64,
    identity_observations_affected: i64,
    cloud_activity_affected: i64,
    user_registry_affected: i64,
    mutation_ids: serde_json::Value,
    justification: Option<String>,
    error_message: Option<String>,
    requested_by: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<AnonymizationRow> for AnonymizationRequest {
    fn from(row: AnonymizationRow) -> Self {
        Self {
            id: row.id,
            identifier_type: match row.identifier_type.as_str() {
                "username" => IdentifierType::Username,
                "email" => IdentifierType::Email,
                "ip" => IdentifierType::Ip,
                _ => IdentifierType::Username,
            },
            identifier_hash: row.identifier_hash,
            status: match row.status.as_str() {
                "pending" => AnonymizationStatus::Pending,
                "running" => AnonymizationStatus::Running,
                "completed" => AnonymizationStatus::Completed,
                "failed" => AnonymizationStatus::Failed,
                _ => AnonymizationStatus::Pending,
            },
            logs_affected: row.logs_affected,
            identity_observations_affected: row.identity_observations_affected,
            cloud_activity_affected: row.cloud_activity_affected,
            user_registry_affected: row.user_registry_affected,
            mutation_ids: row.mutation_ids,
            justification: row.justification,
            error_message: row.error_message,
            requested_by: row.requested_by,
            created_at: row.created_at,
            started_at: row.started_at,
            completed_at: row.completed_at,
        }
    }
}

/// NAN-1262: regression coverage for the OCSF erasure SQL generation (NAN-1259).
/// The full mutation (event scrub + materialized-column recompute) is validated
/// against live CH by hand; these lock the *generated SQL shape* so the OCSF
/// branch can't silently regress, and assert the UDM branch stays byte-identical.
#[cfg(test)]
mod ocsf_anonymization_tests {
    use super::AnonymizationService as A;

    #[test]
    fn quote_anon_col_dotted_vs_reserved_vs_bare() {
        // dotted OCSF columns are double-quoted (else CH reads `a.b` as table.col)
        assert_eq!(A::quote_anon_col("user.name"), "\"user.name\"");
        assert_eq!(A::quote_anon_col("src_endpoint.ip"), "\"src_endpoint.ip\"");
        // the UDM `user` reserved word keeps its backticks (byte-identical)
        assert_eq!(A::quote_anon_col("user"), "`user`");
        // plain UDM columns stay bare
        assert_eq!(A::quote_anon_col("src_ip"), "src_ip");
    }

    #[test]
    fn hash_match_where_joins_columns_with_salted_hash() {
        let w = A::build_hash_match_where(&["user.name", "actor.user.name"], "SALT", "HASH");
        assert!(w.contains("lower(hex(SHA256(concat('SALT', lower(\"user.name\"))))) = 'HASH'"));
        assert!(w.contains("lower(hex(SHA256(concat('SALT', lower(\"actor.user.name\"))))) = 'HASH'"));
        assert!(w.contains(" OR "));
    }

    #[test]
    fn ocsf_erasure_matches_subject_on_dotted_identity_columns() {
        // NAN-1443: OCSF erasure no longer rewrites the `event` JSON — `event` is
        // EPHEMERAL and every PII column is MATERIALIZED from it, so a mutation
        // can neither rewrite nor re-derive it. Erasure now DELETEs the subject's
        // rows, matched by the dotted OCSF identity columns via
        // `build_hash_match_where`. Lock that match shape here.
        let w = A::build_hash_match_where(&["user.name", "actor.user.name"], "SALT", "HASH");
        assert!(
            w.contains("lower(hex(SHA256(concat('SALT', lower(\"user.name\"))))) = 'HASH'"),
            "must match the dotted OCSF user column: {w}"
        );
        assert!(w.contains("\"actor.user.name\""), "got: {w}");
        // The generic free-text rewrite helper is unchanged and still serves the
        // UDM message/ext path (see `freetext_replace_udm_unchanged`).
        let e = A::build_freetext_replace("message", &["user"], "SALT", "HASH");
        assert!(e.starts_with("message = if("), "got: {e}");
    }

    #[test]
    fn freetext_replace_udm_unchanged() {
        // UDM `ext` path: reads/writes `ext`, backticks the `user` column, never
        // references `event` — byte-identical to pre-OCSF behavior.
        let ext = A::build_freetext_replace("ext", &["user", "src_user"], "SALT", "HASH");
        assert!(ext.starts_with("ext = if("));
        assert!(ext.contains("toString(ext)"));
        assert!(ext.contains("`user`"));
        assert!(!ext.contains("event"));
        // UDM `message` path reads the bare column.
        let msg = A::build_freetext_replace("message", &["user"], "SALT", "HASH");
        assert!(msg.starts_with("message = if("));
        assert!(msg.contains("`message`"));
        assert!(!msg.contains("toString(ext)") && !msg.contains("event"));
    }
}
