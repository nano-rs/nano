// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository for detection-as-code push targets (NAN-1745).
//!
//! The GitHub PAT is stored AES-256-GCM-encrypted as `(BYTEA ciphertext,
//! VARCHAR nonce)`, mirroring the `cloud_credentials` pattern. All read paths
//! project `has_token` rather than the ciphertext, so the secret only ever
//! leaves this layer through the explicit `get_decrypted_token` call used by the
//! GitHub write client.

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::models::{DetectionCodeTarget, NewDetectionCodeTarget, UpdateDetectionCodeTarget};
use crate::crypto::{EncryptedData, EncryptionService};

#[derive(Error, Debug)]
pub enum DetectionCodeTargetError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Push target not found: {0}")]
    NotFound(Uuid),
    #[error("A push target named '{0}' already exists")]
    DuplicateName(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
}

/// Columns projected for the secret-free `DetectionCodeTarget` view. Note the
/// computed `has_token` in place of the raw `token_encrypted`/`token_nonce`.
const DCT_SELECT: &str = "id, name, repo_url, base_branch, path_template, pr_branch_prefix, \
     rule_format, enabled, (token_encrypted IS NOT NULL) AS has_token, last_pr_url, last_pr_at, \
     last_used_at, created_at, updated_at, created_by";

#[derive(Clone)]
pub struct DetectionCodeTargetRepository {
    pool: PgPool,
    crypto: EncryptionService,
}

impl DetectionCodeTargetRepository {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            crypto: EncryptionService::from_env(),
        }
    }

    pub fn with_crypto(pool: PgPool, crypto: EncryptionService) -> Self {
        Self { pool, crypto }
    }

    /// Encrypt a PAT into `(ciphertext bytes, base64 nonce)` for BYTEA storage.
    fn encrypt_token(&self, pat: &str) -> Result<(Vec<u8>, String), DetectionCodeTargetError> {
        let encrypted = self
            .crypto
            .encrypt(pat.as_bytes())
            .map_err(|e| DetectionCodeTargetError::Encryption(e.to_string()))?;
        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted.ciphertext,
        )
        .map_err(|e| DetectionCodeTargetError::Encryption(e.to_string()))?;
        Ok((ciphertext_bytes, encrypted.nonce))
    }

    async fn name_taken(&self, name: &str, exclude: Option<Uuid>) -> Result<bool, DetectionCodeTargetError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM detection_code_targets WHERE name = $1 AND ($2::uuid IS NULL OR id != $2)",
        )
        .bind(name)
        .bind(exclude)
        .fetch_one(&self.pool)
        .await?;
        Ok(count > 0)
    }

    pub async fn create(
        &self,
        req: &NewDetectionCodeTarget,
        created_by: Option<Uuid>,
    ) -> Result<DetectionCodeTarget, DetectionCodeTargetError> {
        if self.name_taken(&req.name, None).await? {
            return Err(DetectionCodeTargetError::DuplicateName(req.name.clone()));
        }

        // Encrypt the optional PAT up front so a bad key fails before we insert.
        let token = match req.token.as_deref() {
            Some(pat) if !pat.is_empty() => Some(self.encrypt_token(pat)?),
            _ => None,
        };
        let (ciphertext, nonce) = match token {
            Some((ct, nonce)) => (Some(ct), Some(nonce)),
            None => (None, None),
        };

        let sql = format!(
            r#"
            INSERT INTO detection_code_targets
                (name, repo_url, base_branch, path_template, pr_branch_prefix, rule_format,
                 enabled, token_encrypted, token_nonce, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING {DCT_SELECT}
            "#
        );
        let row = sqlx::query(&sql)
            .bind(&req.name)
            .bind(&req.repo_url)
            .bind(req.base_branch.as_deref().unwrap_or("main"))
            .bind(
                req.path_template
                    .as_deref()
                    .unwrap_or("detections/{rule_name}.yaml"),
            )
            .bind(req.pr_branch_prefix.as_deref().unwrap_or("nano-tuning/"))
            .bind(req.rule_format.as_deref().unwrap_or("nanosiem"))
            .bind(req.enabled.unwrap_or(true))
            .bind(ciphertext)
            .bind(nonce)
            .bind(created_by)
            .fetch_one(&self.pool)
            .await?;
        Ok(Self::row_to_target(&row))
    }

    pub async fn list(&self) -> Result<Vec<DetectionCodeTarget>, DetectionCodeTargetError> {
        let sql = format!("SELECT {DCT_SELECT} FROM detection_code_targets ORDER BY name ASC");
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(Self::row_to_target).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<DetectionCodeTarget, DetectionCodeTargetError> {
        let sql = format!("SELECT {DCT_SELECT} FROM detection_code_targets WHERE id = $1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DetectionCodeTargetError::NotFound(id))?;
        Ok(Self::row_to_target(&row))
    }

    /// The push target that AI tuning should route PRs to: enabled and holding a
    /// token, most-recently-updated first. `None` means "no target configured",
    /// which the tuning paths treat as "fall back to the normal DB behavior".
    pub async fn find_active(&self) -> Result<Option<DetectionCodeTarget>, DetectionCodeTargetError> {
        let sql = format!(
            "SELECT {DCT_SELECT} FROM detection_code_targets \
             WHERE enabled = TRUE AND token_encrypted IS NOT NULL \
             ORDER BY updated_at DESC LIMIT 1"
        );
        let row = sqlx::query(&sql).fetch_optional(&self.pool).await?;
        Ok(row.as_ref().map(Self::row_to_target))
    }

    pub async fn update(
        &self,
        id: Uuid,
        req: &UpdateDetectionCodeTarget,
    ) -> Result<DetectionCodeTarget, DetectionCodeTargetError> {
        let existing = self.get(id).await?;
        if let Some(ref name) = req.name {
            if name != &existing.name && self.name_taken(name, Some(id)).await? {
                return Err(DetectionCodeTargetError::DuplicateName(name.clone()));
            }
        }

        let sql = format!(
            r#"
            UPDATE detection_code_targets SET
                name = COALESCE($2, name),
                repo_url = COALESCE($3, repo_url),
                base_branch = COALESCE($4, base_branch),
                path_template = COALESCE($5, path_template),
                pr_branch_prefix = COALESCE($6, pr_branch_prefix),
                enabled = COALESCE($7, enabled)
            WHERE id = $1
            RETURNING {DCT_SELECT}
            "#
        );
        let row = sqlx::query(&sql)
            .bind(id)
            .bind(&req.name)
            .bind(&req.repo_url)
            .bind(&req.base_branch)
            .bind(&req.path_template)
            .bind(&req.pr_branch_prefix)
            .bind(req.enabled)
            .fetch_one(&self.pool)
            .await?;
        Ok(Self::row_to_target(&row))
    }

    /// Store (or replace) the encrypted PAT for a target.
    pub async fn set_token(
        &self,
        id: Uuid,
        pat: &str,
    ) -> Result<DetectionCodeTarget, DetectionCodeTargetError> {
        // Confirm existence before the encrypt work so we return NotFound cleanly.
        self.get(id).await?;
        let (ciphertext, nonce) = self.encrypt_token(pat)?;
        let sql = format!(
            r#"
            UPDATE detection_code_targets
            SET token_encrypted = $2, token_nonce = $3
            WHERE id = $1
            RETURNING {DCT_SELECT}
            "#
        );
        let row = sqlx::query(&sql)
            .bind(id)
            .bind(&ciphertext)
            .bind(&nonce)
            .fetch_one(&self.pool)
            .await?;
        Ok(Self::row_to_target(&row))
    }

    /// Decrypt the stored PAT for use by the GitHub write client. `None` when no
    /// token has been configured for the target.
    pub async fn get_decrypted_token(
        &self,
        id: Uuid,
    ) -> Result<Option<String>, DetectionCodeTargetError> {
        let row = sqlx::query(
            "SELECT token_encrypted, token_nonce FROM detection_code_targets WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DetectionCodeTargetError::NotFound(id))?;

        let ciphertext: Option<Vec<u8>> = row.get("token_encrypted");
        let nonce: Option<String> = row.get("token_nonce");
        let (ciphertext, nonce) = match (ciphertext, nonce) {
            (Some(ct), Some(n)) => (ct, n),
            _ => return Ok(None),
        };

        let encrypted = EncryptedData {
            ciphertext: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &ciphertext,
            ),
            nonce,
        };
        let plaintext = self
            .crypto
            .decrypt(&encrypted)
            .map_err(|e| DetectionCodeTargetError::Encryption(e.to_string()))?;
        let token = String::from_utf8(plaintext)
            .map_err(|e| DetectionCodeTargetError::Encryption(e.to_string()))?;
        Ok(Some(token))
    }

    /// Record that a PR was just opened against this target.
    pub async fn mark_pr_opened(
        &self,
        id: Uuid,
        pr_url: &str,
    ) -> Result<(), DetectionCodeTargetError> {
        sqlx::query(
            "UPDATE detection_code_targets \
             SET last_pr_url = $2, last_pr_at = NOW(), last_used_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(pr_url)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), DetectionCodeTargetError> {
        let result = sqlx::query("DELETE FROM detection_code_targets WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(DetectionCodeTargetError::NotFound(id));
        }
        Ok(())
    }

    fn row_to_target(row: &sqlx::postgres::PgRow) -> DetectionCodeTarget {
        DetectionCodeTarget {
            id: row.get("id"),
            name: row.get("name"),
            repo_url: row.get("repo_url"),
            base_branch: row.get("base_branch"),
            path_template: row.get("path_template"),
            pr_branch_prefix: row.get("pr_branch_prefix"),
            rule_format: row.get("rule_format"),
            enabled: row.get("enabled"),
            has_token: row.get("has_token"),
            last_pr_url: row.get("last_pr_url"),
            last_pr_at: row.get("last_pr_at"),
            last_used_at: row.get("last_used_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            created_by: row.get("created_by"),
        }
    }
}
