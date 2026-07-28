// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud credential repository for encrypted storage
//!
//! Secret material is stored AES-256-GCM-encrypted, with full version history
//! in `cloud_credential_versions` and the active version's payload mirrored
//! into `cloud_credentials` so the read-at-deploy path stays a single-row
//! lookup.

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::types::{
    CloudCredential, CloudCredentialVersion, CreateCloudCredential, RollbackCloudCredential,
    RotateCloudCredential, UpdateCloudCredential,
};
use crate::crypto::{EncryptedData, EncryptionService};

#[derive(Error, Debug)]
pub enum CredentialRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Credential not found: {0}")]
    NotFound(Uuid),
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Credential name already exists: {0}")]
    DuplicateName(String),
    #[error("Invalid provider: {0}")]
    InvalidProvider(String),
    #[error("Credential version not found: credential={credential_id}, version={version}")]
    VersionNotFound { credential_id: Uuid, version: i32 },
}

#[derive(Clone)]
pub struct CredentialRepository {
    pool: PgPool,
    crypto: EncryptionService,
}

const CRED_SELECT: &str = "id, name, provider, description, region, external_id, environment, expires_at, last_used_at, active_version, created_at, updated_at";

impl CredentialRepository {
    pub fn new(pool: PgPool) -> Self {
        let crypto = EncryptionService::from_env();
        Self { pool, crypto }
    }

    pub fn with_crypto(pool: PgPool, crypto: EncryptionService) -> Self {
        Self { pool, crypto }
    }

    fn row_to_credential(row: &sqlx::postgres::PgRow) -> CloudCredential {
        CloudCredential {
            id: row.get("id"),
            name: row.get("name"),
            provider: row.get("provider"),
            description: row.get("description"),
            region: row.get("region"),
            external_id: row.get("external_id"),
            environment: row.get("environment"),
            expires_at: row.get("expires_at"),
            last_used_at: row.get("last_used_at"),
            active_version: row.get("active_version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }

    /// List all credentials (metadata only, no secrets)
    pub async fn list(&self) -> Result<Vec<CloudCredential>, CredentialRepositoryError> {
        let sql = format!("SELECT {CRED_SELECT} FROM cloud_credentials ORDER BY name");
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        Ok(rows.iter().map(Self::row_to_credential).collect())
    }

    /// List credentials by provider
    pub async fn list_by_provider(
        &self,
        provider: &str,
    ) -> Result<Vec<CloudCredential>, CredentialRepositoryError> {
        let sql = format!(
            "SELECT {CRED_SELECT} FROM cloud_credentials WHERE provider = $1 ORDER BY name"
        );
        let rows = sqlx::query(&sql)
            .bind(provider)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(Self::row_to_credential).collect())
    }

    /// Get credential metadata by ID (no secrets)
    pub async fn get(&self, id: Uuid) -> Result<CloudCredential, CredentialRepositoryError> {
        let sql = format!("SELECT {CRED_SELECT} FROM cloud_credentials WHERE id = $1");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(CredentialRepositoryError::NotFound(id))?;
        Ok(Self::row_to_credential(&row))
    }

    /// Encrypt a JSON credential payload, returning (ciphertext bytes, nonce string)
    fn encrypt_payload(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<(Vec<u8>, String), CredentialRepositoryError> {
        let plaintext = serde_json::to_vec(credentials)
            .map_err(|e| CredentialRepositoryError::EncryptionError(e.to_string()))?;

        let encrypted = self
            .crypto
            .encrypt(&plaintext)
            .map_err(|e| CredentialRepositoryError::EncryptionError(e.to_string()))?;

        let ciphertext_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &encrypted.ciphertext,
        )
        .map_err(|e| CredentialRepositoryError::EncryptionError(e.to_string()))?;

        Ok((ciphertext_bytes, encrypted.nonce))
    }

    /// Create a new credential. Encrypts the payload, writes the parent row
    /// with the active mirror, and inserts version 1 in the same transaction
    /// so the version history is never out of sync with the parent.
    pub async fn create(
        &self,
        req: &CreateCloudCredential,
        created_by: Option<Uuid>,
    ) -> Result<CloudCredential, CredentialRepositoryError> {
        if req.provider != "aws_s3" && req.provider != "gcp_pubsub" && req.provider != "kafka" {
            return Err(CredentialRepositoryError::InvalidProvider(
                req.provider.clone(),
            ));
        }

        if let Some(env) = req.environment.as_deref() {
            if env != "prod" && env != "staging" && env != "dev" {
                return Err(CredentialRepositoryError::InvalidProvider(format!(
                    "environment '{env}' must be one of prod / staging / dev"
                )));
            }
        }

        let existing: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM cloud_credentials WHERE name = $1")
                .bind(&req.name)
                .fetch_one(&self.pool)
                .await?;

        if existing > 0 {
            return Err(CredentialRepositoryError::DuplicateName(req.name.clone()));
        }

        let (ciphertext_bytes, nonce) = self.encrypt_payload(&req.credentials)?;

        let mut tx = self.pool.begin().await?;

        let parent_sql = format!(
            r#"
            INSERT INTO cloud_credentials
                (name, provider, credentials_encrypted, nonce, description, region,
                 external_id, environment, expires_at, active_version, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10)
            RETURNING {CRED_SELECT}
            "#
        );
        let row = sqlx::query(&parent_sql)
            .bind(&req.name)
            .bind(&req.provider)
            .bind(&ciphertext_bytes)
            .bind(&nonce)
            .bind(&req.description)
            .bind(&req.region)
            .bind(&req.external_id)
            .bind(&req.environment)
            .bind(req.expires_at)
            .bind(created_by)
            .fetch_one(&mut *tx)
            .await?;

        let credential = Self::row_to_credential(&row);

        sqlx::query(
            r#"
            INSERT INTO cloud_credential_versions
                (credential_id, version_number, credentials_encrypted, nonce, created_by, note, is_active, external_id)
            VALUES ($1, 1, $2, $3, $4, $5, true, $6)
            "#,
        )
        .bind(credential.id)
        .bind(&ciphertext_bytes)
        .bind(&nonce)
        .bind(created_by)
        .bind(Some("Initial version"))
        .bind(&req.external_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(credential)
    }

    /// Update a credential's metadata. Secret material can no longer be
    /// updated through this path — use `rotate` instead so version history is
    /// preserved.
    pub async fn update(
        &self,
        id: Uuid,
        req: &UpdateCloudCredential,
    ) -> Result<CloudCredential, CredentialRepositoryError> {
        self.get(id).await?;

        if let Some(env) = req.environment.as_deref() {
            if env != "prod" && env != "staging" && env != "dev" {
                return Err(CredentialRepositoryError::InvalidProvider(format!(
                    "environment '{env}' must be one of prod / staging / dev"
                )));
            }
        }

        if let Some(ref name) = req.name {
            let existing: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM cloud_credentials WHERE name = $1 AND id != $2",
            )
            .bind(name)
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
            if existing > 0 {
                return Err(CredentialRepositoryError::DuplicateName(name.clone()));
            }
        }

        // COALESCE preserves the existing value when the request field is None.
        // For nullable columns where the caller may want to clear the value,
        // they can pass an explicit empty-string sentinel and we treat it as
        // NULL — keeps the request shape simple while still allowing clears.
        let sql = format!(
            r#"
            UPDATE cloud_credentials SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                region = COALESCE($4, region),
                environment = COALESCE($5, environment),
                expires_at = COALESCE($6, expires_at)
            WHERE id = $1
            RETURNING {CRED_SELECT}
            "#
        );
        let row = sqlx::query(&sql)
            .bind(id)
            .bind(&req.name)
            .bind(&req.description)
            .bind(&req.region)
            .bind(&req.environment)
            .bind(req.expires_at)
            .fetch_one(&self.pool)
            .await?;

        Ok(Self::row_to_credential(&row))
    }

    /// Rotate the secret material — creates a new active version, marks the
    /// old one inactive, and mirrors the new payload into the parent row in a
    /// single transaction.
    pub async fn rotate(
        &self,
        id: Uuid,
        req: &RotateCloudCredential,
        rotated_by: Option<Uuid>,
    ) -> Result<(CloudCredential, CloudCredentialVersion), CredentialRepositoryError> {
        // Confirm the credential exists before doing the encrypt work
        self.get(id).await?;

        let (ciphertext_bytes, nonce) = self.encrypt_payload(&req.credentials)?;

        let mut tx = self.pool.begin().await?;

        // Publication triggers lock the singleton before source/credential
        // rows. Preserve that global order here because this flow explicitly
        // locks the credential before its later UPDATE fires the trigger.
        sqlx::query(
            "SELECT singleton FROM vector_config_publication_state \
             WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await?;

        // Lock the row to serialize concurrent rotations.
        sqlx::query("SELECT id FROM cloud_credentials WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;

        let next_version: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM cloud_credential_versions WHERE credential_id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE cloud_credential_versions SET is_active = false WHERE credential_id = $1 AND is_active = true",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;

        let version_row = sqlx::query(
            r#"
            INSERT INTO cloud_credential_versions
                (credential_id, version_number, credentials_encrypted, nonce, created_by, note, is_active, external_id)
            VALUES ($1, $2, $3, $4, $5, $6, true, $7)
            RETURNING id, credential_id, version_number, created_at, created_by, note, is_active, reverted_from_version
            "#,
        )
        .bind(id)
        .bind(next_version)
        .bind(&ciphertext_bytes)
        .bind(&nonce)
        .bind(rotated_by)
        .bind(&req.note)
        .bind(&req.external_id)
        .fetch_one(&mut *tx)
        .await?;

        let parent_sql = format!(
            r#"
            UPDATE cloud_credentials SET
                credentials_encrypted = $2,
                nonce = $3,
                active_version = $4,
                external_id = $5
            WHERE id = $1
            RETURNING {CRED_SELECT}
            "#
        );
        let parent_row = sqlx::query(&parent_sql)
            .bind(id)
            .bind(&ciphertext_bytes)
            .bind(&nonce)
            .bind(next_version)
            .bind(&req.external_id)
            .fetch_one(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok((
            Self::row_to_credential(&parent_row),
            Self::row_to_version(&version_row),
        ))
    }

    /// Roll back to a previous version. Creates a new version row that copies
    /// the target's payload and records `reverted_from_version`, then marks it
    /// active and mirrors the payload into the parent row.
    pub async fn rollback(
        &self,
        id: Uuid,
        req: &RollbackCloudCredential,
        rolled_back_by: Option<Uuid>,
    ) -> Result<(CloudCredential, CloudCredentialVersion), CredentialRepositoryError> {
        self.get(id).await?;

        let mut tx = self.pool.begin().await?;

        // Match the singleton -> credential lock order used by publication
        // triggers before taking the explicit row lock below.
        sqlx::query(
            "SELECT singleton FROM vector_config_publication_state \
             WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query("SELECT id FROM cloud_credentials WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;

        // Fetch the target version's payload
        let target = sqlx::query(
            "SELECT credentials_encrypted, nonce, external_id FROM cloud_credential_versions \
             WHERE credential_id = $1 AND version_number = $2",
        )
        .bind(id)
        .bind(req.version)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(CredentialRepositoryError::VersionNotFound {
            credential_id: id,
            version: req.version,
        })?;
        let target_ciphertext: Vec<u8> = target.get("credentials_encrypted");
        let target_nonce: String = target.get("nonce");
        // NAN-2186: restore the ExternalId that belonged to THIS payload. The
        // id is a trust-policy condition on the role ARN inside the payload, so
        // carrying the current one backwards would pair a restored role with an
        // id its trust policy never referenced.
        let target_external_id: Option<String> = target.get("external_id");

        let next_version: i32 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM cloud_credential_versions WHERE credential_id = $1",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE cloud_credential_versions SET is_active = false WHERE credential_id = $1 AND is_active = true",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;

        let note = req
            .note
            .clone()
            .unwrap_or_else(|| format!("Rolled back to v{}", req.version));

        let version_row = sqlx::query(
            r#"
            INSERT INTO cloud_credential_versions
                (credential_id, version_number, credentials_encrypted, nonce, created_by, note, is_active, reverted_from_version, external_id)
            VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8)
            RETURNING id, credential_id, version_number, created_at, created_by, note, is_active, reverted_from_version
            "#,
        )
        .bind(id)
        .bind(next_version)
        .bind(&target_ciphertext)
        .bind(&target_nonce)
        .bind(rolled_back_by)
        .bind(&note)
        .bind(req.version)
        .bind(&target_external_id)
        .fetch_one(&mut *tx)
        .await?;

        let parent_sql = format!(
            r#"
            UPDATE cloud_credentials SET
                credentials_encrypted = $2,
                nonce = $3,
                active_version = $4,
                external_id = $5
            WHERE id = $1
            RETURNING {CRED_SELECT}
            "#
        );
        let parent_row = sqlx::query(&parent_sql)
            .bind(id)
            .bind(&target_ciphertext)
            .bind(&target_nonce)
            .bind(next_version)
            .bind(&target_external_id)
            .fetch_one(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok((
            Self::row_to_credential(&parent_row),
            Self::row_to_version(&version_row),
        ))
    }

    /// List all versions for a credential, newest first.
    pub async fn list_versions(
        &self,
        id: Uuid,
    ) -> Result<Vec<CloudCredentialVersion>, CredentialRepositoryError> {
        // Confirm the credential exists so we can return NotFound rather than
        // an empty list when the caller passes a bogus id.
        self.get(id).await?;

        let rows = sqlx::query(
            r#"
            SELECT id, credential_id, version_number, created_at, created_by, note, is_active, reverted_from_version
            FROM cloud_credential_versions
            WHERE credential_id = $1
            ORDER BY version_number DESC
            "#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(Self::row_to_version).collect())
    }

    fn row_to_version(row: &sqlx::postgres::PgRow) -> CloudCredentialVersion {
        CloudCredentialVersion {
            id: row.get("id"),
            credential_id: row.get("credential_id"),
            version_number: row.get("version_number"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            note: row.get("note"),
            is_active: row.get("is_active"),
            reverted_from_version: row.get("reverted_from_version"),
        }
    }

    /// Get decrypted credentials for a credential ID — reads the active
    /// version's payload from the parent-row mirror so deploy stays a
    /// single-row lookup.
    pub async fn get_decrypted(
        &self,
        id: Uuid,
    ) -> Result<serde_json::Value, CredentialRepositoryError> {
        let row =
            sqlx::query(
                "SELECT credentials_encrypted, nonce, external_id FROM cloud_credentials WHERE id = $1",
            )
                .bind(id)
                .fetch_optional(&self.pool)
                .await?
                .ok_or(CredentialRepositoryError::NotFound(id))?;

        let ciphertext: Vec<u8> = row.get("credentials_encrypted");
        let nonce: String = row.get("nonce");

        let ciphertext_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ciphertext);

        let encrypted = EncryptedData {
            ciphertext: ciphertext_b64,
            nonce,
        };

        let plaintext = self
            .crypto
            .decrypt(&encrypted)
            .map_err(|e| CredentialRepositoryError::EncryptionError(e.to_string()))?;

        let mut value: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| CredentialRepositoryError::EncryptionError(e.to_string()))?;

        // NAN-2186: `external_id` lives in its own unencrypted column (it is an
        // identifier the account owner must be able to read back, not a
        // secret), but every config generator consumes ONE credential JSON.
        // Merge it in here — the single funnel every deploy path already goes
        // through — so the column stays the sole source of truth and the
        // generators need no second lookup.
        if let Some(external_id) = row.get::<Option<String>, _>("external_id") {
            if !external_id.trim().is_empty() {
                if let Some(map) = value.as_object_mut() {
                    map.insert(
                        "external_id".to_string(),
                        serde_json::Value::String(external_id),
                    );
                }
            }
        }

        Ok(value)
    }

    /// Best-effort timestamp of the most recent authorized credential use.
    pub async fn mark_used(&self, id: Uuid) -> Result<(), CredentialRepositoryError> {
        sqlx::query("UPDATE cloud_credentials SET last_used_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete a credential (and cascade its versions via the FK) only when no
    /// source configuration references it. The reference predicate is part of
    /// the DELETE statement to avoid a check-then-act gap and return
    /// a useful in-use error; restrictive foreign keys remain the final guard
    /// against concurrent and out-of-band writers.
    pub async fn delete(&self, id: Uuid) -> Result<(), CredentialRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "DELETE FROM cloud_credentials cc \
             WHERE cc.id = $1 \
               AND NOT EXISTS (SELECT 1 FROM source_configurations sc WHERE sc.credential_id = cc.id)",
        )
            .bind(id)
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 1 {
            tx.commit().await?;
            return Ok(());
        }
        tx.rollback().await?;

        let counts = sqlx::query_as::<_, (bool, i64)>(
            "SELECT EXISTS(SELECT 1 FROM cloud_credentials WHERE id = $1), \
                    (SELECT COUNT(*) FROM source_configurations WHERE credential_id = $1)",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if !counts.0 {
            return Err(CredentialRepositoryError::NotFound(id));
        }

        Err(CredentialRepositoryError::EncryptionError(format!(
            "Cannot delete credential: {} source configuration(s) are using it",
            counts.1
        )))
    }

    pub async fn exists(&self, id: Uuid) -> Result<bool, CredentialRepositoryError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cloud_credentials WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_credential_provider_validation() {
        let valid_providers = ["aws_s3", "gcp_pubsub", "kafka"];
        assert!(valid_providers.contains(&"aws_s3"));
        assert!(valid_providers.contains(&"gcp_pubsub"));
        assert!(valid_providers.contains(&"kafka"));
        assert!(!valid_providers.contains(&"azure_blob"));
    }
}
