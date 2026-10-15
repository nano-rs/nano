// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant-owned export configuration. Credentials are write-only and use the
//! connector feed AES-GCM envelope, with an encrypted tenant binding.

use crate::crypto::EncryptionService;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("invalid export configuration")]
    Invalid,
    #[error("export target is locked; disable it before rotating credentials")]
    Locked,
    #[error("export credential unavailable")]
    Credential,
    #[error("export storage unavailable")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CatalogAuthentication {
    #[default]
    Oauth,
    Bearer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CustomerExportConfig {
    pub catalog_uri: String,
    #[serde(default)]
    pub catalog_authentication: CatalogAuthentication,
    pub warehouse: String,
    pub namespace: String,
    pub bucket_endpoint: String,
    pub bucket: String,
    pub region: String,
    /// Prefix owned exclusively by this tenant's export, inside the customer's bucket.
    pub prefix: String,
    pub oauth_server_uri: Option<String>,
    pub oauth_scope: Option<String>,
    pub oauth_audience: Option<String>,
}

impl CustomerExportConfig {
    pub fn validate(&self, tenant: Uuid) -> Result<(), ExportError> {
        if self.catalog_authentication == CatalogAuthentication::Bearer
            && (self.oauth_server_uri.is_some()
                || self.oauth_scope.is_some()
                || self.oauth_audience.is_some())
        {
            return Err(ExportError::Invalid);
        }
        if tenant.is_nil() {
            return Err(ExportError::Invalid);
        }
        for uri in [&self.catalog_uri, &self.bucket_endpoint]
            .into_iter()
            .chain(self.oauth_server_uri.iter())
        {
            endpoint(uri)?;
        }
        for value in [&self.warehouse, &self.region] {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(ExportError::Invalid);
            }
        }
        if self.namespace.is_empty()
            || self.namespace.len() > 128
            || !self
                .namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !(3..=63).contains(&self.bucket.len())
            || !self
                .bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || self.prefix.len() > 512
            || self.prefix.starts_with('/')
            || self.prefix.contains("//")
            || !self.prefix.ends_with(&format!("tenant={tenant}/"))
            || self.prefix.split('/').any(|s| s == "." || s == "..")
            || !self
                .prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_=".contains(&b))
        {
            return Err(ExportError::Invalid);
        }
        for value in [self.oauth_scope.as_ref(), self.oauth_audience.as_ref()]
            .into_iter()
            .flatten()
        {
            if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
                return Err(ExportError::Invalid);
            }
        }
        Ok(())
    }
}

/// Only HTTPS DNS origins without userinfo, query or fragment. Runtime egress
/// additionally resolves public addresses and pins the connection on EVERY hop.
pub fn endpoint(value: &str) -> Result<url::Url, ExportError> {
    let url = url::Url::parse(value).map_err(|_| ExportError::Invalid)?;
    let host = url.host_str().ok_or(ExportError::Invalid)?;
    if value.len() > 2048
        || value.chars().any(char::is_control)
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || host.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.')
        || host.ends_with(".localhost")
        // URL parsing normalizes encoded traversal before exposing path().
        || value.contains('%')
        || value.contains("..")
    {
        return Err(ExportError::Invalid);
    }
    Ok(url)
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateExportSettings {
    pub enabled: bool,
    pub customer: CustomerExportConfig,
    /// Replace all credentials while disabled, or omit to preserve. Never returned.
    /// Required keys: catalog_credential, access_key_id, secret_access_key.
    #[schema(schema_with = write_only_credentials)]
    pub credentials: Option<HashMap<String, String>>,
    /// Compare-and-swap revision; zero creates the first target.
    pub expected_revision: i64,
}

// Utoipa's map annotation decorates the map's values/keys instead of the
// enclosing property. Explicitly mark the whole nullable map write-only.
fn write_only_credentials() -> utoipa::openapi::schema::Object {
    use utoipa::openapi::schema::{ObjectBuilder, SchemaType, Type};
    ObjectBuilder::new()
        .schema_type(SchemaType::Array(vec![Type::Object,Type::Null]))
        .additional_properties(Some(ObjectBuilder::new().schema_type(Type::String)))
        .description(Some("Replace all credentials while disabled, or omit to preserve. Required keys: catalog_credential, access_key_id, secret_access_key. Optional: session_token. Never returned."))
        .write_only(Some(true)).build()
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ExportSettings {
    pub available: bool,
    pub enabled: bool,
    pub customer: Option<CustomerExportConfig>,
    pub credential_configured: bool,
    pub revision: i64,
    pub last_success: Option<DateTime<Utc>>,
    pub lag_hours: i64,
    pub bytes_copied: i64,
    pub files: i64,
    pub errors: serde_json::Value,
    pub next_run_at: Option<DateTime<Utc>>,
}

pub fn feature_enabled() -> bool {
    std::env::var("NANO_ICEBERG_EXPORT_ENABLED").is_ok_and(|v| v == "true")
}

pub fn seal(
    cipher: &EncryptionService,
    tenant: Uuid,
    mut credentials: HashMap<String, String>,
) -> Result<(Vec<u8>, String), ExportError> {
    if credentials.len() > 4
        || !["catalog_credential", "access_key_id", "secret_access_key"]
            .iter()
            .all(|k| credentials.contains_key(*k))
        || credentials.iter().any(|(k, v)| {
            ![
                "catalog_credential",
                "access_key_id",
                "secret_access_key",
                "session_token",
            ]
            .contains(&k.as_str())
                || v.is_empty()
                || v.len() > 4096
                || v.chars().any(char::is_control)
        })
    {
        return Err(ExportError::Invalid);
    }
    credentials.insert("tenant_id".into(), tenant.to_string());
    let encrypted = cipher
        .encrypt_json(&credentials)
        .map_err(|_| ExportError::Credential)?;
    Ok((
        base64::engine::general_purpose::STANDARD
            .decode(encrypted.ciphertext)
            .map_err(|_| ExportError::Credential)?,
        encrypted.nonce,
    ))
}

pub fn open(
    cipher: &EncryptionService,
    tenant: Uuid,
    ciphertext: &[u8],
    nonce: &str,
) -> Result<HashMap<String, String>, ExportError> {
    let mut values = cipher
        .decrypt_credentials_bytea(ciphertext, nonce)
        .map_err(|_| ExportError::Credential)?;
    if values.remove("tenant_id").as_deref() != Some(&tenant.to_string()) {
        return Err(ExportError::Credential);
    }
    if values.len() > 4
        || !["catalog_credential", "access_key_id", "secret_access_key"]
            .iter()
            .all(|k| values.get(*k).is_some_and(|v| !v.is_empty()))
    {
        return Err(ExportError::Credential);
    }
    Ok(values)
}

pub async fn read(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    available: bool,
) -> Result<ExportSettings, ExportError> {
    let row = sqlx::query("SELECT enabled,customer_config,credentials_encrypted IS NOT NULL AS credential_configured,revision,last_success,lag_hours,bytes_copied,files,errors,next_run_at FROM iceberg_export_settings WHERE tenant_id=$1")
        .bind(tenant).fetch_optional(&mut **tx).await?;
    match row {
        None => Ok(ExportSettings {
            available,
            enabled: false,
            customer: None,
            credential_configured: false,
            revision: 0,
            last_success: None,
            lag_hours: 0,
            bytes_copied: 0,
            files: 0,
            errors: serde_json::json!({}),
            next_run_at: None,
        }),
        Some(r) => Ok(ExportSettings {
            available,
            enabled: r.try_get("enabled")?,
            customer: Some(
                serde_json::from_value(r.try_get("customer_config")?)
                    .map_err(|_| ExportError::Invalid)?,
            ),
            credential_configured: r.try_get("credential_configured")?,
            revision: r.try_get("revision")?,
            last_success: r.try_get("last_success")?,
            lag_hours: r.try_get("lag_hours")?,
            bytes_copied: r.try_get("bytes_copied")?,
            files: r.try_get("files")?,
            errors: r.try_get("errors")?,
            next_run_at: r.try_get("next_run_at")?,
        }),
    }
}

/// Caller supplies the authenticated tenant transaction and appends its audit
/// in this same transaction. No client-selected tenant is accepted.
pub async fn update(
    tx: &mut Transaction<'_, Postgres>,
    tenant: Uuid,
    cipher: &EncryptionService,
    input: UpdateExportSettings,
) -> Result<ExportSettings, ExportError> {
    input.customer.validate(tenant)?;
    if input.expected_revision < 0 || (input.enabled && !feature_enabled()) {
        return Err(ExportError::Invalid);
    }
    // Serialize create/update as well as runner claims for this tenant.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,3580))")
        .bind(format!("iceberg-export:{tenant}"))
        .execute(&mut **tx)
        .await?;
    let old = sqlx::query("SELECT enabled,customer_config,revision,credentials_encrypted,credentials_nonce,lease_until FROM iceberg_export_settings WHERE tenant_id=$1 FOR UPDATE")
        .bind(tenant).fetch_optional(&mut **tx).await?;
    let (ct, nonce) = if let Some(ref old) = old {
        let revision: i64 = old.try_get("revision")?;
        let config: serde_json::Value = old.try_get("customer_config")?;
        let lease: Option<DateTime<Utc>> = old.try_get("lease_until")?;
        // Location is immutable once created; rotating credentials retains the cursor.
        if revision != input.expected_revision
            || config != serde_json::to_value(&input.customer).map_err(|_| ExportError::Invalid)?
            || lease.is_some_and(|t| t > Utc::now())
            || (old.try_get::<bool, _>("enabled")? && input.credentials.is_some())
        {
            return Err(ExportError::Locked);
        }
        match input.credentials {
            Some(values) => seal(cipher, tenant, values)?,
            None => (
                old.try_get("credentials_encrypted")?,
                old.try_get("credentials_nonce")?,
            ),
        }
    } else {
        if input.expected_revision != 0 {
            return Err(ExportError::Locked);
        }
        seal(
            cipher,
            tenant,
            input.credentials.ok_or(ExportError::Invalid)?,
        )?
    };
    sqlx::query("INSERT INTO iceberg_export_settings(tenant_id,enabled,customer_config,credentials_encrypted,credentials_nonce) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id) DO UPDATE SET enabled=EXCLUDED.enabled,credentials_encrypted=EXCLUDED.credentials_encrypted,credentials_nonce=EXCLUDED.credentials_nonce,revision=iceberg_export_settings.revision+1,next_run_at=now(),updated_at=now()")
        .bind(tenant).bind(input.enabled).bind(serde_json::to_value(input.customer).map_err(|_| ExportError::Invalid)?).bind(ct).bind(nonce).execute(&mut **tx).await?;
    read(tx, tenant, feature_enabled()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_credentials_are_bound_to_tenant() {
        let cipher = EncryptionService::new(&[7; 32]);
        let tenant = Uuid::new_v4();
        let values = HashMap::from([
            (
                "catalog_credential".into(),
                "test-client:test-secret".into(),
            ),
            ("access_key_id".into(), "test-access".into()),
            ("secret_access_key".into(), "test-secret".into()),
        ]);
        let (ct, nonce) = seal(&cipher, tenant, values.clone()).unwrap();
        assert!(!String::from_utf8_lossy(&ct).contains("test-secret"));
        assert_eq!(open(&cipher, tenant, &ct, &nonce).unwrap(), values);
        assert!(open(&cipher, Uuid::new_v4(), &ct, &nonce).is_err());
    }
    #[test]
    fn customer_prefix_preserves_exact_tenant_storage_coordinates() {
        let tenant = Uuid::new_v4();
        let mut config = CustomerExportConfig {
            catalog_uri: "https://catalog.example".into(),
            catalog_authentication: CatalogAuthentication::Oauth,
            warehouse: "customer".into(),
            namespace: "nano".into(),
            bucket_endpoint: "https://bucket.example".into(),
            bucket: "customer-bucket".into(),
            region: "us-east-1".into(),
            prefix: format!("export/tenant={tenant}/"),
            oauth_server_uri: None,
            oauth_scope: None,
            oauth_audience: None,
        };
        assert!(config.validate(tenant).is_ok());
        assert!(config.validate(Uuid::new_v4()).is_err());
        config.prefix = format!("export//tenant={tenant}/");
        assert!(
            config.validate(tenant).is_err(),
            "OpenDAL collapses empty prefix segments while Iceberg URIs preserve them"
        );
    }
    #[test]
    fn endpoint_refuses_secret_and_internal_shapes() {
        for url in [
            "http://catalog.example",
            "https://127.0.0.1",
            "https://localhost",
            "https://user:secret@catalog.example",
            "https://catalog.example?token=secret",
            "https://catalog.example/%2e%2e",
            "https://[::1]",
        ] {
            assert!(endpoint(url).is_err());
        }
        assert!(endpoint("https://catalog.example/iceberg").is_ok());
    }
}
