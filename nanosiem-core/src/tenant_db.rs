// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enterprise-shared PostgreSQL tenant transaction substrate.
//!
//! This module is dormant unless an enterprise-shared caller deliberately
//! constructs a signer and uses [`TenantDbContextSigner::begin_transaction`].
//! Dedicated/managed/demo/open-core pools never call it. A context is signed
//! outside PostgreSQL, accepted only by the exact configured runtime login
//! role, and converted by migration 320 into a transaction-local proof. The
//! proof is bound to PostgreSQL's current transaction ID, so copying custom
//! GUC values across pooled connections or transactions cannot confer scope.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const MAX_CONTEXT_TTL_SECONDS: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum TenantDbError {
    #[error("enterprise-shared database identity is invalid")]
    InvalidDatabaseIdentity,
    #[error("enterprise-shared runtime role identity is invalid")]
    InvalidRuntimeRole,
    #[error("enterprise-shared context key must contain at least 32 bytes")]
    WeakContextKey,
    #[error("enterprise-shared context TTL must be between 1 and 60 seconds")]
    InvalidContextTtl,
    #[error("enterprise-shared tenant/actor identity may not be nil")]
    NilIdentity,
    #[error("enterprise-shared context signing failed")]
    SigningFailed,
    #[error("enterprise-shared tenant transaction failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("enterprise-shared RLS catalog audit failed: {0:?}")]
    CatalogAudit(Vec<TenantRlsCatalogViolation>),
}

/// A signed context is intentionally not `Debug` or `Serialize`: its HMAC is
/// a short-lived database authorization credential and must not enter logs.
pub struct SignedTenantDbContext {
    database: String,
    runtime_role: String,
    tenant_id: Uuid,
    actor_id: Uuid,
    expires_epoch: i64,
    nonce: Uuid,
    key_id: Uuid,
    signature_hex: String,
}

/// Signs exact-tenant PostgreSQL transaction contexts.
///
/// The key is supplied by the deployment secret provider. Migration 320 does
/// not generate or embed it. The same verifier key is installed separately by
/// the explicit RLS activation workflow.
pub struct TenantDbContextSigner {
    database: String,
    runtime_role: String,
    key_id: Uuid,
    key: Vec<u8>,
    ttl_seconds: i64,
}

impl TenantDbContextSigner {
    pub fn new(
        database: impl Into<String>,
        runtime_role: impl Into<String>,
        key_id: Uuid,
        key: Vec<u8>,
        ttl_seconds: i64,
    ) -> Result<Self, TenantDbError> {
        let database = database.into();
        let runtime_role = runtime_role.into();
        if !valid_pg_identity(&database) {
            return Err(TenantDbError::InvalidDatabaseIdentity);
        }
        if !valid_pg_identity(&runtime_role) {
            return Err(TenantDbError::InvalidRuntimeRole);
        }
        if key.len() < 32 {
            return Err(TenantDbError::WeakContextKey);
        }
        if !(1..=MAX_CONTEXT_TTL_SECONDS).contains(&ttl_seconds) {
            return Err(TenantDbError::InvalidContextTtl);
        }
        if key_id.is_nil() {
            return Err(TenantDbError::NilIdentity);
        }
        Ok(Self {
            database,
            runtime_role,
            key_id,
            key,
            ttl_seconds,
        })
    }

    pub fn sign(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
    ) -> Result<SignedTenantDbContext, TenantDbError> {
        self.sign_at(tenant_id, actor_id, Utc::now(), Uuid::now_v7())
    }

    fn sign_at(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        now: DateTime<Utc>,
        nonce: Uuid,
    ) -> Result<SignedTenantDbContext, TenantDbError> {
        if tenant_id.is_nil() || actor_id.is_nil() || nonce.is_nil() {
            return Err(TenantDbError::NilIdentity);
        }
        let expires_epoch = now.timestamp() + self.ttl_seconds;
        let payload = canonical_payload(
            &self.database,
            &self.runtime_role,
            tenant_id,
            actor_id,
            expires_epoch,
            nonce,
            self.key_id,
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.key).map_err(|_| TenantDbError::SigningFailed)?;
        mac.update(payload.as_bytes());
        let signature_hex = hex::encode(mac.finalize().into_bytes());
        Ok(SignedTenantDbContext {
            database: self.database.clone(),
            runtime_role: self.runtime_role.clone(),
            tenant_id,
            actor_id,
            expires_epoch,
            nonce,
            key_id: self.key_id,
            signature_hex,
        })
    }

    /// Begin a PostgreSQL transaction and install its signed tenant context.
    ///
    /// Returning the transaction only after the setter succeeds prevents an
    /// accidentally tenantless repository call. Callers must execute all
    /// tenant-owned SQL through the returned transaction, never the pool.
    pub async fn begin_transaction<'a>(
        &self,
        pool: &'a PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
    ) -> Result<Transaction<'a, Postgres>, TenantDbError> {
        let mut transaction = pool.begin().await?;
        if let Err(error) = apply_idle_backstop(&mut transaction).await {
            let _ = transaction.rollback().await;
            return Err(error);
        }
        let context = self.sign(tenant_id, actor_id)?;
        if let Err(error) = apply_context(&mut transaction, &context).await {
            let _ = transaction.rollback().await;
            return Err(error);
        }
        Ok(transaction)
    }

    /// Begin a signed tenant transaction whose authority reads and writes
    /// share one serializable PostgreSQL order. Detection result publication
    /// uses this so a concurrent revocation cannot interleave partial output.
    pub async fn begin_serializable_transaction<'a>(
        &self,
        pool: &'a PgPool,
        tenant_id: Uuid,
        actor_id: Uuid,
    ) -> Result<Transaction<'a, Postgres>, TenantDbError> {
        let mut transaction = pool.begin().await?;
        if let Err(error) = sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await
        {
            let _ = transaction.rollback().await;
            return Err(TenantDbError::Database(error));
        }
        if let Err(error) = apply_idle_backstop(&mut transaction).await {
            let _ = transaction.rollback().await;
            return Err(error);
        }
        let context = self.sign(tenant_id, actor_id)?;
        if let Err(error) = apply_context(&mut transaction, &context).await {
            let _ = transaction.rollback().await;
            return Err(error);
        }
        Ok(transaction)
    }

    /// Install a fresh, transaction-local proof between bounded database batches.
    /// The caller must retain the same authorized tenant/actor and revalidate
    /// its credential. This does not commit or relax the transaction's fences.
    pub async fn refresh_transaction_context(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant_id: Uuid,
        actor_id: Uuid,
    ) -> Result<(), TenantDbError> {
        let context = self.sign(tenant_id, actor_id)?;
        apply_context(transaction, &context).await
    }
}

/// NAN-4377: transaction-local setting naming the tenant automation key a
/// request authenticated with. The SOAR source-event trigger
/// (`nano_shared.enqueue_soar_source_event`) records events written under it
/// as AI-originated, so a case-triggered flow an API/agent key causes runs
/// under the AI approval policy instead of as a plain `trigger`.
pub const ORIGIN_AUTOMATION_KEY_SETTING: &str = "nano_shared.origin_automation_key";

/// Mark this transaction's source writes as caused by an automation key
/// (`is_local = true`: it ends with the transaction and never reaches the
/// next pooled user). Interactive sessions never call this. The trigger only
/// ever tightens policy on a marked event, so an unmarked write by a key
/// would be the failure mode; every key-admitting tenant write gate marks.
pub async fn mark_automation_key_origin(
    transaction: &mut Transaction<'_, Postgres>,
    key_id: Uuid,
) -> Result<(), TenantDbError> {
    if key_id.is_nil() {
        return Err(TenantDbError::NilIdentity);
    }
    sqlx::query("SELECT set_config($1, $2, true)")
        .bind(ORIGIN_AUTOMATION_KEY_SETTING)
        .bind(key_id.to_string())
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(TenantDbError::Database)
}

/// NAN-3080: longest a signed tenant transaction may sit idle between
/// statements. A transaction held open while its owner awaits something else
/// (another pool connection, a lake search) locks rows that other tenant
/// work and the automation-key authority reads queue behind. On 2026-09-30 a
/// detection publish sat idle in transaction for 13 minutes and took the
/// tenant API down. PostgreSQL now ends such a session instead.
pub const TENANT_TX_IDLE_TIMEOUT: &str = "120s";

/// Transaction-local `idle_in_transaction_session_timeout` (see
/// [`TENANT_TX_IDLE_TIMEOUT`]); `is_local = true`, so it ends with the
/// transaction and never leaks to the pooled session.
async fn apply_idle_backstop(transaction: &mut Transaction<'_, Postgres>) -> Result<(), TenantDbError> {
    sqlx::query("SELECT set_config('idle_in_transaction_session_timeout', $1, true)")
        .bind(TENANT_TX_IDLE_TIMEOUT)
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(TenantDbError::Database)
}

async fn apply_context(
    transaction: &mut Transaction<'_, Postgres>,
    context: &SignedTenantDbContext,
) -> Result<(), TenantDbError> {
    sqlx::query(
        r#"
        SELECT nano_shared.set_tenant_context(
            $1::name,
            $2::name,
            $3::uuid,
            $4::uuid,
            $5::bigint,
            $6::uuid,
            $7::uuid,
            $8::text
        )
        "#,
    )
    .bind(&context.database)
    .bind(&context.runtime_role)
    .bind(context.tenant_id)
    .bind(context.actor_id)
    .bind(context.expires_epoch)
    .bind(context.nonce)
    .bind(context.key_id)
    .bind(&context.signature_hex)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn canonical_payload(
    database: &str,
    runtime_role: &str,
    tenant_id: Uuid,
    actor_id: Uuid,
    expires_epoch: i64,
    nonce: Uuid,
    key_id: Uuid,
) -> String {
    format!("v1|{database}|{runtime_role}|{tenant_id}|{actor_id}|{expires_epoch}|{nonce}|{key_id}")
}

fn valid_pg_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && (bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
pub struct TenantRlsCatalogViolation {
    pub code: String,
    pub object_name: String,
    pub detail: String,
}

/// Run the migration-320 catalog audit through an owner/control-plane pool.
/// The tenant data-plane role intentionally lacks EXECUTE on this function.
pub async fn audit_tenant_rls_catalog(
    control_pool: &PgPool,
    expected_runtime_role: &str,
    expected_owner_role: &str,
) -> Result<Vec<TenantRlsCatalogViolation>, TenantDbError> {
    if !valid_pg_identity(expected_runtime_role) {
        return Err(TenantDbError::InvalidRuntimeRole);
    }
    if !valid_pg_identity(expected_owner_role) {
        return Err(TenantDbError::InvalidRuntimeRole);
    }
    Ok(sqlx::query_as::<_, TenantRlsCatalogViolation>(
        r#"
        SELECT code, object_name, detail
        FROM nano_shared.audit_rls_catalog($1::name, $2::name)
        ORDER BY code, object_name
        "#,
    )
    .bind(expected_runtime_role)
    .bind(expected_owner_role)
    .fetch_all(control_pool)
    .await?)
}

/// Run the migration-320 catalog audit inside an activation transaction.
///
/// The activation helper must not commit verifier keys, policies, or role ACLs
/// until this returns an empty result. Keeping this separate from the pool
/// variant makes that ordering structural: the caller cannot accidentally
/// audit on another connection or against a pre-activation snapshot.
pub async fn audit_tenant_rls_catalog_in_transaction(
    control_transaction: &mut Transaction<'_, Postgres>,
    expected_runtime_role: &str,
    expected_owner_role: &str,
) -> Result<Vec<TenantRlsCatalogViolation>, TenantDbError> {
    if !valid_pg_identity(expected_runtime_role) {
        return Err(TenantDbError::InvalidRuntimeRole);
    }
    if !valid_pg_identity(expected_owner_role) {
        return Err(TenantDbError::InvalidRuntimeRole);
    }
    Ok(sqlx::query_as::<_, TenantRlsCatalogViolation>(
        r#"
        SELECT code, object_name, detail
        FROM nano_shared.audit_rls_catalog($1::name, $2::name)
        ORDER BY code, object_name
        "#,
    )
    .bind(expected_runtime_role)
    .bind(expected_owner_role)
    .fetch_all(&mut **control_transaction)
    .await?)
}

pub async fn require_tenant_rls_catalog(
    control_pool: &PgPool,
    expected_runtime_role: &str,
    expected_owner_role: &str,
) -> Result<(), TenantDbError> {
    let violations =
        audit_tenant_rls_catalog(control_pool, expected_runtime_role, expected_owner_role).await?;
    if violations.is_empty() {
        Ok(())
    } else {
        Err(TenantDbError::CatalogAudit(violations))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> TenantDbContextSigner {
        TenantDbContextSigner::new(
            "nano_shared_test",
            "nano_shared_runtime",
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
            vec![0x11; 32],
            30,
        )
        .unwrap()
    }

    #[test]
    fn canonical_payload_matches_postgres_contract() {
        let tenant = Uuid::parse_str("20000000-0000-0000-0000-000000000001").unwrap();
        let actor = Uuid::parse_str("30000000-0000-0000-0000-000000000001").unwrap();
        let nonce = Uuid::parse_str("40000000-0000-0000-0000-000000000001").unwrap();
        let key = Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            canonical_payload(
                "nano_shared_test",
                "nano_shared_runtime",
                tenant,
                actor,
                1_800_000_000,
                nonce,
                key,
            ),
            "v1|nano_shared_test|nano_shared_runtime|20000000-0000-0000-0000-000000000001|30000000-0000-0000-0000-000000000001|1800000000|40000000-0000-0000-0000-000000000001|10000000-0000-0000-0000-000000000001"
        );
    }

    #[test]
    fn signatures_are_exact_tenant_and_nonce_bound() {
        let signer = signer();
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let actor = Uuid::parse_str("30000000-0000-0000-0000-000000000001").unwrap();
        let tenant_a = Uuid::parse_str("20000000-0000-0000-0000-000000000001").unwrap();
        let tenant_b = Uuid::parse_str("20000000-0000-0000-0000-000000000002").unwrap();
        let nonce_a = Uuid::parse_str("40000000-0000-0000-0000-000000000001").unwrap();
        let nonce_b = Uuid::parse_str("40000000-0000-0000-0000-000000000002").unwrap();
        let a = signer.sign_at(tenant_a, actor, now, nonce_a).unwrap();
        let b = signer.sign_at(tenant_b, actor, now, nonce_a).unwrap();
        let c = signer.sign_at(tenant_a, actor, now, nonce_b).unwrap();
        assert_ne!(a.signature_hex, b.signature_hex);
        assert_ne!(a.signature_hex, c.signature_hex);
        assert_eq!(a.signature_hex.len(), 64);
    }

    #[test]
    fn fresh_batch_signature_uses_clock_after_previous_ttl() {
        let signer = signer();
        let tenant = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let start = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let old = signer
            .sign_at(tenant, actor, start, Uuid::new_v4())
            .unwrap();
        let later = start + chrono::Duration::seconds(61);
        let fresh = signer
            .sign_at(tenant, actor, later, Uuid::new_v4())
            .unwrap();
        assert!(old.expires_epoch <= later.timestamp());
        assert_eq!(fresh.expires_epoch, later.timestamp() + 30);
        assert_eq!(fresh.tenant_id, old.tenant_id);
        assert_eq!(fresh.actor_id, old.actor_id);
        assert_ne!(fresh.nonce, old.nonce);
        assert_ne!(fresh.signature_hex, old.signature_hex);
    }

    #[test]
    fn unsafe_identity_key_and_ttl_inputs_fail_closed() {
        let key_id = Uuid::now_v7();
        assert!(matches!(
            TenantDbContextSigner::new("db-name", "runtime", key_id, vec![1; 32], 30),
            Err(TenantDbError::InvalidDatabaseIdentity)
        ));
        assert!(matches!(
            TenantDbContextSigner::new("database", "Runtime", key_id, vec![1; 32], 30),
            Err(TenantDbError::InvalidRuntimeRole)
        ));
        assert!(matches!(
            TenantDbContextSigner::new("database", "runtime", key_id, vec![1; 31], 30),
            Err(TenantDbError::WeakContextKey)
        ));
        assert!(matches!(
            TenantDbContextSigner::new("database", "runtime", key_id, vec![1; 32], 61),
            Err(TenantDbError::InvalidContextTtl)
        ));
    }
}
