// SPDX-License-Identifier: AGPL-3.0-or-later
//! C12 durable staging protocol. Staged vendor bytes confer no approval or
//! activation authority. The open edition retains types and refuses effects.
use super::{ContentKind, VerifiedContentCatalog};
use crate::tenant_db::TenantDbContextSigner;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

pub const AUTHORITY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_STAGES: i64 = 16;
pub const MAX_STORED_BYTES: i64 = 64 * 1024 * 1024;
pub const MAX_CONTENT_APPROVAL_BYTES: usize = 640 * 1024;
pub const CONTENT_APPROVAL_CONTRACT: &str = "nano.sovereign.content-approval.v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StagingError {
    #[error("content staging requires the enterprise edition")]
    Unsupported,
    #[error("content staging authority denied")]
    Denied,
    #[error("content staging authority or database unavailable")]
    Unavailable,
    #[error("content staging state changed")]
    Conflict,
    #[error("content staging capacity reached")]
    Capacity,
    #[error("staged content not found")]
    NotFound,
    #[error("content staging input is invalid")]
    Invalid,
}

/// Derived by C01's customer-local composition root, never request fields.
#[derive(Clone)]
pub struct ContentNamespace {
    pub installation_id: String,
    pub tenant_id: Uuid,
    pub binding_sha256: [u8; 32],
    pub authority_epochs: [u64; 4],
}
impl ContentNamespace {
    pub fn validate(&self) -> Result<(), StagingError> {
        if self.tenant_id.is_nil()
            || self.installation_id.is_empty()
            || self.installation_id.len() > 128
            || !self
                .installation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            || self
                .authority_epochs
                .iter()
                .any(|e| *e == 0 || *e > 9_007_199_254_740_991)
        {
            return Err(StagingError::Invalid);
        }
        Ok(())
    }
}

/// Implemented by the C01 root. Namespace rotations share a database lock
/// with each staging transaction; callbacks recheck current authority too.
#[async_trait::async_trait]
pub trait ContentCommitAuthority: Send + Sync {
    async fn revalidate(&self) -> Result<(), StagingError>;
}

/// Sealed member credential, distinct from the installation grant and vendor
/// signature. Scheduled repository-follow credentials cannot stage uploads.
#[derive(Clone)]
pub struct ContentCatalogAccess {
    pub(crate) tenant_id: Uuid,
    pub(crate) actor_id: Uuid,
    pub(crate) kind: ContentKind,
    #[cfg(feature = "enterprise")]
    pub(crate) authority: crate::enterprise_shared_security::AuthorizedTenantSecurity,
    #[cfg(feature = "enterprise")]
    pub(crate) credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
    #[cfg(feature = "enterprise")]
    pub(crate) client: crate::audit::ClientContext,
}
impl ContentCatalogAccess {
    #[cfg(feature = "enterprise")]
    pub fn member(
        authority: crate::enterprise_shared_security::AuthorizedTenantSecurity,
        credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
        client: crate::audit::ClientContext,
    ) -> Result<Self, StagingError> {
        use crate::enterprise_shared_tenant_credential::TenantCredentialProof;
        if matches!(
            &credential,
            TenantCredentialProof::RepositorySchedule { .. }
        ) || authority.tenant().tenant_id.is_nil()
            || authority.actor_id().is_nil()
        {
            return Err(StagingError::Denied);
        }
        let kind = match authority.permission() {
            crate::enterprise_shared_sources_parsers::SYNC => ContentKind::Parsers,
            crate::enterprise_shared_rule_repositories::SYNC => ContentKind::Rules,
            _ => return Err(StagingError::Denied),
        };
        Ok(Self {
            tenant_id: authority.tenant().tenant_id,
            actor_id: authority.actor_id(),
            kind,
            authority,
            credential,
            client,
        })
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn actor_id(&self) -> Uuid {
        self.actor_id
    }
    pub fn kind(&self) -> ContentKind {
        self.kind
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StagedContentReceipt {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub installation_id: String,
    pub kind: ContentKind,
    pub repository: String,
    pub upstream_commit: String,
    pub archive_sha256: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
}

/// An exact current predecessor, including local imported objects. Its digest
/// is opaque; no private rule text, parser body or source config is returned.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentPredecessor {
    pub repository_id: Option<Uuid>,
    pub state_sha256: String,
}

/// Public proposal data, not approval or authority. Consumers must verify the
/// customer signature and compare every field with current locked PG state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentApprovalPayload {
    pub contract: String,
    pub installation_id: String,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub namespace_sha256: String,
    pub authority_epochs: [u64; 4],
    pub stage_id: Uuid,
    pub archive_sha256: String,
    pub kind: ContentKind,
    pub repository: String,
    pub upstream_commit: String,
    pub predecessor: ContentPredecessor,
    /// Explicit detections to create; an empty list only updates the catalog.
    pub rule_import_paths: Vec<String>,
    pub nonce: Uuid,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Only the real signed-tenant reader constructs a proposal. Serialization of
/// its public payload does not confer customer approval or consume a nonce.
pub struct ContentApprovalProposal {
    pub(crate) payload: ContentApprovalPayload,
    pub(crate) bytes: Vec<u8>,
}
impl ContentApprovalProposal {
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }
    pub fn claims(&self) -> &ContentApprovalPayload {
        &self.payload
    }
}

/// Current explicit import/create authority, separate from upload/sync rights.
/// A missing manage authority only permits an existing first-party repository.
pub struct ContentRuleApplyAccess {
    _sealed: (),
    #[cfg(feature = "enterprise")]
    pub(crate) create: Option<crate::enterprise_shared_security::AuthorizedTenantSecurity>,
    #[cfg(feature = "enterprise")]
    pub(crate) manage: Option<crate::enterprise_shared_security::AuthorizedTenantSecurity>,
    #[cfg(feature = "enterprise")]
    pub(crate) credential:
        Option<crate::enterprise_shared_tenant_credential::TenantCredentialProof>,
}
impl ContentRuleApplyAccess {
    /// Updating an existing catalog needs only the store's current SYNC proof.
    pub fn catalog_only() -> Self {
        Self {
            _sealed: (),
            #[cfg(feature = "enterprise")]
            create: None,
            #[cfg(feature = "enterprise")]
            manage: None,
            #[cfg(feature = "enterprise")]
            credential: None,
        }
    }
    #[cfg(feature = "enterprise")]
    pub fn catalog_member(
        manage: crate::enterprise_shared_security::AuthorizedTenantSecurity,
        credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
    ) -> Result<Self, StagingError> {
        if manage.permission() != "rule_repositories:manage"
            || matches!(&credential, crate::enterprise_shared_tenant_credential::TenantCredentialProof::RepositorySchedule { .. }) {
            return Err(StagingError::Denied);
        }
        Ok(Self {
            _sealed: (),
            create: None,
            manage: Some(manage),
            credential: Some(credential),
        })
    }

    #[cfg(feature = "enterprise")]
    pub fn member(
        create: crate::enterprise_shared_security::AuthorizedTenantSecurity,
        manage: Option<crate::enterprise_shared_security::AuthorizedTenantSecurity>,
        credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
    ) -> Result<Self, StagingError> {
        if create.permission() != "detections:create"
            || matches!(&credential, crate::enterprise_shared_tenant_credential::TenantCredentialProof::RepositorySchedule { .. })
            || manage.as_ref().is_some_and(|m| m.permission() != "rule_repositories:manage"
                || m.tenant() != create.tenant() || m.actor_id() != create.actor_id()
                || m.grant_authority_revision() != create.grant_authority_revision()
                || m.plan_assignment_revision() != create.plan_assignment_revision()) {
            return Err(StagingError::Denied);
        }
        Ok(Self {
            _sealed: (),
            create: Some(create),
            manage,
            credential: Some(credential),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentRuleApplyReceipt {
    pub nonce: Uuid,
    pub archive_sha256: String,
    pub repository_id: Uuid,
    pub imported: u32,
    pub preserved: u32,
}

pub struct ContentStagingStore {
    pub(crate) _sealed: (),
    #[cfg(feature = "enterprise")]
    pub(crate) pool: PgPool,
    #[cfg(feature = "enterprise")]
    pub(crate) signer: Arc<TenantDbContextSigner>,
    #[cfg(feature = "enterprise")]
    pub(crate) namespace: ContentNamespace,
    #[cfg(feature = "enterprise")]
    pub(crate) access: ContentCatalogAccess,
    #[cfg(feature = "enterprise")]
    pub(crate) authority: Arc<dyn ContentCommitAuthority>,
}
impl ContentStagingStore {
    /// The trusted customer root supplies fresh approval+vendor authority.
    /// All scope, expiry and predecessor checks repeat inside the transaction.
    pub async fn apply_rules(
        &self,
        payload: &[u8],
        catalog: &VerifiedContentCatalog,
        access: &ContentRuleApplyAccess,
        approval_and_read: &dyn ContentCommitAuthority,
    ) -> Result<ContentRuleApplyReceipt, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (payload, catalog, access, approval_and_read);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::apply::apply(
                self,
                payload,
                catalog,
                access,
                approval_and_read,
            )
            .await
        }
    }
    /// Read-only reconciliation after an ambiguous commit; never reapplies.
    pub async fn rule_apply_receipt(
        &self,
        nonce: Uuid,
    ) -> Result<Option<ContentRuleApplyReceipt>, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = nonce;
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::apply::read_receipt(self, nonce).await
        }
    }
    pub async fn prepare_approval(
        &self,
        id: Uuid,
        catalog: &VerifiedContentCatalog,
        rule_import_paths: &[String],
        read_and_commit: &dyn ContentCommitAuthority,
    ) -> Result<ContentApprovalProposal, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (id, catalog, rule_import_paths, read_and_commit);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::prepare_approval(
                self,
                id,
                catalog,
                rule_import_paths,
                read_and_commit,
            )
            .await
        }
    }
    pub async fn connect(
        pool: PgPool,
        signer: Arc<TenantDbContextSigner>,
        namespace: ContentNamespace,
        access: ContentCatalogAccess,
        authority: Arc<dyn ContentCommitAuthority>,
    ) -> Result<Self, StagingError> {
        namespace.validate()?;
        if namespace.tenant_id != access.tenant_id {
            return Err(StagingError::Denied);
        }
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (pool, signer, namespace, access, authority);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::connect(
                pool, signer, namespace, access, authority,
            )
            .await
        }
    }
    pub async fn configure(
        provisioner: &PgPool,
        namespace: &ContentNamespace,
        expected: Option<&ContentNamespace>,
        authority: &dyn ContentCommitAuthority,
    ) -> Result<(), StagingError> {
        namespace.validate()?;
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (provisioner, namespace, expected, authority);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::configure(
                provisioner,
                namespace,
                expected,
                authority,
            )
            .await
        }
    }
    pub async fn stage(
        &self,
        catalog: &VerifiedContentCatalog,
        archive: &[u8],
        read_and_commit: &dyn ContentCommitAuthority,
    ) -> Result<StagedContentReceipt, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (catalog, archive, read_and_commit);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::stage(self, catalog, archive, read_and_commit)
                .await
        }
    }
    pub async fn list(&self) -> Result<Vec<StagedContentReceipt>, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::list(self).await
        }
    }
    /// Raw persisted bytes remain untrusted. The C01 ArtifactRead root must
    /// verify them again before creating a new sealed content input.
    pub async fn load(&self, id: Uuid) -> Result<(StagedContentReceipt, Vec<u8>), StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = id;
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::load(self, id).await
        }
    }
    /// Later approval/active-head references use restrictive FKs, so this can
    /// discard unused cache entries without removing a referenced artifact.
    pub async fn forget(&self, id: Uuid) -> Result<(), StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = id;
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::forget(self, id).await
        }
    }
}

#[cfg(all(test, not(feature = "enterprise")))]
mod edition_tests {
    use super::*;
    struct NoIo;
    #[async_trait::async_trait]
    impl ContentCommitAuthority for NoIo {
        async fn revalidate(&self) -> Result<(), StagingError> {
            panic!("the open edition must refuse before authority or database IO")
        }
    }
    #[tokio::test]
    async fn staging_refuses_without_the_enterprise_edition_before_io() {
        let namespace = ContentNamespace {
            installation_id: "fixture".into(),
            tenant_id: Uuid::from_u128(1),
            binding_sha256: [1; 32],
            authority_epochs: [1; 4],
        };
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgresql://localhost:1/unused")
            .unwrap();
        assert_eq!(
            ContentStagingStore::configure(&pool, &namespace, None, &NoIo).await,
            Err(StagingError::Unsupported)
        );
        let signer = Arc::new(
            TenantDbContextSigner::new(
                "unused",
                "nano_shared_app_runtime",
                Uuid::from_u128(2),
                vec![3; 32],
                30,
            )
            .unwrap(),
        );
        let access = ContentCatalogAccess {
            tenant_id: namespace.tenant_id,
            actor_id: Uuid::from_u128(3),
            kind: ContentKind::Rules,
        };
        assert!(matches!(
            ContentStagingStore::connect(pool, signer, namespace, access, Arc::new(NoIo)).await,
            Err(StagingError::Unsupported)
        ));
    }
}
