// SPDX-License-Identifier: AGPL-3.0-or-later
//! Explicit customer-approved parser catalog import; never runtime deployment.
use super::{ContentKind, VerifiedContentCatalog, staging::*};
use uuid::Uuid;

pub const PARSER_CATALOG_APPROVAL_CONTRACT: &str = "nano.sovereign.parser-catalog-approval.v1";
pub const MAX_PARSER_IMPORTS: usize = 100;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentParserApprovalPayload {
    pub contract: String,
    pub content: ContentApprovalPayload,
    pub import_paths: Vec<String>,
}
pub struct ContentParserApprovalProposal {
    payload: ContentParserApprovalPayload,
    bytes: Vec<u8>,
}
impl ContentParserApprovalProposal {
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }
    pub fn claims(&self) -> &ContentParserApprovalPayload {
        &self.payload
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentParserApplyReceipt {
    pub nonce: Uuid,
    pub archive_sha256: String,
    pub repository_id: Uuid,
    pub imported: u32,
    pub preserved: u32,
}

pub struct ContentParserApplyAccess {
    _sealed: (),
    #[cfg(feature = "enterprise")]
    pub(crate) import: Option<crate::enterprise_shared_security::AuthorizedTenantSecurity>,
    #[cfg(feature = "enterprise")]
    pub(crate) manage: Option<crate::enterprise_shared_security::AuthorizedTenantSecurity>,
    #[cfg(feature = "enterprise")]
    pub(crate) credential:
        Option<crate::enterprise_shared_tenant_credential::TenantCredentialProof>,
}
impl ContentParserApplyAccess {
    pub fn catalog_only() -> Self {
        Self {
            _sealed: (),
            #[cfg(feature = "enterprise")]
            import: None,
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
        if manage.permission() != "parser_repositories:manage" || matches!(&credential, crate::enterprise_shared_tenant_credential::TenantCredentialProof::RepositorySchedule {..}) {
            return Err(StagingError::Denied);
        }
        Ok(Self {
            _sealed: (),
            import: None,
            manage: Some(manage),
            credential: Some(credential),
        })
    }
    #[cfg(feature = "enterprise")]
    pub fn member(
        import: crate::enterprise_shared_security::AuthorizedTenantSecurity,
        manage: Option<crate::enterprise_shared_security::AuthorizedTenantSecurity>,
        credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
    ) -> Result<Self, StagingError> {
        if import.permission() != "parser_repositories:import"
            || manage.as_ref().is_some_and(|a| a.permission() != "parser_repositories:manage")
            || matches!(&credential, crate::enterprise_shared_tenant_credential::TenantCredentialProof::RepositorySchedule {..}) {
            return Err(StagingError::Denied);
        }
        Ok(Self {
            _sealed: (),
            import: Some(import),
            manage,
            credential: Some(credential),
        })
    }
}
impl ContentStagingStore {
    pub async fn prepare_parser_approval(
        &self,
        id: Uuid,
        catalog: &VerifiedContentCatalog,
        import_paths: &[String],
        authority: &dyn ContentCommitAuthority,
    ) -> Result<ContentParserApprovalProposal, StagingError> {
        if catalog.provenance().kind != ContentKind::Parsers {
            return Err(StagingError::Denied);
        }
        let mut paths = import_paths.to_vec();
        paths.sort();
        if paths.len() > MAX_PARSER_IMPORTS
            || paths.windows(2).any(|p| p[0] == p[1])
            || paths
                .iter()
                .any(|p| !catalog.files().iter().any(|f| &f.path == p))
        {
            return Err(StagingError::Invalid);
        }
        let base = self.prepare_approval(id, catalog, &[], authority).await?;
        let payload = ContentParserApprovalPayload {
            contract: PARSER_CATALOG_APPROVAL_CONTRACT.into(),
            content: base.claims().clone(),
            import_paths: paths,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| StagingError::Invalid)?;
        if bytes.len() > MAX_CONTENT_APPROVAL_BYTES {
            return Err(StagingError::Capacity);
        }
        Ok(ContentParserApprovalProposal { payload, bytes })
    }
    pub async fn apply_parsers(
        &self,
        payload: &[u8],
        catalog: &VerifiedContentCatalog,
        access: &ContentParserApplyAccess,
        approval: &dyn ContentCommitAuthority,
    ) -> Result<ContentParserApplyReceipt, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (payload, catalog, access, approval);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::parser_apply::apply(
                self, payload, catalog, access, approval,
            )
            .await
        }
    }
    pub async fn parser_apply_receipt(
        &self,
        nonce: Uuid,
    ) -> Result<Option<ContentParserApplyReceipt>, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = nonce;
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::parser_apply::read_receipt(self, nonce).await
        }
    }
}
