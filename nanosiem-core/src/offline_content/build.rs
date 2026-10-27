// SPDX-License-Identifier: AGPL-3.0-or-later
//! Current tenant parser build inputs, not approval or runtime activation.
use super::{VerifiedContentCatalog, staging::*};
use crate::parsers::tenant_bundle::model::TenantSources;
use uuid::Uuid;

pub struct ContentParserBuildAccess {
    _sealed: (),
    #[cfg(feature = "enterprise")]
    pub(crate) deploy: crate::enterprise_shared_security::AuthorizedTenantSecurity,
    #[cfg(feature = "enterprise")]
    pub(crate) credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
}
impl ContentParserBuildAccess {
    #[cfg(feature = "enterprise")]
    pub fn member(
        deploy: crate::enterprise_shared_security::AuthorizedTenantSecurity,
        credential: crate::enterprise_shared_tenant_credential::TenantCredentialProof,
    ) -> Result<Self, StagingError> {
        if deploy.permission() != "log_sources:deploy"
            || matches!(&credential, crate::enterprise_shared_tenant_credential::TenantCredentialProof::RepositorySchedule { .. }) {
            return Err(StagingError::Denied);
        }
        Ok(Self {
            _sealed: (),
            deploy,
            credential,
        })
    }
}
/// Private input bytes. Deliberately not Debug/Serialize: this is an internal
/// worker input, never a browser response or diagnostic/audit payload.
pub struct ContentParserSources {
    pub(crate) document: TenantSources,
    pub(crate) native_sha256: String,
    pub(crate) rollout_ids: Vec<Uuid>,
    pub(crate) stage_id: Uuid,
    pub(crate) archive_sha256: String,
}
impl ContentParserSources {
    pub fn document(&self) -> &TenantSources {
        &self.document
    }
    /// Digest of native serialization. A Node bridge canonicalizes its own
    /// published document; these are deliberately different byte contracts.
    pub fn native_sha256(&self) -> &str {
        &self.native_sha256
    }
    pub fn rollout_ids(&self) -> &[Uuid] {
        &self.rollout_ids
    }
    pub fn stage_id(&self) -> Uuid {
        self.stage_id
    }
    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }
}
impl ContentStagingStore {
    pub async fn parser_build_sources(
        &self,
        id: Uuid,
        catalog: &VerifiedContentCatalog,
        access: &ContentParserBuildAccess,
        rollout_ids: &[Uuid],
        read_and_execute: &dyn ContentCommitAuthority,
    ) -> Result<ContentParserSources, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (id, catalog, access, rollout_ids, read_and_execute);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::build::sources(
                self,
                id,
                catalog,
                access,
                rollout_ids,
                read_and_execute,
            )
            .await
        }
    }
}
