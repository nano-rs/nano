// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native parser head protocol. Public claims are never execution authority.
use super::{build::ContentParserBuildAccess, staging::*};
use uuid::Uuid;

pub const PARSER_RUNTIME_APPROVAL: &str = "nano.sovereign.parser-runtime-approval.v2";
pub const PARSER_RUNTIME_HEAD: &str = "nano.sovereign.parser-runtime-head.v1";
pub const MAX_RUNTIME_APPROVAL_BYTES: usize = 16 * 1024;

/// Retention proof checked INSIDE the native head CAS transaction, after the
/// predecessor check and before any head, nonce or audit write. The root
/// supplies an implementation bound to exact durable retention holds on the
/// approved candidate's artifacts (C12 CP15: C13 exact-nonce holds), which
/// must stay locked through this transaction's COMMIT. `candidate` and `nonce`
/// are taken from the parsed, scope-checked approval payload; an
/// implementation must refuse unless its holds bind exactly those. It must be
/// read-only and never release anything. No default or no-op is supplied.
#[async_trait::async_trait]
pub trait ParserRuntimeRetention: Send + Sync {
    async fn check_in(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        candidate: &ParserRuntimeCandidate,
        nonce: Uuid,
    ) -> Result<(), StagingError>;
}

/// H06 lease-row liveness (C14 Step 0 option b), checked INSIDE the native
/// head CAS transaction after the predecessor check and before
/// [`ParserRuntimeRetention`]. Global lock order: onboarding credential →
/// parser head → slot grant → lease row → C13 holds/objects → ingest cells.
///
/// The root supplies an implementation over the H06 lease row (keyed by
/// tenant + host + slot) that takes the slot grant through
/// `nano_shared.sovereign_slot_grant_hold` and the lease row `FOR SHARE`,
/// both held through COMMIT, and refuses unless that row is unexpired by the
/// database clock, not tombstoned, recorded under the ACTIVE grant's
/// sequence and placed exactly at `target` for `tenant_id`. It returns the
/// row's recorded readback FIELDS (never a trusted hash). The CAS itself
/// checks them against the approved candidate and target
/// ([`ParserRuntimeReadback::bound_to`]) and stores their canonical hash in
/// the head. Read-only. No default or no-op is supplied.
#[async_trait::async_trait]
pub trait ParserRuntimeLiveness: Send + Sync {
    async fn check_in(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        target: &ParserRuntimeTarget,
    ) -> Result<ParserRuntimeReadback, StagingError>;
}

/// The placement a customer approves (approval v2): WHAT runs WHERE, never
/// which process or until when. Liveness and the loaded-runtime readback are
/// read from the locked H06 lease row at CAS time
/// ([`ParserRuntimeLiveness`]), so a respawn on the same placement needs no
/// re-approval while a placement change does.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserRuntimeTarget {
    pub host_id: String,
    pub slot_id: String,
    pub placement_revision: u64,
    pub assignment_epoch: u64,
    pub fence_generation: u64,
    pub ingest_cell_id: Uuid,
    pub ingest_cell_generation: u64,
    pub ingest_cell_assignment_revision: u64,
    pub runtime_image_digest: String,
    pub deployment_job_binding_sha256: String,
}
/// Domain of [`ParserRuntimeReadback::canonical_sha256`] (house form).
pub const PARSER_RUNTIME_READBACK_DOMAIN: &[u8] =
    b"nano/sovereign/c14-parser-runtime-readback/v1\0";

/// C14 Step 0 B3: what one live native ingest child accepted, as measured by
/// its supervisor. Built only by the C14 slot actor after the child echoed
/// the exact sealed bytes; recorded into the H06 lease row by fields (never a
/// trusted hash). The C12 head CAS recomputes [`Self::canonical_sha256`] from
/// the locked row. It is not execution authority, and `engine_sha256` is
/// child-attested provenance only: it is never a CAS predicate input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserRuntimeReadback {
    pub tenant_id: Uuid,
    pub host_id: String,
    pub slot_id: String,
    pub placement_revision: u64,
    pub assignment_epoch: u64,
    pub fence_generation: u64,
    pub ingest_cell_id: Uuid,
    pub ingest_cell_generation: u64,
    pub ingest_cell_assignment_revision: u64,
    pub runtime_image_digest: String,
    pub deployment_job_binding_sha256: String,
    pub grant_sequence: u64,
    pub counter: u64,
    pub process_instance: u128,
    pub statement_sha256: String,
    pub content_sha256: String,
    pub engine_sha256: String,
}
impl ParserRuntimeReadback {
    /// SHA-256 over the domain and every field in this fixed order, each
    /// u32-BE length-prefixed (UUIDs 16 bytes, integers big-endian, strings
    /// UTF-8). One function for C14 (record) and C12 (CAS recompute).
    pub fn canonical_sha256(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(PARSER_RUNTIME_READBACK_DOMAIN);
        let mut field = |bytes: &[u8]| {
            h.update((bytes.len() as u32).to_be_bytes());
            h.update(bytes);
        };
        field(self.tenant_id.as_bytes());
        field(self.host_id.as_bytes());
        field(self.slot_id.as_bytes());
        field(&self.placement_revision.to_be_bytes());
        field(&self.assignment_epoch.to_be_bytes());
        field(&self.fence_generation.to_be_bytes());
        field(self.ingest_cell_id.as_bytes());
        field(&self.ingest_cell_generation.to_be_bytes());
        field(&self.ingest_cell_assignment_revision.to_be_bytes());
        field(self.runtime_image_digest.as_bytes());
        field(self.deployment_job_binding_sha256.as_bytes());
        field(&self.grant_sequence.to_be_bytes());
        field(&self.counter.to_be_bytes());
        field(&self.process_instance.to_be_bytes());
        field(self.statement_sha256.as_bytes());
        field(self.content_sha256.as_bytes());
        field(self.engine_sha256.as_bytes());
        h.finalize().into()
    }
    /// The CAS predicate over a locked lease row's recorded readback: the
    /// exact tenant and approved placement, and the approved candidate's
    /// statement, content and image. `engine_sha256` is provenance only and
    /// is checked for shape, never against anything.
    pub fn bound_to(
        &self,
        tenant_id: Uuid,
        target: &ParserRuntimeTarget,
        candidate: &ParserRuntimeCandidate,
    ) -> bool {
        self.tenant_id == tenant_id
            && !self.tenant_id.is_nil()
            && self.host_id == target.host_id
            && self.slot_id == target.slot_id
            && self.placement_revision == target.placement_revision
            && self.assignment_epoch == target.assignment_epoch
            && self.fence_generation == target.fence_generation
            && self.ingest_cell_id == target.ingest_cell_id
            && self.ingest_cell_generation == target.ingest_cell_generation
            && self.ingest_cell_assignment_revision == target.ingest_cell_assignment_revision
            && self.runtime_image_digest == target.runtime_image_digest
            && self.runtime_image_digest == candidate.runtime_image_digest
            && self.deployment_job_binding_sha256 == target.deployment_job_binding_sha256
            && self.statement_sha256 == candidate.statement_sha256
            && self.content_sha256 == candidate.content_sha256
            && self.grant_sequence != 0
            && self.counter != 0
            && self.process_instance != 0
            && runtime_digest(&self.engine_sha256)
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserRuntimeCandidate {
    pub stage_id: Uuid,
    pub archive_sha256: String,
    pub statement_sha256: String,
    pub content_sha256: String,
    pub report_sha256: String,
    pub native_sources_sha256: String,
    pub build_job_binding_sha256: String,
    pub runtime_image_digest: String,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserRuntimePredecessor {
    pub revision: u64,
    pub nonce: Uuid,
    pub state_sha256: String,
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserRuntimeApprovalPayload {
    pub contract: String,
    pub installation_id: String,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub namespace_sha256: String,
    pub authority_epochs: [u64; 4],
    pub candidate: ParserRuntimeCandidate,
    pub target: ParserRuntimeTarget,
    pub predecessor: Option<ParserRuntimePredecessor>,
    pub nonce: Uuid,
    pub issued_at: i64,
    pub expires_at: i64,
}
pub struct ParserRuntimeApprovalProposal {
    pub(crate) claims: ParserRuntimeApprovalPayload,
    pub(crate) bytes: Vec<u8>,
}
impl ParserRuntimeApprovalProposal {
    pub fn claims(&self) -> &ParserRuntimeApprovalPayload {
        &self.claims
    }
    pub fn payload(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserRuntimeHead {
    pub contract: String,
    pub revision: u64,
    pub nonce: Uuid,
    pub stage_id: Uuid,
    pub candidate: ParserRuntimeCandidate,
    pub target: ParserRuntimeTarget,
    pub predecessor_revision: u64,
    pub predecessor_nonce: Option<Uuid>,
    pub approval_sha256: String,
    /// [`ParserRuntimeReadback::canonical_sha256`] of the lease row's
    /// readback locked by this CAS. Evidence of what was live at COMMIT; the
    /// head binds a candidate and a placement, never a process.
    pub observed_readback_sha256: String,
}

pub(crate) fn runtime_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl ParserRuntimeCandidate {
    pub fn validate(&self) -> Result<(), StagingError> {
        if self.stage_id.is_nil()
            || [
                &self.archive_sha256,
                &self.statement_sha256,
                &self.content_sha256,
                &self.report_sha256,
                &self.native_sources_sha256,
                &self.build_job_binding_sha256,
            ]
            .iter()
            .any(|s| !runtime_digest(s))
            || !self
                .runtime_image_digest
                .strip_prefix("sha256:")
                .is_some_and(runtime_digest)
        {
            return Err(StagingError::Invalid);
        }
        Ok(())
    }
}
impl ParserRuntimeTarget {
    pub fn validate(&self) -> Result<(), StagingError> {
        if [&self.host_id, &self.slot_id].iter().any(|s| {
            s.is_empty()
                || s.len() > 128
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        }) || [
            self.placement_revision,
            self.assignment_epoch,
            self.fence_generation,
            self.ingest_cell_generation,
            self.ingest_cell_assignment_revision,
        ]
        .iter()
        .any(|n| *n == 0 || *n > 9_007_199_254_740_991)
            || self.ingest_cell_id.is_nil()
            || !runtime_digest(&self.deployment_job_binding_sha256)
            || !self
                .runtime_image_digest
                .strip_prefix("sha256:")
                .is_some_and(runtime_digest)
        {
            return Err(StagingError::Invalid);
        }
        Ok(())
    }
}
impl ContentStagingStore {
    /// Protected point-in-time metadata, never an installed-runtime lease.
    /// An expected head must still match while the supplied current read
    /// authority is checked under the namespace/head transaction locks.
    pub async fn read_parser_runtime_head(
        &self,
        expected: Option<&ParserRuntimeHead>,
        authority: &dyn ContentCommitAuthority,
    ) -> Result<Option<ParserRuntimeHead>, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (expected, authority);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::runtime::read_head(self, expected, authority)
                .await
        }
    }

    /// Proposal only; the root must obtain an actual held placement fence and
    /// current runtime candidate. This does not consume an approval.
    pub async fn prepare_parser_runtime_approval(
        &self,
        candidate: &ParserRuntimeCandidate,
        target: &ParserRuntimeTarget,
        access: &ContentParserBuildAccess,
        authority: &dyn ContentCommitAuthority,
    ) -> Result<ParserRuntimeApprovalProposal, StagingError> {
        candidate.validate()?;
        target.validate()?;
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (access, authority);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::runtime::prepare(
                self, candidate, target, access, authority,
            )
            .await
        }
    }
    /// This performs ONLY a fenced head CAS. It never dispatches a worker or
    /// reconstructs execution authority from a serialized result.
    pub async fn commit_parser_runtime_head(
        &self,
        payload: &[u8],
        access: &ContentParserBuildAccess,
        authority: &dyn ContentCommitAuthority,
        liveness: &dyn ParserRuntimeLiveness,
        retention: &dyn ParserRuntimeRetention,
    ) -> Result<ParserRuntimeHead, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (payload, access, authority, liveness, retention);
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::runtime::commit(
                self, payload, access, authority, liveness, retention,
            )
            .await
        }
    }
    /// Reconcile a possibly committed nonce without repeating any effect.
    pub async fn parser_runtime_receipt(
        &self,
        nonce: Uuid,
    ) -> Result<Option<ParserRuntimeHead>, StagingError> {
        #[cfg(not(feature = "enterprise"))]
        {
            let _ = nonce;
            Err(StagingError::Unsupported)
        }
        #[cfg(feature = "enterprise")]
        {
            crate::enterprise_shared_content_staging::runtime::receipt(self, nonce).await
        }
    }
}
