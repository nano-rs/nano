// SPDX-License-Identifier: AGPL-3.0-or-later

//! Async search job registry
//!
//! This module provides pluggable storage for async search jobs via the
//! `SearchJobStore` trait. Two implementations are available:
//! - `InMemoryJobStore` — DashMap-backed, single-instance (default for tests)
//! - `RedisJobStore` — Redis-backed, multi-instance (active/active deployments)

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::auth::ScopeSet;

use super::admission::QueryPriority;
use super::job_signing::{
    DurableJobSignedRecord, DurableJobSigningError, DurableJobSigningKey, JOB_SIGNATURE_FIELD,
};
use super::tenant::SearchTenantScope;
use super::types::{SearchRequest, SearchResponse, TimeRangeInput};

/// Maximum number of concurrent jobs
const MAX_JOBS: usize = 1000;

/// Truncate a stored query for a job-list preview WITHOUT panicking on a
/// non-char-boundary byte offset.
///
/// NAN-2010 (F12/F15/F16/F17/F25): the client query is stored verbatim (before
/// any parse), and the previews sliced it with `&query[..97]` guarded only by a
/// byte-length check. A multibyte UTF-8 character straddling byte 97 made the
/// slice panic — and because `list_all` enumerates every user's jobs, an
/// unprivileged user's crafted query persistently broke `/api/search/admin/jobs`
/// for admins (cross-user DoS). Cut at the largest char boundary at or below 97.
pub(super) fn truncate_query_preview(query: &str) -> String {
    if query.len() <= 100 {
        return query.to_string();
    }
    let mut end = 97;
    while end > 0 && !query.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &query[..end])
}

/// TTL for completed/failed jobs (5 minutes)
const COMPLETED_JOB_TTL: Duration = Duration::from_secs(300);
const DURABLE_COMPLETED_JOB_TTL: Duration = Duration::from_secs(86_400);

/// Status of an async search job
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchJobStatus {
    /// Job is waiting in the admission queue
    Queued,
    /// Job is currently executing
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed with an error
    Failed,
    /// Job was cancelled by the user
    Cancelled,
}

/// Execution backend for an asynchronous search job.
///
/// `Inline` preserves the existing short-query behavior during the ClickHouse
/// migration. `LakeDurable` is claimed by an isolated runner and stores only a
/// result-manifest reference in the job store.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchJobBackend {
    Inline,
    LakeDurable,
}

impl std::fmt::Display for SearchJobBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inline => write!(f, "inline"),
            Self::LakeDurable => write!(f, "lake_durable"),
        }
    }
}

impl std::str::FromStr for SearchJobBackend {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "" | "inline" => Ok(Self::Inline),
            "lake_durable" => Ok(Self::LakeDurable),
            _ => Err(format!("unknown search-job backend: {value}")),
        }
    }
}

/// Immutable pointer to a manifest-last, paged result artifact.
///
/// The URI identifies a deployment-owned object-store location. Callers never
/// provide it, and the read API verifies the digest and the job's current
/// authorization scope before exposing any page.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchJobResultRef {
    /// Server-resolved shared tenant. Dedicated/open-core pointers remain
    /// tenantless for wire compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    pub manifest_uri: String,
    pub manifest_sha256: String,
    pub rows: u64,
    pub parts: usize,
    /// True when the durable operation deliberately stopped at a bounded
    /// result envelope. Retained for old manifests as false by default.
    #[serde(default)]
    pub has_more: bool,
    #[serde(default = "default_durable_result_page_rows")]
    pub page_rows: usize,
    /// Server-authored proof that bounds every event which could have
    /// contributed to this frozen result. Shared results without this receipt
    /// are deliberately unreadable; dedicated/open-core results remain
    /// byte-compatible with `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_proof: Option<DurableResultRetentionProof>,
}

impl SearchJobResultRef {
    pub fn verify_tenant(&self, tenant: SearchTenantScope) -> Result<(), DurableJobStoreError> {
        tenant
            .verify_stored_tenant(self.tenant_id)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        match (tenant, self.retention_proof.as_ref()) {
            (SearchTenantScope::Dedicated, None) => Ok(()),
            (SearchTenantScope::EnterpriseSharedRetained { .. }, Some(proof)) => {
                proof.verify_identity(tenant)
            }
            _ => Err(DurableJobStoreError::Invalid(
                "durable result retention proof does not match its tenant scope".to_string(),
            )),
        }
    }

    /// Re-evaluate the moving frontier at read time. A result is valid only
    /// while its oldest possible contributing event remains inside the
    /// tenant's current retention window.
    pub fn verify_retention_at(
        &self,
        tenant: SearchTenantScope,
        now: DateTime<Utc>,
    ) -> Result<(), DurableJobStoreError> {
        self.verify_tenant(tenant)?;
        let Some(proof) = self.retention_proof.as_ref() else {
            return Ok(());
        };
        proof.verify_current(tenant, now)
    }

    pub fn verify_retention_for_range(
        &self,
        tenant: SearchTenantScope,
        range: &TimeRangeInput,
        now: DateTime<Utc>,
    ) -> Result<(), DurableJobStoreError> {
        self.verify_retention_at(tenant, now)?;
        let Some(proof) = self.retention_proof.as_ref() else {
            return Ok(());
        };
        if proof.min_event_time_micros < range.start.timestamp_micros()
            || proof.max_event_time_micros != range.end.timestamp_micros()
        {
            return Err(DurableJobStoreError::Invalid(
                "durable result contribution range differs from its admitted request".to_string(),
            ));
        }
        Ok(())
    }
}

/// Immutable moving-retention receipt for a durable query result.
///
/// The contribution bounds are conservative query-input bounds, not a claim
/// that rows existed at both endpoints. This is what makes aggregate results
/// safe: once the moving cutoff passes the minimum bound, the entire frozen
/// artifact is denied rather than leaking an aggregate influenced by expired
/// events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableResultRetentionProof {
    pub retention_revision: i64,
    pub retention_days: u16,
    pub irreversible_event_time_floor_micros: i64,
    pub evaluated_at_micros: i64,
    pub cutoff_micros: i64,
    pub min_event_time_micros: i64,
    pub max_event_time_micros: i64,
}

impl DurableResultRetentionProof {
    pub fn from_shared_job(
        tenant: SearchTenantScope,
        evaluated_at: DateTime<Utc>,
        range: &TimeRangeInput,
    ) -> Result<Self, DurableJobStoreError> {
        let (retention_revision, retention_days, irreversible_event_time_floor_micros) = tenant
            .require_retention_identity()
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let cutoff = tenant.event_time_cutoff(evaluated_at).ok_or_else(|| {
            DurableJobStoreError::Invalid(
                "durable result has no shared retention cutoff".to_string(),
            )
        })?;
        let proof = Self {
            retention_revision,
            retention_days,
            irreversible_event_time_floor_micros,
            evaluated_at_micros: evaluated_at.timestamp_micros(),
            cutoff_micros: cutoff.timestamp_micros(),
            min_event_time_micros: range.start.timestamp_micros(),
            max_event_time_micros: range.end.timestamp_micros(),
        };
        proof.verify_current(tenant, evaluated_at)?;
        Ok(proof)
    }

    /// NAN-3078: the earliest event time an execution of the proven job may
    /// read at `now`, derived from the proof's own retention identity so the
    /// executing cell (which holds no tenant policy) can enforce it. The proof
    /// must be internally consistent: its cutoff is exactly the policy's cutoff
    /// at evaluation and its contribution range starts at or after it. The
    /// floor only moves forward with `now`, so a queued job that waited past
    /// the cutoff reads less, never more.
    pub fn execution_floor(&self, now: DateTime<Utc>) -> Result<DateTime<Utc>, DurableJobStoreError> {
        let invalid = || DurableJobStoreError::Invalid("durable job retention proof is invalid".to_string());
        if self.retention_revision <= 0
            || !matches!(self.retention_days, 30 | 90 | 180 | 365)
            || self.irreversible_event_time_floor_micros < 0
            || self.min_event_time_micros < self.cutoff_micros
            || self.max_event_time_micros <= self.min_event_time_micros
        {
            return Err(invalid());
        }
        let cutoff_at = |at: DateTime<Utc>| {
            let rolling = at - chrono::Duration::days(i64::from(self.retention_days));
            DateTime::from_timestamp_micros(self.irreversible_event_time_floor_micros)
                .map(|irreversible| rolling.max(irreversible))
        };
        let evaluated_at = DateTime::from_timestamp_micros(self.evaluated_at_micros).ok_or_else(invalid)?;
        if cutoff_at(evaluated_at).ok_or_else(invalid)?.timestamp_micros() != self.cutoff_micros {
            return Err(invalid());
        }
        let current = cutoff_at(now.max(evaluated_at)).ok_or_else(invalid)?;
        let admitted = DateTime::from_timestamp_micros(self.min_event_time_micros).ok_or_else(invalid)?;
        Ok(current.max(admitted))
    }

    fn verify_identity(&self, tenant: SearchTenantScope) -> Result<(), DurableJobStoreError> {
        let (revision, days, floor_micros) = tenant
            .require_retention_identity()
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let evaluated_at = DateTime::from_timestamp_micros(self.evaluated_at_micros)
            .ok_or_else(|| DurableJobStoreError::Invalid("retention proof time is invalid".to_string()))?;
        let expected_cutoff = tenant.event_time_cutoff(evaluated_at).ok_or_else(|| {
            DurableJobStoreError::Invalid("retention proof cutoff is unavailable".to_string())
        })?;
        if self.retention_revision != revision
            || self.retention_days != days
            || self.irreversible_event_time_floor_micros != floor_micros
            || self.cutoff_micros != expected_cutoff.timestamp_micros()
            || self.min_event_time_micros < self.cutoff_micros
            || self.max_event_time_micros <= self.min_event_time_micros
        {
            return Err(DurableJobStoreError::Invalid(
                "durable result retention proof is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_current(
        &self,
        tenant: SearchTenantScope,
        now: DateTime<Utc>,
    ) -> Result<(), DurableJobStoreError> {
        self.verify_identity(tenant)?;
        let current_cutoff = tenant.event_time_cutoff(now).ok_or_else(|| {
            DurableJobStoreError::Invalid("current retention cutoff is unavailable".to_string())
        })?;
        if self.min_event_time_micros < current_cutoff.timestamp_micros() {
            return Err(DurableJobStoreError::Invalid(
                "durable result has crossed the current retention cutoff".to_string(),
            ));
        }
        Ok(())
    }
}

/// One verified page from a durable query result artifact. Object-store
/// coordinates remain server-side; the API exposes only rows and pagination.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchJobResultPage {
    pub page: usize,
    pub pages: usize,
    pub total_rows: u64,
    pub row_offset: u64,
    pub rows: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchJobResultSummary {
    pub rows: u64,
    pub pages: usize,
    pub page_rows: usize,
    #[serde(default)]
    pub has_more: bool,
}

const fn default_durable_result_page_rows() -> usize {
    10_000
}

/// Immutable event-generation identity captured when a durable lake job is
/// admitted. Risk/prevalence publication and runner sizing are deliberately
/// outside this fence; the event snapshot, derivatives, compiler, and native
/// query runtime are not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableLakeGenerationPin {
    pub generation_id: String,
    pub event_config_sha256: String,
    pub snapshot_id: i64,
    /// Exact Iceberg metadata object selected by the admitted generation.
    ///
    /// Older queued jobs legitimately omit this during a rolling upgrade. A
    /// runner can still execute them from the content-addressed event config,
    /// but fleet metadata GC must fail closed until they leave the active set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iceberg_metadata_location: Option<String>,
    pub compiler_sha256: String,
    pub native_artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_snapshot_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hot_tail_id: Option<String>,
}

impl DurableLakeGenerationPin {
    /// The zero-snapshot bootstrap generation (NAN-2361 wave 8): snapshot 0
    /// under an `event-0-<config>` identity. Nothing else may carry snapshot 0.
    pub fn is_bootstrap(&self) -> bool {
        self.snapshot_id == 0 && self.generation_id.starts_with("event-0-")
    }

    pub fn validate(&self) -> Result<(), DurableJobStoreError> {
        let id_ok = !self.generation_id.is_empty()
            && self.generation_id.len() <= 256
            && self
                .generation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        let digests_ok = [
            self.event_config_sha256.as_str(),
            self.compiler_sha256.as_str(),
            self.native_artifact_sha256.as_str(),
        ]
        .into_iter()
        .all(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        let tail_digest_ok = self
            .hot_tail_manifest_sha256
            .as_deref()
            .is_none_or(valid_sha256);
        let tail_id_ok = self.hot_tail_id.as_deref().is_none_or(valid_sha256);
        // NAN-2361 wave 8: the bootstrap generation of an empty Iceberg table
        // is snapshot 0 with an `event-0-…` identity, and its signed hot tail
        // is pinned at 0 too. It is admitted so an empty (or hot-tail-only)
        // tenant searches and gets zero rows instead of an outage; every real
        // generation still needs a positive snapshot.
        let bootstrap = self.is_bootstrap();
        let tail_pair_ok = matches!(
            (&self.hot_tail_manifest_sha256, self.hot_tail_snapshot_id, bootstrap),
            (None, None, _) | (Some(_), Some(1..), _) | (Some(_), Some(0), true)
        ) && (self.hot_tail_manifest_sha256.is_some()
            || self.hot_tail_id.is_none());
        let snapshot_ok = self.snapshot_id > 0 || bootstrap;
        let metadata_location_ok = self
            .iceberg_metadata_location
            .as_deref()
            .is_none_or(valid_iceberg_metadata_location);
        if !id_ok
            || !digests_ok
            || !metadata_location_ok
            || !tail_digest_ok
            || !tail_id_ok
            || !tail_pair_ok
            || !snapshot_ok
        {
            return Err(DurableJobStoreError::Invalid(
                "durable lake generation pin is invalid".to_string(),
            ));
        }
        Ok(())
    }
}

fn valid_iceberg_metadata_location(value: &str) -> bool {
    let Some((table, name)) = value.rsplit_once("/metadata/") else {
        return false;
    };
    value.len() <= 2_048
        && value.starts_with("s3://")
        && table.len() > "s3://".len()
        && !value.chars().any(char::is_control)
        && !name.is_empty()
        && !name.contains('/')
        && name.ends_with(".metadata.json")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// One atomically fenced lease returned to a durable lake runner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableSearchJobClaim {
    pub job_id: String,
    pub tenant_id: Option<Uuid>,
    pub attempt: u32,
    pub fence: u64,
    pub lease_owner: String,
    pub lease_expires_at_ms: i64,
    pub request: SearchRequest,
    pub user_id: Uuid,
    pub priority: QueryPriority,
    pub scope_deny: BTreeSet<String>,
    pub scope_artifact_deny: BTreeSet<String>,
    /// Exact shared-session authority captured atomically with admission.
    /// Dedicated jobs carry `None`; shared jobs must carry `Some` and the
    /// runner revalidates it before execution, on every lease heartbeat, and
    /// before result publication.
    pub authority: Option<DurableSearchJobAuthority>,
    pub generation_pin: DurableLakeGenerationPin,
    /// Closed, server-authored operation dispatched by the isolated worker.
    /// Public callers can submit nPL, but cannot manufacture product-task
    /// payloads or storage coordinates.
    pub task: DurableLakeTask,
    /// Deployment-owned execution class. API callers cannot select this; the
    /// durable coordinator promotes it only after a typed resource failure.
    pub resource_class: DurableQueryResourceClass,
}

/// Immutable authority provenance for enterprise-shared durable work.
///
/// This contains identifiers and revision numbers only, never bearer tokens or
/// secrets. The credential union prevents an automation key from being
/// interpreted as a browser session or inheriting its owner's authority.
/// Roles/permissions are the server-resolved sets whose exact equality is
/// checked before a worker is allowed to consume shared resources.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurableSearchCredentialAuthority {
    Session {
        access_jti: Uuid,
        credential_time_micros: i64,
    },
    TenantAutomationKey {
        key_id: Uuid,
        owner_user_id: Uuid,
        key_revision: i64,
        issued_at_micros: i64,
        expires_at_micros: Option<i64>,
        tenant_slug: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableSearchJobAuthority {
    pub tenant_id: Uuid,
    /// Exact acting credential: user ID for a session, key ID for automation.
    pub user_id: Uuid,
    pub credential: DurableSearchCredentialAuthority,
    pub membership_authority_revision: i64,
    pub entitlement_assignment_revision: i64,
    pub retention_revision: i64,
    pub retention_days: u16,
    pub irreversible_event_time_floor_micros: i64,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl DurableSearchJobAuthority {
    pub fn validate_for(
        &self,
        tenant: SearchTenantScope,
        user_id: Uuid,
    ) -> Result<(), DurableJobStoreError> {
        let credential_valid = match &self.credential {
            DurableSearchCredentialAuthority::Session {
                access_jti,
                credential_time_micros,
            } => *access_jti != Uuid::nil() && *credential_time_micros > 0,
            DurableSearchCredentialAuthority::TenantAutomationKey {
                key_id,
                owner_user_id,
                key_revision,
                issued_at_micros,
                expires_at_micros,
                tenant_slug,
            } => {
                *key_id == self.user_id
                    && *key_id != Uuid::nil()
                    && *owner_user_id != Uuid::nil()
                    && *owner_user_id != *key_id
                    && *key_revision > 0
                    && *issued_at_micros > 0
                    && expires_at_micros.is_none_or(|value| value > *issued_at_micros)
                    && !tenant_slug.is_empty()
                    && tenant_slug.len() <= 63
                    && tenant_slug.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }
        };
        if self.user_id != user_id
            || self.user_id == Uuid::nil()
            || !credential_valid
            || self.membership_authority_revision <= 0
            || self.entitlement_assignment_revision <= 0
            || self.retention_revision <= 0
            || self.irreversible_event_time_floor_micros < 0
            || !matches!(self.retention_days, 30 | 90 | 180 | 365)
            || self.roles.len() > 256
            || self.permissions.len() > 4096
        {
            return Err(DurableJobStoreError::Invalid(
                "durable shared authority is invalid".to_string(),
            ));
        }
        let (retention_revision, retention_days, irreversible_event_time_floor_micros) = tenant
            .require_retention_identity()
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        if retention_revision != self.retention_revision
            || retention_days != self.retention_days
            || irreversible_event_time_floor_micros != self.irreversible_event_time_floor_micros
        {
            return Err(DurableJobStoreError::Invalid(
                "durable shared authority retention identity changed".to_string(),
            ));
        }
        tenant
            .verify_stored_tenant(Some(self.tenant_id))
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))
    }
}

impl DurableSearchJobClaim {
    pub fn verify_worker_tenant(
        &self,
        worker_scope: SearchTenantScope,
    ) -> Result<(), DurableJobStoreError> {
        worker_scope
            .verify_stored_tenant(self.tenant_id)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))
    }
}

/// Versioned durable operation. Keep this enum closed: each product task has
/// its own validator and produces a typed object-store artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DurableLakeTask {
    SearchNplV1,
    /// Server-authored interactive admission evidence, covered by the job signature.
    SearchNplShedV1 {
        estimated_bytes: u64,
        budget_bytes: u64,
    },
    LateralV1 {
        query: String,
        start_micros: i64,
        end_micros: i64,
    },
    RetroV1 {
        indicators: Vec<String>,
        axis: String,
        submode: String,
        offset: usize,
        limit: usize,
    },
    /// Exact Asset-view totals and facets. The nPL strings are generated by
    /// Nano after validating the typed identifier/identity request; callers
    /// cannot submit this task through the public Search API.
    AssetV1 {
        identifier_field: String,
        identifier_value: String,
        identities: Vec<serde_json::Value>,
        filters: Option<super::types::AssetEventFilters>,
        summary_query: String,
        source_query: String,
        user_query: String,
    },
    /// Complete Asset dossier for entities whose exact event set exceeds the
    /// interactive materialization envelope.
    AssetDossierV1 {
        identifier_field: String,
        identifier_value: String,
        identities: Vec<serde_json::Value>,
        event_query: String,
    },
    /// Complete `| cloud` landing-page aggregate. Query text is generated by
    /// Nano from typed provider/account filters; the public Search API cannot
    /// manufacture this task or supply storage coordinates.
    CloudOverviewV1 {
        provider: Option<String>,
        account: Option<String>,
        identity_query: String,
        service_query: String,
        change_query: String,
        denied_query: String,
        /// Bounded control-plane risk snapshot captured at admission so the
        /// isolated event job produces the same badges without network access.
        risk: Vec<(String, i32, Option<String>)>,
    },
    /// Exact count/facets/resource/user companion for the already-painted
    /// Cloud event page. All queries are generated by Nano from the typed
    /// filters; the public request cannot submit this closed task directly.
    CloudEventsSummaryV1 {
        query: String,
        filters: Option<super::types::CloudEventFilters>,
        queries: DurableCloudEventsSummaryQueries,
        include_panels: bool,
    },
    /// Exact principal-scoped Cloud dossier. The event query is generated by
    /// Nano from typed principal/account/provider inputs; facet filtering and
    /// response assembly remain a closed product operation in the runner.
    CloudDossierV1 {
        principal: String,
        account: Option<String>,
        provider: Option<String>,
        filters: super::service::cloud_dossier::CloudDossierFacetFilters,
        event_query: String,
        risk: Option<(i32, Option<String>)>,
    },
    /// Complete cloud-user chronology and session summary when the principal's
    /// event set cannot be materialized in the interactive lane.
    CloudUserTimelineV1 {
        user: String,
        event_query: String,
    },
    /// Complete cloud entity correlation for one typed user/IP/resource pivot.
    /// Resource matching remains a server-side typed operation because nPL does
    /// not yet expose predicates over OCSF resource-object arrays.
    CloudEntityPivotV1 {
        entity_type: String,
        entity_value: String,
        event_query: String,
    },
    /// NAN-3078: complete `| baseline` for one resolved entity when the
    /// interactive lane cannot finish every dimension inside its wall budget.
    /// The admitted request range is the whole contribution envelope
    /// (`activity_start..incident_end`), so the job's retention proof bounds
    /// the lookback reads too, not only the analyst's current window. All
    /// queries are generated in the runner from these typed inputs.
    BaselineV1 {
        entity_type: String,
        entity_value: String,
        window_days: i64,
        activity_days: i64,
        dims: Option<Vec<String>>,
        incident_start_micros: i64,
        incident_end_micros: i64,
    },
    /// Complete rare-artifact export from one generation-pinned prevalence
    /// snapshot. The runner resolves storage coordinates from its archived
    /// tenant config and streams the result through Parquet pages.
    PrevalenceExportV1 {
        window: String,
        artifact_type: Option<String>,
        max_prevalence: u64,
        format: String,
    },
    /// NAN-3078: a search with top-level Nano-side stages (prevalence,
    /// lookup, inputlookup, identity). The runner executes the job's
    /// `request.query` — the SQL-only candidate prefix, planned exactly as the
    /// interactive lake lane plans it — like `SearchNplV1`. The Nano-side
    /// suffix of `post_query` is applied by Search when the verified result is
    /// read, so the raw candidate pages are never exposed.
    SearchNplPostV1 {
        post_query: String,
        requested_limit: usize,
        requested_offset: usize,
        /// Scan envelope carried over from the interactive refusal, exactly as
        /// `SearchNplShedV1` carries it. Zero when unknown.
        #[serde(default)]
        required_scan_bytes: u64,
    },
}

/// Largest suffix query a `SearchNplPostV1` job may carry.
pub const MAX_DURABLE_POST_QUERY_BYTES: usize = 65_536;
/// Largest caller page (offset + limit) a `SearchNplPostV1` job may carry.
pub const MAX_DURABLE_POST_PAGE_ROWS: usize = 1_000_000;

impl DurableLakeTask {
    pub fn shed_from_resource_error(detail: &str) -> Self {
        let bytes = |key: &str| detail.split(';').find_map(|part| {
            part.trim().strip_prefix(key)?.parse::<u64>().ok()
        });
        // Older workers return only the exhausted resource kind. Preserve their
        // 4 GiB interactive envelope rather than re-admitting them at 1 GiB.
        Self::SearchNplShedV1 {
            estimated_bytes: bytes("estimated_bytes=").unwrap_or(4 << 30),
            budget_bytes: bytes("budget_bytes=").unwrap_or(4 << 30),
        }
    }

    pub fn required_scan_bytes(&self) -> u64 {
        match self {
            Self::SearchNplShedV1 { estimated_bytes, budget_bytes } => (*estimated_bytes).max(*budget_bytes),
            Self::SearchNplPostV1 { required_scan_bytes, .. } => *required_scan_bytes,
            _ => 0,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::SearchNplV1 | Self::SearchNplShedV1 { .. } => "search_npl_v1",
            Self::LateralV1 { .. } => "lateral_v1",
            Self::RetroV1 { .. } => "retro_v1",
            Self::AssetV1 { .. } => "asset_v1",
            Self::AssetDossierV1 { .. } => "asset_dossier_v1",
            Self::CloudOverviewV1 { .. } => "cloud_overview_v1",
            Self::CloudEventsSummaryV1 { .. } => "cloud_events_summary_v1",
            Self::CloudDossierV1 { .. } => "cloud_dossier_v1",
            Self::CloudUserTimelineV1 { .. } => "cloud_user_timeline_v1",
            Self::CloudEntityPivotV1 { .. } => "cloud_entity_pivot_v1",
            Self::BaselineV1 { .. } => "baseline_v1",
            Self::PrevalenceExportV1 { .. } => "prevalence_export_v1",
            Self::SearchNplPostV1 { .. } => "search_npl_post_v1",
        }
    }

    /// NAN-3078: the typed product views a lean cell's query[T] executes
    /// inside the job's retention-bound window, in bounded memory: bounded
    /// aggregate reads, or (Cloud dossier) a streaming fold.
    ///
    /// NAN-3086: Retro runs here too. Every read it issues (the per-indicator
    /// rollups, the pivot slices and the rarity denominator, which sits at the
    /// END of the admitted range) is a sub-window of the admitted range, so
    /// query[T] clamps each one to the proof's current cutoff like any view.
    ///
    /// NAN-3088: Prevalence export runs here too. On a cell it does not read
    /// a generation snapshot: query[T] builds the prevalence window relation
    /// (part partials inside, exact rows at the edges) over the proof's
    /// clamped execution window, so an export whose admitted range crosses
    /// the retention cutoff is exact at the cutoff and never counts an
    /// expired observation. (The gen1 job child keeps its snapshot export.)
    ///
    /// Not here, and so not queued on a shared tenant:
    /// * Cloud user timeline and Cloud entity pivot: their artifacts ARE the
    ///   event set. Asset dossiers use a byte/row-bounded collection and refuse
    ///   oversized reads before committing an artifact.
    pub fn is_lean_view(&self) -> bool {
        matches!(
            self,
            Self::LateralV1 { .. }
                | Self::AssetV1 { .. }
                | Self::AssetDossierV1 { .. }
                | Self::CloudOverviewV1 { .. }
                | Self::CloudEventsSummaryV1 { .. }
                | Self::CloudDossierV1 { .. }
                | Self::BaselineV1 { .. }
                | Self::RetroV1 { .. }
                | Self::PrevalenceExportV1 { .. }
        )
    }

    pub fn validate(&self) -> Result<(), DurableJobStoreError> {
        match self {
            Self::SearchNplV1 | Self::SearchNplShedV1 { .. } => Ok(()),
            Self::LateralV1 { query, start_micros, end_micros } => {
                if start_micros >= end_micros || chrono::DateTime::from_timestamp_micros(*start_micros).is_none()
                    || chrono::DateTime::from_timestamp_micros(*end_micros).is_none() {
                    return Err(DurableJobStoreError::Invalid("Invalid durable Lateral window".into()));
                }
                super::validate_lake_lateral_job(query).map_err(|error| DurableJobStoreError::Invalid(error.to_string()))
            }
            Self::RetroV1 {
                indicators,
                axis,
                submode,
                offset,
                limit,
            } => {
                let indicators_ok = !indicators.is_empty()
                    && indicators.len() <= 1_000
                    && indicators.iter().all(|value| {
                        !value.is_empty()
                            && value.len() <= 2_048
                            && !value.chars().any(char::is_control)
                    });
                let shape_ok = matches!(
                    (axis.as_str(), submode.as_str(), indicators.len()),
                    ("indicator", "summary", 1)
                        | ("indicator", "list", _)
                        | ("asset" | "user", "pivot", _)
                );
                if !indicators_ok
                    || !shape_ok
                    || *limit == 0
                    || *limit > 500
                    || offset.saturating_add(*limit) > 1_000_000
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable retro task violates its indicator, axis, mode, or page contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::AssetV1 {
                identifier_field,
                identifier_value,
                identities,
                filters,
                summary_query,
                source_query,
                user_query,
            } => {
                const ASSET_FIELDS: &[&str] = &[
                    "src_endpoint.hostname",
                    "dst_endpoint.hostname",
                    "device.hostname",
                    "src_endpoint.ip",
                    "dst_endpoint.ip",
                    "user.name",
                    "actor.user.name",
                    "src_endpoint.mac",
                    "dst_endpoint.mac",
                ];
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                let query_ok = |query: &str| text_ok(query, 65_536);
                let identities_bytes = serde_json::to_vec(identities)
                    .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?
                    .len();
                let filters_bytes = serde_json::to_vec(filters)
                    .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?
                    .len();
                if !ASSET_FIELDS.contains(&identifier_field.as_str())
                    || !text_ok(identifier_value, 2_048)
                    || identities.len() > 200
                    || identities_bytes > 262_144
                    || filters_bytes > 65_536
                    || !query_ok(summary_query)
                    || !query_ok(source_query)
                    || !query_ok(user_query)
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable asset task violates its identifier, identity, or query contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::AssetDossierV1 {
                identifier_field,
                identifier_value,
                identities,
                event_query,
            } => {
                const ASSET_FIELDS: &[&str] = &[
                    "src_endpoint.hostname",
                    "dst_endpoint.hostname",
                    "device.hostname",
                    "src_endpoint.ip",
                    "dst_endpoint.ip",
                    "user.name",
                    "actor.user.name",
                    "src_endpoint.mac",
                    "dst_endpoint.mac",
                ];
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                let identities_bytes = serde_json::to_vec(identities)
                    .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?
                    .len();
                if !ASSET_FIELDS.contains(&identifier_field.as_str())
                    || !text_ok(identifier_value, 2_048)
                    || identities.len() > 200
                    || identities_bytes > 262_144
                    || !text_ok(event_query, 65_536)
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable Asset dossier violates its identifier, identity, or query contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::CloudOverviewV1 {
                provider,
                account,
                identity_query,
                service_query,
                change_query,
                denied_query,
                risk,
            } => {
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                let filter_ok = |value: &Option<String>| {
                    value.as_deref().is_none_or(|value| text_ok(value, 2_048))
                };
                if !filter_ok(provider)
                    || !filter_ok(account)
                    || [identity_query, service_query, change_query, denied_query]
                        .iter()
                        .any(|query| !text_ok(query, 65_536))
                    || risk.len() > 1_000
                    || risk.iter().any(|(entity, score, rule)| {
                        !text_ok(entity, 4_096)
                            || !(0..=1_000_000).contains(score)
                            || rule.as_deref().is_some_and(|rule| !text_ok(rule, 4_096))
                    })
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable cloud overview violates its filter, query, or risk contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::CloudEventsSummaryV1 {
                query,
                filters,
                queries,
                ..
            } => {
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                let filter_values_ok = |values: &Option<Vec<String>>| {
                    values.as_ref().is_none_or(|values| {
                        values.len() <= 100 && values.iter().all(|value| text_ok(value, 2_048))
                    })
                };
                let filters_ok = filters.as_ref().is_none_or(|filters| {
                    filter_values_ok(&filters.cloud_providers)
                        && filter_values_ok(&filters.cloud_services)
                        && filter_values_ok(&filters.cloud_regions)
                        && filter_values_ok(&filters.cloud_account_ids)
                        && filter_values_ok(&filters.resource_types)
                        && filter_values_ok(&filters.change_types)
                        && filters
                            .search_text
                            .as_deref()
                            .is_none_or(|value| text_ok(value, 4_096))
                });
                if !text_ok(query, 65_536)
                    || !filters_ok
                    || queries.all().iter().any(|query| !text_ok(query, 65_536))
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable Cloud event summary violates its filter or query contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::CloudDossierV1 {
                principal,
                account,
                provider,
                filters,
                event_query,
                risk,
            } => {
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                let optional_ok = |value: &Option<String>| {
                    value.as_deref().is_none_or(|value| text_ok(value, 2_048))
                };
                let facet_ok = |values: &[String]| {
                    values.len() <= 100 && values.iter().all(|value| text_ok(value, 2_048))
                };
                if !text_ok(principal, 4_096)
                    || !optional_ok(account)
                    || !optional_ok(provider)
                    || !facet_ok(&filters.services)
                    || !facet_ok(&filters.regions)
                    || !facet_ok(&filters.accounts)
                    || !facet_ok(&filters.resource_types)
                    || !facet_ok(&filters.change_types)
                    || !text_ok(event_query, 65_536)
                    || risk.as_ref().is_some_and(|(score, rule)| {
                        !(0..=1_000_000).contains(score)
                            || rule.as_deref().is_some_and(|rule| !text_ok(rule, 4_096))
                    })
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable Cloud dossier violates its scope, facet, query, or risk contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::CloudUserTimelineV1 { user, event_query } => {
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                if !text_ok(user, 4_096) || !text_ok(event_query, 65_536) {
                    return Err(DurableJobStoreError::Invalid(
                        "durable Cloud user timeline violates its user or query contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::CloudEntityPivotV1 {
                entity_type,
                entity_value,
                event_query,
            } => {
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                if !matches!(entity_type.as_str(), "user" | "ip" | "resource")
                    || !text_ok(entity_value, 4_096)
                    || !text_ok(event_query, 65_536)
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable Cloud entity pivot violates its entity or query contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::BaselineV1 {
                entity_type,
                entity_value,
                window_days,
                activity_days,
                dims,
                incident_start_micros,
                incident_end_micros,
            } => {
                let text_ok = |value: &str, max: usize| {
                    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
                };
                let incident = incident_end_micros.saturating_sub(*incident_start_micros);
                if !matches!(entity_type.as_str(), "host" | "user" | "ip")
                    || !text_ok(entity_value, 512)
                    || !(1..=90).contains(window_days)
                    || !(1..=365).contains(activity_days)
                    || dims.as_ref().is_some_and(|dims| {
                        dims.is_empty() || dims.len() > 16 || dims.iter().any(|dim| !text_ok(dim, 128))
                    })
                    || *incident_start_micros <= 0
                    || incident <= 0
                    || incident > 7 * 86_400_000_000
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable baseline violates its entity, window, dimension, or incident contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::PrevalenceExportV1 {
                window,
                artifact_type,
                max_prevalence,
                format,
            } => {
                if !matches!(window.as_str(), "1h" | "24h" | "7d" | "30d")
                    || !matches!(
                        artifact_type.as_deref(),
                        None | Some("hash" | "domain" | "ip")
                    )
                    || *max_prevalence > 1_000_000
                    || !matches!(format.as_str(), "csv" | "json")
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable Prevalence export violates its window, type, prevalence, or format contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
            Self::SearchNplPostV1 {
                post_query,
                requested_limit,
                requested_offset,
                required_scan_bytes: _,
            } => {
                let query_ok = !post_query.trim().is_empty()
                    && post_query.len() <= MAX_DURABLE_POST_QUERY_BYTES
                    && !post_query
                        .chars()
                        .any(|character| character.is_control() && !character.is_whitespace());
                if !query_ok
                    || *requested_limit == 0
                    || requested_offset.saturating_add(*requested_limit) > MAX_DURABLE_POST_PAGE_ROWS
                {
                    return Err(DurableJobStoreError::Invalid(
                        "durable post-processed search violates its query or page contract"
                            .to_string(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Tasks whose runner work is one compiled nPL statement over
    /// `request.query`, committed as ordinary result pages.
    pub fn is_search(&self) -> bool {
        matches!(
            self,
            Self::SearchNplV1 | Self::SearchNplShedV1 { .. } | Self::SearchNplPostV1 { .. }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DurableCloudEventsSummaryQueries {
    pub total: String,
    pub providers: String,
    pub services: String,
    pub regions: String,
    pub accounts: String,
    pub resource_types: String,
    pub change_types: String,
    pub resources: String,
    pub users: String,
}

impl DurableCloudEventsSummaryQueries {
    fn all(&self) -> [&str; 9] {
        [
            &self.total,
            &self.providers,
            &self.services,
            &self.regions,
            &self.accounts,
            &self.resource_types,
            &self.change_types,
            &self.resources,
            &self.users,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableQueryResourceClass {
    Medium,
    Large,
}

impl std::str::FromStr for DurableQueryResourceClass {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "medium" | "" => Ok(Self::Medium),
            "large" => Ok(Self::Large),
            _ => Err("invalid durable query resource class".to_string()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DurableJobStoreError {
    #[error("durable search jobs require Redis/Dragonfly")]
    Unsupported,
    #[error("durable search job store is unavailable: {0}")]
    Unavailable(String),
    #[error("durable search job state is invalid: {0}")]
    Invalid(String),
    /// NAN-2361: the record's HMAC did not verify under this tenant's key
    /// (or it was unsigned). The record has already been marked failed and
    /// must never be executed. Runners count and skip; they do not exit.
    #[error("durable search job record rejected: {0}")]
    SignatureRejected(String),
    /// The claimed record failed validation and its attempt was fenced off.
    /// Runners skip this record; configuration and store failures stay fatal
    /// or retryable through their existing error variants.
    #[error("durable search job claim rejected before execution")]
    ClaimRejected,
}

impl std::fmt::Display for SearchJobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => write!(f, "queued"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for SearchJobStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("unknown job status: {}", s)),
        }
    }
}

/// Progress information for a running search job
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchJobProgress {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    /// Number of rows scanned so far
    pub rows_scanned: u64,
    /// Estimated total rows to scan
    pub rows_total: u64,
    /// Completion percentage (0-100)
    pub percent: u8,
    /// Time elapsed since job started (milliseconds)
    pub elapsed_ms: u64,
}

/// An async search job
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub struct SearchJob {
    /// Unique job identifier
    pub id: String,
    /// Server-resolved shared tenant. `None` is valid only in the dedicated
    /// keyspace.
    pub tenant_id: Option<Uuid>,
    /// Current job status
    pub status: SearchJobStatus,
    /// ClickHouse query_id for progress tracking and cancellation
    pub query_id: String,
    /// Who owns this job
    pub user_id: Option<Uuid>,
    /// Queue priority level
    pub priority: QueryPriority,
    /// Queue position (1-based, set while queued)
    pub queue_position: Option<u32>,
    /// When the job was created (wall clock for cross-instance consistency)
    pub created_at: DateTime<Utc>,
    /// When the job completed (for TTL calculation)
    pub completed_at: Option<DateTime<Utc>>,
    /// The original search request
    pub request: SearchRequest,
    /// The search results (when completed)
    pub result: Option<SearchResponse>,
    /// Error message (when failed)
    pub error: Option<String>,
    /// Execution backend. Durable lake jobs are never executed inside the API
    /// process and never store their result body in Redis.
    pub backend: SearchJobBackend,
    /// Monotonic durable-attempt number. Zero for an unclaimed job.
    pub attempt: u32,
    /// Monotonic fencing token. A stale runner cannot publish after this value
    /// changes, even if its native query eventually returns.
    pub fence: u64,
    /// Manifest pointer for a completed durable result.
    pub result_ref: Option<SearchJobResultRef>,
    /// Exact event generation captured at durable admission.
    pub generation_pin: Option<DurableLakeGenerationPin>,
    /// Typed durable operation, when this job was submitted to the lake lane.
    /// Kept server-side; public job responses expose only its stable kind.
    pub task: Option<DurableLakeTask>,
    /// Exact authority stamp for enterprise-shared durable execution.
    pub durable_authority: Option<DurableSearchJobAuthority>,
    /// NAN-2096: the effective source-scope deny-set the job EXECUTED under,
    /// stamped atomically at creation and immutable thereafter.
    ///
    /// `None` means the provenance is UNKNOWN — the job predates the stamp (a
    /// rolling upgrade left it in a shared Redis store) or its stored payload
    /// failed to decode. Unknown is never treated as `Some(empty)`; see
    /// [`SearchJob::result_visible_under`] for the (deliberately narrow) rule
    /// that governs it.
    pub scope_deny: Option<BTreeSet<String>>,
}

impl SearchJob {
    /// Create a new running job under `scope`.
    pub fn new(id: String, request: SearchRequest, scope: &ScopeSet) -> Self {
        Self::new_for_tenant(SearchTenantScope::dedicated(), id, request, scope)
    }

    pub fn new_for_tenant(
        tenant: SearchTenantScope,
        id: String,
        request: SearchRequest,
        scope: &ScopeSet,
    ) -> Self {
        Self {
            id,
            tenant_id: tenant.tenant_id(),
            status: SearchJobStatus::Running,
            query_id: String::new(),
            user_id: None,
            priority: QueryPriority::Interactive,
            queue_position: None,
            created_at: Utc::now(),
            completed_at: None,
            request,
            result: None,
            error: None,
            backend: SearchJobBackend::Inline,
            attempt: 0,
            fence: 0,
            result_ref: None,
            generation_pin: None,
            task: None,
            durable_authority: None,
            scope_deny: Some(scope.deny_set().clone()),
        }
    }

    /// Create a new job in Queued state with user, priority and execution scope.
    pub fn new_queued(
        id: String,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Self {
        Self::new_queued_for_tenant(
            SearchTenantScope::dedicated(),
            id,
            request,
            user_id,
            priority,
            scope,
        )
    }

    pub fn new_queued_for_tenant(
        tenant: SearchTenantScope,
        id: String,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Self {
        Self {
            id,
            tenant_id: tenant.tenant_id(),
            status: SearchJobStatus::Queued,
            query_id: String::new(),
            user_id: Some(user_id),
            priority,
            queue_position: None,
            created_at: Utc::now(),
            completed_at: None,
            request,
            result: None,
            error: None,
            backend: SearchJobBackend::Inline,
            attempt: 0,
            fence: 0,
            result_ref: None,
            generation_pin: None,
            task: None,
            durable_authority: None,
            scope_deny: Some(scope.deny_set().clone()),
        }
    }

    /// NAN-2096: may a caller whose CURRENT effective source-scope deny-set is
    /// `current_deny` read this job's stored status/result?
    ///
    /// A completed result is a frozen snapshot of rows that were visible under
    /// the deny-set captured at submission. Ownership plus `search:execute` is
    /// not authorization to that snapshot after the caller's data scope
    /// narrows, so the read is re-decided here on every poll:
    ///
    /// * `current_deny ⊆ scope_deny` → every source that could have contributed
    ///   to the result is still visible to the caller. Allowed. (Widening the
    ///   caller's visibility is always safe — the result can only under-report.)
    /// * anything in `current_deny` that was NOT denied at submission → a source
    ///   the caller may no longer see could be in the result. Denied.
    /// * `scope_deny == None` (unknown provenance) → readable ONLY by a caller
    ///   whose deny-set is empty. That is not a fail-open exception: a caller
    ///   denied nothing may already read every source directly, so the snapshot
    ///   can hold nothing they are not entitled to. Every *restricted* caller is
    ///   refused, which is the fail-closed half that matters.
    ///
    /// This is deliberately set-based rather than row-level: results carry no
    /// per-row source manifest, so a mixed-source result fails closed as soon as
    /// ONE contributing source could be denied. Re-checking at READ time (rather
    /// than refusing to persist) is what makes revocation retroactive — an
    /// already-running job keeps executing under its submission scope, but its
    /// output stops being readable the moment the scope narrows.
    pub fn result_visible_under(&self, current_deny: &BTreeSet<String>) -> bool {
        match &self.scope_deny {
            Some(submitted) => current_deny.is_subset(submitted),
            None => current_deny.is_empty(),
        }
    }

    pub fn verify_interactive_retention(
        &self,
        tenant: SearchTenantScope,
        now: DateTime<Utc>,
    ) -> Result<(), DurableJobStoreError> {
        if self.backend != SearchJobBackend::Inline || self.generation_pin.is_none() {
            return Err(DurableJobStoreError::Invalid(
                "inline job has no lake admission proof".into(),
            ));
        }
        #[cfg(feature = "enterprise")]
        let shared_scope = tenant.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(tenant, SearchTenantScope::Dedicated);
        if shared_scope {
            self.durable_authority
                .as_ref()
                .ok_or_else(|| {
                    DurableJobStoreError::Invalid("interactive authority missing".into())
                })?
                .validate_for(
                    tenant,
                    self.user_id.ok_or_else(|| {
                        DurableJobStoreError::Invalid("interactive owner missing".into())
                    })?,
                )?;
            DurableResultRetentionProof::from_shared_job(
                tenant,
                self.created_at,
                &self.request.time_range,
            )?
            .verify_current(tenant, now)?;
        }
        Ok(())
    }

    pub fn belongs_to_tenant(&self, tenant: SearchTenantScope) -> bool {
        tenant.verify_stored_tenant(self.tenant_id).is_ok()
    }

    /// Check if this job has expired (completed/failed + TTL elapsed)
    pub fn is_expired(&self) -> bool {
        if self.status == SearchJobStatus::Running || self.status == SearchJobStatus::Queued {
            return false;
        }
        match self.completed_at {
            Some(completed) => {
                let elapsed = Utc::now().signed_duration_since(completed);
                elapsed
                    > chrono::Duration::from_std(COMPLETED_JOB_TTL)
                        .unwrap_or(chrono::Duration::seconds(300))
            }
            None => false,
        }
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u64 {
        let elapsed = Utc::now().signed_duration_since(self.created_at);
        elapsed.num_milliseconds().max(0) as u64
    }

    /// Get created_at as milliseconds since Unix epoch
    pub fn created_at_ms(&self) -> u64 {
        self.created_at.timestamp_millis() as u64
    }
}

/// Response for job status API
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchJobStatusResponse {
    /// Job ID
    pub job_id: String,
    /// Current status
    pub status: SearchJobStatus,
    /// Progress information (when running)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<SearchJobProgress>,
    /// Search results (when completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<SearchResponse>,
    /// Object-store manifest pointer for a completed durable lake job.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<SearchJobResultRef>,
    /// Public pagination metadata for a durable result. The deployment-owned
    /// object URI in `result_ref` is stripped by the authenticated HTTP layer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub durable_result: Option<SearchJobResultSummary>,
    /// Error message (when failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Queue position (1-based, when status is Queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<u32>,
    /// Estimated wait time in seconds (when status is Queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_wait_seconds: Option<u32>,
    /// Stable typed operation name for product-owned durable jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_kind: Option<String>,
    /// Original nPL used to open the correct product view from Jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Original immutable query window used by the durable task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRangeInput>,
    /// Dataset captured at admission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
}

/// Response for async search initiation
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AsyncSearchResponse {
    /// Job ID for polling
    pub job_id: String,
    /// Initial status ("queued" or "running"; "completed" when an identical
    /// settled search re-serves a finished durable job)
    // NAN-3809: the "completed" re-serve.
    pub status: String,
}

/// Summary of a search job for the active searches panel
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SearchJobSummary {
    /// Job ID
    pub job_id: String,
    /// Current status
    pub status: SearchJobStatus,
    /// Query text (truncated)
    pub query: String,
    /// Timestamp when job was created (ms since epoch)
    pub created_at_ms: u64,
    /// Time elapsed since creation (milliseconds)
    pub elapsed_ms: u64,
    /// Queue position (1-based, when queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<u32>,
    /// Priority level
    pub priority: QueryPriority,
    /// Stable typed operation name for product-owned durable jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_kind: Option<String>,
}

/// Summary of a search job for the admin search jobs page
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AdminSearchJobSummary {
    /// Job ID
    pub job_id: String,
    /// Current status
    pub status: SearchJobStatus,
    /// User who created the job (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Query text (truncated)
    pub query: String,
    /// Timestamp when job was created (ms since epoch)
    pub created_at_ms: u64,
    /// Time elapsed since creation (milliseconds)
    pub elapsed_ms: u64,
    /// Queue position (1-based, when queued)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue_position: Option<u32>,
    /// Priority level
    pub priority: QueryPriority,
    /// Stable typed operation name for product-owned durable jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_kind: Option<String>,
}

// ============================================================================
// SearchJobStore trait
// ============================================================================

/// UUIDv8 reserves the interactive-origin lane while retaining a UUID-shaped
/// polling ID. Durable coordinator admissions use UUIDv7. Promotion preserves
/// this ID, including in coordinator result manifests.
pub(super) fn interactive_job_id() -> String {
    let mut bytes = *Uuid::now_v7().as_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

pub(super) fn is_interactive_job_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id && uuid.get_version_num() == 8)
}

/// Atomic cancellation disposition. Once promotion wins, only the durable
/// coordinator may acknowledge cancellation; a Redis tombstone alone could be
/// lost on expiry/restart while a submitted durable job still runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractiveJobCancellation {
    Inactive,
    Cancelled,
    Hosted,
}

/// Pluggable storage backend for async search jobs.
///
/// All methods are async to support both in-memory (instant) and
/// Redis-backed (network I/O) implementations.
#[async_trait]
pub trait SearchJobStore: Send + Sync + std::fmt::Debug {
    /// Create a new Running job. Returns None if max jobs exceeded.
    ///
    /// `scope` (NAN-2096) is the effective source-scope deny-set the job will
    /// execute under. It is stamped on the job in the SAME write that creates
    /// it, so a job can never exist with an unknown execution scope.
    async fn create(&self, request: SearchRequest, scope: &ScopeSet) -> Option<String>;

    /// Create a new Queued job with user/priority. Returns None if max jobs exceeded.
    ///
    /// See [`SearchJobStore::create`] for `scope`.
    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Option<String>;

    /// Atomically create a durable lake job and enqueue it for an isolated
    /// runner. Implementations must fail closed when durable shared state is
    /// unavailable; silently falling back to process memory would strand jobs
    /// during an API restart.
    async fn create_durable_queued(
        &self,
        _request: SearchRequest,
        _task: &DurableLakeTask,
        _user_id: Uuid,
        _priority: QueryPriority,
        _scope: &ScopeSet,
        _generation_pin: &DurableLakeGenerationPin,
        _authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    fn supports_interactive_lake(&self) -> bool {
        false
    }

    async fn create_interactive_lake(
        &self,
        _request: SearchRequest,
        _user_id: Uuid,
        _priority: QueryPriority,
        _scope: &ScopeSet,
        _generation_pin: &DurableLakeGenerationPin,
        _authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Fence inline completion before handing the same ID to the coordinator.
    /// Returns false if cancellation, completion, or expiry already won.
    async fn begin_hosted_promotion(&self, _id: &str) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    async fn cancel_interactive_checked(
        &self,
        _id: &str,
    ) -> Result<InteractiveJobCancellation, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    async fn promote_interactive_lake(
        &self,
        _job_id: &str,
        _scope: &ScopeSet,
    ) -> Result<(), DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    async fn complete_interactive_lake(
        &self,
        _job_id: &str,
        _result: SearchResponse,
    ) -> Result<(), DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    async fn fail_interactive_lake(
        &self,
        _job_id: &str,
        _error: &str,
    ) -> Result<(), DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Claim the oldest eligible durable job with a monotonically increasing
    /// attempt and fence. The lease transition and queue removal are atomic.
    async fn claim_durable(
        &self,
        _worker_id: &str,
        _lease: Duration,
    ) -> Result<Option<DurableSearchJobClaim>, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Extend a lease only when job, owner, attempt, fence, and running state
    /// still match. `false` means the caller is stale and must stop publishing.
    async fn renew_durable_lease(
        &self,
        _job_id: &str,
        _worker_id: &str,
        _attempt: u32,
        _fence: u64,
        _lease: Duration,
    ) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Publish bounded, advisory progress under the same attempt/fence CAS as
    /// the lease. A stale runner can never overwrite the active attempt.
    async fn update_durable_progress(
        &self,
        _job_id: &str,
        _worker_id: &str,
        _attempt: u32,
        _fence: u64,
        _progress: &SearchJobProgress,
    ) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Publish a result pointer using a compare-and-set fence. Result bytes
    /// remain in object storage; Redis receives only this bounded metadata.
    async fn complete_durable(
        &self,
        _job_id: &str,
        _worker_id: &str,
        _attempt: u32,
        _fence: u64,
        _result: &SearchJobResultRef,
    ) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Finish an attempt. Retryable failures return the job to the durable
    /// queue under a new future fence; terminal failures expose a bounded error.
    async fn fail_durable_attempt(
        &self,
        _job_id: &str,
        _worker_id: &str,
        _attempt: u32,
        _fence: u64,
        _error: &str,
        _retryable: bool,
        _promote_resource_class: bool,
        _max_attempts: u32,
    ) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Cancel only the currently leased durable attempt. Authority revocation
    /// in a stale runner must never cancel a replacement attempt. Unsupported
    /// stores fail closed instead of falling back to whole-job cancellation.
    async fn cancel_durable_claim(
        &self,
        _job_id: &str,
        _worker_id: &str,
        _attempt: u32,
        _fence: u64,
    ) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// NAN-2653: hand the currently leased attempt back to the queue without
    /// charging its failure budget. Used when this runner cannot execute the
    /// job (its admission-pin artifacts live on another reader pod) and when a
    /// draining runner gives up an in-flight attempt at shutdown. Fenced like
    /// every other lease mutation: a stale runner can never release a
    /// replacement attempt. Neither `execution_failures` nor
    /// `lease_recoveries` changes, and the claim's `attempt` increment is
    /// undone, so the next claim reuses the attempt number under a new fence.
    async fn release_durable_claim(
        &self,
        _job_id: &str,
        _worker_id: &str,
        _attempt: u32,
        _fence: u64,
    ) -> Result<bool, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Requeue or terminally fail expired durable leases. This makes API and
    /// runner restarts recoverable without trusting process-local tasks.
    async fn reconcile_durable_leases(
        &self,
        _max_attempts: u32,
    ) -> Result<usize, DurableJobStoreError> {
        Err(DurableJobStoreError::Unsupported)
    }

    /// Get a job by ID (without result payload to avoid large clones).
    async fn get(&self, job_id: &str) -> Option<SearchJob>;

    /// Get a job without collapsing a shared-store outage into "not found".
    ///
    /// In-memory stores cannot fail and inherit this wrapper. Network-backed
    /// stores override it so public polling endpoints can distinguish an
    /// absent job from temporarily unavailable durable state.
    async fn get_checked(&self, job_id: &str) -> Result<Option<SearchJob>, DurableJobStoreError> {
        Ok(self.get(job_id).await)
    }

    /// One coherent ledger snapshot for ownership/scope checks AND public status.
    async fn get_snapshot_checked(&self, job_id: &str) -> Result<Option<(SearchJob, SearchJobStatusResponse)>, DurableJobStoreError> {
        let Some(job) = self.get_checked(job_id).await? else { return Ok(None); };
        Ok(self.get_status_checked(job_id).await?.map(|status| (job, status)))
    }

    /// Get full job status including result.
    async fn get_status(&self, job_id: &str) -> Option<SearchJobStatusResponse>;

    /// Get full job status while preserving shared-store failures.
    async fn get_status_checked(
        &self,
        job_id: &str,
    ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
        Ok(self.get_status(job_id).await)
    }

    /// Get the ClickHouse query_id for a job.
    async fn get_query_id(&self, job_id: &str) -> Option<String>;

    /// Set the ClickHouse query_id for a job.
    async fn set_query_id(&self, job_id: &str, query_id: String);

    /// Mark a job as completed with results.
    async fn complete(&self, job_id: &str, result: SearchResponse);

    /// Mark a job as failed with an error message.
    async fn fail(&self, job_id: &str, error: String);

    /// Mark a job as cancelled.
    async fn cancel(&self, job_id: &str);

    /// Transition a queued job to Running.
    async fn start(&self, job_id: &str);

    /// Remove a job from the store.
    async fn remove(&self, job_id: &str) -> Option<SearchJob>;

    /// Update the queue position for a queued job.
    async fn set_queue_position(&self, job_id: &str, position: u32);

    /// List jobs for a specific user.
    async fn list_for_user(&self, user_id: Uuid) -> Vec<SearchJobSummary>;

    /// List a user's jobs without collapsing a shared-store outage into an
    /// empty list (NAN-2361). In-memory stores cannot fail and inherit this
    /// wrapper; network-backed stores override it so the Search Jobs surface
    /// answers 503 "retry shortly" instead of "you have no jobs" while the
    /// registry is unreachable.
    async fn list_for_user_checked(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError> {
        Ok(self.list_for_user(user_id).await)
    }

    /// List all jobs (admin view), filtered to those the viewer may see.
    ///
    /// NAN-2096/NAN-2109: the admin summary carries every principal's query
    /// preview, so the source-scope predicate lives INSIDE this call rather than
    /// in the handler — a caller cannot list a job whose result the poll route
    /// would refuse them. Pass an EMPTY `viewer_deny` for internal, non-user
    /// consumers (metrics, admission accounting): an empty deny-set is a subset
    /// of every stamp, so nothing is filtered out.
    async fn list_all(&self, viewer_deny: &BTreeSet<String>) -> Vec<AdminSearchJobSummary>;

    async fn list_all_checked(
        &self,
        viewer_deny: &BTreeSet<String>,
    ) -> Result<Vec<AdminSearchJobSummary>, DurableJobStoreError> {
        Ok(self.list_all(viewer_deny).await)
    }

    /// Count of active (Running + Queued) jobs.
    async fn active_count(&self) -> usize;

    /// Total job count.
    async fn total_count(&self) -> usize;

    /// Periodic cleanup of expired/stale jobs.
    /// Default no-op (RedisJobStore uses native TTL expiry).
    async fn cleanup(&self) {}
}

// ============================================================================
// InMemoryJobStore (formerly SearchJobRegistry)
// ============================================================================

/// In-memory job store using DashMap for lock-free concurrent access.
/// Jobs are automatically cleaned up after TTL expires.
#[derive(Debug, Clone)]
pub struct InMemoryJobStore {
    tenant: SearchTenantScope,
    assignment_revision: Option<u64>,
    jobs: Arc<DashMap<String, SearchJob>>,
}

impl Default for InMemoryJobStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryJobStore {
    /// Create a new in-memory job store
    pub fn new() -> Self {
        Self {
            tenant: SearchTenantScope::dedicated(),
            assignment_revision: None,
            jobs: Arc::new(DashMap::new()),
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn new_enterprise_shared(tenant_id: Uuid) -> Self {
        Self {
            tenant: SearchTenantScope::EnterpriseShared(tenant_id),
            assignment_revision: None,
            jobs: Arc::new(DashMap::new()),
        }
    }

    #[cfg(feature = "enterprise")]
    /// Build an assignment-versioned tenant view for pivt. A worker rotation
    /// changes the physical namespace, so an opaque job id issued under an old
    /// worker assignment cannot address the replacement assignment's state.
    pub fn new_enterprise_shared_assignment(tenant_id: Uuid, assignment_revision: u64) -> Self {
        Self {
            tenant: SearchTenantScope::EnterpriseShared(tenant_id),
            assignment_revision: Some(assignment_revision),
            jobs: Arc::new(DashMap::new()),
        }
    }

    #[cfg(feature = "enterprise")]
    /// Return a tenant-pinned view over the same process-local backing map.
    /// This is useful for a shared-mode dispatcher while keeping the tenant
    /// boundary structural: every operation derives its physical key from the
    /// pinned view, never from a caller-supplied tenant selector.
    pub fn enterprise_shared_view(&self, tenant_id: Uuid) -> Self {
        Self {
            tenant: SearchTenantScope::EnterpriseShared(tenant_id),
            assignment_revision: None,
            jobs: Arc::clone(&self.jobs),
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn enterprise_shared_assignment_view(
        &self,
        tenant_id: Uuid,
        assignment_revision: u64,
    ) -> Self {
        Self {
            tenant: SearchTenantScope::EnterpriseShared(tenant_id),
            assignment_revision: Some(assignment_revision),
            jobs: Arc::clone(&self.jobs),
        }
    }

    fn storage_key(&self, job_id: &str) -> String {
        match self.tenant {
            SearchTenantScope::Dedicated => job_id.to_string(),
            SearchTenantScope::EnterpriseShared(tenant_id)
            | SearchTenantScope::EnterpriseSharedRetained { tenant_id, .. } => match self
                .assignment_revision
            {
                Some(revision) => {
                    format!("search:{{jobs:{tenant_id}:assignment:{revision}}}:memory/job/{job_id}")
                }
                None => self.tenant.redis_job_key(&format!("memory/job/{job_id}")),
            },
        }
    }

    fn owns(&self, job: &SearchJob) -> bool {
        job.belongs_to_tenant(self.tenant)
    }

    /// Cleanup expired jobs
    pub fn cleanup_expired(&self) {
        let expired_ids: Vec<String> = self
            .jobs
            .iter()
            .filter(|r| self.owns(r.value()) && r.value().is_expired())
            .map(|r| r.key().clone())
            .collect();

        for id in expired_ids {
            self.jobs.remove(&id);
            tracing::debug!("Cleaned up expired job: {}", id);
        }
    }
}

#[async_trait]
impl SearchJobStore for InMemoryJobStore {
    async fn create(&self, request: SearchRequest, scope: &ScopeSet) -> Option<String> {
        self.cleanup_expired();

        if self.total_count().await >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let job = SearchJob::new_for_tenant(self.tenant, job_id.clone(), request, scope);
        self.jobs.insert(self.storage_key(&job_id), job);

        tracing::debug!("Created async search job: {}", job_id);
        Some(job_id)
    }

    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Option<String> {
        self.cleanup_expired();

        if self.total_count().await >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let job = SearchJob::new_queued_for_tenant(
            self.tenant,
            job_id.clone(),
            request,
            user_id,
            priority,
            scope,
        );
        self.jobs.insert(self.storage_key(&job_id), job);

        tracing::debug!(
            "Created queued search job: {} (user={}, priority={})",
            job_id,
            user_id,
            priority
        );
        Some(job_id)
    }

    async fn get(&self, job_id: &str) -> Option<SearchJob> {
        self.jobs.get(self.storage_key(job_id).as_str()).map(|r| {
            let job = r.value();
            SearchJob {
                id: job.id.clone(),
                tenant_id: job.tenant_id,
                status: job.status.clone(),
                query_id: job.query_id.clone(),
                user_id: job.user_id,
                priority: job.priority,
                queue_position: job.queue_position,
                created_at: job.created_at,
                completed_at: job.completed_at,
                request: job.request.clone(),
                result: None,
                error: job.error.clone(),
                backend: job.backend,
                attempt: job.attempt,
                fence: job.fence,
                result_ref: job.result_ref.clone(),
                generation_pin: job.generation_pin.clone(),
                task: job.task.clone(),
                durable_authority: job.durable_authority.clone(),
                scope_deny: job.scope_deny.clone(),
            }
        })
    }

    async fn get_status(&self, job_id: &str) -> Option<SearchJobStatusResponse> {
        self.jobs.get(self.storage_key(job_id).as_str()).map(|r| {
            let job = r.value();
            SearchJobStatusResponse {
                job_id: job.id.clone(),
                status: job.status.clone(),
                progress: None,
                result: job.result.clone(),
                result_ref: job.result_ref.clone(),
                durable_result: None,
                error: job.error.clone(),
                queue_position: job.queue_position,
                estimated_wait_seconds: None,
                task_kind: job.task.as_ref().map(|task| task.kind().to_string()),
                query: Some(job.request.query.clone()),
                time_range: Some(job.request.time_range.clone()),
                dataset: job.request.dataset.clone(),
            }
        })
    }

    async fn get_query_id(&self, job_id: &str) -> Option<String> {
        self.jobs
            .get(self.storage_key(job_id).as_str())
            .map(|r| r.value().query_id.clone())
    }

    async fn set_query_id(&self, job_id: &str, query_id: String) {
        if let Some(mut job) = self.jobs.get_mut(self.storage_key(job_id).as_str()) {
            job.query_id = query_id;
        }
    }

    async fn complete(&self, job_id: &str, result: SearchResponse) {
        if let Some(mut job) = self.jobs.get_mut(self.storage_key(job_id).as_str()) {
            job.status = SearchJobStatus::Completed;
            job.completed_at = Some(Utc::now());
            job.result = Some(result);
            job.result_ref = None;
            tracing::debug!("Job {} completed successfully", job_id);
        }
    }

    async fn fail(&self, job_id: &str, error: String) {
        let error = if error.trim().is_empty() {
            "Search job failed".to_owned()
        } else {
            error
        };
        if let Some(mut job) = self.jobs.get_mut(self.storage_key(job_id).as_str()) {
            job.status = SearchJobStatus::Failed;
            job.completed_at = Some(Utc::now());
            job.error = Some(error);
            tracing::debug!("Job {} failed: {}", job_id, job.error.as_ref().unwrap());
        }
    }

    async fn cancel(&self, job_id: &str) {
        if let Some(mut job) = self.jobs.get_mut(self.storage_key(job_id).as_str()) {
            job.status = SearchJobStatus::Cancelled;
            job.error = Some("Search job cancelled by request".to_owned());
            job.completed_at = Some(Utc::now());
            tracing::debug!("Job {} cancelled", job_id);
        }
    }

    async fn start(&self, job_id: &str) {
        if let Some(mut job) = self.jobs.get_mut(self.storage_key(job_id).as_str()) {
            if job.status == SearchJobStatus::Queued {
                job.status = SearchJobStatus::Running;
                job.queue_position = None;
                tracing::debug!("Job {} transitioned Queued -> Running", job_id);
            }
        }
    }

    async fn remove(&self, job_id: &str) -> Option<SearchJob> {
        self.jobs
            .remove(self.storage_key(job_id).as_str())
            .map(|(_, job)| job)
    }

    async fn set_queue_position(&self, job_id: &str, position: u32) {
        if let Some(mut job) = self.jobs.get_mut(self.storage_key(job_id).as_str()) {
            job.queue_position = Some(position);
        }
    }

    async fn list_for_user(&self, user_id: Uuid) -> Vec<SearchJobSummary> {
        self.jobs
            .iter()
            .filter(|r| self.owns(r.value()) && r.value().user_id == Some(user_id))
            .map(|r| {
                let job = r.value();
                let query = truncate_query_preview(&job.request.query);
                SearchJobSummary {
                    job_id: job.id.clone(),
                    status: job.status.clone(),
                    query,
                    created_at_ms: job.created_at_ms(),
                    elapsed_ms: job.elapsed_ms(),
                    queue_position: job.queue_position,
                    priority: job.priority,
                    task_kind: job.task.as_ref().map(|task| task.kind().to_string()),
                }
            })
            .collect()
    }

    async fn list_all(&self, viewer_deny: &BTreeSet<String>) -> Vec<AdminSearchJobSummary> {
        self.jobs
            .iter()
            .filter(|r| self.owns(r.value()) && r.value().result_visible_under(viewer_deny))
            .map(|r| {
                let job = r.value();
                let query = truncate_query_preview(&job.request.query);
                AdminSearchJobSummary {
                    job_id: job.id.clone(),
                    status: job.status.clone(),
                    user_id: job.user_id.map(|u| u.to_string()),
                    query,
                    created_at_ms: job.created_at_ms(),
                    elapsed_ms: job.elapsed_ms(),
                    queue_position: job.queue_position,
                    priority: job.priority,
                    task_kind: job.task.as_ref().map(|task| task.kind().to_string()),
                }
            })
            .collect()
    }

    async fn active_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|r| {
                self.owns(r.value())
                    && (r.status == SearchJobStatus::Running || r.status == SearchJobStatus::Queued)
            })
            .count()
    }

    async fn total_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|job| self.owns(job.value()))
            .count()
    }

    async fn cleanup(&self) {
        self.cleanup_expired();
    }
}

// ============================================================================
// Legacy type alias for backward compatibility
// ============================================================================

/// Backward-compatible alias — new code should use `InMemoryJobStore` directly.
pub type SearchJobRegistry = InMemoryJobStore;

// ============================================================================
// RedisJobStore
// ============================================================================

/// Why a durable job's object-store result artifact is still reachable.
///
/// Durable query-result GC (NAN-2361 sweep) deletes an artifact only when NO
/// reference of any kind remains. Each variant is a distinct "keep" reason so
/// the sweep can log why an old artifact survived instead of silently skipping
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableResultReference {
    /// The job hash still exists (any status). While the record lives, the
    /// read API can serve pages from the artifact — an analyst may be mid-way
    /// through a large export, so the artifact must not be touched.
    JobRecord,
    /// The job is a member of the admission/active index.
    ActiveIndex,
    /// The job is enqueued on the durable lake queue (v2 or legacy).
    DurableQueue,
    /// A runner currently holds a fenced lease for the job.
    DurableLease,
}

impl DurableResultReference {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JobRecord => "job_record",
            Self::ActiveIndex => "active_index",
            Self::DurableQueue => "durable_queue",
            Self::DurableLease => "durable_lease",
        }
    }
}

/// Counters from one orphaned-index reconciliation sweep.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DurableIndexReconciliation {
    /// Index-set members examined.
    pub scanned: usize,
    /// Orphaned members removed (job hash expired and the job holds no queue
    /// or lease reference).
    pub removed: usize,
    /// Members retained because the job is still referenced.
    pub retained: usize,
}

impl DurableIndexReconciliation {
    fn absorb(&mut self, other: Self) {
        self.scanned = self.scanned.saturating_add(other.scanned);
        self.removed = self.removed.saturating_add(other.removed);
        self.retained = self.retained.saturating_add(other.retained);
    }
}

/// Redis-backed job store for active/active search deployments.
///
/// Dedicated key schema retains `search:{jobs}:...`. Enterprise-shared stores
/// use `search:{jobs:<tenant_uuid>}:...`; assignment-versioned pivt views use
/// `search:{jobs:<tenant_uuid>:assignment:<revision>}:...`. The tenant-specific
/// Redis Cluster hash tag keeps each view's atomic job/queue/lease scripts in
/// one slot without allowing equal job IDs to address another tenant or stale
/// worker assignment.
///
/// Legacy inline results are stored gzip-compressed in `result_gz` during the
/// migration. Durable lake jobs never write that field: they store a bounded
/// `result_ref_json` manifest pointer and keep all result pages in object
/// storage. TTL is set on completion.
#[derive(Clone)]
pub struct RedisJobStore {
    conn: crate::redis_transport::ReconnectingConnection,
    tenant: SearchTenantScope,
    assignment_revision: Option<u64>,
    /// NAN-2361: per-tenant HMAC key. When present every durable record this
    /// store enqueues is signed and every durable record it claims or reads
    /// back must verify. Enterprise-shared scopes refuse to enqueue or claim
    /// without one; the dedicated keyspace stays unsigned for compatibility.
    signer: Option<Arc<DurableJobSigningKey>>,
}

// redis 1.2 defaults every multiplexed command to 500 ms. That is too narrow
// for durable metadata on a busy shared node: a healthy Dragonfly instance can
// miss one scheduling slice while ingestion owns the CPUs, and the caller then
// sees a false outage. Keep the deadline finite, explicit, and comfortably
// below the durable runner's 30-second lease-renewal window.
// The shared reconnecting transport preserves this two-second budget.

impl std::fmt::Debug for RedisJobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisJobStore").finish()
    }
}

#[cfg(test)]
fn redis_job_store_connection_config() -> redis::aio::ConnectionManagerConfig {
    crate::redis_transport::reconnecting::connection_config()
}

impl RedisJobStore {
    async fn create_lake_job(
        &self,
        existing_id: Option<&str>,
        interactive: bool,
        request: SearchRequest,
        task: &DurableLakeTask,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation_pin: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        generation_pin.validate()?;
        task.validate()?;
        match (self.tenant, authority) {
            (SearchTenantScope::Dedicated, None) => {}
            (
                SearchTenantScope::EnterpriseShared(_)
                | SearchTenantScope::EnterpriseSharedRetained { .. },
                Some(authority),
            ) => {
                authority.validate_for(self.tenant, user_id)?;
            }
            _ => {
                return Err(DurableJobStoreError::Invalid(
                    "durable job authority does not match its tenant keyspace".to_string(),
                ));
            }
        }
        let job_id = existing_id.map(str::to_owned).unwrap_or_else(|| {
            if interactive {
                interactive_job_id()
            } else {
                Uuid::now_v7().to_string()
            }
        });
        Self::validate_job_id(&job_id)?;
        let backend = if interactive {
            "inline"
        } else {
            "lake_durable"
        };
        let now_ms = Utc::now().timestamp_millis();
        let request_json = serde_json::to_string(&request)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let generation_pin_json = serde_json::to_string(generation_pin)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let task_json = serde_json::to_string(task)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let authority_json = authority
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?
            .unwrap_or_default();
        let tenant_id = self
            .tenant
            .tenant_id()
            .map(|tenant_id| tenant_id.to_string())
            .unwrap_or_default();
        let scope_deny = Self::encode_scope_deny(scope);
        if request_json.is_empty() || task_json.is_empty() || scope_deny.is_empty() {
            return Err(DurableJobStoreError::Invalid(
                "durable job request or scope failed to serialize".to_string(),
            ));
        }
        let scope_artifact_deny = serde_json::to_string(scope.artifact_deny_set())
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let priority_text = priority.to_string();
        let user_id_text = user_id.to_string();
        let created_at_ms = now_ms.to_string();
        let job_key = self.job_key(&job_id);
        // NAN-2361: sign every field the runner trusts, bound to the physical
        // key. Shared scopes never enqueue unsigned.
        self.require_signer_for_shared()?;
        let signature = match self.signer.as_ref() {
            Some(signer) => signer.sign(&DurableJobSignedRecord {
                job_key: &job_key,
                tenant_id: &tenant_id,
                job_id: &job_id,
                backend,
                user_id: &user_id_text,
                priority: &priority_text,
                created_at_ms: &created_at_ms,
                request_json: &request_json,
                task_json: &task_json,
                generation_pin_json: &generation_pin_json,
                authority_json: &authority_json,
                scope_deny: &scope_deny,
                scope_artifact_deny: &scope_artifact_deny,
            }),
            None => String::new(),
        };

        if existing_id.is_none() {
            self.prune_expired_active_jobs().await?;
        }
        let script = redis::Script::new(
            r#"
            if ARGV[15] == '0' and redis.call('SCARD', KEYS[3]) >= tonumber(ARGV[1]) then
                return 0
            end
            if ARGV[15] == '1' then
                if redis.call('HGET', KEYS[1], 'backend') ~= 'inline' or
                   redis.call('HGET', KEYS[1], 'status') ~= 'running' then return -1 end
            elseif redis.call('EXISTS', KEYS[1]) ~= 0 then
                return -1
            end
            redis.call('HSET', KEYS[1],
                'status', ARGV[16],
                'backend', ARGV[14],
                'query_id', '',
                'user_id', ARGV[2],
                'priority', ARGV[3],
                'queue_position', '',
                'created_at_ms', ARGV[4],
                'completed_at_ms', '',
                'request_json', ARGV[5],
                'error', '',
                'scope_deny', ARGV[6],
                'attempt', '0',
                'execution_failures', '0',
                'lease_recoveries', '0',
                'resource_class', 'medium',
                'fence', '0',
                'lease_owner', '',
                'lease_expires_at_ms', '',
                'result_ref_json', '',
                'progress_json', '',
                'generation_pin_json', ARGV[8],
                'task_json', ARGV[9],
                'tenant_id', ARGV[10],
                'scope_artifact_deny', ARGV[11],
                'authority_json', ARGV[12],
                'signature', ARGV[13])
            redis.call('SADD', KEYS[2], ARGV[7])
            redis.call('SADD', KEYS[3], ARGV[7])
            redis.call('SADD', KEYS[4], ARGV[7])
            if ARGV[14] == 'lake_durable' then
                redis.call('PERSIST', KEYS[1])
                redis.call('ZADD', KEYS[5], ARGV[4], ARGV[7])
                redis.call('LREM', KEYS[6], 0, ARGV[7])
                redis.call('RPUSH', KEYS[6], ARGV[7])
            else
                redis.call('EXPIRE', KEYS[1], 600)
            end
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let created: i64 = script
            .key(&job_key)
            .key(self.all_index_key())
            .key(self.active_index_key())
            .key(self.user_index_key(&user_id))
            .key(self.durable_queue_key())
            .key(self.durable_scale_signal_key())
            .arg(MAX_JOBS)
            .arg(user_id_text)
            .arg(priority_text)
            .arg(created_at_ms)
            .arg(request_json)
            .arg(scope_deny)
            .arg(&job_id)
            .arg(generation_pin_json)
            .arg(task_json)
            .arg(tenant_id)
            .arg(scope_artifact_deny)
            .arg(authority_json)
            .arg(signature)
            .arg(backend)
            .arg(if existing_id.is_some() { 1 } else { 0 })
            .arg(if interactive { "running" } else { "queued" })
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;

        match created {
            1 => Ok(job_id),
            0 => Err(DurableJobStoreError::Unavailable(format!(
                "maximum durable job count {MAX_JOBS} reached"
            ))),
            _ => Err(DurableJobStoreError::Invalid(
                "durable job ID collision".to_string(),
            )),
        }
    }

    async fn prune_expired_active_jobs(&self) -> Result<(), DurableJobStoreError> {
        let mut conn = self.conn.clone();
        let ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        if ids.is_empty() {
            return Ok(());
        }
        // Dragonfly requires every accessed key to be declared before execution.
        let script = redis::Script::new(
            r#"
            for index = 3, #KEYS do
                if redis.call('EXISTS', KEYS[index]) == 0 then
                    redis.call('SREM', KEYS[1], ARGV[index - 2])
                    redis.call('SREM', KEYS[2], ARGV[index - 2])
                end
            end
            return 1
        "#,
        );
        let mut invocation = script.prepare_invoke();
        invocation
            .key(self.active_index_key())
            .key(self.all_index_key());
        for id in ids.iter().take(MAX_JOBS) {
            Self::validate_job_id(id)?;
            invocation.key(self.job_key(id)).arg(id);
        }
        let _: i64 = invocation
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        Ok(())
    }

    /// Create a new Redis job store from an existing ConnectionManager.
    pub fn new(conn: impl Into<crate::redis_transport::ReconnectingConnection>) -> Self {
        Self {
            conn: conn.into(),
            tenant: SearchTenantScope::dedicated(),
            assignment_revision: None,
            signer: None,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn new_enterprise_shared(
        conn: impl Into<crate::redis_transport::ReconnectingConnection>,
        tenant_id: Uuid,
    ) -> Self {
        Self {
            conn: conn.into(),
            tenant: SearchTenantScope::EnterpriseShared(tenant_id),
            assignment_revision: None,
            signer: None,
        }
    }

    #[cfg(feature = "enterprise")]
    pub fn new_enterprise_shared_assignment(
        conn: impl Into<crate::redis_transport::ReconnectingConnection>,
        tenant_id: Uuid,
        assignment_revision: u64,
    ) -> Self {
        Self {
            conn: conn.into(),
            tenant: SearchTenantScope::EnterpriseShared(tenant_id),
            assignment_revision: Some(assignment_revision),
            signer: None,
        }
    }

    #[cfg(feature = "enterprise")]
    /// Create the hosted shared job store from the exact current retention
    /// identity. Tenant-only legacy scopes are deliberately rejected.
    pub fn new_enterprise_shared_retained_assignment(
        conn: impl Into<crate::redis_transport::ReconnectingConnection>,
        tenant: SearchTenantScope,
        assignment_revision: u64,
    ) -> Result<Self, super::tenant::SearchTenantError> {
        tenant.require_retention_identity()?;
        Ok(Self {
            conn: conn.into(),
            tenant,
            assignment_revision: Some(assignment_revision),
            signer: None,
        })
    }

    /// Attach the tenant's durable-record signing key (NAN-2361). The key's
    /// tenant must equal this store's tenant; a mismatch is a wiring bug and
    /// is rejected rather than silently signing under the wrong key.
    pub fn with_job_signing_key(
        mut self,
        key: DurableJobSigningKey,
    ) -> Result<Self, DurableJobStoreError> {
        match self.tenant.tenant_id() {
            Some(tenant_id) if tenant_id == key.tenant_id() => {}
            Some(_) => {
                return Err(DurableJobStoreError::Invalid(
                    "durable job signing key belongs to another tenant".to_string(),
                ))
            }
            None => {}
        }
        self.signer = Some(Arc::new(key));
        Ok(self)
    }

    pub fn has_job_signing_key(&self) -> bool {
        self.signer.is_some()
    }

    #[cfg(feature = "enterprise")]
    fn is_enterprise_shared_scope(&self) -> bool {
        !matches!(self.tenant, SearchTenantScope::Dedicated)
    }

    /// Enterprise-shared scopes never enqueue or claim unsigned records.
    fn require_signer_for_shared(&self) -> Result<(), DurableJobStoreError> {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.is_enterprise_shared_scope();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.tenant, SearchTenantScope::Dedicated);
        if shared_scope && self.signer.is_none() {
            return Err(DurableJobStoreError::Invalid(
                "enterprise-shared durable jobs require a job signing key".to_string(),
            ));
        }
        Ok(())
    }

    fn signature_rejection(error: DurableJobSigningError) -> DurableJobStoreError {
        DurableJobStoreError::SignatureRejected(error.to_string())
    }

    /// Create a new Redis job store, connecting to the given URL.
    /// Returns None if connection fails (caller should fall back to InMemoryJobStore).
    pub async fn connect(redis_url: &str) -> Option<Self> {
        Self::connect_for_scope(redis_url, SearchTenantScope::dedicated()).await
    }

    #[cfg(feature = "enterprise")]
    pub async fn connect_enterprise_shared(redis_url: &str, tenant_id: Uuid) -> Option<Self> {
        Self::connect_for_scope(redis_url, SearchTenantScope::EnterpriseShared(tenant_id)).await
    }

    #[cfg(feature = "enterprise")]
    pub async fn connect_enterprise_shared_retained(
        redis_url: &str,
        tenant: SearchTenantScope,
    ) -> Option<Self> {
        tenant.require_retention_identity().ok()?;
        Self::connect_for_scope(redis_url, tenant).await
    }

    #[cfg(feature = "enterprise")]
    /// Connect a retained enterprise-shared store that addresses the
    /// assignment-versioned physical namespace. The product search service
    /// enqueues durable jobs under `search:{jobs:<tenant>:assignment:<rev>}`;
    /// a runner without the same revision polls a namespace nothing writes to.
    pub async fn connect_enterprise_shared_retained_assignment(
        redis_url: &str,
        tenant: SearchTenantScope,
        assignment_revision: u64,
    ) -> Option<Self> {
        tenant.require_retention_identity().ok()?;
        let mut store = Self::connect_for_scope(redis_url, tenant).await?;
        store.assignment_revision = Some(assignment_revision);
        Some(store)
    }

    async fn connect_for_scope(redis_url: &str, tenant: SearchTenantScope) -> Option<Self> {
        let client = match crate::redis_transport::client_from_url(redis_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("RedisJobStore: failed to create Redis client: {}", e);
                return None;
            }
        };

        match crate::redis_transport::ReconnectingConnection::new(client).await {
            Ok(conn) => {
                tracing::info!("RedisJobStore connected to {}", redact_redis_url(redis_url));
                let store = Self {
                    conn,
                    tenant,
                    assignment_revision: None,
                    signer: None,
                };
                match store.rebuild_durable_scale_signal().await {
                    Ok(depth) => tracing::info!(
                        durable_queue_depth = depth,
                        "rebuilt durable job autoscaling signal"
                    ),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "failed to rebuild durable job autoscaling signal"
                        );
                        return None;
                    }
                }
                match store.rebuild_active_index().await {
                    Ok(count) => tracing::info!(
                        active_jobs = count,
                        "rebuilt active search-job admission index"
                    ),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "failed to rebuild active search-job admission index"
                        );
                        return None;
                    }
                }
                Some(store)
            }
            Err(e) => {
                tracing::warn!(
                    "RedisJobStore: failed to connect to {}: {}",
                    redact_redis_url(redis_url),
                    e
                );
                None
            }
        }
    }

    /// Return the immutable event-generation pins owned by queued or running
    /// durable lake jobs. Generation-cache GC uses this as its positive retain
    /// set; completed jobs need only their object-result manifest and therefore
    /// disappear from the active index before their source generation is
    /// eligible for deletion.
    pub async fn active_durable_generation_pins(
        &self,
    ) -> Result<Vec<DurableLakeGenerationPin>, DurableJobStoreError> {
        let mut conn = self.conn.clone();
        let active_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        if active_ids.len() > MAX_JOBS {
            return Err(DurableJobStoreError::Invalid(
                "active durable generation pin set exceeds the admission bound".to_string(),
            ));
        }
        if active_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut pipeline = redis::pipe();
        for job_id in &active_ids {
            pipeline
                .cmd("HMGET")
                .arg(self.job_key(job_id))
                .arg("backend")
                .arg("status")
                .arg("generation_pin_json")
                .arg("tenant_id");
        }
        let rows: Vec<Vec<Vec<u8>>> = pipeline
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        let mut pins = Vec::new();
        for fields in rows {
            if fields.len() != 4 {
                return Err(DurableJobStoreError::Invalid(
                    "active durable generation pin field set is invalid".to_string(),
                ));
            }
            if fields[0].as_slice() != b"lake_durable"
                && !(fields[0].as_slice() == b"inline" && !fields[2].is_empty())
            {
                continue;
            }
            if !matches!(fields[1].as_slice(), b"queued" | b"running") {
                continue;
            }
            if fields[2].is_empty() {
                return Err(DurableJobStoreError::Invalid(
                    "active durable job omitted its generation pin".to_string(),
                ));
            }
            let stored_tenant = if fields[3].is_empty() {
                None
            } else {
                Some(
                    Uuid::parse_str(&String::from_utf8_lossy(&fields[3]))
                        .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?,
                )
            };
            self.tenant
                .verify_stored_tenant(stored_tenant)
                .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
            let pin: DurableLakeGenerationPin =
                serde_json::from_slice(&fields[2]).map_err(|error| {
                    DurableJobStoreError::Invalid(format!(
                        "active durable generation pin is invalid: {error}"
                    ))
                })?;
            pin.validate()?;
            pins.push(pin);
        }
        Ok(pins)
    }

    fn job_key(&self, job_id: &str) -> String {
        // Keep every job, queue, and lease key in one Redis Cluster hash slot.
        // The durable state transitions below are Lua scripts and therefore
        // cannot atomically touch keys spread across cluster slots.
        self.scoped_key(&format!("job:{job_id}"))
    }

    fn scoped_key(&self, suffix: &str) -> String {
        match (self.tenant, self.assignment_revision) {
            (
                SearchTenantScope::EnterpriseShared(tenant_id)
                | SearchTenantScope::EnterpriseSharedRetained { tenant_id, .. },
                Some(revision),
            ) => {
                format!("search:{{jobs:{tenant_id}:assignment:{revision}}}:{suffix}")
            }
            _ => self.tenant.redis_job_key(suffix),
        }
    }

    fn user_index_key(&self, user_id: &Uuid) -> String {
        self.scoped_key(&format!("index:user:{user_id}"))
    }

    fn user_index_pattern(&self) -> String {
        self.scoped_key("index:user:*")
    }

    fn all_index_key(&self) -> String {
        self.scoped_key("index:all")
    }

    fn active_index_key(&self) -> String {
        self.scoped_key("index:active")
    }

    /// Queue contract v2 contains task variants added after the first durable
    /// runner release. Keeping it on a distinct key is the rolling-upgrade
    /// fence: a v1 runner can continue draining v1 work, but can never claim a
    /// task it cannot deserialize.
    fn durable_queue_key(&self) -> String {
        self.scoped_key("lake:queue:v2")
    }

    fn legacy_durable_queue_key(&self) -> String {
        self.scoped_key("lake:queue")
    }

    fn durable_lease_key(&self) -> String {
        self.scoped_key("lake:leases")
    }
    // KEDA's Redis scaler measures LLEN, while the sorted set above remains the
    // authoritative oldest-first queue. Every queue transition updates this
    // shadow list in the same Lua transaction. Values are job IDs only so a
    // startup rebuild can recover exact scale depth from DURABLE_QUEUE_KEY.
    fn durable_scale_signal_key(&self) -> String {
        self.scoped_key("lake:scale:v2")
    }

    fn legacy_durable_scale_signal_key(&self) -> String {
        self.scoped_key("lake:scale:v1")
    }

    fn durable_error(error: redis::RedisError) -> DurableJobStoreError {
        DurableJobStoreError::Unavailable(error.to_string())
    }

    async fn rebuild_durable_scale_signal(&self) -> Result<usize, DurableJobStoreError> {
        let script = redis::Script::new(
            r#"
            local queued = redis.call('ZRANGE', KEYS[1], 0, -1)
            redis.call('DEL', KEYS[2])
            for _, job_id in ipairs(queued) do
                redis.call('RPUSH', KEYS[2], job_id)
            end
            return #queued
            "#,
        );
        let mut conn = self.conn.clone();
        script
            .key(self.durable_queue_key())
            .key(self.durable_scale_signal_key())
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)
    }

    /// Rebuild the admission-only index from retained job history. Older Nano
    /// versions counted `ALL_INDEX_KEY`, so terminal hashes that were retained
    /// for the Jobs UI (and stale members whose hashes had expired) eventually
    /// exhausted the 1,000-job limit forever. Keep history and admission as
    /// separate concerns, and make upgrades self-healing on every connection.
    async fn rebuild_active_index(&self) -> Result<usize, DurableJobStoreError> {
        const REBUILD_BATCH: usize = 100;
        let mut conn = self.conn.clone();
        let history: Vec<String> = redis::cmd("SMEMBERS")
            .arg(self.all_index_key())
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        let existing: Vec<String> = redis::cmd("SMEMBERS")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        let candidates = history
            .into_iter()
            .chain(existing)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let script = redis::Script::new(
            r#"
            for index = 3, #KEYS do
                local job_id = ARGV[index - 2]
                local status = redis.call('HGET', KEYS[index], 'status')
                if status == 'queued' or status == 'running' then
                    redis.call('SADD', KEYS[1], job_id)
                else
                    redis.call('SREM', KEYS[1], job_id)
                    if not status then
                        redis.call('SREM', KEYS[2], job_id)
                    end
                end
            end
            return redis.call('SCARD', KEYS[1])
            "#,
        );
        for batch in candidates.chunks(REBUILD_BATCH) {
            let mut invocation = script.prepare_invoke();
            invocation
                .key(self.active_index_key())
                .key(self.all_index_key());
            for job_id in batch {
                invocation.key(self.job_key(job_id));
            }
            for job_id in batch {
                invocation.arg(job_id);
            }
            let _: usize = invocation
                .invoke_async(&mut conn)
                .await
                .map_err(Self::durable_error)?;
        }
        redis::cmd("SCARD")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)
    }

    fn validate_runner_id(worker_id: &str) -> Result<(), DurableJobStoreError> {
        if worker_id.is_empty()
            || worker_id.len() > 256
            || !worker_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(DurableJobStoreError::Invalid(
                "runner ID is invalid".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_durable_result(
        &self,
        result: &SearchJobResultRef,
    ) -> Result<(), DurableJobStoreError> {
        result.verify_tenant(self.tenant)?;
        let digest_ok = result.manifest_sha256.len() == 64
            && result
                .manifest_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit());
        let uri_ok = result.manifest_uri.len() <= 4096
            && (result.manifest_uri.starts_with("s3://")
                || result.manifest_uri.starts_with("file://"))
            && !result.manifest_uri.chars().any(char::is_control);
        if !digest_ok
            || !uri_ok
            || result.parts > 100_000
            || result.page_rows == 0
            || result.page_rows > 50_000
        {
            return Err(DurableJobStoreError::Invalid(
                "durable result reference is invalid".to_string(),
            ));
        }
        Ok(())
    }

    /// Compress a SearchResponse to gzip bytes for Redis storage.
    fn compress_result(result: &SearchResponse) -> Option<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let json = serde_json::to_vec(result).ok()?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&json).ok()?;
        encoder.finish().ok()
    }

    /// Decompress gzip bytes back to a SearchResponse.
    fn decompress_result(data: &[u8]) -> Option<SearchResponse> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let mut decoder = GzDecoder::new(data);
        let mut json_bytes = Vec::new();
        decoder.read_to_end(&mut json_bytes).ok()?;
        serde_json::from_slice(&json_bytes).ok()
    }

    /// NAN-2096: serialize the execution deny-set for the `scope_deny` hash
    /// field. An UNRESTRICTED scope round-trips as `"[]"`, which is distinct
    /// from a missing field (a pre-NAN-2096 job) — the reader must be able to
    /// tell "denied nothing" from "we don't know what this ran under".
    ///
    /// A serialization failure (unreachable for `BTreeSet<String>`) degrades to
    /// the EMPTY STRING, which decodes back as "unknown", not as `[]`. Falling
    /// back to `[]` would silently stamp a restricted job as unrestricted — the
    /// one direction that fails open.
    fn encode_scope_deny(scope: &ScopeSet) -> String {
        serde_json::to_string(scope.deny_set()).unwrap_or_default()
    }

    /// Inverse of [`Self::encode_scope_deny`]. An absent field (legacy job) or
    /// unparseable payload yields `None` — unknown provenance, which
    /// [`SearchJob::result_visible_under`] treats as fail-closed.
    fn decode_scope_deny(raw: Option<&str>) -> Option<BTreeSet<String>> {
        let raw = raw?;
        if raw.is_empty() {
            return None;
        }
        serde_json::from_str(raw).ok()
    }

    async fn read_job_snapshot_checked(&self, job_id: &str) -> Result<Option<(SearchJob, SearchJobStatusResponse)>, DurableJobStoreError> {
        Self::validate_job_id(job_id)?;
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let fields: Vec<Option<Vec<u8>>> = redis::cmd("HMGET")
            .arg(&key)
            .arg("status")
            .arg("query_id")
            .arg("user_id")
            .arg("priority")
            .arg("queue_position")
            .arg("created_at_ms")
            .arg("completed_at_ms")
            .arg("request_json")
            .arg("error")
            .arg("scope_deny")
            .arg("backend")
            .arg("attempt")
            .arg("fence")
            .arg("result_ref_json")
            .arg("generation_pin_json")
            .arg("task_json")
            .arg("tenant_id")
            .arg("authority_json")
            .arg("scope_artifact_deny")
            .arg(JOB_SIGNATURE_FIELD)
            .arg("result_gz")
            .arg("progress_json")
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;

        let job_fields = fields.iter().take(20).map(|value| value.as_ref().map(|bytes| String::from_utf8(bytes.clone())).transpose())
            .collect::<Result<Vec<_>, _>>().map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let Some(job) = self.decode_job_fields(job_id, job_fields)? else { return Ok(None); };
        let status_fields = [0, 8, 4, 20, 13, 21, 16].iter().map(|index| fields.get(*index).cloned().flatten().unwrap_or_default()).collect();
        let status = self.decode_status_fields(job_id, status_fields)?.ok_or_else(|| DurableJobStoreError::Invalid("job snapshot has no status".into()))?;
        Ok(Some((job, status)))
    }

    async fn read_job_checked(
        &self,
        job_id: &str,
    ) -> Result<Option<SearchJob>, DurableJobStoreError> {
        Self::validate_job_id(job_id)?;
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);

        // `Vec<Option<String>>`, NOT `Vec<String>`: redis-rs 1.x fails the WHOLE
        // conversion if any HMGET slot is nil, and `scope_deny` is absent on
        // jobs written before NAN-2096.
        let fields: Vec<Option<String>> = redis::cmd("HMGET")
            .arg(&key)
            .arg("status")
            .arg("query_id")
            .arg("user_id")
            .arg("priority")
            .arg("queue_position")
            .arg("created_at_ms")
            .arg("completed_at_ms")
            .arg("request_json")
            .arg("error")
            .arg("scope_deny")
            .arg("backend")
            .arg("attempt")
            .arg("fence")
            .arg("result_ref_json")
            .arg("generation_pin_json")
            .arg("task_json")
            .arg("tenant_id")
            .arg("authority_json")
            .arg("scope_artifact_deny")
            .arg(JOB_SIGNATURE_FIELD)
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;

        self.decode_job_fields(job_id, fields)
    }

    fn decode_job_fields(&self, job_id: &str, fields: Vec<Option<String>>) -> Result<Option<SearchJob>, DurableJobStoreError> {
        let key = self.job_key(job_id);
        let field = |idx: usize| -> &str {
            fields
                .get(idx)
                .and_then(|value| value.as_deref())
                .unwrap_or_default()
        };
        if fields.len() < 9 || field(0).is_empty() {
            return Ok(None);
        }

        let invalid = |message: String| DurableJobStoreError::Invalid(message);
        let status = field(0).parse().map_err(invalid)?;
        let user_id = if field(2).is_empty() {
            None
        } else {
            Some(Uuid::parse_str(field(2)).map_err(|error| invalid(error.to_string()))?)
        };
        let queue_position = if field(4).is_empty() {
            None
        } else {
            Some(
                field(4)
                    .parse()
                    .map_err(|error: std::num::ParseIntError| invalid(error.to_string()))?,
            )
        };
        let created_at_ms = field(5)
            .parse()
            .map_err(|error: std::num::ParseIntError| invalid(error.to_string()))?;
        let created_at = DateTime::from_timestamp_millis(created_at_ms)
            .ok_or_else(|| invalid("job creation timestamp is invalid".to_string()))?;
        let completed_at = if field(6).is_empty() {
            None
        } else {
            let completed_at_ms = field(6)
                .parse()
                .map_err(|error: std::num::ParseIntError| invalid(error.to_string()))?;
            Some(
                DateTime::from_timestamp_millis(completed_at_ms)
                    .ok_or_else(|| invalid("job completion timestamp is invalid".to_string()))?,
            )
        };
        let request = serde_json::from_str(field(7))
            .map_err(|error| invalid(format!("job request is invalid: {error}")))?;
        let result_ref: Option<SearchJobResultRef> =
            if field(13).is_empty() {
                None
            } else {
                Some(serde_json::from_str(field(13)).map_err(|error| {
                    invalid(format!("job result reference is invalid: {error}"))
                })?)
            };
        let generation_pin = if field(14).is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(field(14))
                    .map_err(|error| invalid(format!("job generation pin is invalid: {error}")))?,
            )
        };
        let task = if field(15).is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(field(15))
                    .map_err(|error| invalid(format!("job task is invalid: {error}")))?,
            )
        };
        let tenant_id = if field(16).is_empty() {
            None
        } else {
            Some(Uuid::parse_str(field(16)).map_err(|error| invalid(error.to_string()))?)
        };
        self.tenant
            .verify_stored_tenant(tenant_id)
            .map_err(|error| invalid(error.to_string()))?;
        if let Some(result_ref) = &result_ref {
            result_ref.verify_tenant(self.tenant)?;
        }
        let durable_authority: Option<DurableSearchJobAuthority> = if field(17).is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(field(17))
                    .map_err(|error| invalid(format!("job authority stamp is invalid: {error}")))?,
            )
        };
        match (self.tenant, durable_authority.as_ref()) {
            (SearchTenantScope::Dedicated, None) => {}
            (
                SearchTenantScope::EnterpriseShared(_)
                | SearchTenantScope::EnterpriseSharedRetained { .. },
                Some(authority),
            ) => {
                let owner = user_id.ok_or_else(|| {
                    invalid("shared durable job has no authority owner".to_string())
                })?;
                authority.validate_for(self.tenant, owner)?;
            }
            (
                SearchTenantScope::EnterpriseShared(_)
                | SearchTenantScope::EnterpriseSharedRetained { .. },
                None,
            ) if field(10).parse().unwrap_or(SearchJobBackend::Inline)
                == SearchJobBackend::Inline => {}
            _ => {
                return Err(invalid(
                    "job authority does not match its tenant keyspace".to_string(),
                ));
            }
        }

        // NAN-2361: a durable record served back to the API must carry the
        // enqueue-time signature; result visibility and authority display
        // derive from these fields.
        if field(10).parse().unwrap_or(SearchJobBackend::Inline) == SearchJobBackend::LakeDurable
            || !field(14).is_empty()
        {
            if let Some(signer) = self.signer.as_ref() {
                let record = DurableJobSignedRecord {
                    job_key: &key,
                    tenant_id: field(16),
                    job_id,
                    backend: field(10),
                    user_id: field(2),
                    priority: field(3),
                    created_at_ms: field(5),
                    request_json: field(7),
                    task_json: field(15),
                    generation_pin_json: field(14),
                    authority_json: field(17),
                    scope_deny: field(9),
                    scope_artifact_deny: field(18),
                };
                signer
                    .verify(&record, field(19))
                    .map_err(Self::signature_rejection)?;
            } else {
                self.require_signer_for_shared()?;
            }
        }

        Ok(Some(SearchJob {
            id: job_id.to_string(),
            tenant_id,
            status,
            query_id: field(1).to_string(),
            user_id,
            priority: field(3).parse().unwrap_or(QueryPriority::Interactive),
            queue_position,
            created_at,
            completed_at,
            request,
            result: None,
            error: (!field(8).is_empty()).then(|| field(8).to_string()),
            backend: field(10).parse().unwrap_or(SearchJobBackend::Inline),
            attempt: field(11).parse().unwrap_or(0),
            fence: field(12).parse().unwrap_or(0),
            result_ref,
            generation_pin,
            task,
            durable_authority,
            scope_deny: Self::decode_scope_deny(Some(field(9))),
        }))
    }

    async fn read_status_checked(
        &self,
        job_id: &str,
    ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
        Self::validate_job_id(job_id)?;
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let fields: Vec<Vec<u8>> = redis::cmd("HMGET")
            .arg(&key)
            .arg("status")
            .arg("error")
            .arg("queue_position")
            .arg("result_gz")
            .arg("result_ref_json")
            .arg("progress_json")
            .arg("tenant_id")
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;

        self.decode_status_fields(job_id, fields)
    }

    fn decode_status_fields(&self, job_id: &str, fields: Vec<Vec<u8>>) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
        if fields.len() < 7 || fields[0].is_empty() {
            return Ok(None);
        }
        let invalid = |message: String| DurableJobStoreError::Invalid(message);
        let status = String::from_utf8_lossy(&fields[0])
            .parse()
            .map_err(invalid)?;
        let queue_position = if fields[2].is_empty() {
            None
        } else {
            Some(
                String::from_utf8_lossy(&fields[2])
                    .parse()
                    .map_err(|error: std::num::ParseIntError| invalid(error.to_string()))?,
            )
        };
        let result = if fields[3].is_empty() {
            None
        } else {
            Some(
                Self::decompress_result(&fields[3])
                    .ok_or_else(|| invalid("inline job result is invalid".to_string()))?,
            )
        };
        let result_ref: Option<SearchJobResultRef> =
            if fields[4].is_empty() {
                None
            } else {
                Some(serde_json::from_slice(&fields[4]).map_err(|error| {
                    invalid(format!("job result reference is invalid: {error}"))
                })?)
            };
        let tenant_id = if fields[6].is_empty() {
            None
        } else {
            Some(
                Uuid::parse_str(&String::from_utf8_lossy(&fields[6]))
                    .map_err(|error| invalid(error.to_string()))?,
            )
        };
        self.tenant
            .verify_stored_tenant(tenant_id)
            .map_err(|error| invalid(error.to_string()))?;
        if let Some(result_ref) = &result_ref {
            result_ref.verify_tenant(self.tenant)?;
        }
        let progress = if fields[5].is_empty() {
            None
        } else {
            Some(
                serde_json::from_slice(&fields[5])
                    .map_err(|error| invalid(format!("job progress is invalid: {error}")))?,
            )
        };

        Ok(Some(SearchJobStatusResponse {
            job_id: job_id.to_string(),
            status,
            progress,
            result,
            result_ref,
            durable_result: None,
            error: (!fields[1].is_empty()).then(|| String::from_utf8_lossy(&fields[1]).to_string()),
            queue_position,
            estimated_wait_seconds: None,
            task_kind: None,
            query: None,
            time_range: None,
            dataset: None,
        }))
    }

    /// Apply completion TTL to job key and indexes.
    async fn set_completion_ttl(&self, job_id: &str, user_id: Option<&str>) {
        let mut conn = self.conn.clone();
        let ttl = COMPLETED_JOB_TTL.as_secs() as i64;

        let key = self.job_key(job_id);
        let _: Result<(), _> = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(ttl)
            .query_async(&mut conn)
            .await;

        // Note: We don't expire the index sets themselves — they use SREM on cleanup.
        // Stale entries in the index are harmless (get() returns None for expired keys).
        // `reconcile_index_orphans` SREMs orphaned entries periodically from the
        // durable result GC sweep; user index entries are also cleaned lazily on
        // list_for_user.
        let _ = user_id;
    }

    fn validate_job_id(job_id: &str) -> Result<(), DurableJobStoreError> {
        if job_id.is_empty()
            || job_id.len() > 128
            || !job_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(DurableJobStoreError::Invalid(
                "job ID is invalid".to_string(),
            ));
        }
        Ok(())
    }

    /// Report whether ANY live reference to `job_id` remains: its job hash
    /// (fetchable results), the admission/active index, either durable queue,
    /// or a runner lease. One Lua script so the verdict is a single-point-in-
    /// time snapshot — the durable result GC treats `Some(_)` as "must retain"
    /// and only ever deletes artifacts for jobs that return `None`.
    pub async fn durable_result_reference(
        &self,
        job_id: &str,
    ) -> Result<Option<DurableResultReference>, DurableJobStoreError> {
        Self::validate_job_id(job_id)?;
        let script = redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) == 1 then return 'job_record' end
            if redis.call('SISMEMBER', KEYS[2], ARGV[1]) == 1 then return 'active_index' end
            if redis.call('ZSCORE', KEYS[3], ARGV[1]) then return 'durable_queue' end
            if redis.call('ZSCORE', KEYS[4], ARGV[1]) then return 'durable_queue' end
            if redis.call('ZSCORE', KEYS[5], ARGV[1]) then return 'durable_lease' end
            return ''
            "#,
        );
        let mut conn = self.conn.clone();
        let verdict: String = script
            .key(self.job_key(job_id))
            .key(self.active_index_key())
            .key(self.durable_queue_key())
            .key(self.legacy_durable_queue_key())
            .key(self.durable_lease_key())
            .arg(job_id)
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        match verdict.as_str() {
            "" => Ok(None),
            "job_record" => Ok(Some(DurableResultReference::JobRecord)),
            "active_index" => Ok(Some(DurableResultReference::ActiveIndex)),
            "durable_queue" => Ok(Some(DurableResultReference::DurableQueue)),
            "durable_lease" => Ok(Some(DurableResultReference::DurableLease)),
            other => Err(DurableJobStoreError::Invalid(format!(
                "durable result reference verdict is invalid: {other}"
            ))),
        }
    }

    /// Remove index-set members whose job hash has expired AND which hold no
    /// queue or lease reference. The existence checks and the SREM run in one
    /// Lua script per member, so a job created or re-queued concurrently can
    /// never lose its index entry (every writer creates the hash in the same
    /// transaction as — or before — the index SADD).
    async fn reconcile_index_members(
        &self,
        index_key: &str,
        members: &[String],
    ) -> Result<DurableIndexReconciliation, DurableJobStoreError> {
        let script = redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[2]) == 1 then return -1 end
            if redis.call('ZSCORE', KEYS[3], ARGV[1])
                or redis.call('ZSCORE', KEYS[4], ARGV[1])
                or redis.call('ZSCORE', KEYS[5], ARGV[1]) then return -1 end
            return redis.call('SREM', KEYS[1], ARGV[1])
            "#,
        );
        let mut conn = self.conn.clone();
        let mut report = DurableIndexReconciliation::default();
        for job_id in members {
            report.scanned = report.scanned.saturating_add(1);
            if Self::validate_job_id(job_id).is_err() {
                // A member we cannot even parse is left alone: it is inert
                // garbage, and deleting what we do not understand is exactly
                // the failure mode this sweep must never have.
                report.retained = report.retained.saturating_add(1);
                continue;
            }
            let verdict: i64 = script
                .key(index_key)
                .key(self.job_key(job_id))
                .key(self.durable_queue_key())
                .key(self.legacy_durable_queue_key())
                .key(self.durable_lease_key())
                .arg(job_id)
                .invoke_async(&mut conn)
                .await
                .map_err(Self::durable_error)?;
            match verdict {
                1 => report.removed = report.removed.saturating_add(1),
                -1 => report.retained = report.retained.saturating_add(1),
                _ => {}
            }
        }
        Ok(report)
    }

    /// Reconcile orphaned members out of the job index sets (`index:all`,
    /// `index:active`, and every `index:user:*` set). The code has long
    /// acknowledged that SREM-maintained sets accrue orphans once job hashes
    /// expire; this makes the cleanup real. Bounded by `max_members` per
    /// sweep so one call cannot monopolize the metadata service.
    pub async fn reconcile_index_orphans(
        &self,
        max_members: usize,
    ) -> Result<DurableIndexReconciliation, DurableJobStoreError> {
        if !(1..=100_000).contains(&max_members) {
            return Err(DurableJobStoreError::Invalid(
                "index reconciliation member bound is invalid".to_string(),
            ));
        }
        let mut conn = self.conn.clone();
        let mut index_keys = vec![
            self.all_index_key().to_string(),
            self.active_index_key().to_string(),
        ];
        let mut cursor: u64 = 0;
        for _ in 0..10_000 {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(self.user_index_pattern())
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await
                .map_err(Self::durable_error)?;
            index_keys.extend(keys);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        let mut report = DurableIndexReconciliation::default();
        'sweep: for index_key in index_keys {
            let mut cursor: u64 = 0;
            loop {
                let (next, members): (u64, Vec<String>) = redis::cmd("SSCAN")
                    .arg(&index_key)
                    .arg(cursor)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut conn)
                    .await
                    .map_err(Self::durable_error)?;
                let remaining = max_members.saturating_sub(report.scanned);
                let batch = &members[..members.len().min(remaining)];
                report.absorb(self.reconcile_index_members(&index_key, batch).await?);
                if report.scanned >= max_members {
                    break 'sweep;
                }
                cursor = next;
                if cursor == 0 {
                    break;
                }
            }
        }
        Ok(report)
    }
}

#[async_trait]
impl SearchJobStore for RedisJobStore {
    async fn create(&self, request: SearchRequest, scope: &ScopeSet) -> Option<String> {
        let mut conn = self.conn.clone();

        // Check job limit
        let count: usize = redis::cmd("SCARD")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .unwrap_or(0);

        if count >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let now = Utc::now();
        let request_json = serde_json::to_string(&request).unwrap_or_default();
        let tenant_id = self
            .tenant
            .tenant_id()
            .map(|tenant_id| tenant_id.to_string())
            .unwrap_or_default();

        let key = self.job_key(&job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("running")
            .arg("query_id")
            .arg("")
            .arg("user_id")
            .arg("")
            .arg("priority")
            .arg(format!("{}", QueryPriority::Interactive))
            .arg("queue_position")
            .arg("")
            .arg("created_at_ms")
            .arg(now.timestamp_millis().to_string())
            .arg("completed_at_ms")
            .arg("")
            .arg("request_json")
            .arg(&request_json)
            .arg("error")
            .arg("")
            .arg("scope_deny")
            .arg(Self::encode_scope_deny(scope))
            .arg("backend")
            .arg("inline")
            .arg("attempt")
            .arg("0")
            .arg("fence")
            .arg("0")
            .arg("result_ref_json")
            .arg("")
            .arg("tenant_id")
            .arg(tenant_id)
            .query_async(&mut conn)
            .await;
        // Add to global index
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(self.all_index_key())
            .arg(&job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(self.active_index_key())
            .arg(&job_id)
            .query_async(&mut conn)
            .await;

        tracing::debug!("Created async search job in Redis: {}", job_id);
        Some(job_id)
    }

    async fn create_queued(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
    ) -> Option<String> {
        let mut conn = self.conn.clone();

        let count: usize = redis::cmd("SCARD")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .unwrap_or(0);

        if count >= MAX_JOBS {
            tracing::warn!("Max async jobs limit reached ({})", MAX_JOBS);
            return None;
        }

        let job_id = Uuid::now_v7().to_string();
        let now = Utc::now();
        let request_json = serde_json::to_string(&request).unwrap_or_default();
        let tenant_id = self
            .tenant
            .tenant_id()
            .map(|tenant_id| tenant_id.to_string())
            .unwrap_or_default();

        let key = self.job_key(&job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("queued")
            .arg("query_id")
            .arg("")
            .arg("user_id")
            .arg(user_id.to_string())
            .arg("priority")
            .arg(format!("{}", priority))
            .arg("queue_position")
            .arg("")
            .arg("created_at_ms")
            .arg(now.timestamp_millis().to_string())
            .arg("completed_at_ms")
            .arg("")
            .arg("request_json")
            .arg(&request_json)
            .arg("error")
            .arg("")
            .arg("scope_deny")
            .arg(Self::encode_scope_deny(scope))
            .arg("backend")
            .arg("inline")
            .arg("attempt")
            .arg("0")
            .arg("fence")
            .arg("0")
            .arg("result_ref_json")
            .arg("")
            .arg("tenant_id")
            .arg(tenant_id)
            .query_async(&mut conn)
            .await;
        // Add to global and user indexes
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(self.all_index_key())
            .arg(&job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(self.active_index_key())
            .arg(&job_id)
            .query_async(&mut conn)
            .await;

        let user_key = self.user_index_key(&user_id);
        let _: Result<(), _> = redis::cmd("SADD")
            .arg(&user_key)
            .arg(&job_id)
            .query_async(&mut conn)
            .await;

        tracing::debug!(
            "Created queued search job in Redis: {} (user={}, priority={})",
            job_id,
            user_id,
            priority
        );
        Some(job_id)
    }

    async fn create_durable_queued(
        &self,
        request: SearchRequest,
        task: &DurableLakeTask,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation_pin: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        self.create_lake_job(
            None,
            false,
            request,
            task,
            user_id,
            priority,
            scope,
            generation_pin,
            authority,
        )
        .await
    }

    fn supports_interactive_lake(&self) -> bool {
        true
    }

    async fn create_interactive_lake(
        &self,
        request: SearchRequest,
        user_id: Uuid,
        priority: QueryPriority,
        scope: &ScopeSet,
        generation_pin: &DurableLakeGenerationPin,
        authority: Option<&DurableSearchJobAuthority>,
    ) -> Result<String, DurableJobStoreError> {
        self.create_lake_job(
            None,
            true,
            request,
            &DurableLakeTask::SearchNplV1,
            user_id,
            priority,
            scope,
            generation_pin,
            authority,
        )
        .await
    }

    async fn begin_hosted_promotion(&self, id: &str) -> Result<bool, DurableJobStoreError> {
        let mut conn = self.conn.clone();
        let changed: i64 = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'backend') ~= 'inline' then return 0 end
            local status = redis.call('HGET', KEYS[1], 'status')
            if status == 'queued' then return 1 end
            if status ~= 'running' then return 0 end
            redis.call('HSET', KEYS[1], 'status', 'queued')
            return 1
        "#,
        )
        .key(self.job_key(id))
        .invoke_async(&mut conn)
        .await
        .map_err(Self::durable_error)?;
        Ok(changed == 1)
    }

    async fn cancel_interactive_checked(
        &self,
        id: &str,
    ) -> Result<InteractiveJobCancellation, DurableJobStoreError> {
        let mut conn = self.conn.clone();
        let changed: i64 = redis::Script::new(r#"
            if redis.call('HGET', KEYS[1], 'backend') ~= 'inline' then return 0 end
            local status = redis.call('HGET', KEYS[1], 'status')
            if status == 'queued' then return 2 end
            if status ~= 'running' and status ~= 'cancelled' then return 0 end
            redis.call('HSET', KEYS[1], 'status', 'cancelled', 'error', 'Search job cancelled by request', 'completed_at_ms', ARGV[2])
            redis.call('SREM', KEYS[2], ARGV[1])
            redis.call('EXPIRE', KEYS[1], ARGV[3])
            return 1
        "#).key(self.job_key(id)).key(self.active_index_key()).arg(id)
            .arg(Utc::now().timestamp_millis()).arg(COMPLETED_JOB_TTL.as_secs())
            .invoke_async(&mut conn).await.map_err(Self::durable_error)?;
        Ok(match changed {
            1 => InteractiveJobCancellation::Cancelled,
            2 => InteractiveJobCancellation::Hosted,
            _ => InteractiveJobCancellation::Inactive,
        })
    }

    async fn promote_interactive_lake(
        &self,
        job_id: &str,
        scope: &ScopeSet,
    ) -> Result<(), DurableJobStoreError> {
        let job = self
            .read_job_checked(job_id)
            .await?
            .ok_or_else(|| DurableJobStoreError::Invalid("interactive job disappeared".into()))?;
        if job.backend == SearchJobBackend::LakeDurable {
            return Ok(());
        }
        let pin = job.generation_pin.as_ref().ok_or_else(|| {
            DurableJobStoreError::Invalid("interactive job has no generation pin".into())
        })?;
        let authority = job.durable_authority.as_ref();
        if job.scope_deny.as_ref() != Some(scope.deny_set()) {
            return Err(DurableJobStoreError::Invalid(
                "interactive scope changed".into(),
            ));
        }
        self.create_lake_job(
            Some(job_id),
            false,
            job.request,
            &DurableLakeTask::SearchNplV1,
            job.user_id
                .ok_or_else(|| DurableJobStoreError::Invalid("job owner missing".into()))?,
            job.priority,
            scope,
            pin,
            authority,
        )
        .await?;
        Ok(())
    }

    async fn complete_interactive_lake(
        &self,
        job_id: &str,
        result: SearchResponse,
    ) -> Result<(), DurableJobStoreError> {
        let result_gz = Self::compress_result(&result).ok_or_else(|| {
            DurableJobStoreError::Invalid("could not compress interactive result".into())
        })?;
        let mut conn = self.conn.clone();
        let changed: i64 = redis::Script::new(r#"
            if redis.call('HGET', KEYS[1], 'backend') ~= 'inline' or
               redis.call('HGET', KEYS[1], 'status') ~= 'running' then return 0 end
            redis.call('HSET', KEYS[1], 'status', 'completed', 'completed_at_ms', ARGV[2], 'result_gz', ARGV[3])
            redis.call('SREM', KEYS[2], ARGV[1])
            redis.call('EXPIRE', KEYS[1], ARGV[4])
            return 1
        "#).key(self.job_key(job_id)).key(self.active_index_key())
            .arg(job_id).arg(Utc::now().timestamp_millis()).arg(result_gz)
            .arg(COMPLETED_JOB_TTL.as_secs()).invoke_async(&mut conn).await.map_err(Self::durable_error)?;
        if changed == 0 {
            tracing::debug!(
                job_id,
                "interactive completion discarded after cancellation"
            );
        }
        Ok(())
    }

    async fn fail_interactive_lake(
        &self,
        job_id: &str,
        error: &str,
    ) -> Result<(), DurableJobStoreError> {
        let mut conn = self.conn.clone();
        let _: i64 = redis::Script::new(r#"
            if redis.call('HGET', KEYS[1], 'backend') ~= 'inline' or
               redis.call('HGET', KEYS[1], 'status') ~= 'running' then return 0 end
            redis.call('HSET', KEYS[1], 'status', 'failed', 'error', ARGV[2], 'completed_at_ms', ARGV[3])
            redis.call('SREM', KEYS[2], ARGV[1])
            redis.call('EXPIRE', KEYS[1], ARGV[4])
            return 1
        "#).key(self.job_key(job_id)).key(self.active_index_key()).arg(job_id).arg(error)
            .arg(Utc::now().timestamp_millis()).arg(COMPLETED_JOB_TTL.as_secs())
            .invoke_async(&mut conn).await.map_err(Self::durable_error)?;
        Ok(())
    }

    async fn claim_durable(
        &self,
        worker_id: &str,
        lease: Duration,
    ) -> Result<Option<DurableSearchJobClaim>, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        self.require_signer_for_shared()?;
        if lease < Duration::from_secs(5) || lease > Duration::from_secs(3_600) {
            return Err(DurableJobStoreError::Invalid(
                "durable lease must be between 5 and 3600 seconds".to_string(),
            ));
        }
        let lease_ms = i64::try_from(lease.as_millis())
            .map_err(|_| DurableJobStoreError::Invalid("durable lease is too large".to_string()))?;
        let expires_ms = Utc::now().timestamp_millis().saturating_add(lease_ms);
        let claim_script = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[3], 'status') ~= 'queued'
                or redis.call('HGET', KEYS[3], 'backend') ~= 'lake_durable' then
                redis.call('ZREM', KEYS[1], ARGV[1])
                redis.call('LREM', KEYS[4], 0, ARGV[1])
                return {}
            end
            local attempt = redis.call('HINCRBY', KEYS[3], 'attempt', 1)
            local fence = redis.call('HINCRBY', KEYS[3], 'fence', 1)
            redis.call('HSET', KEYS[3],
                'status', 'running',
                'queue_position', '',
                'lease_owner', ARGV[2],
                'lease_expires_at_ms', ARGV[3],
                'error', '',
                'progress_json', '')
            redis.call('ZREM', KEYS[1], ARGV[1])
            redis.call('ZADD', KEYS[2], ARGV[3], ARGV[1])
            redis.call('LREM', KEYS[4], 0, ARGV[1])
            return {ARGV[1], tostring(attempt), tostring(fence),
                redis.call('HGET', KEYS[3], 'request_json') or '',
                redis.call('HGET', KEYS[3], 'user_id') or '',
                redis.call('HGET', KEYS[3], 'priority') or '',
                redis.call('HGET', KEYS[3], 'scope_deny') or '',
                redis.call('HGET', KEYS[3], 'generation_pin_json') or '',
                redis.call('HGET', KEYS[3], 'resource_class') or 'medium',
                redis.call('HGET', KEYS[3], 'task_json') or '{"kind":"search_npl_v1"}',
                redis.call('HGET', KEYS[3], 'tenant_id') or '',
                redis.call('HGET', KEYS[3], 'scope_artifact_deny') or '',
                redis.call('HGET', KEYS[3], 'authority_json') or '',
                redis.call('HGET', KEYS[3], 'signature') or '',
                redis.call('HGET', KEYS[3], 'created_at_ms') or '',
                redis.call('HGET', KEYS[3], 'backend') or ''}
            "#,
        );
        let mut conn = self.conn.clone();
        let mut fields: Vec<String> = Vec::new();
        'queues: for (queue_key, scale_key) in [
            (self.durable_queue_key(), self.durable_scale_signal_key()),
            (
                self.legacy_durable_queue_key(),
                self.legacy_durable_scale_signal_key(),
            ),
        ] {
            for _ in 0..100 {
                let candidates: Vec<String> = redis::cmd("ZRANGE")
                    .arg(&queue_key)
                    .arg(0)
                    .arg(0)
                    .query_async(&mut conn)
                    .await
                    .map_err(Self::durable_error)?;
                let Some(job_id) = candidates.first() else {
                    break;
                };
                fields = claim_script
                    .key(&queue_key)
                    .key(self.durable_lease_key())
                    .key(self.job_key(job_id))
                    .key(&scale_key)
                    .arg(job_id)
                    .arg(worker_id)
                    .arg(expires_ms)
                    .invoke_async(&mut conn)
                    .await
                    .map_err(Self::durable_error)?;
                if !fields.is_empty() {
                    break 'queues;
                }
            }
        }
        if fields.is_empty() {
            return Ok(None);
        }
        if fields.len() != 16 {
            return Err(DurableJobStoreError::Invalid(
                "durable claim returned an invalid field set".to_string(),
            ));
        }
        // NAN-2361: verify the enqueue-time signature BEFORE deserializing
        // or validating any authority/credential field. The claim script has
        // already moved the record to running under this worker's lease, so a
        // rejected record is marked terminally failed (never re-queued) and
        // the caller receives a typed error it can count and skip.
        if let Some(signer) = self.signer.as_ref() {
            let job_id = fields[0].as_str();
            let record = DurableJobSignedRecord {
                job_key: &self.job_key(job_id),
                tenant_id: &fields[10],
                job_id,
                backend: &fields[15],
                user_id: &fields[4],
                priority: &fields[5],
                created_at_ms: &fields[14],
                request_json: &fields[3],
                task_json: &fields[9],
                generation_pin_json: &fields[7],
                authority_json: &fields[12],
                scope_deny: &fields[6],
                scope_artifact_deny: &fields[11],
            };
            if let Err(error) = signer.verify(&record, &fields[13]) {
                let attempt: u32 = fields[1].parse().unwrap_or(0);
                let fence: u64 = fields[2].parse().unwrap_or(0);
                let reason = format!("durable job record rejected before execution: {error}");
                let failed = self
                    .fail_durable_attempt(job_id, worker_id, attempt, fence, &reason, false, false, 1)
                    .await;
                tracing::error!(
                    job_id,
                    error = %error,
                    marked_failed = ?failed,
                    "durable job signature rejected; record will not execute"
                );
                if let Err(store_error) = failed {
                    return Err(store_error);
                }
                return Err(Self::signature_rejection(error));
            }
        }
        let attempt = fields[1]
            .parse()
            .map_err(|_| DurableJobStoreError::Invalid("invalid attempt".to_string()))?;
        let fence = fields[2]
            .parse()
            .map_err(|_| DurableJobStoreError::Invalid("invalid fence".to_string()))?;
        let decoded = (|| {
            let request = serde_json::from_str(&fields[3])
                .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
            let user_id = Uuid::parse_str(&fields[4])
                .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
            let priority = fields[5].parse().map_err(DurableJobStoreError::Invalid)?;
            let scope_deny = Self::decode_scope_deny(Some(&fields[6])).ok_or_else(|| {
                DurableJobStoreError::Invalid("durable claim has unknown source scope".to_string())
            })?;
            let generation_pin: DurableLakeGenerationPin = serde_json::from_str(&fields[7])
                .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
            generation_pin.validate()?;
            let resource_class = fields[8].parse().map_err(DurableJobStoreError::Invalid)?;
            let task: DurableLakeTask = serde_json::from_str(&fields[9])
                .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
            task.validate()?;
            let tenant_id = if fields[10].is_empty() {
                None
            } else {
                Some(
                    Uuid::parse_str(&fields[10])
                        .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?,
                )
            };
            self.tenant
                .verify_stored_tenant(tenant_id)
                .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
            let scope_artifact_deny = Self::decode_scope_deny(Some(&fields[11])).ok_or_else(|| {
                DurableJobStoreError::Invalid(
                    "durable claim has unknown artifact source scope".to_string(),
                )
            })?;
            let authority: Option<DurableSearchJobAuthority> = if fields[12].is_empty() {
                None
            } else {
                Some(
                    serde_json::from_str(&fields[12])
                        .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?,
                )
            };
            match (self.tenant, authority.as_ref()) {
                (SearchTenantScope::Dedicated, None) => {}
                (
                    SearchTenantScope::EnterpriseShared(_)
                    | SearchTenantScope::EnterpriseSharedRetained { .. },
                    Some(authority),
                ) => {
                    authority.validate_for(self.tenant, user_id)?;
                }
                _ => {
                    return Err(DurableJobStoreError::Invalid(
                        "claimed durable authority does not match its tenant keyspace".to_string(),
                    ));
                }
            }

            Ok(DurableSearchJobClaim {
                job_id: fields[0].clone(),
                tenant_id,
                attempt,
                fence,
                lease_owner: worker_id.to_string(),
                lease_expires_at_ms: expires_ms,
                request,
                user_id,
                priority,
                scope_deny,
                scope_artifact_deny,
                authority,
                generation_pin,
                task,
                resource_class,
            })
        })();
        match decoded {
            Ok(claim) => Ok(Some(claim)),
            Err(_validation_error) => {
                // Do not persist raw decoder errors: they may contain record
                // contents. Never retry a record rejected before execution.
                let marked_failed = self
                    .fail_durable_attempt(
                        &fields[0],
                        worker_id,
                        attempt,
                        fence,
                        "durable job claim failed validation before execution",
                        false,
                        false,
                        1,
                    )
                    .await?;
                // A false CAS means cancellation or another fence won; do not
                // overwrite that state. Backend errors above remain retryable.
                tracing::warn!(
                    job_id = %fields[0],
                    marked_failed,
                    "durable job claim rejected before execution"
                );
                Err(DurableJobStoreError::ClaimRejected)
            }
        }
    }

    async fn renew_durable_lease(
        &self,
        job_id: &str,
        worker_id: &str,
        attempt: u32,
        fence: u64,
        lease: Duration,
    ) -> Result<bool, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        if lease < Duration::from_secs(5) || lease > Duration::from_secs(3_600) {
            return Err(DurableJobStoreError::Invalid(
                "durable lease must be between 5 and 3600 seconds".to_string(),
            ));
        }
        let lease_ms = i64::try_from(lease.as_millis())
            .map_err(|_| DurableJobStoreError::Invalid("durable lease is too large".to_string()))?;
        let expires_ms = Utc::now().timestamp_millis().saturating_add(lease_ms);
        let script = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'status') ~= 'running'
                or redis.call('HGET', KEYS[1], 'backend') ~= 'lake_durable'
                or redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1]
                or tonumber(redis.call('HGET', KEYS[1], 'attempt') or '-1') ~= tonumber(ARGV[2])
                or tonumber(redis.call('HGET', KEYS[1], 'fence') or '-1') ~= tonumber(ARGV[3]) then
                return 0
            end
            redis.call('HSET', KEYS[1], 'lease_expires_at_ms', ARGV[4])
            redis.call('ZADD', KEYS[2], ARGV[4], ARGV[5])
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let renewed: i64 = script
            .key(self.job_key(job_id))
            .key(self.durable_lease_key())
            .arg(worker_id)
            .arg(attempt)
            .arg(fence)
            .arg(expires_ms)
            .arg(job_id)
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        Ok(renewed == 1)
    }

    async fn update_durable_progress(
        &self,
        job_id: &str,
        worker_id: &str,
        attempt: u32,
        fence: u64,
        progress: &SearchJobProgress,
    ) -> Result<bool, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        if progress.percent > 100 {
            return Err(DurableJobStoreError::Invalid(
                "durable job progress is invalid".to_string(),
            ));
        }
        let progress_json = serde_json::to_string(progress)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let script = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'status') ~= 'running'
                or redis.call('HGET', KEYS[1], 'backend') ~= 'lake_durable'
                or redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1]
                or tonumber(redis.call('HGET', KEYS[1], 'attempt') or '-1') ~= tonumber(ARGV[2])
                or tonumber(redis.call('HGET', KEYS[1], 'fence') or '-1') ~= tonumber(ARGV[3]) then
                return 0
            end
            redis.call('HSET', KEYS[1], 'progress_json', ARGV[4])
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let updated: i64 = script
            .key(self.job_key(job_id))
            .arg(worker_id)
            .arg(attempt)
            .arg(fence)
            .arg(progress_json)
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        Ok(updated == 1)
    }

    async fn complete_durable(
        &self,
        job_id: &str,
        worker_id: &str,
        attempt: u32,
        fence: u64,
        result: &SearchJobResultRef,
    ) -> Result<bool, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        self.validate_durable_result(result)?;
        let result_json = serde_json::to_string(result)
            .map_err(|error| DurableJobStoreError::Invalid(error.to_string()))?;
        let now_ms = Utc::now().timestamp_millis();
        let script = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'status') ~= 'running'
                or redis.call('HGET', KEYS[1], 'backend') ~= 'lake_durable'
                or redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1]
                or tonumber(redis.call('HGET', KEYS[1], 'attempt') or '-1') ~= tonumber(ARGV[2])
                or tonumber(redis.call('HGET', KEYS[1], 'fence') or '-1') ~= tonumber(ARGV[3]) then
                return 0
            end
            redis.call('HSET', KEYS[1],
                'status', 'completed',
                'completed_at_ms', ARGV[4],
                'result_ref_json', ARGV[5],
                'result_gz', '',
                'lease_owner', '',
                'lease_expires_at_ms', '')
            redis.call('ZREM', KEYS[2], ARGV[6])
            redis.call('LREM', KEYS[3], 0, ARGV[6])
            redis.call('SREM', KEYS[4], ARGV[6])
            redis.call('EXPIRE', KEYS[1], ARGV[7])
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let completed: i64 = script
            .key(self.job_key(job_id))
            .key(self.durable_lease_key())
            .key(self.durable_scale_signal_key())
            .key(self.active_index_key())
            .arg(worker_id)
            .arg(attempt)
            .arg(fence)
            .arg(now_ms)
            .arg(result_json)
            .arg(job_id)
            .arg(DURABLE_COMPLETED_JOB_TTL.as_secs())
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        Ok(completed == 1)
    }

    async fn fail_durable_attempt(
        &self,
        job_id: &str,
        worker_id: &str,
        attempt: u32,
        fence: u64,
        error: &str,
        retryable: bool,
        promote_resource_class: bool,
        max_attempts: u32,
    ) -> Result<bool, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        if error.trim().is_empty() || error.len() > 4096 || max_attempts == 0 || max_attempts > 10 {
            return Err(DurableJobStoreError::Invalid(
                "durable attempt failure metadata is invalid".to_string(),
            ));
        }
        let now_ms = Utc::now().timestamp_millis();
        let script = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'status') ~= 'running'
                or redis.call('HGET', KEYS[1], 'backend') ~= 'lake_durable'
                or redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1]
                or tonumber(redis.call('HGET', KEYS[1], 'attempt') or '-1') ~= tonumber(ARGV[2])
                or tonumber(redis.call('HGET', KEYS[1], 'fence') or '-1') ~= tonumber(ARGV[3]) then
                return 0
            end
            redis.call('ZREM', KEYS[2], ARGV[4])
            redis.call('LREM', KEYS[4], 0, ARGV[4])
            redis.call('HSET', KEYS[1],
                'lease_owner', '',
                'lease_expires_at_ms', '',
                'error', ARGV[5],
                'progress_json', '')
            local execution_failures = redis.call('HINCRBY', KEYS[1], 'execution_failures', 1)
            if ARGV[7] == '1' then
                redis.call('HSET', KEYS[1], 'resource_class', 'large')
            end
            if ARGV[6] == '1' and execution_failures < tonumber(ARGV[8]) then
                redis.call('HSET', KEYS[1], 'status', 'queued', 'queue_position', '')
                redis.call('ZADD', KEYS[3], ARGV[9], ARGV[4])
                redis.call('RPUSH', KEYS[4], ARGV[4])
            else
                redis.call('HSET', KEYS[1], 'status', 'failed', 'completed_at_ms', ARGV[9])
                redis.call('SREM', KEYS[5], ARGV[4])
                redis.call('EXPIRE', KEYS[1], ARGV[10])
            end
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let changed: i64 = script
            .key(self.job_key(job_id))
            .key(self.durable_lease_key())
            .key(self.durable_queue_key())
            .key(self.durable_scale_signal_key())
            .key(self.active_index_key())
            .arg(worker_id)
            .arg(attempt)
            .arg(fence)
            .arg(job_id)
            .arg(error)
            .arg(if retryable { 1 } else { 0 })
            .arg(if promote_resource_class { 1 } else { 0 })
            .arg(max_attempts)
            .arg(now_ms)
            .arg(DURABLE_COMPLETED_JOB_TTL.as_secs())
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        Ok(changed == 1)
    }

    async fn cancel_durable_claim(
        &self,
        job_id: &str,
        worker_id: &str,
        attempt: u32,
        fence: u64,
    ) -> Result<bool, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        Self::validate_job_id(job_id)?;
        if attempt == 0 || fence == 0 {
            return Err(DurableJobStoreError::ClaimRejected);
        }
        let script = redis::Script::new(
            r#"
            local now = redis.call('TIME')
            local now_ms = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
            if redis.call('HGET', KEYS[1], 'status') ~= 'running'
                or redis.call('HGET', KEYS[1], 'backend') ~= 'lake_durable'
                or redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1]
                or redis.call('HGET', KEYS[1], 'attempt') ~= ARGV[2]
                or redis.call('HGET', KEYS[1], 'fence') ~= ARGV[3]
                or tonumber(redis.call('HGET', KEYS[1], 'lease_expires_at_ms') or '0') <= now_ms then
                return 0
            end
            redis.call('HINCRBY', KEYS[1], 'fence', 1)
            redis.call('HSET', KEYS[1], 'status', 'cancelled',
                'error', 'Search authority revoked or changed',
                'completed_at_ms', now_ms, 'lease_owner', '', 'lease_expires_at_ms', '', 'progress_json', '')
            redis.call('ZREM', KEYS[2], ARGV[4])
            redis.call('ZREM', KEYS[3], ARGV[4])
            redis.call('ZREM', KEYS[4], ARGV[4])
            redis.call('LREM', KEYS[5], 0, ARGV[4])
            redis.call('LREM', KEYS[6], 0, ARGV[4])
            redis.call('SREM', KEYS[7], ARGV[4])
            redis.call('EXPIRE', KEYS[1], ARGV[5])
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let changed: i64 = script
            .key(self.job_key(job_id))
            .key(self.durable_queue_key())
            .key(self.legacy_durable_queue_key())
            .key(self.durable_lease_key())
            .key(self.durable_scale_signal_key())
            .key(self.legacy_durable_scale_signal_key())
            .key(self.active_index_key())
            .arg(worker_id).arg(attempt).arg(fence).arg(job_id)
            .arg(DURABLE_COMPLETED_JOB_TTL.as_secs())
            .invoke_async(&mut conn).await.map_err(Self::durable_error)?;
        Ok(changed == 1)
    }

    async fn release_durable_claim(
        &self,
        job_id: &str,
        worker_id: &str,
        attempt: u32,
        fence: u64,
    ) -> Result<bool, DurableJobStoreError> {
        Self::validate_runner_id(worker_id)?;
        Self::validate_job_id(job_id)?;
        if attempt == 0 || fence == 0 {
            return Err(DurableJobStoreError::ClaimRejected);
        }
        let now_ms = Utc::now().timestamp_millis();
        // Same CAS as fail/renew. The fence bump invalidates any in-flight
        // renew/progress/complete from the releasing attempt even if a new
        // claim happens to reuse the owner string. The attempt counter is
        // decremented (never below zero) because this attempt never ran.
        let script = redis::Script::new(
            r#"
            if redis.call('HGET', KEYS[1], 'status') ~= 'running'
                or redis.call('HGET', KEYS[1], 'backend') ~= 'lake_durable'
                or redis.call('HGET', KEYS[1], 'lease_owner') ~= ARGV[1]
                or tonumber(redis.call('HGET', KEYS[1], 'attempt') or '-1') ~= tonumber(ARGV[2])
                or tonumber(redis.call('HGET', KEYS[1], 'fence') or '-1') ~= tonumber(ARGV[3]) then
                return 0
            end
            redis.call('HINCRBY', KEYS[1], 'fence', 1)
            if tonumber(ARGV[2]) > 0 then
                redis.call('HINCRBY', KEYS[1], 'attempt', -1)
            end
            redis.call('HINCRBY', KEYS[1], 'claim_releases', 1)
            redis.call('HSET', KEYS[1],
                'status', 'queued',
                'queue_position', '',
                'lease_owner', '',
                'lease_expires_at_ms', '',
                'progress_json', '')
            redis.call('ZREM', KEYS[2], ARGV[4])
            redis.call('ZADD', KEYS[3], ARGV[5], ARGV[4])
            redis.call('LREM', KEYS[4], 0, ARGV[4])
            redis.call('RPUSH', KEYS[4], ARGV[4])
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let changed: i64 = script
            .key(self.job_key(job_id))
            .key(self.durable_lease_key())
            .key(self.durable_queue_key())
            .key(self.durable_scale_signal_key())
            .arg(worker_id)
            .arg(attempt)
            .arg(fence)
            .arg(job_id)
            .arg(now_ms)
            .invoke_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        Ok(changed == 1)
    }

    async fn reconcile_durable_leases(
        &self,
        max_attempts: u32,
    ) -> Result<usize, DurableJobStoreError> {
        if max_attempts == 0 || max_attempts > 10 {
            return Err(DurableJobStoreError::Invalid(
                "durable max attempts is invalid".to_string(),
            ));
        }
        let now_ms = Utc::now().timestamp_millis();
        let reconcile_script = redis::Script::new(
            r#"
            local status = redis.call('HGET', KEYS[3], 'status')
            local expires = tonumber(redis.call('HGET', KEYS[3], 'lease_expires_at_ms') or '0')
            if status ~= 'running' or expires <= 0 or expires > tonumber(ARGV[1]) then
                redis.call('ZREM', KEYS[1], ARGV[2])
                return 0
            end
            local lease_recoveries = redis.call('HINCRBY', KEYS[3], 'lease_recoveries', 1)
            redis.call('HINCRBY', KEYS[3], 'fence', 1)
            redis.call('HSET', KEYS[3],
                'lease_owner', '',
                'lease_expires_at_ms', '',
                'error', 'runner lease expired',
                'progress_json', '')
            if lease_recoveries < tonumber(ARGV[3]) then
                redis.call('HSET', KEYS[3], 'status', 'queued', 'queue_position', '')
                redis.call('ZADD', KEYS[2], ARGV[1], ARGV[2])
                redis.call('LREM', KEYS[4], 0, ARGV[2])
                redis.call('RPUSH', KEYS[4], ARGV[2])
            else
                redis.call('HSET', KEYS[3], 'status', 'failed', 'completed_at_ms', ARGV[1])
                redis.call('LREM', KEYS[4], 0, ARGV[2])
                redis.call('SREM', KEYS[5], ARGV[2])
                redis.call('EXPIRE', KEYS[3], ARGV[4])
            end
            redis.call('ZREM', KEYS[1], ARGV[2])
            return 1
            "#,
        );
        let mut conn = self.conn.clone();
        let expired: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg(self.durable_lease_key())
            .arg("-inf")
            .arg(now_ms)
            .arg("LIMIT")
            .arg(0)
            .arg(100)
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;
        let mut changed = 0_usize;
        for job_id in expired {
            let reconciled: i64 = reconcile_script
                .key(self.durable_lease_key())
                .key(self.durable_queue_key())
                .key(self.job_key(&job_id))
                .key(self.durable_scale_signal_key())
                .key(self.active_index_key())
                .arg(now_ms)
                .arg(&job_id)
                .arg(max_attempts)
                .arg(DURABLE_COMPLETED_JOB_TTL.as_secs())
                .invoke_async(&mut conn)
                .await
                .map_err(Self::durable_error)?;
            changed = changed.saturating_add(usize::from(reconciled == 1));
        }
        Ok(changed)
    }

    async fn get(&self, job_id: &str) -> Option<SearchJob> {
        self.read_job_checked(job_id).await.ok().flatten()
    }

    async fn get_checked(&self, job_id: &str) -> Result<Option<SearchJob>, DurableJobStoreError> {
        self.read_job_checked(job_id).await
    }

    async fn get_snapshot_checked(&self, job_id: &str) -> Result<Option<(SearchJob, SearchJobStatusResponse)>, DurableJobStoreError> {
        self.read_job_snapshot_checked(job_id).await
    }

    async fn get_status(&self, job_id: &str) -> Option<SearchJobStatusResponse> {
        self.read_status_checked(job_id).await.ok().flatten()
    }

    async fn get_status_checked(
        &self,
        job_id: &str,
    ) -> Result<Option<SearchJobStatusResponse>, DurableJobStoreError> {
        self.read_status_checked(job_id).await
    }

    async fn get_query_id(&self, job_id: &str) -> Option<String> {
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let qid: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("query_id")
            .query_async(&mut conn)
            .await
            .ok()?;
        qid.filter(|s| !s.is_empty())
    }

    async fn set_query_id(&self, job_id: &str, query_id: String) {
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("query_id")
            .arg(&query_id)
            .query_async(&mut conn)
            .await;
    }

    async fn complete(&self, job_id: &str, result: SearchResponse) {
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let now_ms = Utc::now().timestamp_millis().to_string();

        // Compress result for storage
        let result_gz = Self::compress_result(&result).unwrap_or_default();

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("completed")
            .arg("completed_at_ms")
            .arg(&now_ms)
            .arg("result_gz")
            .arg(&result_gz[..])
            .arg("result_ref_json")
            .arg("")
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("SREM")
            .arg(self.active_index_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;

        // Get user_id for TTL cleanup
        let user_id: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("user_id")
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();

        self.set_completion_ttl(job_id, user_id.as_deref()).await;
        tracing::debug!("Job {} completed successfully (Redis)", job_id);
    }

    async fn fail(&self, job_id: &str, error: String) {
        let error = if error.trim().is_empty() {
            "Search job failed".to_owned()
        } else {
            error
        };
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let now_ms = Utc::now().timestamp_millis().to_string();

        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("status")
            .arg("failed")
            .arg("completed_at_ms")
            .arg(&now_ms)
            .arg("error")
            .arg(&error)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("SREM")
            .arg(self.active_index_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;

        self.set_completion_ttl(job_id, None).await;
        tracing::debug!("Job {} failed (Redis): {}", job_id, error);
    }

    async fn cancel(&self, job_id: &str) {
        if Self::validate_job_id(job_id).is_err() {
            tracing::debug!("cancel ignored: job ID is invalid");
            return;
        }
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let now_ms = Utc::now().timestamp_millis().to_string();

        // Incrementing the fence is the cancellation barrier for durable
        // runners. A native call that returns after this point may leave an
        // orphan object prefix, but its completion CAS can never publish it.
        let script = redis::Script::new(
            r#"
            if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
            redis.call('HINCRBY', KEYS[1], 'fence', 1)
            redis.call('HSET', KEYS[1],
                'status', 'cancelled',
                'error', 'Search job cancelled by request',
                'completed_at_ms', ARGV[1],
                'lease_owner', '',
                'lease_expires_at_ms', '')
            redis.call('ZREM', KEYS[2], ARGV[2])
            redis.call('ZREM', KEYS[3], ARGV[2])
            redis.call('ZREM', KEYS[4], ARGV[2])
            redis.call('LREM', KEYS[5], 0, ARGV[2])
            redis.call('LREM', KEYS[6], 0, ARGV[2])
            redis.call('SREM', KEYS[7], ARGV[2])
            return 1
            "#,
        );
        let _: Result<i64, _> = script
            .key(&key)
            .key(self.durable_queue_key())
            .key(self.legacy_durable_queue_key())
            .key(self.durable_lease_key())
            .key(self.durable_scale_signal_key())
            .key(self.legacy_durable_scale_signal_key())
            .key(self.active_index_key())
            .arg(&now_ms)
            .arg(job_id)
            .invoke_async(&mut conn)
            .await;

        self.set_completion_ttl(job_id, None).await;
        tracing::debug!("Job {} cancelled (Redis)", job_id);
    }

    async fn start(&self, job_id: &str) {
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);

        // Only transition if currently queued
        let current: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("status")
            .query_async(&mut conn)
            .await
            .ok()
            .flatten();

        if current.as_deref() == Some("queued") {
            let _: Result<(), _> = redis::cmd("HSET")
                .arg(&key)
                .arg("status")
                .arg("running")
                .arg("queue_position")
                .arg("")
                .query_async(&mut conn)
                .await;
            tracing::debug!("Job {} transitioned Queued -> Running (Redis)", job_id);
        }
    }

    async fn remove(&self, job_id: &str) -> Option<SearchJob> {
        let job = self.get(job_id).await;

        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);

        // Remove from indexes
        let _: Result<(), _> = redis::cmd("SREM")
            .arg(self.all_index_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("SREM")
            .arg(self.active_index_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;

        if let Some(ref j) = job {
            if let Some(uid) = &j.user_id {
                let _: Result<(), _> = redis::cmd("SREM")
                    .arg(self.user_index_key(uid))
                    .arg(job_id)
                    .query_async(&mut conn)
                    .await;
            }
        }

        let _: Result<(), _> = redis::cmd("ZREM")
            .arg(self.durable_queue_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("ZREM")
            .arg(self.legacy_durable_queue_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("ZREM")
            .arg(self.durable_lease_key())
            .arg(job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("LREM")
            .arg(self.durable_scale_signal_key())
            .arg(0)
            .arg(job_id)
            .query_async(&mut conn)
            .await;
        let _: Result<(), _> = redis::cmd("LREM")
            .arg(self.legacy_durable_scale_signal_key())
            .arg(0)
            .arg(job_id)
            .query_async(&mut conn)
            .await;

        // Delete the hash
        let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;

        job
    }

    async fn set_queue_position(&self, job_id: &str, position: u32) {
        let mut conn = self.conn.clone();
        let key = self.job_key(job_id);
        let _: Result<(), _> = redis::cmd("HSET")
            .arg(&key)
            .arg("queue_position")
            .arg(position.to_string())
            .query_async(&mut conn)
            .await;
    }

    async fn list_for_user(&self, user_id: Uuid) -> Vec<SearchJobSummary> {
        self.list_for_user_checked(user_id)
            .await
            .unwrap_or_default()
    }

    async fn list_for_user_checked(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<SearchJobSummary>, DurableJobStoreError> {
        let mut conn = self.conn.clone();
        let user_key = self.user_index_key(&user_id);

        let job_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&user_key)
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;

        let mut summaries = Vec::new();
        for jid in job_ids {
            match self.read_job_checked(&jid).await {
                Ok(Some(job)) => {
                    let query = truncate_query_preview(&job.request.query);
                    let created_at_ms = job.created_at_ms();
                    let elapsed_ms = job.elapsed_ms();
                    summaries.push(SearchJobSummary {
                        job_id: job.id,
                        status: job.status,
                        query,
                        created_at_ms,
                        elapsed_ms,
                        queue_position: job.queue_position,
                        priority: job.priority,
                        task_kind: job.task.as_ref().map(|task| task.kind().to_string()),
                    });
                }
                // A transport failure mid-list is an outage, not "fewer jobs".
                Err(error @ DurableJobStoreError::Unavailable(_)) => return Err(error),
                // Absent, unsigned, or malformed records are dropped from the
                // caller's view and unindexed exactly as `get` did before
                // (`get` collapsed every non-transport failure into `None`).
                Ok(None) | Err(_) => {
                    let _: Result<(), _> = redis::cmd("SREM")
                        .arg(&user_key)
                        .arg(&jid)
                        .query_async(&mut conn)
                        .await;
                }
            }
        }
        Ok(summaries)
    }

    async fn list_all(&self, viewer_deny: &BTreeSet<String>) -> Vec<AdminSearchJobSummary> {
        self.list_all_checked(viewer_deny).await.unwrap_or_default()
    }

    async fn list_all_checked(
        &self,
        viewer_deny: &BTreeSet<String>,
    ) -> Result<Vec<AdminSearchJobSummary>, DurableJobStoreError> {
        let mut conn = self.conn.clone();

        let job_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(self.all_index_key())
            .query_async(&mut conn)
            .await
            .map_err(Self::durable_error)?;

        let mut summaries = Vec::new();
        for jid in job_ids {
            let job = match self.read_job_checked(&jid).await {
                Ok(job) => job,
                Err(error @ DurableJobStoreError::Unavailable(_)) => return Err(error),
                Err(_) => None,
            };
            if let Some(job) = job {
                // `get` already decoded the stamp, so the filter is free.
                if !job.result_visible_under(viewer_deny) {
                    continue;
                }
                let query = truncate_query_preview(&job.request.query);
                let created_at_ms = job.created_at_ms();
                let elapsed_ms = job.elapsed_ms();
                summaries.push(AdminSearchJobSummary {
                    job_id: job.id,
                    status: job.status,
                    user_id: job.user_id.map(|u| u.to_string()),
                    query,
                    created_at_ms,
                    elapsed_ms,
                    queue_position: job.queue_position,
                    priority: job.priority,
                    task_kind: job.task.as_ref().map(|task| task.kind().to_string()),
                });
            } else {
                // Stale index entry — clean up
                let _: Result<(), _> = redis::cmd("SREM")
                    .arg(self.all_index_key())
                    .arg(&jid)
                    .query_async(&mut conn)
                    .await;
            }
        }
        Ok(summaries)
    }

    async fn active_count(&self) -> usize {
        let mut conn = self.conn.clone();
        redis::cmd("SCARD")
            .arg(self.active_index_key())
            .query_async(&mut conn)
            .await
            .unwrap_or(0)
    }

    async fn total_count(&self) -> usize {
        let mut conn = self.conn.clone();
        redis::cmd("SCARD")
            .arg(self.all_index_key())
            .query_async(&mut conn)
            .await
            .unwrap_or(0)
    }
}

#[cfg(test)]
#[path = "jobs_nan3078_tests.rs"]
mod nan3078_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::types::TimeRangeInput;

    #[test]
    fn lateral_task_is_closed_and_binds_valid_incident_window() {
        let task = |query: &str, start, end| DurableLakeTask::LateralV1 {
            query: query.into(), start_micros: start, end_micros: end,
        };
        let valid = task("device.hostname=\"fixture-host\" | lateral methods=auth maxhops=2", 1, 2);
        assert!(valid.validate().is_ok());
        assert!(valid.is_lean_view());
        assert_eq!(valid.kind(), "lateral_v1");
        for query in ["*", "* | lateral | head 1", "* | baseline | lateral", "* | append [ * | baseline ] | lateral", "device.hostname IN [ * | baseline ] | lateral", "* | lateral\n"] {
            assert!(task(query, 1, 2).validate().is_err(), "{query}");
        }
        assert!(task("* | lateral", 2, 1).validate().is_err());
        assert!(task("* | lateral", i64::MIN, i64::MAX).validate().is_err());
        let encoded = serde_json::to_value(&valid).unwrap();
        assert_eq!(serde_json::from_value::<DurableLakeTask>(encoded).unwrap(), valid);
    }

    // The ignored Dragonfly contract tests share one global sorted-set queue.
    // Rust runs tests concurrently by default, so serialize these two callers
    // even when they use a dedicated logical database on the deployed service.
    static REDIS_CONTRACT_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn durable_job_store_does_not_inherit_the_crates_subsecond_timeout() {
        let config = redis_job_store_connection_config();
        assert_eq!(config.response_timeout(), Some(Duration::from_secs(2)));
        assert_eq!(config.connection_timeout(), Some(Duration::from_secs(2)));
    }

    /// NAN-2010 (F12/F15/F16/F17/F25): the job-list preview must not panic when
    /// the stored query has a multibyte character straddling the truncation
    /// offset. Before the fix `&query[..97]` panicked, breaking the admin
    /// all-jobs endpoint for every admin (cross-user DoS).
    #[test]
    fn truncate_query_preview_never_panics_on_multibyte_boundary() {
        // 95 ASCII + two 3-byte chars => byte 97 lands inside the first '€'.
        let q = format!("{}€€", "a".repeat(95));
        assert!(q.len() > 100 && !q.is_char_boundary(97));
        let preview = truncate_query_preview(&q);
        assert!(preview.ends_with("..."));
        assert!(preview.len() <= 100 + 3);

        // A 4-byte emoji straddling the offset must also be safe.
        let q2 = format!("{}😀ok", "b".repeat(96));
        let _ = truncate_query_preview(&q2); // must not panic

        // Short queries are returned verbatim.
        assert_eq!(truncate_query_preview("short"), "short");
    }

    fn make_test_request() -> SearchRequest {
        SearchRequest {
            query: "test".to_string(),
            time_range: TimeRangeInput {
                start: Utc::now(),
                end: Utc::now(),
            },
            limit: None,
            offset: None,
            include_sql: None,
            skip_histogram: false,
            skip_field_stats: false,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        }
    }

    fn make_generation_pin() -> DurableLakeGenerationPin {
        DurableLakeGenerationPin {
            generation_id: "event-42-aaaaaaaaaaaa".to_string(),
            event_config_sha256: "a".repeat(64),
            snapshot_id: 42,
            iceberg_metadata_location: Some(
                "s3://lake/warehouse/tenant-a/events/metadata/00042.metadata.json".to_string(),
            ),
            compiler_sha256: "b".repeat(64),
            native_artifact_sha256: "c".repeat(64),
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
        }
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn interactive_lake_signed_store_completes_promotes_and_fences_cancellation() {
        let Ok(url) = std::env::var("NANO_TEST_REDIS_URL") else {
            return;
        };
        let tenant_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let tenant = SearchTenantScope::enterprise_shared_retained(tenant_id, 13, 90, 0).unwrap();
        let store = RedisJobStore::connect_enterprise_shared_retained(&url, tenant)
            .await
            .unwrap()
            .with_job_signing_key(DurableJobSigningKey::from_bytes([0x7b; 32], tenant_id))
            .unwrap();
        let authority = DurableSearchJobAuthority {
            tenant_id,
            user_id,
            credential: DurableSearchCredentialAuthority::Session {
                access_jti: Uuid::now_v7(),
                credential_time_micros: Utc::now().timestamp_micros(),
            },
            membership_authority_revision: 7,
            entitlement_assignment_revision: 11,
            retention_revision: 13,
            retention_days: 90,
            irreversible_event_time_floor_micros: 0,
            roles: vec!["analyst".into()],
            permissions: vec!["search:execute".into()],
        };
        let mut request = make_test_request();
        request.time_range.start = Utc::now() - chrono::Duration::hours(1);
        request.time_range.end = Utc::now();
        let scope = ScopeSet::from_denied(deny(&["secret-source"]));
        let pin = make_generation_pin();
        let first = store
            .create_interactive_lake(
                request.clone(),
                user_id,
                QueryPriority::Interactive,
                &scope,
                &pin,
                Some(&authority),
            )
            .await
            .unwrap();
        assert!(store
            .claim_durable("test-runner", Duration::from_secs(30))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            store.active_durable_generation_pins().await.unwrap(),
            vec![pin.clone()]
        );
        store
            .complete_interactive_lake(&first, SearchResponse::empty())
            .await
            .unwrap();
        let job = store.get_checked(&first).await.unwrap().unwrap();
        assert_eq!(job.backend, SearchJobBackend::Inline);
        assert_eq!(job.status, SearchJobStatus::Completed);
        job.verify_interactive_retention(tenant, Utc::now())
            .unwrap();
        assert!(job
            .verify_interactive_retention(tenant, Utc::now() + chrono::Duration::days(90))
            .is_err());
        assert!(store
            .get_status_checked(&first)
            .await
            .unwrap()
            .unwrap()
            .result
            .is_some());
        let (snapshot_job, snapshot_status) = store.get_snapshot_checked(&first).await.unwrap().unwrap();
        assert_eq!(snapshot_job.id, first);
        assert_eq!(snapshot_job.scope_deny, job.scope_deny);
        assert_eq!(serde_json::to_value(&snapshot_status).unwrap(),
            serde_json::to_value(store.get_status_checked(&first).await.unwrap().unwrap()).unwrap());
        assert!(snapshot_status.result.is_some(), "the combined read must retain the compressed inline payload");
        assert!(store.get_snapshot_checked(&Uuid::now_v7().to_string()).await.unwrap().is_none());
        assert!(durable_scale_signal_entries(&store).await.is_empty());

        let second = store
            .create_interactive_lake(
                request.clone(),
                user_id,
                QueryPriority::Interactive,
                &scope,
                &pin,
                Some(&authority),
            )
            .await
            .unwrap();
        store
            .promote_interactive_lake(&second, &scope)
            .await
            .unwrap();
        let claim = store
            .claim_durable("test-runner", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.job_id, second);
        assert_eq!(claim.scope_deny, *scope.deny_set());
        assert_eq!(claim.generation_pin, pin);
        store
            .complete_interactive_lake(&second, SearchResponse::empty())
            .await
            .unwrap();
        assert_eq!(
            store.get_checked(&second).await.unwrap().unwrap().backend,
            SearchJobBackend::LakeDurable
        );

        let third = store
            .create_interactive_lake(
                request,
                user_id,
                QueryPriority::Interactive,
                &scope,
                &pin,
                Some(&authority),
            )
            .await
            .unwrap();
        store.cancel(&third).await;
        store
            .complete_interactive_lake(&third, SearchResponse::empty())
            .await
            .unwrap();
        assert!(store
            .promote_interactive_lake(&third, &scope)
            .await
            .is_err());
        store
            .fail_interactive_lake(&third, "late failure")
            .await
            .unwrap();
        assert_eq!(
            store.get_checked(&third).await.unwrap().unwrap().status,
            SearchJobStatus::Cancelled
        );
        let mut conn = store.conn.clone();
        let _: () = redis::cmd("HSET")
            .arg(store.job_key(&first))
            .arg("scope_deny")
            .arg("[]")
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(
            store.get_checked(&first).await.is_err(),
            "interactive provenance must remain signed"
        );
        for id in [&first, &second, &third] {
            store.remove(id).await;
        }
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_in_memory_jobs_cannot_poll_cancel_list_or_complete_across_tenants() {
        let backing = InMemoryJobStore::new();
        let tenant_a = Uuid::from_u128(0xa);
        let tenant_b = Uuid::from_u128(0xb);
        let store_a = backing.enterprise_shared_view(tenant_a);
        let store_b = backing.enterprise_shared_view(tenant_b);
        let user_id = Uuid::from_u128(0xfeed);
        let scope = ScopeSet::default();
        let job_id = "identical-client-visible-job-id";

        let mut request_a = make_test_request();
        request_a.query = "tenant-a-query".to_string();
        let mut request_b = make_test_request();
        request_b.query = "tenant-b-query".to_string();
        store_a.jobs.insert(
            store_a.storage_key(job_id),
            SearchJob::new_queued_for_tenant(
                store_a.tenant,
                job_id.to_string(),
                request_a,
                user_id,
                QueryPriority::Interactive,
                &scope,
            ),
        );
        store_b.jobs.insert(
            store_b.storage_key(job_id),
            SearchJob::new_queued_for_tenant(
                store_b.tenant,
                job_id.to_string(),
                request_b,
                user_id,
                QueryPriority::Interactive,
                &scope,
            ),
        );

        assert_eq!(store_a.total_count().await, 1);
        assert_eq!(store_b.total_count().await, 1);
        assert_eq!(
            store_a.get(job_id).await.unwrap().request.query,
            "tenant-a-query"
        );
        assert_eq!(
            store_b.get(job_id).await.unwrap().request.query,
            "tenant-b-query"
        );

        store_a.cancel(job_id).await;
        assert_eq!(
            store_a.get_status(job_id).await.unwrap().status,
            SearchJobStatus::Cancelled
        );
        assert_eq!(
            store_b.get_status(job_id).await.unwrap().status,
            SearchJobStatus::Queued
        );

        store_b.complete(job_id, SearchResponse::empty()).await;
        assert_eq!(
            store_a.get_status(job_id).await.unwrap().status,
            SearchJobStatus::Cancelled
        );
        assert_eq!(
            store_b.get_status(job_id).await.unwrap().status,
            SearchJobStatus::Completed
        );
        assert_eq!(
            store_a.list_for_user(user_id).await[0].query,
            "tenant-a-query"
        );
        assert_eq!(
            store_b.list_for_user(user_id).await[0].query,
            "tenant-b-query"
        );

        store_a.remove(job_id).await;
        assert!(store_a.get(job_id).await.is_none());
        assert!(store_b.get(job_id).await.is_some());
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn enterprise_shared_worker_revisions_use_disjoint_job_namespaces() {
        let backing = InMemoryJobStore::new();
        let tenant_id = Uuid::from_u128(0xa);
        let revision_one = backing.enterprise_shared_assignment_view(tenant_id, 1);
        let revision_two = backing.enterprise_shared_assignment_view(tenant_id, 2);
        let job_id = "same-opaque-job-id";
        let scope = ScopeSet::default();
        revision_one.jobs.insert(
            revision_one.storage_key(job_id),
            SearchJob::new_for_tenant(
                revision_one.tenant,
                job_id.to_string(),
                make_test_request(),
                &scope,
            ),
        );

        assert!(revision_one.get(job_id).await.is_some());
        assert!(revision_two.get(job_id).await.is_none());
        assert_ne!(
            revision_one.storage_key(job_id),
            revision_two.storage_key(job_id)
        );
        assert_eq!(
            InMemoryJobStore::new().storage_key(job_id),
            job_id,
            "dedicated job ids remain byte-compatible"
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn enterprise_shared_worker_claim_and_result_reference_reject_foreign_tenant() {
        let tenant_a =
            SearchTenantScope::enterprise_shared_retained(Uuid::from_u128(0xa), 1, 90, 0).unwrap();
        let tenant_b =
            SearchTenantScope::enterprise_shared_retained(Uuid::from_u128(0xb), 1, 90, 0).unwrap();
        let claim = DurableSearchJobClaim {
            job_id: "same-job".to_string(),
            tenant_id: tenant_a.tenant_id(),
            attempt: 1,
            fence: 1,
            lease_owner: "worker-a".to_string(),
            lease_expires_at_ms: 1,
            request: make_test_request(),
            user_id: Uuid::from_u128(1),
            priority: QueryPriority::Interactive,
            scope_deny: BTreeSet::new(),
            scope_artifact_deny: BTreeSet::new(),
            authority: Some(DurableSearchJobAuthority {
                tenant_id: Uuid::from_u128(0xa),
                user_id: Uuid::from_u128(1),
                credential: DurableSearchCredentialAuthority::Session {
                    access_jti: Uuid::from_u128(2),
                    credential_time_micros: 1,
                },
                membership_authority_revision: 1,
                entitlement_assignment_revision: 1,
                retention_revision: 1,
                retention_days: 90,
                irreversible_event_time_floor_micros: 0,
                roles: vec!["analyst".to_string()],
                permissions: vec!["search:execute".to_string()],
            }),
            generation_pin: make_generation_pin(),
            task: DurableLakeTask::SearchNplV1,
            resource_class: DurableQueryResourceClass::Medium,
        };
        assert!(claim.verify_worker_tenant(tenant_a).is_ok());
        assert!(claim.verify_worker_tenant(tenant_b).is_err());
        assert!(claim
            .verify_worker_tenant(SearchTenantScope::Dedicated)
            .is_err());

        let evaluated_at = Utc::now();
        let contribution_range = TimeRangeInput::new(
            evaluated_at - chrono::Duration::hours(1),
            evaluated_at,
        );
        let result = SearchJobResultRef {
            tenant_id: tenant_a.tenant_id(),
            manifest_uri: "s3://results/manifest.json".to_string(),
            manifest_sha256: "a".repeat(64),
            rows: 1,
            parts: 1,
            has_more: false,
            page_rows: 10_000,
            retention_proof: Some(
                DurableResultRetentionProof::from_shared_job(
                    tenant_a,
                    evaluated_at,
                    &contribution_range,
                )
                .unwrap(),
            ),
        };
        assert!(result.verify_tenant(tenant_a).is_ok());
        assert!(result.verify_tenant(tenant_b).is_err());
        assert!(result
            .verify_retention_for_range(tenant_a, &contribution_range, evaluated_at)
            .is_ok());
        assert!(result
            .verify_retention_for_range(
                tenant_a,
                &contribution_range,
                evaluated_at + chrono::Duration::days(91),
            )
            .is_err());
        let mut unstamped = result.clone();
        unstamped.retention_proof = None;
        assert!(unstamped.verify_tenant(tenant_a).is_err());
        let tenantless = SearchJobResultRef {
            tenant_id: None,
            ..result
        };
        assert!(tenantless.verify_tenant(tenant_a).is_err());

        let dedicated = SearchJobResultRef {
            tenant_id: None,
            manifest_uri: "file:///tmp/results/manifest.json".to_string(),
            manifest_sha256: "b".repeat(64),
            rows: 1,
            parts: 1,
            has_more: false,
            page_rows: 10_000,
            retention_proof: None,
        };
        assert!(dedicated
            .verify_retention_at(SearchTenantScope::Dedicated, evaluated_at)
            .is_ok());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn durable_shared_authority_requires_exact_tenant_user_and_revisions() {
        let tenant_id = Uuid::from_u128(0xa);
        let user_id = Uuid::from_u128(1);
        let authority = DurableSearchJobAuthority {
            tenant_id,
            user_id,
            credential: DurableSearchCredentialAuthority::Session {
                access_jti: Uuid::from_u128(2),
                credential_time_micros: 1,
            },
            membership_authority_revision: 3,
            entitlement_assignment_revision: 4,
            retention_revision: 5,
            retention_days: 90,
            irreversible_event_time_floor_micros: 0,
            roles: vec!["analyst".to_string()],
            permissions: vec!["search:execute".to_string()],
        };
        assert!(authority
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 5, 90, 0).unwrap(),
                user_id
            )
            .is_ok());
        assert!(authority
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(Uuid::from_u128(0xb), 5, 90, 0)
                    .unwrap(),
                user_id,
            )
            .is_err());
        assert!(authority
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 5, 90, 0).unwrap(),
                Uuid::from_u128(9),
            )
            .is_err());

        let mut invalid = authority;
        invalid.membership_authority_revision = 0;
        assert!(invalid
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 5, 90, 0).unwrap(),
                user_id
            )
            .is_err());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn durable_automation_authority_is_key_principal_not_owner_session() {
        let tenant_id = Uuid::from_u128(0xa);
        let key_id = Uuid::from_u128(2);
        let owner_user_id = Uuid::from_u128(1);
        let authority = DurableSearchJobAuthority {
            tenant_id,
            user_id: key_id,
            credential: DurableSearchCredentialAuthority::TenantAutomationKey {
                key_id,
                owner_user_id,
                key_revision: 3,
                issued_at_micros: 100,
                expires_at_micros: Some(200),
                tenant_slug: "tenant-a".to_string(),
            },
            membership_authority_revision: 4,
            entitlement_assignment_revision: 5,
            retention_revision: 6,
            retention_days: 90,
            irreversible_event_time_floor_micros: 0,
            roles: vec!["api_key".to_string()],
            permissions: vec!["search:execute".to_string()],
        };
        assert!(authority
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 6, 90, 0).unwrap(),
                key_id
            )
            .is_ok());
        assert!(authority
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 6, 90, 0).unwrap(),
                owner_user_id,
            )
            .is_err());

        let mut cross_key = authority.clone();
        cross_key.user_id = Uuid::from_u128(3);
        assert!(cross_key
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 6, 90, 0).unwrap(),
                cross_key.user_id
            )
            .is_err());
        let mut expired_before_issue = authority;
        if let DurableSearchCredentialAuthority::TenantAutomationKey {
            expires_at_micros, ..
        } = &mut expired_before_issue.credential
        {
            *expires_at_micros = Some(99);
        }
        assert!(expired_before_issue
            .validate_for(
                SearchTenantScope::enterprise_shared_retained(tenant_id, 6, 90, 0).unwrap(),
                key_id
            )
            .is_err());
    }

    async fn durable_scale_signal_entries(store: &RedisJobStore) -> Vec<String> {
        let mut conn = store.conn.clone();
        redis::cmd("LRANGE")
            .arg(store.durable_scale_signal_key())
            .arg(0)
            .arg(-1)
            .query_async(&mut conn)
            .await
            .expect("read durable scale signal")
    }

    #[test]
    fn durable_generation_pin_requires_a_complete_hot_tail_fence() {
        let mut pin = make_generation_pin();
        pin.iceberg_metadata_location = Some(
            "s3://lake/warehouse/tenant-b/events/metadata/nested/00042.metadata.json".to_string(),
        );
        assert!(pin.validate().is_err());

        pin.iceberg_metadata_location = None;
        assert!(
            pin.validate().is_ok(),
            "rolling-upgrade pins remain executable even though fleet GC refuses them"
        );
        pin.iceberg_metadata_location =
            Some("s3://lake/warehouse/tenant-a/events/metadata/00042.metadata.json".to_string());
        pin.hot_tail_manifest_sha256 = Some("d".repeat(64));
        assert!(pin.validate().is_err());

        pin.hot_tail_snapshot_id = Some(43);
        assert!(pin.validate().is_ok());

        pin.hot_tail_id = Some("not-a-digest".to_string());
        assert!(pin.validate().is_err());
    }

    #[test]
    fn durable_generation_pin_admits_only_the_bootstrap_zero_snapshot() {
        // NAN-2361 wave 8: an empty tenant's bootstrap generation is snapshot 0
        // under an `event-0-…` identity, with its signed hot tail pinned at 0.
        let mut pin = make_generation_pin();
        pin.snapshot_id = 0;
        assert!(pin.validate().is_err(), "a real generation id never carries snapshot 0");

        pin.generation_id = format!("event-0-{}", &pin.event_config_sha256[..16]);
        assert!(pin.is_bootstrap());
        assert!(pin.validate().is_ok(), "the bootstrap pin is admitted");

        pin.hot_tail_manifest_sha256 = Some("d".repeat(64));
        pin.hot_tail_snapshot_id = Some(0);
        assert!(pin.validate().is_ok(), "its hot tail is pinned at the bootstrap snapshot");

        pin.hot_tail_snapshot_id = Some(1);
        assert!(pin.validate().is_ok(), "a later tail on the bootstrap base is still a valid pair");

        let mut real = make_generation_pin();
        real.hot_tail_manifest_sha256 = Some("d".repeat(64));
        real.hot_tail_snapshot_id = Some(0);
        assert!(real.validate().is_err(), "a real generation cannot pin a zero-snapshot tail");
    }

    #[test]
    fn durable_retro_task_is_closed_and_bounded() {
        let valid = DurableLakeTask::RetroV1 {
            indicators: vec!["198.51.100.25".to_string()],
            axis: "asset".to_string(),
            submode: "pivot".to_string(),
            offset: 0,
            limit: 50,
        };
        assert!(valid.validate().is_ok());

        // NAN-2361: Summary no longer escalates from the interactive path (the
        // cost was the unfiltered denominator, now windowed + cached, not the
        // IOC lookup). The validator still accepts the shape because the
        // durable runner implements it and it remains reachable for replay /
        // future re-escalation — but nothing in the normal path submits it.
        let valid_summary = DurableLakeTask::RetroV1 {
            indicators: vec![
                "175f1e89ea77f991487f7932be495aa777d53d6e6a934aee5b9c7066750b93c2".to_string(),
            ],
            axis: "indicator".to_string(),
            submode: "summary".to_string(),
            offset: 0,
            limit: 50,
        };
        assert!(valid_summary.validate().is_ok());

        // Summary is exclusively the ONE-indicator shape — more than one
        // literal under axis=indicator must still resolve as a List hunt
        // (`enqueue_durable_retro_view`'s own submode derivation), not a
        // Summary task with multiple indicators.
        let invalid_multi_indicator_summary = DurableLakeTask::RetroV1 {
            indicators: vec!["a".to_string(), "b".to_string()],
            axis: "indicator".to_string(),
            submode: "summary".to_string(),
            offset: 0,
            limit: 50,
        };
        assert!(invalid_multi_indicator_summary.validate().is_err());

        let invalid_axis = DurableLakeTask::RetroV1 {
            indicators: vec!["198.51.100.25".to_string()],
            axis: "raw_sql".to_string(),
            submode: "pivot".to_string(),
            offset: 0,
            limit: 50,
        };
        assert!(invalid_axis.validate().is_err());

        let invalid_indicator = DurableLakeTask::RetroV1 {
            indicators: vec!["bad\0indicator".to_string()],
            axis: "indicator".to_string(),
            submode: "list".to_string(),
            offset: 0,
            limit: 50,
        };
        assert!(invalid_indicator.validate().is_err());
    }

    #[test]
    fn durable_asset_task_is_closed_and_bounded() {
        let task = |identifier_field: &str, identities: Vec<serde_json::Value>| {
            DurableLakeTask::AssetV1 {
            identifier_field: identifier_field.to_string(),
            identifier_value: "srv-web02.corp.local".to_string(),
            identities,
            filters: Some(crate::search::AssetEventFilters {
                source_types: Some(vec!["windows_sysmon".to_string()]),
                ..Default::default()
            }),
            summary_query: "device.hostname=\"srv-web02.corp.local\" | stats count() as event_count"
                .to_string(),
            source_query: "device.hostname=\"srv-web02.corp.local\" | stats count() as event_count by metadata.log_source"
                .to_string(),
            user_query: "device.hostname=\"srv-web02.corp.local\" | stats count() as event_count by actor.user.name"
                .to_string(),
            }
        };
        let valid = task(
            "device.hostname",
            vec![serde_json::json!({"hostname": "srv-web02.corp.local"})],
        );
        assert_eq!(valid.kind(), "asset_v1");
        assert!(valid.validate().is_ok());

        let invalid_field = task("raw_sql", vec![serde_json::json!({})]);
        assert!(invalid_field.validate().is_err());

        let oversized_identities = task("device.hostname", vec![serde_json::json!({}); 201]);
        assert!(oversized_identities.validate().is_err());
    }

    #[test]
    fn durable_asset_dossier_task_is_closed_and_bounded() {
        let valid = DurableLakeTask::AssetDossierV1 {
            identifier_field: "device.hostname".to_string(),
            identifier_value: "srv-web02.corp.local".to_string(),
            identities: vec![serde_json::json!({"hostname": "srv-web02.corp.local"})],
            event_query: "device.hostname=\"srv-web02.corp.local\" | sort -time".to_string(),
        };
        assert_eq!(valid.kind(), "asset_dossier_v1");
        assert!(valid.is_lean_view());
        assert!(valid.validate().is_ok());

        let invalid = DurableLakeTask::AssetDossierV1 {
            identifier_field: "raw_sql".to_string(),
            identifier_value: "host".to_string(),
            identities: Vec::new(),
            event_query: "host | sort -time".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn durable_cloud_overview_task_is_closed_and_bounded() {
        let task = |identity_query: &str, risk: Vec<(String, i32, Option<String>)>| {
            DurableLakeTask::CloudOverviewV1 {
                provider: Some("aws".to_string()),
                account: None,
                identity_query: identity_query.to_string(),
                service_query: "class_uid=6003 | stats count() as events by api.service.name"
                    .to_string(),
                change_query: "class_uid=6003 | stats count() as events by api.operation"
                    .to_string(),
                denied_query: "class_uid=6003 | stats count() as events".to_string(),
                risk,
            }
        };
        let valid = task(
            "class_uid=6003 | stats count() as events by actor.user.name",
            vec![("alice".to_string(), 72, Some("Cloud anomaly".to_string()))],
        );
        assert_eq!(valid.kind(), "cloud_overview_v1");
        assert!(valid.validate().is_ok());

        assert!(task("bad\0query", Vec::new()).validate().is_err());
        assert!(task(
            "class_uid=6003 | stats count() as events",
            vec![("alice".to_string(), -1, None)],
        )
        .validate()
        .is_err());
    }

    #[test]
    fn durable_cloud_event_summary_task_is_closed_and_bounded() {
        let queries = DurableCloudEventsSummaryQueries {
            total: "class_uid=6003 | stats count() as event_count".to_string(),
            providers: "class_uid=6003 | stats count() by cloud.provider".to_string(),
            services: "class_uid=6003 | stats count() by api.service.name".to_string(),
            regions: "class_uid=6003 | stats count() by cloud.region".to_string(),
            accounts: "class_uid=6003 | stats count() by cloud.account.uid".to_string(),
            resource_types: "class_uid=6003 | stats count() by resources.type".to_string(),
            change_types: "class_uid=6003 | stats count() by activity_name".to_string(),
            resources: "class_uid=6003 | stats count() by resources.uid".to_string(),
            users: "class_uid=6003 | stats count() by actor.user.name".to_string(),
        };
        let valid = DurableLakeTask::CloudEventsSummaryV1 {
            query: "class_uid=6003 | cloud".to_string(),
            filters: Some(crate::search::CloudEventFilters {
                cloud_providers: Some(vec!["aws".to_string()]),
                ..Default::default()
            }),
            queries: queries.clone(),
            include_panels: true,
        };
        assert_eq!(valid.kind(), "cloud_events_summary_v1");
        assert!(valid.validate().is_ok());

        let mut invalid = valid;
        if let DurableLakeTask::CloudEventsSummaryV1 { queries, .. } = &mut invalid {
            queries.total = "bad\0query".to_string();
        }
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn durable_cloud_dossier_task_is_closed_and_bounded() {
        let valid = DurableLakeTask::CloudDossierV1 {
            principal: "alice".to_string(),
            account: Some("123".to_string()),
            provider: Some("aws".to_string()),
            filters: crate::search::CloudDossierFacetFilters {
                services: vec!["iam".to_string()],
                ..Default::default()
            },
            event_query: "class_uid=6003 AND actor.user.name=\"alice\" | sort -time".to_string(),
            risk: Some((72, Some("Cloud anomaly".to_string()))),
        };
        assert_eq!(valid.kind(), "cloud_dossier_v1");
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        if let DurableLakeTask::CloudDossierV1 { filters, .. } = &mut invalid {
            filters.services = vec!["iam".to_string(); 101];
        }
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn durable_cloud_companion_tasks_are_closed_and_bounded() {
        let timeline = DurableLakeTask::CloudUserTimelineV1 {
            user: "alice@example.com".to_string(),
            event_query: "class_uid=6003 AND actor.user.name=\"alice@example.com\" | sort -time"
                .to_string(),
        };
        assert_eq!(timeline.kind(), "cloud_user_timeline_v1");
        assert!(timeline.validate().is_ok());

        let pivot = DurableLakeTask::CloudEntityPivotV1 {
            entity_type: "resource".to_string(),
            entity_value: "arn:aws:s3:::example".to_string(),
            event_query: "class_uid=6003 | sort -time".to_string(),
        };
        assert_eq!(pivot.kind(), "cloud_entity_pivot_v1");
        assert!(pivot.validate().is_ok());

        let invalid = DurableLakeTask::CloudEntityPivotV1 {
            entity_type: "sql".to_string(),
            entity_value: "anything".to_string(),
            event_query: "class_uid=6003".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn durable_prevalence_export_task_is_closed_and_unbounded_by_row_count() {
        let valid = DurableLakeTask::PrevalenceExportV1 {
            window: "30d".to_string(),
            artifact_type: Some("hash".to_string()),
            max_prevalence: 3,
            format: "csv".to_string(),
        };
        assert_eq!(valid.kind(), "prevalence_export_v1");
        assert!(valid.validate().is_ok());

        let mut invalid = valid.clone();
        if let DurableLakeTask::PrevalenceExportV1 { window, .. } = &mut invalid {
            *window = "365d".to_string();
        }
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn test_create_and_get_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Running);
        assert!(job.result.is_none());
        assert!(job.error.is_none());
    }

    #[tokio::test]
    async fn test_complete_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        let result = SearchResponse::empty();
        store.complete(&job_id, result).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Completed);
        assert!(status.result.is_some());
    }

    #[tokio::test]
    async fn test_fail_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        store.fail(&job_id, "Test error".to_string()).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Failed);
        assert_eq!(status.error.as_ref().unwrap(), "Test error");
        store.fail(&job_id, "   ".to_owned()).await;
        assert_eq!(
            store.get_status(&job_id).await.unwrap().error.as_deref(),
            Some("Search job failed")
        );
    }

    #[tokio::test]
    async fn test_cancel_job() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        store.cancel(&job_id).await;

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Cancelled);
        assert_eq!(
            status.error.as_deref(),
            Some("Search job cancelled by request")
        );
    }

    #[tokio::test]
    async fn test_set_query_id() {
        let store = InMemoryJobStore::new();
        let job_id = store
            .create(make_test_request(), &ScopeSet::unrestricted())
            .await
            .unwrap();

        store
            .set_query_id(&job_id, "ch-query-123".to_string())
            .await;

        let query_id = store.get_query_id(&job_id).await.unwrap();
        assert_eq!(query_id, "ch-query-123");
    }

    #[tokio::test]
    async fn test_create_queued_and_start() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(
                make_test_request(),
                user_id,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Queued);
        assert_eq!(job.user_id, Some(user_id));
        assert_eq!(job.priority, QueryPriority::Interactive);

        // Transition to Running
        store.start(&job_id).await;
        let job = store.get(&job_id).await.unwrap();
        assert_eq!(job.status, SearchJobStatus::Running);
    }

    #[tokio::test]
    async fn test_list_for_user() {
        let store = InMemoryJobStore::new();
        let user1 = Uuid::now_v7();
        let user2 = Uuid::now_v7();

        let _j1 = store
            .create_queued(
                make_test_request(),
                user1,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();
        let _j2 = store
            .create_queued(
                make_test_request(),
                user1,
                QueryPriority::Analytics,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();
        let _j3 = store
            .create_queued(
                make_test_request(),
                user2,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        let user1_jobs = store.list_for_user(user1).await;
        assert_eq!(user1_jobs.len(), 2);

        let user2_jobs = store.list_for_user(user2).await;
        assert_eq!(user2_jobs.len(), 1);
    }

    #[tokio::test]
    async fn test_set_queue_position() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(
                make_test_request(),
                user_id,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        store.set_queue_position(&job_id, 3).await;
        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.queue_position, Some(3));
    }

    // ========================================================================
    // NAN-2096 — async results must not survive source-scope revocation
    // ========================================================================

    fn deny(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn job_stamped_with(scope: &[&str]) -> SearchJob {
        SearchJob::new_queued(
            "job-1".to_string(),
            make_test_request(),
            Uuid::now_v7(),
            QueryPriority::Interactive,
            &ScopeSet::from_denied(deny(scope)),
        )
    }

    /// The reported repro: a job runs while `windows_sysmon` is visible, then the
    /// source is restricted. Polling the completed job must no longer expose it.
    #[test]
    fn scope_narrowed_after_submission_hides_the_result() {
        let job = job_stamped_with(&["audit"]);
        // Same scope as submission → still readable.
        assert!(job.result_visible_under(&deny(&["audit"])));
        // `windows_sysmon` newly restricted → the snapshot may contain it.
        assert!(!job.result_visible_under(&deny(&["audit", "windows_sysmon"])));
    }

    /// Widening the caller's visibility is always safe — the stored result can
    /// only under-report relative to what they may now see.
    #[test]
    fn scope_widened_after_submission_still_returns_the_result() {
        let job = job_stamped_with(&["audit", "insider_threat"]);
        assert!(job.result_visible_under(&deny(&["audit"])));
        assert!(job.result_visible_under(&BTreeSet::new()));
    }

    /// A result built from several sources fails closed as soon as ONE of them
    /// could now be denied — results carry no per-row source manifest, so there
    /// is nothing to re-filter against.
    #[test]
    fn mixed_source_result_fails_closed_on_one_new_denial() {
        let job = job_stamped_with(&[]);
        assert!(job.result_visible_under(&BTreeSet::new()));
        assert!(!job.result_visible_under(&deny(&["aws_cloudtrail"])));
    }

    /// Swapping one denied source for another is NOT a subset relation: the
    /// newly denied source could be in the result even though the deny-set is
    /// the same size.
    #[test]
    fn equal_size_but_different_denial_fails_closed() {
        let job = job_stamped_with(&["insider_threat"]);
        assert!(!job.result_visible_under(&deny(&["windows_sysmon"])));
    }

    /// Legacy jobs (written before the stamp existed) have unknown provenance.
    /// Unknown is never "unrestricted": only a caller denied nothing at all may
    /// read them.
    #[test]
    fn unstamped_legacy_job_fails_closed_for_restricted_callers() {
        let mut job = job_stamped_with(&[]);
        job.scope_deny = None;
        assert!(!job.result_visible_under(&deny(&["audit"])));
        assert!(!job.result_visible_under(&deny(&["windows_sysmon"])));
        assert!(job.result_visible_under(&BTreeSet::new()));
    }

    /// The stamp is written by the CREATING call, so no job can exist without
    /// one — verified through the store rather than the constructor.
    #[tokio::test]
    async fn in_memory_store_stamps_the_execution_scope_at_creation() {
        let store = InMemoryJobStore::new();
        let scope = ScopeSet::from_denied(deny(&["audit", "insider_threat"]));

        let queued = store
            .create_queued(
                make_test_request(),
                Uuid::now_v7(),
                QueryPriority::Interactive,
                &scope,
            )
            .await
            .unwrap();
        let job = store.get(&queued).await.unwrap();
        assert_eq!(
            job.scope_deny.as_ref(),
            Some(&deny(&["audit", "insider_threat"]))
        );
        assert!(!job.result_visible_under(&deny(&["audit", "insider_threat", "windows_sysmon"])));

        // The non-queued constructor stamps identically.
        let running = store.create(make_test_request(), &scope).await.unwrap();
        let job = store.get(&running).await.unwrap();
        assert_eq!(
            job.scope_deny.as_ref(),
            Some(&deny(&["audit", "insider_threat"]))
        );
    }

    /// NAN-2109 + NAN-2096: the admin list carries every principal's query
    /// preview, so the scope predicate lives INSIDE `list_all` — an admin cannot
    /// enumerate a job whose result the poll route would refuse them. Internal
    /// consumers pass an empty deny-set and still see everything.
    #[tokio::test]
    async fn admin_list_hides_jobs_the_viewer_could_not_poll() {
        let store = InMemoryJobStore::new();
        let visible = store
            .create_queued(
                make_test_request(),
                Uuid::now_v7(),
                QueryPriority::Interactive,
                &ScopeSet::from_denied(deny(&["audit", "windows_sysmon"])),
            )
            .await
            .unwrap();
        let hidden = store
            .create_queued(
                make_test_request(),
                Uuid::now_v7(),
                QueryPriority::Interactive,
                &ScopeSet::from_denied(deny(&["audit"])),
            )
            .await
            .unwrap();

        // Viewer denied `windows_sysmon` sees only the job that already
        // excluded it.
        let viewer = deny(&["audit", "windows_sysmon"]);
        let ids: Vec<String> = store
            .list_all(&viewer)
            .await
            .into_iter()
            .map(|j| j.job_id)
            .collect();
        assert!(ids.contains(&visible));
        assert!(!ids.contains(&hidden));

        // Internal / unrestricted consumers (admission accounting) see all.
        assert_eq!(store.list_all(&BTreeSet::new()).await.len(), 2);
        assert_eq!(store.active_count().await, 2);
    }

    /// Redis parity: an UNRESTRICTED scope must round-trip as "denied nothing",
    /// distinct from a legacy row where the hash field is simply absent. If
    /// these collapsed, either every unrestricted job would fail closed or every
    /// legacy job would be treated as unrestricted.
    #[test]
    fn redis_scope_encoding_distinguishes_unrestricted_from_missing() {
        let unrestricted = RedisJobStore::encode_scope_deny(&ScopeSet::unrestricted());
        assert_eq!(unrestricted, "[]");
        assert_eq!(
            RedisJobStore::decode_scope_deny(Some(&unrestricted)),
            Some(BTreeSet::new())
        );

        let restricted =
            RedisJobStore::encode_scope_deny(&ScopeSet::from_denied(deny(&["audit", "zeek"])));
        assert_eq!(
            RedisJobStore::decode_scope_deny(Some(&restricted)),
            Some(deny(&["audit", "zeek"]))
        );

        // Legacy row: field absent (nil → None) or empty. Both are "unknown".
        assert_eq!(RedisJobStore::decode_scope_deny(None), None);
        assert_eq!(RedisJobStore::decode_scope_deny(Some("")), None);
        // Corrupt payload is unknown too, never silently unrestricted.
        assert_eq!(RedisJobStore::decode_scope_deny(Some("{not json")), None);

        // A restricted scope must never encode to the unrestricted stamp. The
        // encoder's `unwrap_or_default()` failure path yields "" (which decodes
        // to `None`/unknown) precisely so that a serialization failure cannot
        // downgrade a restricted job to "denied nothing" — the one fail-open
        // direction. Serialization of `BTreeSet<String>` cannot actually fail,
        // so the branch is asserted by construction rather than executed.
        assert_ne!(restricted, "[]");
        assert_ne!(
            RedisJobStore::encode_scope_deny(&ScopeSet::unrestricted()),
            ""
        );
    }

    /// NAN-2653: a runner that cannot execute a claim (pin artifacts live on
    /// a peer reader pod, or it is draining) hands the job back without
    /// charging the failure or lease-recovery budgets, under the usual CAS.
    #[tokio::test]
    #[ignore = "requires NANO_TEST_REDIS_URL pointing at Redis or Dragonfly"]
    async fn durable_redis_release_requeues_without_consuming_attempt_budgets() {
        let _test_guard = REDIS_CONTRACT_TEST_LOCK.lock().await;
        let redis_url = std::env::var("NANO_TEST_REDIS_URL")
            .expect("NANO_TEST_REDIS_URL must be set for the ignored integration test");
        let store = RedisJobStore::connect(&redis_url)
            .await
            .expect("connect to Redis/Dragonfly");
        let job_id = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                Uuid::now_v7(),
                QueryPriority::Analytics,
                &ScopeSet::unrestricted(),
                &make_generation_pin(),
                None,
            )
            .await
            .expect("create durable job");
        let worker = format!("release-test-{}", Uuid::now_v7());
        let lease = Duration::from_secs(30);
        let mut conn = store.conn.clone();
        let field_conn = store.conn.clone();
        let field = |name: &'static str| {
            let mut conn = field_conn.clone();
            let key = store.job_key(&job_id);
            async move {
                redis::cmd("HGET")
                    .arg(key)
                    .arg(name)
                    .query_async::<Option<String>>(&mut conn)
                    .await
                    .expect("read job field")
            }
        };
        let mut last_fence = 0;
        for _ in 0..5 {
            let claim = store
                .claim_durable(&worker, lease)
                .await
                .expect("claim")
                .expect("queued job is claimable");
            assert_eq!(claim.job_id, job_id);
            assert_eq!(claim.attempt, 1, "a release never consumes an attempt");
            assert!(claim.fence > last_fence);
            last_fence = claim.fence;
            // Stale fence, stale attempt, and a foreign owner are all refused.
            assert!(!store
                .release_durable_claim(&job_id, &worker, claim.attempt, claim.fence + 1)
                .await
                .expect("stale fence"));
            assert!(!store
                .release_durable_claim(&job_id, &worker, claim.attempt + 1, claim.fence)
                .await
                .expect("stale attempt"));
            assert!(!store
                .release_durable_claim(&job_id, "someone-else", claim.attempt, claim.fence)
                .await
                .expect("foreign owner"));
            assert!(store
                .release_durable_claim(&job_id, &worker, claim.attempt, claim.fence)
                .await
                .expect("release current claim"));
            // A second release of the same attempt is a no-op.
            assert!(!store
                .release_durable_claim(&job_id, &worker, claim.attempt, claim.fence)
                .await
                .expect("double release"));
            // The released attempt is fenced off everywhere.
            assert!(!store
                .renew_durable_lease(&job_id, &worker, claim.attempt, claim.fence, lease)
                .await
                .expect("stale renew"));
            let queued = store.get(&job_id).await.expect("released job");
            assert_eq!(queued.status, SearchJobStatus::Queued);
            assert_eq!(queued.attempt, 0);
            assert_eq!(queued.fence, claim.fence + 1);
            assert_eq!(field("execution_failures").await.as_deref(), Some("0"));
            assert_eq!(field("lease_recoveries").await.as_deref().unwrap_or("0"), "0");
            assert_eq!(field("lease_owner").await.as_deref(), Some(""));
            let leased: Option<f64> = redis::cmd("ZSCORE")
                .arg(store.durable_lease_key())
                .arg(&job_id)
                .query_async(&mut conn)
                .await
                .expect("lease score");
            assert!(leased.is_none(), "a released job holds no lease");
            let queued_score: Option<f64> = redis::cmd("ZSCORE")
                .arg(store.durable_queue_key())
                .arg(&job_id)
                .query_async(&mut conn)
                .await
                .expect("queue score");
            assert!(queued_score.is_some(), "a released job is claimable again");
        }
        assert_eq!(field("claim_releases").await.as_deref(), Some("5"));
        // The full failure budget is still available after five releases.
        let claim = store
            .claim_durable(&worker, lease)
            .await
            .expect("claim")
            .expect("released job is claimable");
        assert!(store
            .fail_durable_attempt(
                &job_id, &worker, claim.attempt, claim.fence, "worker execution failed", true,
                false, 2,
            )
            .await
            .expect("retryable failure"));
        assert_eq!(
            store.get(&job_id).await.expect("job").status,
            SearchJobStatus::Queued,
            "releases must not have consumed the execution-failure budget"
        );
        store.remove(&job_id).await;
    }

    /// Real Redis/Dragonfly contract test. It is ignored in ordinary unit runs
    /// because it needs a live metadata service; CI and release validation run
    /// it explicitly with `NANO_TEST_REDIS_URL`.
    #[tokio::test]
    #[ignore = "requires NANO_TEST_REDIS_URL pointing at Redis or Dragonfly"]
    async fn durable_redis_claim_fence_requeue_and_pointer_only_completion() {
        let _test_guard = REDIS_CONTRACT_TEST_LOCK.lock().await;
        let redis_url = std::env::var("NANO_TEST_REDIS_URL")
            .expect("NANO_TEST_REDIS_URL must be set for the ignored integration test");
        let store = RedisJobStore::connect(&redis_url)
            .await
            .expect("connect to Redis/Dragonfly");
        let active_before = store.active_count().await;
        let mut pins_before = store
            .active_durable_generation_pins()
            .await
            .expect("read initial active generation pins");
        pins_before.sort_by(|left, right| left.generation_id.cmp(&right.generation_id));
        let user_id = Uuid::now_v7();
        let scope = ScopeSet::from_denied(deny(&["audit"]));
        let job_id = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                None,
            )
            .await
            .expect("create durable job");

        let created = store.get(&job_id).await.expect("created job");
        assert_eq!(created.backend, SearchJobBackend::LakeDurable);
        assert_eq!(created.status, SearchJobStatus::Queued);
        assert_eq!(created.scope_deny, Some(deny(&["audit"])));
        assert_eq!(created.generation_pin, Some(make_generation_pin()));
        let active_pins = store
            .active_durable_generation_pins()
            .await
            .expect("read active generation pins");
        assert!(active_pins.contains(&make_generation_pin()));
        assert_eq!(store.active_count().await, active_before + 1);
        assert_eq!(
            durable_scale_signal_entries(&store).await,
            vec![job_id.clone()]
        );

        // A runner built against the original queue contract only polls the
        // unversioned key. New task variants must never appear there during a
        // rolling upgrade, otherwise the old process claims first and fails
        // while deserializing `task_json`.
        let mut conn = store.conn.clone();
        let current_score: Option<f64> = redis::cmd("ZSCORE")
            .arg(store.durable_queue_key())
            .arg(&job_id)
            .query_async(&mut conn)
            .await
            .expect("read current durable queue");
        let legacy_score: Option<f64> = redis::cmd("ZSCORE")
            .arg(store.legacy_durable_queue_key())
            .arg(&job_id)
            .query_async(&mut conn)
            .await
            .expect("read legacy durable queue");
        assert!(current_score.is_some());
        assert!(legacy_score.is_none());

        // Upgrades may encounter a populated authoritative sorted set with no
        // v2 list signal yet. Connecting a new process must rebuild it before
        // KEDA is allowed to observe an empty queue.
        let mut conn = store.conn.clone();
        let _: () = redis::cmd("DEL")
            .arg(store.durable_scale_signal_key())
            .query_async(&mut conn)
            .await
            .expect("delete test scale signal");
        assert!(durable_scale_signal_entries(&store).await.is_empty());
        let store = RedisJobStore::connect(&redis_url)
            .await
            .expect("reconnect and rebuild durable scale signal");
        assert_eq!(
            durable_scale_signal_entries(&store).await,
            vec![job_id.clone()]
        );

        let worker = format!("test-runner-{}", Uuid::now_v7());
        let first = store
            .claim_durable(&worker, Duration::from_secs(30))
            .await
            .expect("claim")
            .expect("queued claim");
        assert_eq!(first.job_id, job_id);
        assert_eq!(first.attempt, 1);
        assert_eq!(first.fence, 1);
        assert_eq!(first.resource_class, DurableQueryResourceClass::Medium);
        assert_eq!(first.generation_pin, make_generation_pin());
        assert_eq!(first.task, DurableLakeTask::SearchNplV1);
        assert!(
            store
                .active_durable_generation_pins()
                .await
                .expect("read running generation pins")
                .contains(&make_generation_pin()),
            "a claimed/running job must remain in metadata-GC pin authority"
        );
        assert!(durable_scale_signal_entries(&store).await.is_empty());
        assert!(store
            .renew_durable_lease(
                &job_id,
                &worker,
                first.attempt,
                first.fence,
                Duration::from_secs(30),
            )
            .await
            .expect("renew"));
        assert!(!store
            .renew_durable_lease(
                &job_id,
                &worker,
                first.attempt,
                first.fence + 1,
                Duration::from_secs(30),
            )
            .await
            .expect("reject stale renew"));
        let progress = SearchJobProgress {
            phase: None,
            attempt: None,
            rows_scanned: 12,
            rows_total: 100,
            percent: 12,
            elapsed_ms: 345,
        };
        assert!(store
            .update_durable_progress(&job_id, &worker, first.attempt, first.fence, &progress,)
            .await
            .expect("publish fenced progress"));
        let observed_progress = store
            .get_status(&job_id)
            .await
            .expect("running status")
            .progress
            .expect("running progress");
        assert_eq!(observed_progress.rows_scanned, 12);
        assert_eq!(observed_progress.percent, 12);

        // Force this isolated test lease into the past without sleeping. The
        // reconciler must fence and requeue it atomically.
        let mut conn = store.conn.clone();
        let expired_ms = Utc::now().timestamp_millis() - 1;
        let _: () = redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(store.job_key(&job_id))
            .arg("lease_expires_at_ms")
            .arg(expired_ms)
            .ignore()
            .cmd("ZADD")
            .arg(store.durable_lease_key())
            .arg(expired_ms)
            .arg(&job_id)
            .ignore()
            .query_async(&mut conn)
            .await
            .expect("expire test lease");
        assert_eq!(
            store.reconcile_durable_leases(2).await.expect("reconcile"),
            1
        );
        let requeued = store.get(&job_id).await.expect("requeued job");
        assert_eq!(requeued.status, SearchJobStatus::Queued);
        assert_eq!(requeued.attempt, 1);
        assert_eq!(requeued.fence, 2);
        assert!(
            store
                .active_durable_generation_pins()
                .await
                .expect("read requeued generation pins")
                .contains(&make_generation_pin()),
            "a requeued job must remain in metadata-GC pin authority"
        );
        assert_eq!(
            durable_scale_signal_entries(&store).await,
            vec![job_id.clone()]
        );

        let second = store
            .claim_durable(&worker, Duration::from_secs(30))
            .await
            .expect("reclaim")
            .expect("requeued claim");
        assert_eq!(second.job_id, job_id);
        assert_eq!(second.attempt, 2);
        assert_eq!(second.fence, 3);
        assert_eq!(
            second.resource_class,
            DurableQueryResourceClass::Medium,
            "a lease recovery must not consume costly resource escalation"
        );
        assert!(!store
            .update_durable_progress(&job_id, &worker, first.attempt, first.fence, &progress,)
            .await
            .expect("reject stale progress"));

        assert!(store
            .fail_durable_attempt(
                &job_id,
                &worker,
                second.attempt,
                second.fence,
                "Code: 241 MEMORY_LIMIT_EXCEEDED",
                true,
                true,
                2,
            )
            .await
            .expect("requeue typed resource failure"));
        assert_eq!(
            durable_scale_signal_entries(&store).await,
            vec![job_id.clone()]
        );
        let third = store
            .claim_durable(&worker, Duration::from_secs(30))
            .await
            .expect("claim promoted retry")
            .expect("promoted claim");
        assert_eq!(third.attempt, 3);
        assert_eq!(third.resource_class, DurableQueryResourceClass::Large);
        assert!(durable_scale_signal_entries(&store).await.is_empty());

        let result_ref = SearchJobResultRef {
            tenant_id: None,
            manifest_uri: format!("file:///tmp/nano-job-results/{job_id}/manifest.json"),
            manifest_sha256: "a".repeat(64),
            rows: 42,
            parts: 2,
            has_more: false,
            page_rows: 10_000,
            retention_proof: None,
        };
        assert!(!store
            .complete_durable(&job_id, &worker, first.attempt, first.fence, &result_ref,)
            .await
            .expect("reject stale completion"));
        let completed_progress = SearchJobProgress {
            phase: None,
            attempt: None,
            rows_scanned: result_ref.rows,
            rows_total: result_ref.rows,
            percent: 100,
            elapsed_ms: 678,
        };
        assert!(store
            .update_durable_progress(
                &job_id,
                &worker,
                third.attempt,
                third.fence,
                &completed_progress,
            )
            .await
            .expect("publish completed progress"));
        assert!(store
            .complete_durable(&job_id, &worker, third.attempt, third.fence, &result_ref,)
            .await
            .expect("complete current attempt"));

        let status = store.get_status(&job_id).await.expect("completed status");
        assert_eq!(status.status, SearchJobStatus::Completed);
        assert_eq!(status.result_ref, Some(result_ref));
        assert!(status.result.is_none());
        assert_eq!(
            status.progress.expect("completed progress").elapsed_ms,
            completed_progress.elapsed_ms
        );
        let result_gz: Vec<u8> = redis::cmd("HGET")
            .arg(store.job_key(&job_id))
            .arg("result_gz")
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        assert!(result_gz.is_empty(), "durable result bytes entered Redis");
        assert!(durable_scale_signal_entries(&store).await.is_empty());
        assert_eq!(
            store.active_count().await,
            active_before,
            "retained terminal history must not consume active-job admission capacity"
        );
        let mut pins_after = store
            .active_durable_generation_pins()
            .await
            .expect("read terminal generation pins");
        pins_after.sort_by(|left, right| left.generation_id.cmp(&right.generation_id));
        assert_eq!(
            pins_after, pins_before,
            "completed result manifests must release their source generation"
        );

        store.remove(&job_id).await;
        assert!(store.get(&job_id).await.is_none());
        assert!(durable_scale_signal_entries(&store).await.is_empty());
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    #[ignore = "requires NANO_TEST_REDIS_URL pointing at Redis or Dragonfly"]
    async fn durable_redis_shared_admission_atomically_round_trips_authority() {
        let _test_guard = REDIS_CONTRACT_TEST_LOCK.lock().await;
        let redis_url = std::env::var("NANO_TEST_REDIS_URL")
            .expect("NANO_TEST_REDIS_URL must be set for the ignored integration test");
        let tenant_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let retained = SearchTenantScope::enterprise_shared_retained(tenant_id, 13, 90, 0).unwrap();
        let store = RedisJobStore::connect_enterprise_shared_retained(&redis_url, retained)
            .await
            .expect("connect shared Redis/Dragonfly namespace");
        let authority = DurableSearchJobAuthority {
            tenant_id,
            user_id,
            credential: DurableSearchCredentialAuthority::Session {
                access_jti: Uuid::now_v7(),
                credential_time_micros: Utc::now().timestamp_micros(),
            },
            membership_authority_revision: 7,
            entitlement_assignment_revision: 11,
            retention_revision: 13,
            retention_days: 90,
            irreversible_event_time_floor_micros: 0,
            roles: vec!["analyst".to_string()],
            permissions: vec!["search:execute".to_string()],
        };
        let scope = ScopeSet::from_denied(deny(&["audit", "windows_sysmon"]));

        // Shared jobs must fail closed without a tenant signing key, even when
        // the request otherwise carries valid authority. The remainder tests
        // the current signed contract, not the retired unsigned admission path.
        let unsigned_error = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                Some(&authority),
            )
            .await
            .expect_err("unsigned shared admission must fail");
        assert!(unsigned_error.to_string().contains("job signing key"));
        let store = store
            .with_job_signing_key(DurableJobSigningKey::from_bytes([0x7b; 32], tenant_id))
            .expect("attach synthetic tenant signing key");

        assert!(store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                None,
            )
            .await
            .is_err());
        let mut foreign = authority.clone();
        foreign.tenant_id = Uuid::now_v7();
        assert!(store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                Some(&foreign),
            )
            .await
            .is_err());

        let job_id = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                Some(&authority),
            )
            .await
            .expect("create shared durable job");
        let stored = store.get(&job_id).await.expect("read shared durable job");
        assert_eq!(stored.durable_authority.as_ref(), Some(&authority));
        let claim = store
            .claim_durable("shared-authority-test", Duration::from_secs(30))
            .await
            .expect("claim shared job")
            .expect("queued shared claim");
        assert_eq!(claim.tenant_id, Some(tenant_id));
        assert_eq!(claim.user_id, user_id);
        assert_eq!(claim.authority, Some(authority.clone()));
        assert_eq!(claim.scope_deny, *scope.deny_set());
        assert_eq!(claim.scope_artifact_deny, *scope.artifact_deny_set());

        store.cancel(&job_id).await;
        store.remove(&job_id).await;

        // Runtime sizing is intentionally mutable/unsigned (promotion changes
        // it). An invalid sizing field must not strand a valid signed job in
        // running after post-signature validation rejects the record.
        let stale_job = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                Some(&authority),
            )
            .await
            .expect("enqueue signed job before invalid runtime hint");
        let _: () = redis::cmd("HSET")
            .arg(store.job_key(&stale_job))
            .arg("resource_class")
            .arg("invalid-fixture-class")
            .query_async(&mut store.conn.clone())
            .await
            .expect("set invalid unsigned runtime hint in owned job");
        let rejected = store
            .claim_durable("invalid-runtime-hint-test", Duration::from_secs(30))
            .await
            .expect_err("invalid runtime hint must be rejected after signature verification");
        assert!(matches!(rejected, DurableJobStoreError::ClaimRejected));
        let failed = store.get(&stale_job).await.expect("read rejected job");
        assert_eq!(failed.status, SearchJobStatus::Failed);
        assert_eq!(failed.attempt, 1);
        let lease_score: Option<f64> = redis::cmd("ZSCORE")
            .arg(store.durable_lease_key())
            .arg(&stale_job)
            .query_async(&mut store.conn.clone())
            .await
            .expect("read rejected lease index");
        assert!(lease_score.is_none());
        assert!(durable_scale_signal_entries(&store).await.is_empty());
        assert!(store
            .claim_durable("invalid-runtime-hint-test", Duration::from_secs(30))
            .await
            .expect("terminal rejection must not requeue")
            .is_none());
        store.remove(&stale_job).await;
        let next_job = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                user_id,
                QueryPriority::Analytics,
                &scope,
                &make_generation_pin(),
                Some(&authority),
            )
            .await
            .expect("enqueue healthy job after rejection");
        let next_claim = store
            .claim_durable("invalid-runtime-hint-test", Duration::from_secs(30))
            .await
            .expect("continue claiming after rejection")
            .expect("healthy job is claimable");
        assert_eq!(next_claim.job_id, next_job);
        store.cancel(&next_job).await;
        store.remove(&next_job).await;
    }

    #[tokio::test]
    #[ignore = "requires NANO_TEST_REDIS_URL pointing at Redis or Dragonfly"]
    async fn durable_redis_cancel_fences_a_running_publisher() {
        let _test_guard = REDIS_CONTRACT_TEST_LOCK.lock().await;
        let redis_url = std::env::var("NANO_TEST_REDIS_URL")
            .expect("NANO_TEST_REDIS_URL must be set for the ignored integration test");
        let store = RedisJobStore::connect(&redis_url)
            .await
            .expect("connect to Redis/Dragonfly");
        let job_id = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                Uuid::now_v7(),
                QueryPriority::Analytics,
                &ScopeSet::unrestricted(),
                &make_generation_pin(),
                None,
            )
            .await
            .expect("create durable job");
        assert_eq!(
            durable_scale_signal_entries(&store).await,
            vec![job_id.clone()]
        );
        let worker = format!("test-runner-{}", Uuid::now_v7());
        let claim = store
            .claim_durable(&worker, Duration::from_secs(30))
            .await
            .expect("claim")
            .expect("queued claim");
        assert!(durable_scale_signal_entries(&store).await.is_empty());
        store.cancel(&job_id).await;
        assert!(durable_scale_signal_entries(&store).await.is_empty());

        let result_ref = SearchJobResultRef {
            tenant_id: None,
            manifest_uri: format!("s3://test-results/{job_id}/manifest.json"),
            manifest_sha256: "b".repeat(64),
            rows: 1,
            parts: 1,
            has_more: false,
            page_rows: 10_000,
            retention_proof: None,
        };
        assert!(!store
            .complete_durable(&job_id, &worker, claim.attempt, claim.fence, &result_ref,)
            .await
            .expect("cancelled completion is a stale no-op"));
        assert_eq!(
            store.get(&job_id).await.expect("cancelled job").status,
            SearchJobStatus::Cancelled
        );
        store.remove(&job_id).await;
    }

    #[tokio::test]
    #[ignore = "requires isolated NANO_TEST_REDIS_URL; scripts/test-durable-claim-cancellation.mjs"]
    async fn durable_redis_claim_cancellation_rejects_expired_and_replaced_attempts() {
        let _test_guard = REDIS_CONTRACT_TEST_LOCK.lock().await;
        let url=std::env::var("NANO_TEST_REDIS_URL").expect("isolated fixture required");
        let store=RedisJobStore::connect(&url).await.unwrap();
        let id=store.create_durable_queued(make_test_request(), &DurableLakeTask::SearchNplV1,
            Uuid::now_v7(), QueryPriority::Analytics, &ScopeSet::unrestricted(), &make_generation_pin(), None).await.unwrap();
        let first=store.claim_durable("first",Duration::from_secs(30)).await.unwrap().unwrap();
        assert_eq!(first.job_id,id);
        assert!(!store.cancel_durable_claim(&id,"foreign",first.attempt,first.fence).await.unwrap());
        assert!(!store.cancel_durable_claim(&id,"first",first.attempt+1,first.fence).await.unwrap());
        let mut conn=store.conn.clone();
        // Move only this synthetic lease into the past; do not wait on a real clock.
        let _:()=redis::cmd("HSET").arg(store.job_key(&id)).arg("lease_expires_at_ms").arg(1)
            .query_async(&mut conn).await.unwrap();
        let _:()=redis::cmd("ZADD").arg(store.durable_lease_key()).arg(1).arg(&id)
            .query_async(&mut conn).await.unwrap();
        assert!(!store.cancel_durable_claim(&id,"first",first.attempt,first.fence).await.unwrap());
        assert_eq!(store.reconcile_durable_leases(2).await.unwrap(),1);
        let next=store.claim_durable("replacement",Duration::from_secs(30)).await.unwrap().unwrap();
        assert!(next.fence>first.fence);
        assert!(!store.cancel_durable_claim(&id,"first",first.attempt,first.fence).await.unwrap());
        assert!(store.cancel_durable_claim(&id,&next.lease_owner,next.attempt,next.fence).await.unwrap());
        assert!(!store.cancel_durable_claim(&id,&next.lease_owner,next.attempt,next.fence).await.unwrap());
        let cancelled = store.get(&id).await.unwrap();
        assert_eq!(cancelled.status, SearchJobStatus::Cancelled);
        assert!(cancelled.error.unwrap().contains("authority revoked"));
        assert!(durable_scale_signal_entries(&store).await.is_empty());
        let ttl:i64=redis::cmd("TTL").arg(store.job_key(&id)).query_async(&mut conn).await.unwrap();
        assert!(ttl>0 && ttl<=DURABLE_COMPLETED_JOB_TTL.as_secs() as i64);
        store.remove(&id).await;
    }

    #[tokio::test]
    #[ignore = "requires NANO_TEST_REDIS_URL pointing at Redis or Dragonfly"]
    async fn durable_result_reference_and_index_reconciliation() {
        let _test_guard = REDIS_CONTRACT_TEST_LOCK.lock().await;
        let redis_url = std::env::var("NANO_TEST_REDIS_URL")
            .expect("NANO_TEST_REDIS_URL must be set for the ignored integration test");
        let store = RedisJobStore::connect(&redis_url)
            .await
            .expect("connect to Redis/Dragonfly");
        let mut conn = store.conn.clone();

        // A live queued durable job is referenced through its record.
        let live_job = store
            .create_durable_queued(
                make_test_request(),
                &DurableLakeTask::SearchNplV1,
                Uuid::now_v7(),
                QueryPriority::Analytics,
                &ScopeSet::unrestricted(),
                &make_generation_pin(),
                None,
            )
            .await
            .expect("create durable job");
        assert_eq!(
            store
                .durable_result_reference(&live_job)
                .await
                .expect("live verdict"),
            Some(DurableResultReference::JobRecord)
        );

        // An orphaned index member: present in the set, but its job hash has
        // expired and it holds no queue or lease reference.
        let orphan = format!("gc-orphan-{}", Uuid::now_v7());
        let _: () = redis::cmd("SADD")
            .arg(store.all_index_key())
            .arg(&orphan)
            .query_async(&mut conn)
            .await
            .expect("plant orphan member");
        assert_eq!(
            store
                .durable_result_reference(&orphan)
                .await
                .expect("orphan verdict"),
            None,
            "the ALL index alone must not keep an artifact alive"
        );

        // Reconciliation removes the orphan and never touches the live member.
        let report = store
            .reconcile_index_members(&store.all_index_key(), &[orphan.clone(), live_job.clone()])
            .await
            .expect("reconcile");
        assert_eq!(report.scanned, 2);
        assert_eq!(report.removed, 1);
        assert_eq!(report.retained, 1);
        let orphan_present: bool = redis::cmd("SISMEMBER")
            .arg(store.all_index_key())
            .arg(&orphan)
            .query_async(&mut conn)
            .await
            .expect("check orphan");
        let live_present: bool = redis::cmd("SISMEMBER")
            .arg(store.all_index_key())
            .arg(&live_job)
            .query_async(&mut conn)
            .await
            .expect("check live member");
        assert!(!orphan_present, "orphan member must be reconciled away");
        assert!(live_present, "live member must survive reconciliation");

        // A job referenced ONLY by a queue entry (record raced away) is still
        // protected: plant a queue-only member and confirm both the verdict
        // and the reconciler leave it alone.
        let queue_only = format!("gc-queue-only-{}", Uuid::now_v7());
        let _: () = redis::cmd("ZADD")
            .arg(store.durable_queue_key())
            .arg(0)
            .arg(&queue_only)
            .query_async(&mut conn)
            .await
            .expect("plant queue-only member");
        let _: () = redis::cmd("SADD")
            .arg(store.all_index_key())
            .arg(&queue_only)
            .query_async(&mut conn)
            .await
            .expect("plant queue-only index member");
        assert_eq!(
            store
                .durable_result_reference(&queue_only)
                .await
                .expect("queue-only verdict"),
            Some(DurableResultReference::DurableQueue)
        );
        let report = store
            .reconcile_index_members(&store.all_index_key(), &[queue_only.clone()])
            .await
            .expect("reconcile queue-only");
        assert_eq!(report.retained, 1);
        assert_eq!(report.removed, 0);

        // Clean up everything this test planted.
        let _: () = redis::cmd("ZREM")
            .arg(store.durable_queue_key())
            .arg(&queue_only)
            .query_async(&mut conn)
            .await
            .expect("remove planted queue member");
        let _: () = redis::cmd("SREM")
            .arg(store.all_index_key())
            .arg(&queue_only)
            .query_async(&mut conn)
            .await
            .expect("remove planted index member");
        store.remove(&live_job).await;
        assert!(store.get(&live_job).await.is_none());
    }

    #[tokio::test]
    async fn test_queued_status_in_response() {
        let store = InMemoryJobStore::new();
        let user_id = Uuid::now_v7();
        let job_id = store
            .create_queued(
                make_test_request(),
                user_id,
                QueryPriority::Interactive,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();

        let status = store.get_status(&job_id).await.unwrap();
        assert_eq!(status.status, SearchJobStatus::Queued);
    }
}

/// Render a Redis URL for logs without its credential (`redis://user:***@host`).
pub(crate) fn redact_redis_url(url: &str) -> String {
    match url.find("://").map(|i| i + 3) {
        Some(start) => match url[start..].find('@') {
            Some(at) => {
                let user = url[start..start + at].split(':').next().unwrap_or("");
                format!("{}{}:***@{}", &url[..start], user, &url[start + at + 1..])
            }
            None => url.to_string(),
        },
        None => url.to_string(),
    }
}
