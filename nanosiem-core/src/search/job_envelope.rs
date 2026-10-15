// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hosted transport validation, before a coordinator claim reaches a runner.
//! This does not select a backend or replace live authority checks at execution,
//! heartbeat and publication. Dedicated/Redis decoding remains unchanged.

use std::collections::BTreeSet;
use uuid::Uuid;

use super::admission::QueryPriority;
use super::job_signing::{DurableJobEnvelope, DurableJobSigningKey};
use super::jobs::{
    DurableJobStoreError, DurableLakeGenerationPin, DurableLakeTask, DurableQueryResourceClass,
    DurableSearchJobAuthority, DurableSearchJobClaim,
};
use super::tenant::SearchTenantScope;
use super::types::SearchRequest;
use crate::auth::ScopeSet;

/// Server-authored admission data. Object storage coordinates and authority
/// never come directly from a public submission body.
pub struct HostedJobSubmission<'a> {
    pub request: &'a SearchRequest,
    pub task: &'a DurableLakeTask,
    pub user_id: Uuid,
    pub priority: QueryPriority,
    pub scope: &'a ScopeSet,
    pub generation_pin: &'a DurableLakeGenerationPin,
    pub authority: &'a DurableSearchJobAuthority,
    pub created_at_ms: i64,
}

/// Prepare the exact immutable bytes for idempotent submission. The caller
/// retains this envelope across transport retries; it must not regenerate the
/// timestamp or job ID after a lost acknowledgement.
pub fn encode_hosted_job(
    submission: HostedJobSubmission<'_>,
    context: HostedClaimContext<'_>,
) -> Result<DurableJobEnvelope, DurableJobStoreError> {
    let rejected = || DurableJobStoreError::ClaimRejected;
    context
        .tenant
        .require_retention_identity()
        .map_err(|_| rejected())?;
    if context.tenant.tenant_id() != Some(context.signer.tenant_id())
        || context.job_id.is_nil()
        || context.assignment_revision <= 0
        || context.job_key.is_empty()
        || context.job_key.len() > 1024
        || submission.created_at_ms <= 0
        || submission.authority.entitlement_assignment_revision != context.assignment_revision
    {
        return Err(rejected());
    }
    submission
        .generation_pin
        .validate()
        .map_err(|_| rejected())?;
    submission.task.validate().map_err(|_| rejected())?;
    submission
        .authority
        .validate_for(context.tenant, submission.user_id)
        .map_err(|_| rejected())?;
    let mut envelope = DurableJobEnvelope {
        tenant_id: context.signer.tenant_id().to_string(),
        job_id: context.job_id.to_string(),
        backend: "lake_durable".into(),
        user_id: submission.user_id.to_string(),
        priority: submission.priority.to_string(),
        created_at_ms: submission.created_at_ms.to_string(),
        request_json: serde_json::to_string(submission.request).map_err(|_| rejected())?,
        task_json: serde_json::to_string(submission.task).map_err(|_| rejected())?,
        generation_pin_json: serde_json::to_string(submission.generation_pin)
            .map_err(|_| rejected())?,
        authority_json: serde_json::to_string(submission.authority).map_err(|_| rejected())?,
        scope_deny: serde_json::to_string(submission.scope.deny_set()).map_err(|_| rejected())?,
        scope_artifact_deny: serde_json::to_string(submission.scope.artifact_deny_set())
            .map_err(|_| rejected())?,
        signature: String::new(),
    };
    envelope.signature = context
        .signer
        .sign(&envelope.signed_record(context.job_key));
    envelope
        .verify(context.signer, context.job_key, context.job_id)
        .map_err(|_| rejected())?;
    // Contract limit applies to the JSON-string payload, including escaping,
    // not only to the HMAC canonical byte sequence.
    let payload = serde_json::to_string(&envelope).map_err(|_| rejected())?;
    if serde_json::to_vec(&payload).map_err(|_| rejected())?.len() > 65_536 {
        return Err(rejected());
    }
    Ok(envelope)
}

/// Resolved by trusted runtime configuration, never taken from the payload.
#[derive(Clone, Copy)]
pub struct HostedClaimContext<'a> {
    pub tenant: SearchTenantScope,
    pub assignment_revision: i64,
    pub signer: &'a DurableJobSigningKey,
    /// Includes physical tenant, retention, assignment and recovery epoch.
    pub job_key: &'a str,
    pub job_id: Uuid,
}

/// Mutable CAS state returned by the authenticated coordinator. These fields
/// are not part of the immutable enqueue-time signature.
pub struct HostedClaimLease {
    pub owner: String,
    pub attempt: u32,
    pub fence: u64,
    pub expires_at_ms: i64,
    pub resource_class: DurableQueryResourceClass,
}

/// Immutable authenticated job data, also used for queued/terminal polling.
/// Polling must not invent a running lease just to validate an envelope.
pub struct DecodedHostedJob {
    pub request: SearchRequest,
    pub user_id: Uuid,
    pub priority: QueryPriority,
    pub scope_deny: BTreeSet<String>,
    pub scope_artifact_deny: BTreeSet<String>,
    pub authority: DurableSearchJobAuthority,
    pub generation_pin: DurableLakeGenerationPin,
    pub task: DurableLakeTask,
    pub created_at_ms: i64,
}

/// Decode only after authenticating the exact transport strings. Collapse
/// malformed record errors to a content-free rejection; JSON errors can contain
/// query/authority data and must not escape to logs or durable error fields.
pub fn decode_hosted_claim(
    envelope: &DurableJobEnvelope,
    context: HostedClaimContext<'_>,
    lease: HostedClaimLease,
) -> Result<DurableSearchJobClaim, DurableJobStoreError> {
    let rejected = || DurableJobStoreError::ClaimRejected;
    context
        .tenant
        .require_retention_identity()
        .map_err(|_| rejected())?;
    if context.tenant.tenant_id() != Some(context.signer.tenant_id())
        || context.assignment_revision <= 0
        || context.job_id.is_nil()
        || lease.owner.is_empty()
        || lease.owner.len() > 128
        || !lease
            .owner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || lease.attempt == 0
        || lease.fence == 0
        || lease.expires_at_ms <= 0
    {
        return Err(rejected());
    }
    let job = decode_hosted_job(envelope, context)?;
    Ok(DurableSearchJobClaim {
        job_id: context.job_id.to_string(),
        tenant_id: context.tenant.tenant_id(),
        attempt: lease.attempt,
        fence: lease.fence,
        lease_owner: lease.owner,
        lease_expires_at_ms: lease.expires_at_ms,
        request: job.request,
        user_id: job.user_id,
        priority: job.priority,
        scope_deny: job.scope_deny,
        scope_artifact_deny: job.scope_artifact_deny,
        authority: Some(job.authority),
        generation_pin: job.generation_pin,
        task: job.task,
        resource_class: lease.resource_class,
    })
}

pub fn decode_hosted_job(
    envelope: &DurableJobEnvelope,
    context: HostedClaimContext<'_>,
) -> Result<DecodedHostedJob, DurableJobStoreError> {
    let rejected = || DurableJobStoreError::ClaimRejected;
    context
        .tenant
        .require_retention_identity()
        .map_err(|_| rejected())?;
    if context.tenant.tenant_id() != Some(context.signer.tenant_id())
        || context.assignment_revision <= 0
        || context.job_id.is_nil()
    {
        return Err(rejected());
    }
    envelope
        .verify(context.signer, context.job_key, context.job_id)
        .map_err(|_| rejected())?;
    let request = serde_json::from_str(&envelope.request_json).map_err(|_| rejected())?;
    let user_id = Uuid::parse_str(&envelope.user_id).map_err(|_| rejected())?;
    let priority = envelope.priority.parse().map_err(|_| rejected())?;
    let scope_deny = serde_json::from_str(&envelope.scope_deny).map_err(|_| rejected())?;
    let scope_artifact_deny =
        serde_json::from_str(&envelope.scope_artifact_deny).map_err(|_| rejected())?;
    let generation_pin: DurableLakeGenerationPin =
        serde_json::from_str(&envelope.generation_pin_json).map_err(|_| rejected())?;
    generation_pin.validate().map_err(|_| rejected())?;
    let task: DurableLakeTask =
        serde_json::from_str(&envelope.task_json).map_err(|_| rejected())?;
    task.validate().map_err(|_| rejected())?;
    let authority: DurableSearchJobAuthority =
        serde_json::from_str(&envelope.authority_json).map_err(|_| rejected())?;
    authority
        .validate_for(context.tenant, user_id)
        .map_err(|_| rejected())?;
    if authority.entitlement_assignment_revision != context.assignment_revision {
        return Err(rejected());
    }
    let created_at_ms = envelope
        .created_at_ms
        .parse::<i64>()
        .map_err(|_| rejected())?;
    if created_at_ms <= 0 {
        return Err(rejected());
    }
    Ok(DecodedHostedJob {
        request,
        user_id,
        priority,
        scope_deny,
        scope_artifact_deny,
        authority,
        generation_pin,
        task,
        created_at_ms,
    })
}

#[cfg(all(test, feature = "enterprise"))]
#[path = "job_envelope_tests.rs"]
mod tests;
