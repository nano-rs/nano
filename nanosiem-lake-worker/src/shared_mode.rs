// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared-deployment mode switch and its hook point (NAN-3861).
//!
//! the hosted shared deployment mode selects the hosted multi-tenant
//! object-store authority: every durable write must go through an
//! owner-authorized serialized writer, and ambient OpenDAL/Iceberg writers
//! are refused. Open code asks this module, never the hosted modules:
//!
//! - [`active`] and [`require_serialized_writer_authority`] are plain env
//!   checks and behave the same in every build.
//! - The remaining decisions go through [`SharedModeHooks`]. The enterprise
//!   build installs the hosted implementation; an open build has none, so it
//!   refuses every shared-mode write and admits everything else exactly as
//!   the hosted guards do outside shared mode.

use std::future::Future;
use std::pin::Pin;

use anyhow::{bail, Result};

use crate::job::{DurableResultPublication, ResultArtifactRef};
use crate::otel_handoff::StagedTailPublication;

/// The `DEPLOYMENT_MODE` value that selects the hosted shared authority.
pub const SHARED_DEPLOYMENT_MODE: &str = "enterprise_shared";

pub fn active() -> bool {
    std::env::var("DEPLOYMENT_MODE").ok().as_deref() == Some(SHARED_DEPLOYMENT_MODE)
}

/// Refuse every hosted writer that still reaches R2 through ambient
/// OpenDAL/Iceberg credentials. Conditional create by itself cannot serialize
/// a delayed writer against a retention tombstone, and Iceberg FileIO also
/// exposes multipart/delete operations without the event-time identity the
/// tenant Worker/DO must attest. Call this before schema or data mutation.
pub fn require_serialized_writer_authority(writer_class: &str) -> Result<()> {
    if active() {
        bail!(
            "direct enterprise_shared R2 {writer_class} mutation is release-blocked: use the serialized writer permit/commit authority"
        );
    }
    Ok(())
}

/// Boxed future returned by [`SharedModeHooks::commit_durable_result`].
pub(crate) type HookFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Shared-mode decisions open code delegates. Implemented by the hosted
/// authority in enterprise builds and by [`OpenBuild`] otherwise.
pub(crate) trait SharedModeHooks: Send + Sync {
    /// Release block for primary Iceberg data/manifest/metadata mutation.
    fn require_serialized_primary_iceberg_authority(&self, operation: &str) -> Result<()>;
    /// Admit the tail-pack fast-append only through the exact catalog broker.
    fn require_tail_pack_catalog_authority(&self, tenant_id: &str, table_location: &str) -> Result<()>;
    /// Admit the metadata-only additive-schema transaction.
    fn require_additive_schema_broker_authority(&self) -> Result<()>;
    /// Check one staged OTLP hot-tail object against the writer contract
    /// before it is published or mirrored.
    fn validate_staged_tail(&self, publication: &StagedTailPublication) -> Result<()>;
    /// Publish a durable query result through the serialized writer. Called
    /// only when [`active`].
    fn commit_durable_result<'a>(
        &'a self,
        publication: DurableResultPublication<'a>,
    ) -> HookFuture<'a, ResultArtifactRef>;
}

pub(crate) fn hooks() -> &'static dyn SharedModeHooks {
    #[cfg(feature = "enterprise")]
    {
        &crate::enterprise_shared_hooks::HOSTED
    }
    #[cfg(not(feature = "enterprise"))]
    {
        &OpenBuild
    }
}

pub fn require_serialized_primary_iceberg_authority(operation: &str) -> Result<()> {
    hooks().require_serialized_primary_iceberg_authority(operation)
}

pub fn require_tail_pack_catalog_authority(tenant_id: &str, table_location: &str) -> Result<()> {
    hooks().require_tail_pack_catalog_authority(tenant_id, table_location)
}

pub fn require_additive_schema_broker_authority() -> Result<()> {
    hooks().require_additive_schema_broker_authority()
}

/// An open build carries no shared-mode authority: outside shared mode the
/// hosted guards admit everything, and in shared mode it refuses.
#[cfg_attr(feature = "enterprise", allow(dead_code))]
pub(crate) struct OpenBuild;

#[cfg_attr(feature = "enterprise", allow(dead_code))]
fn refuse_in_shared_mode(operation: &str) -> Result<()> {
    if active() {
        bail!(
            "DEPLOYMENT_MODE={SHARED_DEPLOYMENT_MODE} {operation} needs the hosted writer authority, which this build does not include"
        );
    }
    Ok(())
}

impl SharedModeHooks for OpenBuild {
    fn require_serialized_primary_iceberg_authority(&self, operation: &str) -> Result<()> {
        refuse_in_shared_mode(&format!("primary Iceberg {operation}"))
    }

    fn require_tail_pack_catalog_authority(&self, _tenant_id: &str, _table_location: &str) -> Result<()> {
        refuse_in_shared_mode("tail-pack catalog commit")
    }

    fn require_additive_schema_broker_authority(&self) -> Result<()> {
        refuse_in_shared_mode("additive schema commit")
    }

    fn validate_staged_tail(&self, publication: &StagedTailPublication) -> Result<()> {
        publication.validate()
    }

    fn commit_durable_result<'a>(
        &'a self,
        _publication: DurableResultPublication<'a>,
    ) -> HookFuture<'a, ResultArtifactRef> {
        Box::pin(async move {
            refuse_in_shared_mode("durable query result publication")?;
            bail!("durable query result publication through the shared writer is not available in this build")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_build_admits_outside_shared_mode() {
        // DEPLOYMENT_MODE is never set to the shared value in unit tests.
        if active() {
            return;
        }
        let open = OpenBuild;
        assert!(open.require_serialized_primary_iceberg_authority("append").is_ok());
        assert!(open.require_tail_pack_catalog_authority("t", "s3://b/t").is_ok());
        assert!(open.require_additive_schema_broker_authority().is_ok());
        assert!(require_serialized_writer_authority("durable_query_result").is_ok());
    }
}
