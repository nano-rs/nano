// SPDX-License-Identifier: AGPL-3.0-or-later
//! Platform enrichment contracts and the isolated enterprise publisher role.
//! Admission/read consumers remain inactive; search never performs feed IO.
mod admission;
#[cfg(feature = "enterprise")]
pub mod billing;
#[cfg(all(feature = "enterprise", target_os = "linux"))]
pub mod adapters;
#[cfg(all(feature = "enterprise", target_os = "linux"))]
pub mod cache;
#[cfg(feature = "enterprise")]
pub mod publisher;
#[cfg(feature = "enterprise")]
pub mod retention;
mod stamp;
pub mod portable;
pub mod read;
pub use admission::*;
pub use stamp::*;

use crate::auth::TrustedTenantContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedClass {
    Baseline,
    Premium,
}

/// Explicit allowlist; no arbitrary metadata, source URLs, manifests, object
/// locators, credential references, purchase IDs or error text can escape.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct FeedDto {
    pub feed_id: String,
    pub class: FeedClass,
    pub display_name: String,
    pub registry_revision: i64,
    pub cadence_seconds: i32,
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RevisionReference {
    pub feed_id: String,
    pub feed_revision: i64,
    pub tier: String,
    pub grant_revision: i64,
    pub entitlement_revision: i64,
}
impl RevisionReference {
    fn valid(&self) -> bool {
        slug(&self.feed_id)
            && slug(&self.tier)
            && self.feed_revision > 0
            && self.grant_revision > 0
            && self.entitlement_revision > 0
    }
}
fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_lowercase()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema, thiserror::Error,
)]
#[serde(rename_all = "snake_case")]
pub enum DenialReason {
    #[error("missing enrichment right")]
    Missing,
    #[error("expired enrichment right")]
    Expired,
    #[error("revoked enrichment right")]
    Revoked,
    #[error("disabled enrichment right")]
    Disabled,
    #[error("enrichment authority unavailable")]
    AuthorityFailure,
    #[error("invalid enrichment reference")]
    InvalidReference,
}

/// Server-produced, serializable but NOT deserializable authorization result.
/// Consumers must resolve again at publication/return; this is not a bearer
/// token and cannot turn a stored revision into current feed intelligence.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuthorizedRevision {
    pub tenant_id: Uuid,
    pub reference: RevisionReference,
    pub class: FeedClass,
    pub digest: String,
    pub mapping_revision: i64,
    pub deny_epoch: i64,
    pub valid_until: DateTime<Utc>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AuthorityRow {
    tenant_id: Uuid,
    feed_id: String,
    class: String,
    feed_revision: i64,
    digest: String,
    mapping_revision: i64,
    tier: String,
    grant_revision: i64,
    entitlement_revision: i64,
    deny_epoch: i64,
    enabled: bool,
    state: String,
    effective_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    grant_effective_at: DateTime<Utc>,
    grant_expires_at: Option<DateTime<Utc>>,
    valid_until: DateTime<Utc>,
    revoked: bool,
    evaluated_at: DateTime<Utc>,
}

pub struct PlatformEnrichmentResolver;
impl PlatformEnrichmentResolver {
    /// Uses the caller's signed tenant transaction or bound lake session. The
    /// definer re-proves authority; a caller-supplied UUID/revision is not proof.
    pub async fn resolve(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &TrustedTenantContext,
        reference: &RevisionReference,
    ) -> Result<AuthorizedRevision, DenialReason> {
        if tenant.tenant_id.is_nil() || !reference.valid() {
            return Err(DenialReason::InvalidReference);
        }
        let row = sqlx::query_as::<_, AuthorityRow>(
            "SELECT * FROM nano_shared.resolve_platform_enrichment($1,$2,$3,$4,$5,$6)",
        )
        .bind(tenant.tenant_id)
        .bind(&reference.feed_id)
        .bind(reference.feed_revision)
        .bind(&reference.tier)
        .bind(reference.grant_revision)
        .bind(reference.entitlement_revision)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| DenialReason::AuthorityFailure);
        evaluate(tenant.tenant_id, reference, row)
    }
}
fn evaluate(
    tenant: Uuid,
    reference: &RevisionReference,
    row: Result<Option<AuthorityRow>, DenialReason>,
) -> Result<AuthorizedRevision, DenialReason> {
    let row = row?.ok_or(DenialReason::Missing)?;
    if !reference.valid()
        || row.tenant_id != tenant
        || row.feed_id != reference.feed_id
        || row.feed_revision != reference.feed_revision
        || row.tier != reference.tier
        || row.grant_revision != reference.grant_revision
        || row.entitlement_revision != reference.entitlement_revision
        || !digest_valid(&row.digest)
        || row.mapping_revision <= 0
        || row.deny_epoch < 0
    {
        return Err(DenialReason::InvalidReference);
    }
    let class = match row.class.as_str() {
        "baseline" if row.tier == "included" => FeedClass::Baseline,
        "premium" if row.tier != "included" => FeedClass::Premium,
        _ => return Err(DenialReason::InvalidReference),
    };
    if row.revoked || row.state == "revoked" {
        return Err(DenialReason::Revoked);
    }
    let valid_until = row
        .expires_at
        .into_iter()
        .chain(row.grant_expires_at)
        .chain([row.valid_until])
        .min()
        .unwrap();
    if valid_until <= row.evaluated_at || row.state == "expired" {
        return Err(DenialReason::Expired);
    }
    if row.state != "active"
        || row.effective_at > row.evaluated_at
        || row.grant_effective_at > row.evaluated_at
    {
        return Err(DenialReason::Missing);
    }
    if !row.enabled {
        return Err(DenialReason::Disabled);
    }
    Ok(AuthorizedRevision {
        tenant_id: tenant,
        reference: reference.clone(),
        class,
        digest: row.digest,
        mapping_revision: row.mapping_revision,
        deny_epoch: row.deny_epoch,
        valid_until,
        evaluated_at: row.evaluated_at,
    })
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Uuid, RevisionReference, AuthorityRow) {
        let tenant = Uuid::from_u128(1);
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let r = RevisionReference {
            feed_id: "synthient".into(),
            feed_revision: 1,
            tier: "premium".into(),
            grant_revision: 1,
            entitlement_revision: 1,
        };
        let row = AuthorityRow {
            tenant_id: tenant,
            feed_id: r.feed_id.clone(),
            class: "premium".into(),
            feed_revision: 1,
            digest: "ab".repeat(32),
            mapping_revision: 1,
            tier: r.tier.clone(),
            grant_revision: 1,
            entitlement_revision: 1,
            deny_epoch: 0,
            enabled: true,
            state: "active".into(),
            effective_at: now,
            expires_at: None,
            grant_effective_at: now,
            grant_expires_at: None,
            valid_until: now + chrono::Duration::hours(1),
            revoked: false,
            evaluated_at: now,
        };
        (tenant, r, row)
    }
    #[test]
    fn missing_grant() {
        let (t, r, _) = fixture();
        assert_eq!(
            evaluate(t, &r, Ok(None)).unwrap_err(),
            DenialReason::Missing
        );
    }
    #[test]
    fn expired_grant() {
        let (t, r, mut row) = fixture();
        row.grant_expires_at = Some(row.evaluated_at);
        assert_eq!(
            evaluate(t, &r, Ok(Some(row))).unwrap_err(),
            DenialReason::Expired
        );
    }
    #[test]
    fn revoked_grant() {
        let (t, r, mut row) = fixture();
        row.revoked = true;
        assert_eq!(
            evaluate(t, &r, Ok(Some(row))).unwrap_err(),
            DenialReason::Revoked
        );
    }
    #[test]
    fn authority_failure_is_closed_and_redacted() {
        let (t, r, _) = fixture();
        assert_eq!(
            evaluate(t, &r, Err(DenialReason::AuthorityFailure)).unwrap_err(),
            DenialReason::AuthorityFailure
        );
        assert_eq!(
            serde_json::to_string(&DenialReason::AuthorityFailure).unwrap(),
            "\"authority_failure\""
        );
    }
    #[test]
    fn foreign_tenant_and_mixed_revision_rejected() {
        let (_, r, row) = fixture();
        assert!(evaluate(Uuid::from_u128(2), &r, Ok(Some(row))).is_err());
        let (t, mut r, row) = fixture();
        r.grant_revision = 2;
        assert!(evaluate(t, &r, Ok(Some(row))).is_err());
    }
    #[test]
    fn redacted_serialization_allowlist() {
        let (t, r, row) = fixture();
        let result = evaluate(t, &r, Ok(Some(row))).unwrap();
        let json = serde_json::to_value(result).unwrap();
        let keys: std::collections::BTreeSet<_> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "tenant_id",
                "reference",
                "class",
                "digest",
                "mapping_revision",
                "deny_epoch",
                "valid_until",
                "evaluated_at"
            ])
        );
        let dto = FeedDto {
            feed_id: "ipinfo_lite".into(),
            class: FeedClass::Baseline,
            display_name: "IPinfo Lite".into(),
            registry_revision: 1,
            cadence_seconds: 604800,
            available: false,
        };
        let json = serde_json::to_value(dto).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 6);
        for name in [
            "credential_ref",
            "token",
            "object_key",
            "signed_manifest",
            "purchase_key",
            "source_url",
        ] {
            assert!(json.get(name).is_none());
        }
    }
    #[test]
    fn disabled_future_and_expired_feed_rejected() {
        let (t, r, mut row) = fixture();
        row.enabled = false;
        assert_eq!(
            evaluate(t, &r, Ok(Some(row))).unwrap_err(),
            DenialReason::Disabled
        );
        let (t, r, mut row) = fixture();
        row.grant_effective_at += chrono::Duration::seconds(1);
        assert_eq!(
            evaluate(t, &r, Ok(Some(row))).unwrap_err(),
            DenialReason::Missing
        );
        let (t, r, mut row) = fixture();
        row.valid_until = row.evaluated_at;
        assert_eq!(
            evaluate(t, &r, Ok(Some(row))).unwrap_err(),
            DenialReason::Expired
        );
    }
}

/// Internal repository only. No HTTP handler, scheduler, onboarding or bronze
/// caller invokes this in phase 1. The DB capabilities own authorization/audit.
pub struct PlatformEnrichmentRepository;
impl PlatformEnrichmentRepository {
    pub async fn list_feeds(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &TrustedTenantContext,
        actor: Uuid,
    ) -> Result<Vec<FeedDto>, DenialReason> {
        let rows: Vec<(String, String, String, i64, i32, bool)> =
            sqlx::query_as("SELECT * FROM nano_shared.list_platform_enrichment_feeds($1,$2)")
                .bind(tenant.tenant_id)
                .bind(actor)
                .fetch_all(&mut **tx)
                .await
                .map_err(|_| DenialReason::AuthorityFailure)?;
        rows.into_iter()
            .map(
                |(feed_id, class, display_name, registry_revision, cadence_seconds, available)| {
                    let class = match class.as_str() {
                        "baseline" => FeedClass::Baseline,
                        "premium" => FeedClass::Premium,
                        _ => return Err(DenialReason::InvalidReference),
                    };
                    Ok(FeedDto {
                        feed_id,
                        class,
                        display_name,
                        registry_revision,
                        cadence_seconds,
                        available,
                    })
                },
            )
            .collect()
    }
    /// Owner-only bootstrap connection, never a tenant settings transaction.
    pub async fn provision_baseline(
        tx: &mut Transaction<'_, Postgres>,
        tenant: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT nano_shared.provision_platform_enrichment_baseline($1)")
            .bind(tenant)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
    /// Conflict is SQLSTATE 40001. This cannot insert or upgrade a grant.
    pub async fn set_enabled(
        tx: &mut Transaction<'_, Postgres>,
        tenant: &TrustedTenantContext,
        actor: Uuid,
        feed_id: &str,
        expected_revision: i64,
        enabled: bool,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT nano_shared.set_platform_enrichment_enabled($1,$2,$3,$4,$5)")
            .bind(tenant.tenant_id)
            .bind(actor)
            .bind(feed_id)
            .bind(expected_revision)
            .bind(enabled)
            .fetch_one(&mut **tx)
            .await
    }
}
