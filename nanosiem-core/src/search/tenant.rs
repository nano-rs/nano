// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant identity for search caches, jobs, leases, and result artifacts.
//!
//! Dedicated/open-core deployments retain their exact historical keyspace.
//! Enterprise-shared callers must construct an explicit tenant scope; there is
//! no shared-mode default tenant and no raw client selector constructor.

use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchTenantScope {
    Dedicated,
    EnterpriseShared(Uuid),
    EnterpriseSharedRetained {
        tenant_id: Uuid,
        retention_revision: i64,
        retention_days: u16,
        irreversible_event_time_floor_micros: i64,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SearchTenantError {
    #[error("enterprise-shared search requires a resolved tenant")]
    MissingTenant,
    #[error("search identity belongs to another tenant")]
    ForeignTenant,
    #[error("enterprise-shared search requires the current retention policy identity")]
    MissingRetentionPolicy,
}

impl Default for SearchTenantScope {
    fn default() -> Self {
        Self::Dedicated
    }
}

impl SearchTenantScope {
    pub const fn dedicated() -> Self {
        Self::Dedicated
    }

    #[cfg(feature = "enterprise")]
    /// Construct the shared search boundary from server-resolved identity.
    /// `None` is never interpreted as a default tenant.
    pub fn enterprise_shared(tenant_id: Option<Uuid>) -> Result<Self, SearchTenantError> {
        tenant_id
            .filter(|tenant_id| !tenant_id.is_nil())
            .map(Self::EnterpriseShared)
            .ok_or(SearchTenantError::MissingTenant)
    }

    pub const fn tenant_id(self) -> Option<Uuid> {
        match self {
            Self::Dedicated => None,
            Self::EnterpriseShared(tenant_id) => Some(tenant_id),
            Self::EnterpriseSharedRetained { tenant_id, .. } => Some(tenant_id),
        }
    }

    #[cfg(feature = "enterprise")]
    pub const fn is_enterprise_shared(self) -> bool {
        matches!(
            self,
            Self::EnterpriseShared(_) | Self::EnterpriseSharedRetained { .. }
        )
    }

    #[cfg(feature = "enterprise")]
    pub fn enterprise_shared_retained(
        tenant_id: Uuid,
        retention_revision: i64,
        retention_days: u16,
        irreversible_event_time_floor_micros: i64,
    ) -> Result<Self, SearchTenantError> {
        if tenant_id.is_nil()
            || retention_revision <= 0
            || irreversible_event_time_floor_micros < 0
            || !matches!(retention_days, 30 | 90 | 180 | 365)
        {
            return Err(SearchTenantError::MissingTenant);
        }
        Ok(Self::EnterpriseSharedRetained {
            tenant_id,
            retention_revision,
            retention_days,
            irreversible_event_time_floor_micros,
        })
    }

    pub const fn retention_identity(self) -> Option<(i64, u16, i64)> {
        match self {
            Self::EnterpriseSharedRetained {
                retention_revision,
                retention_days,
                irreversible_event_time_floor_micros,
                ..
            } => Some((
                retention_revision,
                retention_days,
                irreversible_event_time_floor_micros,
            )),
            _ => None,
        }
    }

    /// Return the server-resolved retention identity required by every hosted
    /// shared query/cache/job path. The legacy tenant-only scope remains only
    /// for decoding historical state and must never authorize execution.
    pub const fn require_retention_identity(self) -> Result<(i64, u16, i64), SearchTenantError> {
        match self {
            Self::EnterpriseSharedRetained {
                retention_revision,
                retention_days,
                irreversible_event_time_floor_micros,
                ..
            } => Ok((
                retention_revision,
                retention_days,
                irreversible_event_time_floor_micros,
            )),
            Self::EnterpriseShared(_) => Err(SearchTenantError::MissingRetentionPolicy),
            Self::Dedicated => Err(SearchTenantError::MissingTenant),
        }
    }

    /// NAN-3894: the event-time cutoff for OTLP spans/metrics. They are kept
    /// at least [`OTEL_MIN_RETENTION_DAYS`](crate::observability::slo_repository::OTEL_MIN_RETENTION_DAYS)
    /// days (never less than the tenant's own retention), so the longest SLO
    /// window stays readable. The irreversible floor still applies.
    pub fn otel_event_time_cutoff(
        self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        use crate::observability::slo_repository::OTEL_MIN_RETENTION_DAYS;
        self.retention_identity().map(|(_, days, floor_micros)| {
            let days = u32::from(days).max(OTEL_MIN_RETENTION_DAYS);
            let rolling = now - chrono::Duration::days(i64::from(days));
            let irreversible = chrono::DateTime::from_timestamp_micros(floor_micros)
                .expect("validated enterprise-shared retention floor");
            std::cmp::max(rolling, irreversible)
        })
    }

    /// Whether a cached result for `time_range` may be served to this tenant
    /// at `now` (NAN-2361 wave 6). A fixed-TTL cache entry can outlive the
    /// continuously moving retention cutoff, so a shared tenant is served
    /// from cache only when the requested window lies entirely inside the
    /// retention window at delivery: every row it can hold is then still
    /// retained. Dedicated deployments have no cutoff and always qualify.
    pub fn cacheable_window(
        self,
        window_start: chrono::DateTime<chrono::Utc>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        match self {
            Self::Dedicated => true,
            Self::EnterpriseShared(_) => false,
            Self::EnterpriseSharedRetained { .. } => self
                .event_time_cutoff(now)
                .is_some_and(|cutoff| window_start >= cutoff),
        }
    }

    pub fn event_time_cutoff(
        self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        self.retention_identity().map(|(_, days, floor_micros)| {
            let rolling = now - chrono::Duration::days(i64::from(days));
            let irreversible = chrono::DateTime::from_timestamp_micros(floor_micros)
                .expect("validated enterprise-shared retention floor");
            std::cmp::max(rolling, irreversible)
        })
    }

    /// Verify a tenant stamp read from shared state or a worker claim.
    /// Legacy dedicated records are intentionally tenantless.
    pub fn verify_stored_tenant(self, stored: Option<Uuid>) -> Result<(), SearchTenantError> {
        match (self, stored) {
            (Self::Dedicated, None) => Ok(()),
            (Self::EnterpriseShared(expected), Some(actual)) if expected == actual => Ok(()),
            (
                Self::EnterpriseSharedRetained {
                    tenant_id: expected,
                    ..
                },
                Some(actual),
            ) if expected == actual => Ok(()),
            (Self::EnterpriseShared(_), None) | (Self::EnterpriseSharedRetained { .. }, None) => {
                Err(SearchTenantError::MissingTenant)
            }
            _ => Err(SearchTenantError::ForeignTenant),
        }
    }

    /// Fold the tenant into a cache/result identity while preserving the exact
    /// dedicated byte sequence.
    pub fn fold_identity(self, identity: &mut Vec<u8>) {
        if let Some(tenant_id) = self.tenant_id() {
            const DOMAIN: &[u8] = b"nano.enterprise_shared.tenant.v1";
            identity.extend_from_slice(&(DOMAIN.len() as u64).to_le_bytes());
            identity.extend_from_slice(DOMAIN);
            let tenant = tenant_id.as_bytes();
            identity.extend_from_slice(&(tenant.len() as u64).to_le_bytes());
            identity.extend_from_slice(tenant);
            if let Some((retention_revision, retention_days, floor_micros)) =
                self.retention_identity()
            {
                const RETENTION_DOMAIN: &[u8] = b"nano.enterprise_shared.retention.v1";
                identity.extend_from_slice(&(RETENTION_DOMAIN.len() as u64).to_le_bytes());
                identity.extend_from_slice(RETENTION_DOMAIN);
                identity.extend_from_slice(&retention_revision.to_le_bytes());
                identity.extend_from_slice(&retention_days.to_le_bytes());
                identity.extend_from_slice(&floor_micros.to_le_bytes());
            }
        }
    }

    /// Redis cluster hash tag used by all keys touched in one job Lua script.
    /// Dedicated output remains exactly `{jobs}`.
    pub fn redis_job_hash_tag(self) -> String {
        match self {
            Self::Dedicated => "{jobs}".to_string(),
            Self::EnterpriseShared(tenant_id) => format!("{{jobs:{tenant_id}}}"),
            Self::EnterpriseSharedRetained {
                tenant_id,
                retention_revision,
                irreversible_event_time_floor_micros,
                ..
            } => format!(
                "{{jobs:{tenant_id}:retention:{retention_revision}:floor:{irreversible_event_time_floor_micros}}}"
            ),
        }
    }

    pub fn redis_job_key(self, suffix: &str) -> String {
        format!("search:{}:{suffix}", self.redis_job_hash_tag())
    }

    /// Shared request/query ownership key. Dedicated output is the historical
    /// key so existing deployments do not rotate live cancellation state.
    pub fn query_owner_key(self, request_digest: &str) -> String {
        match self {
            Self::Dedicated => format!("nanosiem:search:query-owner:{request_digest}"),
            Self::EnterpriseShared(tenant_id) => {
                format!("nanosiem:search:tenant:{tenant_id}:query-owner:{request_digest}")
            }
            Self::EnterpriseSharedRetained {
                tenant_id,
                retention_revision,
                irreversible_event_time_floor_micros,
                ..
            } => format!(
                "nanosiem:search:tenant:{tenant_id}:retention:{retention_revision}:floor:{irreversible_event_time_floor_micros}:query-owner:{request_digest}"
            ),
        }
    }

    /// Internal execution identity for a client request id. Dedicated mode is
    /// byte-compatible. Shared mode hashes the authenticated tenant boundary
    /// with the opaque client value so equal ids can execute/cancel
    /// independently without exposing another tenant's tracker entry.
    pub fn execution_request_id(self, client_request_id: &str) -> String {
        match self {
            Self::Dedicated => client_request_id.to_string(),
            Self::EnterpriseShared(_) | Self::EnterpriseSharedRetained { .. } => {
                use sha2::{Digest, Sha256};
                let mut identity = Vec::new();
                self.fold_identity(&mut identity);
                let mut hash = Sha256::new();
                hash.update(identity);
                hash.update((client_request_id.len() as u64).to_le_bytes());
                hash.update(client_request_id.as_bytes());
                format!("shared-{}", hex::encode(hash.finalize()))
            }
        }
    }
}

/// The serving generation a shared tenant's query worker answers from
/// (NAN-2361 wave 6). Folded into every result-cache key so an erasure or
/// retention swap — which activates a new generation on a new Iceberg
/// snapshot — invalidates cached results immediately instead of after the
/// TTL. Dedicated deployments have no generation and pass `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServingGenerationKey {
    pub generation_id: String,
    pub snapshot_id: i64,
}

impl ServingGenerationKey {
    pub fn fold_identity(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(b"serving-generation:v1:");
        bytes.extend_from_slice(&(self.generation_id.len() as u64).to_le_bytes());
        bytes.extend_from_slice(self.generation_id.as_bytes());
        bytes.extend_from_slice(&self.snapshot_id.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_scope_requires_a_resolved_tenant() {
        assert_eq!(
            SearchTenantScope::enterprise_shared(None),
            Err(SearchTenantError::MissingTenant)
        );
        assert_eq!(
            SearchTenantScope::enterprise_shared(Some(Uuid::nil())),
            Err(SearchTenantError::MissingTenant)
        );
        assert_eq!(
            SearchTenantScope::enterprise_shared_retained(Uuid::nil(), 1, 365, 0),
            Err(SearchTenantError::MissingTenant)
        );
    }

    /// NAN-3894: OTLP reads use a cutoff at least `OTEL_MIN_RETENTION_DAYS`
    /// back, so a `SLO_WINDOW_DAYS_MAX` window plus the skew hour is never
    /// clamped; a longer tenant retention and the irreversible floor still win.
    #[test]
    fn otel_cutoff_covers_the_longest_slo_window() {
        use crate::observability::slo_repository::{OTEL_MIN_RETENTION_DAYS, SLO_WINDOW_DAYS_MAX};
        let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let scope = |days: u16, floor_micros: i64| SearchTenantScope::EnterpriseSharedRetained {
            tenant_id: Uuid::from_u128(7),
            retention_revision: 1,
            retention_days: days,
            irreversible_event_time_floor_micros: floor_micros,
        };
        let slo_start = now - chrono::Duration::days(i64::from(SLO_WINDOW_DAYS_MAX)) - chrono::Duration::hours(1);
        let short = scope(30, 0);
        assert!(short.event_time_cutoff(now).unwrap() > slo_start, "log retention alone would clamp it");
        assert_eq!(
            short.otel_event_time_cutoff(now),
            Some(now - chrono::Duration::days(i64::from(OTEL_MIN_RETENTION_DAYS)))
        );
        assert!(short.otel_event_time_cutoff(now).unwrap() <= slo_start);
        assert_eq!(scope(365, 0).otel_event_time_cutoff(now), scope(365, 0).event_time_cutoff(now));
        let floor = now - chrono::Duration::days(3);
        assert_eq!(scope(30, floor.timestamp_micros()).otel_event_time_cutoff(now), Some(floor));
        assert_eq!(SearchTenantScope::Dedicated.otel_event_time_cutoff(now), None);
    }

    #[test]
    fn dedicated_keyspace_is_byte_compatible() {
        let scope = SearchTenantScope::dedicated();
        assert_eq!(scope.redis_job_key("job/abc"), "search:{jobs}:job/abc");
        assert_eq!(
            scope.query_owner_key("digest"),
            "nanosiem:search:query-owner:digest"
        );
        let mut identity = b"query".to_vec();
        scope.fold_identity(&mut identity);
        assert_eq!(identity, b"query");
    }

    #[test]
    fn identical_ids_are_disjoint_between_shared_tenants() {
        let a = SearchTenantScope::EnterpriseShared(Uuid::from_u128(1));
        let b = SearchTenantScope::EnterpriseShared(Uuid::from_u128(2));
        assert_ne!(a.redis_job_key("job/same"), b.redis_job_key("job/same"));
        assert_ne!(
            a.query_owner_key("same-query"),
            b.query_owner_key("same-query")
        );
        assert_ne!(
            a.execution_request_id("same-query"),
            b.execution_request_id("same-query")
        );
        assert_eq!(
            SearchTenantScope::Dedicated.execution_request_id("same-query"),
            "same-query"
        );
        assert_eq!(
            a.verify_stored_tenant(b.tenant_id()),
            Err(SearchTenantError::ForeignTenant)
        );
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn retention_revision_and_exact_event_cutoff_are_part_of_shared_identity() {
        let tenant = Uuid::from_u128(1);
        let revision_one = SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap();
        let revision_two = SearchTenantScope::enterprise_shared_retained(
            tenant,
            2,
            365,
            chrono::DateTime::parse_from_rfc3339("2026-05-31T12:00:00Z")
                .unwrap()
                .timestamp_micros(),
        )
        .unwrap();
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-29T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(
            revision_one.event_time_cutoff(now).unwrap(),
            now - chrono::Duration::days(90)
        );
        assert_eq!(
            revision_two.event_time_cutoff(now).unwrap(),
            now - chrono::Duration::days(90),
            "increasing days cannot move the irreversible cutoff backwards"
        );
        let mut one = b"query".to_vec();
        let mut two = b"query".to_vec();
        revision_one.fold_identity(&mut one);
        revision_two.fold_identity(&mut two);
        assert_ne!(
            one, two,
            "retention changes must invalidate shared identity"
        );
        assert_ne!(
            revision_one.redis_job_key("same"),
            revision_two.redis_job_key("same")
        );
        assert_eq!(
            SearchTenantScope::EnterpriseShared(tenant).require_retention_identity(),
            Err(SearchTenantError::MissingRetentionPolicy)
        );
    }
}
