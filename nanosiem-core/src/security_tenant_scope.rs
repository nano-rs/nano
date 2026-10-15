// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-aware identity for in-memory/Redis caches and async idempotency.
//!
//! Dedicated output is byte-for-byte the historical unscoped identity; a
//! tenant-scoped key is prefixed with the tenant id so two tenants can never
//! share a cache entry, lease or idempotency slot.

use std::fmt;

use uuid::Uuid;

/// Tenant-aware identity for in-memory/Redis caches and async idempotency.
/// Dedicated output is byte-for-byte the historical unscoped identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityTenantScope {
    Dedicated,
    EnterpriseShared(Uuid),
}

impl SecurityTenantScope {
    pub const fn dedicated() -> Self {
        Self::Dedicated
    }

    pub fn cache_key(self, legacy_key: &str) -> String {
        match self {
            Self::Dedicated => legacy_key.to_string(),
            Self::EnterpriseShared(tenant_id) => {
                format!("nano:enterprise_shared:{tenant_id}:{legacy_key}")
            }
        }
    }

    pub fn worker_claim_key(self, worker_identity: &str, rule_id: Uuid) -> String {
        let legacy = format!("detection-claim:{worker_identity}:{rule_id}");
        self.cache_key(&legacy)
    }

    pub fn idempotency_key(self, domain: &str, opaque_id: &str) -> String {
        let legacy = format!("{domain}:{opaque_id}");
        self.cache_key(&legacy)
    }
}

impl fmt::Display for SecurityTenantScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dedicated => formatter.write_str("dedicated"),
            Self::EnterpriseShared(tenant_id) => write!(formatter, "enterprise_shared:{tenant_id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_keys_are_the_legacy_bytes_and_tenants_never_collide() {
        let rule = Uuid::from_u128(7);
        let dedicated = SecurityTenantScope::dedicated();
        assert_eq!(dedicated.cache_key("k"), "k");
        assert_eq!(
            dedicated.worker_claim_key("w", rule),
            format!("detection-claim:w:{rule}")
        );
        let a = SecurityTenantScope::EnterpriseShared(Uuid::from_u128(1));
        let b = SecurityTenantScope::EnterpriseShared(Uuid::from_u128(2));
        assert_ne!(a.idempotency_key("d", "x"), b.idempotency_key("d", "x"));
        assert_eq!(
            a.cache_key("k"),
            format!("nano:enterprise_shared:{}:k", Uuid::from_u128(1))
        );
    }
}
