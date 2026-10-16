// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared IOC memory envelope for all editions.
use serde::{Deserialize, Serialize};

/// At maximum URL/tag/note lengths (including JSON escaping), 8,000
/// coordinator records fit inside the existing 64 MiB request contract.
pub const MAX_INDICATORS_PER_LIST: usize = 8_000;
/// Per-tenant list cap (lists share the tenant's lookup-table budget too).
pub const MAX_TENANT_IOC_LISTS: usize = 50;
/// Farm probes: 25k maximum-metadata rows plus an 8k chunked replacement
/// peaked at 549.0 MiB (including conservative seeding). Adding the full
/// 121 MiB service baseline leaves 34.6% headroom under 1 GiB (NAN-3910).
pub const MAX_INDICATORS_PER_TENANT: usize = 25_000;
pub const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Operator-owned database overrides; omitted fields retain code defaults.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IocLimits {
    pub indicators_per_list: usize,
    pub indicators_per_tenant: usize,
    pub list_count: usize,
    pub upload_bytes: usize,
}
impl Default for IocLimits {
    fn default() -> Self {
        Self {
            indicators_per_list: MAX_INDICATORS_PER_LIST,
            indicators_per_tenant: MAX_INDICATORS_PER_TENANT,
            list_count: MAX_TENANT_IOC_LISTS,
            upload_bytes: MAX_UPLOAD_BYTES,
        }
    }
}

impl IocLimits {
    /// Invalid operator configuration fails closed; there is no unlimited
    /// sentinel or environment-variable fallback.
    pub fn from_config(config: serde_json::Value) -> Result<Self, &'static str> {
        let limits: Self = serde_json::from_value(config)
            .map_err(|_| "invalid IOC limit configuration; contact support")?;
        if limits.indicators_per_list == 0
            || limits.indicators_per_tenant == 0
            || limits.list_count == 0
            || limits.upload_bytes == 0
            || limits.indicators_per_list > MAX_INDICATORS_PER_LIST
            || limits.indicators_per_tenant > MAX_INDICATORS_PER_TENANT
            || limits.list_count > MAX_TENANT_IOC_LISTS
            || limits.upload_bytes > MAX_UPLOAD_BYTES
        {
            return Err(
                "IOC limit configuration exceeds the tested memory envelope; contact support",
            );
        }
        Ok(limits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema, thiserror::Error)]
#[error("IOC {limit} limit {maximum} exceeded: current usage {current}, attempted {attempted}")]
pub struct IocLimitExceeded {
    pub limit: &'static str,
    pub maximum: usize,
    pub current: usize,
    pub attempted: usize,
}

#[derive(Debug, Clone, Copy, Default, Serialize, utoipa::ToSchema)]
pub struct IocUsage {
    pub list_count: usize,
    pub indicators: usize,
}
