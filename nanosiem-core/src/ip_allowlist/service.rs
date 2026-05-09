// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist service with in-memory caching

use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::repository::{IpAllowlistRepository, IpAllowlistRepositoryError};
use super::types::*;

/// How often to refresh the cached allowlist from the database
const CACHE_TTL_SECS: u64 = 30;

#[derive(Error, Debug)]
pub enum IpAllowlistServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] IpAllowlistRepositoryError),
    #[error("Invalid CIDR notation: {0}")]
    InvalidCidr(String),
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Self-lockout protection: your current IP {0} would be blocked by this change")]
    SelfLockout(String),
}

/// A parsed CIDR entry for fast matching
#[derive(Clone)]
struct CachedCidr {
    id: Uuid,
    scope: IpAllowlistScope,
    cidr_str: String,
    description: Option<String>,
    network: IpNetwork,
}

/// Simple IP network representation (avoids external ipnet dependency)
#[derive(Clone)]
enum IpNetwork {
    V4 { addr: u32, prefix_len: u8 },
    V6 { addr: u128, prefix_len: u8 },
}

impl IpNetwork {
    fn parse(cidr: &str) -> Result<Self, String> {
        // Handle bare IP addresses (no prefix) by adding /32 or /128
        let cidr = if !cidr.contains('/') {
            if cidr.contains(':') {
                format!("{}/128", cidr)
            } else {
                format!("{}/32", cidr)
            }
        } else {
            cidr.to_string()
        };

        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("invalid CIDR format: {}", cidr));
        }

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| format!("invalid prefix length: {}", parts[1]))?;
        let ip: IpAddr = parts[0]
            .parse()
            .map_err(|_| format!("invalid IP address: {}", parts[0]))?;

        match ip {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(format!("IPv4 prefix length {} exceeds 32", prefix_len));
                }
                Ok(IpNetwork::V4 {
                    addr: u32::from(v4),
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(format!("IPv6 prefix length {} exceeds 128", prefix_len));
                }
                Ok(IpNetwork::V6 {
                    addr: u128::from(v6),
                    prefix_len,
                })
            }
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpNetwork::V4 { addr, prefix_len }, IpAddr::V4(v4)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let ip_bits = u32::from(*v4);
                let mask = u32::MAX.checked_shl(32 - *prefix_len as u32).unwrap_or(0);
                (ip_bits & mask) == (*addr & mask)
            }
            (IpNetwork::V6 { addr, prefix_len }, IpAddr::V6(v6)) => {
                if *prefix_len == 0 {
                    return true;
                }
                let ip_bits = u128::from(*v6);
                let mask = u128::MAX.checked_shl(128 - *prefix_len as u32).unwrap_or(0);
                (ip_bits & mask) == (*addr & mask)
            }
            // IPv4 network can't contain IPv6 address and vice versa
            _ => false,
        }
    }
}

/// Cached allowlist state
struct CacheState {
    entries: Vec<CachedCidr>,
    last_refresh: std::time::Instant,
    has_any_rules: bool,
}

/// IP Allowlist service with in-memory cached CIDR matching
#[derive(Clone)]
pub struct IpAllowlistService {
    pool: PgPool,
    cache: Arc<RwLock<Option<CacheState>>>,
    /// Emergency bypass via NANO_IP_ALLOWLIST_DISABLED env var
    disabled: bool,
}

impl IpAllowlistService {
    pub fn new(pool: PgPool) -> Self {
        let disabled = std::env::var("NANO_IP_ALLOWLIST_DISABLED")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        if disabled {
            tracing::warn!("IP allowlist is DISABLED via NANO_IP_ALLOWLIST_DISABLED env var");
        }

        Self {
            pool,
            cache: Arc::new(RwLock::new(None)),
            disabled,
        }
    }

    fn repository(&self) -> IpAllowlistRepository {
        IpAllowlistRepository::new(self.pool.clone())
    }

    /// Check if an IP is allowed for a given scope.
    ///
    /// Returns true if:
    /// - The allowlist is disabled via env var
    /// - No enabled rules exist (feature not active)
    /// - The IP is a loopback address (127.0.0.1, ::1)
    /// - The IP matches a global or scope-specific CIDR rule
    pub async fn is_allowed(&self, ip_str: &str, scope: IpAllowlistScope) -> bool {
        // Emergency bypass
        if self.disabled {
            return true;
        }

        // Always allow loopback
        if ip_str == "127.0.0.1" || ip_str == "::1" {
            return true;
        }

        // Parse the IP
        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(ip = %ip_str, "Failed to parse IP for allowlist check — denying");
                return false;
            }
        };

        // Refresh cache if needed
        let cache = self.get_or_refresh_cache().await;

        // If no rules exist, allowlist is inactive — allow everything
        if !cache.has_any_rules {
            return true;
        }

        // Check against cached CIDRs (global + scope-specific)
        for entry in &cache.entries {
            if entry.scope == IpAllowlistScope::Global || entry.scope == scope {
                if entry.network.contains(&ip) {
                    return true;
                }
            }
        }

        false
    }

    /// Force a cache refresh (call after CRUD operations)
    pub async fn invalidate_cache(&self) {
        let mut cache = self.cache.write().await;
        *cache = None;
    }

    async fn get_or_refresh_cache(&self) -> CacheState {
        // Fast path: check if cache is still valid
        {
            let cache = self.cache.read().await;
            if let Some(ref state) = *cache {
                if state.last_refresh.elapsed().as_secs() < CACHE_TTL_SECS {
                    return CacheState {
                        entries: state.entries.clone(),
                        last_refresh: state.last_refresh,
                        has_any_rules: state.has_any_rules,
                    };
                }
            }
        }

        // Slow path: refresh from database
        let repo = self.repository();
        let entries = match repo.list(None).await {
            Ok(entries) => entries,
            Err(e) => {
                tracing::error!(error = %e, "Failed to load IP allowlist from database — allowing all traffic");
                return CacheState {
                    entries: Vec::new(),
                    last_refresh: std::time::Instant::now(),
                    has_any_rules: false,
                };
            }
        };

        let has_any_rules = entries.iter().any(|e| e.enabled);

        let cached: Vec<CachedCidr> = entries
            .into_iter()
            .filter(|e| e.enabled)
            .filter_map(|e| {
                match IpNetwork::parse(&e.cidr) {
                    Ok(network) => Some(CachedCidr {
                        id: e.id,
                        scope: e.scope,
                        cidr_str: e.cidr,
                        description: e.description,
                        network,
                    }),
                    Err(err) => {
                        tracing::warn!(cidr = %e.cidr, error = %err, "Skipping invalid CIDR in allowlist");
                        None
                    }
                }
            })
            .collect();

        let state = CacheState {
            entries: cached,
            last_refresh: std::time::Instant::now(),
            has_any_rules,
        };

        // Update the cache
        let mut cache = self.cache.write().await;
        *cache = Some(CacheState {
            entries: state.entries.clone(),
            last_refresh: state.last_refresh,
            has_any_rules: state.has_any_rules,
        });

        state
    }

    // ========================================================================
    // CRUD operations (delegate to repository)
    // ========================================================================

    /// List all allowlist entries, optionally filtered by scope
    pub async fn list(
        &self,
        scope: Option<IpAllowlistScope>,
    ) -> Result<Vec<IpAllowlistEntry>, IpAllowlistServiceError> {
        Ok(self.repository().list(scope).await?)
    }

    /// Get a single entry by ID
    pub async fn get(&self, id: Uuid) -> Result<IpAllowlistEntry, IpAllowlistServiceError> {
        Ok(self.repository().get(id).await?)
    }

    /// Create a new allowlist entry
    pub async fn create(
        &self,
        entry: CreateIpAllowlistEntry,
        created_by: Option<Uuid>,
    ) -> Result<IpAllowlistEntry, IpAllowlistServiceError> {
        // Validate CIDR
        IpNetwork::parse(&entry.cidr).map_err(|e| IpAllowlistServiceError::InvalidCidr(e))?;

        let result = self.repository().create(&entry, created_by).await?;
        self.invalidate_cache().await;
        Ok(result)
    }

    /// Update an existing allowlist entry
    pub async fn update(
        &self,
        id: Uuid,
        update: UpdateIpAllowlistEntry,
    ) -> Result<IpAllowlistEntry, IpAllowlistServiceError> {
        // Validate CIDR if provided
        if let Some(ref cidr) = update.cidr {
            IpNetwork::parse(cidr).map_err(|e| IpAllowlistServiceError::InvalidCidr(e))?;
        }

        let result = self.repository().update(id, &update).await?;
        self.invalidate_cache().await;
        Ok(result)
    }

    /// Delete an allowlist entry
    pub async fn delete(&self, id: Uuid) -> Result<(), IpAllowlistServiceError> {
        self.repository().delete(id).await?;
        self.invalidate_cache().await;
        Ok(())
    }

    /// Validate that a given IP would still be allowed after proposed changes.
    /// Used for self-lockout protection.
    pub async fn validate_no_self_lockout(
        &self,
        admin_ip: &str,
        scope: IpAllowlistScope,
    ) -> Result<(), IpAllowlistServiceError> {
        let ip: IpAddr = admin_ip
            .parse()
            .map_err(|_| IpAllowlistServiceError::InvalidIp(admin_ip.to_string()))?;

        // After cache invalidation, check if the admin would still be allowed
        let cache = self.get_or_refresh_cache().await;

        if !cache.has_any_rules {
            return Ok(());
        }

        // Check if admin IP matches any rule in the relevant scopes
        for entry in &cache.entries {
            if entry.scope == IpAllowlistScope::Global || entry.scope == scope {
                if entry.network.contains(&ip) {
                    return Ok(());
                }
            }
        }

        Err(IpAllowlistServiceError::SelfLockout(admin_ip.to_string()))
    }

    /// Test an IP against the current allowlist
    pub async fn test_ip(
        &self,
        ip_str: &str,
        scope: Option<IpAllowlistScope>,
    ) -> Result<TestIpResponse, IpAllowlistServiceError> {
        let ip: IpAddr = ip_str
            .parse()
            .map_err(|_| IpAllowlistServiceError::InvalidIp(ip_str.to_string()))?;

        let cache = self.get_or_refresh_cache().await;

        if !cache.has_any_rules {
            return Ok(TestIpResponse {
                ip: ip_str.to_string(),
                allowed: true,
                matched_rules: vec![],
                allowlist_active: false,
            });
        }

        let mut matched_rules = Vec::new();

        for entry in &cache.entries {
            // If testing a specific scope, only check global + that scope
            if let Some(test_scope) = scope {
                if entry.scope != IpAllowlistScope::Global && entry.scope != test_scope {
                    continue;
                }
            }

            if entry.network.contains(&ip) {
                matched_rules.push(MatchedRule {
                    id: entry.id,
                    scope: entry.scope,
                    cidr: entry.cidr_str.clone(),
                    description: entry.description.clone(),
                });
            }
        }

        let allowed = !matched_rules.is_empty();

        Ok(TestIpResponse {
            ip: ip_str.to_string(),
            allowed,
            matched_rules,
            allowlist_active: true,
        })
    }

    /// Get allowlist status summary
    pub async fn status(&self) -> Result<IpAllowlistStatus, IpAllowlistServiceError> {
        let entries = self.repository().list(None).await?;
        let enabled_rules = entries.iter().filter(|e| e.enabled).count();

        let mut rules_by_scope = std::collections::HashMap::new();
        for entry in &entries {
            if entry.enabled {
                *rules_by_scope
                    .entry(entry.scope.as_str().to_string())
                    .or_insert(0) += 1;
            }
        }

        Ok(IpAllowlistStatus {
            active: enabled_rules > 0,
            total_rules: entries.len(),
            enabled_rules,
            rules_by_scope,
        })
    }
}
