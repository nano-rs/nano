// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

async fn unavailable() -> IpAllowlistService {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://fixture:fixture@127.0.0.1:1/never_connect")
        .unwrap();
    pool.close().await;
    IpAllowlistService { pool, cache: Arc::new(RwLock::new(None)), disabled: false }
}

#[tokio::test]
async fn policy_failure_never_becomes_an_empty_allowlist() {
    let service = unavailable().await;
    assert!(service.check_allowed("203.0.113.5", IpAllowlistScope::Api).await.is_err());
    assert!(!service.is_allowed("203.0.113.5", IpAllowlistScope::Api).await);
    assert!(service.cache.read().await.is_none());
    assert!(service.test_ip("203.0.113.5", None).await.is_err());
    assert!(service.validate_no_self_lockout("203.0.113.5", IpAllowlistScope::Api).await.is_err());
}

#[tokio::test]
async fn expired_empty_cache_cannot_allow_traffic_when_refresh_fails() {
    let service = unavailable().await;
    *service.cache.write().await = Some(CacheState {
        entries: vec![], has_any_rules: false,
        last_refresh: std::time::Instant::now() - std::time::Duration::from_secs(CACHE_TTL_SECS + 1),
    });
    for _ in 0..2 {
        assert!(service.check_allowed("203.0.113.5", IpAllowlistScope::Api).await.is_err());
    }
    assert!(service.cache.read().await.as_ref().unwrap().last_refresh.elapsed().as_secs() >= CACHE_TTL_SECS);
}

#[tokio::test]
async fn valid_empty_cache_preserves_inactive_policy_until_expiry_or_invalidation() {
    let service = unavailable().await;
    *service.cache.write().await = Some(CacheState {
        entries: vec![], has_any_rules: false, last_refresh: std::time::Instant::now(),
    });
    assert!(service.check_allowed("203.0.113.5", IpAllowlistScope::Api).await.unwrap());
    service.invalidate_cache().await;
    assert!(service.check_allowed("203.0.113.5", IpAllowlistScope::Api).await.is_err());
}

#[tokio::test]
async fn valid_rules_preserve_scope_and_address_matching() {
    let service = unavailable().await;
    let entries = [(IpAllowlistScope::Api, "203.0.113.0/24"), (IpAllowlistScope::Global, "2001:db8::/32")]
        .into_iter().map(|(scope, cidr)| CachedCidr {
            id: Uuid::new_v4(), scope, cidr_str: cidr.into(), description: None,
            network: IpNetwork::parse(cidr).unwrap(),
        }).collect();
    *service.cache.write().await = Some(CacheState {
        entries, has_any_rules: true, last_refresh: std::time::Instant::now(),
    });
    assert!(service.check_allowed("203.0.113.5", IpAllowlistScope::Api).await.unwrap());
    assert!(!service.check_allowed("203.0.113.5", IpAllowlistScope::Search).await.unwrap());
    assert!(!service.check_allowed("198.51.100.5", IpAllowlistScope::Api).await.unwrap());
    assert!(service.check_allowed("2001:db8::5", IpAllowlistScope::Search).await.unwrap());
}

#[tokio::test]
async fn explicit_legacy_exceptions_and_invalid_address_behavior_are_preserved() {
    let mut service = unavailable().await;
    for ip in ["127.0.0.1", "::1"] {
        assert!(service.check_allowed(ip, IpAllowlistScope::Api).await.unwrap());
    }
    assert!(!service.check_allowed("not-an-ip", IpAllowlistScope::Api).await.unwrap());
    service.disabled = true;
    assert!(service.check_allowed("203.0.113.5", IpAllowlistScope::Api).await.unwrap());
}
