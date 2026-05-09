// SPDX-License-Identifier: AGPL-3.0-or-later

// ! Query Result Caching for AI Detection Auto-Tuning
//!
//! Provides in-memory caching for frequently accessed tuning data:
//! - Baseline statistics (refreshed hourly)
//! - Recent metrics (refreshed every 5 minutes)
//! - Rule configuration (refreshed on updates)

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::{Baseline, RuleMetrics};

/// Cache entry with expiration
#[derive(Clone, Debug)]
struct CacheEntry<T> {
    data: T,
    expires_at: DateTime<Utc>,
}

impl<T> CacheEntry<T> {
    fn new(data: T, ttl: Duration) -> Self {
        Self {
            data,
            expires_at: Utc::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// In-memory cache for tuning data
#[derive(Clone)]
pub struct TuningCache {
    baselines: Arc<RwLock<HashMap<Uuid, CacheEntry<Baseline>>>>,
    metrics: Arc<RwLock<HashMap<Uuid, CacheEntry<RuleMetrics>>>>,
    rule_configs: Arc<RwLock<HashMap<Uuid, CacheEntry<RuleConfig>>>>,
}

/// Rule configuration for auto-tuning
#[derive(Clone, Debug)]
pub struct RuleConfig {
    pub rule_id: Uuid,
    pub auto_tuning_enabled: bool,
    pub auto_tuning_min_confidence: f64,
    pub auto_tuning_critical: bool,
    pub auto_tuning_disabled_until: Option<DateTime<Utc>>,
}

impl TuningCache {
    /// Create a new tuning cache
    pub fn new() -> Self {
        Self {
            baselines: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            rule_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a baseline from cache
    ///
    /// Returns None if not cached or expired.
    pub async fn get_baseline(&self, rule_id: Uuid) -> Option<Baseline> {
        let cache = self.baselines.read().await;
        cache.get(&rule_id).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.data.clone())
            }
        })
    }

    /// Store a baseline in cache
    ///
    /// Baselines are cached for 1 hour.
    pub async fn set_baseline(&self, baseline: Baseline) {
        let mut cache = self.baselines.write().await;
        let ttl = Duration::hours(1);
        cache.insert(baseline.rule_id, CacheEntry::new(baseline, ttl));
    }

    /// Invalidate a baseline cache entry
    pub async fn invalidate_baseline(&self, rule_id: Uuid) {
        let mut cache = self.baselines.write().await;
        cache.remove(&rule_id);
    }

    /// Get metrics from cache
    ///
    /// Returns None if not cached or expired.
    pub async fn get_metrics(&self, rule_id: Uuid) -> Option<RuleMetrics> {
        let cache = self.metrics.read().await;
        cache.get(&rule_id).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.data.clone())
            }
        })
    }

    /// Store metrics in cache
    ///
    /// Metrics are cached for 5 minutes.
    pub async fn set_metrics(&self, metrics: RuleMetrics) {
        let mut cache = self.metrics.write().await;
        let ttl = Duration::minutes(5);
        cache.insert(metrics.rule_id, CacheEntry::new(metrics, ttl));
    }

    /// Invalidate a metrics cache entry
    pub async fn invalidate_metrics(&self, rule_id: Uuid) {
        let mut cache = self.metrics.write().await;
        cache.remove(&rule_id);
    }

    /// Get rule configuration from cache
    ///
    /// Returns None if not cached or expired.
    pub async fn get_rule_config(&self, rule_id: Uuid) -> Option<RuleConfig> {
        let cache = self.rule_configs.read().await;
        cache.get(&rule_id).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.data.clone())
            }
        })
    }

    /// Store rule configuration in cache
    ///
    /// Rule configs are cached for 15 minutes.
    pub async fn set_rule_config(&self, config: RuleConfig) {
        let mut cache = self.rule_configs.write().await;
        let ttl = Duration::minutes(15);
        cache.insert(config.rule_id, CacheEntry::new(config, ttl));
    }

    /// Invalidate a rule configuration cache entry
    pub async fn invalidate_rule_config(&self, rule_id: Uuid) {
        let mut cache = self.rule_configs.write().await;
        cache.remove(&rule_id);
    }

    /// Clear all expired entries from all caches
    ///
    /// This should be called periodically to prevent memory growth.
    pub async fn cleanup_expired(&self) {
        // Clean baselines
        {
            let mut cache = self.baselines.write().await;
            cache.retain(|_, entry| !entry.is_expired());
        }

        // Clean metrics
        {
            let mut cache = self.metrics.write().await;
            cache.retain(|_, entry| !entry.is_expired());
        }

        // Clean rule configs
        {
            let mut cache = self.rule_configs.write().await;
            cache.retain(|_, entry| !entry.is_expired());
        }
    }

    /// Clear all caches
    pub async fn clear_all(&self) {
        self.baselines.write().await.clear();
        self.metrics.write().await.clear();
        self.rule_configs.write().await.clear();
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let baselines_count = self.baselines.read().await.len();
        let metrics_count = self.metrics.read().await.len();
        let rule_configs_count = self.rule_configs.read().await.len();

        CacheStats {
            baselines_count,
            metrics_count,
            rule_configs_count,
            total_entries: baselines_count + metrics_count + rule_configs_count,
        }
    }
}

impl Default for TuningCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub baselines_count: usize,
    pub metrics_count: usize,
    pub rule_configs_count: usize,
    pub total_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_baseline_cache() {
        let cache = TuningCache::new();
        let rule_id = Uuid::now_v7();

        let baseline = Baseline {
            rule_id,
            established_at: Utc::now(),
            last_updated: Utc::now(),
            mean_alerts_per_hour: 10.0,
            std_dev_alerts_per_hour: 2.0,
            percentile_95: 15.0,
            percentile_99: 20.0,
            threshold_breach_level: 14.0,
            data_points: 100,
            status: Default::default(),
        };

        // Store baseline
        cache.set_baseline(baseline.clone()).await;

        // Retrieve baseline
        let cached = cache.get_baseline(rule_id).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().rule_id, rule_id);

        // Invalidate baseline
        cache.invalidate_baseline(rule_id).await;
        let cached = cache.get_baseline(rule_id).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_metrics_cache() {
        let cache = TuningCache::new();
        let rule_id = Uuid::now_v7();

        let metrics = RuleMetrics {
            rule_id,
            timestamp: Utc::now(),
            alert_count_1h: 10,
            alert_count_24h: 100,
            alert_count_7d: 500,
            unique_users: 5,
            unique_hosts: 3,
            unique_ips: 8,
            avg_severity: 3.5,
            execution_time_ms: 100,
        };

        // Store metrics
        cache.set_metrics(metrics.clone()).await;

        // Retrieve metrics
        let cached = cache.get_metrics(rule_id).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().rule_id, rule_id);

        // Invalidate metrics
        cache.invalidate_metrics(rule_id).await;
        let cached = cache.get_metrics(rule_id).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_rule_config_cache() {
        let cache = TuningCache::new();
        let rule_id = Uuid::now_v7();

        let config = RuleConfig {
            rule_id,
            auto_tuning_enabled: true,
            auto_tuning_min_confidence: 0.8,
            auto_tuning_critical: false,
            auto_tuning_disabled_until: None,
        };

        // Store config
        cache.set_rule_config(config.clone()).await;

        // Retrieve config
        let cached = cache.get_rule_config(rule_id).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().rule_id, rule_id);

        // Invalidate config
        cache.invalidate_rule_config(rule_id).await;
        let cached = cache.get_rule_config(rule_id).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = TuningCache::new();
        let rule_id = Uuid::now_v7();

        // Create a cache entry with very short TTL for testing
        let baseline = Baseline {
            rule_id,
            established_at: Utc::now(),
            last_updated: Utc::now(),
            mean_alerts_per_hour: 10.0,
            std_dev_alerts_per_hour: 2.0,
            percentile_95: 15.0,
            percentile_99: 20.0,
            threshold_breach_level: 14.0,
            data_points: 100,
            status: Default::default(),
        };

        // Manually create an expired entry
        {
            let mut baselines = cache.baselines.write().await;
            let expired_entry = CacheEntry {
                data: baseline,
                expires_at: Utc::now() - Duration::seconds(1),
            };
            baselines.insert(rule_id, expired_entry);
        }

        // Try to retrieve - should return None because it's expired
        let cached = cache.get_baseline(rule_id).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let cache = TuningCache::new();
        let rule_id1 = Uuid::now_v7();
        let rule_id2 = Uuid::now_v7();

        // Add one expired and one valid entry
        {
            let mut baselines = cache.baselines.write().await;

            let expired_baseline = Baseline {
                rule_id: rule_id1,
                established_at: Utc::now(),
                last_updated: Utc::now(),
                mean_alerts_per_hour: 10.0,
                std_dev_alerts_per_hour: 2.0,
                percentile_95: 15.0,
                percentile_99: 20.0,
                threshold_breach_level: 14.0,
                data_points: 100,
                status: Default::default(),
            };

            let valid_baseline = Baseline {
                rule_id: rule_id2,
                established_at: Utc::now(),
                last_updated: Utc::now(),
                mean_alerts_per_hour: 10.0,
                std_dev_alerts_per_hour: 2.0,
                percentile_95: 15.0,
                percentile_99: 20.0,
                threshold_breach_level: 14.0,
                data_points: 100,
                status: Default::default(),
            };

            baselines.insert(
                rule_id1,
                CacheEntry {
                    data: expired_baseline,
                    expires_at: Utc::now() - Duration::seconds(1),
                },
            );

            baselines.insert(
                rule_id2,
                CacheEntry::new(valid_baseline, Duration::hours(1)),
            );
        }

        // Cleanup expired entries
        cache.cleanup_expired().await;

        // Check that expired entry is gone and valid entry remains
        let stats = cache.get_stats().await;
        assert_eq!(stats.baselines_count, 1);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = TuningCache::new();

        let rule_id = Uuid::now_v7();

        let baseline = Baseline {
            rule_id,
            established_at: Utc::now(),
            last_updated: Utc::now(),
            mean_alerts_per_hour: 10.0,
            std_dev_alerts_per_hour: 2.0,
            percentile_95: 15.0,
            percentile_99: 20.0,
            threshold_breach_level: 14.0,
            data_points: 100,
            status: Default::default(),
        };

        let metrics = RuleMetrics {
            rule_id,
            timestamp: Utc::now(),
            alert_count_1h: 10,
            alert_count_24h: 100,
            alert_count_7d: 500,
            unique_users: 5,
            unique_hosts: 3,
            unique_ips: 8,
            avg_severity: 3.5,
            execution_time_ms: 100,
        };

        cache.set_baseline(baseline).await;
        cache.set_metrics(metrics).await;

        let stats = cache.get_stats().await;
        assert_eq!(stats.baselines_count, 1);
        assert_eq!(stats.metrics_count, 1);
        assert_eq!(stats.total_entries, 2);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let cache = TuningCache::new();
        let rule_id = Uuid::now_v7();

        let baseline = Baseline {
            rule_id,
            established_at: Utc::now(),
            last_updated: Utc::now(),
            mean_alerts_per_hour: 10.0,
            std_dev_alerts_per_hour: 2.0,
            percentile_95: 15.0,
            percentile_99: 20.0,
            threshold_breach_level: 14.0,
            data_points: 100,
            status: Default::default(),
        };

        cache.set_baseline(baseline).await;

        let stats = cache.get_stats().await;
        assert_eq!(stats.total_entries, 1);

        cache.clear_all().await;

        let stats = cache.get_stats().await;
        assert_eq!(stats.total_entries, 0);
    }
}
