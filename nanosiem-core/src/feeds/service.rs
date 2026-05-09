// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed service for business logic

use clickhouse::Client as ClickHouseClient;
use regex::Regex;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use uuid::Uuid;

use super::repository::{FeedRepository, FeedRepositoryError};
use super::types::{Feed, FeedHealthMetrics, FeedHistoryPoint, FeedStats, NewFeed, UpdateFeed};
use crate::db::DualPool;

#[derive(Error, Debug)]
pub enum FeedServiceError {
    #[error("Repository error: {0}")]
    RepositoryError(#[from] FeedRepositoryError),
    #[error("Invalid regex pattern: {0}")]
    InvalidPattern(String),
    #[error("Feed must have at least one matching criteria")]
    NoMatchingCriteria,
}

/// Feed service for managing log sourcetypes
#[derive(Clone)]
pub struct FeedService {
    pool: PgPool,
    ch_client: Option<ClickHouseClient>,
    /// Carried through to FeedRepository so rollup-backed reads pick the
    /// `_distributed` wrapper in cluster mode (NAN-735).
    table_names: crate::db::TableNames,
    /// Cached compiled regex patterns for feed matching
    pattern_cache: Arc<RwLock<HashMap<Uuid, Regex>>>,
}

impl FeedService {
    /// Create a new feed service with PostgreSQL only (legacy mode)
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ch_client: None,
            table_names: crate::db::TableNames::new(false),
            pattern_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new feed service with DualPool (ClickHouse for log stats)
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        Self {
            pool: dual_pool.postgres().clone(),
            ch_client: Some(dual_pool.clickhouse().clone()),
            table_names: dual_pool.table_names(),
            pattern_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn repository(&self) -> FeedRepository {
        if let Some(ref ch_client) = self.ch_client {
            FeedRepository::with_clickhouse(
                self.pool.clone(),
                ch_client.clone(),
                self.table_names.clone(),
            )
        } else {
            FeedRepository::new(self.pool.clone())
        }
    }

    /// List all feeds
    pub async fn list(&self) -> Result<Vec<Feed>, FeedServiceError> {
        Ok(self.repository().list().await?)
    }

    /// List enabled feeds
    pub async fn list_enabled(&self) -> Result<Vec<Feed>, FeedServiceError> {
        Ok(self.repository().list_enabled().await?)
    }

    /// Get a feed by ID
    pub async fn get(&self, id: Uuid) -> Result<Feed, FeedServiceError> {
        Ok(self.repository().find_by_id(id).await?)
    }

    /// Get a feed by name
    pub async fn get_by_name(&self, name: &str) -> Result<Feed, FeedServiceError> {
        Ok(self.repository().find_by_name(name).await?)
    }

    /// Create a new feed
    pub async fn create(&self, new_feed: NewFeed) -> Result<Feed, FeedServiceError> {
        // Validate that at least one matching criteria is set
        if new_feed.match_field.is_none()
            && new_feed.match_pattern.is_none()
            && new_feed.match_values.is_none()
        {
            return Err(FeedServiceError::NoMatchingCriteria);
        }

        // Validate regex pattern if provided
        if let Some(ref pattern) = new_feed.match_pattern {
            Regex::new(pattern).map_err(|e| FeedServiceError::InvalidPattern(e.to_string()))?;
        }

        Ok(self.repository().create(&new_feed).await?)
    }

    /// Update a feed
    pub async fn update(&self, id: Uuid, update: UpdateFeed) -> Result<Feed, FeedServiceError> {
        // Validate regex pattern if provided
        if let Some(ref pattern) = update.match_pattern {
            Regex::new(pattern).map_err(|e| FeedServiceError::InvalidPattern(e.to_string()))?;
        }

        // Clear pattern cache for this feed
        if let Ok(mut cache) = self.pattern_cache.write() {
            cache.remove(&id);
        }

        Ok(self.repository().update(id, &update).await?)
    }

    /// Delete a feed
    pub async fn delete(&self, id: Uuid) -> Result<(), FeedServiceError> {
        // Clear pattern cache for this feed
        if let Ok(mut cache) = self.pattern_cache.write() {
            cache.remove(&id);
        }
        Ok(self.repository().delete(id).await?)
    }

    /// Enable a feed
    pub async fn enable(&self, id: Uuid) -> Result<Feed, FeedServiceError> {
        Ok(self.repository().enable(id).await?)
    }

    /// Disable a feed
    pub async fn disable(&self, id: Uuid) -> Result<Feed, FeedServiceError> {
        Ok(self.repository().disable(id).await?)
    }

    /// Get feed statistics
    pub async fn get_stats(&self) -> Result<Vec<FeedStats>, FeedServiceError> {
        Ok(self.repository().get_stats().await?)
    }

    /// Get detailed health metrics for a specific feed
    pub async fn get_health_metrics(
        &self,
        feed_id: Uuid,
    ) -> Result<FeedHealthMetrics, FeedServiceError> {
        Ok(self.repository().get_health_metrics(feed_id).await?)
    }

    /// Get historical ingestion data for charts
    pub async fn get_ingestion_history(
        &self,
        feed_id: Uuid,
    ) -> Result<Vec<FeedHistoryPoint>, FeedServiceError> {
        Ok(self.repository().get_ingestion_history(feed_id).await?)
    }

    /// Get discovered sourcetypes from logs
    pub async fn get_discovered_sourcetypes(&self) -> Result<Vec<(String, i64)>, FeedServiceError> {
        Ok(self.repository().get_discovered_sourcetypes().await?)
    }

    /// Match a log event to a feed based on field values
    /// Returns the feed name if matched, None otherwise
    pub fn match_event(&self, feeds: &[Feed], event: &serde_json::Value) -> Option<String> {
        for feed in feeds {
            if !feed.enabled {
                continue;
            }

            if self.matches_feed(feed, event) {
                return Some(feed.name.clone());
            }
        }
        None
    }

    /// Check if an event matches a specific feed
    fn matches_feed(&self, feed: &Feed, event: &serde_json::Value) -> bool {
        let Some(ref match_field) = feed.match_field else {
            return false;
        };

        // Get the field value from the event
        let field_value = self.get_nested_field(event, match_field);
        let Some(value_str) = field_value.and_then(|v| v.as_str()) else {
            return false;
        };

        // Check exact match values first
        if let Some(ref match_values) = feed.match_values {
            if match_values.iter().any(|v| v == value_str) {
                return true;
            }
        }

        // Check regex pattern
        if let Some(ref pattern_str) = feed.match_pattern {
            // Try to get cached regex or compile new one
            let regex = {
                let cache = self.pattern_cache.read().ok();
                cache.and_then(|c| c.get(&feed.id).cloned())
            };

            let regex = regex.unwrap_or_else(|| {
                let compiled =
                    Regex::new(pattern_str).unwrap_or_else(|_| Regex::new("^$").unwrap());
                if let Ok(mut cache) = self.pattern_cache.write() {
                    cache.insert(feed.id, compiled.clone());
                }
                compiled
            });

            if regex.is_match(value_str) {
                return true;
            }
        }

        false
    }

    /// Get a nested field value from JSON using dot notation
    fn get_nested_field<'a>(
        &self,
        value: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = value;

        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    current = map.get(part)?;
                }
                serde_json::Value::Array(arr) => {
                    let index: usize = part.parse().ok()?;
                    current = arr.get(index)?;
                }
                _ => return None,
            }
        }

        Some(current)
    }
}
