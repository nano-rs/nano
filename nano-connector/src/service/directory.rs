// SPDX-License-Identifier: AGPL-3.0-or-later

//! G22: where a `kind: identity` feed's rows land.
//!
//! The runner opens one [`IdentityDirectory`] per identity run from its
//! [`IdentityDirectories`]. In production that is the ClickHouse
//! `user_registry` (plus the feed's PostgreSQL `identity_providers` row for
//! status), through `nanosiem_core::identity::directory_feed::FeedDirectory`.
//! The runner otherwise needs no ClickHouse access, so this is opt-in: a
//! runner started without `CLICKHOUSE_URL` refuses identity feeds with a
//! clear error and keeps running collectors.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nanosiem_core::identity::IdentityRepository;
use nanosiem_core::identity::directory_feed::{DirectoryRow, FeedDirectory, provider_type_for_connector};

use super::feed::FeedDefinition;
use crate::identity::{Directory, MemoryDirectory};

/// One identity run's directory, with the provider status hooks.
#[async_trait::async_trait]
pub trait IdentityDirectory: Directory {
    /// The run started (provider `in_progress`).
    async fn started(&self) -> Result<(), String>;
    /// The run ended: record status, error, duration and rows written.
    async fn finished(&self, ok: bool, error: Option<&str>, duration_ms: i64, rows: u64);
}

/// Opens the directory of a claimed identity feed.
#[async_trait::async_trait]
pub trait IdentityDirectories: Send + Sync {
    async fn open(&self, feed: &FeedDefinition) -> Result<Arc<dyn IdentityDirectory>, String>;
}

/// The ClickHouse `user_registry` behind a feed's `identity_providers` row.
pub struct ClickHouseDirectories {
    repo: IdentityRepository,
}

impl ClickHouseDirectories {
    pub fn new(pool: sqlx::PgPool, clickhouse: clickhouse::Client) -> Self {
        Self { repo: IdentityRepository::new_with_clickhouse(pool, clickhouse) }
    }
}

#[async_trait::async_trait]
impl IdentityDirectories for ClickHouseDirectories {
    async fn open(&self, feed: &FeedDefinition) -> Result<Arc<dyn IdentityDirectory>, String> {
        let provider_type = provider_type_for_connector(&feed.connector)
            .ok_or_else(|| format!("connector `{}` has no identity provider type", feed.connector))?;
        let dir = FeedDirectory::open(self.repo.clone(), feed.feed_id, &feed.name, provider_type)
            .await
            .map_err(|e| format!("identity directory: {e}"))?;
        Ok(Arc::new(ClickHouseDirectory(dir)))
    }
}

struct ClickHouseDirectory(FeedDirectory);

fn err(e: impl std::fmt::Display) -> String {
    format!("identity directory: {e}")
}

#[async_trait::async_trait]
impl Directory for ClickHouseDirectory {
    async fn upsert(&self, rows: &[DirectoryRow], patch: bool) -> Result<u64, String> {
        self.0.upsert(rows, patch).await.map_err(err)
    }
    async fn references(&self, ids: &[String]) -> Result<HashMap<String, String>, String> {
        self.0.references(ids).await.map_err(err)
    }
    async fn set_managers(&self, pairs: &[(String, String)]) -> Result<u64, String> {
        self.0.set_managers(pairs).await.map_err(err)
    }
    async fn retire_absent(&self, seen: &HashSet<String>) -> Result<u64, String> {
        self.0.retire_absent(seen).await.map_err(err)
    }
    async fn replace_groups(&self, groups: &HashMap<String, Vec<String>>) -> Result<(u64, u64), String> {
        self.0.replace_groups(groups).await.map_err(err)
    }
}

#[async_trait::async_trait]
impl IdentityDirectory for ClickHouseDirectory {
    async fn started(&self) -> Result<(), String> {
        self.0.mark_running().await.map_err(err)
    }
    async fn finished(&self, ok: bool, error: Option<&str>, duration_ms: i64, rows: u64) {
        let status = if ok { "completed" } else { "failed" };
        if let Err(e) = self.0.finish(status, error, duration_ms, rows).await {
            tracing::warn!(provider_id = %self.0.provider_id(), error = %e, "identity provider status was not recorded");
        }
    }
}

/// Runner without a directory: identity feeds fail with this reason.
pub const IDENTITY_UNCONFIGURED: &str =
    "identity_directory_unconfigured: this runner has no user directory (set CLICKHOUSE_URL and its credentials to run identity feeds)";

/// In-memory directories, one per feed (tests).
#[derive(Default)]
pub struct MemoryDirectories {
    pub feeds: std::sync::Mutex<HashMap<uuid::Uuid, Arc<MemoryFeedDirectory>>>,
}

impl MemoryDirectories {
    pub fn feed(&self, id: uuid::Uuid) -> Arc<MemoryFeedDirectory> {
        self.feeds.lock().expect("directories").entry(id).or_default().clone()
    }
}

#[async_trait::async_trait]
impl IdentityDirectories for MemoryDirectories {
    async fn open(&self, feed: &FeedDefinition) -> Result<Arc<dyn IdentityDirectory>, String> {
        Ok(self.feed(feed.feed_id))
    }
}

/// A [`MemoryDirectory`] that also records run outcomes.
#[derive(Default)]
pub struct MemoryFeedDirectory {
    pub dir: MemoryDirectory,
    pub outcomes: std::sync::Mutex<Vec<(bool, Option<String>, u64)>>,
}

#[async_trait::async_trait]
impl Directory for MemoryFeedDirectory {
    async fn upsert(&self, rows: &[DirectoryRow], patch: bool) -> Result<u64, String> {
        self.dir.upsert(rows, patch).await
    }
    async fn references(&self, ids: &[String]) -> Result<HashMap<String, String>, String> {
        self.dir.references(ids).await
    }
    async fn set_managers(&self, pairs: &[(String, String)]) -> Result<u64, String> {
        self.dir.set_managers(pairs).await
    }
    async fn retire_absent(&self, seen: &HashSet<String>) -> Result<u64, String> {
        self.dir.retire_absent(seen).await
    }
    async fn replace_groups(&self, groups: &HashMap<String, Vec<String>>) -> Result<(u64, u64), String> {
        self.dir.replace_groups(groups).await
    }
}

#[async_trait::async_trait]
impl IdentityDirectory for MemoryFeedDirectory {
    async fn started(&self) -> Result<(), String> {
        Ok(())
    }
    async fn finished(&self, ok: bool, error: Option<&str>, _duration_ms: i64, rows: u64) {
        self.outcomes.lock().expect("outcomes").push((ok, error.map(str::to_string), rows));
    }
}
