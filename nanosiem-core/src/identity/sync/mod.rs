// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity provider sync implementations
//!
//! Each provider implements the SyncProvider trait for full and delta sync.
//! Providers that paginate should override `full_sync_paged` to yield pages
//! one at a time, keeping memory bounded for large directories.

pub mod entra;
pub mod google;
pub mod okta;
pub mod workday;

use super::types::{ConnectionTestResult, DeltaSyncResult};
use async_trait::async_trait;

/// Callback that receives each page of users during a paged sync.
/// Returns the count of users processed for progress tracking.
///
/// NAN-1151: pages are now the provider's RAW user objects
/// (`serde_json::Value`), not pre-mapped `UserRecordUpsert`s — the caller emits
/// them onto the `nano_enrich` lane where the repo-sourced per-source VRL does
/// the mapping. The hard-coded Rust mappers are gone.
pub type PageCallback<'a> = &'a (dyn Fn(
    Vec<serde_json::Value>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<u64, SyncError>> + Send + 'a>,
> + Send
         + Sync);

/// Trait for identity provider sync implementations.
///
/// NAN-1151: providers fetch and yield RAW provider user objects; mapping to
/// `user_registry` happens in VRL on the enrichment lane, not here.
#[async_trait]
pub trait SyncProvider: Send + Sync {
    /// Perform a full sync — fetch all users from the provider as raw JSON.
    /// Default implementation used as fallback for providers that don't support paged sync.
    async fn full_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
    ) -> Result<Vec<serde_json::Value>, SyncError>;

    /// Perform a full sync, yielding pages to a callback as they arrive.
    /// Each page is dropped after the callback processes it, keeping memory bounded.
    /// Returns the total number of users synced.
    ///
    /// Default implementation falls back to `full_sync` and passes all results as one page.
    async fn full_sync_paged(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        on_page: PageCallback<'_>,
    ) -> Result<u64, SyncError> {
        let users = self.full_sync(credentials, config).await?;
        let count = users.len() as u64;
        on_page(users).await?;
        Ok(count)
    }

    /// Perform a delta sync — fetch only changed users since the last sync
    /// Returns None if delta sync is not supported or the delta_link is invalid.
    async fn delta_sync(
        &self,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        delta_link: Option<&str>,
    ) -> Result<Option<DeltaSyncResult>, SyncError>;

    /// Test the connection to the provider
    async fn test_connection(
        &self,
        credentials: &serde_json::Value,
    ) -> Result<ConnectionTestResult, SyncError>;
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("Authentication failed: {0}")]
    AuthError(String),
    #[error("API error: {status} {message}")]
    ApiError { status: u16, message: String },
    #[error("Rate limited, retry after {retry_after_secs:?}s")]
    RateLimited { retry_after_secs: Option<u64> },
    #[error("Invalid credentials: {0}")]
    InvalidCredentials(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}
