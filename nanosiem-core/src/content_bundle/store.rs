// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL store of installed content channels (PG migration 309).
//!
//! `content_channel_state` holds the last good install per channel and the
//! latest check; `content_channel_files` holds the verified files of that
//! install. An install replaces both in ONE transaction, so readers (the
//! repository syncs, through [`super::source`]) see either the previous
//! snapshot or the new one, never a mix.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{PgPool, Row};

use super::contract::{SignedContentDescriptor, VerifiedContent};
use super::tree::{self, Files};

/// One channel's stored state.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct ChannelRow {
    pub channel: String,
    pub enabled: bool,
    #[schema(value_type = Option<Object>)]
    pub signed_descriptor: Option<serde_json::Value>,
    pub sequence: Option<i64>,
    pub upstream_commit: Option<String>,
    pub tree_sha256: Option<String>,
    pub file_count: Option<i32>,
    pub source: Option<String>,
    pub route: Option<String>,
    pub installed_at: Option<DateTime<Utc>>,
    pub applied_at: Option<DateTime<Utc>>,
    pub apply_error: Option<String>,
    pub last_check_at: Option<DateTime<Utc>>,
    pub last_check_status: Option<String>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
}

/// A file of an installed snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    pub path: String,
    pub blob_sha1: String,
    pub size: i64,
}

#[derive(Clone)]
pub struct ContentStore {
    pool: PgPool,
}

const STATE_COLUMNS: &str = "channel, enabled, signed_descriptor, sequence, upstream_commit, tree_sha256, \
    file_count, source, route, installed_at, applied_at, apply_error, last_check_at, last_check_status, \
    last_error, last_error_at";

fn row_from(r: &sqlx::postgres::PgRow) -> ChannelRow {
    ChannelRow {
        channel: r.get("channel"),
        enabled: r.get("enabled"),
        signed_descriptor: r.get("signed_descriptor"),
        sequence: r.get("sequence"),
        upstream_commit: r.get("upstream_commit"),
        tree_sha256: r.get("tree_sha256"),
        file_count: r.get("file_count"),
        source: r.get("source"),
        route: r.get("route"),
        installed_at: r.get("installed_at"),
        applied_at: r.get("applied_at"),
        apply_error: r.get("apply_error"),
        last_check_at: r.get("last_check_at"),
        last_check_status: r.get("last_check_status"),
        last_error: r.get("last_error"),
        last_error_at: r.get("last_error_at"),
    }
}

impl ContentStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn get(&self, channel: &str) -> Result<Option<ChannelRow>, sqlx::Error> {
        let row = sqlx::query(&format!(
            "SELECT {STATE_COLUMNS} FROM content_channel_state WHERE channel = $1"
        ))
        .bind(channel)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_from))
    }

    pub async fn list(&self) -> Result<Vec<ChannelRow>, sqlx::Error> {
        let rows = sqlx::query(&format!(
            "SELECT {STATE_COLUMNS} FROM content_channel_state ORDER BY channel"
        ))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_from).collect())
    }

    /// Opt a channel out (or back in). Creates the row when missing.
    pub async fn set_enabled(&self, channel: &str, enabled: bool) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO content_channel_state (channel, enabled) VALUES ($1, $2) \
             ON CONFLICT (channel) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW()",
        )
        .bind(channel)
        .bind(enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Record the latest check outcome (`checking`, `current`, `installed`,
    /// `refused`, `failed`, `skipped`). The installed snapshot is untouched.
    pub async fn record_check(
        &self,
        channel: &str,
        status: &str,
        error: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO content_channel_state (channel, last_check_at, last_check_status, last_error, last_error_at) \
             VALUES ($1, $2, $3, $4, CASE WHEN $4::text IS NULL THEN NULL ELSE $2 END) \
             ON CONFLICT (channel) DO UPDATE SET last_check_at = EXCLUDED.last_check_at, \
               last_check_status = EXCLUDED.last_check_status, \
               last_error = COALESCE(EXCLUDED.last_error, content_channel_state.last_error), \
               last_error_at = COALESCE(EXCLUDED.last_error_at, content_channel_state.last_error_at), \
               updated_at = NOW()",
        )
        .bind(channel)
        .bind(at)
        .bind(status)
        .bind(error)
        .execute(&self.pool)
        .await?;
        if error.is_none() && matches!(status, "current" | "installed") {
            sqlx::query(
                "UPDATE content_channel_state SET last_error = NULL, last_error_at = NULL WHERE channel = $1",
            )
            .bind(channel)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Record the outcome of applying an installed snapshot to its consumer
    /// (repository rows marked due, or an extension's applier).
    pub async fn record_apply(&self, channel: &str, error: Option<&str>) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE content_channel_state SET applied_at = CASE WHEN $2::text IS NULL THEN NOW() ELSE applied_at END, \
             apply_error = $2, updated_at = NOW() WHERE channel = $1",
        )
        .bind(channel)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Install a verified bundle: replace the channel's files and record the
    /// descriptor in ONE transaction. When the tree is unchanged (a re-sealed
    /// descriptor for the same commit), only the state row changes.
    pub async fn install(
        &self,
        verified: &VerifiedContent,
        source: &str,
        route: &str,
    ) -> Result<bool, sqlx::Error> {
        let d = verified.descriptor();
        let descriptor = serde_json::to_value(verified.signed()).expect("descriptor serializes");
        let mut tx = self.pool.begin().await?;
        let previous_tree: Option<Option<String>> =
            sqlx::query_scalar("SELECT tree_sha256 FROM content_channel_state WHERE channel = $1 FOR UPDATE")
                .bind(&d.channel)
                .fetch_optional(&mut *tx)
                .await?;
        let files_present: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM content_channel_files WHERE channel = $1)",
        )
        .bind(&d.channel)
        .fetch_one(&mut *tx)
        .await?;
        let tree_changed = previous_tree.flatten().as_deref() != Some(d.tree.sha256.as_str()) || !files_present;
        sqlx::query(
            "INSERT INTO content_channel_state (channel, signed_descriptor, sequence, upstream_commit, tree_sha256, \
               file_count, source, route, installed_at, last_check_at, last_check_status, last_error, last_error_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), 'installed', NULL, NULL) \
             ON CONFLICT (channel) DO UPDATE SET signed_descriptor = EXCLUDED.signed_descriptor, \
               sequence = EXCLUDED.sequence, upstream_commit = EXCLUDED.upstream_commit, \
               tree_sha256 = EXCLUDED.tree_sha256, file_count = EXCLUDED.file_count, source = EXCLUDED.source, \
               route = EXCLUDED.route, installed_at = NOW(), last_check_at = NOW(), \
               last_check_status = 'installed', last_error = NULL, last_error_at = NULL, updated_at = NOW()",
        )
        .bind(&d.channel)
        .bind(&descriptor)
        .bind(d.sequence as i64)
        .bind(&d.upstream.commit)
        .bind(&d.tree.sha256)
        .bind(d.tree.files as i32)
        .bind(source)
        .bind(route)
        .execute(&mut *tx)
        .await?;
        if tree_changed {
            sqlx::query("DELETE FROM content_channel_files WHERE channel = $1")
                .bind(&d.channel)
                .execute(&mut *tx)
                .await?;
            // Batched UNNEST inserts keep one round trip per ~500 files.
            let entries: Vec<(&String, &Vec<u8>)> = verified.files().iter().collect();
            for chunk in entries.chunks(500) {
                let paths: Vec<&str> = chunk.iter().map(|(p, _)| p.as_str()).collect();
                let shas: Vec<String> = chunk.iter().map(|(_, c)| tree::git_blob_sha1(c)).collect();
                let sizes: Vec<i64> = chunk.iter().map(|(_, c)| c.len() as i64).collect();
                let contents: Vec<&[u8]> = chunk.iter().map(|(_, c)| c.as_slice()).collect();
                sqlx::query(
                    "INSERT INTO content_channel_files (channel, path, blob_sha1, size, content) \
                     SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::bigint[], $5::bytea[])",
                )
                .bind(&d.channel)
                .bind(&paths)
                .bind(&shas)
                .bind(&sizes)
                .bind(&contents)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(tree_changed)
    }

    /// The installed descriptor of `channel`, re-validated structurally (its
    /// signature was verified at install; a key retired later must not
    /// orphan it).
    pub async fn installed_descriptor(
        &self,
        channel: &str,
    ) -> Result<Option<SignedContentDescriptor>, sqlx::Error> {
        Ok(self.get(channel).await?.and_then(|r| installed_from(r.signed_descriptor.as_ref())))
    }

    /// File listing of the installed snapshot under `prefix` (empty = all).
    pub async fn list_files(&self, channel: &str, prefix: &str) -> Result<Vec<StoredFile>, sqlx::Error> {
        let prefix = prefix.trim_matches('/');
        let rows = sqlx::query(
            "SELECT path, blob_sha1, size FROM content_channel_files WHERE channel = $1 \
             AND ($2 = '' OR path = $2 OR starts_with(path, $2 || '/')) ORDER BY path",
        )
        .bind(channel)
        .bind(prefix)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| StoredFile { path: r.get("path"), blob_sha1: r.get("blob_sha1"), size: r.get("size") })
            .collect())
    }

    /// One file of the installed snapshot.
    pub async fn read_file(&self, channel: &str, path: &str) -> Result<Option<Vec<u8>>, sqlx::Error> {
        sqlx::query_scalar("SELECT content FROM content_channel_files WHERE channel = $1 AND path = $2")
            .bind(channel)
            .bind(path.trim_start_matches('/'))
            .fetch_optional(&self.pool)
            .await
    }

    /// Every file under `prefixes` (empty slice = all), for materializing.
    pub async fn read_tree(&self, channel: &str, prefixes: &[String]) -> Result<Files, sqlx::Error> {
        let prefixes: Vec<String> = prefixes.iter().map(|p| p.trim_matches('/').to_string()).collect();
        let rows = sqlx::query(
            "SELECT path, content FROM content_channel_files WHERE channel = $1 AND (cardinality($2::text[]) = 0 \
             OR EXISTS (SELECT 1 FROM unnest($2::text[]) p WHERE p = '' OR path = p OR starts_with(path, p || '/'))) \
             ORDER BY path",
        )
        .bind(channel)
        .bind(&prefixes)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(|r| (r.get::<String, _>("path"), r.get::<Vec<u8>, _>("content"))).collect())
    }
}

/// Parse a stored descriptor (structure re-validated, signature not
/// re-checked).
pub fn installed_from(stored: Option<&serde_json::Value>) -> Option<SignedContentDescriptor> {
    let signed: SignedContentDescriptor = serde_json::from_value(stored?.clone()).ok()?;
    signed.descriptor.validate().ok()?;
    Some(signed)
}
