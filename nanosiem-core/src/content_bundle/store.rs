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
use sqlx::{Connection, PgPool, Row};

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
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {STATE_COLUMNS} FROM content_channel_state WHERE channel = $1"
        )))
        .bind(channel)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_from))
    }

    pub async fn list(&self) -> Result<Vec<ChannelRow>, sqlx::Error> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {STATE_COLUMNS} FROM content_channel_state ORDER BY channel"
        )))
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
        let mut connection = self.pool.acquire().await?;
        let result = install_on(&mut connection, verified, source, route).await;
        // NAN-5668: a small-file batch can grow this connection's buffers to
        // several MiB; hand them back rather than keep them pooled, on success
        // and on failure alike.
        connection.shrink_buffers();
        result
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
        match self.read_file_capped(channel, path, u64::MAX).await? {
            CappedFile::Missing => Ok(None),
            CappedFile::Body(body) => Ok(Some(body)),
            CappedFile::TooLarge(_) => unreachable!("no file exceeds u64::MAX bytes"),
        }
    }

    /// One file of the installed snapshot, refused before it is read when it
    /// is larger than `cap` bytes. Large files are read in slices (NAN-5668).
    pub async fn read_file_capped(&self, channel: &str, path: &str, cap: u64) -> Result<CappedFile, sqlx::Error> {
        let path = path.trim_start_matches('/');
        let mut connection = self.pool.acquire().await?;
        let mut tx = connection.begin_with(SNAPSHOT_READ).await?;
        let size: Option<i64> =
            sqlx::query_scalar("SELECT octet_length(content)::bigint FROM content_channel_files WHERE channel = $1 AND path = $2")
                .bind(channel)
                .bind(path)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(size) = size else { return Ok(CappedFile::Missing) };
        if size as u64 > cap {
            return Ok(CappedFile::TooLarge(size as u64));
        }
        let body = read_sliced(&mut tx, channel, path, size).await?;
        tx.commit().await?;
        Ok(CappedFile::Body(body))
    }

    /// Every file under `prefixes` (empty slice = all), for materializing.
    ///
    /// NAN-5668: files up to [`READ_SLICE_BYTES`] come back in one query; a
    /// larger one (the 53 MB MITRE bundle) is read in slices, all inside one
    /// snapshot, so neither the DataRow buffer nor the decode copy of a whole
    /// file is ever held next to the file itself.
    pub async fn read_tree(&self, channel: &str, prefixes: &[String]) -> Result<Files, sqlx::Error> {
        let prefixes: Vec<String> = prefixes.iter().map(|p| p.trim_matches('/').to_string()).collect();
        let mut connection = self.pool.acquire().await?;
        let mut tx = connection.begin_with(SNAPSHOT_READ).await?;
        let rows = sqlx::query(
            "SELECT path, octet_length(content)::bigint AS len, \
               CASE WHEN octet_length(content) <= $3 THEN content END AS content \
             FROM content_channel_files WHERE channel = $1 AND (cardinality($2::text[]) = 0 \
             OR EXISTS (SELECT 1 FROM unnest($2::text[]) p WHERE p = '' OR path = p OR starts_with(path, p || '/'))) \
             ORDER BY path",
        )
        .bind(channel)
        .bind(&prefixes)
        .bind(READ_SLICE_BYTES)
        .fetch_all(&mut *tx)
        .await?;
        let mut files = Files::new();
        let mut large = Vec::new();
        for row in &rows {
            let path: String = row.get("path");
            match row.get::<Option<Vec<u8>>, _>("content") {
                Some(content) => {
                    files.insert(path, content);
                }
                None => large.push((path, row.get::<i64, _>("len"))),
            }
        }
        drop(rows);
        for (path, size) in large {
            let body = read_sliced(&mut tx, channel, &path, size).await?;
            files.insert(path, body);
        }
        tx.commit().await?;
        Ok(files)
    }
}

/// The install transaction of [`ContentStore::install`].
async fn install_on(
    connection: &mut sqlx::PgConnection,
    verified: &VerifiedContent,
    source: &str,
    route: &str,
) -> Result<bool, sqlx::Error> {
    let d = verified.descriptor();
    let descriptor = serde_json::to_value(verified.signed()).expect("descriptor serializes");
    let mut tx = connection.begin().await?;
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
        // Batched UNNEST inserts keep one round trip per ~500 small files
        // (and at most INSERT_BATCH_BYTES of content per statement).
        let (large, small): (Vec<(&String, &Vec<u8>)>, Vec<(&String, &Vec<u8>)>) = verified
            .files()
            .iter()
            .partition(|(_, content)| content.len() as i64 > READ_SLICE_BYTES);
        let mut batch: Vec<(&String, &Vec<u8>)> = Vec::new();
        let mut batch_bytes = 0usize;
        for entry in small {
            if batch.len() == 500 || (batch_bytes + entry.1.len() > INSERT_BATCH_BYTES && !batch.is_empty()) {
                insert_batch(&mut tx, &d.channel, &batch).await?;
                batch.clear();
                batch_bytes = 0;
            }
            batch_bytes += entry.1.len();
            batch.push(entry);
        }
        if !batch.is_empty() {
            insert_batch(&mut tx, &d.channel, &batch).await?;
        }
        // NAN-5668: a large file (the 53 MB MITRE bundle) goes up in
        // slices and is assembled server-side, so the client never holds
        // the bind buffer and the socket's write buffer of the whole file
        // next to the verified copy (~194 MiB peak for that bundle).
        if !large.is_empty() {
            sqlx::query(
                "CREATE TEMP TABLE content_file_slices (n integer NOT NULL, part bytea NOT NULL) ON COMMIT DROP",
            )
            .execute(&mut *tx)
            .await?;
        }
        for (path, content) in large {
            for (n, part) in content.chunks(READ_SLICE_BYTES as usize).enumerate() {
                sqlx::query("INSERT INTO content_file_slices (n, part) VALUES ($1, $2)")
                    .bind(n as i32)
                    .bind(part)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query(
                "INSERT INTO content_channel_files (channel, path, blob_sha1, size, content) \
                 SELECT $1, $2, $3, $4, string_agg(part, ''::bytea ORDER BY n) FROM content_file_slices",
            )
            .bind(&d.channel)
            .bind(path.as_str())
            .bind(tree::git_blob_sha1(content))
            .bind(content.len() as i64)
            .execute(&mut *tx)
            .await?;
            let stored: Option<i64> = sqlx::query_scalar(
                "SELECT octet_length(content)::bigint FROM content_channel_files WHERE channel = $1 AND path = $2",
            )
            .bind(&d.channel)
            .bind(path.as_str())
            .fetch_optional(&mut *tx)
            .await?;
            if stored != Some(content.len() as i64) {
                return Err(sqlx::Error::Protocol(format!(
                    "content file {path} stored {stored:?} of {} bytes",
                    content.len()
                )));
            }
            sqlx::query("TRUNCATE content_file_slices").execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(tree_changed)
}

/// Bytes of small-file content per batched UNNEST insert (NAN-5668).
const INSERT_BATCH_BYTES: usize = 8 * 1024 * 1024;

async fn insert_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel: &str,
    batch: &[(&String, &Vec<u8>)],
) -> Result<(), sqlx::Error> {
    let paths: Vec<&str> = batch.iter().map(|(p, _)| p.as_str()).collect();
    let shas: Vec<String> = batch.iter().map(|(_, c)| tree::git_blob_sha1(c)).collect();
    let sizes: Vec<i64> = batch.iter().map(|(_, c)| c.len() as i64).collect();
    let contents: Vec<&[u8]> = batch.iter().map(|(_, c)| c.as_slice()).collect();
    sqlx::query(
        "INSERT INTO content_channel_files (channel, path, blob_sha1, size, content) \
         SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::bigint[], $5::bytea[])",
    )
    .bind(channel)
    .bind(&paths)
    .bind(&shas)
    .bind(&sizes)
    .bind(&contents)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// A file read with a size cap.
#[derive(Debug, PartialEq, Eq)]
pub enum CappedFile {
    Missing,
    /// The stored size, over the cap; nothing was read.
    TooLarge(u64),
    Body(Vec<u8>),
}

/// Slice size for reading and writing large content files (NAN-5668). A
/// whole-row read of the 53 MB MITRE bundle held the DataRow buffer, its
/// `Vec<u8>` decode copy and the connection's grown read buffer at once
/// (~180 MiB peak), and the pooled connection kept the grown buffer
/// afterwards; a whole-file bind on install peaked at ~194 MiB.
pub const READ_SLICE_BYTES: i64 = 1024 * 1024;

/// Multi-statement reads see one snapshot, so an install committing between
/// slices cannot splice two versions of a file together.
const SNAPSHOT_READ: &str = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY";

/// Read one stored file of `size` bytes in [`READ_SLICE_BYTES`] slices into
/// an exactly-sized buffer.
async fn read_sliced(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    channel: &str,
    path: &str,
    size: i64,
) -> Result<Vec<u8>, sqlx::Error> {
    let mut body = Vec::with_capacity(size.max(0) as usize);
    let mut offset: i64 = 0;
    while offset < size {
        let slice: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT substring(content FROM $3::integer FOR $4::integer) FROM content_channel_files WHERE channel = $1 AND path = $2",
        )
        .bind(channel)
        .bind(path)
        .bind(offset + 1)
        .bind(READ_SLICE_BYTES)
        .fetch_optional(&mut **tx)
        .await?;
        let slice = slice.ok_or(sqlx::Error::RowNotFound)?;
        if slice.is_empty() {
            break;
        }
        offset += slice.len() as i64;
        body.extend_from_slice(&slice);
    }
    if body.len() as i64 != size {
        return Err(sqlx::Error::Protocol(format!(
            "content file {path} read {} of {size} bytes",
            body.len()
        )));
    }
    Ok(body)
}

/// Parse a stored descriptor (structure re-validated, signature not
/// re-checked).
pub fn installed_from(stored: Option<&serde_json::Value>) -> Option<SignedContentDescriptor> {
    let signed: SignedContentDescriptor = serde_json::from_value(stored?.clone()).ok()?;
    signed.descriptor.validate().ok()?;
    Some(signed)
}
