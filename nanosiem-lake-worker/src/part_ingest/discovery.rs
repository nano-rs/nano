// SPDX-License-Identifier: AGPL-3.0-or-later

//! DO-notified discovery (no LIST loops).
//!
//! The raw-handoff Durable Object already knows every object it hands to the
//! tenant's Vector lane. It (through the cell supervisor, phase 5) delivers
//! one [`SourceNotice`] per parsed bronze object into the tenant's local
//! spool directory; `ingest[T]` consumes the spool and deletes a notice only
//! after the log entry that consumed its object committed. Delivery is
//! at-least-once; the uid window makes replays exactly-once.
//!
//! Reading a local spool directory is a local `readdir`, not an R2 LIST: the
//! bucket is never listed on the ingest path.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One "new object for tenant T" notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceNotice {
    pub tenant_id: String,
    /// Bronze object key in the tenant bucket.
    pub key: String,
    /// Object version / etag the notifier saw.
    pub version: String,
    pub bytes: u64,
    /// SHA-256 of the object when the notifier knows it; verified on fetch.
    pub sha256: Option<String>,
    /// SHA-256 of the raw edge object this bronze object was parsed from.
    pub edge_sha256: Option<String>,
    pub notified_at_ms: i64,
}

/// An opaque handle to a delivered notice.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NoticeHandle(pub String);

/// Row counts of a notice acknowledged without an `add` (refused whole,
/// every row a duplicate, a crash replay, or missing): `rows =
/// rows_rejected + rows_duplicate`. Edge sources record them as a `skipped`
/// item of the next range or floor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AckCounts {
    pub rows: u64,
    pub rows_rejected: u64,
    pub rows_duplicate: u64,
}

/// A part-log op the queue needs appended before it can move on
/// (`EdgeFloor` / `EdgeEnd`).
#[derive(Debug, Clone)]
pub struct PointRequest {
    pub op: crate::parts::part_log::LogOp,
    pub end: bool,
    pub request: crate::edge_log::EdgePointRequest,
}

#[async_trait]
pub trait NoticeQueue: Send + Sync {
    /// Up to `max` undelivered-or-unacked notices, oldest first.
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>>;
    /// Remove notices whose objects are durably consumed: their rows are in
    /// the flush's `add` entry (for an edge source, this commits the flush's
    /// issued range).
    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()>;
    /// Acknowledge notices without an `add` (see [`AckCounts`]). Called
    /// after their `reject` entries and before the flush's range is issued.
    /// Default: plain acks.
    async fn ack_skipped(&self, acks: &[(NoticeHandle, AckCounts)]) -> Result<()> {
        if acks.is_empty() {
            return Ok(());
        }
        let handles = acks.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>();
        self.ack(&handles).await
    }
    /// The flush's `edge_log` range (edge sources only).
    async fn range_for_flush(
        &self,
        _sources: &[crate::parts::provenance::SourceObject],
        _rows_rejected: u64,
        _rows_duplicate: u64,
    ) -> Result<Option<crate::parts::EdgeLogRange>> {
        Ok(None)
    }
    /// Flushes whose ranges may be issued and not yet acknowledged at once
    /// (NAN-3619). Ingest never keeps more flushes in flight than this.
    /// Default 1: a range is issued only after the previous flush's ack.
    fn max_outstanding_ranges(&self) -> usize {
        1
    }
    /// An op ingest must append now (edge floor / end), if any.
    async fn point_due(&self, _now_ms: i64) -> Result<Option<PointRequest>> {
        Ok(None)
    }
    async fn point_appended(&self, _point: &PointRequest) -> Result<()> {
        Ok(())
    }
}

/// A directory spool: `{notified_at_ms:013}-{id}.json`, written atomically
/// (temp + rename) by the notifier.
#[derive(Debug, Clone)]
pub struct SpoolQueue {
    dir: PathBuf,
    tenant_id: String,
}

impl SpoolQueue {
    pub fn new(dir: impl AsRef<Path>, tenant_id: &str) -> Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
        Ok(Self { dir: dir.as_ref().to_path_buf(), tenant_id: tenant_id.to_string() })
    }

    /// Notifier side (used by the supervisor and by tests).
    pub fn deliver(&self, notice: &SourceNotice) -> Result<NoticeHandle> {
        if notice.tenant_id != self.tenant_id {
            bail!("notice belongs to another tenant");
        }
        let name = format!("{:013}-{}.json", notice.notified_at_ms.max(0), uuid::Uuid::new_v4().simple());
        let temp = self.dir.join(format!(".tmp-{name}"));
        std::fs::write(&temp, serde_json::to_vec(notice)?)?;
        std::fs::rename(&temp, self.dir.join(&name))?;
        Ok(NoticeHandle(name))
    }
}

#[async_trait]
impl NoticeQueue for SpoolQueue {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let mut names = std::fs::read_dir(&self.dir)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".json") && !name.starts_with('.'))
            .collect::<Vec<_>>();
        names.sort();
        let mut out = Vec::new();
        for name in names.into_iter().take(max) {
            let bytes = match std::fs::read(self.dir.join(&name)) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            let notice: SourceNotice =
                serde_json::from_slice(&bytes).with_context(|| format!("spool notice {name} does not parse"))?;
            if notice.tenant_id != self.tenant_id {
                bail!("spool holds a notice for another tenant");
            }
            out.push((NoticeHandle(name), notice));
        }
        Ok(out)
    }

    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        for handle in handles {
            if handle.0.contains('/') {
                bail!("notice handle is invalid");
            }
            match std::fs::remove_file(self.dir.join(&handle.0)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
