// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ingest[T]` over the tenant edge log (NAN-2874): the [`NoticeQueue`] and
//! [`ObjectStore`] adapters over [`EdgeLogSource`], so a lean tenant (no
//! bronze at all) ingests straight from the edge-log Durable Object.
//!
//! - `pending` / `get` map pulled segments to notices and verified bytes;
//! - `range_for_flush` gives the flush's `edge_log` (on the `add` entry and
//!   every L0 record of it);
//! - `ack` after the `add` commits the flush's range to the DO;
//!   `ack_skipped` (segments without rows) makes them skips of the next
//!   range or floor;
//! - `point_due` surfaces the `EdgeFloor` / `EdgeEnd` the source asks for.

use anyhow::{bail, Result};
use async_trait::async_trait;
use std::path::Path;
use std::sync::Arc;

use super::discovery::{AckCounts, NoticeHandle, NoticeQueue, PointRequest, SourceNotice};
use crate::edge_log::{EdgeAck, EdgeLogSource, EdgeLogTransport};
use crate::parts::part_log::ObjectStore;
use crate::parts::provenance::SourceObject;
use crate::parts::EdgeLogRange;

/// The tenant's edge log as ingest[T]'s notice queue.
pub struct EdgeQueue<T: EdgeLogTransport> {
    source: Arc<EdgeLogSource<T>>,
    tenant_id: String,
}

impl<T: EdgeLogTransport> EdgeQueue<T> {
    pub fn new(source: Arc<EdgeLogSource<T>>, tenant_id: &str) -> Self {
        Self { source, tenant_id: tenant_id.to_string() }
    }

    pub fn source(&self) -> &Arc<EdgeLogSource<T>> {
        &self.source
    }
}

#[async_trait]
impl<T: EdgeLogTransport + 'static> NoticeQueue for EdgeQueue<T> {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        Ok(self
            .source
            .pending(max)
            .await?
            .into_iter()
            .map(|n| {
                (
                    NoticeHandle(n.handle),
                    SourceNotice {
                        tenant_id: self.tenant_id.clone(),
                        key: n.key,
                        version: n.version,
                        bytes: n.bytes,
                        sha256: Some(n.sha256),
                        edge_sha256: None,
                        notified_at_ms: n.received_at_ms,
                    },
                )
            })
            .collect())
    }

    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        if handles.is_empty() {
            return Ok(());
        }
        let handles = handles.iter().map(|h| h.0.clone()).collect::<Vec<_>>();
        self.source.ack(&handles).await
    }

    async fn ack_skipped(&self, acks: &[(NoticeHandle, AckCounts)]) -> Result<()> {
        if acks.is_empty() {
            return Ok(());
        }
        let acks = acks
            .iter()
            .map(|(handle, counts)| EdgeAck {
                handle: handle.0.clone(),
                rows: counts.rows,
                rows_rejected: counts.rows_rejected,
                rows_duplicate: counts.rows_duplicate,
            })
            .collect::<Vec<_>>();
        self.source.ack_skipped(&acks).await
    }

    async fn range_for_flush(
        &self,
        sources: &[SourceObject],
        rows_rejected: u64,
        rows_duplicate: u64,
    ) -> Result<Option<EdgeLogRange>> {
        self.source.range_for_flush(sources, rows_rejected, rows_duplicate).await
    }

    fn max_outstanding_ranges(&self) -> usize {
        self.source.max_issued_ranges()
    }

    async fn point_due(&self, now_ms: i64) -> Result<Option<PointRequest>> {
        if let Some(floor) = self.source.floor_due(now_ms).await {
            return Ok(Some(PointRequest { op: floor.floor_op(), end: false, request: floor }));
        }
        // `end_due` pulls from the DO; only ask once a pull reported `drain`
        // (every `pending` pull refreshes the mode).
        if self.source.mode().await != "drain" {
            return Ok(None);
        }
        Ok(self.source.end_due().await?.map(|end| PointRequest { op: end.end_op(), end: true, request: end }))
    }

    async fn point_appended(&self, point: &PointRequest) -> Result<()> {
        if point.end {
            self.source.end_appended(&point.request).await
        } else {
            self.source.floor_appended(&point.request).await
        }
    }
}

/// Pulled segment bytes as ingest[T]'s source object store (read-only).
pub struct EdgeSegments<T: EdgeLogTransport> {
    source: Arc<EdgeLogSource<T>>,
}

impl<T: EdgeLogTransport> EdgeSegments<T> {
    pub fn new(source: Arc<EdgeLogSource<T>>) -> Self {
        Self { source }
    }
}

#[async_trait]
impl<T: EdgeLogTransport + 'static> ObjectStore for EdgeSegments<T> {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.source.get(key).await)
    }

    async fn get_to_file(&self, key: &str, path: &Path) -> Result<bool> {
        match self.source.get(key).await {
            Some(bytes) => {
                std::fs::write(path, bytes)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn put_if_absent(&self, _key: &str, _bytes: &[u8]) -> Result<bool> {
        bail!("edge segments are read-only")
    }

    async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
        bail!("edge segments are read-only")
    }

    async fn delete(&self, _key: &str) -> Result<()> {
        bail!("edge segments are read-only")
    }

    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        bail!("edge segments are never listed")
    }
}
