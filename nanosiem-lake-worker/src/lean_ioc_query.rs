// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tenant-pinned IOC reads for query[T]. Each request pins the durable current
//! pointer and verifies its immutable revision before returning a result.
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;

use crate::lean_enrichment_snapshot::LeanEnrichmentSnapshots;
use crate::parts::part_log::ObjectStore;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub snapshot_id: String,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub snapshot_id: String,
    #[serde(default)]
    pub feeds: Vec<String>,
    #[serde(default)]
    pub feed_name_contains: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub artifact_types: Vec<String>,
    #[serde(default)]
    pub cursor_published_at_ms: Option<i64>,
    #[serde(default)]
    pub cursor_value: Option<String>,
    pub limit: usize,
    #[serde(default)]
    pub count_only: bool,
}

fn binding(tenant: Uuid, request_id: &str, body_tenant: &str, snapshot_id: &str) -> Result<()> {
    ensure!(
        !tenant.is_nil() && body_tenant == tenant.to_string(),
        "IOC request tenant differs from process tenant"
    );
    ensure!(
        !request_id.is_empty()
            && request_id.len() <= 128
            && request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "invalid IOC request id"
    );
    ensure!(
        snapshot_id == format!("ioc-{tenant}-current"),
        "IOC pointer is not assigned to this tenant"
    );
    Ok(())
}

pub async fn lookup(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: LookupRequest,
) -> Result<Value> {
    binding(
        tenant,
        &request.request_id,
        &request.tenant_id,
        &request.snapshot_id,
    )?;
    ensure!(
        !request.value.trim().is_empty()
            && request.value.len() <= 4096
            && !request.value.chars().any(char::is_control),
        "invalid IOC value"
    );
    let store = LeanEnrichmentSnapshots::new(tenant, objects, scratch)?;
    let pointer = store
        .current()
        .await?
        .ok_or_else(|| anyhow::anyhow!("tenant IOC pointer is absent"))?;
    let snapshot = store.load(&pointer).await?;
    let results = snapshot.lookup_all(&request.value);
    // NAN-3881: the tenant's own indicator sources searched, so a miss can
    // say "no matches in N sources". Additive; older readers ignore it.
    let sources = snapshot.ioc_sources();
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
        "snapshot_version": pointer.sha256, "value": request.value,
        "budget": {"decision":"allow", "estimated_scan_bytes":0,
                   "resident_snapshot_bytes":pointer.bytes,
                   "estimate_kind":"resident-immutable-ioc-snapshot"},
        "results": results, "sources": sources, "wall_seconds": 0.0
    }))
}

pub async fn source_records(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: SourceRequest,
) -> Result<Value> {
    binding(
        tenant,
        &request.request_id,
        &request.tenant_id,
        &request.snapshot_id,
    )?;
    let valid_text = |value: &String| {
        !value.trim().is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
    };
    ensure!(
        request.feeds.len() <= 1024
            && request.feed_name_contains.len() <= 1024
            && request.tags.len() <= 1024
            && request.artifact_types.len() <= 64,
        "IOC filters exceed limits"
    );
    ensure!(
        request
            .feeds
            .iter()
            .chain(&request.feed_name_contains)
            .chain(&request.tags)
            .chain(&request.artifact_types)
            .all(valid_text),
        "invalid IOC filter"
    );
    ensure!(
        (1..=100_000).contains(&request.limit)
            && request.cursor_published_at_ms.is_some() == request.cursor_value.is_some(),
        "invalid IOC page or cursor"
    );
    ensure!(
        request.cursor_published_at_ms.is_none_or(|ms| ms >= 0)
            && request.cursor_value.as_ref().is_none_or(valid_text),
        "invalid IOC cursor"
    );
    let store = LeanEnrichmentSnapshots::new(tenant, objects, scratch)?;
    let pointer = store
        .current()
        .await?
        .ok_or_else(|| anyhow::anyhow!("tenant IOC pointer is absent"))?;
    let snapshot = store.load(&pointer).await?;
    let cursor = request
        .cursor_published_at_ms
        .zip(request.cursor_value.as_deref());
    let count = snapshot.source_record_count(
        &request.feeds,
        &request.feed_name_contains,
        &request.tags,
        &request.artifact_types,
        cursor,
    );
    let records = if request.count_only {
        Vec::new()
    } else {
        snapshot.source_records(
            &request.feeds,
            &request.feed_name_contains,
            &request.tags,
            &request.artifact_types,
            cursor,
            request.limit,
        )
    };
    Ok(json!({
        "ok": true, "schema_version": 1, "request_id": request.request_id,
        "tenant_id": request.tenant_id, "snapshot_id": request.snapshot_id,
        "snapshot_version": pointer.sha256, "count": count, "records": records,
        "budget": {"decision":"allow", "estimated_scan_bytes":0,
                   "resident_snapshot_bytes":pointer.bytes,
                   "estimate_kind":"resident-immutable-ioc-snapshot"},
        "wall_seconds": 0.0
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{enrichment::IocSnapshotInput, parts::part_log::LocalObjectStore};

    #[tokio::test]
    async fn current_revision_replays_and_other_tenant_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let objects = LocalObjectStore::new(dir.path().join("objects")).unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let store = LeanEnrichmentSnapshots::new(a, &objects, &dir.path().join("publish")).unwrap();
        store
            .publish(&[IocSnapshotInput {
                ioc_value: "8.8.8.8".into(),
                ioc_type: "ip".into(),
                source_id: "feed".into(),
                ..Default::default()
            }])
            .await
            .unwrap();
        let request = || LookupRequest {
            request_id: "request1".into(),
            tenant_id: a.to_string(),
            snapshot_id: format!("ioc-{a}-current"),
            value: "8.8.8.8".into(),
        };
        let first = lookup(&objects, &dir.path().join("query"), a, request())
            .await
            .unwrap();
        assert_eq!(first["results"].as_array().unwrap().len(), 1);
        let replay = lookup(&objects, &dir.path().join("restart"), a, request())
            .await
            .unwrap();
        assert_eq!(first["snapshot_version"], replay["snapshot_version"]);
        assert_eq!(first["sources"], json!(["feed"]));
        assert!(lookup(&objects, &dir.path().join("other"), b, request())
            .await
            .is_err());
        // NAN-3881: tenant B publishes its own indicator for the same value
        // under its own feed, in its own tenant-scoped object store (the
        // snapshot pointer key is per kind, so each tenant has its own
        // store, as in production). Tenant A's lookup never returns B's
        // verdict or lists B's source, and B's process never answers for A.
        let b_objects = LocalObjectStore::new(dir.path().join("objects-b")).unwrap();
        let b_store =
            LeanEnrichmentSnapshots::new(b, &b_objects, &dir.path().join("publish-b")).unwrap();
        b_store
            .publish(&[
                IocSnapshotInput {
                    ioc_value: "8.8.8.8".into(),
                    ioc_type: "ip".into(),
                    source_id: "b-private-feed".into(),
                    enrichment_name: "B private feed".into(),
                    is_ioc: true,
                    ..Default::default()
                },
                IocSnapshotInput {
                    ioc_value: "203.0.113.9".into(),
                    ioc_type: "ip".into(),
                    source_id: "b-private-feed".into(),
                    enrichment_name: "B private feed".into(),
                    is_ioc: true,
                    ..Default::default()
                },
            ])
            .await
            .unwrap();
        let a_after = lookup(&objects, &dir.path().join("query-a2"), a, request())
            .await
            .unwrap();
        assert_eq!(a_after["sources"], json!(["feed"]));
        let a_results = a_after["results"].as_array().unwrap();
        assert_eq!(a_results.len(), 1);
        assert!(a_results.iter().all(|r| r["source_id"] != "B private feed"));
        let b_only = LookupRequest { value: "203.0.113.9".into(), ..request() };
        let a_miss = lookup(&objects, &dir.path().join("query-a3"), a, b_only)
            .await
            .unwrap();
        assert!(a_miss["results"].as_array().unwrap().is_empty());
        // Tenant A's request (A's tenant id and pointer) on tenant B's process
        // is refused by the binding, not answered from B's snapshot.
        assert!(lookup(&b_objects, &dir.path().join("other-b"), b, request())
            .await
            .is_err());
        let page = SourceRequest {
            request_id: "page1".into(),
            tenant_id: a.to_string(),
            snapshot_id: format!("ioc-{a}-current"),
            feeds: vec!["feed".into()],
            feed_name_contains: vec![],
            tags: vec![],
            artifact_types: vec!["ip".into()],
            cursor_published_at_ms: None,
            cursor_value: None,
            limit: 10,
            count_only: false,
        };
        let records = source_records(&objects, &dir.path().join("restart"), a, page)
            .await
            .unwrap();
        assert_eq!(records["count"], 1);
        assert_eq!(records["records"][0]["value"], "8.8.8.8");
    }
}
