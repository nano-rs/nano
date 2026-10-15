// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity directory reads for query[T] (NAN-3500). Each request pins the
//! tenant's current identity manifest; the merged view is cached per
//! revision so repeated reads do not re-merge. The store is the tenant's
//! read-only enrichment prefix (`enrichment_reader` credential).

use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use crate::lean_identity_snapshot::{IdentityStore, IdentityView, ListFilter};
use crate::parts::part_log::ObjectStore;

const MAX_PAGE: usize = 1000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    pub tenant_id: String,
    #[serde(default)]
    pub filter: ListFilter,
    #[serde(default)]
    pub offset: usize,
    pub limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupRequest {
    pub tenant_id: String,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsRequest {
    pub tenant_id: String,
}

type CachedView = Option<(Uuid, Uuid, Arc<IdentityView>)>;

fn cache() -> &'static tokio::sync::Mutex<CachedView> {
    static CACHE: OnceLock<tokio::sync::Mutex<CachedView>> = OnceLock::new();
    CACHE.get_or_init(|| tokio::sync::Mutex::new(None))
}

fn bind(tenant: Uuid, body_tenant: &str) -> Result<()> {
    ensure!(
        !tenant.is_nil() && body_tenant == tenant.to_string(),
        "identity request tenant differs from process tenant"
    );
    Ok(())
}

/// The current merged view, or `None` when the tenant has no directory yet.
async fn current_view(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
) -> Result<Option<Arc<IdentityView>>> {
    let store = IdentityStore::new(tenant, objects, scratch)?;
    let Some(manifest) = store.current().await? else {
        return Ok(None);
    };
    let mut cached = cache().lock().await;
    if let Some((cached_tenant, revision, view)) = cached.as_ref() {
        if *cached_tenant == tenant && *revision == manifest.revision {
            return Ok(Some(view.clone()));
        }
    }
    let view = Arc::new(store.load_view(&manifest).await?);
    *cached = Some((tenant, manifest.revision, view.clone()));
    Ok(Some(view))
}

fn envelope(tenant: Uuid, view: Option<&IdentityView>, result: Value) -> Value {
    json!({
        "ok": true,
        "schema_version": 1,
        "tenant_id": tenant.to_string(),
        "revision": view.map(|v| v.revision().to_string()),
        "result": result,
    })
}

pub async fn list(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: ListRequest,
) -> Result<Value> {
    bind(tenant, &request.tenant_id)?;
    ensure!(
        request.limit > 0 && request.limit <= MAX_PAGE,
        "identity page size is invalid"
    );
    if let Some(search) = &request.filter.search {
        ensure!(
            search.len() <= 256 && !search.chars().any(char::is_control),
            "identity search is invalid"
        );
    }
    let Some(view) = current_view(objects, scratch, tenant).await? else {
        return Ok(envelope(tenant, None, json!({"total": 0, "users": []})));
    };
    let (total, users) = view.list(&request.filter, request.offset, request.limit)?;
    Ok(envelope(
        tenant,
        Some(&view),
        json!({"total": total, "users": users}),
    ))
}

pub async fn lookup(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: LookupRequest,
) -> Result<Value> {
    bind(tenant, &request.tenant_id)?;
    ensure!(
        !request.value.trim().is_empty()
            && request.value.len() <= 1024
            && !request.value.chars().any(char::is_control),
        "identity lookup value is invalid"
    );
    let Some(view) = current_view(objects, scratch, tenant).await? else {
        return Ok(envelope(tenant, None, json!({"rows": []})));
    };
    let rows = view.lookup(&request.value)?;
    Ok(envelope(tenant, Some(&view), json!({"rows": rows})))
}

pub async fn stats(
    objects: &dyn ObjectStore,
    scratch: &Path,
    tenant: Uuid,
    request: StatsRequest,
) -> Result<Value> {
    bind(tenant, &request.tenant_id)?;
    let Some(view) = current_view(objects, scratch, tenant).await? else {
        return Ok(envelope(tenant, None, json!({"total": 0})));
    };
    Ok(envelope(
        tenant,
        Some(&view),
        serde_json::to_value(view.stats())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lean_identity_snapshot::{IdentityRow, SourceKind};
    use crate::parts::part_log::LocalObjectStore;

    #[tokio::test]
    async fn reads_are_bound_to_the_process_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let objects = LocalObjectStore::new(dir.path().join("r2")).unwrap();
        let tenant = Uuid::new_v4();
        let scratch = dir.path().join("q");
        let empty = list(
            &objects,
            &scratch,
            tenant,
            ListRequest {
                tenant_id: tenant.to_string(),
                filter: ListFilter::default(),
                offset: 0,
                limit: 10,
            },
        )
        .await
        .unwrap();
        assert_eq!(empty["result"]["total"], 0);

        let writer = IdentityStore::new(tenant, &objects, &dir.path().join("w")).unwrap();
        let mut row = IdentityRow::new("okta", "a", SourceKind::Pull, 1);
        row.email = "a@example.com".into();
        writer.append_delta(None, vec![row]).await.unwrap();

        let found = lookup(
            &objects,
            &scratch,
            tenant,
            LookupRequest {
                tenant_id: tenant.to_string(),
                value: "A@EXAMPLE.COM".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(found["result"]["rows"].as_array().unwrap().len(), 1);
        let counted = stats(
            &objects,
            &scratch,
            tenant,
            StatsRequest {
                tenant_id: tenant.to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(counted["result"]["total"], 1);

        // Another tenant named in the body is refused before any read.
        let other = Uuid::new_v4();
        assert!(lookup(
            &objects,
            &scratch,
            tenant,
            LookupRequest {
                tenant_id: other.to_string(),
                value: "a@example.com".into(),
            }
        )
        .await
        .is_err());
        // A process bound to another tenant refuses this tenant's manifest.
        assert!(stats(
            &objects,
            &dir.path().join("q2"),
            other,
            StatsRequest {
                tenant_id: other.to_string()
            }
        )
        .await
        .is_err());
        assert!(list(
            &objects,
            &scratch,
            tenant,
            ListRequest {
                tenant_id: tenant.to_string(),
                filter: ListFilter::default(),
                offset: 0,
                limit: MAX_PAGE + 1,
            }
        )
        .await
        .is_err());
    }
}
