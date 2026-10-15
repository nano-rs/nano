// SPDX-License-Identifier: AGPL-3.0-or-later

//! RustFS bronze retention follows the listing queue's durable consumed
//! watermark. Never delete an unconsumed upload or infer consumption from age.

use crate::{part_ingest::s3_store::S3ObjectStore, parts::part_log::ObjectStore};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, path::PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    kind: String,
    tenant_id: String,
    prefix: String,
    watermark: Option<String>,
    acked: BTreeMap<String, i64>,
}

pub struct LocalBronzeRetention {
    store: &'static S3ObjectStore,
    tenant: String,
    state: PathBuf,
}

impl LocalBronzeRetention {
    pub fn new(store: &'static S3ObjectStore, tenant: &str, state: PathBuf) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(tenant)?;
        ensure!(
            state.is_absolute(),
            "bronze retention cursor must be absolute"
        );
        Ok(Self {
            store,
            tenant: tenant.into(),
            state,
        })
    }

    pub async fn collect(&self, retention_days: Option<u64>, now_ms: i64) -> Result<usize> {
        let Some(days) = retention_days else {
            return Ok(0);
        };
        ensure!((1..=3650).contains(&days), "invalid local bronze retention");
        // A missing cursor means the queue has not durably consumed anything.
        let file = match std::fs::File::open(&self.state) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            file.metadata()?.len() <= 64 * 1024 * 1024,
            "bronze cursor is too large"
        );
        let cursor: Cursor = serde_json::from_reader(file).context("read durable bronze cursor")?;
        let prefix = format!("tenant_id={}/", self.tenant);
        ensure!(
            cursor.kind == "nano.lake.bronze-list-cursor.v1"
                && cursor.tenant_id == self.tenant
                && cursor.prefix == prefix,
            "bronze cursor is for another storage scope"
        );
        let Some(watermark) = cursor.watermark else {
            return Ok(0);
        };
        ensure!(
            watermark.starts_with(&prefix)
                && !watermark.contains("..")
                && cursor
                    .acked
                    .keys()
                    .all(|key| key.starts_with(&prefix) && key > &watermark),
            "invalid bronze watermark"
        );
        let cutoff = now_ms.saturating_sub((days as i64).saturating_mul(86_400_000));
        let mut deleted = 0;
        // Bound each pass and preserve lexicographic progression by deleting
        // eligible keys. Object identity is immutable on this trusted-local store.
        let keys = self
            .store
            .list_local_gc_candidates(&prefix, |key| eligible(key, &prefix, &watermark, cutoff))
            .await?;
        for key in keys {
            self.store.delete(&key).await?;
            deleted += 1;
        }
        Ok(deleted)
    }
}

fn eligible(key: &str, prefix: &str, watermark: &str, cutoff: i64) -> bool {
    if !key.starts_with(prefix)
        || key > watermark
        || key.contains("..")
        || !key.ends_with(".parquet")
    {
        return false;
    }
    let Some((stamp, _)) = key.rsplit('/').next().and_then(|name| name.split_once('-')) else {
        return false;
    };
    if !stamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let Some(value) = stamp.parse::<i64>().ok() else {
        return false;
    };
    let time = match stamp.len() {
        10 => value.checked_mul(1000),
        13 => Some(value),
        16 => Some(value / 1000),
        _ => None,
    };
    time.is_some_and(|time| time < cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rustfs_delete_waits_for_the_durable_consumption_watermark() {
        use axum::{
            http::{Method, StatusCode, Uri},
            response::IntoResponse,
            Router,
        };
        use std::sync::{Arc, Mutex};
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let prefix = format!("tenant_id={tenant}/");
        let consumed = format!("{prefix}logs/1700000000-a.parquet");
        let pending = format!("{prefix}logs/1700000001-b.parquet");
        let objects = Arc::new(Mutex::new(std::collections::BTreeSet::from([
            consumed.clone(),
            pending.clone(),
        ])));
        let state = objects.clone();
        let app = Router::new().fallback(move |method: Method, uri: Uri, body: axum::body::Bytes| {
            let state = state.clone();
            async move {
                if method == Method::POST {
                    let body = std::str::from_utf8(&body).unwrap();
                    for key in body.split("<Key>").skip(1).map(|part| part.split("</Key>").next().unwrap()) {
                        state.lock().unwrap().remove(key.strip_prefix("bronze-v2/").unwrap());
                    }
                    return (StatusCode::OK, [("content-type", "application/xml")], "<DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></DeleteResult>").into_response();
                }
                if method == Method::DELETE {
                    // OpenDAL percent-encodes the '=' in our closed UUID fixture keys.
                    let key = uri.path().strip_prefix("/nano-lake/bronze-v2/").unwrap().replace("%3D", "=");
                    assert!(state.lock().unwrap().remove(&key), "unexpected DELETE fixture key: {key}");
                    return (StatusCode::NO_CONTENT, String::new()).into_response();
                }
                let contents = state.lock().unwrap().iter().map(|key| format!("<Contents><Key>bronze-v2/{key}</Key><Size>10</Size><ETag>e</ETag><LastModified>2023-11-14T00:00:00Z</LastModified></Contents>")).collect::<String>();
                (StatusCode::OK, [("content-type", "application/xml")], format!("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>nano-lake</Name><IsTruncated>false</IsTruncated>{contents}</ListBucketResult>")).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Box::leak(Box::new(
            S3ObjectStore::new(&crate::part_ingest::s3_store::S3Location {
                endpoint,
                region: "us-east-1".into(),
                bucket: "nano-lake".into(),
                prefix: "bronze-v2".into(),
                access_key_id: "test".into(),
                secret_access_key: "test".into(),
                session_token: None,
            })
            .unwrap(),
        ));
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("bronze-list-cursor.json");
        let gc = LocalBronzeRetention::new(store, tenant, state_path.clone()).unwrap();
        assert_eq!(gc.collect(Some(7), 1_800_000_000_000).await.unwrap(), 0);
        std::fs::write(&state_path, serde_json::to_vec(&serde_json::json!({"kind":"nano.lake.bronze-list-cursor.v1", "tenant_id":tenant, "prefix":prefix, "watermark":consumed, "acked":{}})).unwrap()).unwrap();
        assert_eq!(gc.collect(Some(7), 1_800_000_000_000).await.unwrap(), 1);
        assert_eq!(
            *objects.lock().unwrap(),
            std::collections::BTreeSet::from([pending])
        );
        std::fs::write(&state_path, b"broken cursor").unwrap();
        assert!(gc.collect(Some(7), 1_800_000_000_000).await.is_err());
        server.abort();
    }

    #[test]
    fn only_expired_consumed_bronze_is_eligible() {
        let p = "tenant_id=tenant/";
        let old = "tenant_id=tenant/logs/1700000000-a.parquet";
        assert!(eligible(old, p, old, 1_800_000_000_000));
        assert!(!eligible(
            old,
            p,
            "tenant_id=tenant/logs/1600000000-a.parquet",
            1_800_000_000_000
        ));
        assert!(!eligible(old, "tenant_id=other/", old, 1_800_000_000_000));
        assert!(!eligible(old, p, old, 1_600_000_000_000));
        assert!(!eligible(
            "tenant_id=tenant/../1700000000-a.parquet",
            p,
            old,
            1_800_000_000_000
        ));
    }
}
