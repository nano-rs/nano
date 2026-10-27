// SPDX-License-Identifier: AGPL-3.0-or-later
//! Loopback REST + S3 transport. The client, expiry updates, reload validation,
//! manifest reads and guarded metadata purge are the production implementation.
use super::*;
use crate::part_ingest::iceberg_export::{
    hosted::{HostedCatalogPolicy, HostedExportTarget},
    lifecycle::{
        metadata::{MetadataDeleteAuthority, MetadataDeleteRequest, MetadataGc},
        CatalogLifecycleBackend, CatalogReadFence, RestLifecycleBackend,
    },
};
use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
use anyhow::Context;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, Response, StatusCode},
    routing::any,
    Router,
};
use iceberg::{io::FileIO, spec::Datum};
use std::sync::Mutex;

struct Wire {
    tenant: String,
    prefix: String,
    table: Table,
    before_expiry: Table,
    objects: HashMap<String, Vec<u8>>,
    events: Vec<&'static str>,
    fail_commit: bool,
    stale_reload: bool,
    fail_delete: bool,
    expected_control: Option<String>,
    rest_auth_seen: usize,
    config_override: Option<String>,
    rest_uri: String,
    commit_fixtures: Vec<serde_json::Value>,
    /// NAN-4662: answer every request for the table with this status.
    table_status: Option<u16>,
}
struct Authority(Arc<Mutex<Wire>>, String, String);
#[async_trait::async_trait]
impl MetadataDeleteAuthority for Authority {
    fn tenant_id(&self) -> &str {
        &self.1
    }
    fn metadata_prefix(&self) -> &str {
        &self.2
    }
    async fn inventory(&self) -> Result<Vec<String>> {
        let state = self.0.lock().unwrap();
        Ok(state
            .objects
            .keys()
            .filter(|p| p.starts_with(&state.prefix))
            .cloned()
            .collect())
    }
    async fn retire(&self, request: &MetadataDeleteRequest) -> Result<MetadataDeleteRequest> {
        let mut state = self.0.lock().unwrap();
        ensure!(!state.fail_delete, "metadata delete unavailable");
        ensure!(
            request.tenant_id == state.tenant
                && request.metadata_prefix == state.prefix
                && request.current_metadata == state.table.metadata_location().unwrap()
                && request.table_uuid == state.table.metadata().uuid()
                && request.key != request.current_metadata,
            "metadata ownership mismatch"
        );
        state
            .objects
            .remove(&request.key)
            .context("metadata object absent")?;
        state.events.push("delete");
        Ok(request.clone())
    }
}
struct Controls;
#[async_trait::async_trait]
impl HostedCatalogPolicy for Controls {
    async fn verify_manual_maintenance(&self, _: &iceberg::TableIdent) -> Result<()> {
        Ok(())
    }
}
#[async_trait::async_trait]
impl CatalogReadFence for Controls {
    fn tenant_id(&self) -> &str {
        TENANT_ID
    }
    fn bucket(&self) -> &str {
        "nano-shared-r2-00000000-0000-0000-0000-000000000001"
    }
    async fn close_and_drain(&self) -> Result<()> {
        Ok(())
    }
    async fn invalidate_results(&self) -> Result<()> {
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        Ok(())
    }
}
fn changed(table: &Table, updates: Vec<TableUpdate>) -> Table {
    let mut builder = table
        .metadata()
        .clone()
        .into_builder(table.metadata_location().map(str::to_string));
    for update in updates {
        builder = update.apply(builder).unwrap();
    }
    let metadata = builder.build().unwrap().metadata;
    let location = format!(
        "{}/metadata/{}.metadata.json",
        metadata.location(),
        uuid::Uuid::new_v4()
    );
    Table::builder()
        .metadata(metadata)
        .identifier(table.identifier().clone())
        .file_io(table.file_io().clone())
        .runtime(iceberg::Runtime::current())
        .metadata_location(location)
        .build()
        .unwrap()
}
async fn handler(State(state): State<Arc<Mutex<Wire>>>, request: Request<Body>) -> Response<Body> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let range = request
        .headers()
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = to_bytes(request.into_body(), 2_000_000).await.unwrap();
    let mut state = state.lock().unwrap();
    if let Some(expected) = &state.expected_control {
        if path.starts_with("/v1/") {
            assert_eq!(authorization, format!("Bearer {expected}"));
            state.rest_auth_seen += 1;
        } else {
            assert!(
                !authorization.contains(expected),
                "control capability leaked to object storage"
            );
        }
    }
    if path == "/v1/config" {
        if let Some(uri) = &state.config_override {
            return json(serde_json::json!({"defaults":{},"overrides":{"uri":uri}}));
        }
        return json(serde_json::json!({"defaults":{},"overrides":{}}));
    }
    if path == "/v1/namespaces/nano/tables/events_v1"
        || path == "/v1/namespaces/agent/tables/events_v1"
    {
        if let Some(status) = state.table_status {
            return Response::builder().status(status).header("content-type", "application/json")
                .body(Body::from(r#"{"error":{"message":"fixture","type":"AgentCatalogRefused","code":0}}"#)).unwrap();
        }
        if method == "POST" {
            state.events.push("commit");
            if state.fail_commit {
                return Response::builder().status(409).body(Body::from(r#"{"error":{"message":"fixture conflict","type":"CommitFailedException","code":409}}"#)).unwrap();
            }
            let request: iceberg_catalog_rest::CommitTableRequest =
                serde_json::from_slice(&body).unwrap();
            for requirement in request.requirements {
                requirement.check(Some(state.table.metadata())).unwrap();
            }
            state.table = changed(&state.table, request.updates);
            let key = state.table.metadata_location().unwrap().to_string();
            let bytes = serde_json::to_vec(state.table.metadata()).unwrap();
            state.objects.insert(key, bytes);
        } else {
            state.events.push("load");
        }
        let table = if state.stale_reload && state.events.contains(&"commit") && method == "GET" {
            &state.before_expiry
        } else {
            &state.table
        };
        return json(
            serde_json::json!({"metadata-location":table.metadata_location().unwrap(), "metadata":table.metadata(), "config":{}}),
        );
    }
    // The S3 client percent-encodes the fixed tenant= segment on the wire.
    let uri = format!("s3:/{}", path.replace("%3D", "="));
    let Some(bytes) = state.objects.get(&uri).cloned() else {
        return Response::builder().status(404).body(Body::empty()).unwrap();
    };
    state.events.push("s3-read");
    let mut response = Response::builder()
        .header("last-modified", "Thu, 01 Jan 2026 00:00:00 GMT")
        .header("etag", "\"fixture\"")
        .header("accept-ranges", "bytes");
    let mut selected = bytes.clone();
    if let Some(range) = range.and_then(|r| r.strip_prefix("bytes=").map(str::to_string)) {
        let (start, end) = range.split_once('-').unwrap();
        let start = start.parse::<usize>().unwrap();
        let end = if end.is_empty() {
            bytes.len() - 1
        } else {
            end.parse::<usize>().unwrap().min(bytes.len() - 1)
        };
        selected = bytes[start..=end].to_vec();
        response = response.status(StatusCode::PARTIAL_CONTENT).header(
            "content-range",
            format!("bytes {start}-{end}/{}", bytes.len()),
        );
    }
    response
        .header("content-length", selected.len())
        .body(if method == "HEAD" {
            Body::empty()
        } else {
            Body::from(selected)
        })
        .unwrap()
}
fn json(value: serde_json::Value) -> Response<Body> {
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&value).unwrap()))
        .unwrap()
}
struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn setup() -> (
    tempfile::TempDir,
    Server,
    RestLifecycleBackend,
    Arc<Mutex<Wire>>,
) {
    setup_mode(false).await
}
async fn setup_mode(
    platform: bool,
) -> (
    tempfile::TempDir,
    Server,
    RestLifecycleBackend,
    Arc<Mutex<Wire>>,
) {
    let (dir, _catalog, table) = fixture().await;
    let bucket = crate::lake_part_gc::request::tenant_bucket(TENANT_ID);
    let location = if platform {
        format!("s3://{bucket}/__r2_data_catalog/agent/v2/tenant={TENANT_ID}/agent/events_v1")
    } else {
        format!(
            "s3://{bucket}/{}/nano/events_v1",
            crate::parts::format::iceberg_export_prefix(TENANT_ID).unwrap()
        )
    };
    let metadata = table
        .metadata()
        .clone()
        .into_builder(None)
        .set_location(location.clone())
        .build()
        .unwrap()
        .metadata;
    let mut table = Table::builder()
        .metadata(metadata)
        .identifier(
            iceberg::TableIdent::from_strs([if platform { "agent" } else { "nano" }, "events_v1"])
                .unwrap(),
        )
        .file_io(FileIO::new_with_memory())
        .runtime(iceberg::Runtime::current())
        .metadata_location(format!("{location}/metadata/initial.metadata.json"))
        .build()
        .unwrap();
    let signer = LocalPartSigner::new(
        "lab-signer-nan4380",
        ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    )
    .unwrap();
    let target = Arc::new(
        HostedExportTarget::new(
            TENANT_ID.into(),
            Arc::new(LocalObjectStore::new(dir.path().join("parts")).unwrap()),
            signer.trusted(),
            bucket,
        )
        .unwrap(),
    );
    let data_prefix = target.data_prefix();
    let mut objects = HashMap::from([(
        table.metadata_location().unwrap().to_string(),
        serde_json::to_vec(table.metadata()).unwrap(),
    )]);
    let mut commit_fixtures=Vec::new();
    for (at, part, removed, value) in [
        (1, HOUR_ID, vec![], "erased-subject"),
        (2, DAY_ID, vec![HOUR_ID], "survivor"),
    ] {
        let mut added = files(part, &data_prefix);
        let original = &added[part][0];
        added.get_mut(part).unwrap()[0] = DataFileBuilder::default()
            .content(original.content_type())
            .file_format(original.file_format())
            .file_path(original.file_path().to_string())
            .partition(Struct::empty())
            .partition_spec_id(0)
            .record_count(10)
            .file_size_in_bytes(100)
            .lower_bounds(HashMap::from([(8, Datum::string(value))]))
            .upper_bounds(HashMap::from([(8, Datum::string(value))]))
            .build()
            .unwrap();
        let delta = manifest(at, (at > 1).then_some(at - 1), Some(part), &removed);
        let (snapshot, snapshot_requirements) = prepare_lifecycle_snapshot(
            &table,
            &delta,
            added,
            &contract(false).schema,
            &data_prefix,
            100,
        )
        .await
        .unwrap();
        let (_,mut requirements,mut updates)=contract(false).evolution(&table).unwrap();
        requirements.extend(snapshot_requirements);
        updates.extend([
            TableUpdate::AddSnapshot{snapshot:snapshot.clone()},
            TableUpdate::SetSnapshotRef{ref_name:MAIN_BRANCH.into(),reference:SnapshotReference::new(snapshot.snapshot_id(),SnapshotRetention::branch(None,None,None))},
            TableUpdate::SetProperties{updates:HashMap::from([(CHECKPOINT.into(),at.to_string()),(DIGEST.into(),manifest_digest(&delta).unwrap())])},
        ]);
        commit_fixtures.push(serde_json::json!({"before":table.metadata(),"request":iceberg_catalog_rest::CommitTableRequest{identifier:Some(table.identifier().clone()),requirements,updates}}));
        let list = table
            .manifest_list_reader(&Arc::new(snapshot.clone()))
            .load()
            .await
            .unwrap();
        for path in std::iter::once(snapshot.manifest_list().to_string())
            .chain(list.entries().iter().map(|d| d.manifest_path.clone()))
        {
            let bytes = table
                .file_io()
                .new_input(&path)
                .unwrap()
                .read()
                .await
                .unwrap();
            objects.insert(path, bytes.to_vec());
        }
        let id = snapshot.snapshot_id();
        table = changed(
            &table,
            vec![
                TableUpdate::AddSnapshot { snapshot },
                TableUpdate::SetSnapshotRef {
                    ref_name: MAIN_BRANCH.into(),
                    reference: SnapshotReference::new(
                        id,
                        SnapshotRetention::branch(None, None, None),
                    ),
                },
            ],
        );
        objects.insert(
            table.metadata_location().unwrap().to_string(),
            serde_json::to_vec(table.metadata()).unwrap(),
        );
    }
    let prefix = format!("{location}/metadata/");
    let state = Arc::new(Mutex::new(Wire {
        tenant: TENANT_ID.into(),
        prefix: prefix.clone(),
        before_expiry: table.clone(),
        table,
        objects,
        events: vec![],
        fail_commit: false,
        stale_reload: false,
        fail_delete: false,
        expected_control: platform
            .then(|| "tenant-scoped-platform-control-fixture-123456789".to_string()),
        rest_auth_seen: 0,
        config_override: None,
        rest_uri: String::new(),
        commit_fixtures,
        table_status: None,
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    state.lock().unwrap().rest_uri = endpoint.clone();
    let app = Router::new()
        .fallback(any(handler))
        .with_state(state.clone());
    let server = Server(tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    }));
    let config = crate::iceberg::CatalogConfig {
        uri: endpoint.clone(),
        warehouse: "fixture".into(),
        credential: None,
        token_file: None,
        oauth_scope: None,
        oauth_audience: None,
        oauth_server_uri: None,
        realm: None,
        allow_anonymous: !platform,
        s3_endpoint: endpoint.clone(),
        s3_region: "us-east-1".into(),
        s3_access_key: "fixture".into(),
        s3_secret_key: "fixture".into(),
        s3_session_token: None,
        s3_path_style_access: true,
        s3_default_credentials: false,
        vended_credentials: false,
    };
    let metadata = Arc::new(
        MetadataGc::new(
            TENANT_ID,
            &location,
            Arc::new(Authority(state.clone(), TENANT_ID.into(), prefix)),
        )
        .unwrap(),
    );
    let backend = RestLifecycleBackend::new(
        config,
        ExportTable {
            tenant_id: TENANT_ID.into(),
            namespace: if platform { "agent" } else { "nano" }.into(),
            dataset: "events".into(),
            location,
            data_prefix,
            max_files: 100,
            contract: contract(false),
        },
        target,
        Arc::new(Controls),
        Arc::new(Controls),
        metadata,
    )
    .unwrap();
    let backend = if platform {
        let token = state.lock().unwrap().expected_control.clone().unwrap();
        backend.with_platform_auth(
            Arc::new(crate::part_ingest::platform_tls::PlatformCatalogClient::new(&endpoint,Duration::from_secs(20),Default::default()).unwrap()),
            token.clone(),
            Arc::new(crate::part_ingest::iceberg_export::activation::platform_io::PlatformMetadataFactory::new(
                TENANT_ID,&crate::lake_part_gc::request::tenant_bucket(TENANT_ID),&format!("__r2_data_catalog/agent/v2/tenant={TENANT_ID}/agent/"),
                &endpoint,uuid::Uuid::new_v4(),token.clone(),
                Arc::new(crate::part_ingest::platform_tls::PlatformCatalogClient::new(&endpoint,Duration::from_secs(20),Default::default()).unwrap()),dir.path(),
            ).unwrap()),
        )
    } else {
        backend
    };
    (dir, server, backend, state)
}
#[tokio::test]
async fn production_platform_client_expires_and_purges_without_a_bearer_file_or_vendor_key() {
    let (dir, _server, backend, state) = setup_mode(true).await;
    assert_eq!(
        backend.expire_and_inspect().await.unwrap(),
        BTreeSet::from([DAY_ID.to_string()])
    );
    let state = state.lock().unwrap();
    assert!(state.rest_auth_seen >= 4);
    assert!(state.events.contains(&"commit") && state.events.contains(&"delete"));
    assert_eq!(state.table.metadata().snapshots().len(), 1);
    assert!(!state
        .objects
        .values()
        .any(|bytes| bytes.windows(14).any(|w| w == b"erased-subject")));
    let token = state.expected_control.as_ref().unwrap().as_bytes();
    let mut directories = vec![dir.path().to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else {
                let bytes = std::fs::read(path).unwrap();
                assert!(
                    !bytes.windows(token.len()).any(|w| w == token),
                    "control capability projected to disk"
                );
            }
        }
    }
}
#[tokio::test]
async fn production_platform_client_refuses_a_runtime_authority_override_before_table_io() {
    let (_dir, _server, backend, state) = setup_mode(true).await;
    {
        let mut state = state.lock().unwrap();
        state.config_override = Some(format!("{}/escape", state.rest_uri));
    }
    assert!(backend.expire_and_inspect().await.is_err());
    let state = state.lock().unwrap();
    assert_eq!(state.rest_auth_seen, 1);
    assert!(state.events.is_empty());
}
#[tokio::test]
async fn production_rest_expires_reloads_inspects_and_purges_all_old_metadata() {
    let (_dir, _server, backend, state) = setup().await;
    assert!(
        state
            .lock()
            .unwrap()
            .objects
            .values()
            .any(|b| b.windows(14).any(|w| w == b"erased-subject")),
        "old bounds fixture"
    );
    let referenced = backend.expire_and_inspect().await.unwrap();
    assert_eq!(referenced, BTreeSet::from([DAY_ID.to_string()]));
    let state = state.lock().unwrap();
    assert_eq!(state.table.metadata().snapshots().len(), 1);
    assert!(state.events.iter().filter(|e| **e == "load").count() >= 2);
    assert!(state.events.contains(&"s3-read") && state.events.contains(&"delete"));
    let reload = state.events.iter().rposition(|e| *e == "load").unwrap();
    let delete = state.events.iter().position(|e| *e == "delete").unwrap();
    assert!(
        reload < delete,
        "reload must succeed before physical metadata deletion"
    );
    assert!(!state
        .objects
        .values()
        .any(|b| b.windows(14).any(|w| w == b"erased-subject")));
}
#[tokio::test]
async fn production_rest_conflict_and_stale_reload_never_authorize_metadata_deletion() {
    for stale in [false, true] {
        let (_dir, _server, backend, state) = setup().await;
        {
            let mut state = state.lock().unwrap();
            state.stale_reload = stale;
            state.fail_commit = !stale;
        }
        let error = backend.expire_and_inspect().await.unwrap_err();
        assert!(
            error.to_string().contains(if stale {
                "expiry not observed"
            } else {
                "expiry unacknowledged"
            }),
            "{error:#}"
        );
        let state = state.lock().unwrap();
        assert!(state.events.contains(&"commit"));
        assert!(!state.events.contains(&"delete"));
    }
}
#[tokio::test]
async fn production_rest_metadata_delete_failure_is_not_a_successful_expiry() {
    let (_dir, _server, backend, state) = setup().await;
    state.lock().unwrap().fail_delete = true;
    assert!(backend
        .expire_and_inspect()
        .await
        .unwrap_err()
        .to_string()
        .contains("metadata delete unavailable"));
}

/// Offline fixture refresh for the platform scope decoder. The bytes are emitted
/// by the production Iceberg writer; no provider or credential is involved.
#[tokio::test]
#[ignore = "explicit fixture regeneration only"]
async fn emit_platform_scope_fixture() {
    use base64::Engine;
    let (_dir, _server, _backend, state) = setup_mode(true).await;
    let state = state.lock().unwrap();
    let metadata = serde_json::to_value(state.table.metadata()).unwrap();
    let snapshot = metadata["snapshots"].as_array().unwrap().last().unwrap();
    let objects: std::collections::BTreeMap<_, _> = state
        .objects
        .iter()
        .filter(|(p, _)| p.ends_with(".avro"))
        .map(|(p, b)| (p, base64::engine::general_purpose::STANDARD.encode(b)))
        .collect();
    println!(
        "NAN4438_FIXTURE {}",
        serde_json::json!({"tenant":TENANT_ID,"root":state.table.metadata().location(),"snapshot":snapshot,"objects":objects,"commits":state.commit_fixtures})
    );
}

/// NAN-4662: the production REST read behind "no committed snapshot". Only an
/// absent table (404) or one holding no snapshot at all (current or retained
/// for time travel) proves it; any other answer is an error, never "absent".
#[tokio::test]
async fn production_rest_commit_state_needs_an_absent_or_snapshotless_table() {
    let (_dir, _server, backend, state) = setup().await;
    assert!(!backend.no_committed_snapshot().await.unwrap(), "committed history");
    let ids = {
        let mut state = state.lock().unwrap();
        let ids = state.table.metadata().snapshots().map(|s| s.snapshot_id()).collect::<Vec<_>>();
        state.table = changed(&state.table, vec![TableUpdate::RemoveSnapshotRef { ref_name: MAIN_BRANCH.into() }]);
        assert!(state.table.metadata().current_snapshot_id().is_none());
        ids
    };
    assert!(!backend.no_committed_snapshot().await.unwrap(), "retained snapshots still reference parts");
    {
        let mut state = state.lock().unwrap();
        state.table = changed(&state.table, vec![TableUpdate::RemoveSnapshots { snapshot_ids: ids }]);
        assert_eq!(state.table.metadata().snapshots().len(), 0);
    }
    assert!(backend.no_committed_snapshot().await.unwrap(), "never committed");
    state.lock().unwrap().table_status = Some(404);
    assert!(backend.no_committed_snapshot().await.unwrap(), "absent");
    for status in [403, 500, 503] {
        state.lock().unwrap().table_status = Some(status);
        assert!(backend.no_committed_snapshot().await.is_err(), "{status} is not absence");
    }
}
