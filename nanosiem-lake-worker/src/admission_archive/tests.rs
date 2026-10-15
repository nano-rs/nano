// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    reserved: BTreeMap<(Uuid, String), Descriptor>,
    published: BTreeMap<(Uuid, String), Publication>,
    references: BTreeMap<(Uuid, Uuid), String>,
    retired: BTreeSet<(Uuid, String)>,
}

#[derive(Default)]
struct Authority {
    state: Mutex<State>,
    fail_publish: AtomicUsize,
    lose_publish_ack: AtomicUsize,
}

impl Authority {
    fn retire(&self, tenant: Uuid, identity: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let key = (tenant, identity.to_string());
        if !state.published.contains_key(&key)
            || state
                .references
                .iter()
                .any(|((t, _), d)| *t == tenant && d == identity)
        {
            bail!("held or incomplete");
        }
        state.retired.insert(key);
        Ok(())
    }
}

#[async_trait]
impl RetentionAuthority for Authority {
    async fn reserve(&self, descriptor: &Descriptor) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let key = (descriptor.tenant_id, descriptor.sha256()?);
        if state.retired.contains(&key) {
            bail!("retired");
        }
        state.reserved.insert(key, descriptor.clone());
        Ok(())
    }
    async fn publish(&self, publication: &Publication) -> Result<()> {
        if self.fail_publish.load(Ordering::SeqCst) != 0 {
            bail!("publication crash");
        }
        let mut state = self.state.lock().unwrap();
        let key = (publication.descriptor.tenant_id, publication.validate()?);
        if state.retired.contains(&key) || state.reserved.get(&key) != Some(&publication.descriptor)
        {
            bail!("not reserved");
        }
        state.published.insert(key, publication.clone());
        if self.lose_publish_ack.load(Ordering::SeqCst) != 0 {
            bail!("publication committed but acknowledgment was lost");
        }
        Ok(())
    }
    async fn retain(&self, tenant: Uuid, identity: &str, reference: Uuid) -> Result<Publication> {
        let mut state = self.state.lock().unwrap();
        let key = (tenant, identity.to_string());
        if state.retired.contains(&key) {
            bail!("retired");
        }
        let publication = state.published.get(&key).context("unpublished")?.clone();
        if state
            .references
            .get(&(tenant, reference))
            .is_some_and(|d| d != identity)
        {
            bail!("reference rebound");
        }
        state
            .references
            .insert((tenant, reference), identity.into());
        Ok(publication)
    }
    async fn release(&self, tenant: Uuid, identity: &str, reference: Uuid) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state
            .references
            .get(&(tenant, reference))
            .is_some_and(|d| d != identity)
        {
            bail!("reference rebound");
        }
        state.references.remove(&(tenant, reference));
        Ok(())
    }
}

#[derive(Default)]
struct Store {
    bytes: Mutex<BTreeMap<String, Vec<u8>>>,
    operation: AtomicUsize,
    fail_at: AtomicUsize,
}

impl Store {
    fn boundary(&self) -> Result<()> {
        let step = self.operation.fetch_add(1, Ordering::SeqCst) + 1;
        if step == self.fail_at.load(Ordering::SeqCst) {
            bail!("remote unavailable");
        }
        Ok(())
    }
}

#[async_trait]
impl ObjectArchive for Store {
    async fn put_immutable(
        &self,
        key: &str,
        dependency: &Dependency,
        path: &Path,
    ) -> Result<ObjectReceipt> {
        self.boundary()?;
        let bytes = std::fs::read(path)?;
        let mut objects = self.bytes.lock().unwrap();
        if let Some(previous) = objects.get(key) {
            if previous != &bytes {
                bail!("immutable collision");
            }
        } else {
            objects.insert(key.into(), bytes);
        }
        Ok(ObjectReceipt {
            key: key.into(),
            sha256: dependency.sha256.clone(),
            bytes: dependency.bytes,
            version: "exact-v1".into(),
        })
    }
}

#[async_trait]
impl ObjectReader for Store {
    async fn get_exact(&self, receipt: &ObjectReceipt, path: &Path) -> Result<()> {
        self.boundary()?;
        let objects = self.bytes.lock().unwrap();
        std::fs::write(
            path,
            objects
                .get(&receipt.key)
                .context("retired or missing object")?,
        )?;
        Ok(())
    }
}

struct Secrets;
impl SecretProvider for Secrets {
    fn read(&self, _: &SecretReference) -> Result<Vec<u8>> {
        bail!("missing secret");
    }
}

fn fixture() -> (tempfile::TempDir, Descriptor, BTreeMap<String, PathBuf>) {
    let root = tempfile::tempdir().unwrap();
    let compiler = b"exact compiler";
    let native = b"exact native";
    let config = serde_json::to_vec(&serde_json::json!({
        "assigned_tenant_id": "tenant-a", "compiler": {"path": "/old/compiler", "sha256": digest(compiler)},
        "native_library": {"path": "/old/native", "sha256": digest(native)}
    })).unwrap();
    let event_config_sha256 = crate::config::event_config_sha256(&config).unwrap();
    let mut descriptor = Descriptor {
        contract: CONTRACT,
        tenant_id: Uuid::new_v4(),
        logical_tenant_id: "tenant-a".into(),
        assignment_revision: 1,
        executor_abi: "test-abi-1".into(),
        pin: DurableLakeGenerationPin {
            generation_id: crate::config::event_generation_id(42, &event_config_sha256).unwrap(),
            event_config_sha256,
            snapshot_id: 42,
            iceberg_metadata_location: None,
            compiler_sha256: digest(compiler),
            native_artifact_sha256: digest(native),
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
        },
        dependencies: Vec::new(),
        secrets: Vec::new(),
    };
    let mut sources = BTreeMap::new();
    for (locator, bytes) in [
        ("compiler", compiler.as_slice()),
        ("native-library", native.as_slice()),
        ("worker-config", config.as_slice()),
    ] {
        let path = root.path().join(locator);
        std::fs::write(&path, bytes).unwrap();
        descriptor.dependencies.push(Dependency {
            locator: locator.into(),
            sha256: digest(bytes),
            bytes: bytes.len() as u64,
            executable: locator == "compiler",
        });
        sources.insert(locator.into(), path);
    }
    (root, descriptor, sources)
}

#[tokio::test]
async fn cold_resolution_survives_origin_directory_loss() {
    let (root, descriptor, sources) = fixture();
    let authority = Authority::default();
    let store = Store::default();
    let identity = publish(&authority, &store, descriptor.clone(), &sources)
        .await
        .unwrap();
    drop(root);
    let resolved = resolve(
        &authority,
        &store,
        &Secrets,
        descriptor.tenant_id,
        &identity,
        "test-abi-1",
        Uuid::new_v4(),
    )
    .await
    .unwrap();
    assert_eq!(resolved.files.len(), 3);
    assert_eq!(
        std::fs::read(&resolved.files["compiler"]).unwrap(),
        b"exact compiler"
    );
    assert!(resolved.root().join("verified-descriptor.json").exists());
}

#[tokio::test]
async fn every_upload_and_readback_crash_boundary_is_unadmissible_and_replayable() {
    for boundary in 1..=6 {
        let (_root, descriptor, sources) = fixture();
        let authority = Authority::default();
        let store = Store::default();
        store.fail_at.store(boundary, Ordering::SeqCst);
        assert!(publish(&authority, &store, descriptor.clone(), &sources)
            .await
            .is_err());
        let identity = descriptor.sha256().unwrap();
        assert!(authority
            .retain(descriptor.tenant_id, &identity, Uuid::new_v4())
            .await
            .is_err());
        assert!(authority.retire(descriptor.tenant_id, &identity).is_err());
        store.fail_at.store(0, Ordering::SeqCst);
        assert_eq!(
            publish(&authority, &store, descriptor.clone(), &sources)
                .await
                .unwrap(),
            identity
        );
        authority
            .retain(descriptor.tenant_id, &identity, Uuid::new_v4())
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn crash_after_all_uploads_before_visibility_is_not_admissible() {
    let (_root, descriptor, sources) = fixture();
    let authority = Authority::default();
    let store = Store::default();
    authority.fail_publish.store(1, Ordering::SeqCst);
    assert!(publish(&authority, &store, descriptor.clone(), &sources)
        .await
        .is_err());
    assert_eq!(store.bytes.lock().unwrap().len(), 3);
    assert!(authority
        .retain(
            descriptor.tenant_id,
            &descriptor.sha256().unwrap(),
            Uuid::new_v4()
        )
        .await
        .is_err());
    authority.fail_publish.store(0, Ordering::SeqCst);
    publish(&authority, &store, descriptor, &sources)
        .await
        .unwrap();
}

#[tokio::test]
async fn lost_publication_ack_exposes_only_complete_descriptor_and_replays() {
    let (_root, descriptor, sources) = fixture();
    let authority = Authority::default();
    let store = Store::default();
    authority.lose_publish_ack.store(1, Ordering::SeqCst);
    assert!(publish(&authority, &store, descriptor.clone(), &sources)
        .await
        .is_err());
    let identity = descriptor.sha256().unwrap();
    let complete = authority
        .retain(descriptor.tenant_id, &identity, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(complete.validate().unwrap(), identity);
    authority.lose_publish_ack.store(0, Ordering::SeqCst);
    assert_eq!(
        publish(&authority, &store, descriptor, &sources)
            .await
            .unwrap(),
        identity
    );
}

#[tokio::test]
async fn remote_error_has_no_fallback_and_keeps_retention_reference() {
    let (_root, descriptor, sources) = fixture();
    let authority = Authority::default();
    let store = Store::default();
    let identity = publish(&authority, &store, descriptor.clone(), &sources)
        .await
        .unwrap();
    store.fail_at.store(7, Ordering::SeqCst);
    assert!(resolve(
        &authority,
        &store,
        &Secrets,
        descriptor.tenant_id,
        &identity,
        "test-abi-1",
        Uuid::new_v4()
    )
    .await
    .is_err());
    assert_eq!(store.operation.load(Ordering::SeqCst), 7);
    assert!(authority.retire(descriptor.tenant_id, &identity).is_err());
}

#[tokio::test]
async fn corrupt_or_retired_remote_object_refuses_resolution() {
    for corrupt in [false, true] {
        let (_root, descriptor, sources) = fixture();
        let authority = Authority::default();
        let store = Store::default();
        let identity = publish(&authority, &store, descriptor.clone(), &sources)
            .await
            .unwrap();
        let key = store.bytes.lock().unwrap().keys().next().unwrap().clone();
        if corrupt {
            store.bytes.lock().unwrap().insert(key, b"corrupt".to_vec());
        } else {
            store.bytes.lock().unwrap().remove(&key);
        }
        assert!(resolve(
            &authority,
            &store,
            &Secrets,
            descriptor.tenant_id,
            &identity,
            "test-abi-1",
            Uuid::new_v4()
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn wrong_tenant_and_abi_do_not_read_objects() {
    let (_root, descriptor, sources) = fixture();
    let authority = Authority::default();
    let store = Store::default();
    let identity = publish(&authority, &store, descriptor.clone(), &sources)
        .await
        .unwrap();
    for (tenant, abi) in [
        (Uuid::new_v4(), "test-abi-1"),
        (descriptor.tenant_id, "wrong-abi"),
    ] {
        assert!(resolve(
            &authority,
            &store,
            &Secrets,
            tenant,
            &identity,
            abi,
            Uuid::new_v4()
        )
        .await
        .is_err());
    }
    assert_eq!(store.operation.load(Ordering::SeqCst), 6);
}

#[tokio::test]
async fn held_pin_prevents_gc_and_retirement_prevents_republication() {
    let (_root, descriptor, sources) = fixture();
    let authority = Arc::new(Authority::default());
    let store = Store::default();
    let identity = publish(authority.as_ref(), &store, descriptor.clone(), &sources)
        .await
        .unwrap();
    let reference = Uuid::new_v4();
    authority
        .retain(descriptor.tenant_id, &identity, reference)
        .await
        .unwrap();
    let other = authority.clone();
    let id = identity.clone();
    let tenant = descriptor.tenant_id;
    assert!(
        tokio::task::spawn_blocking(move || other.retire(tenant, &id))
            .await
            .unwrap()
            .is_err()
    );
    authority
        .release(tenant, &identity, reference)
        .await
        .unwrap();
    authority.retire(tenant, &identity).unwrap();
    assert!(authority
        .retain(tenant, &identity, Uuid::new_v4())
        .await
        .is_err());
    assert!(publish(authority.as_ref(), &store, descriptor, &sources)
        .await
        .is_err());
}

#[test]
fn verification_reports_missing_or_changed_reads_and_missing_telemetry() {
    let (_root, descriptor, _) = fixture();
    assert!(
        verify_observed_reads("job".into(), &descriptor, &descriptor.dependencies)
            .unwrap()
            .gaps
            .is_empty()
    );
    let mut observed = descriptor.dependencies.clone();
    observed[0].sha256 = "0".repeat(64);
    let report = verify_observed_reads("job".into(), &descriptor, &observed).unwrap();
    assert_eq!(report.covered_reads, 2);
    assert_eq!(report.gaps.len(), 1);
    assert_eq!(
        verify_observed_reads("job".into(), &descriptor, &[])
            .unwrap()
            .gaps
            .len(),
        1
    );
}

#[test]
fn malformed_descriptor_and_missing_executable_fail_closed() {
    let (_root, descriptor, _) = fixture();
    let mut changed = descriptor.clone();
    changed.dependencies.remove(0);
    assert!(changed.validate().is_err());
    let mut changed = descriptor.clone();
    changed.dependencies.reverse();
    assert!(changed.validate().is_err());
    let mut changed = descriptor;
    changed.pin.hot_tail_manifest_sha256 = Some("a".repeat(64));
    changed.pin.hot_tail_snapshot_id = Some(43);
    assert!(changed.validate().is_err());
}

#[tokio::test]
async fn missing_source_never_reserves_or_uploads() {
    let (_root, descriptor, mut sources) = fixture();
    sources.remove("compiler");
    let authority = Authority::default();
    let store = Store::default();
    assert!(publish(&authority, &store, descriptor, &sources)
        .await
        .is_err());
    assert!(authority.state.lock().unwrap().reserved.is_empty());
    assert_eq!(store.operation.load(Ordering::SeqCst), 0);
}

fn archived_config_fixture() -> (tempfile::TempDir, PathBuf, DurableLakeGenerationPin) {
    use serde_json::json;
    let root = tempfile::tempdir().unwrap();
    let artifact = |name: &str, bytes: &[u8]| {
        let path = root.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        json!({"path": path, "sha256": digest(bytes)})
    };
    let compiler = artifact("compiler", b"compiler-v1");
    let native = artifact("native", b"native-v1");
    let data = root.path().join("snapshot");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("part.parquet"), b"snapshot bytes").unwrap();
    let stamps = artifact("object-stamps.json", &serde_json::to_vec(&json!({
        "metadata_location": "s3://bucket/events/metadata/v1.metadata.json", "snapshot_id":42,
        "table":"events", "objects":[{"relative_path":"part.parquet", "source_uri":"s3://bucket/events/data/part.parquet",
        "version_id":"v1", "size_bytes":14, "sha256":digest(b"snapshot bytes")}]
    })).unwrap());
    let keyword = root.path().join("keyword");
    let fragment = root.path().join("fragment");
    for path in [&keyword, &fragment] {
        std::fs::create_dir(path).unwrap();
        std::fs::write(path.join("part"), b"index bytes").unwrap();
    }
    let config = json!({
        "schema_version":1, "generation_id":"active", "assigned_tenant_id":"tenant-a",
        "compiler":compiler, "native_library":native,
        "tenant":{"tenant_id":"tenant-a", "source":"s3://bucket/events", "iceberg_metadata_file_path":"metadata/v1.metadata.json",
        "source_manifest":artifact("source.json",b"{}"), "max_query_bytes":1024, "max_execution_seconds":10,
        "threads":1, "event_contract":"ocsf-1.9", "allow_broad_npl":true},
        "snapshot_cache":{"object_stamp_manifest":stamps,"data_directory":data,"max_bytes":1024,"ancestor_snapshot_ids":[42]},
        "entity_sidecar":{"manifest":artifact("entity.json",b"{}"),"hmac_key":artifact("hmac", &[9;32]),
            "index_files":[artifact("entity.idx",b"entity index")]},
        "keyword_sidecar":{"manifest":artifact("keyword.json",b"{}"),"index_directory":keyword,
            "index_tree_sha256":crate::config::index_directory_sha256(&keyword,"keyword").unwrap().0,
            "fragment_manifest":artifact("fragment.json",b"{}"),"fragment_index_directory":fragment,
            "fragment_index_tree_sha256":crate::config::index_directory_sha256(&fragment,"fragment").unwrap().0}
    });
    let path = root.path().join("worker.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let archived =
        crate::config::archive_event_config(&path, &root.path().join("archive"), 42).unwrap();
    let pin = DurableLakeGenerationPin {
        generation_id: archived.generation_id,
        event_config_sha256: archived.event_config_sha256,
        snapshot_id: 42,
        iceberg_metadata_location: Some("s3://bucket/events/metadata/v1.metadata.json".into()),
        compiler_sha256: digest(b"compiler-v1"),
        native_artifact_sha256: digest(b"native-v1"),
        hot_tail_manifest_sha256: None,
        hot_tail_snapshot_id: None,
        hot_tail_id: None,
    };
    (root, archived.path, pin)
}

#[tokio::test]
async fn archived_config_inventory_includes_snapshot_derivatives_and_excludes_secret_bytes() {
    let (_root, path, pin) = archived_config_fixture();
    let inventory = inventory::capture(
        Uuid::new_v4(),
        "tenant-a",
        1,
        "abi-1",
        pin,
        &path,
        None,
        &BTreeMap::new(),
    )
    .await
    .unwrap();
    assert!(inventory.descriptor.dependencies.len() >= 10);
    assert!(inventory
        .descriptor
        .dependencies
        .iter()
        .any(|d| d.locator.ends_with("snapshot/part.parquet")));
    assert!(inventory
        .descriptor
        .dependencies
        .iter()
        .any(|d| d.locator.ends_with("keyword/part")));
    assert!(inventory
        .descriptor
        .dependencies
        .iter()
        .all(|d| d.sha256 != digest(&[9; 32])));
    assert_eq!(inventory.descriptor.secrets[0].sha256, digest(&[9; 32]));
}

#[tokio::test]
async fn archived_pin_missing_dependency_is_a_gap_not_a_descriptor() {
    let (root, path, pin) = archived_config_fixture();
    std::fs::remove_file(root.path().join("snapshot/part.parquet")).unwrap();
    assert!(inventory::capture(
        Uuid::new_v4(),
        "tenant-a",
        1,
        "abi-1",
        pin,
        &path,
        None,
        &BTreeMap::new()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn archived_pin_rejects_wrong_tenant_and_compiler() {
    let (_root, path, mut pin) = archived_config_fixture();
    assert!(inventory::capture(
        Uuid::new_v4(),
        "tenant-b",
        1,
        "abi-1",
        pin.clone(),
        &path,
        None,
        &BTreeMap::new()
    )
    .await
    .is_err());
    pin.compiler_sha256 = "f".repeat(64);
    assert!(inventory::capture(
        Uuid::new_v4(),
        "tenant-a",
        1,
        "abi-1",
        pin,
        &path,
        None,
        &BTreeMap::new()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn exact_slatedb_checkpoint_closure_opens_on_a_cold_root_after_origin_loss() {
    use slatedb::config::{CheckpointOptions, CheckpointScope};
    use slatedb::object_store::local::LocalFileSystem;
    use slatedb::{Db, DbReaderBuilder, DbReaderMode};
    let origin = tempfile::tempdir().unwrap();
    let database_path = origin.path().to_str().unwrap().trim_start_matches('/');
    let object_store = Arc::new(LocalFileSystem::new_with_prefix("/").unwrap());
    let db = Db::builder(database_path, object_store.clone())
        .build()
        .await
        .unwrap();
    db.put(b"pinned", b"checkpoint-value").await.unwrap();
    db.flush().await.unwrap();
    let checkpoint = db
        .create_checkpoint(CheckpointScope::All, &CheckpointOptions::default())
        .await
        .unwrap();
    db.close().await.unwrap();
    let (_fixture, mut descriptor, _) = fixture();
    descriptor.dependencies.clear();
    let mut inventory = inventory::Inventory {
        descriptor,
        sources: BTreeMap::new(),
    };
    inventory
        .checkpoint(database_path, checkpoint.id)
        .await
        .unwrap();
    assert!(inventory
        .descriptor
        .dependencies
        .iter()
        .any(|d| d.locator.ends_with(".sst")));
    assert!(inventory
        .checkpoint(database_path, Uuid::new_v4())
        .await
        .is_err());
    let cold = tempfile::tempdir().unwrap();
    for path in inventory.sources.values() {
        let destination = cold.path().join(path.strip_prefix(origin.path()).unwrap());
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(path, destination).unwrap();
    }
    drop(origin);
    let reader = DbReaderBuilder::new(
        cold.path().to_str().unwrap().trim_start_matches('/'),
        object_store,
    )
    .with_reader_mode(DbReaderMode::Checkpoint(checkpoint.id))
    .build()
    .await
    .unwrap();
    assert_eq!(
        reader.get(b"pinned").await.unwrap().unwrap().as_ref(),
        b"checkpoint-value"
    );
    reader.close().await.unwrap();
}

#[cfg(feature = "enterprise")]
mod hosted_tests;
