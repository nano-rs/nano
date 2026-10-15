// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{PinnedManifest, RefreshOutcome, SharedSchemaProfile};
use nanosiem_core::schema::{profile_for_id, SchemaId, SchemaProfile};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Stand-in for `ApiConfig::try_schema_profile()`, which in lake mode parses the
/// multi-MB source manifest. Counting the calls is what proves the handler path
/// no longer rebuilds.
fn build_counted(builds: &AtomicUsize) -> Arc<dyn SchemaProfile> {
    builds.fetch_add(1, Ordering::SeqCst);
    profile_for_id(SchemaId::Ocsf)
}

#[test]
fn profile_is_built_once_and_handed_out_by_reference() {
    let builds = AtomicUsize::new(0);
    let shared = SharedSchemaProfile::new(build_counted(&builds));

    let first = shared.load();
    let second = shared.load();
    let third = shared.clone().load();

    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first, &third));
}

#[test]
fn store_publishes_a_new_profile_to_later_readers() {
    let shared = SharedSchemaProfile::new(profile_for_id(SchemaId::Ocsf));
    let before = shared.load();

    shared.store(profile_for_id(SchemaId::Udm), None);
    let after = shared.load();

    assert!(!Arc::ptr_eq(&before, &after));
    assert_eq!(after.id(), SchemaId::Udm);
    // The pre-swap reader keeps its whole profile.
    assert_eq!(before.id(), SchemaId::Ocsf);
}

/// A generation promotion rewrites the worker config to point at a NEW immutable
/// manifest. The refresher must notice and republish, or the API keeps resolving
/// OCSF field names against a generation the worker no longer serves.
#[test]
fn promoted_generation_swaps_the_pinned_profile() {
    let lake = TempLake::new("promoted");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned);

    let before = shared.load();
    lake.write_generation("gen-2", "tenant-a", "{\"objects\":[1,2]}");
    let builds = AtomicUsize::new(0);
    let outcome = lake.refresh(&shared, &|| Ok(build_counted(&builds)));

    match outcome {
        RefreshOutcome::Swapped { generation_id, .. } => {
            assert_eq!(generation_id.as_deref(), Some("gen-2"));
        }
        other => panic!("expected a swap, got {other:?}"),
    }
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    assert!(!Arc::ptr_eq(&before, &shared.load()));
    let manifest = shared.pinned_manifest().expect("identity must be re-pinned");
    assert_eq!(manifest.generation_id.as_deref(), Some("gen-2"));
    assert_eq!(manifest.path, lake.manifest_path("gen-2").to_string_lossy());
}

/// NAN-3492: a trusted-local install has no worker config, so only the
/// worker-served schema can move the profile past the one resolved at boot.
#[test]
fn installed_worker_schema_is_adopted_once_and_keeps_the_manifest_identity() {
    let lake = TempLake::new("adopt");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let boot = profile_for_id(SchemaId::Ocsf);
    let shared = shared_with(boot.clone(), pinned);
    let manifest = shared.pinned_manifest();

    assert!(!shared.adopt(None), "no worker-served schema: nothing to adopt");
    assert!(!shared.adopt(Some(boot.clone())), "the boot profile is already active");
    assert!(Arc::ptr_eq(&shared.load(), &boot));

    let installed = profile_for_id(SchemaId::Ocsf);
    assert!(shared.adopt(Some(installed.clone())));
    assert!(Arc::ptr_eq(&shared.load(), &installed));
    assert_eq!(shared.pinned_manifest(), manifest);
    assert!(!shared.adopt(Some(installed)), "an unchanged install is not republished");
}

/// The steady state: no promotion, so the tick must not rebuild the profile.
#[test]
fn unchanged_manifest_does_not_rebuild() {
    let lake = TempLake::new("unchanged");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned);

    let builds = AtomicUsize::new(0);
    assert_eq!(
        lake.refresh(&shared, &|| Ok(build_counted(&builds))),
        RefreshOutcome::Unchanged
    );
    assert_eq!(builds.load(Ordering::SeqCst), 0);
}

/// A refresh that cannot read the manifest it was pointed at must be a no-op,
/// never a blanked field inventory.
#[test]
fn unreadable_manifest_retains_the_previous_profile() {
    let lake = TempLake::new("unreadable");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned.clone());
    let before = shared.load();

    // Promotion pointer written, manifest missing (mid-promotion or lost volume).
    lake.write_worker_config("gen-2", "tenant-a", &lake.manifest_path("gen-2"), "deadbeef");
    let builds = AtomicUsize::new(0);
    let outcome = lake.refresh(&shared, &|| Ok(build_counted(&builds)));

    assert!(matches!(outcome, RefreshOutcome::Failed(_)), "{outcome:?}");
    assert_eq!(builds.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(&before, &shared.load()));
    assert_eq!(shared.pinned_manifest(), Some(pinned));
}

/// An invalid worker config is likewise non-fatal.
#[test]
fn invalid_worker_config_retains_the_previous_profile() {
    let lake = TempLake::new("invalid-config");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned.clone());
    let before = shared.load();

    std::fs::write(lake.worker_config_path(), "{ not json").unwrap();
    let outcome = lake.refresh(&shared, &|| Ok(profile_for_id(SchemaId::Udm)));

    assert!(matches!(outcome, RefreshOutcome::Failed(_)), "{outcome:?}");
    assert!(Arc::ptr_eq(&before, &shared.load()));
    assert_eq!(shared.pinned_manifest(), Some(pinned));
}

/// A rebuild that rejects the new manifest (untrusted/unparseable snapshot) must
/// leave the serving profile alone rather than propagate the failure.
#[test]
fn failed_rebuild_retains_the_previous_profile() {
    let lake = TempLake::new("failed-rebuild");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned.clone());
    let before = shared.load();

    lake.write_generation("gen-2", "tenant-a", "{\"objects\":[1,2]}");
    let outcome = lake.refresh(&shared, &|| Err("manifest object lacks field_types".to_string()));

    assert!(matches!(outcome, RefreshOutcome::Failed(_)), "{outcome:?}");
    assert!(Arc::ptr_eq(&before, &shared.load()));
    assert_eq!(shared.pinned_manifest(), Some(pinned));
}

/// The identity fence: the product must not follow the worker's word on tenant.
#[test]
fn cross_tenant_manifest_is_refused() {
    let lake = TempLake::new("cross-tenant");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned.clone());
    let before = shared.load();

    lake.write_generation("gen-2", "tenant-b", "{\"objects\":[1,2]}");
    let outcome = lake.refresh(&shared, &|| panic!("a foreign tenant must never be rebuilt"));

    assert!(matches!(outcome, RefreshOutcome::Refused(_)), "{outcome:?}");
    assert!(Arc::ptr_eq(&before, &shared.load()));
    assert_eq!(shared.pinned_manifest(), Some(pinned));
}

/// A worker config that stops stating a tenant cannot prove it is still ours.
#[test]
fn missing_tenant_is_refused_against_a_pinned_tenant() {
    let lake = TempLake::new("missing-tenant");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned);

    let manifest = lake.write_manifest("gen-2", "{\"objects\":[1,2]}");
    std::fs::write(
        lake.worker_config_path(),
        serde_json::json!({
            "generation_id": "gen-2",
            "tenant": { "source_manifest": { "path": manifest, "sha256": "unverified" } },
        })
        .to_string(),
    )
    .unwrap();

    let outcome = lake.refresh(&shared, &|| panic!("an unstated tenant must never be rebuilt"));
    assert!(matches!(outcome, RefreshOutcome::Refused(_)), "{outcome:?}");
}

/// Same bytes reached under a new path (the operator refresh script rewrites the
/// host copy) is not a new field inventory — re-pin, don't rebuild.
#[test]
fn identical_bytes_under_a_new_path_are_repinned_without_a_rebuild() {
    let lake = TempLake::new("same-bytes");
    let pinned = lake.write_generation("gen-1", "tenant-a", "{\"objects\":[1]}");
    let shared = shared_with(profile_for_id(SchemaId::Ocsf), pinned.clone());
    let before = shared.load();

    // Byte-identical manifest, different path/generation stamp.
    lake.write_generation("gen-1-copy", "tenant-a", "{\"objects\":[1]}");
    let outcome = lake.refresh(&shared, &|| panic!("identical bytes must not rebuild"));

    assert_eq!(outcome, RefreshOutcome::Unchanged);
    assert!(Arc::ptr_eq(&before, &shared.load()));
    let repinned = shared.pinned_manifest().unwrap();
    assert_ne!(repinned.path, pinned.path);
    assert_eq!(repinned.digest, pinned.digest);
}

fn shared_with(profile: Arc<dyn SchemaProfile>, manifest: PinnedManifest) -> SharedSchemaProfile {
    SharedSchemaProfile::with_manifest(profile, Some(manifest))
}

/// A throwaway on-disk lake layout: one worker config plus per-generation
/// manifests, mirroring what the generation manager rewrites on promotion.
///
/// Files rather than env vars so these tests never mutate process-global state
/// and can run in parallel with the rest of the suite.
struct TempLake {
    root: tempfile::TempDir,
}

impl TempLake {
    fn new(name: &str) -> Self {
        Self {
            root: tempfile::Builder::new()
                .prefix(&format!("nan2361-schema-refresh-{name}-"))
                .tempdir()
                .unwrap(),
        }
    }

    fn worker_config_path(&self) -> PathBuf {
        self.root.path().join("worker.json")
    }

    fn manifest_path(&self, generation: &str) -> PathBuf {
        self.root
            .path()
            .join(format!("{generation}-source-manifest.json"))
    }

    fn write_manifest(&self, generation: &str, body: &str) -> String {
        let path = self.manifest_path(generation);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().to_string()
    }

    fn write_worker_config(&self, generation: &str, tenant: &str, manifest: &Path, sha256: &str) {
        std::fs::write(
            self.worker_config_path(),
            serde_json::json!({
                "generation_id": generation,
                "assigned_tenant_id": tenant,
                "tenant": {
                    "source_manifest": { "path": manifest.to_string_lossy(), "sha256": sha256 },
                },
            })
            .to_string(),
        )
        .unwrap();
    }

    /// Write a manifest and point the worker config at it, as a promotion does.
    fn write_generation(&self, generation: &str, tenant: &str, body: &str) -> PinnedManifest {
        let manifest = self.write_manifest(generation, body);
        let digest = super::digest_file(&manifest).unwrap();
        self.write_worker_config(generation, tenant, Path::new(&manifest), &digest);
        super::observe_active_manifest(&self.worker_config_path().to_string_lossy())
            .unwrap()
            .pin(digest)
    }

    fn refresh(
        &self,
        shared: &SharedSchemaProfile,
        rebuild: &dyn Fn() -> Result<Arc<dyn SchemaProfile>, String>,
    ) -> RefreshOutcome {
        shared.refresh_from_worker_config(&self.worker_config_path().to_string_lossy(), rebuild)
    }
}

impl Drop for TempLake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
