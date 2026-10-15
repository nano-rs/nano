// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end derivative tiering probe against REAL infrastructure
//! (NAN-2361). Ignored by default; the harness provides:
//!
//! - `NANO_TIER_E2E_DATA` — a real count-rollup directory (manifest.json +
//!   object-*.parquet), e.g. copied from a live generation.
//! - `NANO_TIER_E2E_STORE` — `s3://bucket/prefix` already mirrored by
//!   `lake_derivative_mirror`.
//! - `NANO_TIER_E2E_ENGINE_URL` — engine-facing tier root reachable from
//!   wherever the emitted SQL will execute.
//! - `NANO_TIER_E2E_OUT` — directory to write `baseline.json`,
//!   `tiered.json`, and `warm.json` plan files for the SQL harness.
//! - the `NANO_LAKE_RESULT_S3_*` credential contract for hydration.
//!
//! It proves, in-process and against the real store: a rollup whose parts
//! are ALL absent locally still loads and plans (direct s3() reads, nothing
//! dropped, nothing blocking), and background hydration admits real bytes
//! through the digest fence. The emitted plans are then executed by the
//! harness in a real ClickHouse and compared for exact equality — the
//! "tiered read returns the CORRECT answer" half that no mock can prove.
//!
//! Run:
//! `cargo test -p nanosiem-lake-worker --test derivative_tier_e2e -- --ignored`

use nanosiem_lake_worker::config::LoadedCountRollupConfig;
use nanosiem_lake_worker::derivative_tier::{
    ArtifactRef, DerivativeTier, OpendalArtifactStore, open_upload_store,
};
use nanosiem_lake_worker::planner::{ObjectStoreCredentials, TenantQueryConfig};
use nanosiem_lake_worker::rollup::{COUNT_ROLLUP_BUCKET_US, CountRollup, CountRollupSql};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set for the tiering E2E"))
}

fn tenant() -> TenantQueryConfig {
    TenantQueryConfig {
        tenant_id: "tenant-a".to_string(),
        source: "s3://bucket/table".to_string(),
        iceberg_metadata_file_path: "metadata/v1.json".to_string(),
        max_query_bytes: 2 * 1024 * 1024 * 1024,
        max_memory_bytes: 1024 * 1024 * 1024,
        max_execution_seconds: 120,
        threads: 4,
        credentials: ObjectStoreCredentials::Static {
            access_key: env("NANO_LAKE_RESULT_S3_ACCESS_KEY_ID"),
            secret_key: env("NANO_LAKE_RESULT_S3_SECRET_ACCESS_KEY"),
            session_token: None,
        },
        snapshot_cache: None,
    }
}

fn write_plan(out: &Path, name: &str, plans: &[CountRollupSql]) {
    assert_eq!(plans.len(), 1, "the probe corpus must fit one plan chunk");
    let plan = &plans[0];
    let value = serde_json::json!({
        "sql": plan.sql,
        "params": plan.params,
        "parts": plan.parts,
        "remote_parts": plan.remote_parts,
    });
    std::fs::write(out.join(name), serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

#[derive(serde::Deserialize)]
struct ManifestIdentity {
    tenant_id: String,
    event_snapshot_id: i64,
    object_stamp_sha256: String,
    rollup_version: String,
    objects: Vec<ManifestObject>,
}

#[derive(serde::Deserialize)]
struct ManifestObject {
    relative_path: String,
    min_bucket_start_us: i64,
    max_bucket_start_us: i64,
    bytes: u64,
    sha256: String,
}

#[test]
#[ignore = "requires a mirrored object store, real rollup data, and the NANO_TIER_E2E_* environment"]
fn tiered_rollup_with_no_local_parts_plans_direct_reads_and_hydrates_real_bytes() {
    let data = PathBuf::from(env("NANO_TIER_E2E_DATA"));
    let out = PathBuf::from(env("NANO_TIER_E2E_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let manifest: ManifestIdentity =
        serde_json::from_slice(&std::fs::read(data.join("manifest.json")).unwrap()).unwrap();
    let start_us = manifest
        .objects
        .iter()
        .map(|object| object.min_bucket_start_us)
        .min()
        .unwrap();
    let end_exclusive_us = manifest
        .objects
        .iter()
        .map(|object| object.max_bucket_start_us)
        .max()
        .unwrap()
        + COUNT_ROLLUP_BUCKET_US;
    assert_eq!(start_us.rem_euclid(COUNT_ROLLUP_BUCKET_US), 0);
    let tenant = tenant();
    let plan = |rollup: &CountRollup| {
        rollup
            .plan(
                &tenant,
                "metadata.log_source",
                true,
                None,
                None,
                start_us,
                end_exclusive_us,
                None,
                &BTreeSet::new(),
            )
            .unwrap()
    };

    // 1. Baseline: the pristine all-local strict load, exactly today's path.
    let strict = CountRollup::load(
        LoadedCountRollupConfig {
            manifest: data.join("manifest.json"),
            data_directory: data.clone(),
        },
        &manifest.tenant_id,
        manifest.event_snapshot_id,
        &manifest.object_stamp_sha256,
    )
    .unwrap();
    let baseline = plan(&strict);
    assert_eq!(baseline[0].remote_parts, 0);
    write_plan(&out, "baseline.json", &baseline);

    // 2. Evict EVERY part locally; keep only the manifest.
    let evicted_root = tempfile::TempDir::new().unwrap();
    let evicted = evicted_root.path().join("count-rollup");
    std::fs::create_dir(&evicted).unwrap();
    std::fs::copy(data.join("manifest.json"), evicted.join("manifest.json")).unwrap();

    // 3. Tier over the REAL store.
    let (operator, prefix) = open_upload_store(&env("NANO_TIER_E2E_STORE")).unwrap();
    let store = Arc::new(OpendalArtifactStore::with_prefix(operator, &prefix));
    let cache_directory = evicted_root.path().join("tier-cache");
    let tier = DerivativeTier::new(
        &env("NANO_TIER_E2E_ENGINE_URL"),
        &cache_directory,
        64 * 1024 * 1024,
        store,
    )
    .unwrap();

    let tiered = CountRollup::load_tiered(
        LoadedCountRollupConfig {
            manifest: evicted.join("manifest.json"),
            data_directory: evicted.clone(),
        },
        &manifest.tenant_id,
        manifest.event_snapshot_id,
        &manifest.object_stamp_sha256,
        Some(tier.clone()),
    )
    .expect("a fully evicted rollup must still load through the tier");
    let cold = plan(&tiered);
    // Every part is a cache miss: all planned as DIRECT object reads —
    // none dropped, none blocking on hydration.
    assert_eq!(cold[0].parts, manifest.objects.len());
    assert_eq!(cold[0].remote_parts, manifest.objects.len());
    assert!(cold[0].sql.contains("s3("));
    write_plan(&out, "tiered.json", &cold);

    // 4. Hydrate one real artifact synchronously through the digest fence
    //    and prove the cache then serves it pinned.
    let sample = &manifest.objects[0];
    let artifact = ArtifactRef::new(
        "count-rollup",
        &manifest.rollup_version,
        &sample.sha256,
        sample.bytes,
    )
    .unwrap();
    tier.hydrate_blocking(&artifact)
        .expect("hydrating a mirrored artifact from the real store");
    let pin = tier.pin(&artifact).expect("hydrated artifact must be pinned");
    let bytes = std::fs::read(pin.path()).unwrap();
    assert_eq!(bytes.len() as u64, sample.bytes);
    assert_eq!(
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes)),
        sample.sha256,
        "cached bytes must be the fenced originals"
    );
    assert_eq!(
        std::fs::read(data.join(&sample.relative_path)).unwrap(),
        bytes,
        "round trip through the store must reproduce the source part exactly"
    );
    drop(pin);

    // 5. A warm plan mixes pinned cache hits with direct reads.
    let warm = plan(&tiered);
    assert!(warm[0].remote_parts < cold[0].remote_parts);
    assert!(!warm[0].pins.is_empty());
    write_plan(&out, "warm.json", &warm);
}
