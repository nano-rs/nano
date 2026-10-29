// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use nanosiem_lake_cell::budget::{GIB, MIB};
use nanosiem_lake_cell::{landing_budget, trusted_local};

/// Render through the production initializer, read its actual Compose
/// limit, then give that container limit to the production runtime model.
fn rendered_limits(memory: u64, cpus: u32) -> (usize, u64) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("proc")).unwrap();
    std::fs::create_dir_all(root.path().join("sys/devices/system/cpu")).unwrap();
    std::fs::write(
        root.path().join("proc/meminfo"),
        format!("MemTotal: {} kB\n", memory / 1024),
    )
    .unwrap();
    std::fs::write(
        root.path().join("sys/devices/system/cpu/online"),
        format!("0-{}", cpus - 1),
    )
    .unwrap();
    let out = root.path().join("out");
    trusted_local::init(
        &trusted_local::InitArgs {
            out: out.clone(),
            host_root: root.path().into(),
            chdb_sha256: Some("a".repeat(64)),
            ..Default::default()
        },
        &|name| match name {
            "NANO_LAKE_ACCESS_KEY_ID" => Some("test-access".into()),
            "NANO_LAKE_SECRET_ACCESS_KEY" => Some("test-secret".into()),
            _ => None,
        },
    )
    .unwrap();
    let rendered: Value =
        serde_json::from_slice(&std::fs::read(out.join("compose.resources.json")).unwrap())
            .unwrap();
    let services = rendered["services"].as_object().unwrap();
    let total: u64 = services
        .values()
        .map(|s| s["mem_limit"].as_u64().unwrap())
        .sum();
    assert!(total <= memory / 100 * 95, "render must retain OS headroom");
    let landing = &services["lean-landing"];
    let container_memory = landing["mem_limit"].as_u64().unwrap();
    assert_eq!(landing["memswap_limit"], container_memory);
    let cpu_millis = landing["cpus"].as_u64().unwrap() as u32 * 1000;
    let limits = bucket_drop_limits(container_memory, cpu_millis);
    assert!(
        limits.0 >= 1,
        "supported host must fit a converter: {container_memory}"
    );
    assert!(limits.1 >= limits.0 as u64 * MAX_LANDING_BYTES);
    assert!(landing_budget::memory_for_lanes(limits.0) <= container_memory);
    println!(
        "NAN4844_RENDER host_mib={} cpus={cpus} landing_mib={} lanes={} flight_mib={}",
        memory / MIB,
        container_memory / MIB,
        limits.0,
        limits.1 / MIB
    );
    limits
}

#[test]
fn nan4844_production_render_and_runtime_agree_on_8_16_32_gib() {
    for memory in [8 * GIB, 16 * GIB, 32 * GIB] {
        for cpus in [4, 8, 16, 64] {
            rendered_limits(memory, cpus);
        }
    }
    // Mythos: Docker exposes 15,965 MiB on its nominal 16 GiB host.
    assert!(rendered_limits(15_965 * MIB, 8).0 >= 2);
}

struct RendezvousEmit {
    barrier: tokio::sync::Barrier,
}

#[async_trait]
impl Emit for RendezvousEmit {
    async fn emit(
        &self,
        store: &Operator,
        tenant: &str,
        candidate: &Candidate,
        converted: &Converted,
    ) -> Result<String> {
        // If byte admission silently serializes the advertised lanes, the
        // first emit times out while the next file never gets to convert.
        tokio::time::timeout(std::time::Duration::from_secs(15), self.barrier.wait()).await?;
        BronzeObjects
            .emit(store, tenant, candidate, converted)
            .await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nan4844_mythos_40_mib_objects_overlap_through_the_engine() {
    let limits = rendered_limits(15_965 * MIB, 8);
    assert!(
        limits.0 >= 2,
        "Mythos must convert more than one file at a time"
    );
    let store = Operator::new(opendal::services::Memory::default())
        .unwrap()
        .finish();
    for file in 0..limits.0 {
        let mut body = ndjson(&[sysmon(Some(&format!("mythos:{file}")), file as i64)]);
        // Keep this admission regression cheap: valid OCSF followed by
        // whitespace lines has the real reported wire size, without a
        // throughput benchmark's hundreds of thousands of VRL evaluations.
        let rows_end = body.len();
        body.resize(40 * MIB as usize, b' ');
        for line in body[rows_end..].chunks_mut(1024) {
            *line.last_mut().unwrap() = b'\n';
        }
        store
            .write(&key(&format!("mythos/{file}.ndjson")), body)
            .await
            .unwrap();
    }
    let ledger = MemoryLedger {
        sources: vec![source()],
        ..Default::default()
    };
    let discover = PrefixDiscover { ledger: &ledger };
    let (_, candidates) = discover.discover(&store, TENANT, limits.0).await.unwrap();
    assert_eq!(candidates.len(), limits.0);
    assert!(candidates
        .iter()
        .all(|candidate| candidate.size == 40 * MIB));
    let emit = RendezvousEmit {
        barrier: tokio::sync::Barrier::new(limits.0),
    };
    let report = Engine {
        store: &store,
        discover: &discover,
        emit: &emit,
        stage: &stage(),
        tenant_id: TENANT,
        max_files_per_tick: limits.0,
    }
    .tick_with_limits(limits)
    .await
    .unwrap();
    assert_eq!(report.accepted, limits.0, "{report:?}");
    assert_eq!(report.failed, 0, "{report:?}");
    assert!(keys_under(&store, LANDING_PREFIX).await.is_empty());
}

#[tokio::test]
async fn nan4844_insufficient_memory_fails_before_claiming_or_deleting() {
    let store = Operator::new(opendal::services::Memory::default())
        .unwrap()
        .finish();
    let landed = key("still-owned.ndjson");
    store
        .write(&landed, ndjson(&[sysmon(Some("held"), 1)]))
        .await
        .unwrap();
    let ledger = MemoryLedger {
        sources: vec![source()],
        ..Default::default()
    };
    let discover = PrefixDiscover { ledger: &ledger };
    let error = Engine {
        store: &store,
        discover: &discover,
        emit: &BronzeObjects,
        stage: &stage(),
        tenant_id: TENANT,
        max_files_per_tick: 4,
    }
    .tick_with_limits(bucket_drop_limits(
        landing_budget::memory_for_lanes(1) - 1,
        8000,
    ))
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("cannot fit one maximum-size object"));
    assert!(ledger.files.lock().unwrap().is_empty());
    assert!(store.exists(&landed).await.unwrap());
}

#[test]
fn nan4844_conversion_heap_fits_the_shared_lane_model() {
    let file = crate::landing_fixture::tenzir_auth_parquet(
        "budget",
        50_000,
        Utc::now().timestamp_millis(),
    );
    let stage = stage();
    let _serial = crate::test_heap::MEASUREMENT
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    crate::test_heap::track_current_thread(true);
    let base = crate::test_heap::reset_peak();
    // Synchronous conversion on the tracked thread includes the actual VRL,
    // decode and bronze writer allocations, including retained output.
    let converted = convert_file(
        &file,
        FileFormat::Parquet,
        &stage,
        TENANT,
        &source(),
        Utc::now(),
    );
    let peak = crate::test_heap::peak() - base;
    crate::test_heap::track_current_thread(false);
    assert_eq!(converted.unwrap().rows_accepted, 50_000);
    let bound = landing_budget::CONVERSION_FIXED_BYTES
        + landing_budget::CONVERSION_WIRE_COPIES * file.len() as u64;
    println!(
        "NAN4844_HEAP input_bytes={} peak_bytes={peak} bound_bytes={bound}",
        file.len()
    );
    assert!(
        peak <= bound as isize,
        "converter exceeded the sizing model"
    );
}
