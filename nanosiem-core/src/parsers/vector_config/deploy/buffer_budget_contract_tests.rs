// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregate Vector disk-buffer budget contract (P0 launch gate).

use super::*;
use std::collections::HashMap;
use std::process::Command;

fn static_vector_graph() -> String {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("config/vector");
    let mut files: Vec<_> = std::fs::read_dir(directory)
        .expect("read static Vector config")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("toml"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|path| std::fs::read_to_string(path).expect("read static Vector TOML"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn endpoints(shards: usize) -> Vec<String> {
    (0..shards)
        .map(|shard| format!("http://clickhouse-shard-{shard}:8123"))
        .collect()
}

fn full_ocsf_graph(shards: usize) -> String {
    let endpoints = endpoints(shards);
    let mut pipeline = VectorConfigManager::pipeline_config_content().to_string();
    pipeline.push_str(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK);
    let pipeline = VectorConfigManager::shard_route_clickhouse_sinks(pipeline, &endpoints);
    let ocsf = VectorConfigManager::shard_route_clickhouse_sinks(
        VectorConfigManager::ocsf_sink_content(&["\"generic_ocsf_prepare\"".to_string()]),
        &endpoints,
    );
    let enrichment = VectorConfigManager::shard_route_clickhouse_sinks(
        VectorConfigManager::static_enrichment_lane(),
        &endpoints,
    );
    format!(
        "{}\n{pipeline}\n{ocsf}\n{enrichment}",
        static_vector_graph()
    )
}

fn sized(cpu: u32, memory_mib: u32, capacity: u64, shards: usize) -> HashMap<String, u64> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let output = Command::new("bash")
        .arg(root.join("scripts/lib/resource-sizing.sh"))
        .args([
            "--cpu",
            &cpu.to_string(),
            "--memory-mib",
            &memory_mib.to_string(),
            "--topology",
            "role",
            "--roles",
            "ingest",
            "--shards",
            &shards.to_string(),
            "--vector-data-capacity-bytes",
            &capacity.to_string(),
            "--format",
            "env",
        ])
        .output()
        .expect("run resource sizer");
    assert!(
        output.status.success(),
        "resource sizer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("sizer output is UTF-8")
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            value.parse().ok().map(|value| (key.to_string(), value))
        })
        .collect()
}

#[test]
fn rendered_graph_fits_aggregate_budget_across_host_classes() {
    // Exact vm-final5 evidence plus representative small/medium/large hosts.
    let cases = [
        ("small", 2, 4096, 17_179_869_184, 1),
        ("vm-final5", 4, 15_987, 67_049_664_512, 2),
        ("medium", 8, 32_768, 137_438_953_472, 2),
        ("large", 16, 65_536, 549_755_813_888, 4),
    ];

    let minimum = vector_disk_buffer_contract_value("VECTOR_DISK_BUFFER_MIN_BYTES") as u64;
    let static_count = vector_disk_buffer_contract_value("VECTOR_DISK_BUFFER_STATIC_COUNT") as u64;
    let sharded_count =
        (vector_disk_buffer_contract_value("VECTOR_DISK_BUFFER_PIPELINE_SHARDED_COUNT")
            + vector_disk_buffer_contract_value("VECTOR_DISK_BUFFER_ENRICHMENT_SHARDED_COUNT"))
            as u64;

    assert_eq!(minimum, VECTOR_DISK_BUFFER_MIN_BYTES as u64);
    for (name, cpu, memory_mib, capacity, shards) in cases {
        let graph = full_ocsf_graph(shards);
        let actual_count = disk_buffer_component_count(&graph) as u64;
        let expected_count = static_count + sharded_count * shards as u64;
        assert_eq!(
            actual_count, expected_count,
            "{name}: manifest/render drift"
        );

        let values = sized(cpu, memory_mib, capacity, shards);
        let declared_count = values["VECTOR_DISK_BUFFER_COUNT"];
        let per_component = values["VECTOR_DISK_BUFFER_MAX_BYTES"];
        let budget = values["VECTOR_DISK_BUFFER_TOTAL_BUDGET_BYTES"];
        let headroom = values["VECTOR_DISK_HEADROOM_BYTES"];
        assert_eq!(declared_count, actual_count, "{name}: sizer/render drift");
        assert!(per_component >= minimum, "{name}: below Vector minimum");
        assert_eq!(per_component * actual_count, budget, "{name}: wrong sum");
        assert!(budget <= capacity, "{name}: budget exceeds filesystem");
        assert_eq!(
            budget + headroom,
            capacity,
            "{name}: capacity not conserved"
        );

        let rendered = graph.replace(
            "${VECTOR_DISK_BUFFER_MAX_BYTES:-268435488}",
            &per_component.to_string(),
        );
        assert_eq!(
            rendered
                .matches(&format!("max_size = {per_component}"))
                .count() as u64,
            actual_count,
            "{name}: a disk buffer escaped the common allocation"
        );

        if name == "vm-final5" {
            if let Some(directory) = std::env::var_os("NANO_BUFFER_BUDGET_RENDER_DIR") {
                let directory = std::path::PathBuf::from(directory);
                std::fs::create_dir_all(&directory).expect("create render proof directory");
                let endpoints = endpoints(shards);
                let mut pipeline = VectorConfigManager::pipeline_config_content().to_string();
                pipeline.push_str(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK);
                std::fs::write(
                    directory.join("_pipeline.toml"),
                    VectorConfigManager::shard_route_clickhouse_sinks(pipeline, &endpoints),
                )
                .expect("write rendered pipeline");
                std::fs::write(
                    directory.join("_ocsf_sink.toml"),
                    VectorConfigManager::shard_route_clickhouse_sinks(
                        VectorConfigManager::ocsf_sink_content(&[
                            "\"generic_ocsf_prepare\"".to_string()
                        ]),
                        &endpoints,
                    ),
                )
                .expect("write rendered OCSF sink");
                std::fs::write(
                    directory.join("_enrichment.toml"),
                    VectorConfigManager::shard_route_clickhouse_sinks(
                        VectorConfigManager::static_enrichment_lane(),
                        &endpoints,
                    ),
                )
                .expect("write rendered enrichment lane");
                std::fs::write(
                    directory.join("_enrichment_router.toml"),
                    super::super::router::enrichment_router_block(&[], "\"auth_check\""),
                )
                .expect("write rendered enrichment router block");
            }
        }
    }
}

#[test]
fn generated_enrichment_cannot_exceed_manifest_inventory() {
    let lane = format!(
        "{}\n[sinks.future.buffer]\ntype = \"disk\"\nmax_size = 268435488\n",
        VectorConfigManager::static_enrichment_lane()
    );
    let error = VectorConfigManager::guard_enrichment_lane(&[], &lane)
        .expect_err("a fourth enrichment disk buffer must exceed the inventory");
    assert!(
        error.to_string().contains("filesystem budget inventory"),
        "unexpected guard error: {error}"
    );
}
