// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5287: every disk buffer on an acknowledged ingest path (HEC, HTTP,
//! OTLP logs, push enrichment) renders the operator's acknowledgement durability.
//!
//! nano-rs/vector 0.61.0-nano.10 fsyncs a disk buffer before it acknowledges a
//! record a source waits on (NAN-5285), and adds the per-buffer opt-out
//! `acknowledgement_durability = "fsync" | "page_cache"`. nano renders the
//! value as a literal from `NANO_INGEST_ACK_DURABILITY` in the rendering
//! process (see [`ACK_DURABILITY_ENV`] for why not a Vector `${...}`), so every
//! ingest host installs the same value with the same generation. fsync (the
//! default, and any unset value) renders no key at all: the default config is
//! byte-identical to before, and Vector's default is fsync. Vector rejects the key on a memory buffer, so it must
//! never appear there. The static OTLP trace and metric sinks are not
//! rendered; they keep Vector's default (fsync).

use super::*;

const PAGE_CACHE: &str = "acknowledgement_durability = \"page_cache\"";
const METRICS: &str = include_str!("../../../../../config/vector/92-metrics.toml");

fn endpoints(shards: usize) -> Vec<String> {
    (0..shards)
        .map(|shard| format!("http://clickhouse-shard-{shard}:8123"))
        .collect()
}

/// Every config nano ships or renders that holds a disk buffer, single-shard
/// and shard-expanded.
fn rendered() -> Vec<(String, String)> {
    let parser = super::super::router::builtin_identity_parser(
        &crate::identity::normalizers::BUILTIN_IDENTITY_NORMALIZERS[0],
    );
    let ocsf = VectorConfigManager::ocsf_sink_content(&["\"generic_ocsf_prepare\"".to_string()]);
    let mut out = vec![
        (
            "generated pipeline".to_string(),
            VectorConfigManager::full_pipeline_config_content(),
        ),
        ("OCSF sink".to_string(), ocsf.clone()),
        (
            "static enrichment lane".to_string(),
            VectorConfigManager::static_enrichment_lane(),
        ),
        (
            "generated enrichment lane".to_string(),
            VectorConfigManager::generate_enrichment_lane(&[&parser]),
        ),
    ];
    let shards = endpoints(2);
    out.push((
        "2-shard pipeline".to_string(),
        VectorConfigManager::shard_route_clickhouse_sinks(
            with_ack_durability(VectorConfigManager::pipeline_config_content(), ack_durability()),
            &shards,
        ),
    ));
    out.push((
        "2-shard OCSF sink".to_string(),
        VectorConfigManager::shard_route_clickhouse_sinks(ocsf, &shards),
    ));
    out.push((
        "2-shard enrichment lane".to_string(),
        VectorConfigManager::shard_route_clickhouse_sinks(
            VectorConfigManager::static_enrichment_lane(),
            &shards,
        ),
    ));
    out
}

fn buffers(raw: &str) -> Vec<(String, toml::Table)> {
    let doc: toml::Table = toml::from_str(&crate::vector_env::substitute_like_vector(raw))
        .unwrap_or_else(|e| panic!("not valid TOML after substitution: {e}"));
    let mut out = Vec::new();
    if let Some(sinks) = doc.get("sinks").and_then(toml::Value::as_table) {
        for (name, def) in sinks {
            if let Some(buffer) = def.get("buffer").and_then(toml::Value::as_table) {
                out.push((name.clone(), buffer.clone()));
            }
        }
    }
    out
}

fn with_mode<T>(mode: &'static str, f: impl FnOnce() -> T) -> T {
    ACK_DURABILITY_FORCED.with(|c| c.set(Some(mode)));
    let out = f();
    ACK_DURABILITY_FORCED.with(|c| c.set(None));
    out
}

fn disk_buffers(raw: &str) -> Vec<(String, toml::Table)> {
    buffers(raw)
        .into_iter()
        .filter(|(_, b)| b.get("type").and_then(toml::Value::as_str) == Some("disk"))
        .collect()
}

/// Golden, default (fsync): no disk buffer carries the key, so the rendered
/// config is unchanged and Vector applies its fsync default.
#[test]
fn fsync_default_renders_no_key() {
    for (label, raw) in with_mode("fsync", rendered) {
        assert!(!raw.contains("acknowledgement_durability"), "{label}");
        let disk = disk_buffers(&raw);
        assert!(!disk.is_empty(), "{label}: no disk buffers");
        for (sink, buffer) in disk {
            let mut keys: Vec<&str> = buffer.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["max_size", "type", "when_full"], "{label}: {sink}");
        }
    }
    // Unset is the same render as explicit fsync.
    let unset: Vec<String> = rendered().into_iter().map(|(_, r)| r).collect();
    let fsync: Vec<String> = with_mode("fsync", rendered).into_iter().map(|(_, r)| r).collect();
    assert_eq!(unset, fsync);
}

/// Golden, page_cache: every disk buffer of every renderer (single-shard and
/// shard-expanded, pipeline, OCSF sink, both enrichment lanes) carries it.
#[test]
fn page_cache_renders_on_every_disk_buffer() {
    for (label, raw) in with_mode("page_cache", rendered) {
        let disk = disk_buffers(&raw);
        assert!(!disk.is_empty(), "{label}");
        assert_eq!(raw.matches(PAGE_CACHE).count(), disk.len(), "{label}");
        for (sink, buffer) in disk {
            let mut keys: Vec<&str> = buffer.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["acknowledgement_durability", "max_size", "type", "when_full"],
                "{label}: {sink}"
            );
            assert_eq!(buffer["acknowledgement_durability"].as_str(), Some("page_cache"), "{label}: {sink}");
            assert_eq!(buffer["when_full"].as_str(), Some("block"), "{label}: {sink}");
        }
    }
}

/// Vector refuses `acknowledgement_durability` on a memory buffer; the one
/// memory-buffered sink in the static bundle must stay without it.
#[test]
fn memory_buffers_never_carry_the_durability_setting() {
    assert!(!METRICS.contains("acknowledgement_durability"));
    for (label, raw) in with_mode("page_cache", rendered) {
        for (sink, buffer) in buffers(&raw) {
            if buffer.get("type").and_then(toml::Value::as_str) == Some("memory") {
                assert!(
                    !buffer.contains_key("acknowledgement_durability"),
                    "{label}: memory-buffered {sink} must not set acknowledgement_durability"
                );
            }
        }
    }
}

#[test]
fn only_the_two_modes_render_and_anything_else_is_fsync() {
    assert_eq!(ack_durability_from(None), "fsync");
    assert_eq!(ack_durability_from(Some("")), "fsync");
    assert_eq!(ack_durability_from(Some("fsync")), "fsync");
    assert_eq!(ack_durability_from(Some(" page_cache ")), "page_cache");
    for bad in ["PAGE_CACHE", "pagecache", "none", "${X}"] {
        assert_eq!(ack_durability_from(Some(bad)), "fsync", "{bad}");
    }
    // The line goes after a blocking buffer's when_full line only.
    let raw = "x = \"block\"\nwhen_full = \"block\"\nwhen_full = \"drop_newest\"\n";
    assert_eq!(
        with_ack_durability(raw, "page_cache"),
        "x = \"block\"\nwhen_full = \"block\"\nacknowledgement_durability = \"page_cache\"\nwhen_full = \"drop_newest\"\n"
    );
    assert_eq!(with_ack_durability(raw, "fsync"), raw);
}

/// Every process that renders Vector config gets the setting from one place:
/// both Compose files forward it to nano-api and nano-jobs (default fsync), and
/// the chart sets it on every api and jobs pod from one validated value.
#[test]
fn every_renderer_receives_the_setting() {
    fn repo_file(path: &str) -> Option<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join(path);
        path.exists()
            .then(|| std::fs::read_to_string(&path).expect("read repo file"))
    }
    let line = "NANO_INGEST_ACK_DURABILITY: ${NANO_INGEST_ACK_DURABILITY:-fsync}";
    if let Some(text) = repo_file("docker-compose.opensource.yml") {
        let anchor = text
            .split("x-nano-vector-render-env: &nano-vector-render-env")
            .nth(1)
            .and_then(|rest| rest.split("\n\n").next())
            .expect("x-nano-vector-render-env anchor");
        assert!(anchor.contains(line), "open-core api/jobs render env lacks {line}");
    }
    if let Some(text) = repo_file("docker-compose.yml") {
        assert!(text.contains(line), "docker-compose.yml nano-api lacks {line}");
    }
    if let Some(helm) = repo_file("deploy/helm/nano/templates/_helpers.tpl") {
        assert!(helm.contains("- name: NANO_INGEST_ACK_DURABILITY"));
        assert!(helm.contains("vector.ackDurability must be fsync or page_cache"));
    }
}
