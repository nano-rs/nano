// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4976: what a HEC indexer ackId means, pinned at render time.
//!
//! The OOTB `splunk_hec_ingest` source runs with `acknowledgements.enabled`, so
//! an event POST carrying `X-Splunk-Request-Channel` answers an `ackId` that
//! `/services/collector/ack` reports true once EVERY sink the event reached has
//! finalized it. Vector finalizes a disk-buffered event when it is written to
//! the buffer, a memory-buffered one only after the sink's INSERT. So:
//!
//! * every ClickHouse sink on the event path is disk-buffered: an ackId means
//!   "committed to the durable buffer in front of ClickHouse" on every lane
//!   (raw, parsed, UDM, OCSF). A memory-buffered telemetry sink (the old
//!   `clickhouse_parser_health`) held parsed events' acks until its INSERT and
//!   expired them Errored after a long outage, so senders re-sent duplicates;
//! * all block at capacity (NAN-5004): `drop_newest` finalizes as Dropped and
//!   Vector's source aggregator treats Dropped as Delivered;
//! * the static seed `_pipeline.toml` matches the generated sinks.

use super::*;

const HEC_SOURCE: &str = include_str!("../../../../../config/vector/02-hec-source.toml");
const SEED_PIPELINE: &str = include_str!("../../../../../config/vector/sources/parsers/_pipeline.toml");

fn load(raw: &str) -> toml::Table {
    toml::from_str(&crate::vector_env::substitute_like_vector(raw))
        .unwrap_or_else(|e| panic!("not valid TOML after substitution: {e}\n{raw}"))
}

fn parser(name: &str) -> Parser {
    Parser {
        id: uuid::Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: name.to_string(),
        parser_vrl: ".parsed = true".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: Some(vec![format!("{name}_key")]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

/// Every sink the deploy renders for the event pipeline under `ocsf`, with
/// one enabled parser (so the parser-health branch and the OCSF fork exist).
fn rendered_event_sinks(ocsf: bool) -> toml::Table {
    let parsers = [parser("acme")];
    let mut docs = vec![
        VectorConfigManager::pipeline_config_content().to_string(),
        VectorConfigManager::combiner_config_content_for(&parsers, ocsf),
    ];
    if ocsf {
        docs.push(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK.to_string());
        let inputs = VectorConfigManager::ocsf_sink_inputs_for(true, &parsers);
        docs.push(VectorConfigManager::ocsf_sink_content(&inputs));
    }
    let mut sinks = toml::Table::new();
    for raw in docs {
        if let Some(t) = load(&raw).get("sinks").and_then(|v| v.as_table()) {
            sinks.extend(t.clone());
        }
    }
    sinks
}

#[test]
fn hec_source_enables_indexer_acknowledgements() {
    let doc = load(HEC_SOURCE);
    let src = doc["sources"]["splunk_hec_ingest"].as_table().expect("splunk_hec_ingest");
    assert_eq!(src["type"].as_str(), Some("splunk_hec"));
    assert_eq!(
        src.get("acknowledgements").and_then(|a| a.get("enabled")).and_then(|v| v.as_bool()),
        Some(true),
        "without source acks the ack route answers 400 (AckIsDisabled) and no ackId is issued"
    );
    // Auth stays on the per-source token store: the ack route runs the same
    // authorization filter as the event route.
    assert!(src.get("valid_tokens_file").is_some(), "per-source tokens file must stay configured");
    let acks = src["acknowledgements"].as_table().expect("acknowledgement bounds");
    assert_eq!(acks["max_pending_acks"].as_integer(), Some(100_000));
    assert_eq!(acks["max_number_of_ack_channels"].as_integer(), Some(10_000));
    assert_eq!(acks["max_pending_acks_per_channel"].as_integer(), Some(10_000));
    assert_eq!(acks["ack_idle_cleanup"].as_bool(), Some(true));
    assert_eq!(acks["max_idle_time"].as_integer(), Some(300));
}

#[test]
fn vector_hec_has_no_post_ack_admission_drop() {
    let doc = load(HEC_SOURCE);
    let transforms = doc["transforms"].as_table().expect("HEC transforms");
    let input = |name: &str| {
        transforms[name]["inputs"]
            .as_array()
            .and_then(|values| values.first())
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| panic!("{name} has one input"))
    };
    assert_eq!(input("hec_normalize"), "splunk_hec_ingest");
    for name in [
        "hec_admission_prep",
        "hec_rate_limit_credential",
        "hec_rate_limit_client",
        "hec_rate_limit_global",
        "hec_admission_cleanup",
    ] {
        assert!(!transforms.contains_key(name), "{name} would drop after Vector allocated an ackId");
    }
}

#[test]
fn every_event_sink_is_disk_buffered_and_blocks_instead_of_dropping() {
    for ocsf in [false, true] {
        let sinks = rendered_event_sinks(ocsf);
        assert!(sinks.contains_key("clickhouse_logs"), "ocsf={ocsf}: {sinks:?}");
        assert!(sinks.contains_key("clickhouse_parser_health"), "ocsf={ocsf}: {sinks:?}");
        if ocsf {
            assert!(sinks.contains_key("clickhouse_ocsf_logs"), "{sinks:?}");
        }
        for (name, def) in &sinks {
            let buffer = def.get("buffer").and_then(|b| b.as_table());
            let ty = buffer.and_then(|b| b.get("type")).and_then(|v| v.as_str());
            let when_full = buffer.and_then(|b| b.get("when_full")).and_then(|v| v.as_str());
            assert_eq!(
                ty,
                Some("disk"),
                "ocsf={ocsf}: sink `{name}` must be disk-buffered, or a HEC ackId on its \
                 events waits for its INSERT (and expires Errored in an outage)"
            );
            assert_eq!(
                when_full,
                Some("block"),
                "ocsf={ocsf}: sink `{name}` must backpressure at capacity, not silently drop (NAN-5004)"
            );
            let size = buffer.and_then(|b| b.get("max_size")).and_then(|v| v.as_integer()).unwrap_or(0);
            assert!(size >= 268_435_488, "ocsf={ocsf}: `{name}` max_size {size} is below Vector's disk minimum");
        }
    }
}

#[test]
fn seed_pipeline_sinks_match_the_generated_ones() {
    let seed = load(SEED_PIPELINE);
    let generated = load(VectorConfigManager::pipeline_config_content());
    for name in ["clickhouse_logs", "clickhouse_parser_health"] {
        assert_eq!(
            seed["sinks"][name], generated["sinks"][name],
            "config/vector/sources/parsers/_pipeline.toml `{name}` drifted from pipeline_config_content()"
        );
    }
}
