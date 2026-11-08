// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4957: dictionary memory in SIEM Health.

use super::*;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

fn dict(name: &str, layout: &str, bytes: u64) -> DictionaryMemory {
    DictionaryMemory {
        name: name.to_string(),
        layout: layout.to_string(),
        status: "LOADED".to_string(),
        element_count: 1,
        bytes_allocated: bytes,
    }
}

/// The 4G box before migration 185: the 1.32 GiB IP trie plus the prevalence
/// caches against a 3.2 GiB server limit.
fn before_185() -> InsertIntegrityMetrics {
    let dictionary_memory = vec![
        dict("nanosiem.ip_enrichment_dict", "Trie", 1352 * MIB),
        dict("nanosiem.ip_prevalence_dict", "ComplexKeyCache", 320 * MIB),
        dict("nanosiem.ioc_enrichment_dict", "ComplexKeyHashed", 122 * MIB),
    ];
    InsertIntegrityMetrics {
        probes_available: true,
        dictionary_bytes_total: dictionary_memory.iter().map(|d| d.bytes_allocated).sum(),
        dictionary_memory,
        server_memory_limit_bytes: 3 * GIB + 205 * MIB,
        dictionary_memory_probe_ok: true,
        ..Default::default()
    }
}

/// The same box after migration 185.
fn after_185() -> InsertIntegrityMetrics {
    let dictionary_memory = vec![
        dict("nanosiem.ip_prevalence_dict", "ComplexKeyCache", 320 * MIB),
        dict("nanosiem.ip_geo_trie_dict", "Trie", 202 * MIB),
        dict("nanosiem.ioc_enrichment_dict", "ComplexKeyHashed", 122 * MIB),
        dict("nanosiem.ip_geo_attrs_dict", "Hashed", 50 * MIB),
    ];
    InsertIntegrityMetrics {
        dictionary_bytes_total: dictionary_memory.iter().map(|d| d.bytes_allocated).sum(),
        dictionary_memory,
        ..before_185()
    }
}

#[test]
fn large_dictionaries_on_a_small_box_are_a_high_finding() {
    let ii = before_185();
    assert_eq!(dictionary_memory_share_pct(&ii), Some(54));
    let recs = insert_integrity_recommendations(&ii);
    let rec = recs
        .iter()
        .find(|r| r.title.contains("dictionaries hold"))
        .expect("dictionary memory finding");
    assert_eq!(rec.priority, "high");
    assert!(rec.title.contains("54%"), "{}", rec.title);
    assert!(
        rec.description.contains("nanosiem.ip_enrichment_dict (Trie, 1352 MiB)"),
        "{}",
        rec.description
    );
}

#[test]
fn split_geo_dictionaries_clear_the_finding() {
    let ii = after_185();
    assert_eq!(dictionary_memory_share_pct(&ii), Some(21));
    assert!(insert_integrity_recommendations(&ii)
        .iter()
        .all(|r| !r.title.contains("dictionaries hold")));
}

#[test]
fn medium_between_warn_and_high() {
    let mut ii = after_185();
    ii.dictionary_bytes_total = ii.server_memory_limit_bytes * 40 / 100;
    let recs = insert_integrity_recommendations(&ii);
    let rec = recs.iter().find(|r| r.title.contains("dictionaries hold")).expect("finding");
    assert_eq!(rec.priority, "medium");
}

#[test]
fn unmeasured_memory_never_warns() {
    let mut no_grant = before_185();
    no_grant.dictionary_memory_probe_ok = false;
    assert_eq!(dictionary_memory_share_pct(&no_grant), None);
    let mut no_limit = before_185();
    no_limit.server_memory_limit_bytes = 0;
    assert_eq!(dictionary_memory_share_pct(&no_limit), None);
    for ii in [no_grant, no_limit] {
        assert!(insert_integrity_recommendations(&ii)
            .iter()
            .all(|r| !r.title.contains("dictionaries hold")));
    }
}

#[test]
fn high_share_drags_the_ingestion_score() {
    let mut m = IngestionMetrics {
        source_volumes: vec![SourceVolumeMetric {
            source_type: "windows_event".to_string(),
            count_24h: 1_000,
            count_prior_24h: 1_000,
            change_pct: 0.0,
        }],
        total_events_24h: 1_000,
        total_events_prior_24h: 1_000,
        silent_sources: vec![],
        insert_integrity: after_185(),
    };
    let healthy = score_ingestion(&m);
    m.insert_integrity = before_185();
    assert_eq!(score_ingestion(&m), healthy - 10);
}

#[test]
fn reports_stored_before_nan_4957_deserialize() {
    let old_json = r#"{
        "probes_available": true, "logs_inserts_1h": 1, "new_parts_1h": 1,
        "memory_limit_errors": 0, "cache_dictionary_update_fails": 0,
        "failed_logs_dictionaries": [], "async_insert_failures_1h": null,
        "last_async_insert_error": null
    }"#;
    let ii: InsertIntegrityMetrics = serde_json::from_str(old_json).expect("old report");
    assert!(!ii.dictionary_memory_probe_ok);
    assert!(ii.dictionary_memory.is_empty());
    assert_eq!(dictionary_memory_share_pct(&ii), None);
}

#[test]
fn finding_gives_the_feed_sizing_advice() {
    let recs = insert_integrity_recommendations(&before_185());
    let rec = recs.iter().find(|r| r.title.contains("dictionaries hold")).expect("finding");
    assert!(rec.description.contains("requires 6 GB for ClickHouse"), "{}", rec.description);
    assert!(!rec.description.contains("recommended"), "{}", rec.description);
    assert!(rec.description.contains("CLICKHOUSE_MEM_LIMIT=6G"), "{}", rec.description);
}
