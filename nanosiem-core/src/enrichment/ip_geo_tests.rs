// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

/// Migration 185, with the `src_ip` lookup the UDM `enriched_src_country`
/// column now uses. The Rust form must stay byte-identical to it.
const MIGRATION_185: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../clickhouse/185_ip_geo_dict_split.sql"
));

#[test]
fn geo_attr_expr_matches_migration_185_columns() {
    for attr in IP_GEO_ATTRIBUTES {
        for ip in ["src_ip", "dest_ip"] {
            let expr = geo_attr_expr(attr, ip);
            assert!(
                MIGRATION_185.contains(&format!("MATERIALIZED {expr} CODEC(ZSTD(1))")),
                "migration 185 has no column using {expr}"
            );
        }
    }
}

#[test]
fn geo_attr_expr_never_touches_the_old_dictionary() {
    let expr = geo_attr_expr("country", "ip");
    assert!(!expr.contains("ip_enrichment_dict"), "{expr}");
    assert!(
        expr.contains("toIPv4OrDefault(ip)") && expr.contains("toIPv6OrDefault(ip)"),
        "{expr}"
    );
}

#[test]
fn reload_order_is_attrs_then_trie_and_honors_on_cluster() {
    assert_eq!(
        reload_statements(""),
        vec![
            "SYSTEM RELOAD DICTIONARY nanosiem.ip_geo_attrs_dict".to_string(),
            "SYSTEM RELOAD DICTIONARY nanosiem.ip_geo_trie_dict".to_string(),
        ]
    );
    assert_eq!(
        reload_statements(" ON CLUSTER 'c'")[1],
        "SYSTEM RELOAD DICTIONARY ON CLUSTER 'c' nanosiem.ip_geo_trie_dict"
    );
}

#[test]
fn refresh_view_is_node_local_because_clickhouse_rejects_on_cluster() {
    assert_eq!(
        refresh_view_statement("nanosiem.ip_enrichment_dict_refresh"),
        "SYSTEM REFRESH VIEW nanosiem.ip_enrichment_dict_refresh"
    );
}

#[test]
fn clustered_refresh_endpoints_are_http_only_trimmed_and_deduplicated() {
    assert_eq!(
        refresh_endpoints(" http://ch-0:8123,https://ch-1:8443,http://ch-0:8123 ").unwrap(),
        vec!["http://ch-0:8123", "https://ch-1:8443"]
    );
    assert!(refresh_endpoints("tcp://ch-0:9000").is_err());
    assert!(refresh_endpoints(" , ").is_err());
}

#[test]
fn stale_trie_is_reloaded_not_loaded_one_is_left_lazy() {
    // Loaded before the last staging refresh -> reload the pair.
    assert!(needs_reload("LOADED", "", 100, 200));
    // Loaded after it -> nothing to do.
    assert!(!needs_reload("LOADED", "", 300, 200));
    // A load error (e.g. 241 during a reload) -> retry.
    assert!(needs_reload("LOADED", "Code: 241", 300, 200));
    assert!(needs_reload("FAILED", "", 300, 200));
    // Never loaded: the first lookup loads both halves from current staging.
    assert!(!needs_reload("NOT_LOADED", "", 0, 200));
    assert!(!needs_reload("", "", 0, 200));
}

#[test]
fn stale_probe_reads_the_trie_and_the_staging_refresh() {
    assert!(STALE_PROBE_SQL.contains("name = 'ip_geo_trie_dict'"));
    assert!(STALE_PROBE_SQL.contains("view = 'ip_enrichment_dict_refresh'"));
}
