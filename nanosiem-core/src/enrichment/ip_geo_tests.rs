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

#[test]
fn per_replica_endpoints_win_over_shard_endpoints() {
    // NAN-5215: the refreshed views write node-local staging tables, so every
    // replica needs its own trigger when per-replica endpoints exist.
    assert_eq!(
        refresh_targets(
            Some("http://clickhouse-proxy:18200,http://clickhouse-proxy:18201"),
            Some("http://clickhouse-proxy:18101"),
        )
        .unwrap(),
        RefreshTargets::Replicas(vec![
            "http://clickhouse-proxy:18200".to_string(),
            "http://clickhouse-proxy:18201".to_string(),
        ])
    );
    // The Helm chart's per-replica Services (NAN-5262): every replica of a
    // `replicas: 2` install is triggered, never only the one a shard Service
    // happens to land on.
    assert_eq!(
        refresh_targets(
            Some("http://nano-clickhouse-replica-0-0:8123,http://nano-clickhouse-replica-0-1:8123"),
            Some("http://nano-clickhouse-shard-0:8123"),
        )
        .unwrap(),
        RefreshTargets::Replicas(vec![
            "http://nano-clickhouse-replica-0-0:8123".to_string(),
            "http://nano-clickhouse-replica-0-1:8123".to_string(),
        ])
    );
    // Unset or blank (charts before 2.0.11): the historical per-shard path.
    for replicas in [None, Some(""), Some("  ")] {
        assert_eq!(
            refresh_targets(replicas, Some("http://clickhouse-proxy:18101")).unwrap(),
            RefreshTargets::Shards(vec!["http://clickhouse-proxy:18101".to_string()])
        );
    }
    assert!(refresh_targets(None, None).is_err());
    assert!(refresh_targets(Some("tcp://x:9000"), None).is_err());
}

#[test]
fn wait_probe_covers_only_triggered_replicas_and_skips_dead_ones() {
    let sql = triggered_replicas_probe_sql(
        "default",
        "nanosiem",
        "ip_enrichment_dict_refresh",
        &["ch-1a".to_string(), "o'b".to_string()],
    );
    assert!(sql.contains("FROM clusterAllReplicas('default', system.view_refreshes)"), "{sql}");
    assert!(sql.contains("getMacro('replica') IN ('ch-1a', 'o''b')"), "{sql}");
    assert!(sql.ends_with("SETTINGS skip_unavailable_shards = 1"), "{sql}");
    assert!(sql.contains("database = 'nanosiem' AND view = 'ip_enrichment_dict_refresh'"), "{sql}");
    assert_eq!(sql.matches('?').count(), 2, "{sql}");
}

#[test]
fn only_missing_servers_count_as_unreachable() {
    use clickhouse::error::Error;
    assert!(is_unreachable_replica_error(&Error::TimedOut));
    assert!(is_unreachable_replica_error(&Error::Network("connection refused".into())));
    // The proxy's own gateway error for a dead backend.
    assert!(is_unreachable_replica_error(&Error::BadResponse(
        "<html>502 Bad Gateway</html>".to_string()
    )));
    // A live server rejecting the statement is a real failure.
    assert!(!is_unreachable_replica_error(&Error::BadResponse(
        "Code: 497. DB::Exception: nanosiem_admin: Not enough privileges. (ACCESS_DENIED)".to_string()
    )));
    assert!(!is_unreachable_replica_error(&Error::Custom("x".to_string())));
}
