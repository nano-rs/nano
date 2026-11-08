// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn baseline_contract_contains_every_fresh_seed_once() {
    let migrations = ClickHouseMigrator::baseline_migrations().expect("valid baseline contract");
    let versions: HashSet<_> = migrations
        .iter()
        .map(|migration| migration.version.as_str())
        .collect();

    assert_eq!(migrations.len(), 45);
    assert_eq!(versions.len(), migrations.len());
    for required in ["109", "110", "111", "112", "168", "169"] {
        assert!(versions.contains(required), "missing baseline {required}");
    }
}

#[test]
fn revision_queue_compacts_by_logical_key_in_every_topology() {
    assert_eq!(
        replacing_revision_engine("MergeTree"),
        "ReplacingMergeTree(revision)"
    );
    assert_eq!(
        replacing_revision_engine("ReplicatedMergeTree()"),
        "ReplicatedReplacingMergeTree(revision)"
    );
    assert_eq!(
        replacing_revision_engine("ReplicatedMergeTree('/path', '{replica}')"),
        "ReplicatedReplacingMergeTree('/path', '{replica}', revision)"
    );
}

#[test]
fn global_auxiliary_tables_get_independent_replication_paths() {
    assert_eq!(
        global_table_engine(
            "ReplicatedMergeTree('/clickhouse/tables/nanosiem/_migrations', '{replica}')",
            "_future_timestamp_repair_set"
        ),
        "ReplicatedMergeTree('/clickhouse/tables/nanosiem/_future_timestamp_repair_set', '{replica}')"
    );
    assert_eq!(
        global_table_engine(
            "ReplicatedMergeTree('/clickhouse/tables/nanosiem/_migrations', '{replica}')",
            "_future_timestamp_ip_repair_rows"
        ),
        "ReplicatedMergeTree('/clickhouse/tables/nanosiem/_future_timestamp_ip_repair_rows', '{replica}')"
    );
}
