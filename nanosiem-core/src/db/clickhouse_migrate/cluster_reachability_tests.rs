// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

fn replica(shard_num: u32, replica_num: u32, host: &str) -> ClusterReplica {
    ClusterReplica {
        shard_num,
        replica_num,
        host_name: host.to_string(),
        port: 9000,
    }
}

fn two_by_two(reachable: &[u32]) -> Reachability {
    Reachability {
        replicas: vec![
            replica(1, 1, "ch-1a"),
            replica(1, 2, "ch-1b"),
            replica(2, 1, "ch-2a"),
            replica(2, 2, "ch-2b"),
        ],
        reachable: reachable.iter().copied().collect(),
    }
}

#[test]
fn probes_skip_dead_replicas_and_follow_cluster_order() {
    assert_eq!(
        reachable_ordinals_sql("default"),
        "SELECT shardNum() FROM clusterAllReplicas('default', system.one) SETTINGS skip_unavailable_shards = 1"
    );
    assert_eq!(
        cluster_replicas_sql("o'brien"),
        "SELECT shard_num, replica_num, host_name, port FROM system.clusters WHERE cluster = 'o''brien' ORDER BY shard_num, replica_num"
    );
}

#[test]
fn healthy_cluster_reports_nothing_unreachable() {
    let healthy = two_by_two(&[1, 2, 3, 4]);
    assert!(healthy.all_reachable());
    assert!(healthy.unreachable().is_empty());
    assert_eq!(healthy.describe(), "4/4 replicas reachable");
}

#[test]
fn down_replica_is_named_by_its_configured_address() {
    let degraded = two_by_two(&[1, 2, 3]);
    assert!(!degraded.all_reachable());
    assert_eq!(degraded.unreachable(), vec![&replica(2, 2, "ch-2b")]);
    assert_eq!(
        degraded.describe(),
        "3/4 replicas reachable; unreachable: ch-2b:9000 (shard 2, replica 2)"
    );
}

#[test]
fn an_empty_cluster_listing_is_never_all_reachable() {
    let empty = Reachability {
        replicas: Vec::new(),
        reachable: HashSet::new(),
    };
    assert!(!empty.all_reachable());
}

#[test]
fn only_explicit_non_cloud_clusters_fan_out() {
    assert_eq!(explicit_cluster(Some("default"), "nanosiem", false), Some("default"));
    assert_eq!(explicit_cluster(Some("default"), "nanosiem", true), None);
    assert_eq!(explicit_cluster(Some("nanosiem"), "nanosiem", false), None);
    assert_eq!(explicit_cluster(None, "nanosiem", false), None);
}

#[test]
fn nothing_to_ensure_only_when_every_reachable_replica_has_every_object() {
    // 3 reachable replicas x 4 tracking tables.
    assert!(present_on_every_reachable_replica(3, 4, 12));
    // One reachable replica lacks a table: run the full bootstrap.
    assert!(!present_on_every_reachable_replica(3, 4, 11));
    // Blank cluster.
    assert!(!present_on_every_reachable_replica(3, 4, 0));
    // A replica came back between the two probes: be conservative.
    assert!(!present_on_every_reachable_replica(3, 4, 16));
    // Degenerate inputs never skip.
    assert!(!present_on_every_reachable_replica(0, 4, 0));
    assert!(!present_on_every_reachable_replica(3, 0, 0));
}
