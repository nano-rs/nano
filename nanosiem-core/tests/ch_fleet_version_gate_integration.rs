// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4934 (codex P1): version-gated per-client settings must be gated on
//! EVERY server the client can reach, not on whichever pod answered one
//! `SELECT version()`.
//!
//! Needs a mixed fleet behind a round-robin load balancer:
//! - a 26.8.36.3 node and a 26.10.3.7 node, both replicas of one cluster in
//!   `remote_servers` (no Keeper needed for `clusterAllReplicas`);
//! - an HTTP round-robin in front of both (nginx `upstream`), passed as
//!   `CH_MIXED_FLEET_URL`, user `default` with no password.
//!
//! Skips unless `CH_MIXED_FLEET_URL` is set. Optionally `CLICKHOUSE_TEST_URL`
//! (a single 26.10 node) checks the single-node fallback.
//!   CH_MIXED_FLEET_URL=http://127.0.0.1:18495 \
//!     cargo test -p nanosiem-core --test ch_fleet_version_gate_integration -- --nocapture

use std::collections::BTreeSet;

use nanosiem_core::db::clickhouse_transport::{
    client, fleet_server_versions, fleet_supports, supports_external_set_spill,
    supports_skip_null_typed_paths,
};

const ROUNDS: usize = 20;
const SPILL_PROBE: &str =
    "SELECT count() FROM numbers(1000) WHERE number IN (SELECT number FROM numbers(500))";

#[tokio::test]
async fn gated_settings_stay_off_while_any_replica_is_old() {
    let Ok(url) = std::env::var("CH_MIXED_FLEET_URL") else {
        eprintln!("Skipping: CH_MIXED_FLEET_URL not set");
        return;
    };
    let ch = client().with_url(&url).with_user("default");

    // The pre-fix gate: one `SELECT version()` lands on either pod.
    let mut sampled = BTreeSet::new();
    for _ in 0..ROUNDS {
        sampled.insert(ch.query("SELECT version()").fetch_one::<String>().await.unwrap());
    }
    eprintln!("single-pod version() answers over {ROUNDS} requests: {sampled:?}");
    assert!(sampled.len() >= 2, "the load balancer must reach both versions: {sampled:?}");
    assert!(sampled.iter().any(|v| supports_external_set_spill(v)));
    assert!(sampled.iter().any(|v| !supports_external_set_spill(v)));

    // The fleet probe answers the same, whichever pod receives it.
    for _ in 0..ROUNDS {
        let fleet = fleet_server_versions(&ch).await;
        let versions = fleet.as_ref().expect("fleet probe");
        assert!(versions.iter().any(|v| v.starts_with("26.8.")), "{versions:?}");
        assert!(versions.iter().any(|v| v.starts_with("26.10.")), "{versions:?}");
        assert!(!fleet_supports(&fleet, supports_external_set_spill));
        assert!(!fleet_supports(&fleet, supports_skip_null_typed_paths));
    }

    // The hazard the gate prevents: the option on the client fails on the old pod.
    let enabled = ch.clone().with_option("max_bytes_before_external_set", "67108864");
    let mut failures = 0;
    for _ in 0..ROUNDS {
        if let Err(e) = enabled.query(SPILL_PROBE).fetch_one::<u64>().await {
            assert!(e.to_string().contains("max_bytes_before_external_set"), "{e}");
            failures += 1;
        }
    }
    eprintln!("with the option set: {failures}/{ROUNDS} requests failed (UNKNOWN_SETTING)");
    assert!(failures > 0 && failures < ROUNDS, "expected the old pod to reject some requests");

    // The client the fleet gate builds (option left off) never fails.
    for _ in 0..ROUNDS {
        assert_eq!(ch.query(SPILL_PROBE).fetch_one::<u64>().await.unwrap(), 500);
    }
}

#[tokio::test]
async fn single_node_falls_back_to_its_own_version() {
    let Ok(url) = std::env::var("CLICKHOUSE_TEST_URL") else {
        eprintln!("Skipping: CLICKHOUSE_TEST_URL not set");
        return;
    };
    let user = std::env::var("CLICKHOUSE_ADMIN_USER").unwrap_or_else(|_| "default".into());
    let mut ch = client().with_url(&url).with_user(&user);
    if let Ok(pw) = std::env::var("CLICKHOUSE_ADMIN_PASSWORD") {
        if !pw.is_empty() {
            ch = ch.with_password(pw);
        }
    }
    let Ok(local) = ch.query("SELECT version()").fetch_one::<String>().await else {
        eprintln!("Skipping: ClickHouse not reachable at {url}");
        return;
    };
    let multi_host: u64 = ch
        .query(
            "SELECT count() FROM (SELECT cluster FROM system.clusters \
             WHERE cluster NOT IN ('_all_databases', 'system') GROUP BY cluster HAVING count() > 1)",
        )
        .fetch_one()
        .await
        .unwrap();
    if multi_host > 0 {
        eprintln!("Skipping: {url} defines a multi-host cluster");
        return;
    }
    let fleet = fleet_server_versions(&ch).await;
    assert_eq!(fleet.as_ref().unwrap(), &vec![local.clone()]);
    assert_eq!(fleet_supports(&fleet, supports_external_set_spill), supports_external_set_spill(&local));
}
