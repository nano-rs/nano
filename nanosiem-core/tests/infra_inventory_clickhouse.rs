// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3972 / NAN-4028: execute the generated Infra inventory SQL against a
//! real ClickHouse on the production `otel_metrics` DDL (migrations 140 +
//! 158): Kubernetes node and pod rows (the attributes the collector recipe in
//! `docs/observability/kubernetes-collector.md` emits), the counter-delta
//! network rate, the node-exporter fallback, and the group HAVING. Each run
//! uses unique host names and scopes the read with the `q` filter, so it only
//! reads rows it wrote.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test infra_inventory_clickhouse -- --ignored
//! ```
mod common_ch;

use chrono::{DateTime, Duration, Utc};
use common_ch::{statement, ts, Ch};
use nanosiem_core::query::{infra_hosts_sql, InfraHostsFilters, TimeRange};

const OTEL_METRICS_DDL: &str = include_str!("../../clickhouse/140_otel_metrics.sql");

async fn ensure_schema(ch: &Ch) {
    ch.run("CREATE DATABASE IF NOT EXISTS nanosiem").await;
    ch.run(&statement(OTEL_METRICS_DDL, "CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics\n"))
        .await;
    ch.run(
        "ALTER TABLE nanosiem.otel_metrics \
         ADD COLUMN IF NOT EXISTS aggregation_temporality Int8 DEFAULT 0",
    )
    .await;
}

fn map(pairs: &[(&str, &str)]) -> String {
    let body: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("'{k}','{v}'"))
        .collect();
    format!("map({})", body.join(","))
}

fn point(
    metric: &str,
    service: &str,
    at: DateTime<Utc>,
    value: f64,
    attrs: &[(&str, &str)],
    resource: &[(&str, &str)],
) -> String {
    let attrs = if attrs.is_empty() {
        "map()".to_string()
    } else {
        map(attrs)
    };
    format!(
        "('{metric}','gauge','{service}',toDateTime64('{}',9,'UTC'),{value},0,{attrs},{})",
        ts(at),
        map(resource)
    )
}

fn num(row: &serde_json::Value, key: &str) -> Option<f64> {
    match &row[key] {
        serde_json::Value::Null => None,
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse().ok(),
        other => panic!("{key}: {other}"),
    }
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn kubernetes_nodes_pods_and_node_exporter_hosts_share_one_inventory() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let run = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
    let node = format!("nan3972-{run}-node-a");
    let pod = format!("nan3972-{run}-web-1");
    let legacy = format!("nan3972-{run}-legacy");
    let t0 = Utc::now() - Duration::minutes(10);
    let t1 = t0 + Duration::seconds(60);

    let node_res = [
        ("host.name", node.as_str()),
        ("nano.infra.kind", "node"),
        ("k8s.node.name", node.as_str()),
        ("nano.cluster", "prod"),
        ("cloud.region", "us-east-1"),
        ("host.type", "m6i.large"),
        ("host.group", "prod/us-east-1/general"),
    ];
    let pod_res = [
        ("host.name", pod.as_str()),
        ("nano.infra.kind", "pod"),
        ("k8s.node.name", node.as_str()),
        ("k8s.pod.name", "web-1"),
        ("k8s.namespace.name", "shop"),
        ("k8s.workload.name", "web"),
        ("k8s.pod.phase", "Running"),
        ("nano.cluster", "prod"),
        ("host.group", "prod/us-east-1/general"),
    ];
    let legacy_res = [("host.name", legacy.as_str())];
    let rows = [
        point("system.cpu.usage", "k8s", t1, 1.5, &[], &node_res),
        point("system.cpu.logical.count", "k8s", t1, 2.0, &[], &node_res),
        point("system.memory.usage", "k8s", t1, 4.0e9, &[], &node_res),
        point("system.memory.utilization", "k8s", t1, 0.5, &[], &node_res),
        point("system.network.io.total", "k8s", t0, 1000.0, &[], &node_res),
        point("system.network.io.total", "k8s", t1, 61000.0, &[], &node_res),
        point("nano.infra.health", "k8s", t1, 0.0, &[], &node_res),
        point("k8s.pod.restarts", "k8s", t1, 3.0, &[], &pod_res),
        point("nano.infra.health", "k8s", t1, 1.0, &[], &pod_res),
        point("node_memory_MemAvailable_bytes", "node-exporter", t1, 2.0e9, &[], &legacy_res),
        point("node_memory_MemTotal_bytes", "node-exporter", t1, 8.0e9, &[], &legacy_res),
        point("node_load1", "node-exporter", t1, 0.7, &[], &legacy_res),
        point("node_network_receive_bytes_total", "node-exporter", t0, 100.0, &[("device", "eth0")], &legacy_res),
        point("node_network_receive_bytes_total", "node-exporter", t1, 6100.0, &[("device", "eth0")], &legacy_res),
        point("node_network_transmit_bytes_total", "node-exporter", t0, 0.0, &[("device", "eth0")], &legacy_res),
        point("node_network_transmit_bytes_total", "node-exporter", t1, 0.0, &[("device", "eth0")], &legacy_res),
        // loopback / veth are excluded from the per-scrape interface sum
        point("node_network_receive_bytes_total", "node-exporter", t0, 0.0, &[("device", "lo")], &legacy_res),
        point("node_network_receive_bytes_total", "node-exporter", t1, 9.0e12, &[("device", "lo")], &legacy_res),
        point("node_network_receive_bytes_total", "node-exporter", t1, 9.0e12, &[("device", "veth12ab")], &legacy_res),
    ];
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_metrics \
         (metric_name, metric_type, service_name, timestamp, value, aggregation_temporality, \
          attributes, resource_attributes) VALUES {}",
        rows.join(",")
    ))
    .await;

    let range = TimeRange::new(t0 - Duration::minutes(1), Utc::now());
    let prefix = format!("nan3972-{run}");
    let all = ch
        .rows(&infra_hosts_sql(
            &range,
            &InfraHostsFilters { q: Some(&prefix), ..Default::default() },
            false,
        ))
        .await;
    let by_host = |host: &str| {
        all.iter()
            .find(|r| r["host"] == host)
            .unwrap_or_else(|| panic!("{host} missing from {all:?}"))
            .clone()
    };
    assert_eq!(all.len(), 3, "{all:?}");

    let n = by_host(&node);
    assert_eq!(n["kind"], "node");
    assert_eq!(n["cluster"], "prod");
    assert_eq!(n["region"], "us-east-1");
    assert_eq!(n["instance_type"], "m6i.large");
    assert_eq!(n["host_group"], "prod/us-east-1/general");
    assert_eq!(num(&n, "cpu_cores"), Some(1.5));
    assert_eq!(num(&n, "cpu_count"), Some(2.0));
    assert_eq!(num(&n, "mem_bytes"), Some(4.0e9));
    assert_eq!(num(&n, "mem_util"), Some(0.5));
    assert_eq!(num(&n, "health_n"), Some(1.0));
    let rate = num(&n, "net_rate").expect("two counter samples give a rate");
    assert!((rate - 1000.0).abs() < 1e-6, "node rate {rate}");

    let p = by_host(&pod);
    assert_eq!(p["kind"], "pod");
    assert_eq!(p["pod_name"], "web-1");
    assert_eq!(p["namespace"], "shop");
    assert_eq!(p["workload"], "web");
    assert_eq!(p["phase"], "Running");
    assert_eq!(p["node_name"], node.as_str());
    assert_eq!(num(&p, "restarts"), Some(3.0));
    assert_eq!(num(&p, "health"), Some(1.0));
    // A pod without utilization samples reports none (explicit missing sample).
    assert_eq!(num(&p, "cpu_n"), Some(0.0));
    assert_eq!(num(&p, "mem_n"), Some(0.0));
    assert_eq!(num(&p, "net_rate"), None);

    let l = by_host(&legacy);
    assert_eq!(l["kind"], "");
    // No host.group: the label falls back to the service name.
    assert_eq!(l["host_group"], "node-exporter");
    assert_eq!(num(&l, "mem_util"), Some(0.75));
    assert_eq!(num(&l, "mem_n"), Some(1.0));
    assert_eq!(num(&l, "load_1m"), Some(0.7));
    let rate = num(&l, "net_rate").expect("node-exporter counters give a rate");
    assert!((rate - 100.0).abs() < 1e-6, "legacy rate {rate} (lo/veth must be excluded)");

    // The group filter applies to the aggregated (latest) label.
    let grouped = ch
        .rows(&infra_hosts_sql(
            &range,
            &InfraHostsFilters {
                q: Some(&prefix),
                group: Some("prod/us-east-1/general"),
                env: None,
            },
            false,
        ))
        .await;
    let mut hosts: Vec<&str> = grouped.iter().map(|r| r["host"].as_str().unwrap()).collect();
    hosts.sort_unstable();
    let mut expected = vec![node.as_str(), pod.as_str()];
    expected.sort_unstable();
    assert_eq!(hosts, expected);
}

/// Codex P2-5: a counter reset (node reboot) inside the window. The rate is
/// the sum of non-negative deltas between time-ordered samples, a reset
/// contributing its post-reset value, over the covered duration — not NULL,
/// and not the net first-to-last difference.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn network_rate_survives_counter_resets() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let run = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
    let rebooted = format!("nan4902r-{run}-rebooted");
    let regrown = format!("nan4902r-{run}-regrown");
    let exporter = format!("nan4902r-{run}-exporter");
    let t0 = Utc::now() - Duration::minutes(10);
    let at = |i: i64| t0 + Duration::seconds(60 * i);
    let res = |h: &str| vec![("host.name".to_string(), h.to_string())];
    let point_owned = |metric: &str, svc: &str, t: DateTime<Utc>, v: f64, attrs: &[(&str, &str)], host: &str| {
        let r = res(host);
        let r: Vec<(&str, &str)> = r.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        point(metric, svc, t, v, attrs, &r)
    };
    let mut rows = Vec::new();
    // rebooted: 1000 -> 61000 (+60000), reset to 500 (+500), -> 30500 (+30000)
    for (i, v) in [(0, 1000.0), (1, 61000.0), (2, 500.0), (3, 30500.0)] {
        rows.push(point_owned("system.network.io.total", "k8s", at(i), v, &[], &rebooted));
    }
    // regrown: resets, then grows past its first value: 1000 -> 5000 (+4000),
    // reset 100 (+100), -> 9000 (+8900). Net first-to-last would be 8000.
    for (i, v) in [(0, 1000.0), (1, 5000.0), (2, 100.0), (3, 9000.0)] {
        rows.push(point_owned("system.network.io.total", "k8s", at(i), v, &[], &regrown));
    }
    // node-exporter interface counters with a reset on eth0: +6000, reset
    // +50, +3000.
    for (i, v) in [(0, 100.0), (1, 6100.0), (2, 50.0), (3, 3050.0)] {
        rows.push(point_owned("node_network_receive_bytes_total", "node-exporter", at(i), v, &[("device", "eth0")], &exporter));
    }
    // inserted out of time order on purpose
    rows.reverse();
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_metrics \
         (metric_name, metric_type, service_name, timestamp, value, aggregation_temporality, \
          attributes, resource_attributes) VALUES {}",
        rows.join(",")
    ))
    .await;

    let range = TimeRange::new(t0 - Duration::minutes(1), Utc::now());
    let prefix = format!("nan4902r-{run}");
    let all = ch
        .rows(&infra_hosts_sql(&range, &InfraHostsFilters { q: Some(&prefix), ..Default::default() }, false))
        .await;
    let rate = |host: &str| {
        let row = all.iter().find(|r| r["host"] == host).unwrap_or_else(|| panic!("{host}: {all:?}"));
        num(row, "net_rate").unwrap_or_else(|| panic!("{host}: NULL rate {row}"))
    };
    let close = |a: f64, b: f64| (a - b).abs() < 1e-6;
    assert!(close(rate(&rebooted), 90_500.0 / 180.0), "rebooted {}", rate(&rebooted));
    assert!(close(rate(&regrown), 13_000.0 / 180.0), "regrown {}", rate(&regrown));
    assert!(close(rate(&exporter), 9_050.0 / 180.0), "exporter {}", rate(&exporter));
}
