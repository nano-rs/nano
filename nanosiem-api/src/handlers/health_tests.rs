// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5390: only `/health?strict=1` maps "error" to 503; plain `/health`
//! keeps its 200 contract for healthchecks, routing checks and probes.

use super::HealthQuery;

fn q(strict: Option<&str>) -> HealthQuery {
    HealthQuery { strict: strict.map(str::to_string) }
}

#[test]
fn strict_is_opt_in() {
    assert!(!q(None).is_strict());
    assert!(!q(Some("0")).is_strict());
    assert!(!q(Some("false")).is_strict());
    assert!(!q(Some("")).is_strict());
    assert!(q(Some("1")).is_strict());
    assert!(q(Some("true")).is_strict());
}

#[test]
fn raw_query_parsing_never_rejects() {
    assert!(HealthQuery::from_raw(Some("strict=1")).is_strict());
    assert!(HealthQuery::from_raw(Some("a=b&strict=true")).is_strict());
    assert!(!HealthQuery::from_raw(Some("strict")).is_strict());
    assert!(!HealthQuery::from_raw(Some("%zz&&=")).is_strict());
    assert!(!HealthQuery::from_raw(None).is_strict());
}

// --- NAN-5387: downstream probes follow the topology ------------------------

use super::{downstream_probe_urls, DownstreamProbeUrls};

fn urls(vars: &[(&str, &str)]) -> DownstreamProbeUrls {
    downstream_probe_urls(|key| {
        vars.iter().find(|(k, _)| *k == key).map(|(_, v)| v.to_string())
    })
}

/// Compose (open core and single-host enterprise): the services that exist,
/// not the never-shipped `ingest:3001` / `search:3002`.
#[test]
fn compose_defaults_name_real_services() {
    let u = urls(&[]);
    assert_eq!(u.ingest, "http://vector:9598/metrics");
    assert_eq!(u.search, "http://nano-search:3002/health");
}

/// Helm: VECTOR_METRICS_URL (shared app env) and SEARCH_SERVICE_URL (api).
#[test]
fn helm_addresses_come_from_the_chart_env() {
    let u = urls(&[
        ("VECTOR_METRICS_URL", "http://nano-vector-metrics.ns.svc.cluster.local:9598/metrics"),
        ("SEARCH_SERVICE_URL", "http://nano-search:3002/health"),
    ]);
    assert_eq!(u.ingest, "http://nano-vector-metrics.ns.svc.cluster.local:9598/metrics");
    assert_eq!(u.search, "http://nano-search:3002/health");
}

#[test]
fn explicit_overrides_win_and_blank_values_fall_through() {
    let u = urls(&[
        ("INGEST_SERVICE_URL", "http://ingest-proxy:8080/healthz"),
        ("VECTOR_METRICS_URL", "http://vector:9598/metrics"),
        ("SEARCH_SERVICE_URL", "  "),
        ("NANO_HEALTH_SEARCH_URL", "http://search-host:3002/health"),
    ]);
    assert_eq!(u.ingest, "http://ingest-proxy:8080/healthz");
    assert_eq!(u.search, "http://search-host:3002/health");
}

/// The shipped topology files wire the probes to their own service names.
#[test]
fn shipped_topologies_set_their_probe_addresses() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let read = |p: &str| std::fs::read_to_string(root.join(p)).unwrap();
    let helm_api = read("deploy/helm/nano/templates/app/api.yaml");
    assert!(
        helm_api.contains("SEARCH_SERVICE_URL") && helm_api.contains("-search.{{ .Release.Namespace }}.svc.cluster.local:3002/health"),
        "Helm api must point SEARCH_SERVICE_URL at the search Service"
    );
    let helm_helpers = read("deploy/helm/nano/templates/_helpers.tpl");
    assert!(helm_helpers.contains("- name: VECTOR_METRICS_URL"), "Helm app env must set VECTOR_METRICS_URL");
    let enterprise = read("deploy/compose/docker-compose.enterprise.yml");
    assert!(
        enterprise.contains("INGEST_SERVICE_URL: http://ingest-proxy:8080/healthz"),
        "role-split app hosts probe ingest through the ingest proxy"
    );
    let open = read("docker-compose.opensource.yml");
    assert!(open.contains("  nano-search:") && open.contains("  vector-netns:"));
    let dev = read("docker-compose.yml");
    assert!(dev.contains("SEARCH_SERVICE_URL: http://nanosiem-search:3002/health"));
}

/// NAN-5564: a gated Vector shows as "gated" (not healthy) with the reason.
#[test]
fn ingest_reports_gated_while_vector_waits_for_the_pipeline() {
    let probe = || super::ServiceHealth {
        status: "unavailable".to_string(),
        url: "http://vector:9598/metrics".to_string(),
        latency_ms: None,
        error: Some("connection refused".to_string()),
    };
    let gated = super::gated_ingest_health(probe(), true);
    assert_eq!(gated.status, "gated");
    assert!(gated.error.as_deref().unwrap_or("").contains("waiting for nano-api"));
    assert_eq!(gated.url, "http://vector:9598/metrics");
    assert_eq!(super::gated_ingest_health(probe(), false).status, "unavailable");
}
