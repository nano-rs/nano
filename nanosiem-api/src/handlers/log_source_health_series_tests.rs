// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure tests for `GET /api/log-sources/ingest-endpoint` derivation (NAN-4922).

use super::*;

fn req<'a>(host: Option<&'a str>) -> RequestOrigin<'a> {
    RequestOrigin { host, ..Default::default() }
}

#[test]
fn edge_urls_follow_the_browser_origin_and_keep_its_port() {
    let e = derive_ingest_endpoint(&IngestEndpointConfig::default(), &req(Some("siem.example.com:5173")), TokenDelivery::SharedVolume);
    assert!(!e.configured);
    assert_eq!(e.base_url, "http://siem.example.com:5173");
    assert_eq!(e.hostname, "siem.example.com");
    assert_eq!(e.nano_https_url, "http://siem.example.com:5173/ingest");
    assert_eq!(e.otlp_logs_url, "http://siem.example.com:5173/otlp/v1/logs");
    assert_eq!(e.otlp_traces_url, "http://siem.example.com:5173/otlp/v1/traces");
    assert_eq!(e.otlp_metrics_url, "http://siem.example.com:5173/otlp/v1/metrics");
    // HEC has no edge path: Vector's listener, which authenticates the token itself.
    assert_eq!(e.hec_url, "http://siem.example.com:8088");
    assert_eq!(e.hec_event_url, "http://siem.example.com:8088/services/collector/event");
    assert_eq!(e.hec_health_url, "http://siem.example.com:8088/services/collector/health");
    assert_eq!(e.token_delivery, TokenDelivery::SharedVolume);
}

#[test]
fn never_returns_raw_vector_http_or_otlp_ports() {
    for host in ["siem.example", "siem.example:443", "10.0.0.5:8443"] {
        let e = derive_ingest_endpoint(&IngestEndpointConfig::default(), &req(Some(host)), TokenDelivery::None);
        for url in [&e.nano_https_url, &e.otlp_logs_url, &e.otlp_traces_url, &e.otlp_metrics_url] {
            assert!(!url.contains(":8080") && !url.contains(":4318"), "{url}");
        }
    }
}

#[test]
fn tls_edge_from_forwarded_proto_drops_the_default_port() {
    let r = RequestOrigin { host: Some("siem.example:443"), forwarded_proto: Some("https"), ..Default::default() };
    let e = derive_ingest_endpoint(&IngestEndpointConfig::default(), &r, TokenDelivery::None);
    assert_eq!(e.base_url, "https://siem.example");
    assert_eq!(e.scheme, "https");
    assert_eq!(e.nano_https_url, "https://siem.example/ingest");
    assert_eq!(e.otlp_logs_url, "https://siem.example/otlp/v1/logs");
}

#[test]
fn forwarded_host_wins_over_host() {
    let r = RequestOrigin { host: Some("nano-api:3000"), forwarded_host: Some("siem.example:8443"), forwarded_proto: Some("https") };
    let e = derive_ingest_endpoint(&IngestEndpointConfig::default(), &r, TokenDelivery::None);
    assert_eq!(e.base_url, "https://siem.example:8443");
}

#[test]
fn configured_origin_wins_nano_variable_first() {
    let config = IngestEndpointConfig {
        public_base_url: Some("HTTPS://Ingest.Example.com/".into()),
        base_url: Some("http://other.example".into()),
        hec_port: Some("18088".into()),
        hec_scheme: Some("https".into()),
    };
    let e = derive_ingest_endpoint(&config, &req(Some("req.host:5173")), TokenDelivery::None);
    assert!(e.configured);
    assert_eq!(e.base_url, "https://ingest.example.com");
    assert_eq!(e.nano_https_url, "https://ingest.example.com/ingest");
    assert_eq!(e.hec_url, "https://ingest.example.com:18088");
    let only_base = IngestEndpointConfig { base_url: Some("https://siem.example:8443".into()), ..Default::default() };
    let e = derive_ingest_endpoint(&only_base, &req(Some("x")), TokenDelivery::None);
    assert_eq!(e.otlp_logs_url, "https://siem.example:8443/otlp/v1/logs");
}

#[test]
fn invalid_configured_origin_falls_back_to_the_request() {
    for bad in ["siem.example", "ftp://x.com", "https://x.com/path", "https://user@x.com", "https://x.com:99999", "https://a b", ""] {
        let config = IngestEndpointConfig { public_base_url: Some(bad.into()), ..Default::default() };
        let e = derive_ingest_endpoint(&config, &req(Some("req.host")), TokenDelivery::None);
        assert!(!e.configured, "{bad}");
        assert_eq!(e.base_url, "http://req.host", "{bad}");
    }
}

#[test]
fn hostile_or_missing_request_host_falls_back_to_localhost() {
    for bad in [None, Some("evil.com/\"><script>"), Some(""), Some("a b:80"), Some("h:notaport")] {
        let e = derive_ingest_endpoint(&IngestEndpointConfig::default(), &req(bad), TokenDelivery::None);
        assert_eq!(e.base_url, "http://localhost", "{bad:?}");
    }
}

#[test]
fn ipv6_and_ipv4_hosts() {
    assert_eq!(host_from_header("[::1]:3000").as_deref(), Some("[::1]"));
    assert_eq!(parse_authority("[::1]:3000"), Some(("[::1]".into(), Some(3000))));
    assert_eq!(host_from_header("10.0.0.5:3000").as_deref(), Some("10.0.0.5"));
    assert_eq!(host_from_header("[not-v6]:1"), None);
}

#[test]
fn bad_hec_port_and_scheme_use_defaults() {
    let config = IngestEndpointConfig { hec_port: Some("0".into()), hec_scheme: Some("ftp".into()), ..Default::default() };
    let e = derive_ingest_endpoint(&config, &req(Some("h")), TokenDelivery::None);
    assert_eq!(e.hec_url, "http://h:8088");
}

#[test]
fn json_field_names() {
    let v = serde_json::to_value(derive_ingest_endpoint(&IngestEndpointConfig::default(), &req(Some("h")), TokenDelivery::SharedVolume)).unwrap();
    for k in ["base_url", "hostname", "scheme", "hec_url", "hec_event_url", "hec_health_url", "nano_https_url",
        "otlp_logs_url", "otlp_traces_url", "otlp_metrics_url", "configured", "token_delivery"] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert_eq!(v["token_delivery"], "shared_volume");
}
