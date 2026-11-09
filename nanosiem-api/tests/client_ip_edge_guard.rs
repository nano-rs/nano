// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5015: every shipped nginx edge strips CDN client-IP headers, and both
//! app services get the trusted-proxy configuration.
//!
//! Read at runtime (not `include_str!`) and skipped when absent, because the
//! open-core mirror strips `deploy/` and `ludus/`.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn read_if_present(rel: &str) -> Option<String> {
    std::fs::read_to_string(root().join(rel)).ok()
}

#[test]
fn every_shipped_edge_strips_cdn_client_ip_headers() {
    for rel in [
        "config/nginx/nginx.opensource.conf",
        "config/nginx/nginx.opensource-tls.conf",
        "deploy/compose/config/nginx.app.conf",
        "deploy/compose/config/nginx.ingest.conf.template",
        "deploy/helm/nano/templates/edge/configmap.yaml",
        "deploy/helm/nano/templates/ingest/configmap.yaml",
        "ludus/roles/nanosiem_stack/files/nginx/nginx.conf",
    ] {
        let Some(src) = read_if_present(rel) else { continue };
        let forwards = src.matches("proxy_set_header X-Real-IP $remote_addr;").count();
        assert!(forwards > 0, "{rel}: expected a proxied server block");
        assert!(
            src.matches("proxy_set_header CF-Connecting-IP \"\";").count() >= forwards
                && src.matches("proxy_set_header True-Client-IP \"\";").count() >= forwards,
            "{rel}: a server block forwards to the apps without stripping CF-Connecting-IP / \
             True-Client-IP — a client could claim any address (NAN-5015)"
        );
    }
}

#[test]
fn both_app_services_get_the_trusted_proxy_configuration() {
    for rel in ["docker-compose.opensource.yml", "docker-compose.siem-only.yml"] {
        let Some(src) = read_if_present(rel) else { continue };
        assert_eq!(
            src.matches("TRUSTED_PROXY_CIDRS: ${TRUSTED_PROXY_CIDRS:-").count(),
            2,
            "{rel}: nano-api and nano-search must both trust the Compose nginx"
        );
        assert_eq!(src.matches("TRUSTED_CLIENT_IP_HEADERS: ${TRUSTED_CLIENT_IP_HEADERS:-x-forwarded-for}").count(), 2);
    }
    if let Some(search) = read_if_present("deploy/helm/nano/templates/app/search.yaml") {
        assert!(search.contains("name: TRUSTED_PROXY_CIDRS"));
        assert!(search.contains("name: TRUSTED_CLIENT_IP_HEADERS"));
    }
}

#[test]
fn search_no_longer_has_its_own_ip_extractor() {
    let src = read_if_present("nanosiem-search/src/middleware.rs").expect("search middleware");
    assert!(
        !src.contains("request.headers().get(\"CF-Connecting-IP\")"),
        "nanosiem-search must use the shared trusted-proxy gate (NAN-5015)"
    );
    assert!(src.contains("nanosiem_api_lib::extract_client_ip_origin"));
    assert!(src.contains(".is_allowed_client(ip_str, from_socket, state.scope)"));
}

/// NAN-5015 (review): the compose edges strip CDN headers by default but can
/// be opted in without editing nginx: the strip lines are followed by an
/// include that compose fills from config/nginx/client-ip/<mode>.conf.
#[test]
fn compose_edges_can_opt_in_to_cdn_headers() {
    for rel in ["config/nginx/nginx.opensource.conf", "config/nginx/nginx.opensource-tls.conf"] {
        let Some(src) = read_if_present(rel) else { continue };
        let strip = src.find("proxy_set_header True-Client-IP \"\";").expect("strip line");
        let include = src
            .find("include /etc/nginx/nano-client-ip.d/*.conf;")
            .unwrap_or_else(|| panic!("{rel}: no opt-in include"));
        assert!(include > strip, "{rel}: the opt-in must come after the strip (later wins)");
    }
    for rel in ["docker-compose.opensource.yml", "docker-compose.siem-only.yml", "docker-compose.tls.yml"] {
        let Some(src) = read_if_present(rel) else { continue };
        assert!(
            src.contains("./config/nginx/client-ip/${NANO_EDGE_CDN_CLIENT_IP:-none}.conf:/etc/nginx/nano-client-ip.d/edge.conf:ro"),
            "{rel}: nginx must mount the edge client-IP mode"
        );
    }
    let none = read_if_present("config/nginx/client-ip/none.conf").expect("none.conf");
    assert!(!none.contains("proxy_set_header"), "the default mode must forward nothing");
    let cdn = read_if_present("config/nginx/client-ip/cdn.conf").expect("cdn.conf");
    assert!(cdn.contains("proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;"));
    if let Some(ent) = read_if_present("deploy/compose/docker-compose.enterprise.yml") {
        assert_eq!(
            ent.matches("TRUSTED_CLIENT_IP_HEADERS: ${TRUSTED_CLIENT_IP_HEADERS:-x-forwarded-for}").count(),
            2,
            "enterprise compose: nano-api and nano-search both receive the header list"
        );
    }
}

