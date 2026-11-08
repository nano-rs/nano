// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse keeps its HTTP/1 and query defaults; only TLS trust is adapted,
//! plus one query option: the LZ4 network compression pin (NAN-4906).
//! Native roots retain administrator-installed private CAs and trust removals.
//! Bundled public roots are a fallback only when the OS store is unavailable.
//! Explicit SSL_CERT_FILE/SSL_CERT_DIR overrides use only those roots, as the
//! native loader documents. An empty loaded store rejects HTTPS; certificate
//! and server-name verification are never disabled.
use std::{sync::Arc, time::Duration};

use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};

fn trust_roots(
    native: Vec<rustls::pki_types::CertificateDer<'static>>,
    explicit: bool,
) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(native);
    if roots.is_empty() && !explicit {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    roots
}

pub fn client() -> clickhouse::Client {
    let explicit =
        std::env::var_os("SSL_CERT_FILE").is_some() || std::env::var_os("SSL_CERT_DIR").is_some();
    // A missing/partial OS bundle is not a reason to panic during an HTTP
    // client's construction. No verification is disabled when roots are absent.
    let native = rustls_native_certs::load_native_certs();
    let roots = trust_roots(native.certs, explicit);
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("AWS-LC supports the default TLS protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut tcp = HttpConnector::new();
    tcp.set_keepalive(Some(Duration::from_secs(60)));
    tcp.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(tcp);
    let http = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(2))
        .build(connector);
    // NAN-4906: ClickHouse 26.9 changed the default network compression to ZSTD,
    // and since 26.9.1.1437 (CH #119825) the HTTP `compress=1` response framing
    // follows `network_compression_method`. The `clickhouse` crate (0.14) sends
    // `compress=1` and only decodes LZ4 (method byte 0x82), so against a 26.9+
    // server every read fails with `Decompression("incorrect magic number")`.
    // Pinning it per client keeps the binary working whatever order the server
    // and the services roll in; on pre-26.9 servers LZ4 is already the default.
    clickhouse::Client::with_http_client(http).with_option("network_compression_method", "LZ4")
}

/// CH-2610 (NAN-4923): whether a server `version()` string knows the
/// `type_json_skip_null_typed_paths` query setting (added in ClickHouse 26.9).
///
/// The OCSF `event` column carries Nullable JSON type hints; without the setting
/// a full-row read renders every absent hinted path as `"path": null`. The
/// setting is applied per client, only after the server reported a version that
/// accepts it, and never in the persisted users.d profiles: the supported
/// emergency rollback (26.8.36.3) would refuse to start on an unknown profile
/// setting, and a mixed-version rollout loads new profiles before old binaries
/// are upgraded. Unparseable versions answer false (the safe side).
pub fn supports_skip_null_typed_paths(version: &str) -> bool {
    version_at_least(version, (26, 9))
}

/// NAN-4934: whether a server `version()` string knows the
/// `max_bytes_before_external_set` query setting. It is absent from 26.8.36.3
/// (the rollback target) and from 26.9.27.3, and present in 26.10.3.7, so it is
/// applied per client like `type_json_skip_null_typed_paths`, never in the
/// persisted profiles (an unknown profile setting stops 26.8 from serving any
/// query). Unparseable versions answer false.
pub fn supports_external_set_spill(version: &str) -> bool {
    version_at_least(version, (26, 10))
}

/// NAN-4934: the `max_bytes_before_external_set` threshold, from the per-query
/// `max_memory_usage` the app identity runs under (`getSetting`, readable
/// without a grant; nano-main sets it per tier, the shipped profiles use 20 GB).
/// Above the threshold an `IN (subquery)` set spills to disk instead of growing
/// in memory (≈165 B per key). Measured on 26.10.3.7, same results throughout:
///
/// - 5M keys: 741 → 83 MiB memory, 1,512 → 1,206 ms (spilling was faster).
/// - 1M keys: 165 → 55 MiB at 64 MiB and 59 MiB at 128 MiB, 256 → 389 / 316 ms.
/// - 100k keys: below every threshold, no spill.
///
/// The ratio default (`max_bytes_ratio_before_external_set = 0.5`) never
/// spilled in any run, so an absolute threshold is what bounds IOC-list hunts.
///
/// | per-query `max_memory_usage` | threshold |
/// |---|---|
/// | unknown, unlimited (0) or < 16 GiB | 64 MiB |
/// | 16–64 GiB (the shipped 20 GB default / rawsql profiles) | 128 MiB |
/// | ≥ 64 GiB | 256 MiB |
pub fn external_set_spill_bytes(max_memory_usage: u64) -> u64 {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    match max_memory_usage {
        m if m >= 64 * GIB => 256 * MIB,
        m if m >= 16 * GIB => 128 * MIB,
        _ => 64 * MIB,
    }
}

/// NAN-4957: share of the ClickHouse server memory limit one search may use
/// when the deployment sets no explicit ceiling. The rest stays for resident
/// dictionaries (and a reload's second copy), insert flushes, merges and the
/// caches. On a 4G compose box (3.2 GiB limit) that is ~1.28 GiB per search;
/// a heavy GROUP BY spills to disk well before it (the profile's
/// `max_bytes_ratio_before_external_group_by`), so the ceiling only stops a
/// runaway query from taking the whole server.
pub const SEARCH_MEMORY_SHARE_PCT: u64 = 40;

/// NAN-4957: per-query memory ceiling for searches. An explicit deployment
/// ceiling (`CLICKHOUSE_QUERY_MAX_MEMORY_BYTES`) wins; otherwise
/// [`SEARCH_MEMORY_SHARE_PCT`] of the server limit; `None` (limit unknown)
/// leaves the ClickHouse profile in control, as before.
pub fn query_memory_ceiling(explicit: Option<u64>, server_limit_bytes: u64) -> Option<u64> {
    explicit.or_else(|| {
        (server_limit_bytes > 0).then(|| server_limit_bytes / 100 * SEARCH_MEMORY_SHARE_PCT)
    })
}

/// NAN-4934 (codex P1): every ClickHouse server version this deployment can
/// route a query to, for the per-client setting gates above.
///
/// A single `SELECT version()` samples ONE backend: behind a k8s Service / NLB
/// during a rolling upgrade it can land on an upgraded pod, enable a setting,
/// and every later request that reaches an old pod fails with UNKNOWN_SETTING.
/// So on a deployment with a multi-host cluster in `system.clusters` this
/// collects `version()` from every replica of every such cluster through
/// `clusterAllReplicas` (whichever pod answers fans out to all of them). With
/// no multi-host cluster (single node, compose) the local `version()` is the
/// whole fleet. Any error (an unreachable replica, a missing grant) is
/// returned, and callers then leave every gated setting off. Reading
/// `system.clusters` and `clusterAllReplicas` need grants (SELECT on
/// `system.clusters`, READ ON REMOTE). The runtime app identity intentionally
/// has neither; `DualPool::new` uses the admin identity for fleet discovery so
/// the runtime grant surface stays narrow.
pub async fn fleet_server_versions(client: &clickhouse::Client) -> Result<Vec<String>, String> {
    let clusters: Vec<String> = client
        .query(
            "SELECT cluster FROM system.clusters \
             WHERE cluster NOT IN ('_all_databases', 'system') \
             GROUP BY cluster HAVING count() > 1 ORDER BY cluster",
        )
        .fetch_all::<String>()
        .await
        .map_err(|e| format!("system.clusters: {e}"))?;
    if clusters.is_empty() {
        return client
            .query("SELECT version()")
            .fetch_one::<String>()
            .await
            .map(|v| vec![v])
            .map_err(|e| format!("version(): {e}"));
    }
    let mut versions = Vec::new();
    for cluster in clusters {
        let sql = format!(
            "SELECT DISTINCT version() FROM clusterAllReplicas('{}', system.one) \
             SETTINGS skip_unavailable_shards = 0",
            crate::sql_hygiene::escape_sql_string(&cluster)
        );
        let mut found = client
            .query(&sql)
            .fetch_all::<String>()
            .await
            .map_err(|e| format!("clusterAllReplicas('{cluster}'): {e}"))?;
        versions.append(&mut found);
    }
    versions.sort();
    versions.dedup();
    Ok(versions)
}

/// Whether a gated setting may be enabled: the probe succeeded, found at least
/// one server, and EVERY server version passes `supports` (one old replica
/// keeps it off for the whole client).
pub fn fleet_supports(versions: &Result<Vec<String>, String>, supports: fn(&str) -> bool) -> bool {
    matches!(versions, Ok(v) if !v.is_empty() && v.iter().all(|x| supports(x)))
}

/// `major.minor` of a `version()` string is at least `min`.
fn version_at_least(version: &str, min: (u32, u32)) -> bool {
    let mut parts = version.trim().split('.');
    let major = parts.next().and_then(|p| p.parse::<u32>().ok());
    let minor = parts.next().and_then(|p| p.parse::<u32>().ok());
    matches!((major, minor), (Some(maj), Some(min_)) if (maj, min_) >= min)
}

#[cfg(test)]
mod tests;
