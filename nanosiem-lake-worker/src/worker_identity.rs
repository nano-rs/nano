// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361: client side of the lake query worker's identity report.
//!
//! The worker's unauthenticated `GET /health` answers only `{"status"}`. The
//! generation, snapshot, hot-tail, digest and assignment fields that the
//! activator, retention manager and search readiness need live behind the
//! bearer-authenticated `GET /v1/identity`. Every in-cluster consumer of that
//! report resolves the URL and bearer through this module so the contract is
//! defined once.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Route that serves the full worker identity/health report.
pub const WORKER_IDENTITY_ROUTE: &str = "/v1/identity";

/// File the query Pod mounts its bearer at; `--auth-token-file` of the worker
/// and the default beside `worker.json` for its sidecars.
pub const DEFAULT_WORKER_TOKEN_FILE_NAME: &str = "query-token";

/// Map the historical `--worker-health-url` value onto the identity route.
/// Accepts a URL that already names the identity route, or one ending in
/// `/health` (the pre-NAN-2361 manifests), and refuses anything else so a
/// typo cannot silently probe an unrelated path.
pub fn worker_identity_url(configured: &str) -> Result<String> {
    let trimmed = configured.trim();
    if trimmed.ends_with(WORKER_IDENTITY_ROUTE) {
        return Ok(trimmed.to_string());
    }
    if let Some(base) = trimmed.strip_suffix("/health") {
        return Ok(format!("{base}{WORKER_IDENTITY_ROUTE}"));
    }
    bail!("worker health URL must end with /health or {WORKER_IDENTITY_ROUTE}: {trimmed}");
}

/// Default bearer location for a sidecar that knows only where the worker's
/// config lives: the `query-token` file beside it.
pub fn default_worker_token_file(sibling: &Path) -> PathBuf {
    sibling
        .parent()
        .map(|directory| directory.join(DEFAULT_WORKER_TOKEN_FILE_NAME))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WORKER_TOKEN_FILE_NAME))
}

/// Read and validate the worker bearer. Mirrors the worker's own admission
/// shape (trimmed, at least 32 characters) so a truncated Secret fails here
/// rather than as an opaque 401.
pub fn read_worker_bearer_token(path: &Path) -> Result<String> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("read worker bearer token {}", path.display()))?;
    let token = token.trim().to_string();
    if token.len() < 32 || token.chars().any(char::is_control) {
        bail!(
            "worker bearer token {} must be at least 32 printable characters",
            path.display()
        );
    }
    Ok(token)
}

/// NAN-2653: names every reader Pod of the tenant so a proof that "no reader
/// still serves X" asks ALL of them, not whichever one a ClusterIP Service
/// happens to pick. Value: comma-separated `host:port`, normally the tenant's
/// headless peer Service on the query port, e.g.
/// `nano-lake-generation-peer-<tenant_uuid>.<namespace>.svc:3015`.
/// (`publishNotReadyAddresses: true`, so surge Pods that are still hydrating
/// are included and make the proof fail closed.) Unset keeps the historical
/// single-endpoint behavior.
pub const READER_PEERS_ENV: &str = "NANO_LAKE_READER_PEERS";

/// A tenant runs one reader, two during a surge roll. Anything far above that
/// is a selector bug; refuse rather than fan out.
pub const MAX_READER_PEERS: usize = 16;

/// Parse the peer list. `None` when the variable is unset; an error when it is
/// set but empty or malformed, so a half-rendered manifest fails closed
/// instead of silently reverting to the single-endpoint proof.
pub fn reader_peer_specs(value: Option<&str>) -> Result<Option<Vec<String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let specs = value
        .split(',')
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if specs.is_empty() {
        bail!("{READER_PEERS_ENV} is set but names no reader peers");
    }
    if specs.len() > MAX_READER_PEERS {
        bail!("{READER_PEERS_ENV} names more than {MAX_READER_PEERS} reader peers");
    }
    for spec in &specs {
        let port = spec
            .rsplit_once(':')
            .map(|(_, port)| port)
            .with_context(|| format!("reader peer {spec} has no port"))?;
        if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            bail!("reader peer {spec} has an invalid port");
        }
        if spec.contains('/') || spec.contains('@') {
            bail!("reader peer {spec} must be host:port, not a URL");
        }
    }
    Ok(Some(specs))
}

pub fn reader_peer_specs_from_environment() -> Result<Option<Vec<String>>> {
    match std::env::var(READER_PEERS_ENV) {
        Ok(value) => reader_peer_specs(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(error).context("read reader peer list"),
    }
}

/// Loopback peers are accepted only by unit tests (local listeners).
const ALLOW_LOOPBACK_READER_PEERS: bool = cfg!(test);

/// A reader peer must be a routable Pod address. Loopback, link-local
/// (including cloud metadata at 169.254.169.254), unspecified and multicast
/// answers mean DNS is pointing the bearer-carrying probe somewhere other
/// than a reader Pod.
pub fn reader_peer_address_allowed(address: std::net::IpAddr, allow_loopback: bool) -> bool {
    use std::net::IpAddr;
    let address = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    if address.is_unspecified() || address.is_multicast() {
        return false;
    }
    if address.is_loopback() {
        return allow_loopback;
    }
    match address {
        IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Resolve every spec to Pod addresses (a headless Service yields one A
/// record per Pod). Any resolution failure, an empty result, a
/// non-routable address (see [`reader_peer_address_allowed`]), or more than
/// [`MAX_READER_PEERS`] addresses is an error: an unknown reader set can never
/// prove anything.
pub async fn resolve_reader_peers(specs: &[String]) -> Result<Vec<std::net::SocketAddr>> {
    let mut addresses = std::collections::BTreeSet::new();
    for spec in specs {
        let resolved = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host(spec.as_str()),
        )
        .await
        .with_context(|| format!("resolve reader peer {spec} timed out"))?
        .with_context(|| format!("resolve reader peer {spec}"))?;
        for address in resolved {
            if !reader_peer_address_allowed(address.ip(), ALLOW_LOOPBACK_READER_PEERS) {
                bail!("reader peer {spec} resolved to non-routable address {address}");
            }
            addresses.insert(address);
        }
        if addresses.len() > MAX_READER_PEERS {
            bail!("reader peers resolve to more than {MAX_READER_PEERS} addresses");
        }
    }
    if addresses.is_empty() {
        bail!("reader peers resolved to no addresses");
    }
    Ok(addresses.into_iter().collect())
}

pub fn reader_peer_identity_url(address: std::net::SocketAddr) -> String {
    format!("http://{address}{WORKER_IDENTITY_ROUTE}")
}

/// Fetch `/v1/identity` from every resolved reader. All-or-nothing: one
/// unreachable, non-2xx or undecodable peer fails the whole probe, because
/// the missing report may be exactly the reader still serving the older
/// generation.
pub async fn fetch_reader_peer_identities(
    peers: &[std::net::SocketAddr],
    bearer: &str,
) -> Result<Vec<serde_json::Value>> {
    // The probe carries the reader bearer: never follow a redirect or route
    // it through an ambient HTTP(S)_PROXY.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let mut reports = Vec::with_capacity(peers.len());
    for peer in peers {
        let response = client
            .get(reader_peer_identity_url(*peer))
            .bearer_auth(bearer)
            .send()
            .await
            .with_context(|| format!("query reader peer {peer} identity"))?;
        // Redirects are not followed, so a 3xx must fail here too.
        if !response.status().is_success() {
            bail!("reader peer {peer} identity refused: HTTP {}", response.status());
        }
        let report = response
            .json::<serde_json::Value>()
            .await
            .with_context(|| format!("decode reader peer {peer} identity"))?;
        reports.push(report);
    }
    Ok(reports)
}

/// Env-configured peer probe. `Ok(None)` when [`READER_PEERS_ENV`] is unset.
pub async fn reader_peer_identities_from_environment(
    token_file: &Path,
) -> Result<Option<Vec<serde_json::Value>>> {
    let Some(specs) = reader_peer_specs_from_environment()? else {
        return Ok(None);
    };
    let bearer = read_worker_bearer_token(token_file)?;
    let peers = resolve_reader_peers(&specs).await?;
    fetch_reader_peer_identities(&peers, &bearer).await.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_urls_map_onto_the_identity_route() {
        assert_eq!(
            worker_identity_url("http://127.0.0.1:3015/health").unwrap(),
            "http://127.0.0.1:3015/v1/identity"
        );
        assert_eq!(
            worker_identity_url("http://lake-query-worker:3015/v1/identity ").unwrap(),
            "http://lake-query-worker:3015/v1/identity"
        );
        assert!(worker_identity_url("http://127.0.0.1:3015/ready").is_err());
        assert!(worker_identity_url("http://127.0.0.1:3015/healthz").is_err());
    }

    #[test]
    fn default_token_sits_beside_the_worker_config() {
        assert_eq!(
            default_worker_token_file(Path::new("/var/lib/nano-lake/config/worker.json")),
            PathBuf::from("/var/lib/nano-lake/config/query-token")
        );
    }

    #[test]
    fn bearer_tokens_are_trimmed_and_length_checked() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("query-token");
        std::fs::write(&path, format!("{}\n", "a".repeat(64))).unwrap();
        assert_eq!(read_worker_bearer_token(&path).unwrap(), "a".repeat(64));
        std::fs::write(&path, "short\n").unwrap();
        assert!(read_worker_bearer_token(&path).is_err());
        assert!(read_worker_bearer_token(&directory.path().join("absent")).is_err());
    }

    #[test]
    fn reader_peer_specs_fail_closed_when_set_but_unusable() {
        assert!(reader_peer_specs(None).unwrap().is_none());
        assert_eq!(
            reader_peer_specs(Some(" peer.ns.svc:3015 , 10.0.0.1:3015 ")).unwrap().unwrap(),
            vec!["peer.ns.svc:3015".to_string(), "10.0.0.1:3015".to_string()]
        );
        assert!(reader_peer_specs(Some("")).is_err());
        assert!(reader_peer_specs(Some(" , ")).is_err());
        assert!(reader_peer_specs(Some("peer.ns.svc")).is_err());
        assert!(reader_peer_specs(Some("peer.ns.svc:0")).is_err());
        assert!(reader_peer_specs(Some("http://peer.ns.svc:3015")).is_err());
        let many = vec!["p:1"; MAX_READER_PEERS + 1].join(",");
        assert!(reader_peer_specs(Some(&many)).is_err());
    }

    #[test]
    fn reader_peer_identity_url_targets_the_pod_address() {
        assert_eq!(
            reader_peer_identity_url("10.1.2.3:3015".parse().unwrap()),
            "http://10.1.2.3:3015/v1/identity"
        );
        assert_eq!(
            reader_peer_identity_url("[fd00::1]:3015".parse().unwrap()),
            "http://[fd00::1]:3015/v1/identity"
        );
    }

    #[test]
    fn reader_peers_must_be_routable_pod_addresses() {
        let allowed = |ip: &str, loopback| reader_peer_address_allowed(ip.parse().unwrap(), loopback);
        for ip in ["10.1.2.3", "192.168.0.7", "fd00::1", "2001:db8::1", "::ffff:10.0.0.1"] {
            assert!(allowed(ip, false), "{ip}");
        }
        for ip in [
            "127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "fe80::1", "0.0.0.0", "::",
            "224.0.0.1", "ff02::1", "255.255.255.255", "::ffff:169.254.169.254",
        ] {
            assert!(!allowed(ip, false), "{ip}");
        }
        // Tests may opt into loopback; nothing else loosens.
        assert!(allowed("127.0.0.1", true));
        assert!(!allowed("169.254.169.254", true));
        assert!(!ALLOW_LOOPBACK_READER_PEERS || cfg!(test));
    }

    #[tokio::test]
    async fn non_routable_reader_peer_resolution_fails_closed() {
        for spec in ["0.0.0.0:3015", "169.254.169.254:80", "[fe80::1]:3015", "224.0.0.1:3015"] {
            let error = resolve_reader_peers(&[spec.to_string()]).await.unwrap_err();
            assert!(format!("{error:#}").contains("non-routable"), "{spec}: {error:#}");
        }
    }

    #[tokio::test]
    async fn reader_peer_probe_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let error = fetch_reader_peer_identities(&[address], &"a".repeat(32))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("refused"), "{error:#}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn resolving_reader_peers_unions_and_dedupes_addresses() {
        let peers = resolve_reader_peers(&["127.0.0.1:3015".into(), "127.0.0.1:3015".into()])
            .await
            .unwrap();
        assert_eq!(peers, vec!["127.0.0.1:3015".parse().unwrap()]);
    }

    #[tokio::test]
    async fn one_unreachable_reader_peer_fails_the_whole_probe() {
        // Bind then drop to obtain a closed local port.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(fetch_reader_peer_identities(&[port], &"a".repeat(32)).await.is_err());
    }
}
