// SPDX-License-Identifier: AGPL-3.0-or-later
//! Transport used exclusively by shared inputlookup URL fetches. CONNECT is
//! explicit so proxy status codes can be categorized without exposing internals.
use super::*;
use http_body_util::Empty;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) const UNREACHABLE: &str = "inputlookup storage unreachable";
pub(super) const CONFIG_ERROR: &str = "inputlookup requires NANOSIEM_INPUTLOOKUP_PROXY_URL (http:// proxy); direct access requires NANOSIEM_INPUTLOOKUP_ALLOW_DIRECT_DEV=1";

#[derive(Clone)]
pub(super) enum FetchRoute {
    Proxy(Url),
    Direct,
}
impl FetchRoute {
    pub(super) fn from_env() -> Result<Self, &'static str> {
        let proxy = std::env::var_os("NANOSIEM_INPUTLOOKUP_PROXY_URL")
            .map(|v| v.into_string().map_err(|_| CONFIG_ERROR))
            .transpose()?;
        let direct = std::env::var_os("NANOSIEM_INPUTLOOKUP_ALLOW_DIRECT_DEV")
            .map(|v| v.into_string().map_err(|_| CONFIG_ERROR))
            .transpose()?;
        Self::from_config(proxy.as_deref(), direct.as_deref())
    }
    pub(super) fn from_config(
        proxy: Option<&str>,
        direct: Option<&str>,
    ) -> Result<Self, &'static str> {
        Self::from_config_mode(proxy, direct, cfg!(debug_assertions))
    }
    pub(super) fn from_config_mode(
        proxy: Option<&str>,
        direct: Option<&str>,
        development: bool,
    ) -> Result<Self, &'static str> {
        if direct == Some("1") && !development {
            tracing::warn!("NANOSIEM_INPUTLOOKUP_ALLOW_DIRECT_DEV ignored in release build");
        }
        match proxy {
            Some(raw) => {
                let url = Url::parse(raw).map_err(|_| CONFIG_ERROR)?;
                if url.scheme() != "http"
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || raw.contains(['@', '\\'])
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || raw.chars().any(char::is_control)
                {
                    return Err(CONFIG_ERROR);
                }
                Ok(Self::Proxy(url))
            }
            None if direct == Some("1") && development => Ok(Self::Direct),
            None => Err(CONFIG_ERROR),
        }
    }
    pub(super) fn is_proxy(&self) -> bool {
        matches!(self, Self::Proxy(_))
    }
}

/// Abort the HTTP driver on completion, redirect, deadline, or cancellation.
/// No tunnel task is allowed to outlive the bounded fetch.
pub(super) struct Connection(tokio::task::JoinHandle<()>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn request(
    proxy: &Url,
    url: &Url,
    tenant: Uuid,
    http_status: &mut Option<u16>,
    #[cfg(test)] endpoint: Option<&TestEndpoint>,
) -> Result<(Response, Connection), &'static str> {
    let host = url.host_str().ok_or(STORAGE_POLICY_ERROR)?;
    #[cfg(not(test))]
    let key = std::env::var("NANOSIEM_INPUTLOOKUP_EGRESS_HMAC_KEY").map_err(|_| UNREACHABLE)?;
    #[cfg(test)]
    let key = "test-egress-key-32-bytes-minimum!!";
    let exp = chrono::Utc::now().timestamp() + 60;
    let token =
        super::super::egress_auth::sign(key.as_bytes(), tenant, host, exp).ok_or(UNREACHABLE)?;
    let connect_started = Instant::now();
    let stream = tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = tokio::net::TcpStream::connect((
            proxy.host_str().ok_or(CONFIG_ERROR)?,
            proxy.port_or_known_default().ok_or(CONFIG_ERROR)?,
        ))
        .await
        .map_err(|_| UNREACHABLE)?;
        // Only the validated hostname/443 and authenticated tenant go outside
        // TLS. No origin headers, path, or signed query can enter CONNECT.
        stream
            .write_all(
                format!(
            "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nX-Nano-Tenant: {tenant}\r\nX-Nano-Egress-Token: {token}\r\nX-Nano-Egress-Exp: {exp}\r\n\r\n"
        )
                .as_bytes(),
            )
            .await
            .map_err(|_| UNREACHABLE)?;
        // Read exactly through the header terminator: do not consume tunnel
        // bytes, trust Content-Length, or allocate based on proxy input.
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            if headers.len() >= 8192 {
                return Err(UNREACHABLE);
            }
            headers.push(stream.read_u8().await.map_err(|_| UNREACHABLE)?);
        }
        let mut parsed_headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut parsed_headers);
        if !response
            .parse(&headers)
            .map_err(|_| UNREACHABLE)?
            .is_complete()
        {
            return Err(UNREACHABLE);
        }
        *http_status = response.code;
        match response.code {
            Some(200) => Ok(stream),
            Some(403) => Err("inputlookup proxy denied destination"),
            _ => Err(UNREACHABLE),
        }
    })
    .await
    .map_err(|_| UNREACHABLE)??;

    // Use the same platform trust store and verifying implementation as
    // reqwest's default TLS backend; no certificate/hostname checks are relaxed.
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(not(test))]
    let verifier =
        rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|_| UNREACHABLE)?;
    #[cfg(test)]
    let verifier = if endpoint.is_some() {
        rustls_platform_verifier::Verifier::new_with_extra_roots(
            [rustls::pki_types::CertificateDer::from(
                include_bytes!("fixtures/test-cert.der").to_vec(),
            )],
            provider.clone(),
        )
        .map_err(|_| UNREACHABLE)?
    } else {
        rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|_| UNREACHABLE)?
    };
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| UNREACHABLE)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| STORAGE_POLICY_ERROR)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    // Preserve the ten-second connection budget across TCP, CONNECT, and TLS.
    let tls = tokio::time::timeout(
        Duration::from_secs(10).saturating_sub(connect_started.elapsed()),
        connector.connect(name, stream),
    )
    .await
    .map_err(|_| UNREACHABLE)?
    .map_err(|_| UNREACHABLE)?;
    let (mut sender, driver) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|_| UNREACHABLE)?;
    let connection = Connection(tokio::spawn(async move {
        let _ = driver.await;
    }));
    let target = &url[url::Position::BeforePath..url::Position::AfterQuery];
    let request = hyper::Request::builder()
        .method("GET")
        .uri(target)
        .header("Host", host)
        .header("Accept-Encoding", "identity")
        .header("User-Agent", "NanoSIEM/1.0 InputLookup")
        .body(Empty::<bytes::Bytes>::new())
        .map_err(|_| UNREACHABLE)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| UNREACHABLE)?;
    Ok((
        Response::from(response.map(reqwest::Body::wrap)),
        connection,
    ))
}
