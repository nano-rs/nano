//! Shadow-run transport: forward every request, after the spec's host policy
//! has admitted it, over plain HTTP to a vendor mock on a loopback port, with
//! the original host in `x-mock-host`. This is how the Deno shadow driver
//! routes `fetch`, so both runtimes hit the same mock with the same requests.
//!
//! Dev and CI only (`nano-connector preview --mock-url`). The target must be
//! a loopback address, so a spec under test cannot reach anything else.

use std::net::{IpAddr, SocketAddr};

use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;

use crate::broker::{BodyCaps, BrokerError, InboundResponse, OutboundRequest};
use crate::engine::Transport;
use crate::policy::HostPolicy;

pub struct LoopbackTransport {
    addr: SocketAddr,
}

impl LoopbackTransport {
    /// `url` must be `http://<loopback ip>:<port>`.
    pub fn new(url: &str) -> Result<Self, String> {
        let u = url::Url::parse(url).map_err(|e| format!("--mock-url: {e}"))?;
        if u.scheme() != "http" {
            return Err("--mock-url must be http://<loopback ip>:<port>".into());
        }
        let ip: IpAddr = match u.host() {
            Some(url::Host::Ipv4(ip)) => ip.into(),
            Some(url::Host::Ipv6(ip)) => ip.into(),
            _ => return Err("--mock-url must name a loopback IP, not a host name".into()),
        };
        if !ip.is_loopback() {
            return Err(format!("--mock-url {ip} is not a loopback address"));
        }
        let port = u.port().ok_or("--mock-url needs a port")?;
        Ok(Self { addr: SocketAddr::new(ip, port) })
    }
}

#[async_trait::async_trait]
impl Transport for LoopbackTransport {
    async fn send_once(&self, req: &OutboundRequest, hosts: &HostPolicy, caps: BodyCaps) -> Result<InboundResponse, BrokerError> {
        hosts.check(&req.url)?;
        let host = req.url.host_str().unwrap_or_default().to_string();
        let tcp = tokio::net::TcpStream::connect(self.addr).await.map_err(|e| BrokerError::Connect(self.addr, e.to_string()))?;
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await.map_err(|e| BrokerError::Http(e.to_string()))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let path = match req.url.query() {
            Some(q) => format!("{}?{q}", req.url.path()),
            None => req.url.path().to_string(),
        };
        let mut b = http::Request::builder().method(req.method.clone()).uri(path).header("host", self.addr.to_string()).header("x-mock-host", &host);
        for (k, v) in &req.headers {
            if !k.eq_ignore_ascii_case("host") {
                b = b.header(k.as_str(), v.as_str());
            }
        }
        let r = b.body(Full::new(req.body.clone())).map_err(|e| BrokerError::Http(e.to_string()))?;
        let resp = tx.send_request(r).await.map_err(|e| BrokerError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = Limited::new(resp.into_body(), caps.max_response_bytes as usize)
            .collect()
            .await
            .map_err(|_| BrokerError::ResponseTooLarge(caps.max_response_bytes))?
            .to_bytes();
        driver.abort();
        Ok(InboundResponse { status, headers, body })
    }
}
