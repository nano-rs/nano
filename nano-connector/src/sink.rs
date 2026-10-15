//! Vector HTTP ingest sink: NDJSON POST with `X-Source-Type` and the feed
//! token, the same wire contract as `nanosiem-core::ingestion::VectorIngestClient`.
//! A 2xx is the acknowledgement the engine waits for before checkpointing.
//!
//! The ingest endpoint is an internal service, so this client deliberately
//! does not go through the egress broker (which refuses private addresses).

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::Value;

use crate::engine::Sink;

pub struct VectorSink {
    pub url: url::Url,
    pub token: String,
}

#[async_trait::async_trait]
impl Sink for VectorSink {
    async fn push(&self, source_type: &str, events: &[Value]) -> Result<(), String> {
        let mut body = String::new();
        for (i, e) in events.iter().enumerate() {
            if i > 0 {
                body.push('\n');
            }
            body.push_str(&e.to_string());
        }
        let host = self.url.host_str().ok_or("ingest URL has no host")?.to_string();
        let port = self.url.port_or_known_default().unwrap_or(80);
        if self.url.scheme() != "http" {
            return Err("PoC sink speaks plain http to the in-cluster ingest only".into());
        }
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;
        let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await.map_err(|e| e.to_string())?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = http::Request::post(self.url.path())
            .header("Host", host)
            .header("Content-Type", "application/x-ndjson")
            .header("X-Source-Type", source_type)
            .header("Authorization", format!("Bearer {}", self.token))
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| e.to_string())?;
        let resp = tx.send_request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        let _ = resp.into_body().collect().await;
        driver.abort();
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("ingest answered HTTP {status}"))
        }
    }
}
