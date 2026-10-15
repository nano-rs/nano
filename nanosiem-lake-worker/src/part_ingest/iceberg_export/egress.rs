// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process-local HTTPS CONNECT guard for the isolated export job process.
//! Even catalog-supplied URI/storage overrides and redirects pass this guard.
//! Only configured origins are reachable. Each tunnel validates DNS and dials
//! the exact public address, eliminating resolution/connection rebinding.
use anyhow::{ensure, Result};
use nanosiem_core::{
    iceberg_export::endpoint,
    inputlookup::{SsrfConfig, SsrfValidator},
};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

pub struct ExportEgress {
    task: tokio::task::JoinHandle<()>,
    pub proxy: String,
}
impl Drop for ExportEgress {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ExportEgress {
    pub async fn start(uris: &[String]) -> Result<Self> {
        let mut origins = BTreeSet::new();
        for value in uris {
            let url = endpoint(value)?;
            origins.insert(format!(
                "{}:{}",
                url.host_str().unwrap(),
                url.port_or_known_default().unwrap()
            ));
        }
        ensure!(
            !origins.is_empty() && origins.len() <= 8,
            "export origin bound exceeded"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy = format!("http://{}", listener.local_addr()?);
        let origins = Arc::new(origins);
        let slots = Arc::new(Semaphore::new(8));
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue;
                };
                let origins = origins.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ =
                        tokio::time::timeout(Duration::from_secs(130), tunnel(socket, &origins))
                            .await;
                });
            }
        });
        Ok(Self { task, proxy })
    }
    /// Called only in `lake_job_runner --iceberg-export`, before constructing
    /// any outbound client. Never installed in the serving process.
    pub fn install_process_proxy(&self) {
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            std::env::set_var(name, &self.proxy);
        }
        std::env::set_var("NO_PROXY", "");
        std::env::set_var("no_proxy", "");
    }
}

fn authority(header: &[u8], origins: &BTreeSet<String>) -> Result<String> {
    let text = std::str::from_utf8(header)?;
    let mut words = text
        .split("\r\n")
        .next()
        .unwrap_or_default()
        .split_whitespace();
    ensure!(
        words.next() == Some("CONNECT"),
        "export proxy requires TLS tunnel"
    );
    let authority = words
        .next()
        .ok_or_else(|| anyhow::anyhow!("export proxy request missing authority"))?;
    ensure!(
        words.next() == Some("HTTP/1.1") && words.next().is_none() && origins.contains(authority),
        "export proxy origin denied"
    );
    Ok(authority.to_string())
}
async fn tunnel(mut downstream: TcpStream, origins: &BTreeSet<String>) -> Result<()> {
    let mut header = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !header.ends_with(b"\r\n\r\n") {
            ensure!(header.len() < 4096, "export proxy header too large");
            header.push(downstream.read_u8().await?);
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let target = authority(&header, origins)?;
    let validator = SsrfValidator::new(SsrfConfig {
        allow_http: false,
        ..Default::default()
    });
    let (_, addresses) = validator
        .validate_and_resolve(&format!("https://{target}/"))
        .await
        .map_err(|_| anyhow::anyhow!("export proxy DNS denied"))?;
    let address = addresses
        .first()
        .ok_or_else(|| anyhow::anyhow!("export proxy needs public DNS address"))?;
    let mut upstream =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address)).await??;
    downstream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proxy_rejects_redirected_internal_and_unconfigured_origins() {
        let allowed = BTreeSet::from(["catalog.example:443".into()]);
        assert!(authority(b"CONNECT catalog.example:443 HTTP/1.1\r\n\r\n", &allowed).is_ok());
        for request in [
            "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
            "CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n",
            "GET https://catalog.example/ HTTP/1.1\r\n\r\n",
            "CONNECT other.example:443 HTTP/1.1\r\n\r\n",
        ] {
            assert!(authority(request.as_bytes(), &allowed).is_err());
        }
    }
}
