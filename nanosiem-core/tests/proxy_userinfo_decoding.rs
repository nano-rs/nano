// SPDX-License-Identifier: AGPL-3.0-or-later

//! The installer writes an authenticated proxy as
//! `HTTPS_PROXY=http://<pct-user>:<pct-pass>@host:port` (RFC 3986 userinfo,
//! everything outside unreserved percent-encoded). reqwest builds env proxies
//! with the same `Proxy` URL parsing used here, so this proves it decodes the
//! userinfo before sending Basic `Proxy-Authorization`.

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What the installer's pct_encode produces for these inputs.
fn pct_encode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn proxied_authorization(user: &str, pass: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 4096];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
        }
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
        String::from_utf8_lossy(&request).to_string()
    });
    let proxy_url = format!("http://{}:{}@{addr}", pct_encode(user), pct_encode(pass));
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
        .build()
        .unwrap();
    client.get("http://upstream.nano.invalid/").send().await.unwrap();
    let request = server.await.unwrap();
    request
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("proxy-authorization").then(|| value.trim().to_string())
        })
        .expect("no Proxy-Authorization header sent")
}

#[tokio::test]
async fn percent_encoded_proxy_credentials_are_decoded_for_basic_auth() {
    for (user, pass) in [
        ("svc-nano", "p@ss:w/rd!#$&+=%"),
        ("CORP\\svc nano", "pässwörd/+="),
        ("plain", "plain"),
    ] {
        let header = proxied_authorization(user, pass).await;
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        );
        assert_eq!(header, expected, "user={user:?}");
    }
}
