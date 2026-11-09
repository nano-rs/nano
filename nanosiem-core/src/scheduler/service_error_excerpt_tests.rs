// SPDX-License-Identifier: AGPL-3.0-or-later
//! Non-2xx feed responses never panic the scheduler loop (security review
//! 2026-11-08, NAN-5017).

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serve one response with `status` and `body` (chunked, no Content-Length).
async fn respond(status: &'static str, body: Vec<u8>) -> reqwest::Response {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = [0u8; 2048];
        let _ = sock.read(&mut req).await;
        let mut out = format!("HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\n\r\n").into_bytes();
        for part in body.chunks(4096) {
            out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            out.extend_from_slice(part);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        let _ = sock.write_all(&out).await;
    });
    reqwest::get(format!("http://{addr}/")).await.unwrap()
}

/// Exploit regression: 199 ASCII bytes then `€` straddling byte 200 made
/// `&error_body[..200]` panic inside the supervised loop.
#[tokio::test]
async fn multibyte_char_at_the_cut_does_not_panic() {
    let body = format!("{}€ upstream detail", "a".repeat(199)).into_bytes();
    let response = respond("503 Service Unavailable", body).await;
    let status = response.status();
    let SchedulerError::FetchError(msg) = http_status_error(status, response).await else {
        panic!("expected FetchError");
    };
    assert_eq!(msg, format!("HTTP error 503 Service Unavailable: {}...", "a".repeat(199)));
}

/// A huge error body is not buffered: only the excerpt is read.
#[tokio::test]
async fn huge_error_body_yields_a_short_excerpt() {
    let response = respond("500 Internal Server Error", vec![b'e'; 8 * 1024 * 1024]).await;
    let status = response.status();
    let SchedulerError::FetchError(msg) = http_status_error(status, response).await else {
        panic!("expected FetchError");
    };
    assert!(msg.ends_with("..."));
    assert!(msg.len() < 300, "{}", msg.len());
}

/// Legitimate path: a short error body is reported verbatim.
#[tokio::test]
async fn short_error_body_is_verbatim() {
    let response = respond("404 Not Found", b"no such feed".to_vec()).await;
    let status = response.status();
    let SchedulerError::FetchError(msg) = http_status_error(status, response).await else {
        panic!("expected FetchError");
    };
    assert_eq!(msg, "HTTP error 404 Not Found: no such feed");
}
