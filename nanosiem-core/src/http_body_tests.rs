// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A one-connection HTTP/1.1 server. `chunks` 1-KiB chunks are written with
/// `Transfer-Encoding: chunked` (no Content-Length), or `content_length` is
/// declared and the body written plainly. Returns the address and a counter of
/// body bytes the server managed to WRITE before the client hung up.
pub(crate) async fn serve(chunks: u64, content_length: Option<u64>) -> (SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let written = Arc::new(AtomicU64::new(0));
    let counter = written.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = [0u8; 2048];
        let _ = sock.read(&mut req).await;
        let head = match content_length {
            Some(len) => format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n"),
            None => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_string(),
        };
        if sock.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let chunk = vec![b'x'; 1024];
        for _ in 0..chunks {
            let res = if content_length.is_some() {
                sock.write_all(&chunk).await
            } else {
                let mut framed = b"400\r\n".to_vec();
                framed.extend_from_slice(&chunk);
                framed.extend_from_slice(b"\r\n");
                sock.write_all(&framed).await
            };
            if res.is_err() {
                return;
            }
            counter.fetch_add(1024, Ordering::Relaxed);
        }
        if content_length.is_none() {
            let _ = sock.write_all(b"0\r\n\r\n").await;
        }
    });
    (addr, written)
}

pub(crate) async fn get(addr: SocketAddr) -> Response {
    reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .send()
        .await
        .unwrap()
}

/// Exploit regression: a chunked body far larger than the cap is rejected
/// after reading only about the cap, instead of being buffered whole.
#[tokio::test]
async fn chunked_body_over_cap_stops_early() {
    // 64 MiB offered against a 64 KiB cap.
    let (addr, written) = serve(64 * 1024, None).await;
    let err = read_capped(get(addr).await, 64 * 1024).await.unwrap_err();
    assert!(matches!(err, BodyReadError::TooLarge { limit: 65536, .. }), "{err}");
    // The client stopped reading long before the server finished: socket
    // buffers allow a few MiB in flight, never the full 64 MiB.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(written.load(Ordering::Relaxed) < 32 * 1024 * 1024);
}

#[tokio::test]
async fn declared_length_over_cap_is_rejected_before_reading() {
    let (addr, _) = serve(0, Some(10 * 1024 * 1024)).await;
    let err = read_capped(get(addr).await, 1024).await.unwrap_err();
    assert!(
        matches!(err, BodyReadError::TooLarge { observed: 10485760, .. }),
        "{err}"
    );
}

/// Legitimate path: bodies at or under the cap come back byte-for-byte, with
/// or without Content-Length.
#[tokio::test]
async fn bodies_within_cap_are_returned_whole() {
    let (addr, _) = serve(8, None).await;
    assert_eq!(read_capped(get(addr).await, 8 * 1024).await.unwrap().len(), 8 * 1024);
    let (addr, _) = serve(8, Some(8 * 1024)).await;
    assert_eq!(read_capped(get(addr).await, 8 * 1024).await.unwrap().len(), 8 * 1024);
}

#[tokio::test]
async fn prefix_read_returns_at_most_the_limit() {
    let (addr, _) = serve(1024, None).await;
    let s = read_prefix_lossy(get(addr).await, 200).await;
    assert_eq!(s.len(), 200);
    let (addr, _) = serve(0, None).await;
    assert_eq!(read_prefix_lossy(get(addr).await, 200).await, "");
}
