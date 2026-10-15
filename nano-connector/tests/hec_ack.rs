// SPDX-License-Identifier: AGPL-3.0-or-later

//! A local Vector HEC admission is not a durable delivery receipt.
use std::{convert::Infallible, sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::Duration};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use nano_connector::{engine::Sink, service::{HecConfig, HecSink, Secret}};
use serde_json::json;
use tokio::net::TcpListener;
use uuid::Uuid;

async fn mock(ack_id: bool, acknowledge: bool) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let polls = Arc::new(AtomicUsize::new(0));
    let count = polls.clone();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let count = count.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let count = count.clone();
                    async move {
                        assert!(request.headers().contains_key("x-splunk-request-channel"));
                        let path = request.uri().path().to_string();
                        let _ = request.into_body().collect().await.unwrap();
                        let body = if path.ends_with("/ack") {
                            let n = count.fetch_add(1, Ordering::SeqCst);
                            json!({"acks": {"7": acknowledge && n > 0}})
                        } else if ack_id { json!({"code": 0, "ackId": 7}) }
                        else { json!({"code": 0}) };
                        Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from(body.to_string()))))
                    }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(tcp), service).await;
            });
        }
    });
    (url, polls, task)
}

#[tokio::test]
async fn local_sink_waits_for_true_ack_before_returning_receipt() {
    let (url, polls, task) = mock(true, true).await;
    let sink = HecSink::new(&url, Secret::new("fixture"), Uuid::new_v4(), "fixture", HecConfig {
        allow_http: true, require_ack: true, max_retry_total: Duration::from_secs(2), ..Default::default()
    }).unwrap();
    sink.push("fixture", &[json!({"id": 1})]).await.unwrap();
    assert!(polls.load(Ordering::SeqCst) >= 2);
    assert_eq!(sink.stats.events.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn missing_or_unconfirmed_ack_never_returns_a_receipt() {
    for ack_id in [false, true] {
        let (url, _, task) = mock(ack_id, false).await;
        let sink = HecSink::new(&url, Secret::new("fixture"), Uuid::new_v4(), "fixture", HecConfig {
            allow_http: true, require_ack: true, max_retry_total: Duration::from_millis(50), ..Default::default()
        }).unwrap();
        assert!(sink.push("fixture", &[json!({"id": 1})]).await.is_err());
        assert_eq!(sink.stats.events.load(Ordering::SeqCst), 0);
        task.abort();
    }
}
