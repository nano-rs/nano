// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open-core HEC front door. Vector's initial 200 allocates an ackId;
//! only a true indexer acknowledgement proves the Bronze PUT completed.
//! Match the hosted sender's poll-before-success contract for direct clients.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_BODY: usize = 50 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(25);

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct HecAckRequest {
    pub acks: Vec<u64>,
}

#[derive(Clone)]
struct Proxy {
    client: reqwest::Client,
    upstream: String,
    receipts: Arc<Mutex<BTreeMap<[u8; 32], Instant>>>,
    bodies: Arc<tokio::sync::Semaphore>,
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(body.into()))
        .unwrap()
}

impl Proxy {
    fn new(upstream: String) -> anyhow::Result<Self> {
        Ok(Self {
            upstream,
            receipts: Arc::default(),
            bodies: Arc::new(tokio::sync::Semaphore::new(1)),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(DEADLINE)
                .build()?,
        })
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        match tokio::time::timeout(DEADLINE, forward(self, request)).await {
            Ok(Ok(reply)) => reply,
            _ => response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"text":"Durable delivery not confirmed; retry","code":9}"#,
            ),
        }
    }
}

#[utoipa::path(post, path = "/services/collector/{endpoint}", tag = "ingestion",
    params(("endpoint" = String, Path, description = "HEC event, raw, or ack endpoint")),
    request_body = String,
    responses((status = 200, description = "Every event is durable; ACK queries return sender-bound receipts"),
        (status = 401, description = "Invalid or revoked ingest token"),
        (status = 413, description = "Request exceeds 50 MiB"),
        (status = 503, description = "Durable delivery not confirmed; retry")),
    security(("hec_token" = [])))]
async fn forward(
    proxy: &Proxy,
    request: Request<Incoming>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = request.uri().path();
    let ingest = matches!(
        path,
        "/services/collector"
            | "/services/collector/"
            | "/services/collector/event"
            | "/services/collector/event/1.0"
            | "/services/collector/raw"
            | "/services/collector/raw/1.0"
    );
    if !ingest
        && !matches!(
            path,
            "/services/collector/ack"
                | "/services/collector/health"
                | "/services/collector/health/1.0"
        )
    {
        return Ok(response(StatusCode::NOT_FOUND, "{}"));
    }
    let ack_query = path == "/services/collector/ack";
    let (parts, body) = request.into_parts();
    let url = format!(
        "{}{}",
        proxy.upstream,
        parts.uri.path_and_query().unwrap().as_str()
    );
    if !ingest && !ack_query {
        // Health has no request payload. Never let an anonymous slow body
        // occupy a connection until the delivery deadline.
        let reply = proxy.client.request(parts.method, url).send().await?;
        return Ok(response(reply.status(), reply.bytes().await?));
    }
    let channel = uuid::Uuid::from_bytes(random_id()?).to_string();
    // Authenticate headers before reading an upload. A sender without a valid
    // credential cannot monopolize the one large-body slot. The authoritative
    // token file and its revocation semantics remain owned by Vector.
    let mut check = proxy
        .client
        .post(format!("{}/services/collector/ack", proxy.upstream))
        .header("x-splunk-request-channel", &channel)
        .json(&serde_json::json!({"acks": []}));
    if let Some(auth) = parts.headers.get("authorization") {
        check = check.header("authorization", auth.clone());
    }
    let checked = check.send().await?;
    let checked_status = checked.status();
    let checked_body = checked.bytes().await?;
    if !checked_status.is_success() {
        return Ok(response(checked_status, checked_body));
    }
    let _body_permit = if ingest {
        match proxy.bodies.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"text":"Ingest busy; retry","code":9}"#,
                ))
            }
        }
    } else {
        None
    };
    let body = match Limited::new(body, if ingest { MAX_BODY } else { 128 * 1024 })
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(response(StatusCode::PAYLOAD_TOO_LARGE, "{}")),
    };
    let query_channel = reqwest::Url::parse(&format!("http://localhost{}", parts.uri))?
        .query_pairs()
        .find(|(key, _)| key == "channel")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let sender_channel = parts
        .headers
        .get("x-splunk-request-channel")
        .map(|h| h.as_bytes())
        .unwrap_or(query_channel.as_bytes());
    // A private channel prevents ackId reuse after a Vector restart from
    // confusing a prior request with a newly accepted, still pending batch.
    let mut headers = reqwest::header::HeaderMap::new();
    for name in [
        "authorization",
        "content-type",
        "content-encoding",
        "x-forwarded-for",
    ] {
        if let Some(value) = parts.headers.get(name) {
            headers.insert(name, value.clone());
        }
    }
    headers.insert("x-splunk-request-channel", channel.parse().unwrap());
    let ack_request = ack_query.then(|| body.clone());
    let reply = proxy
        .client
        .request(parts.method, url)
        .headers(headers.clone())
        .body(body)
        .send()
        .await?;
    let status = reply.status();
    let body = reply.bytes().await?;
    if !status.is_success() {
        return Ok(response(status, body));
    }
    if let Some(query) = ack_request {
        let query: HecAckRequest = match serde_json::from_slice(&query) {
            Ok(query) => query,
            Err(_) => return Ok(response(StatusCode::BAD_REQUEST, "{}")),
        };
        // The upstream request above authenticates even a cache hit (token
        // revocation is never bypassed). Match Vector's one-time ACK API.
        let ids = query.acks;
        if ids.len() > 1024 {
            return Ok(response(StatusCode::BAD_REQUEST, "{}"));
        }
        let mut acks = serde_json::Map::new();
        let mut receipts = proxy.receipts.lock().unwrap();
        for id in ids {
            let key = receipt_key(&headers, sender_channel, id);
            let delivered = receipts
                .remove(&key)
                .is_some_and(|expiry| expiry > Instant::now());
            acks.insert(id.to_string(), delivered.into());
        }
        return Ok(response(
            status,
            serde_json::to_vec(&serde_json::json!({"acks": acks}))?,
        ));
    }
    if !ingest {
        return Ok(response(status, body));
    }
    let mut receipt: serde_json::Value = serde_json::from_slice(&body)?;
    let id = receipt["ackId"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing durable receipt"))?;
    // Poll with exactly the sender's credential and channel. Never substitute
    // an install/admin credential. Failure, restart, or an unknown ackId must
    // never produce success. Issue a separate receipt for polling clients.
    loop {
        let mut poll = proxy
            .client
            .post(format!("{}/services/collector/ack", proxy.upstream))
            .header("x-splunk-request-channel", &channel);
        if let Some(auth) = headers.get("authorization") {
            poll = poll.header("authorization", auth.clone());
        }
        let reply = poll.json(&serde_json::json!({"acks": [id]})).send().await?;
        anyhow::ensure!(reply.status().is_success(), "ack query refused");
        let result: serde_json::Value = reply.json().await?;
        if result["acks"][id.to_string()].as_bool() == Some(true) {
            // Vector consumes a true ACK on read. Give polling senders a
            // separate receipt, bound to their token and channel. Receipts
            // expire and are bounded; losing one only causes a safe retry.
            let public_id = u64::from_le_bytes(
                uuid::Uuid::from_bytes(random_id()?).as_bytes()[..8]
                    .try_into()
                    .unwrap(),
            ) & ((1 << 53) - 1);
            let mut receipts = proxy.receipts.lock().unwrap();
            receipts.retain(|_, expiry| *expiry > Instant::now());
            if receipts.len() >= 8192 {
                receipts.pop_first();
            }
            receipts.insert(
                receipt_key(&headers, sender_channel, public_id),
                Instant::now() + Duration::from_secs(600),
            );
            receipt["ackId"] = public_id.into();
            return Ok(response(status, serde_json::to_vec(&receipt)?));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn random_id() -> anyhow::Result<[u8; 16]> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random request id: {e}"))?;
    Ok(bytes)
}

fn receipt_key(headers: &reqwest::header::HeaderMap, channel: &[u8], id: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(
        headers
            .get("authorization")
            .map(|h| h.as_bytes())
            .unwrap_or_default(),
    );
    hash.update([0]);
    hash.update(channel);
    hash.update(id.to_le_bytes());
    hash.finalize().into()
}

/// One large body plus bounded header/auth slots fit the memory guard. Busy
/// senders retry; an in-flight sender never receives a false success receipt.
#[utoipa::path(get, path = "/services/collector/health", tag = "ingestion",
    responses((status = 200, description = "HEC receiver health"),
        (status = 503, description = "HEC upstream unavailable")))]
pub async fn serve() -> anyhow::Result<()> {
    serve_on(
        tokio::net::TcpListener::bind("0.0.0.0:8088").await?,
        "http://vector:8088".into(),
    )
    .await
}

async fn serve_on(listener: tokio::net::TcpListener, upstream: String) -> anyhow::Result<()> {
    let proxy = Proxy::new(upstream)?;
    let capacity = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let permit = capacity.clone().acquire_owned().await?;
        let (stream, peer) = listener.accept().await?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
                let proxy = proxy.clone();
                if !request.headers().contains_key("x-forwarded-for") {
                    request
                        .headers_mut()
                        .insert("x-forwarded-for", peer.ip().to_string().parse().unwrap());
                }
                async move { Ok::<_, Infallible>(proxy.handle(request).await) }
            });
            // No keep-alive: a single idle connection cannot hold admission.
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .header_read_timeout(Duration::from_secs(5))
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct Lab {
        url: String,
        delivered: Arc<AtomicBool>,
        missing_receipt: Arc<AtomicBool>,
        revoked: Arc<AtomicBool>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    async fn lab() -> Lab {
        let delivered = Arc::new(AtomicBool::new(false));
        let missing_receipt = Arc::new(AtomicBool::new(false));
        let revoked = Arc::new(AtomicBool::new(false));
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", upstream.local_addr().unwrap());
        let (ready, missing, denied) =
            (delivered.clone(), missing_receipt.clone(), revoked.clone());
        let mock = tokio::spawn(async move {
            loop {
                let (stream, _) = upstream.accept().await.unwrap();
                let (ready, missing, denied) = (ready.clone(), missing.clone(), denied.clone());
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let (ready, missing, denied) =
                            (ready.clone(), missing.clone(), denied.clone());
                        async move {
                            let auth = request
                                .headers()
                                .get("authorization")
                                .and_then(|h| h.to_str().ok());
                            let result = if denied.load(Ordering::SeqCst)
                                || !matches!(auth, Some("Splunk sender" | "Splunk other"))
                            {
                                response(StatusCode::UNAUTHORIZED, "{}")
                            } else if request.uri().path().ends_with("/ack") {
                                response(StatusCode::OK, serde_json::json!({"acks": {"7": ready.load(Ordering::SeqCst)}}).to_string())
                            } else if missing.load(Ordering::SeqCst) {
                                response(StatusCode::OK, r#"{"code":0}"#)
                            } else {
                                response(StatusCode::OK, r#"{"code":0,"ackId":7}"#)
                            };
                            Ok::<_, Infallible>(result)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let proxy = tokio::spawn(async move {
            serve_on(listener, upstream_url).await.unwrap();
        });
        Lab {
            url,
            delivered,
            missing_receipt,
            revoked,
            tasks: vec![mock, proxy],
        }
    }

    fn post(
        client: &reqwest::Client,
        lab: &Lab,
        path: &str,
        token: &str,
        channel: &str,
    ) -> reqwest::RequestBuilder {
        client
            .post(format!("{}{path}", lab.url))
            .header("authorization", token)
            .header("x-splunk-request-channel", channel)
    }

    #[tokio::test]
    async fn success_waits_for_durable_put_and_polling_receipt_is_sender_bound() {
        let lab = lab().await;
        let client = reqwest::Client::new();
        let request = post(
            &client,
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "channel",
        )
        .body(r#"{"event":"burst"}"#)
        .send();
        tokio::pin!(request);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut request)
                .await
                .is_err(),
            "pending data must not get 200"
        );
        lab.delivered.store(true, Ordering::SeqCst);
        let receipt = request.await.unwrap();
        assert_eq!(receipt.status(), StatusCode::OK);
        let id = receipt.json::<serde_json::Value>().await.unwrap()["ackId"]
            .as_u64()
            .unwrap();
        for (token, channel, expected) in [
            ("Splunk other", "channel", false),
            ("Splunk sender", "wrong-channel", false),
            ("Splunk sender", "channel", true),
            ("Splunk sender", "channel", false),
        ] {
            let reply = post(&client, &lab, "/services/collector/ack", token, channel)
                .json(&serde_json::json!({"acks": [id]}))
                .send()
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            assert_eq!(
                reply.json::<serde_json::Value>().await.unwrap()["acks"][id.to_string()],
                expected
            );
        }
    }

    #[tokio::test]
    async fn missing_receipt_and_invalid_credentials_never_report_success() {
        let lab = lab().await;
        lab.missing_receipt.store(true, Ordering::SeqCst);
        let client = reqwest::Client::new();
        let result = post(
            &client,
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "channel",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        for path in ["/services/collector/event", "/services/collector/ack"] {
            let result = post(&client, &lab, path, "Splunk revoked", "channel")
                .body(r#"{"acks":[7]}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn lost_or_pending_ack_cannot_become_a_success_receipt() {
        let lab = lab().await;
        let client = reqwest::Client::new();
        let request = post(
            &client,
            &lab,
            "/services/collector/raw",
            "Splunk sender",
            "channel",
        )
        .body("raw event")
        .send();
        assert!(tokio::time::timeout(Duration::from_millis(200), request)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn query_channels_work_and_revocation_refuses_a_cached_receipt() {
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        let client = reqwest::Client::new();
        let reply = client
            .post(format!(
                "{}/services/collector/event?channel=query-channel",
                lab.url
            ))
            .header("authorization", "Splunk sender")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let id = reply.json::<serde_json::Value>().await.unwrap()["ackId"]
            .as_u64()
            .unwrap();
        lab.revoked.store(true, Ordering::SeqCst);
        let reply = client
            .post(format!(
                "{}/services/collector/ack?channel=query-channel",
                lab.url
            ))
            .header("authorization", "Splunk sender")
            .json(&serde_json::json!({"acks": [id]}))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
        lab.revoked.store(false, Ordering::SeqCst);
        let reply = client
            .post(format!(
                "{}/services/collector/ack?channel=query-channel",
                lab.url
            ))
            .header("authorization", "Splunk sender")
            .json(&serde_json::json!({"acks": [id]}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            reply.json::<serde_json::Value>().await.unwrap()["acks"][id.to_string()],
            true
        );
    }

    #[test]
    fn gateway_openapi_documents_its_listener_and_credential() {
        use utoipa::OpenApi;
        let spec = serde_json::to_value(HecProxyApiDoc::openapi()).unwrap();
        assert!(spec["paths"]["/services/collector/{endpoint}"]["post"].is_object());
        assert!(spec["paths"]["/services/collector/health"]["get"].is_object());
        assert_eq!(
            spec["components"]["securitySchemes"]["hec_token"]["name"],
            "Authorization"
        );
    }

    #[tokio::test]
    async fn an_unauthenticated_slow_upload_cannot_hold_ingest_admission() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        let mut attacker = tokio::net::TcpStream::connect(lab.url.trim_start_matches("http://"))
            .await
            .unwrap();
        attacker.write_all(b"POST /services/collector/event HTTP/1.1\r\nHost: localhost\r\nAuthorization: Splunk revoked\r\nContent-Length: 50000000\r\n\r\n").await.unwrap();
        // The attacker never sends its promised body. Authentication must
        // refuse it from headers, while an authorized sender still completes.
        let mut answer = [0; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), attacker.read(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&answer[..n])
            .unwrap()
            .contains("401 Unauthorized"));
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "channel",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
    }
}

/// The HEC gateway is a separate listener from nano-api.
#[derive(utoipa::OpenApi)]
#[openapi(paths(forward, serve), components(schemas(HecAckRequest)), modifiers(&HecSecurity))]
pub struct HecProxyApiDoc;

struct HecSecurity;

impl utoipa::Modify for HecSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "hec_token",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "Authorization",
                    "HEC ingest credential: Splunk <token>",
                ))),
            );
    }
}
