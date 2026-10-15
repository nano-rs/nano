//! G2: the security suite. Every attack must fail closed with a typed error,
//! and the mock must show that nothing reached a forbidden destination.

mod common;

use std::io::Write;
use std::sync::Arc;

use common::*;
use nano_connector::broker::BrokerError;
use nano_connector::engine::{EngineError, RunInput};
use nano_connector::policy::PolicyError;
use nano_connector::vrl_exec::VrlError;
use serde_json::json;

const SECRET: &str = "sk_live_THIS-IS-THE-SECRET-42";

fn collector(body: &str) -> String {
    format!(
        r#"
version: 1
name: g2
kind: collector
allow:
  - host: api.example.com
    path_prefixes: ["/v1"]
  - host: internal.example.com
auth: {{ type: bearer, credential: TOKEN }}
rate_limit: {{ backoff_ms: 10, max_retries_5xx: 0 }}
{body}
"#
    )
}

fn is_policy(r: &Result<nano_connector::engine::RunOutput, EngineError>) -> bool {
    matches!(r, Err(EngineError::Policy(_)) | Err(EngineError::Broker(BrokerError::Policy(_))))
}

fn input() -> RunInput {
    RunInput { credentials: creds(&[("TOKEN", SECRET)]), ..Default::default() }
}

fn assert_no_request_outside(mock: &Mock, h: &Harness) {
    for r in mock.requests() {
        assert!(r.host == "api.example.com" || r.host == "internal.example.com", "request reached {}", r.host);
        assert!(r.path.starts_with("/v1") || r.host != "api.example.com", "path {} escaped", r.path);
    }
    for a in h.dialer.dialed.lock().unwrap().iter() {
        assert_eq!(a.ip().to_string(), PUBLIC_IP, "dialed a non-pinned address {a}");
    }
}

#[tokio::test]
async fn ssrf_via_templated_url_and_program_fails_closed() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": []}))), false).await;
    let h = harness(&mock);

    // 1. A state value with traversal is encoded into one segment, then refused.
    let s = spec(&collector(
        r#"
streams:
  - id: s
    initial_state: { p: "../../admin" }
    request: { url: "https://api.example.com/v1/{{state.p}}" }
"#,
    ));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::Policy(PolicyError::PathNotAllowed { .. }))) | Err(EngineError::Policy(PolicyError::PathNotAllowed { .. }))), "{:?}", r.out.err());

    // 2. A program steering next_request at metadata, a literal private IP,
    //    IPv6 loopback, a non-allowlisted host and plain http.
    for target in [
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/v1/x",
        "https://10.0.0.1/v1/x",
        "https://[::1]/v1/x",
        "https://[::ffff:169.254.169.254]/v1/x",
        "https://evil.example.com/v1/x",
        "http://api.example.com/v1/x",
        "https://api.example.com:8443/v1/x",
        "https://api.example.com/admin",
        "https://metadata.google.internal/computeMetadata/v1/",
    ] {
        let s = spec(&collector(&format!(
            r#"
streams:
  - id: s
    program: |
      if .response == null {{ {{"next_request": {{"url": "{target}"}}}} }} else {{ {{"events": []}} }}
"#
        )));
        let r = run(&h, &s, input()).await;
        assert!(is_policy(&r.out), "{target}: {:?}", r.out.as_ref().err());
    }

    // 3. A config-supplied host must match the suffix rule.
    let s = spec(
        r#"
version: 1
name: g2
kind: collector
allow:
  - host: "{{config.DOMAIN}}"
    host_suffixes: [".okta.com"]
streams:
  - id: s
    request: { url: "https://{{config.DOMAIN}}/api" }
"#,
    );
    for d in ["169.254.169.254", "evil.com", "okta.com.evil.com", "a.okta.com/../x", "localhost"] {
        let r = run(&h, &s, RunInput { config: config(json!({"DOMAIN": d})), ..Default::default() }).await;
        assert!(is_policy(&r.out), "{d}: {:?}", r.out.as_ref().err());
    }

    // 4. An allowlisted name that resolves to a private address.
    h.resolver.set("internal.example.com", vec![vec!["10.0.0.5"]]);
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://internal.example.com/x\" }\n"));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DnsBlocked { .. }))), "{:?}", r.out.as_ref().err());

    assert!(mock.requests().is_empty(), "no request may reach the mock: {:?}", mock.requests());
    assert_no_request_outside(&mock, &h);
}

#[tokio::test]
async fn redirect_to_private_address_is_refused_before_connecting() {
    for (loc, expect_dns) in [
        ("https://10.0.0.1/v1/x", false),
        ("https://169.254.169.254/latest/meta-data/", false),
        ("https://[fd00:ec2::254]/v1/x", false),
        ("http://api.example.com/v1/x", false),
        ("https://internal.example.com/v1/x", true),
        ("/admin", false),
    ] {
        let mock = start_mock(
            Arc::new(move |r| {
                if r.path == "/v1/start" {
                    MockResp::status(302, json!({})).header("location", loc)
                } else {
                    MockResp::json(json!({"leaked": true}))
                }
            }),
            false,
        )
        .await;
        let h = harness(&mock);
        h.resolver.set("internal.example.com", vec![vec!["10.0.0.5"]]);
        let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/start\" }\n"));
        let r = run(&h, &s, input()).await;
        match (&r.out, expect_dns) {
            (Err(EngineError::Broker(BrokerError::DnsBlocked { .. })), true) => {}
            (Err(EngineError::Policy(_)) | Err(EngineError::Broker(BrokerError::Policy(_))), false) => {}
            other => panic!("{loc}: {:?}", other.0.as_ref().err()),
        }
        assert_eq!(mock.requests().len(), 1, "{loc}: only the first hop may be sent");
        assert_no_request_outside(&mock, &h);
    }
}

#[tokio::test]
async fn dns_rebinding_cannot_move_a_pinned_connection() {
    let mock = start_mock(
        Arc::new(|r| {
            let page: u32 = r.query.get("cursor").and_then(|c| c.parse().ok()).unwrap_or(0);
            let next = if page < 3 { json!((page + 1).to_string()) } else { json!(null) };
            MockResp::json(json!({ "items": [{"page": page}], "next": next }))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    // Public at check time, private on every later lookup.
    h.resolver.set("api.example.com", vec![vec![PUBLIC_IP], vec!["10.0.0.9"], vec!["169.254.169.254"]]);
    let s = spec(&collector(
        r#"
streams:
  - id: s
    request: { url: "https://api.example.com/v1/items" }
    response: { events_path: items }
    pagination: { type: cursor, from: next, param: cursor }
"#,
    ));
    let r = run(&h, &s, input()).await;
    let out = r.out.expect("pinned run succeeds");
    assert_eq!(out.events, 4);
    assert_eq!(h.resolver.calls_for("api.example.com"), 1, "resolved exactly once per run");
    // Four pages over one kept-alive connection, dialed to the pinned IP.
    let dialed = h.dialer.dialed.lock().unwrap().clone();
    assert_eq!(dialed.len(), 1, "pages reuse the pinned connection: {dialed:?}");
    assert!(dialed.iter().all(|a| a.to_string() == format!("{PUBLIC_IP}:443")), "{dialed:?}");

    // A mixed answer (one public, one private) is refused outright.
    let h = harness(&mock);
    h.resolver.set("api.example.com", vec![vec![PUBLIC_IP, "10.0.0.9"]]);
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DnsBlocked { .. }))));
}

#[tokio::test]
async fn credentials_cannot_be_exfiltrated_via_template_query_body_or_reflection() {
    // 1. Templates have no credentials namespace.
    let bad = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\", query: { k: \"{{credentials.TOKEN}}\" } }\n",
    ));
    let mock = start_mock(
        Arc::new(|r| {
            // An allowlisted endpoint that echoes the request back, auth included.
            MockResp::json(json!({ "echo_auth": r.headers.get("authorization"), "echo_query": r.raw_query, "items": [] }))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let r = run(&h, &bad, input()).await;
    assert!(matches!(r.out, Err(EngineError::Template(_))), "{:?}", r.out.as_ref().err());

    // 2. A reflecting endpoint: the program sees a redacted body, and tries to
    //    ship what it saw in the query and in a POST body.
    let s = spec(&collector(
        r#"
streams:
  - id: s
    request: { url: "https://api.example.com/v1/echo" }
    program: |
      if .state.round == null {
        {"events": [.response.body], "state": {"round": 1},
         "next_request": {"query": {"stolen": .response.body.echo_auth}, "form": {"stolen": .response.body.echo_auth}}}
      } else {
        {"events": [.response.body]}
      }
"#,
    ));
    let r = run(&h, &s, input()).await;
    r.out.expect("run with redacted reflection succeeds");
    for e in r.sink.events() {
        assert!(!e.to_string().contains(SECRET), "secret reached an event: {e}");
    }
    for req in mock.requests() {
        assert!(!req.raw_query.contains(SECRET) && !String::from_utf8_lossy(&req.body).contains(SECRET), "secret left in query/body");
    }

    // 3. A program that knows the secret (e.g. typed into code) cannot place it
    //    in a query or body.
    let s = spec(&collector(&format!(
        r#"
streams:
  - id: s
    request: {{ url: "https://api.example.com/v1/echo" }}
    program: |
      if .state.round == null {{
        {{"state": {{"round": 1}}, "next_request": {{"query": {{"k": "{SECRET}"}}}}}}
      }} else {{ {{"events": []}} }}
"#
    )));
    let before = mock.requests().len();
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::CredentialExfil)), "{:?}", r.out.as_ref().err());
    assert_eq!(mock.requests().len(), before + 1, "the exfil request was never sent");

    // 4. next_request has no headers field: an Authorization override is a
    //    shape error.
    let s = spec(&collector(
        r#"
streams:
  - id: s
    request: { url: "https://api.example.com/v1/echo" }
    program: |
      if .state.round == null {
        {"state": {"round": 1}, "next_request": {"headers": {"Authorization": "Bearer x"}}}
      } else { {"events": []} }
"#,
    ));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::ProgramShape(_))), "{:?}", r.out.as_ref().err());

    // 5. Spec headers cannot carry auth.
    let s = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\", headers: { Authorization: \"Bearer {{config.X}}\" } }\n",
    ));
    assert!(matches!(run(&h, &s, input()).await.out, Err(EngineError::Spec(_))));
}

#[tokio::test]
async fn decompression_bomb_and_huge_response_are_capped() {
    let bomb = {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1024 * 1024];
        for _ in 0..200 {
            gz.write_all(&zeros).unwrap();
        }
        gz.finish().unwrap()
    };
    let compressed = bomb.len();
    let mock = start_mock(
        Arc::new(move |r| match r.path.as_str() {
            "/v1/bomb" => MockResp { status: 200, headers: vec![("content-encoding".into(), "gzip".into())], body: bomb.clone() },
            _ => MockResp { status: 200, headers: vec![], body: vec![b'a'; 40 * 1024 * 1024] },
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let s = spec(&collector(
        "limits: { max_decompressed_bytes: 16777216, max_response_bytes: 8388608 }\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/bomb\" }\n",
    ));
    let r = run(&h, &s, input()).await;
    assert!(compressed < 1024 * 1024, "bomb is {compressed} bytes compressed");
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DecompressedTooLarge(16777216)))), "{:?}", r.out.as_ref().err());

    let s = spec(&collector(
        "limits: { max_response_bytes: 8388608 }\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/huge\" }\n",
    ));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::ResponseTooLarge(8388608)))), "{:?}", r.out.as_ref().err());
}

#[tokio::test]
async fn vrl_workloads_hit_the_budget_and_the_host_survives() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": [1]}))), false).await;
    let h = harness(&mock);

    // Memory: 40 doublings of a string (1 TiB) dies on the worker's RLIMIT_AS.
    let doubling: String = (0..40).map(|_| "s = s + s\n      ").collect();
    let s = spec(&collector(&format!(
        r#"
limits: {{ vrl_timeout_ms: 5000 }}
streams:
  - id: s
    request: {{ url: "https://api.example.com/v1/x" }}
    program: |
      s = "xxxxxxxxxxxxxxxx"
      {doubling}{{"events": [strlen(s)]}}
"#
    )));
    let t = std::time::Instant::now();
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Vrl(VrlError::WorkerDied(_) | VrlError::Budget(_)))), "{:?}", r.out.as_ref().err());
    eprintln!("memory bomb stopped in {:?}: {:?}", t.elapsed(), r.out.as_ref().err());

    // CPU: a 4M-element array walked with regexes exceeds a 300 ms budget.
    let grow: String = (0..22).map(|_| "a = flatten([a, a])\n      ").collect();
    let s = spec(&collector(&format!(
        r#"
limits: {{ vrl_timeout_ms: 300 }}
streams:
  - id: s
    request: {{ url: "https://api.example.com/v1/x" }}
    program: |
      a = ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"]
      {grow}n = 0
      for_each(a) -> |_i, v| {{ if match(string!(v), r'^(a+)+$') {{ n = n + 1 }} }}
      {{"events": [n]}}
"#
    )));
    let t = std::time::Instant::now();
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Vrl(VrlError::Budget(300)))), "{:?}", r.out.as_ref().err());
    assert!(t.elapsed() < std::time::Duration::from_secs(5), "killed promptly: {:?}", t.elapsed());

    // Output: a program returning a giant event list is capped.
    let s = spec(&collector(&format!(
        r#"
limits: {{ vrl_timeout_ms: 5000, max_events: 1000 }}
streams:
  - id: s
    request: {{ url: "https://api.example.com/v1/x" }}
    program: |
      a = [1]
      {}{{"events": a}}
"#,
        (0..14).map(|_| "a = flatten([a, a])\n      ").collect::<String>()
    )));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Cap(_))), "{:?}", r.out.as_ref().err());

    // The host is fine: a normal run still works.
    let s = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    response: { events_path: items }\n",
    ));
    assert_eq!(run(&h, &s, input()).await.out.expect("healthy run").events, 1);
}

#[tokio::test]
async fn wall_clock_cap_stops_a_slow_run() {
    let mock = start_mock(
        Arc::new(|_r| MockResp::json(json!({"items": [1], "next": "x"})).delay(std::time::Duration::from_millis(700))),
        false,
    )
    .await;
    let h = harness(&mock);
    let s = spec(&collector(
        "limits: { max_run_secs: 2 }\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    response: { events_path: items }\n    pagination: { type: cursor, from: next, param: c }\n",
    ));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::WallClock(2))), "{:?}", r.out.as_ref().err());
}
