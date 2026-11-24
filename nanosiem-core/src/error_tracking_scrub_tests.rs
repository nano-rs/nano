// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5798: secret scrubbing. Secrets in each field are removed; normal
//! messages, URLs, names and fields pass through unchanged.

use super::*;
use sentry::protocol::{
    Exception, Frame, LogEntry, Map, ResponseContext, Span, Stacktrace, TraceContext, Url, User,
};

/// (input, secret that must go, text that must stay)
const SECRET_TEXT: &[(&str, &str, &str)] = &[
    ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop", "Authorization: "),
    ("Cookie: a=1; session=real_secret; csrf=xyz", "real_secret", "Cookie: "),
    ("set-cookie: sid=s3cr3tvalue; Path=/", "s3cr3tvalue", "set-cookie: "),
    ("sent Bearer abcdefghijklmnop upstream", "abcdefghijklmnop", "upstream"),
    ("token nit_ABCDEFGHIJ0123456789 rejected", "nit_ABCDEFGHIJ", "rejected"),
    ("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk end", "eyJhbGci", " end"),
    ("key -----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY----- end", "MIIabc", " end"),
    ("access_token=t1 refresh_token=t2 client_secret=t3 password=t4 api_key=t5", "=t", "access_token="),
    (r#"{"api_key": "sk-123456"}"#, "sk-123456", "api_key"),
    ("GET /api/oidc/callback?code=c0de&state=ok&page=2", "c0de", "/api/oidc/callback?code="),
    ("https://h.test/x?token=abc123&sig=s1g&q=alice", "abc123", "q=alice"),
    ("connect postgres://nanosiem:hunter2@db:5432/x failed", "hunter2", "@db:5432/x failed"),
    ("dsn https://publickey123@o1.ingest.sentry.io/42", "publickey123", "@o1.ingest.sentry.io/42"),
    // Light review P2 #1: quoted, JSON and Debug-map header values.
    (r#"{"Cookie": "a=1; session=real_secret; csrf=xyz"}"#, "real_secret", r#"{"Cookie""#),
    (r#"{"Set-Cookie": "nano_session=s3cr3tvalue; Path=/; HttpOnly"}"#, "s3cr3tvalue", "Set-Cookie"),
    (r#"{"Authorization": "Splunk my-hec-secret-123"}"#, "my-hec-secret-123", "Authorization"),
    (r#"headers: {"authorization": "Token my-api-secret-123", "accept": "json"}"#, "my-api-secret-123", r#""accept": "json""#),
    (r#"Cookie="nano_session=s3cr3t; csrf=xyz""#, "s3cr3t", "Cookie="),
    // Single-quoted and spaced secrets.
    ("password='hunter2' rejected", "hunter2", " rejected"),
    ("SELECT * FROM t WHERE client_secret = 'top secret phrase'", "top secret", "SELECT * FROM t WHERE client_secret"),
    ("{'api_key': 'sk-123456', 'host': 'dc01'}", "sk-123456", "'host': 'dc01'"),
    // A password containing `@`.
    ("postgres://user:p@ss@db.internal/x", "ss@db", "@db.internal/x"),
];

#[test]
fn secrets_in_text_are_removed() {
    for (input, secret, kept) in SECRET_TEXT {
        let out = scrub_text(input);
        assert!(!out.contains(secret), "{input:?} -> {out:?} still has {secret:?}");
        assert!(out.contains(kept), "{input:?} -> {out:?} lost {kept:?}");
    }
    assert!(!scrub_text("sig=s1g").is_empty());
    assert!(!scrub_text("https://h.test/x?token=abc123&sig=s1g").contains("s1g"));
}

#[test]
fn normal_text_passes_unchanged() {
    for keep in [
        "search failed for alice: Code: 27. DB::Exception: Cannot parse 'dc01,10.1.2.3' (at row 3). (CANNOT_PARSE_INPUT_ASSERTION_FAILED)",
        "GET /api/hunts/0198f7a2-1c3e-7d4b-9a10-3b5c7e9f0a12?tab=findings&page=2",
        "query parse error: SELECT actor_user FROM ocsf_events WHERE user = alice_admin",
        "peer 2001:db8::1 and 10.20.30.40 refused",
        "login for analyst@example.com failed",
        "nanosiem_core::search::service::core_search",
        "upgraded to v2.0.23 at 12:30:45",
    ] {
        assert_eq!(scrub_text(keep), keep);
    }
}

#[test]
fn request_urls_are_scrubbed_structurally_and_never_fail_open() {
    // Light review P2 #2: text scrubbing of this URL produced an unparseable
    // string (`auth-secret:[Filtered]`), and the original was kept.
    for (raw, secret, kept) in [
        ("http://auth-secret:8080/api?token=mysecret&page=2", "mysecret", "page=2"),
        ("https://u:p%40ss@nano.test/api/search?q=alice&api_key=k3y&code=c0de#frag", "k3y", "q=alice"),
        ("https://nano.test/api/x?sig=s1g&next=/a?token=t0k", "s1g", "nano.test/api/x"),
    ] {
        let mut request = Request { url: Some(Url::parse(raw).unwrap()), ..Default::default() };
        scrub_request(&mut request);
        let url = request.url.expect("url kept").to_string();
        assert!(!url.contains(secret), "{raw} -> {url}");
        assert!(url.contains(kept), "{raw} -> {url} lost {kept}");
        assert!(!url.contains("p%40ss") && !url.contains("c0de") && !url.contains("t0k"), "{raw} -> {url}");
    }
}

#[test]
fn secret_named_fields_and_tags_are_filtered_others_kept() {
    let mut map: BTreeMap<String, Value> = [
        ("query", Value::from("user=alice")),
        ("password", Value::from("hunter2")),
        ("ingest_token", Value::from("x")),
        ("client_secret", Value::from("x")),
        ("Authorization", Value::from("Bearer x")),
        ("nested", serde_json::json!({"api_key": "sk-1", "host": "dc01"})),
        ("url", Value::from("/api/x?token=abc&q=1")),
        ("status", Value::from(500)),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    scrub_fields(&mut map);
    assert_eq!(map["query"], Value::from("user=alice"));
    assert_eq!(map["status"], Value::from(500));
    for k in ["password", "ingest_token", "client_secret", "Authorization"] {
        assert_eq!(map[k], Value::from(FILTERED), "{k}");
    }
    assert_eq!(map["nested"], serde_json::json!({"api_key": FILTERED, "host": "dc01"}));
    assert_eq!(map["url"], Value::from("/api/x?token=[Filtered]&q=1"));
}

#[test]
fn every_payload_path_loses_secrets_and_keeps_the_rest() {
    let mut event = Event {
        message: Some("lookup failed for 10.20.30.40 with password=hunter2".into()),
        logentry: Some(LogEntry { message: "token=tok1 for alice".into(), params: vec![Value::from("Bearer abcdefghij123")] }),
        transaction: Some("/api/search/shared/abc?token=tok2".into()),
        fingerprint: Cow::Owned(vec!["{{ default }}".into(), "client_secret=x".into(), "alice".into()]),
        ..Default::default()
    };
    event.request = Some(Request {
        url: Some(Url::parse("https://u:p@nano.test/api/search?q=alice&api_key=k3y").unwrap()),
        method: Some("POST".into()),
        cookies: Some("session=abc".into()),
        query_string: Some("q=alice&token=tok3".into()),
        headers: [("Authorization".to_string(), "Bearer t".to_string()), ("Accept".to_string(), "json".to_string())]
            .into_iter()
            .collect(),
        ..Default::default()
    });
    event.user = Some(User { id: Some("42".into()), ip_address: Some("10.9.9.9".parse().unwrap()), ..Default::default() });
    event.exception.values.push(Exception {
        ty: "SearchError".into(),
        value: Some("Code: 62. DB::Exception: Syntax error near 'alice' token=tok4".into()),
        stacktrace: Some(Stacktrace {
            frames: vec![Frame {
                function: Some("nanosiem_core::search::run".into()),
                vars: [("password".to_string(), Value::from("hunter2"))].into_iter().collect(),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    });
    event.tags.insert("api_key".into(), "sk-1".into());
    event.tags.insert("service".into(), "nanosiem-api".into());
    event.extra.insert("dsn".into(), "https://k@o1.ingest.sentry.io/1".into());
    event.contexts.insert(
        "trace".into(),
        Context::Trace(Box::new(TraceContext {
            description: Some("search token=tok5".into()),
            data: [("query".to_string(), Value::from("user=alice")), ("secret".to_string(), Value::from("s"))].into_iter().collect(),
            ..Default::default()
        })),
    );
    event.contexts.insert(
        "response".into(),
        Context::Response(Box::new(ResponseContext {
            cookies: Some("s=1".into()),
            headers: [("Set-Cookie".to_string(), "sid=zz9".to_string())].into_iter().collect(),
            ..Default::default()
        })),
    );
    event.breadcrumbs.values.push(Breadcrumb {
        message: Some("console: Authorization: Bearer abcdefghijklmnop".into()),
        data: [("url".to_string(), Value::from("/api/x?code=c0de"))].into_iter().collect(),
        ..Default::default()
    });

    scrub_event(&mut event);
    let text = serde_json::to_string(&event).unwrap();
    for secret in ["hunter2", "tok1", "abcdefghij123", "tok2", "client_secret=x", ":p@", "k3y", "session=abc", "tok3", "Bearer t\"", "tok4", "sk-1", "https://k@", "tok5", "\"s\"", "s=1", "zz9", "c0de", "10.9.9.9"] {
        assert!(!text.contains(secret), "{secret:?} leaked: {text}");
    }
    for kept in ["lookup failed for 10.20.30.40", "/api/search/shared/abc?token=", "alice", "nanosiem_core::search::run", "SearchError", "Syntax error near 'alice'", "nanosiem-api", "user=alice", "json", "{{ default }}"] {
        assert!(text.contains(kept), "{kept:?} lost: {text}");
    }

    let mut tx = Transaction {
        name: Some("GET /api/hunts/h1?token=tok6".into()),
        tags: [("token".to_string(), "t7".to_string()), ("run_id".to_string(), "r1".to_string())].into_iter().collect(),
        spans: vec![Span {
            description: Some("SELECT * FROM logs WHERE user = 'alice' -- password=hunter2".into()),
            op: Some("db.query".into()),
            data: [("db.password".to_string(), Value::from("x9")), ("rows".to_string(), Value::from(3))].into_iter().collect(),
            ..Default::default()
        }],
        ..Default::default()
    };
    scrub_transaction(&mut tx);
    let text = serde_json::to_string(&tx).unwrap();
    for secret in ["tok6", "t7", "hunter2", "x9"] {
        assert!(!text.contains(secret), "{secret:?} leaked: {text}");
    }
    for kept in ["GET /api/hunts/h1?token=", "SELECT * FROM logs WHERE user = 'alice'", "db.query", "r1", "\"rows\":3"] {
        assert!(text.contains(kept), "{kept:?} lost: {text}");
    }

    let mut log = Log {
        level: sentry::protocol::LogLevel::Warn,
        body: "rate limited alice, Cookie: sid=c00kie".into(),
        trace_id: None,
        timestamp: std::time::SystemTime::now(),
        severity_number: None,
        attributes: [
            ("sentry.message.template".to_string(), Value::from("rate limited {}, Cookie: sid=c00kie").into()),
            ("sentry.message.parameter.0".to_string(), Value::from("Bearer abcdefghij999").into()),
            ("access_token".to_string(), Value::from("a7").into()),
            ("user".to_string(), Value::from("alice").into()),
        ]
        .into_iter()
        .collect::<Map<_, _>>(),
    };
    scrub_log(&mut log);
    let text = format!("{} {:?}", log.body, log.attributes);
    for secret in ["c00kie", "abcdefghij999", "a7\""] {
        assert!(!text.contains(secret), "{secret:?} leaked: {text}");
    }
    assert!(log.body.starts_with("rate limited alice"));
    assert_eq!(log.attributes["user"].0, Value::from("alice"));
}
