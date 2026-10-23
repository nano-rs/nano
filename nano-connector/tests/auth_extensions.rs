//! Synthetic protocol tests against the production TLS broker/sequence paths.
//! All credential/token values are generated in memory; no vendor fixtures.
mod common;
use base64::Engine as _;
use common::*;
use nano_connector::{
    auth,
    engine::RunInput,
    policy::EgressDeny,
    secrets::SecretSet,
    sequence::{self, Mode},
    spec::{AllowRule, AuthConfig},
    template::Scope,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Budget(AtomicUsize);
#[async_trait::async_trait]
impl sequence::RequestBudget for Budget {
    async fn reserve(&self) -> Result<bool, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}
fn random_secret() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn session(cookie: bool) -> Value {
    json!({"type":"session_login","login_url":"https://api.example.com/login", "credential_fields":{"username":"USER","password":"PASSWORD"},
        "encoding":if cookie {"form"} else {"json"}, "response":if cookie {json!({"type":"cookie","name":"sid","path_prefix":"/v1"})}
        else {json!({"type":"json_token","pointer":"/session/token","header":"X-Session","prefix":"Session "})}})
}
fn plan(auth: Value, url: &str, method: &str) -> sequence::Plan {
    let allow: Vec<AllowRule> = serde_json::from_value(
        json!([{"host":"api.example.com","path_prefixes":["/login","/v1"]}]),
    )
    .unwrap();
    let auth: AuthConfig = serde_json::from_value(auth).unwrap();
    let steps: Vec<sequence::Step> = serde_json::from_value(
        json!([{"id":"call","request":{"method":method,"url":url},"expect":{"status":[200]}}]),
    )
    .unwrap();
    sequence::compile(
        &allow,
        &auth,
        &steps,
        None,
        &BTreeMap::from([("result".into(), "steps.call".into())]),
        10,
    )
    .unwrap()
}
async fn sequence_run(
    h: &Harness,
    p: &sequence::Plan,
    credentials: &auth::Credentials,
    budget: &Budget,
    mode: Mode<'_>,
) -> Result<sequence::Output, sequence::Error> {
    let secrets = SecretSet::default();
    sequence::run(
        &sequence::RunContext {
            engine: &h.cfg,
            credentials,
            secrets: &secrets,
            deny: EgressDeny::default(),
            idempotency_key: None,
            budget,
        },
        p,
        Scope::default(),
        mode,
    )
    .await
}
async fn login_roundtrip(cookie: bool) {
    let user = random_secret();
    let password = random_secret();
    let first = random_secret();
    let second = random_secret();
    let (u, p, t1, t2) = (
        user.clone(),
        password.clone(),
        first.clone(),
        second.clone(),
    );
    let logins = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (l, c) = (logins.clone(), calls.clone());
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/login" {
                assert_eq!(r.method, "POST");
                if cookie {
                    let fields: BTreeMap<_, _> =
                        url::form_urlencoded::parse(&r.body).into_owned().collect();
                    assert_eq!(fields.get("username"), Some(&u));
                    assert_eq!(fields.get("password"), Some(&p));
                } else {
                    assert_eq!(
                        serde_json::from_slice::<Value>(&r.body).unwrap(),
                        json!({"username":u,"password":p})
                    );
                }
                let token = if l.fetch_add(1, Ordering::SeqCst) == 0 {
                    &t1
                } else {
                    &t2
                };
                return if cookie {
                    MockResp::json(json!({})).header(
                        "Set-Cookie",
                        &format!("sid={token}; Path=/v1; Secure; HttpOnly"),
                    )
                } else {
                    MockResp::json(json!({"session":{"token":token}}))
                };
            }
            let n = c.fetch_add(1, Ordering::SeqCst);
            let expected = if n == 0 { &t1 } else { &t2 };
            let (header, value) = if cookie {
                ("cookie", format!("sid={expected}"))
            } else {
                ("x-session", format!("Session {expected}"))
            };
            assert_eq!(r.headers.get(header), Some(&value));
            if n == 0 {
                return MockResp::status(401, json!({"echo":t1}));
            }
            MockResp::json(json!({"ok":true,"echo":[u,p,t1,t2]}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let credentials = creds(&[("USER", &user), ("PASSWORD", &password)]);
    let budget = Budget(AtomicUsize::new(0));
    let p = plan(session(cookie), "https://api.example.com/v1/action", "POST");
    for _ in 0..2 {
        let out = sequence_run(&h, &p, &credentials, &budget, Mode::Live)
            .await
            .unwrap();
        assert_eq!(out.outputs["result"]["ok"], true);
        let text = serde_json::to_string(&out).unwrap();
        for value in [&user, &password, &first, &second] {
            assert!(!text.contains(value));
        }
    }
    assert_eq!(logins.load(Ordering::SeqCst), 2);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(budget.0.load(Ordering::SeqCst), 5);
    // A fresh connection constructs a new plan; even identical credentials
    // must not reuse another connection's login cache.
    let fresh = plan(session(cookie), "https://api.example.com/v1/action", "GET");
    sequence_run(&h, &fresh, &credentials, &budget, Mode::Live)
        .await
        .unwrap();
    assert_eq!(logins.load(Ordering::SeqCst), 3);
}
#[tokio::test]
async fn session_json_login_reuses_refreshes_once_and_scrubs_every_issued_token() {
    login_roundtrip(false).await;
}
#[tokio::test]
async fn session_cookie_login_reuses_refreshes_once_and_scrubs_every_issued_token() {
    login_roundtrip(true).await;
}

#[tokio::test]
async fn session_login_failures_never_send_the_action_or_echo_vendor_bodies() {
    for status in [302, 401, 403, 429, 500] {
        let marker = random_secret();
        let reflected = marker.clone();
        let mock = start_mock(
            Arc::new(move |r| {
                assert_eq!(r.path, "/login");
                MockResp::status(status, json!({"error":reflected}))
                    .header("Location", "https://evil.example.com/")
            }),
            false,
        )
        .await;
        let h = harness(&mock);
        let p = plan(session(false), "https://api.example.com/v1/action", "GET");
        let err = sequence_run(
            &h,
            &p,
            &creds(&[("USER", &random_secret()), ("PASSWORD", &marker)]),
            &Budget(AtomicUsize::new(0)),
            Mode::Live,
        )
        .await
        .unwrap_err();
        if status == 429 {
            assert!(matches!(err, sequence::Error::RateLimited));
        } else {
            assert!(matches!(err, sequence::Error::Auth));
        }
        assert!(!err.to_string().contains(&marker));
        assert_eq!(mock.requests().len(), 1);
    }
}
#[tokio::test]
async fn session_second_401_stops_and_cookie_scope_refuses_other_paths() {
    let token = random_secret();
    let t = token.clone();
    let logins = Arc::new(AtomicUsize::new(0));
    let l = logins.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/login" {
                l.fetch_add(1, Ordering::SeqCst);
                MockResp::json(json!({"session":{"token":t}}))
            } else {
                MockResp::status(401, json!({}))
            }
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let credentials = creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]);
    let budget = Budget(AtomicUsize::new(0));
    let err = sequence_run(
        &h,
        &plan(session(false), "https://api.example.com/v1/action", "POST"),
        &credentials,
        &budget,
        Mode::Live,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, sequence::Error::Auth));
    assert_eq!(logins.load(Ordering::SeqCst), 2);
    assert_eq!(mock.requests().len(), 4);
    let mut config = session(true);
    config["response"]["path_prefix"] = json!("/restricted");
    assert!(matches!(
        sequence_run(
            &h,
            &plan(config, "https://api.example.com/v1/action", "GET"),
            &credentials,
            &budget,
            Mode::Live
        )
        .await
        .unwrap_err(),
        sequence::Error::Auth
    ));
    assert_eq!(mock.requests().len(), 4);
}
#[tokio::test]
async fn malformed_or_ambiguous_session_tokens_are_refused_specifically() {
    for variant in ["absent", "short", "bad_json", "duplicate_cookie"] {
        let token = random_secret();
        let t = token.clone();
        let mock = start_mock(
            Arc::new(move |_| match variant {
                "absent" => MockResp::json(json!({})),
                "short" => MockResp::json(json!({"session":{"token":"tiny"}})),
                "bad_json" => MockResp::text("{invalid"),
                _ => MockResp::json(json!({}))
                    .header("Set-Cookie", &format!("sid={t}"))
                    .header("Set-Cookie", &format!("sid={t}")),
            }),
            false,
        )
        .await;
        let h = harness(&mock);
        let p = plan(
            session(variant == "duplicate_cookie"),
            "https://api.example.com/v1/action",
            "GET",
        );
        assert!(matches!(
            sequence_run(
                &h,
                &p,
                &creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]),
                &Budget(AtomicUsize::new(0)),
                Mode::Live
            )
            .await
            .unwrap_err(),
            sequence::Error::Auth
        ));
        assert_eq!(mock.requests().len(), 1);
    }
}
#[test]
fn auth_parameters_reject_untrusted_templates_headers_and_canonical_fields() {
    let mut invalid = Vec::new();
    let mut login = session(false);
    login["login_url"] = json!("https://{{input.host}}/login");
    invalid.push(login);
    let mut login = session(false);
    login["response"]["header"] = json!("Host");
    invalid.push(login);
    invalid.push(json!({"type":"composite_token","header":"Content-Length","first_credential":"A","second_credential":"B","separator":"/"}));
    for field in ["header", "timestamp_header", "key_id_header"] {
        let mut hmac = json!({"type":"hmac","credential":"KEY","header":"X-Sig","message":"{body}","key_id_header":"X-Id","key_id_credential":"ID"});
        hmac[field] = json!("Host");
        invalid.push(hmac);
    }
    invalid.push(json!({"type":"hmac","credential":"KEY","header":"X-Sig","message":"{unknown}"}));
    invalid.push(json!({"type":"hmac","credential":"KEY","header":"X-Sig","message":"{method}","timestamp_header":"x-sig"}));
    for config in invalid {
        let mut params = config.as_object().unwrap().clone();
        let kind = params.remove("type").unwrap();
        assert!(matches!(
            auth::build(kind.as_str().unwrap(), &params),
            Err(auth::AuthError::Params(_))
        ));
    }
}

async fn hmac_wire(algorithm: &str, encoding: &str, signature: &'static str) {
    let mock = start_mock(
        Arc::new(move |r| {
            assert_eq!(r.method, "POST");
            assert_eq!(r.path, "/v1/action");
            assert_eq!(r.raw_query, "a=one+two");
            assert_eq!(r.body, br#"{"text":"literal {timestamp} {body}"}"#);
            assert_eq!(
                r.headers.get("x-timestamp").map(String::as_str),
                Some("1700000000")
            );
            assert_eq!(
                r.headers.get("x-key-id").map(String::as_str),
                Some("test-key-id")
            );
            assert_eq!(
                r.headers.get("x-signature").map(String::as_str),
                Some(signature)
            );
            MockResp::json(json!({"ok":true,"signature":signature}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    *h.now.lock().unwrap() = chrono::DateTime::from_timestamp(1700000000, 0).unwrap();
    let mut p = plan(
        json!({"type":"hmac","credential":"KEY","header":"X-Signature","message":"{method}\n{host}\n{uri_path}\n{query}\n{timestamp}\n{body}\n{body_sha256}","algorithm":algorithm,"encoding":encoding,"timestamp_header":"X-Timestamp","key_id_header":"X-Key-Id","key_id_credential":"ID"}),
        "https://api.example.com/v1/action",
        "POST",
    );
    p.steps[0]
        .request
        .query
        .insert("a".into(), "one two".into());
    p.steps[0].request.json = Some(json!({"text":"literal {timestamp} {body}"}));
    p = sequence::compile(
        &p.allow,
        &p.auth_config,
        &p.steps,
        None,
        &p.outputs,
        p.timeout_secs,
    )
    .unwrap();
    let out = sequence_run(
        &h,
        &p,
        &creds(&[("KEY", "engine-hmac-test-key"), ("ID", "test-key-id")]),
        &Budget(AtomicUsize::new(0)),
        Mode::Live,
    )
    .await
    .unwrap();
    assert_eq!(out.outputs["result"]["ok"], true);
    assert!(!serde_json::to_string(&out).unwrap().contains(signature));
}
// Expected signatures computed independently with Python's stdlib hmac/hashlib;
// synthetic protocol key only, never a shipped vendor credential/fixture.
#[tokio::test]
async fn hmac_sha256_hex_signs_exact_method_query_binary_safe_body_and_digest() {
    hmac_wire(
        "sha256",
        "hex",
        "9dbfff65be3ae5da66286fb9bf26284fbad876f646d27e1eb330510fd5302844",
    )
    .await;
}
#[tokio::test]
async fn hmac_sha512_base64_uses_the_configured_hash_and_encoding() {
    hmac_wire(
        "sha512",
        "base64",
        "dgXYQPb8z8tgqrlpXSPZdk1p3NSInwgekwovk1JZI6NTgAz/llTt0KBd4IX0FhxrwddldDvvO3FoFniZFpahjw==",
    )
    .await;
}

#[tokio::test]
async fn composite_token_uses_both_credentials_and_redacts_the_combined_header() {
    let key = random_secret();
    let id = random_secret();
    let composite = format!("{key}/{id}");
    let expected = composite.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            assert_eq!(r.headers.get("x-auth-token"), Some(&expected));
            MockResp::json(json!({"ok":true,"echo":expected}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let p = plan(
        json!({"type":"composite_token","header":"X-Auth-Token","first_credential":"KEY","second_credential":"ID","separator":"/"}),
        "https://api.example.com/v1/action",
        "GET",
    );
    let out = sequence_run(
        &h,
        &p,
        &creds(&[("KEY", &key), ("ID", &id)]),
        &Budget(AtomicUsize::new(0)),
        Mode::Live,
    )
    .await
    .unwrap();
    assert_eq!(out.outputs["result"]["ok"], true);
    let text = serde_json::to_string(&out).unwrap();
    for s in [&key, &id, &composite] {
        assert!(!text.contains(s));
    }
    assert!(matches!(
        sequence_run(
            &h,
            &p,
            &creds(&[("KEY", &key)]),
            &Budget(AtomicUsize::new(0)),
            Mode::Live
        )
        .await
        .unwrap_err(),
        sequence::Error::Auth
    ));
    assert!(matches!(
        sequence_run(
            &h,
            &p,
            &creds(&[("KEY", &key), ("ID", "invalid\r\nheader")]),
            &Budget(AtomicUsize::new(0)),
            Mode::Live
        )
        .await
        .unwrap_err(),
        sequence::Error::Auth
    ));
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn collector_session_login_is_isolated_between_tenants() {
    let user_a = random_secret();
    let user_b = random_secret();
    let token_a = random_secret();
    let token_b = random_secret();
    let (ua, ub, ta, tb) = (
        user_a.clone(),
        user_b.clone(),
        token_a.clone(),
        token_b.clone(),
    );
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/login" {
                let fields: Value = serde_json::from_slice(&r.body).unwrap();
                let token = if fields["username"] == ua {
                    &ta
                } else {
                    assert_eq!(fields["username"], ub);
                    &tb
                };
                return MockResp::json(json!({"session":{"token":token}}));
            }
            let auth = r.headers.get("x-session").unwrap();
            assert!(auth == &format!("Session {ta}") || auth == &format!("Session {tb}"));
            MockResp::json(json!({"data":[{"ok":true,"auth":auth}]}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let spec: nano_connector::spec::ConnectorSpec=serde_json::from_value(json!({"version":1,"name":"session_protocol","kind":"collector","auth":session(false),"allow":[{"host":"api.example.com"}],"streams":[{"id":"events","request":{"url":"https://api.example.com/v1/events"},"response":{"events_path":"data"}}]})).unwrap();
    for (tenant, user) in [("tenant-a", &user_a), ("tenant-b", &user_b)] {
        let result = run(
            &h,
            &spec,
            RunInput {
                tenant: Some(tenant.into()),
                credentials: creds(&[("USER", user), ("PASSWORD", &random_secret())]),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(result.out.unwrap().events, 1);
        let state = format!(
            "{:?}{:?}",
            result.store.saves.lock().unwrap(),
            result.sink.events()
        );
        for s in [&user_a, &user_b, &token_a, &token_b] {
            assert!(!state.contains(s));
        }
    }
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|r| r.path == "/login")
            .count(),
        2
    );
}

#[test]
fn exported_auth_schema_has_no_dangling_nested_references() {
    let schema = serde_json::to_value(nano_connector::spec::ConnectorSpec::json_schema()).unwrap();
    fn check(value: &Value, root: &Value) {
        match value {
            Value::Object(m) => {
                if let Some(Value::String(r)) = m.get("$ref") {
                    if let Some(p) = r.strip_prefix('#') {
                        assert!(root.pointer(p).is_some(), "dangling schema reference {r}");
                    }
                }
                for v in m.values() {
                    check(v, root);
                }
            }
            Value::Array(a) => {
                for v in a {
                    check(v, root);
                }
            }
            _ => {}
        }
    }
    check(&schema, &schema);
    let text = schema.to_string();
    assert!(text.contains("session_login") && text.contains("composite_token"));
}

#[tokio::test]
async fn hmac_sha1_signs_the_configured_compatibility_protocol() {
    hmac_wire("sha1", "hex", "d7309e50812ea21c5ef90f8b4c1ebd982e78f0e1").await;
}

#[tokio::test]
async fn hmac_sha384_signs_the_configured_compatibility_protocol() {
    hmac_wire("sha384","hex","f8d211769fb5ca675d65d638ff272718255db9ddca5178812ceaf316b05e40058c1bd57c4cf600ed8e59ad1e4ad03665").await;
}

#[tokio::test]
async fn new_auth_dry_runs_show_redacted_headers_without_logging_in_or_spending() {
    let mock = start_mock(Arc::new(|_| panic!("dry run dialed")), false).await;
    let h = harness(&mock);
    for (auth, header) in [
        (session(false), "X-Session"),
        (session(true), "Cookie"),
        (
            json!({"type":"composite_token","header":"X-Auth-Token","first_credential":"FIRST","second_credential":"SECOND","separator":"/"}),
            "X-Auth-Token",
        ),
        (
            json!({"type":"hmac","credential":"KEY","header":"X-Signature","message":"{body}"}),
            "X-Signature",
        ),
    ] {
        let p = plan(auth, "https://api.example.com/v1/action", "POST");
        let budget = Budget(AtomicUsize::new(0));
        let out = sequence_run(&h, &p, &creds(&[]), &budget, Mode::DryRun)
            .await
            .unwrap();
        assert!(out
            .http_summary
            .last()
            .unwrap()
            .headers
            .iter()
            .any(|(k, v)| k == header && v == "[REDACTED]"));
        assert_eq!(budget.0.load(Ordering::SeqCst), 0);
    }
    assert_eq!(mock.requests().len(), 0);
}

#[tokio::test]
async fn session_auth_never_retries_other_mutation_statuses() {
    for status in [403, 500, 302] {
        let token = random_secret();
        let t = token.clone();
        let mock = start_mock(
            Arc::new(move |r| {
                if r.path == "/login" {
                    MockResp::json(json!({"session":{"token":t}}))
                } else {
                    MockResp::status(status, json!({"echo":t}))
                        .header("Location", "https://evil.example.com/")
                }
            }),
            false,
        )
        .await;
        let h = harness(&mock);
        let p = plan(session(false), "https://api.example.com/v1/action", "POST");
        let error = sequence_run(
            &h,
            &p,
            &creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]),
            &Budget(AtomicUsize::new(0)),
            Mode::Live,
        )
        .await
        .unwrap_err();
        if status == 403 {
            assert!(matches!(error, sequence::Error::Auth));
        } else {
            assert!(matches!(error, sequence::Error::Ambiguous(_)));
        }
        assert!(!error.to_string().contains(&token));
        assert_eq!(mock.requests().len(), 2);
    }
}

#[tokio::test]
async fn session_token_expiry_fetches_again_after_reuse() {
    let token = random_secret();
    let t = token.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/login" {
                MockResp::json(json!({"session":{"token":t}}))
            } else {
                MockResp::json(json!({"ok":true}))
            }
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let mut auth = session(false);
    auth["expires_in_secs"] = json!(1);
    let p = plan(auth, "https://api.example.com/v1/item", "GET");
    let credentials = creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]);
    let budget = Budget(AtomicUsize::new(0));
    sequence_run(&h, &p, &credentials, &budget, Mode::Live)
        .await
        .unwrap();
    sequence_run(&h, &p, &credentials, &budget, Mode::Live)
        .await
        .unwrap();
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|r| r.path == "/login")
            .count(),
        1
    );
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    sequence_run(&h, &p, &credentials, &budget, Mode::Live)
        .await
        .unwrap();
    assert_eq!(
        mock.requests()
            .iter()
            .filter(|r| r.path == "/login")
            .count(),
        2
    );
}

#[tokio::test]
async fn refresh_cannot_bypass_the_request_usage_budget() {
    struct Limit(AtomicUsize);
    #[async_trait::async_trait]
    impl sequence::RequestBudget for Limit {
        async fn reserve(&self) -> Result<bool, String> {
            Ok(self.0.fetch_add(1, Ordering::SeqCst) < 2)
        }
    }
    let token = random_secret();
    let t = token.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/login" {
                MockResp::json(json!({"session":{"token":t}}))
            } else {
                MockResp::status(401, json!({}))
            }
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let p = plan(session(false), "https://api.example.com/v1/action", "POST");
    let credentials = creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]);
    let secrets = SecretSet::default();
    let budget = Limit(AtomicUsize::new(0));
    let error = sequence::run(
        &sequence::RunContext {
            engine: &h.cfg,
            credentials: &credentials,
            secrets: &secrets,
            deny: EgressDeny::default(),
            idempotency_key: None,
            budget: &budget,
        },
        &p,
        Scope::default(),
        Mode::Live,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, sequence::Error::RateLimited));
    assert_eq!(mock.requests().len(), 2);
}

#[tokio::test]
async fn login_outside_the_allowlist_is_refused_before_any_dial() {
    let mock = start_mock(Arc::new(|_| panic!("unallowlisted login dialed")), false).await;
    let h = harness(&mock);
    let mut config = session(false);
    config["login_url"] = json!("https://evil.example.com/login");
    let p = plan(config, "https://api.example.com/v1/action", "GET");
    let budget = Budget(AtomicUsize::new(0));
    let error = sequence_run(
        &h,
        &p,
        &creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]),
        &budget,
        Mode::Live,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, sequence::Error::Auth));
    assert_eq!(mock.requests().len(), 0);
    assert_eq!(budget.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn session_headers_stay_on_the_login_origin_even_when_another_host_is_allowed() {
    for cookie in [false, true] {
        let token = random_secret();
        let mock = start_mock(
            Arc::new(move |r| {
                if r.path == "/login" {
                    MockResp::json(json!({"session":{"token":token}}))
                        .header("Set-Cookie", &format!("sid={token}; Path=/v1"))
                } else {
                    MockResp::json(json!({"ok":true}))
                }
            }),
            false,
        )
        .await;
        let h = harness(&mock);
        let credentials = creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]);
        let budget = Budget(AtomicUsize::new(0));
        let mut p = plan(session(cookie), "https://api.example.com/v1/action", "GET");
        sequence_run(&h, &p, &credentials, &budget, Mode::Live)
            .await
            .unwrap();
        p.allow
            .push(serde_json::from_value(json!({"host":"logs.example.com"})).unwrap());
        p.steps[0].request.url = "https://logs.example.com/v1/action".into();
        let err = sequence_run(&h, &p, &credentials, &budget, Mode::Live)
            .await
            .unwrap_err();
        assert!(matches!(err, sequence::Error::Auth));
        assert_eq!(
            mock.requests().len(),
            2,
            "cross-origin request must not be sent"
        );
        assert_eq!(h.resolver.calls_for("logs.example.com"), 0);
    }
}

fn collector_spec(auth: Value) -> nano_connector::spec::ConnectorSpec {
    serde_json::from_value(json!({
        "version":1,"name":"auth_review","kind":"collector","auth":auth,
        "allow":[{"host":"api.example.com"}],
        "streams":[{"id":"events","request":{"url":"https://api.example.com/v1/events"},
            "response":{"events_path":"data"}}]
    }))
    .unwrap()
}

#[tokio::test]
async fn collector_initial_and_refresh_logins_obey_request_pacing() {
    use std::time::{Duration, Instant};
    let token = random_secret();
    let times = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = times.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            seen.lock().unwrap().push((r.path.clone(), Instant::now()));
            if r.path == "/login" {
                MockResp::json(json!({"session":{"token":token}}))
            } else if c.fetch_add(1, Ordering::SeqCst) == 0 {
                MockResp::status(401, json!({}))
            } else {
                MockResp::json(json!({"data":[{"ok":true}]}))
            }
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let mut spec = collector_spec(session(false));
    spec.rate_limit.min_interval_ms = 150;
    let started = Instant::now();
    let result = run(
        &h,
        &spec,
        RunInput {
            credentials: creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(result.out.unwrap().requests, 4);
    let times = times.lock().unwrap();
    assert_eq!(times.len(), 4);
    assert_eq!(times[0].0, "/login");
    assert!(times[0].1.duration_since(started) >= Duration::from_millis(150));
    assert_eq!(times[2].0, "/login");
    assert!(times[2].1.duration_since(times[1].1) >= Duration::from_millis(150));
}

#[tokio::test]
async fn collector_login_429_is_rate_limited_without_sending_data_requests() {
    let marker = random_secret();
    let reflected = marker.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            assert_eq!(r.path, "/login");
            MockResp::status(429, json!({"error":reflected})).header("Retry-After", "10")
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let result = run(
        &h,
        &collector_spec(session(false)),
        RunInput {
            credentials: creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]),
            ..Default::default()
        },
    )
    .await;
    let err = result.out.unwrap_err();
    assert!(matches!(
        &err,
        nano_connector::engine::EngineError::Upstream { status: 429, .. }
    ));
    assert!(!err.to_string().contains(&marker));
    assert_eq!(mock.requests().len(), 1);
    assert!(result.sink.events().is_empty());
}

#[tokio::test]
async fn collector_redacts_early_and_current_hmac_signatures_after_128_requests() {
    let signatures = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen = signatures.clone();
    let mock = start_mock(
        Arc::new(move |r| {
            let signature = r.headers["x-signature"].clone();
            let mut seen = seen.lock().unwrap();
            seen.push(signature.clone());
            let next = (seen.len() < 130).then_some(seen.len().to_string());
            MockResp::json(json!({"data":[{"early":seen[0],"current":signature,
                "encoded":base64::engine::general_purpose::STANDARD.encode(format!("{}:{signature}", seen[0]))}],"next":next}))
        }),
        false,
    )
    .await;
    let h = harness(&mock);
    let mut spec = collector_spec(
        json!({"type":"hmac","credential":"KEY","header":"X-Signature","message":"{method}:{path}"}),
    );
    spec.limits.max_requests = 130;
    spec.limits.max_pages = 130;
    spec.streams[0].pagination =
        serde_json::from_value(json!({"type":"token","from":"next","param":"page"})).unwrap();
    let result = run(
        &h,
        &spec,
        RunInput {
            credentials: creds(&[("KEY", &random_secret())]),
            ..Default::default()
        },
    )
    .await;
    let out = result.out.unwrap();
    assert_eq!(out.requests, 130);
    assert_eq!(out.events, 130);
    let state = format!(
        "{:?}{:?}{:?}",
        result.sink.events(),
        result.store.saves.lock().unwrap(),
        out
    );
    let signatures = signatures.lock().unwrap();
    assert_eq!(signatures.len(), 130);
    assert_ne!(signatures[0], signatures[129]);
    for signature in signatures.iter() {
        assert!(
            !state.contains(signature),
            "reflected signature escaped redaction"
        );
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{signature}", signatures[0]));
        assert!(
            !state.contains(&encoded),
            "encoded signatures escaped redaction"
        );
    }
}

// Hold both requests signed with token A until they are in flight, then let
// the late 401 arrive only after the early request has refreshed and used B.
// All actual requests still pass through the production TLS broker.
struct RefreshGate {
    broker: nano_connector::broker::Broker,
    old_header: (String, String),
    old_in_flight: tokio::sync::Barrier,
    fresh_used: tokio::sync::Semaphore,
}
#[async_trait::async_trait]
impl nano_connector::engine::Transport for RefreshGate {
    async fn send_once(
        &self,
        req: &nano_connector::broker::OutboundRequest,
        hosts: &nano_connector::policy::HostPolicy,
        caps: nano_connector::broker::BodyCaps,
    ) -> Result<nano_connector::broker::InboundResponse, nano_connector::broker::BrokerError> {
        let old = req.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case(&self.old_header.0) && value == &self.old_header.1
        });
        if old {
            self.old_in_flight.wait().await;
            if req.url.path() == "/v1/late" {
                self.fresh_used.acquire().await.unwrap().forget();
            }
        }
        let response = self.broker.send_once(req, hosts, caps).await?;
        if !old && req.url.path() == "/v1/early" && response.status == 200 {
            self.fresh_used.add_permits(1);
        }
        Ok(response)
    }
}

async fn concurrent_refresh(kind: &str, native: bool) {
    let first = random_secret();
    let second = random_secret();
    let logins = Arc::new(AtomicUsize::new(0));
    let l = logins.clone();
    let cookie = kind == "cookie";
    let oauth = kind == "oauth";
    let (t1, t2) = (first.clone(), second.clone());
    let mock = start_mock(
        Arc::new(move |r| {
            if r.path == "/login" {
                let n = l.fetch_add(1, Ordering::SeqCst);
                let token = if n == 0 { &t1 } else { &t2 };
                return MockResp::json(if oauth {
                    json!({"access_token":token,"expires_in":3600})
                } else {
                    json!({"session":{"token":token}})
                })
                .header("Set-Cookie", &format!("sid={token}; Path=/v1"));
            }
            let (header, prefix) = if cookie {
                ("cookie", "sid=")
            } else if oauth {
                ("authorization", "Bearer ")
            } else {
                ("x-session", "Session ")
            };
            if r.headers[header] == format!("{prefix}{t1}") {
                MockResp::status(401, json!({}))
            } else {
                assert_eq!(r.headers[header], format!("{prefix}{t2}"));
                MockResp::json(json!({"ok":true,"data":[{"ok":true}]}))
            }
        }),
        false,
    )
    .await;
    let mut h = harness(&mock);
    let (header, prefix) = if cookie {
        ("cookie", "sid=")
    } else if oauth {
        ("authorization", "Bearer ")
    } else {
        ("x-session", "Session ")
    };
    h.cfg.transport = Some(Arc::new(RefreshGate {
        broker: nano_connector::broker::Broker::new(h.cfg.broker.clone(), None).unwrap(),
        old_header: (header.into(), format!("{prefix}{first}")),
        old_in_flight: tokio::sync::Barrier::new(2),
        fresh_used: tokio::sync::Semaphore::new(0),
    }));
    let auth = if oauth {
        json!({"type":"oauth2_client_credentials","token_url":"https://api.example.com/login","client_id_credential":"USER","client_secret_credential":"PASSWORD"})
    } else {
        session(cookie)
    };
    let credentials = creds(&[("USER", &random_secret()), ("PASSWORD", &random_secret())]);
    if native {
        let p = plan(auth, "https://api.example.com/v1/{{config.item}}", "GET");
        let secrets = SecretSet::default();
        let budget = Budget(AtomicUsize::new(0));
        let ctx = sequence::RunContext {
            engine: &h.cfg,
            credentials: &credentials,
            secrets: &secrets,
            deny: EgressDeny::default(),
            idempotency_key: None,
            budget: &budget,
        };
        let early = Scope {
            config: json!({"item":"early"}),
            ..Default::default()
        };
        let late = Scope {
            config: json!({"item":"late"}),
            ..Default::default()
        };
        let (a, b) = tokio::join!(
            sequence::run(&ctx, &p, early, Mode::Live),
            sequence::run(&ctx, &p, late, Mode::Live),
        );
        assert_eq!(a.unwrap().outputs["result"]["ok"], true);
        assert_eq!(b.unwrap().outputs["result"]["ok"], true);
        assert_eq!(budget.0.load(Ordering::SeqCst), 6);
    } else {
        let mut spec = collector_spec(auth);
        spec.streams[0].request.as_mut().unwrap().url =
            "https://api.example.com/v1/{{item}}".into();
        spec.streams[0].fanout = Some(
            serde_json::from_value(json!({
                "discover":{"from":"static","items":["early","late"]},"concurrency":2
            }))
            .unwrap(),
        );
        let result = run(
            &h,
            &spec,
            RunInput {
                credentials,
                ..Default::default()
            },
        )
        .await;
        let out = result.out.unwrap();
        assert_eq!(out.events, 2);
        assert_eq!(out.requests, 6);
    }
    assert_eq!(
        logins.load(Ordering::SeqCst),
        2,
        "late rejection evicted the refreshed token"
    );
    assert_eq!(mock.requests().len(), 6);
}

#[tokio::test]
async fn collector_json_session_late_401_preserves_the_fanout_refresh() {
    concurrent_refresh("json", false).await;
}
#[tokio::test]
async fn collector_cookie_session_late_401_preserves_the_fanout_refresh() {
    concurrent_refresh("cookie", false).await;
}
#[tokio::test]
async fn collector_oauth_late_401_preserves_the_fanout_refresh() {
    concurrent_refresh("oauth", false).await;
}
#[tokio::test]
async fn native_concurrent_sessions_preserve_the_newer_cached_token() {
    for kind in ["json", "cookie"] {
        concurrent_refresh(kind, true).await;
    }
}

#[tokio::test]
async fn hmac_history_uses_the_compiled_ceiling_and_refuses_to_evict_at_capacity() {
    let mock = start_mock(
        Arc::new(|_| MockResp::status(302, json!({})).header("Location", "/v1/next")),
        false,
    )
    .await;
    let mut h = harness(&mock);
    h.cfg.ceilings.max_requests = 1;
    let mut spec = collector_spec(json!({
        "type":"hmac","credential":"KEY","header":"X-Signature","message":"{path}"
    }));
    spec.limits.max_requests = 10;
    let result = run(
        &h,
        &spec,
        RunInput {
            credentials: creds(&[("KEY", &random_secret())]),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(
        result.out.unwrap_err(),
        nano_connector::engine::EngineError::Auth(auth::AuthError::Signing(_))
    ));
    assert_eq!(
        mock.requests().len(),
        1,
        "a redirect must not evict signature history to sign beyond the compiled cap"
    );
}
