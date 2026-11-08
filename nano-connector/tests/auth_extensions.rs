//! Auth plugins on the collector path, against the production TLS broker.
//! All credential/token values are generated in memory; no vendor fixtures.
//! (The request-sequence half of this suite moved to
//! nanosiem-enterprise/tests/soar_engine_auth_extensions.rs in NAN-4914.)
mod common;
use base64::Engine as _;
use common::*;
use nano_connector::{auth, engine::RunInput};
use serde_json::{json, Value};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

fn random_secret() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn session(cookie: bool) -> Value {
    json!({"type":"session_login","login_url":"https://api.example.com/login", "credential_fields":{"username":"USER","password":"PASSWORD"},
        "encoding":if cookie {"form"} else {"json"}, "response":if cookie {json!({"type":"cookie","name":"sid","path_prefix":"/v1"})}
        else {json!({"type":"json_token","pointer":"/session/token","header":"X-Session","prefix":"Session "})}})
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
    // Since every redirect hop consumes the request budget (codex P2-7), the
    // compiled request cap stops the hop before the plugin would have to
    // sign beyond its history; either refusal is correct, eviction is not.
    let err = result.out.unwrap_err();
    assert!(
        matches!(
            err,
            nano_connector::engine::EngineError::Auth(auth::AuthError::Signing(_))
                | nano_connector::engine::EngineError::Cap(_)
        ),
        "{err}"
    );
    assert_eq!(
        mock.requests().len(),
        1,
        "a redirect must not evict signature history to sign beyond the compiled cap"
    );
}

