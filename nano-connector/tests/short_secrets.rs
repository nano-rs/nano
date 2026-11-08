//! NAN-4914 (codex P2-5): a secret credential shorter than the scrubber's
//! minimum is refused before any request, so a vendor echo of it can never
//! reach VRL, the sink or ClickHouse unredacted. Identifiers (client ids,
//! usernames, key ids) are not secrets and may be short.
mod common;

use std::sync::Arc;

use common::*;
use nano_connector::auth::{self, AuthError};
use nano_connector::engine::{EngineError, RunInput};
use serde_json::json;

fn collector(auth: &str) -> nano_connector::spec::ConnectorSpec {
    spec(&format!(
        "version: 1\nname: t\nkind: collector\nallow: [{{ host: api.example.com }}]\nauth: {auth}\nstreams:\n  - id: s\n    request: {{ url: \"https://api.example.com/v1/x\" }}\n    response: {{ events_path: events }}\n    ingest_id: {{ fields: [id] }}\n"
    ))
}

#[tokio::test]
async fn short_secrets_are_refused_before_any_request() {
    // The vendor reflects its credential header into the event body.
    let echo: Handler = Arc::new(|r: &MockReq| {
        let seen = r.headers.get("authorization").or(r.headers.get("x-api-key")).cloned().unwrap_or_default();
        MockResp::json(json!({"events": [{"id": "1", "echo": seen}]}))
    });
    for (auth, creds_) in [
        ("{ type: bearer, credential: TOKEN }", vec![("TOKEN", "abc12")]),
        ("{ type: api_key_header, header: X-Api-Key, credential: KEY }", vec![("KEY", "k1")]),
        ("{ type: api_key_header, header: X-Api-Key, credential: KEY, optional: true }", vec![("KEY", "k1")]),
        ("{ type: basic, username_credential: USER, password_credential: PASS }", vec![("USER", "admin"), ("PASS", "pw")]),
    ] {
        let mock = start_mock(echo.clone(), false).await;
        let h = harness(&mock);
        let r = run(&h, &collector(auth), RunInput { credentials: creds(&creds_), ..Default::default() }).await;
        assert!(matches!(r.out, Err(EngineError::Auth(AuthError::Params(ref m))) if m.contains("shorter")), "{auth}: {:?}", r.out.as_ref().err());
        assert!(mock.requests().is_empty(), "{auth}: a request was sent");
        assert!(r.sink.events().is_empty());
    }
}

#[tokio::test]
async fn short_identifiers_are_fine_and_long_secrets_are_scrubbed() {
    let echo: Handler = Arc::new(|r: &MockReq| MockResp::json(json!({"events": [{"id": "1", "echo": r.headers.get("authorization").cloned().unwrap_or_default()}]})));
    let mock = start_mock(echo, false).await;
    let h = harness(&mock);
    // Username "admin" (5 bytes) is an identifier; the password is long.
    let out = run(
        &h,
        &collector("{ type: basic, username_credential: USER, password_credential: PASS }"),
        RunInput { credentials: creds(&[("USER", "admin"), ("PASS", "long-enough-password")]), ..Default::default() },
    )
    .await;
    let ev = out.sink.events();
    out.out.expect("run");
    assert_eq!(ev.len(), 1);
    let shown = ev[0]["echo"].as_str().unwrap();
    assert!(!shown.contains("bG9uZy1lbm91Z2gtcGFzc3dvcmQ") && !shown.contains("long-enough-password"), "{shown}");
}

#[test]
fn plugins_declare_which_credential_fields_are_identifiers() {
    let b = |kind: &str, p: serde_json::Value| auth::build(kind, p.as_object().unwrap()).unwrap();
    let oauth = b("oauth2_client_credentials", json!({"token_url": "https://api.example.com/t", "client_id_credential": "CID", "client_secret_credential": "CS"}));
    assert_eq!(oauth.secret_fields(), vec!["CS".to_string()]);
    let sa = b("google_service_account", json!({"token_url": "https://oauth2.googleapis.com/token", "private_key_credential": "PK", "client_email_credential": "EMAIL", "scope": "s"}));
    assert_eq!(sa.secret_fields(), vec!["PK".to_string()]);
    let v4 = b("aws_sigv4", json!({"access_key_credential": "AK", "secret_key_credential": "SK", "service": "logs", "region": "us-east-1"}));
    assert_eq!(v4.secret_fields(), vec!["SK".to_string()]);
    let session = b("session_login", json!({"login_url":"https://api.example.com/login","credential_fields":{"username":"USER","password":"PASSWORD"},"response":{"type":"json_token","pointer":"/token","header":"X-Session"}}));
    assert_eq!(session.secret_fields(), vec!["PASSWORD".to_string()]);
    let bearer = b("bearer", json!({"credential": "T"}));
    assert_eq!(bearer.secret_fields(), vec!["T".to_string()]);
}
