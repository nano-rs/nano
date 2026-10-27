//! Closed registry reflection coverage through native sequence execution.
//! Broker/token IO is primed with fakes; the real plugin and response redactor run.
use super::*;
use crate::{
    broker::{BodyCaps, BrokerError, InboundResponse},
    engine::{EngineConfig, Transport},
    policy::{EgressDeny, HostPolicy},
    secrets::SecretSet,
    sequence,
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};
fn secret() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
fn now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc)
}
struct Fetch {
    issued: Mutex<Vec<String>>,
}
impl Fetch {
    fn remember(&self, value: String) -> String {
        self.issued.lock().unwrap().push(value.clone());
        value
    }
    fn reply(&self, body: Value) -> BrokerReply {
        BrokerReply {
            status: 200,
            retry_after: None,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
}
#[async_trait::async_trait]
impl TokenFetch for Fetch {
    async fn post_form(
        &self,
        _: &str,
        form: &[(String, String)],
    ) -> Result<(u16, Vec<u8>), String> {
        for (name, value) in form {
            if matches!(name.as_str(), "assertion" | "client_assertion") {
                self.remember(value.clone());
            }
        }
        let token = self.remember(secret());
        Ok((
            200,
            serde_json::to_vec(
                &json!({"access_token":token,"expires_in":3600,"token_type":"Bearer"}),
            )
            .unwrap(),
        ))
    }
    async fn session_login(&self, _: &OutboundRequest) -> Result<InboundResponse, String> {
        let token = self.remember(secret());
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "set-cookie",
            format!("sid={token}; Secure; Path=/v1").parse().unwrap(),
        );
        Ok(InboundResponse {
            status: 200,
            headers,
            body: serde_json::to_vec(&json!({"token":token})).unwrap().into(),
        })
    }
    async fn post_dwd_assertion(&self, _: &Value) -> Result<BrokerReply, String> {
        let assertion = self.remember(format!("e30.e30.{}", secret()));
        Ok(self.reply(json!({"kind":"google_dwd_assertion","assertion":assertion})))
    }
    async fn post_graph_token(&self, _: &Value) -> Result<BrokerReply, String> {
        let token = self.remember(secret());
        Ok(self.reply(json!({"kind":"azure_access_token","access_token":token,"resource":GRAPH_RESOURCE,"expires_in":3600})))
    }
    async fn post_okta_assertion(&self, _: &Value) -> Result<BrokerReply, String> {
        let claims = json!({"iss":"client123","sub":"client123","aud":"https://acme.okta.com/oauth2/v1/token","exp":now().timestamp()+300});
        let assertion = self.remember(format!(
            "e30.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
            secret()
        ));
        Ok(self.reply(json!({"kind":"okta_client_assertion","assertion":assertion})))
    }
}
struct Reflect {
    primed: Vec<String>,
    seen: Mutex<Vec<String>>,
}
fn auth_material(request: &OutboundRequest) -> Vec<String> {
    let mut values = Vec::new();
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("content-type")
            || name.eq_ignore_ascii_case("date")
            || name.eq_ignore_ascii_case("x-amz-date")
        {
            continue;
        }
        values.push(value.clone());
        if let Some((_, signature)) = value.rsplit_once("Signature=") {
            values.push(signature.to_owned());
        }
        if let Some(encoded) = value.strip_prefix("Basic ") {
            values.push(encoded.to_owned());
            if let Ok(bytes) = STANDARD.decode(encoded) {
                if let Ok(pair) = String::from_utf8(bytes) {
                    values.push(pair.clone());
                    if let Some((_, signature)) = pair.split_once(':') {
                        values.push(signature.to_owned());
                    }
                }
            }
        }
    }
    values.extend(request.url.query_pairs().map(|(_, v)| v.into_owned()));
    if let Ok(v) = serde_json::from_slice::<Value>(&request.body) {
        if let Some(token) = v.get("api_key").and_then(Value::as_str) {
            values.push(token.to_owned());
        }
    }
    values
}
#[async_trait::async_trait]
impl Transport for Reflect {
    async fn send_once(
        &self,
        request: &OutboundRequest,
        hosts: &HostPolicy,
        _: BodyCaps,
    ) -> Result<InboundResponse, BrokerError> {
        hosts.check(&request.url)?;
        let mut reflected = self.primed.clone();
        reflected.extend(auth_material(request));
        self.seen.lock().unwrap().extend(reflected.clone());
        let shapes:Vec<_>=reflected.iter().map(|v|json!({"raw":v,"base64":STANDARD.encode(v),"hex":hex::encode(v),"percent":aws_encode(v)})).collect();
        Ok(InboundResponse {
            status: 200,
            headers: Default::default(),
            body: serde_json::to_vec(
                &json!({"control":"public fixture value","reflections":shapes}),
            )
            .unwrap()
            .into(),
        })
    }
}
struct Budget;
#[async_trait::async_trait]
impl sequence::RequestBudget for Budget {
    async fn reserve(&self) -> Result<bool, String> {
        Ok(true)
    }
}
fn cases() -> Vec<(&'static str, Value)> {
    vec![
        ("none", json!({})),
        ("bearer", json!({"credential":"TOKEN"})),
        ("okta_ssws", json!({"credential":"TOKEN"})),
        (
            "api_key_header",
            json!({"header":"X-Token","credential":"TOKEN"}),
        ),
        ("api_key_query", json!({"param":"key","credential":"TOKEN"})),
        (
            "json_body_credential",
            json!({"field":"api_key","credential":"TOKEN"}),
        ),
        (
            "basic",
            json!({"username_credential":"USER","password_credential":"PASSWORD"}),
        ),
        (
            "oauth2_client_credentials",
            json!({"token_url":"https://api.vendor.com/login","client_id_credential":"USER","client_secret_credential":"PASSWORD"}),
        ),
        (
            "oauth2_json_credential",
            json!({"oauth2":{"token_url":"https://api.vendor.com/login","client_id_credential":"USER","client_secret_credential":"PASSWORD"},"credential":"PIN","field_pointer":"/api_key","selector_pointer":"/operation","selector_value":"lookup","format":"six_digit_pin"}),
        ),
        (
            "google_service_account",
            json!({"token_url":"https://api.vendor.com/login","private_key_credential":"KEY","client_email_credential":"EMAIL","scope":"https://www.googleapis.com/auth/cloud-platform"}),
        ),
        (
            "google_dwd_broker",
            json!({"token_url":"https://api.vendor.com/login","scope":"https://www.googleapis.com/auth/admin.reports.audit.readonly","subject":"admin@example.com"}),
        ),
        (
            "entra_fic_broker",
            json!({"directory_id":"11111111-1111-4111-8111-111111111111","client_id":"22222222-2222-4222-8222-222222222222"}),
        ),
        (
            "okta_broker_jwt",
            json!({"okta_domain":"acme.okta.com","client_id":"client123","scope":"okta.users.read"}),
        ),
        (
            "session_login",
            json!({"login_url":"https://api.vendor.com/login","credential_fields":{"username":"USER","password":"PASSWORD"},"response":{"type":"json_token","pointer":"/token","header":"X-Session"}}),
        ),
        (
            "composite_token",
            json!({"header":"X-Composite","first_credential":"USER","second_credential":"PASSWORD","separator":"/"}),
        ),
        (
            "hmac",
            json!({"credential":"SECRET","header":"X-Signature","message":"{method}\n{path}\n{body}"}),
        ),
        (
            "duo_hmac",
            json!({"integration_key_credential":"IKEY","secret_key_credential":"SECRET"}),
        ),
        (
            "aws_sigv4",
            json!({"region":"us-east-1","service":"ec2","access_key_credential":"USER","secret_key_credential":"SECRET","session_token_credential":"TOKEN"}),
        ),
        (
            "mtls",
            json!({"cert_credential":"CERT","key_credential":"KEY","bearer_credential":"TOKEN"}),
        ),
    ]
}
fn credentials() -> Credentials {
    use aws_lc_rs::encoding::AsDer;
    let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
    let der: aws_lc_rs::encoding::Pkcs8V1Der<'static> = key.as_der().unwrap();
    Credentials::new(HashMap::from([
        ("TOKEN".into(), secret()),
        ("PIN".into(), "824671".into()),
        ("USER".into(), secret()),
        ("PASSWORD".into(), secret()),
        ("SECRET".into(), secret()),
        ("IKEY".into(), "DIABCDEFGHIJKLMNOPQR".into()),
        ("CERT".into(), secret()),
        (
            "KEY".into(),
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
                STANDARD.encode(der.as_ref())
            ),
        ),
        (
            "EMAIL".into(),
            format!("{}@example.iam.gserviceaccount.com", secret()),
        ),
    ]))
}
#[tokio::test]
async fn every_registered_auth_plugin_redacts_vendor_reflections_of_issued_material() {
    let cases = cases();
    assert_eq!(
        cases.iter().map(|(k, _)| *k).collect::<BTreeSet<_>>(),
        registry().iter().map(|r| r.name).collect(),
        "new plugins require a reflection case"
    );
    let credentials = credentials();
    for (kind, params) in cases {
        let auth = crate::spec::AuthConfig {
            kind: kind.into(),
            params: params.as_object().unwrap().clone(),
        };
        let allow=serde_json::from_value::<Vec<crate::spec::AllowRule>>(json!([{"host":"api.vendor.com","path_prefixes":["/login","/v1"]},{"host":"acme.okta.com","path_prefixes":["/oauth2"]}])).unwrap();
        let steps=serde_json::from_value::<Vec<sequence::Step>>(json!([{"id":"call","request":{"method":"POST","url":"https://api.vendor.com/v1/item","json":{"operation":"lookup"}},"expect":{"status":[200]}}])).unwrap();
        let plan = sequence::compile(
            &allow,
            &auth,
            &steps,
            None,
            &BTreeMap::from([("receipt".into(), "steps.call".into())]),
            10,
        )
        .unwrap();
        let fetch = Fetch {
            issued: Mutex::default(),
        };
        let scope = Scope::default();
        let mut priming = OutboundRequest {
            method: http::Method::POST,
            url: "https://api.vendor.com/v1/prime".parse().unwrap(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: br#"{"operation":"lookup"}"#.as_slice().into(),
        };
        plan.auth
            .apply(
                &mut priming,
                &AuthContext {
                    creds: &credentials,
                    fetch: &fetch,
                    scope: &scope,
                    now: now(),
                    feed_id: Some("reflection-feed"),
                },
            )
            .await
            .unwrap_or_else(|_| panic!("{kind}: fake auth setup refused"));
        let transport = Arc::new(Reflect {
            primed: fetch.issued.into_inner().unwrap(),
            seen: Mutex::default(),
        });
        let mut engine = EngineConfig::try_new("/unused-reflection".into()).unwrap();
        engine.transport = Some(transport.clone());
        engine.clock = Arc::new(now);
        let secrets = SecretSet::default();
        let context = sequence::RunContext {
            engine: &engine,
            credentials: &credentials,
            secrets: &secrets,
            deny: EgressDeny::default(),
            idempotency_key: None,
            budget: &Budget,
        };
        let out = sequence::run(&context, &plan, Scope::default(), sequence::Mode::Live)
            .await
            .unwrap_or_else(|_| panic!("{kind}: reflected native sequence failed"));
        assert_eq!(out.outputs["receipt"]["control"], "public fixture value");
        let public = serde_json::to_string(&out).unwrap();
        let mut sensitive = transport.seen.lock().unwrap().clone();
        if kind != "none" {
            assert!(!sensitive.is_empty(), "{kind}: vacuous reflection");
        }
        sensitive.extend(credentials.values().map(str::to_owned));
        sensitive.extend(plan.auth.derived_secrets());
        for value in sensitive {
            if value.len() >= crate::secrets::MIN_SECRET_LEN {
                for shape in [
                    value.clone(),
                    STANDARD.encode(&value),
                    hex::encode(&value),
                    aws_encode(&value),
                ] {
                    assert!(
                        !public.contains(&shape),
                        "{kind}: issued authentication material survived output redaction"
                    );
                }
            }
        }
    }
}
#[tokio::test]
async fn sigv4_retains_early_and_latest_signatures_and_refuses_before_overflow_decoration() {
    let mut plugin = build(
        "aws_sigv4",
        cases()
            .into_iter()
            .find(|(k, _)| *k == "aws_sigv4")
            .unwrap()
            .1
            .as_object()
            .unwrap(),
    )
    .unwrap();
    plugin.set_request_limit(2);
    let creds = credentials();
    let fetch = Fetch {
        issued: Mutex::default(),
    };
    let scope = Scope::default();
    let cx = AuthContext {
        creds: &creds,
        fetch: &fetch,
        scope: &scope,
        now: now(),
        feed_id: None,
    };
    for n in 0..2 {
        let mut req = OutboundRequest {
            method: http::Method::GET,
            url: format!("https://api.vendor.com/v1/{n}").parse().unwrap(),
            headers: vec![],
            body: Default::default(),
        };
        plugin.apply(&mut req, &cx).await.unwrap();
        let authorization = req
            .headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap()
            .1
            .clone();
        let signature = authorization
            .rsplit_once("Signature=")
            .unwrap()
            .1
            .to_owned();
        let retained = plugin.derived_secrets();
        assert!(retained.contains(&authorization) && retained.contains(&signature));
    }
    let retained = plugin.derived_secrets();
    assert_eq!(retained.len(), 4);
    let mut refused = OutboundRequest {
        method: http::Method::GET,
        url: "https://api.vendor.com/v1/overflow".parse().unwrap(),
        headers: vec![],
        body: Default::default(),
    };
    assert!(plugin.apply(&mut refused, &cx).await.is_err());
    assert!(refused.headers.is_empty());
    assert_eq!(retained, plugin.derived_secrets());
}

#[tokio::test]
async fn basic_retains_distinct_envelopes_without_eviction_and_refuses_credential_churn_at_cap() {
    let mut plugin = build(
        "basic",
        json!({"username_credential":"USER","password_credential":"PASSWORD"})
            .as_object()
            .unwrap(),
    )
    .unwrap();
    plugin.set_request_limit(2);
    let fetch = Fetch {
        issued: Mutex::default(),
    };
    let scope = Scope::default();
    for _ in 0..2 {
        let creds = Credentials::new(HashMap::from([
            ("USER".into(), secret()),
            ("PASSWORD".into(), secret()),
        ]));
        let cx = AuthContext {
            creds: &creds,
            fetch: &fetch,
            scope: &scope,
            now: now(),
            feed_id: None,
        };
        for _ in 0..2 {
            let mut request = OutboundRequest {
                method: http::Method::GET,
                url: "https://api.vendor.com/v1/item".parse().unwrap(),
                headers: vec![],
                body: Default::default(),
            };
            plugin.apply(&mut request, &cx).await.unwrap();
            let authorization = request
                .headers
                .iter()
                .find(|(k, _)| k == "Authorization")
                .unwrap()
                .1
                .clone();
            assert!(plugin.derived_secrets().contains(&authorization));
        }
    }
    let retained = plugin.derived_secrets();
    assert_eq!(retained.len(), 4);
    let creds = Credentials::new(HashMap::from([
        ("USER".into(), secret()),
        ("PASSWORD".into(), secret()),
    ]));
    let cx = AuthContext {
        creds: &creds,
        fetch: &fetch,
        scope: &scope,
        now: now(),
        feed_id: None,
    };
    let mut request = OutboundRequest {
        method: http::Method::GET,
        url: "https://api.vendor.com/v1/item".parse().unwrap(),
        headers: vec![],
        body: Default::default(),
    };
    assert!(plugin.apply(&mut request, &cx).await.is_err());
    assert!(request.headers.is_empty());
    assert_eq!(retained, plugin.derived_secrets());
}
