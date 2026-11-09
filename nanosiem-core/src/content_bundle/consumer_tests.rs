// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::content_bundle::contract::tests_support as fx;
use crate::schema::SchemaId;

fn body(signed: &SignedContentDescriptor, url: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "descriptor": signed,
        "bundle_url": url,
        "bundle_sha256": signed.descriptor.payload.sha256,
        "bundle_url_expires_in": 300,
    }))
    .unwrap()
}

#[test]
fn parse_current_accepts_a_verified_descriptor_for_the_asked_channel() {
    let (signed, _) = fx::sealed("rules.main", 3, Utc::now());
    let r = parse_current(&body(&signed, "https://r2.example/x.nancontent"), &fx::ring(), "rules.main", false).unwrap();
    assert_eq!(r.signed, signed);
}

#[test]
fn parse_current_refuses_wrong_channel_digest_and_scheme() {
    let (signed, _) = fx::sealed("rules.main", 3, Utc::now());
    let ok = body(&signed, "https://r2.example/x");
    assert!(matches!(parse_current(&ok, &fx::ring(), "parsers.main", false), Err(ChannelError::Refused(_))));
    let mut v: serde_json::Value = serde_json::from_slice(&ok).unwrap();
    v["bundle_sha256"] = "00".repeat(32).into();
    assert!(parse_current(&serde_json::to_vec(&v).unwrap(), &fx::ring(), "rules.main", false).is_err());
    let http = body(&signed, "http://r2.example/x");
    assert!(parse_current(&http, &fx::ring(), "rules.main", false).is_err());
    assert!(parse_current(&http, &fx::ring(), "rules.main", true).is_ok(), "dev builds may opt into http");
    let creds = body(&signed, "https://user:pw@r2.example/x");
    assert!(parse_current(&creds, &fx::ring(), "rules.main", false).is_err());
}

#[test]
fn parse_current_refuses_an_untrusted_descriptor() {
    let (signed, _) = fx::sealed("rules.main", 3, Utc::now());
    let other = KeyRing::from_hex(&[("x", &"11".repeat(32))]);
    // an all-0x11 point may not be a valid key; any ring without the fixture key refuses
    if let Ok(other) = other {
        assert!(parse_current(&body(&signed, "https://r2.example/x"), &other, "rules.main", false).is_err());
    }
}

#[test]
fn subscriptions_follow_the_profile_and_edition() {
    let ocsf_open: Vec<_> = channels::subscribed(SchemaId::Ocsf, false).iter().map(|c| c.id).collect();
    assert_eq!(
        ocsf_open,
        vec![
            "parsers.main",
            "rules.main",
            "enrichments.main",
            "mitre-attack.v19-1",
        ]
    );
    let udm_ent: Vec<_> = channels::subscribed(SchemaId::Udm, true).iter().map(|c| c.id).collect();
    assert_eq!(
        udm_ent,
        vec![
            "parsers.legacy-clickhouse", "rules.legacy-clickhouse", "playbooks.main", "enrichments.main",
            "integrations.main", "models.main", "mitre-attack.v19-1",
        ]
    );
}

#[test]
fn first_party_repo_lookup() {
    assert_eq!(channels::for_repo("nano-rs", "parsers", "main").unwrap().id, "parsers.main");
    assert_eq!(channels::for_repo("NANOS-SH", "Rules.git", "legacy/clickhouse").unwrap().id, "rules.legacy-clickhouse");
    assert!(channels::for_repo("nano-rs", "parsers", "my-fork-branch").is_none());
    assert!(channels::for_repo("SigmaHQ", "sigma", "master").is_none());
    assert!(channels::is_first_party_owner("nano-rs"));
    assert!(!channels::is_first_party_owner("nano-rs-evil"));
    for c in channels::CHANNELS {
        assert!(channels::id_ok(c.id), "{}", c.id);
    }
}

#[test]
fn repo_url_pattern_matches_first_party_spellings_only() {
    let re = regex::RegexBuilder::new(&repo_url_pattern("parsers")).case_insensitive(true).build().unwrap();
    for ok in ["https://github.com/nano-rs/parsers", "github.com/nanos-sh/parsers.git", "https://www.github.com/NANO-RS/Parsers/"] {
        assert!(re.is_match(ok), "{ok}");
    }
    for bad in ["https://github.com/nano-rs/parsers-fork", "https://github.com/evil/parsers", "https://github.com/nano-rs/parsers/tree/x"] {
        assert!(!re.is_match(bad), "{bad}");
    }
}

#[test]
fn source_dirs_are_synthesized_for_listings() {
    use crate::content_bundle::store::StoredFile;
    let files = vec![
        StoredFile { path: "rules/a/x.yml".into(), blob_sha1: "1".repeat(40), size: 1 },
        StoredFile { path: "rules/b.yml".into(), blob_sha1: "2".repeat(40), size: 1 },
    ];
    let out = crate::content_bundle::source::with_dirs(&files, "rules");
    let names: Vec<_> = out.iter().map(|e| (e.0.as_str(), e.1)).collect();
    assert_eq!(names, vec![("rules", "tree"), ("rules/a", "tree"), ("rules/a/x.yml", "blob"), ("rules/b.yml", "blob")]);
}

/// NAN-4955 review: a presigned bundle URL's query string is a bearer
/// credential; neither a send error nor a body-stream error may carry it
/// into the strings the consumers log, store and return.
#[tokio::test]
async fn http_errors_never_carry_the_presigned_query() {
    use crate::platform_enrichment::consumer::http_error;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const SENTINEL: &str = "X-Amz-Signature=SENTINELdeadbeef";
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    // Send error: nothing listens on the port.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = free.local_addr().unwrap().port();
    drop(free);
    let err = client.get(format!("http://127.0.0.1:{port}/b.nancontent?{SENTINEL}")).send().await.unwrap_err();
    assert!(err.to_string().contains("SENTINEL"), "precondition: reqwest's display includes the URL");
    let text = http_error(err);
    assert!(!text.contains("SENTINEL") && !text.contains("X-Amz"), "{text}");

    // Stream error: headers promise 1000 bytes, the server sends 5 and closes.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nhello").await;
        let _ = s.shutdown().await;
    });
    let resp = client.get(format!("http://{addr}/b.nancontent?{SENTINEL}")).send().await.unwrap();
    let mut stream = futures::StreamExt::boxed(resp.bytes_stream());
    let mut stream_err = None;
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
        if let Err(e) = chunk {
            stream_err = Some(e);
            break;
        }
    }
    let text = http_error(stream_err.expect("truncated body must error"));
    assert!(!text.contains("SENTINEL") && !text.contains("X-Amz"), "{text}");
}

/// The open build knows no extension channel: an id it was never told about
/// is refused as unknown (by the registry and by the contract).
#[test]
fn unregistered_channel_ids_are_unknown() {
    assert!(channels::by_id("vendor-catalog").is_none());
    let (signed, _) = fx::sealed("rules.main", 3, Utc::now());
    let mut d = signed.descriptor.clone();
    d.channel = "vendor-catalog".into();
    assert!(d.validate().is_err());
}

#[test]
fn extension_channels_must_be_extension_kind_and_not_collide() {
    static BAD_KIND: [Channel; 1] = [Channel { id: "x-ext", kind: channels::Kind::Rules, repo: "", branch: "", artifact_path: None, route: Route::Enterprise, subscribers: channels::Subscribers::EnterpriseOnly }];
    static COLLIDE: [Channel; 1] = [Channel { id: "rules.main", kind: channels::Kind::Extension, repo: "", branch: "", artifact_path: None, route: Route::Enterprise, subscribers: channels::Subscribers::EnterpriseOnly }];
    assert!(channels::register_extension_channels(&BAD_KIND).is_err());
    assert!(channels::register_extension_channels(&COLLIDE).is_err());
}
