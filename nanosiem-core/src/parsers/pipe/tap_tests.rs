// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4919: live tap bounds, decoding and redaction. The capture itself is
//! exercised against the real pinned Vector image when
//! `NANO_PIPE_VECTOR_IMAGE` is set (Docker required).
use super::*;
use serde_json::json;

fn request(component: &str) -> TapRequest {
    TapRequest {
        component: component.into(),
        seconds: 5,
        max_events: 10,
    }
}

#[test]
fn a_tap_names_exactly_one_component_within_bounds() {
    request("hec_app_parse").validate().unwrap();
    for bad in ["*", "hec_*", "a,b", "hec-app", "HEC", "", "a b", "x{y}"] {
        assert!(request(bad).validate().is_err(), "{bad}");
    }
    let mut r = request("x");
    r.seconds = MAX_SECONDS + 1;
    assert!(r.validate().is_err());
    r.seconds = 1;
    r.max_events = MAX_EVENTS + 1;
    assert!(r.validate().is_err());
}

#[test]
fn relay_token_comparison_requires_a_long_secret() {
    let token = "x".repeat(MIN_TOKEN_BYTES);
    assert!(token_matches(&token, &token));
    assert!(!token_matches(&token, "y"));
    assert!(!token_matches("short", "short"));
}

/// A test-only `event.Metadata` that DOES carry secrets (tag 6), to prove the
/// relay's own declaration never decodes them.
#[derive(Clone, PartialEq, prost::Message)]
struct MetadataWithSecrets {
    #[prost(message, optional, tag = "1")]
    value: Option<PValue>,
    #[prost(message, optional, tag = "6")]
    secrets: Option<ValueMap>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct LogWithSecrets {
    #[prost(message, optional, tag = "2")]
    value: Option<PValue>,
    #[prost(message, optional, tag = "4")]
    metadata_full: Option<MetadataWithSecrets>,
}

fn s(v: &str) -> PValue {
    PValue {
        kind: Some(kind::Kind::RawBytes(v.as_bytes().to_vec())),
    }
}

fn map(pairs: &[(&str, PValue)]) -> PValue {
    PValue {
        kind: Some(kind::Kind::Map(ValueMap {
            fields: pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        })),
    }
}

#[test]
fn decoded_events_keep_values_and_input_identity_but_never_secrets() {
    let id = "6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10";
    let log = LogWithSecrets {
        value: Some(map(&[
            ("message", s("hello")),
            ("n", PValue { kind: Some(kind::Kind::Integer(7)) }),
        ])),
        metadata_full: Some(MetadataWithSecrets {
            value: Some(map(&[("nano_credential_id", s(id))])),
            secrets: Some(ValueMap {
                fields: [("splunk_hec_token".to_string(), s("SECRET-TOKEN"))].into(),
            }),
        }),
    };
    let bytes = prost::Message::encode_to_vec(&log);
    let decoded = <Log as prost::Message>::decode(bytes.as_slice()).unwrap();
    assert!(!format!("{decoded:?}").contains("SECRET-TOKEN"));
    assert_eq!(input_of(decoded.metadata_full.clone()), Some(format!("push:{id}")));
    assert_eq!(to_json(decoded.value.unwrap()), json!({"message":"hello","n":7}));
}

#[test]
fn captured_events_are_redacted_before_they_leave_the_api() {
    let mut capture = TapCapture {
        events: vec![TapEvent {
            event: json!({"message":"x","headers":{"Authorization":"Bearer abc","x-api-key":"k"},"ok":1}),
            input: None,
        }],
        ..Default::default()
    };
    redact(&mut capture).unwrap();
    assert_eq!(capture.events[0].event, json!({"message":"x","headers":{},"ok":1}));
}

/// Codex P1 (NAN-4919): a credential nested inside an ARRAY must not leak.
#[test]
fn redaction_descends_into_arrays() {
    let mut capture = TapCapture {
        events: vec![TapEvent {
            event: json!({"records":[{"headers":{"Authorization":"Bearer secret","ok":1}},
                                     [{"Set-Cookie":"s=1","keep":true}]],
                          "x":{"list":[{"X-API-KEY":"k"}]}}),
            input: None,
        }],
        ..Default::default()
    };
    redact(&mut capture).unwrap();
    let text = capture.events[0].event.to_string();
    assert!(!text.contains("secret") && !text.contains("s=1") && !text.contains("\"k\""), "{text}");
    assert_eq!(
        capture.events[0].event,
        json!({"records":[{"headers":{"ok":1}},[{"keep":true}]],"x":{"list":[{}]}})
    );
}

#[test]
fn tap_redaction_names_match_the_platform_redactor() {
    for name in CREDENTIAL_FIELD_NAMES {
        assert!(
            crate::parsers::vector_config::CREDENTIAL_FIELD_REDACTION_VRL.contains(&format!("\"{name}\"")),
            "{name} is not in the platform redaction list"
        );
    }
}

/// Codex P2 (NAN-4919): a relay response larger than the protocol bound is
/// refused while reading, before it is buffered whole or decoded.
#[tokio::test]
async fn oversized_relay_responses_are_refused_before_decoding() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = socket.read(&mut buf).await;
        // Chunked, no content-length: only a streaming bound can stop it.
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n")
            .await;
        let chunk = vec![b' '; 1024 * 1024];
        for _ in 0..64 {
            let head = format!("{:x}\r\n", chunk.len());
            if socket.write_all(head.as_bytes()).await.is_err()
                || socket.write_all(&chunk).await.is_err()
                || socket.write_all(b"\r\n").await.is_err()
            {
                return;
            }
        }
    });
    let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
    let error = read_relay_capture(response, 10).await.unwrap_err();
    assert!(error.contains("bound"), "{error}");
}

#[test]
fn relay_captures_are_revalidated_after_decoding() {
    let event = |n: usize| json!({"event": {"m": "x".repeat(n)}, "input": null});
    let body = |events: Vec<Value>| {
        serde_json::to_vec(&json!({"events": events, "dropped_oversize": 0, "ended": "deadline"})).unwrap()
    };
    decode_relay_capture(&body(vec![event(10)]), 1).unwrap();
    assert!(decode_relay_capture(&body(vec![event(10), event(10)]), 1).is_err());
    assert!(decode_relay_capture(&body(vec![event(MAX_EVENT_BYTES)]), 5).is_err());
}

#[tokio::test]
async fn pinned_vector_streams_the_input_of_one_component() {
    let Ok(image) = std::env::var("NANO_PIPE_VECTOR_IMAGE") else {
        eprintln!("NANO_PIPE_VECTOR_IMAGE unset; skipping the live tap fixture");
        return;
    };
    let dir = std::env::temp_dir().join(format!("nano-tap-fixture-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("vector.toml"),
        "[api]\nenabled = true\naddress = \"0.0.0.0:8686\"\n\
         [sources.input]\ntype = \"demo_logs\"\nformat = \"json\"\ninterval = 0.05\n\
         [transforms.src_parse]\ntype = \"remap\"\ninputs = [\"input\"]\nsource = \".parsed = true\"\n\
         [transforms.other_parse]\ntype = \"remap\"\ninputs = [\"input\"]\nsource = \".other = true\"\n\
         [sinks.out]\ntype = \"blackhole\"\ninputs = [\"src_parse\", \"other_parse\"]\n",
    )
    .unwrap();
    let name = format!("nan4919-tap-{}", std::process::id());
    let run = std::process::Command::new("docker")
        .args(["run", "-d", "--rm", "--name", &name, "-p", "127.0.0.1::8686", "-v"])
        .arg(format!("{}:/c:ro", dir.display()))
        .args([&image, "--config", "/c/vector.toml"])
        .output()
        .unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let port = String::from_utf8(
        std::process::Command::new("docker")
            .args(["port", &name, "8686"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let port = port.trim().rsplit(':').next().unwrap().to_string();
    let api = format!("http://127.0.0.1:{port}");
    let mut result = Err(String::new());
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        result = capture(
            &api,
            &TapRequest {
                component: "src_parse".into(),
                seconds: 3,
                max_events: 5,
            },
        )
        .await;
        if result.as_ref().is_ok_and(|c| !c.events.is_empty()) {
            break;
        }
    }
    let _ = std::process::Command::new("docker").args(["rm", "-f", &name]).output();
    let _ = std::fs::remove_dir_all(&dir);
    let capture = result.unwrap();
    assert_eq!(capture.events.len(), 5, "{capture:?}");
    assert_eq!(capture.ended, "max_events");
    // The INPUT of src_parse: raw demo events, not its output, never the
    // other component's.
    for event in &capture.events {
        assert!(event.event.get("parsed").is_none(), "{event:?}");
        assert!(event.event.get("other").is_none(), "{event:?}");
        assert!(event.event.get("message").is_some(), "{event:?}");
    }
}
