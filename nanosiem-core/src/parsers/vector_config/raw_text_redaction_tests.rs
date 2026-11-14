// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5352: credential values written inside TEXT never reach storage.
//!
//! The NAN-4038 key walk removes credential-named fields, but a credential
//! inside a string survived it: an OCSF parser copies the received line into
//! `raw_data` (and often `message`), so a text/plain body such as
//! `{"Authorization": "Bearer ..."}` was stored verbatim. The storage-boundary
//! macro now also redacts the VALUE in place in every string, keeping the rest
//! of the original text. These tests run the macro on the VRL runtime.
//!
//! Every secret here is an obvious fake (`FAKE-...`).

use regex::Regex;
use serde_json::{json, Value as Json};
use vrl::compiler::runtime::Runtime;
use vrl::compiler::state::RuntimeState;
use vrl::compiler::{compile, TargetValue, TimeZone};
use vrl::value::{Secrets, Value};

use super::parser_config::OCSF_PREPARE_VRL;
use super::{
    CREDENTIAL_ESCAPE_GATE_VRL, CREDENTIAL_FIELD_REDACTION_VRL, CREDENTIAL_KEY_PRECHECK_VRL,
    CREDENTIAL_TEXT_GATE_VRL, CREDENTIAL_TEXT_REDACTION_VRL,
};
use crate::parsers::pipe::tap::CREDENTIAL_FIELD_NAMES;

const PREPARE_INPUTS: &str = include_str!("../../../tests/fixtures/nan5180/ocsf_prepare_inputs.ndjson");

const MARKER: &str = "[REDACTED: credential-bearing text]";

fn run(program: &str, event: &Json, metadata: &Json) -> (Json, Json) {
    let compiled = compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles:\n{}", vrl::diagnostic::Formatter::new(program, d)))
        .program;
    let mut target = TargetValue {
        value: Value::from(event.clone()),
        metadata: Value::from(metadata.clone()),
        secrets: Secrets::new(),
    };
    Runtime::new(RuntimeState::default())
        .resolve(&mut target, &compiled, &TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
    (target.value.try_into().unwrap(), target.metadata.try_into().unwrap())
}

/// The macro on `{"raw_data": text}`; returns the redacted text.
fn redact(text: &str) -> String {
    let (out, _) = run(CREDENTIAL_FIELD_REDACTION_VRL, &json!({ "raw_data": text }), &json!({}));
    out["raw_data"].as_str().expect("raw_data stays a string").to_string()
}

fn gate_regex(literal: &str) -> Regex {
    let body = literal
        .strip_prefix("r'")
        .and_then(|s| s.strip_suffix('\''))
        .expect("a VRL raw string");
    Regex::new(body).expect("regex compiles")
}

/// (input, expected output, the fake secrets that must be gone)
fn forms() -> Vec<(&'static str, &'static str, &'static [&'static str])> {
    vec![
        // JSON text, as a text/plain body or an OCSF parser's `raw_data`.
        (
            r#"{"user":"alice","Authorization":"Bearer FAKE-A1","n":1}"#,
            r#"{"user":"alice","Authorization":"[REDACTED]","n":1}"#,
            &["FAKE-A1"],
        ),
        (
            r#"{"Cookie" : "sid=FAKE-B1; x=\"FAKE-B2\"", "ok": true}"#,
            r#"{"Cookie" : "[REDACTED]", "ok": true}"#,
            &["FAKE-B1", "FAKE-B2"],
        ),
        (
            r#"{"set-cookie":["a=FAKE-C1","b=FAKE-C2"],"ok":true}"#,
            r#"{"set-cookie":"[REDACTED]","ok":true}"#,
            &["FAKE-C1", "FAKE-C2"],
        ),
        (r#"{"X-Api-Key":31415926535}"#, r#"{"X-Api-Key":"[REDACTED]"}"#, &["31415926535"]),
        (
            r#"{"Proxy-Authorization":{"scheme":"Basic","v":"FAKE-D1"},"u":"bob"}"#,
            r#"{"Proxy-Authorization":"[REDACTED]","u":"bob"}"#,
            &["FAKE-D1"],
        ),
        (
            "{\"x-api-\u{212A}ey\":\"FAKE-E1\"}",
            "{\"x-api-\u{212A}ey\":\"[REDACTED]\"}",
            &["FAKE-E1"],
        ),
        // The same JSON escaped once inside a string value.
        (
            r#"{"body":"{\"x-webhook-secret\":\"FAKE-F1\",\"u\":\"bob\"}"}"#,
            r#"{"body":"{\"x-webhook-secret\":\"[REDACTED]\",\"u\":\"bob\"}"}"#,
            &["FAKE-F1"],
        ),
        (
            r#"{"body":"{\"cookie\":\"FAKE-G1\\\"FAKE-G2\\\\\",\"u\":\"bob\"}"}"#,
            r#"{"body":"{\"cookie\":\"[REDACTED]\",\"u\":\"bob\"}"}"#,
            &["FAKE-G1", "FAKE-G2"],
        ),
        // Header lines: the value runs to the end of the line.
        (
            "GET / HTTP/1.1\r\nAuthorization: Bearer FAKE-H1\r\nHost: example.test",
            "GET / HTTP/1.1\r\nAuthorization: [REDACTED]\r\nHost: example.test",
            &["FAKE-H1"],
        ),
        (
            r#"{"headers":"Cookie: sid=FAKE-I1; b=FAKE-I2\r\nAccept: */*"}"#,
            r#"{"headers":"Cookie: sid=[REDACTED]; b=[REDACTED]\r\nAccept: */*"}"#,
            &["FAKE-I1", "FAKE-I2"],
        ),
        // Escaped line breaks inside a JSON string (or a body that carries
        // them literally): the name follows `\n`, not a word boundary.
        (
            r#"{"raw":"GET / HTTP/1.1\r\nAuthorization: Bearer FAKE-T1\r\nHost: example.test"}"#,
            r#"{"raw":"GET / HTTP/1.1\r\nAuthorization: [REDACTED]\r\nHost: example.test"}"#,
            &["FAKE-T1"],
        ),
        (
            r#"user=alice\nx-api-key=FAKE-T2\tok"#,
            r#"user=alice\nx-api-key=[REDACTED]\tok"#,
            &["FAKE-T2"],
        ),
        (
            r#"Authorization: "Bearer FAKE-J1" seen"#,
            r#"Authorization: "[REDACTED]" seen"#,
            &["FAKE-J1"],
        ),
        // key=value.
        (
            "user=alice x-api-key=FAKE-K1 action=login",
            "user=alice x-api-key=[REDACTED] action=login",
            &["FAKE-K1"],
        ),
        (
            "authorization=Bearer FAKE-L1 status=401",
            "authorization=[REDACTED] status=401",
            &["FAKE-L1"],
        ),
        (
            r#"cookie="a=FAKE-M1; b=2" next=1"#,
            r#"cookie="[REDACTED]" next=1"#,
            &["FAKE-M1"],
        ),
        ("cookie='FAKE-N1 FAKE-N2' next=1", r#"cookie="[REDACTED]" next=1"#, &["FAKE-N1", "FAKE-N2"]),
        (
            "GET /api?x-api-key=FAKE-O1&page=2 HTTP/1.1",
            "GET /api?x-api-key=[REDACTED]&page=2 HTTP/1.1",
            &["FAKE-O1"],
        ),
        // Letters written as JSON \u00XX escapes (Codex review): decoded, at
        // any position, several at once, the hyphen and the Kelvin sign too,
        // and one escaping level down.
        (
            r#"{"\u0041uthorization":"Bearer FAKE-V1","u":"bob"}"#,
            r#"{"Authorization":"[REDACTED]","u":"bob"}"#,
            &["FAKE-V1"],
        ),
        (
            r#"{"\u0061\u0075thori\u007a\u0061tio\u006E":"FAKE-V2"}"#,
            r#"{"authorization":"[REDACTED]"}"#,
            &["FAKE-V2"],
        ),
        (r#"{"x\u002dapi\u002d\u212Aey":"FAKE-V3"}"#, r#"{"x-api-Key":"[REDACTED]"}"#, &["FAKE-V3"]),
        (
            r#"{"body":"{\"\\u0063ooki\\u0065\":\"FAKE-V4\"}"}"#,
            r#"{"body":"{\"cookie\":\"[REDACTED]\"}"}"#,
            &["FAKE-V4"],
        ),
        (r#"x-api-\u004Bey=FAKE-V5 ok"#, "x-api-Key=[REDACTED] ok", &["FAKE-V5"]),
        // Escaped letters with no credential name stay byte-for-byte.
        (r#"{"note":"\u0041BC"}"#, r#"{"note":"\u0041BC"}"#, &[]),
        // Folded header lines (obs-fold), real and escaped CR/LF / LF.
        (
            "Authorization:\r\n Bearer FAKE-W1\r\nHost: example.test",
            "Authorization: [REDACTED]\r\nHost: example.test",
            &["FAKE-W1"],
        ),
        (
            r#"{"h":"Authorization:\r\n\tBearer FAKE-W2\r\nHost: x"}"#,
            r#"{"h":"Authorization: [REDACTED]\r\nHost: x"}"#,
            &["FAKE-W2"],
        ),
        (
            "Authorization: Bearer\n FAKE-W3\nHost: x",
            "Authorization: [REDACTED]\nHost: x",
            &["FAKE-W3"],
        ),
        (
            r#"X-Api-Key:\n  FAKE-W4\nHost: x"#,
            r#"X-Api-Key: [REDACTED]\nHost: x"#,
            &["FAKE-W4"],
        ),
        ("Cookie:\n sid=FAKE-W5\nHost: x", "Cookie:\n sid=[REDACTED]\nHost: x", &["FAKE-W5"]),
        // Delimited logs: the value ends at the field separator.
        (
            "x-api-key=FAKE-X1;status=200;user=alice",
            "x-api-key=[REDACTED];status=200;user=alice",
            &["FAKE-X1"],
        ),
        (
            "src=192.0.2.1|authorization=Bearer FAKE-X2|status=200",
            "src=192.0.2.1|authorization=[REDACTED]|status=200",
            &["FAKE-X2"],
        ),
        (
            "x-webhook-secret=FAKE-X3,user=alice&x=1",
            "x-webhook-secret=[REDACTED],user=alice&x=1",
            &["FAKE-X3"],
        ),
        (
            "Authorization: Bearer FAKE-X4|status=200",
            "Authorization: [REDACTED]|status=200",
            &["FAKE-X4"],
        ),
        // Cookie headers: each cookie value, the cookie names stay.
        (
            "Cookie: sid=FAKE-Y1; theme=FAKE-Y2",
            "Cookie: sid=[REDACTED]; theme=[REDACTED]",
            &["FAKE-Y1", "FAKE-Y2"],
        ),
        (
            "Set-Cookie: id=FAKE-Y3; Path=/; HttpOnly",
            "Set-Cookie: id=[REDACTED]; Path=[REDACTED]; HttpOnly",
            &["FAKE-Y3"],
        ),
        ("Cookie: FAKE-Y4", "Cookie: [REDACTED]", &["FAKE-Y4"]),
        // Fail closed: forms the in-place rules cannot bound.
        (
            r#"{"a":"{\"b\":\"{\\\"cookie\\\":\\\"FAKE-P1\\\"}\"}"}"#,
            MARKER,
            &["FAKE-P1"],
        ),
        (r#"{"authorization":{"a":{"b":"FAKE-Q1"}}}"#, MARKER, &["FAKE-Q1"]),
        (r#"{"user":"x","cookie":"FAKE-R1"#, MARKER, &["FAKE-R1"]),
        ("session xcookie=FAKE-U1 ok", MARKER, &["FAKE-U1"]),
        (r#"\u000aAuthorization: Bearer FAKE-U2"#, MARKER, &["FAKE-U2"]),
        // A name with no value at all is not a credential.
        (r#"{"user":"x","cookie":"#, r#"{"user":"x","cookie":"#, &[]),
        // Nothing to redact: left byte-for-byte.
        ("Invalid username or password", "Invalid username or password", &[]),
        ("cookies: 3 authorization_header=1", "cookies: 3 authorization_header=1", &[]),
        (
            r#"{"authorizations":[{"decision":"allow"}],"policy":"authorization"}"#,
            r#"{"authorizations":[{"decision":"allow"}],"policy":"authorization"}"#,
            &[],
        ),
        ("Cookie:\nHost: example.test", "Cookie:\nHost: example.test", &[]),
    ]
}

#[test]
fn credential_values_in_text_are_redacted_in_place() {
    for (input, want, secrets) in forms() {
        let got = redact(input);
        assert_eq!(got, want, "input: {input}");
        for secret in secrets {
            assert!(!got.contains(secret), "{secret} survived in {got}");
        }
    }
}

/// Every string at any depth is redacted, including `message`, `unmapped`
/// strings and strings inside arrays; credential KEYS inside arrays (which the
/// path walk does not descend into) are removed too. Other values stay.
#[test]
fn every_string_and_array_member_is_covered() {
    let event = json!({
        "class_uid": 0,
        "message": "Authorization: Bearer FAKE-S1",
        "raw_data": "{\"user\":\"alice\",\"Cookie\":\"FAKE-S2\"}",
        "unmapped": {"lines": ["ok", "x-api-key=FAKE-S3"], "records": [{"Authorization": "FAKE-S4", "u": "bob"}]},
        "Authorization": "FAKE-S5",
        "attributes": {"http.request.header.authorization": ["Bearer FAKE-S6"], "http.method": "GET"},
        "user": {"name": "alice"}
    });
    let (out, _) = run(CREDENTIAL_FIELD_REDACTION_VRL, &event, &json!({}));
    let text = out.to_string();
    for secret in ["FAKE-S1", "FAKE-S2", "FAKE-S3", "FAKE-S4", "FAKE-S5", "FAKE-S6"] {
        assert!(!text.contains(secret), "{secret} survived: {text}");
    }
    assert_eq!(out["message"], json!("Authorization: [REDACTED]"));
    assert_eq!(out["raw_data"], json!("{\"user\":\"alice\",\"Cookie\":\"[REDACTED]\"}"));
    assert_eq!(out["unmapped"]["lines"], json!(["ok", "x-api-key=[REDACTED]"]));
    assert_eq!(out["unmapped"]["records"], json!([{"u": "bob"}]));
    assert_eq!(out["user"], json!({"name": "alice"}));
    assert_eq!(out["attributes"], json!({"http.method": "GET"}));
    assert!(out.get("Authorization").is_none());
}

/// The macro lands unescaped in the environment-interpolated `_pipeline.toml`,
/// where Vector reads any `$1` / `$NAME` as an environment variable and
/// refuses the config (caught by the NAN-5352 end-to-end run).
#[test]
fn redaction_text_has_no_dollar() {
    assert!(!CREDENTIAL_FIELD_REDACTION_VRL.contains('$'));
}

#[test]
fn text_gate_alternation_is_the_credential_name_list() {
    let alternation = Regex::new(r"\(\?:([^)]*)\)").unwrap();
    let mut want: Vec<&str> = CREDENTIAL_FIELD_NAMES.to_vec();
    want.sort_unstable();
    let caps = alternation.captures(CREDENTIAL_TEXT_GATE_VRL).expect("alternation");
    let mut gate: Vec<&str> = caps[1].split('|').collect();
    gate.sort_unstable();
    assert_eq!(gate, want, "text gate names drifted from the redaction names");
    // Every rule in the text pass names the full list, or the header / cookie
    // halves of it (header lines and cookie headers are redacted
    // differently); together they cover every name.
    let rules = Regex::new(r"\(\?:((?:proxy-authorization|set-cookie)\|[^)]*)\)").unwrap();
    let hdr = ["authorization", "proxy-authorization", "x-api-key", "x-webhook-secret"];
    let ck = ["cookie", "set-cookie"];
    let mut seen = 0;
    let mut halves = (false, false);
    for c in rules.captures_iter(CREDENTIAL_TEXT_REDACTION_VRL) {
        let mut names: Vec<&str> = c.get(1).unwrap().as_str().split('|').collect();
        names.sort_unstable();
        if names == hdr {
            halves.0 = true;
        } else if names == ck {
            halves.1 = true;
        } else {
            assert_eq!(names, want);
        }
        seen += 1;
    }
    assert!(halves.0 && halves.1, "header and cookie rules");
    assert!(seen >= 7, "{seen}");
}

/// The text gate is a superset of the NAN-5180 key precheck, so wrapping the
/// key walk in it never skips a walk that used to run: every spelling that
/// downcases to a credential name, as an `encode_json` key at any depth.
#[test]
fn text_gate_matches_everything_the_key_precheck_matches() {
    let (gate, key) = (gate_regex(CREDENTIAL_TEXT_GATE_VRL), gate_regex(CREDENTIAL_KEY_PRECHECK_VRL));
    let mut spellings: std::collections::BTreeMap<char, Vec<char>> = Default::default();
    for c in (0u32..=0x10FFFF).filter_map(char::from_u32) {
        let lower: String = c.to_lowercase().collect();
        let mut it = lower.chars();
        if let (Some(l), None) = (it.next(), it.next()) {
            if l.is_ascii() {
                spellings.entry(l).or_default().push(c);
            }
        }
    }
    let mut checked = 0;
    for name in CREDENTIAL_FIELD_NAMES {
        let chars: Vec<char> = name.chars().collect();
        for (i, base) in chars.iter().enumerate() {
            for alt in &spellings[base] {
                let mut k = chars.clone();
                k[i] = *alt;
                let k: String = k.into_iter().collect();
                for doc in [json!({ k.clone(): 1 }), json!({"a": [{"b": { k.clone(): {"c": 1} }}]})] {
                    let text = serde_json::to_string(&doc).unwrap();
                    assert!(key.is_match(&text));
                    assert!(gate.is_match(&text), "text gate misses {k:?} in {text}");
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 100, "{checked}");
}

/// Events without a credential name pay only the outer gate: on the NAN-5180
/// golden corpus (three `_parse` outputs from each of the 16 shipped OCSF
/// parsers) the gate never fires, and `_ocsf_prepare` produces exactly what it
/// produces with the whole text pass removed.
#[test]
fn golden_corpus_skips_the_text_pass_and_is_unchanged() {
    let gate = gate_regex(CREDENTIAL_TEXT_GATE_VRL);
    let esc = gate_regex(CREDENTIAL_ESCAPE_GATE_VRL);
    let without = OCSF_PREPARE_VRL.replacen(CREDENTIAL_TEXT_REDACTION_VRL, "", 1);
    assert_ne!(without, OCSF_PREPARE_VRL);
    let mut n = 0;
    for line in PREPARE_INPUTS.lines().filter(|l| !l.trim().is_empty()) {
        let r: Json = serde_json::from_str(line).unwrap();
        let text = serde_json::to_string(&r["event"]).unwrap();
        assert!(!gate.is_match(&text) && !esc.is_match(&text), "{}: gate fired", r["parser"]);
        let (mut a, am) = run(OCSF_PREPARE_VRL, &r["event"], &r["metadata"]);
        let (mut b, bm) = run(&without, &r["event"], &r["metadata"]);
        if r["event"]["time"].as_i64().unwrap_or(0) <= 0 {
            a.as_object_mut().unwrap().remove("timestamp");
            b.as_object_mut().unwrap().remove("timestamp");
        }
        assert_eq!(a, b, "{}", r["parser"]);
        assert_eq!(am, bm, "{}", r["parser"]);
        n += 1;
    }
    assert!(n >= 45, "{n}");
}

/// Micro-benchmark of `_ocsf_prepare` on the golden corpus (no credentials),
/// for the PR's before/after numbers. `cargo test --release ... -- --ignored
/// --nocapture ocsf_prepare_cost`.
#[test]
#[ignore]
fn ocsf_prepare_cost() {
    let records: Vec<Json> = PREPARE_INPUTS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let compiled = compile(OCSF_PREPARE_VRL, &vrl::stdlib::all()).unwrap().program;
    let inputs: Vec<(Value, Value)> = records
        .iter()
        .map(|r| (Value::from(r["event"].clone()), Value::from(r["metadata"].clone())))
        .collect();
    let mut runtime = Runtime::new(RuntimeState::default());
    let iterations = 2000;
    let mut best = f64::MAX;
    for _round in 0..5 {
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            for (event, metadata) in &inputs {
                let mut target =
                    TargetValue { value: event.clone(), metadata: metadata.clone(), secrets: Secrets::new() };
                runtime.resolve(&mut target, &compiled, &TimeZone::Local).unwrap();
                runtime.clear();
            }
        }
        let per = start.elapsed().as_secs_f64() * 1e6 / (iterations * inputs.len()) as f64;
        best = best.min(per);
    }
    println!("ocsf_prepare: {best:.2} us/event (best of 5, {} events x {iterations})", inputs.len());
}

/// The bundled Tenzir direct-OCSF pipeline writes straight to ClickHouse, past
/// this storage boundary, so it carries the same rules (NAN-5352 review). Its
/// regexes must stay the Vector ones (numbered instead of named groups; the
/// header rule there also covers cookie headers, whole line, since TQL has no
/// closures). `tenzir/tests/credential_redaction.sh` runs the block in Tenzir.
#[test]
fn tenzir_pipeline_carries_the_same_rules() {
    const TQL: &str = include_str!("../../../../tenzir/pipeline.tql");
    let block = &TQL[TQL.find("CREDENTIAL REDACTION (NAN-5352").expect("redaction block")..];
    assert!(
        TQL.find("CREDENTIAL REDACTION (NAN-5352").unwrap() < TQL.find("\nto_clickhouse table=").unwrap(),
        "the redaction runs before the sink"
    );
    let tql = |name: &str| -> String {
        let at = block.find(&format!("let ${name} = r#\"")).unwrap_or_else(|| panic!("TQL let ${name}"));
        let rest = &block[at + format!("let ${name} = r#\"").len()..];
        rest[..rest.find("\"#").unwrap()].to_string()
    };
    let vrl_rules: Vec<String> = Regex::new(r#"replace_with\(nano_text, r'([^']*)'\)"#)
        .unwrap()
        .captures_iter(CREDENTIAL_TEXT_REDACTION_VRL)
        .map(|c| c[1].replace("(?P<nano_k>", "("))
        .collect();
    assert_eq!(vrl_rules.len(), 6, "{vrl_rules:?}");
    // json, escaped json, quoted value, (cookie: Vector only), header, key=value
    assert_eq!(tql("nano_cred_json"), vrl_rules[0]);
    assert_eq!(tql("nano_cred_esc"), vrl_rules[1]);
    assert_eq!(tql("nano_cred_qval"), vrl_rules[2]);
    assert_eq!(
        tql("nano_cred_hdr"),
        vrl_rules[4].replace(
            "(?:proxy-authorization|authorization|x-webhook-secret|x-api-key)",
            "(?:proxy-authorization|authorization|x-webhook-secret|x-api-key|set-cookie|cookie)"
        )
    );
    assert_eq!(tql("nano_cred_kv"), vrl_rules[5]);
    let unquote = |g: &'static str| g.strip_prefix("r'").and_then(|s| s.strip_suffix('\'')).unwrap();
    assert_eq!(tql("nano_cred_gate"), unquote(CREDENTIAL_TEXT_GATE_VRL));
    assert_eq!(tql("nano_cred_escgate"), unquote(CREDENTIAL_ESCAPE_GATE_VRL));
    let done = Regex::new(r#"nano_left = replace\(nano_text, r'([^']*)'"#).unwrap();
    assert_eq!(tql("nano_cred_done"), done.captures(CREDENTIAL_TEXT_REDACTION_VRL).unwrap()[1]);
    // The fail-closed check also sees names spelled with \u escapes.
    let left = Regex::new(&tql("nano_cred_left")).unwrap();
    for name in CREDENTIAL_FIELD_NAMES {
        assert!(left.is_match(&format!("\"{name}\":")), "{name}");
        let escaped: String = name.chars().map(|c| format!("\\u{:04X}", c as u32)).collect();
        assert!(left.is_match(&format!("\"{escaped}\":")), "{escaped}");
    }
}
