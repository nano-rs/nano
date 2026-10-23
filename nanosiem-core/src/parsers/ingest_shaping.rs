// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4372: the event a parser receives in production for one raw line.
//!
//! A line POSTed to the HTTP ingest front door is shaped by the shipped
//! `parse_content` transform (`config/vector/00-base.toml`) before any parser
//! runs: a JSON object line has its keys merged onto the event root (except
//! `message`, which becomes the object's own string `message` or stays the
//! raw line), and a non-JSON line stays `{"message": <line>}` with the
//! ingest bookkeeping fields. Parser tests used to wrap every sample as a
//! bare `{"message": <line>}`, so a parser that read `.field` or rebuilt
//! the event (`. = {...}`) behaved differently in test and in production.
//!
//! The test paths run the SAME `parse_content` program (read from the
//! shipped config, not a copy) over `{"message": <line>}`, i.e. a delivery
//! with no declared Content-Type, where Vector sniffs JSON by its first
//! character.
//!
//! That shaping is the HTTP front door's (`nano_https`) only. HEC (string
//! and object events alike: the bytes codec keeps the payload in
//! `.message`), every pull lane, connector feeds and fetch sources hand the
//! parser `{"message": <line>}` unchanged. A sample is shaped per delivery
//! path of the source ([`SampleDelivery::for_source_paths`]: the protocols of
//! its bound credentials), and must pass under each.

use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The shipped HTTP front-door config the shaping is read from.
const BASE_CONFIG: &str = include_str!("../../../config/vector/00-base.toml");
/// The transform that shapes a raw HTTP line into the parser's input event.
const SHAPING_TRANSFORM: &str = "parse_content";

static SHAPING_PROGRAM: LazyLock<Result<vrl::compiler::Program, String>> = LazyLock::new(|| {
    let source = transform_source(BASE_CONFIG, SHAPING_TRANSFORM)?;
    vrl::compiler::compile(&source, &super::validator::safe_vrl_functions())
        .map(|compiled| compiled.program)
        .map_err(|diagnostics| {
            format!("{SHAPING_TRANSFORM} does not compile: {diagnostics:?}")
        })
});

/// A transform's VRL `source` from a shipped Vector TOML, after Vector's
/// `${VAR:-default}` substitution (unquoted numeric defaults are not TOML
/// until substituted).
fn transform_source(config: &str, name: &str) -> Result<String, String> {
    static ENV_DEFAULT: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}").expect("valid regex"));
    let table: toml::Table = ENV_DEFAULT
        .replace_all(config, "$1")
        .parse()
        .map_err(|error| format!("00-base.toml does not parse: {error}"))?;
    table
        .get("transforms")
        .and_then(|transforms| transforms.get(name))
        .and_then(|transform| transform.get("source"))
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("00-base.toml has no {name} source"))
}

/// How a source's raw lines reach its parser, i.e. how a sample must be
/// shaped to test it the way production runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SampleDelivery {
    /// The nano HTTP front door (`routed`): `parse_content` merges a JSON
    /// line's keys onto the event root.
    Http,
    /// HEC, pull lanes, connector feeds and fetch sources: the parser gets
    /// `{"message": <line>}`. The default when the delivery path is unknown
    /// (the shape every catalog parser's certified samples are written for).
    #[default]
    Message,
}

impl SampleDelivery {
    /// The shape one ingest credential protocol delivers: `nano_https` is
    /// the HTTP front door; `hec` keeps the payload in `.message` (bytes
    /// codec, string and object events alike). `otlp_http` (and anything
    /// unknown) is approximated as `Message`: an OTLP record's body lands in
    /// `.message`, and its attributes/resource are not reconstructed from a
    /// raw sample line.
    pub fn for_protocol(protocol: &str) -> Self {
        match protocol {
            "nano_https" => Self::Http,
            _ => Self::Message,
        }
    }

    /// Every shape a source's lines reach its parser in, deduplicated and in
    /// a stable order; a sample must pass under each one.
    ///
    /// `source_type` is deliberately NOT consulted: `routed` is the default
    /// for almost every source (AddFeed, the wizard, catalog installs), not a
    /// delivery path. The paths are the protocols of the credentials bound to
    /// the source, plus `Message` when a pull source / connector feed feeds
    /// it (`platform_delivered`) or it is dispatched from a fetch source
    /// configuration (`dispatched`). No known path (no bound credential, or
    /// a dedicated token, which both the HTTP and HEC listeners accept and
    /// which the built-in collectors use over HEC) is `Message`.
    pub fn for_source_paths<'a>(
        platform_delivered: bool,
        dispatched: bool,
        credential_protocols: impl IntoIterator<Item = &'a str>,
    ) -> Vec<Self> {
        let mut shapes: Vec<Self> = credential_protocols.into_iter().map(Self::for_protocol).collect();
        if platform_delivered || dispatched || shapes.is_empty() {
            shapes.push(Self::Message);
        }
        shapes.sort_by_key(|shape| *shape as u8);
        shapes.dedup();
        shapes
    }

    /// The parser's input event for one raw sample line, as JSON text.
    pub fn input(self, raw: &str) -> Result<String, String> {
        match self {
            Self::Http => http_delivery_input(raw),
            Self::Message => Ok(serde_json::json!({ "message": raw }).to_string()),
        }
    }
}

/// The event the parser sees for one raw line delivered over HTTP.
pub fn http_delivery_event(raw: &str) -> Result<serde_json::Value, String> {
    use vrl::compiler::{runtime::Runtime, TargetValue, TimeZone};
    use vrl::value::{Secrets, Value};

    let program = SHAPING_PROGRAM.as_ref().map_err(Clone::clone)?;
    let mut target = TargetValue {
        value: super::validator::json_to_vrl_value(&serde_json::json!({ "message": raw })),
        metadata: Value::Object(BTreeMap::new()),
        secrets: Secrets::default(),
    };
    Runtime::default()
        .resolve(&mut target, program, &TimeZone::Local)
        .map_err(|error| format!("{SHAPING_TRANSFORM} failed on the sample: {error}"))?;
    Ok(super::validator::vrl_value_to_json(&target.value))
}

/// [`http_delivery_event`] serialized as the JSON input the VRL test
/// harness takes.
pub fn http_delivery_input(raw: &str) -> Result<String, String> {
    http_delivery_event(raw).map(|event| event.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_shipped_shaping_program_compiles() {
        assert!(SHAPING_PROGRAM.is_ok(), "{:?}", SHAPING_PROGRAM.as_ref().err());
    }

    /// JSON keys land on the event root, as production does; `message`
    /// is the object's own string message.
    #[test]
    fn a_json_line_is_merged_onto_the_root() {
        let event = http_delivery_event(r#"{"src":"10.0.0.1","status":200,"message":"hi"}"#).unwrap();
        assert_eq!(event["src"], json!("10.0.0.1"));
        assert_eq!(event["status"], json!(200));
        assert_eq!(event["message"], json!("hi"));
        assert_eq!(event["content_format"], json!("json"));
    }

    /// A JSON object without its own `message` keeps the raw line there.
    #[test]
    fn a_json_line_without_message_keeps_the_raw_line() {
        let raw = r#"{"a":1}"#;
        let event = http_delivery_event(raw).unwrap();
        assert_eq!(event["a"], json!(1));
        assert_eq!(event["message"], json!(raw));
    }

    /// NAN-4372 review: a JSON sample with its own top-level `message`.
    /// `nano_https` gets the front door's merge; HEC (and pull / fetch)
    /// hands the parser the raw line in `.message`, which is what
    /// `parse_json(.message)` parsers such as the catalog `windows_event`
    /// read.
    #[test]
    fn each_shape_of_a_json_sample_with_its_own_message() {
        let raw = r#"{"EventID":4624,"message":"An account was successfully logged on."}"#;
        let event: serde_json::Value =
            serde_json::from_str(&SampleDelivery::Http.input(raw).unwrap()).unwrap();
        assert_eq!(event["EventID"], json!(4624));
        assert_eq!(event["message"], json!("An account was successfully logged on."));
        let event: serde_json::Value =
            serde_json::from_str(&SampleDelivery::Message.input(raw).unwrap()).unwrap();
        assert_eq!(event, json!({ "message": raw }));
    }

    /// The shapes come from the bound credentials' protocols, never from the
    /// `routed` default `source_type`.
    #[test]
    fn shapes_follow_the_bound_credential_protocols() {
        use SampleDelivery::{Http, Message};
        assert_eq!(SampleDelivery::for_source_paths(false, false, ["hec"]), vec![Message]);
        assert_eq!(SampleDelivery::for_source_paths(false, false, ["nano_https"]), vec![Http]);
        assert_eq!(
            SampleDelivery::for_source_paths(false, false, ["hec", "nano_https", "hec"]),
            vec![Http, Message]
        );
        assert_eq!(SampleDelivery::for_source_paths(false, false, []), vec![Message]);
        assert_eq!(SampleDelivery::for_source_paths(false, false, ["otlp_http"]), vec![Message]);
        assert_eq!(SampleDelivery::for_source_paths(false, false, ["carrier_pigeon"]), vec![Message]);
        // A pull source / connector feed or a fetch dispatch adds `.message`.
        assert_eq!(SampleDelivery::for_source_paths(true, false, ["nano_https"]), vec![Http, Message]);
        assert_eq!(SampleDelivery::for_source_paths(false, true, []), vec![Message]);
    }

    #[test]
    fn a_plain_line_stays_in_message() {
        let raw = "1700000000.123 42 10.0.0.1 TCP_MISS/200 512 GET http://example.com/ - HIER_DIRECT/1.2.3.4 text/html";
        let event = http_delivery_event(raw).unwrap();
        assert_eq!(event["message"], json!(raw));
        assert_eq!(event["content_format"], json!("raw"));
        assert!(event.get("src").is_none());
    }
}
