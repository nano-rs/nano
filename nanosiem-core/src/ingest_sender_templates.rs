// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sender configuration templates for the hosted ingest endpoint (NAN-2592,
//! data onboarding design §3.2). One server-side registry for curl, HEC
//! senders, HTTPS JSON, OTLP/HTTP, Vector, Fluent Bit, the OpenTelemetry
//! Collector and Cribl Stream, shared by the SIEM "Add data" flow and the
//! docs. The API serves the templates with `{{placeholder}}` markers; the
//! browser fills them in locally. The plaintext token is substituted only in
//! the browser and never reaches this registry or the API.
//!
//! Protocol facts the templates encode (the tenant ingest Worker,
//! `workers/hosted-ingest/src/ingress-router.js`, `source-payload.js`):
//! * HEC (`hec`): `POST /services/collector/event|raw`, `Authorization: Splunk <token>`.
//! * HTTPS JSON (`nano_https`): `POST /ingest` (any non-reserved path),
//!   `Authorization: Bearer <token>`, a JSON array, one object, or NDJSON;
//!   gzip/deflate allowed.
//! * OTLP/HTTP (`otlp_http`): `POST /v1/logs`, `application/x-protobuf`
//!   only, `Authorization: Bearer <token>`.
//!
//! SOURCE-credential templates (`credential_kinds: ["source"]`): the token
//! fixes the source, so none declares one. COLLECTOR templates
//! (`credential_kinds: ["collector"]`, NAN-2597) declare the source per event
//! or per request where the Worker reads it (design §2.1): HEC `sourcetype`,
//! HTTPS JSON `X-Source-Type` / per-event `source_type`, OTLP `nano.source`
//! resource attribute / `x-nano-source` header. An event with no declared
//! source lands as `unknown`; a declared source outside the allowlist fails
//! the whole request (403 `source_not_allowed`).
//!
//! Placeholders are `{{name}}` with no spaces. A sender's own template syntax
//! (Vector's `"{{ field }}"`, with spaces) is not a placeholder and is left
//! as is.

use serde::{Deserialize, Serialize};

/// Registry schema version; bump when a placeholder is renamed or removed.
pub const SENDER_TEMPLATES_VERSION: u32 = 1;

/// A placeholder the browser substitutes before showing a template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct SenderTemplatePlaceholder {
    /// The marker as it appears in `body`, e.g. `{{token}}`.
    pub marker: String,
    /// Field of `GET /api/log-sources/ingest-endpoint` (or of the revealed
    /// credential) that supplies the value.
    pub source: String,
    pub description: String,
    /// `true` for the plaintext token: substitute only in the browser, never
    /// persist the rendered snippet.
    pub secret: bool,
}

/// One copy-paste sender configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct SenderTemplate {
    /// Stable id, e.g. `vector-hec`.
    pub id: String,
    /// `curl`, `vector`, `fluent_bit`, `otel_collector` or `cribl`.
    pub sender: String,
    /// Display name of the sender.
    pub sender_name: String,
    /// Credential protocol the template needs: `hec`, `nano_https` or `otlp_http`.
    pub protocol: String,
    /// Credential kinds the template works with (`source`; `collector` from P2).
    pub credential_kinds: Vec<String>,
    /// Syntax of `body`: `shell`, `toml`, `yaml`, `ini` or `text` (form fields).
    pub format: String,
    pub title: String,
    pub description: String,
    /// The template, with `{{marker}}` placeholders.
    pub body: String,
}

/// `GET /api/log-sources/sender-templates`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct SenderTemplateCatalog {
    pub version: u32,
    pub placeholders: Vec<SenderTemplatePlaceholder>,
    pub templates: Vec<SenderTemplate>,
}

/// Values for [`render`]. Docs render with sample values; the web renders in
/// the browser with the revealed token.
#[derive(Debug, Clone, Default)]
pub struct SenderTemplateValues {
    pub hostname: String,
    pub base_url: String,
    pub hec_url: String,
    pub nano_https_url: String,
    pub otlp_logs_url: String,
    pub token: String,
    pub label: String,
    /// Collector: the names an event may declare (slugs, then aliases), comma-separated.
    pub sources: String,
    /// Collector: one allowlisted slug to show in examples.
    pub example_source: String,
}

const PLACEHOLDERS: &[(&str, &str, &str, bool)] = &[
    ("{{hostname}}", "ingest-endpoint.hostname", "The tenant ingest hostname, `<tenant_slug>.ingest.nano.rs`.", false),
    ("{{base_url}}", "ingest-endpoint.base_url", "`https://<hostname>`.", false),
    ("{{hec_url}}", "ingest-endpoint.hec_url", "HEC event endpoint, `<base_url>/services/collector/event`.", false),
    ("{{nano_https_url}}", "ingest-endpoint.nano_https_url", "HTTPS JSON endpoint, `<base_url>/ingest`.", false),
    ("{{otlp_logs_url}}", "ingest-endpoint.otlp_logs_url", "OTLP/HTTP logs endpoint, `<base_url>/v1/logs`.", false),
    ("{{token}}", "the revealed credential (decrypted in the browser)", "The ingest token. Shown once; never stored.", true),
    ("{{label}}", "the credential label", "The credential's display label, used to name the sender output.", false),
    ("{{sources}}", "the collector credential's source_slugs and source_aliases",
        "Collector templates: every name an event may declare (allowlisted slugs, then aliases), comma-separated.", false),
    ("{{example_source}}", "the collector credential's first source slug",
        "Collector templates: one allowlisted slug used in examples; set the real source per event.", false),
];

fn template(
    id: &str, sender: &str, sender_name: &str, protocol: &str, format: &str, title: &str, description: &str, body: &str,
) -> SenderTemplate {
    kind_template("source", id, sender, sender_name, protocol, format, title, description, body)
}

fn collector(
    id: &str, sender: &str, sender_name: &str, protocol: &str, format: &str, title: &str, description: &str, body: &str,
) -> SenderTemplate {
    kind_template("collector", id, sender, sender_name, protocol, format, title, description, body)
}

#[allow(clippy::too_many_arguments)]
fn kind_template(
    kind: &str, id: &str, sender: &str, sender_name: &str, protocol: &str, format: &str, title: &str, description: &str,
    body: &str,
) -> SenderTemplate {
    SenderTemplate {
        id: id.into(),
        sender: sender.into(),
        sender_name: sender_name.into(),
        protocol: protocol.into(),
        credential_kinds: vec![kind.into()],
        format: format.into(),
        title: title.into(),
        description: description.into(),
        body: body.trim_start_matches('\n').into(),
    }
}

/// The registry, in display order (sender, then protocol).
pub fn sender_templates() -> Vec<SenderTemplate> {
    vec![
        template("curl-hec", "curl", "curl", "hec", "shell", "Send a test event (HEC)",
            "One JSON event to the HEC event endpoint. Expect {\"text\":\"Success\",\"code\":0}.",
            r#"
curl -sS "{{hec_url}}" \
  -H "Authorization: Splunk {{token}}" \
  -H "Content-Type: application/json" \
  -d '{"event": {"message": "hello from curl"}}'
"#),
        template("curl-nano-https", "curl", "curl", "nano_https", "shell", "Send a test event (HTTPS JSON)",
            "One JSON object. A JSON array or newline-delimited JSON also works; gzip with Content-Encoding: gzip.",
            r#"
curl -sS "{{nano_https_url}}" \
  -H "Authorization: Bearer {{token}}" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello from curl"}'
"#),
        template("vector-hec", "vector", "Vector", "hec", "toml", "Vector: HEC sink",
            "Add to vector.toml and set `inputs` to your sources. Uses the `splunk_hec_logs` sink type; Vector appends /services/collector/event.",
            r#"
[sinks.nano_{{label}}]
type = "splunk_hec_logs"
inputs = ["my_source"]
endpoint = "{{base_url}}"
default_token = "{{token}}"
endpoint_target = "event"
compression = "gzip"
encoding.codec = "json"
"#),
        template("vector-http", "vector", "Vector", "nano_https", "toml", "Vector: http sink (JSON)",
            "Newline-delimited JSON over HTTPS with a bearer token.",
            r#"
[sinks.nano_{{label}}]
type = "http"
inputs = ["my_source"]
uri = "{{nano_https_url}}"
method = "post"
compression = "gzip"
auth.strategy = "bearer"
auth.token = "{{token}}"
encoding.codec = "json"
framing.method = "newline_delimited"
request.headers.Content-Type = "application/x-ndjson"
"#),
        template("fluent-bit-hec", "fluent_bit", "Fluent Bit", "hec", "ini", "Fluent Bit: HEC output",
            "Add to fluent-bit.conf (HEC output plugin, `Name splunk`). TLS is required on port 443.",
            r#"
[OUTPUT]
    Name         splunk
    Match        *
    Host         {{hostname}}
    Port         443
    TLS          On
    TLS.Verify   On
    Splunk_Token {{token}}
"#),
        template("fluent-bit-http", "fluent_bit", "Fluent Bit", "nano_https", "ini", "Fluent Bit: http output (JSON lines)",
            "Newline-delimited JSON over HTTPS with a bearer token.",
            r#"
[OUTPUT]
    Name        http
    Match       *
    Host        {{hostname}}
    Port        443
    URI         /ingest
    Format      json_lines
    Header      Authorization Bearer {{token}}
    TLS         On
    TLS.Verify  On
"#),
        template("fluent-bit-otlp", "fluent_bit", "Fluent Bit", "otlp_http", "ini", "Fluent Bit: opentelemetry output",
            "OTLP/HTTP protobuf logs to /v1/logs.",
            r#"
[OUTPUT]
    Name        opentelemetry
    Match       *
    Host        {{hostname}}
    Port        443
    Logs_uri    /v1/logs
    Header      Authorization Bearer {{token}}
    TLS         On
    TLS.Verify  On
"#),
        template("otel-collector-otlphttp", "otel_collector", "OpenTelemetry Collector", "otlp_http", "yaml",
            "OpenTelemetry Collector: otlphttp exporter",
            "Add the exporter and reference it from your logs pipeline. The endpoint accepts protobuf only.",
            r#"
exporters:
  otlphttp/nano:
    logs_endpoint: {{otlp_logs_url}}
    encoding: proto
    compression: gzip
    headers:
      Authorization: "Bearer {{token}}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlphttp/nano]
"#),
        template("otel-collector-hec", "otel_collector", "OpenTelemetry Collector", "hec", "yaml",
            "OpenTelemetry Collector: HEC exporter",
            "Sends collector logs as HEC events with the `splunk_hec` exporter.",
            r#"
exporters:
  splunk_hec/nano:
    endpoint: {{hec_url}}
    token: "{{token}}"
    tls:
      insecure_skip_verify: false

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [splunk_hec/nano]
"#),
        template("cribl-hec", "cribl", "Cribl Stream", "hec", "text", "Cribl Stream: HEC destination",
            "Data > Destinations > HEC-compatible destination > Add Destination. Values for the form.",
            r#"
Output ID:           nano_{{label}}
Load balancing:      No
HEC endpoint:        {{hec_url}}
Authentication:      Manual
HEC auth token:      {{token}}
Compress:            Yes
"#),
        template("cribl-webhook", "cribl", "Cribl Stream", "nano_https", "text", "Cribl Stream: Webhook destination",
            "Data > Destinations > Webhook > Add Destination. Values for the form.",
            r#"
Output ID:           nano_{{label}}
URL:                 {{nano_https_url}}
Method:              POST
Format:              NDJSON
Compress:            Yes
Authentication type: Auth token
Token:               {{token}}
"#),
        template("cribl-otlp", "cribl", "Cribl Stream", "otlp_http", "text", "Cribl Stream: OpenTelemetry destination",
            "Data > Destinations > OpenTelemetry > Add Destination. Values for the form.",
            r#"
Output ID:           nano_{{label}}
Protocol:            HTTP
Endpoint:            {{base_url}}
OTLP version:        1.3.1
Compression:         Gzip
Authentication type: Auth token
Token:               {{token}}
"#),
    ]
    .into_iter()
    .chain(collector_templates())
    .collect()
}

/// Collector-credential templates (NAN-2597): one token, many sources; each
/// declares the source where the Worker reads it (design §2.1).
fn collector_templates() -> Vec<SenderTemplate> {
    vec![
        collector("curl-hec-collector", "curl", "curl", "hec", "shell", "Send a test event (HEC, collector)",
            "Each HEC envelope declares its source in `sourcetype`. Expect {\"text\":\"Success\",\"code\":0}.",
            r#"
# Allowed sourcetype values: {{sources}}
# An event without a sourcetype lands as unknown; any other value rejects the request (403).
curl -sS "{{hec_url}}" \
  -H "Authorization: Splunk {{token}}" \
  -H "Content-Type: application/json" \
  -d '{"sourcetype": "{{example_source}}", "event": {"message": "hello from curl"}}'
"#),
        collector("curl-nano-https-collector", "curl", "curl", "nano_https", "shell", "Send a test event (HTTPS JSON, collector)",
            "Declare the source per request with X-Source-Type, or per event with a `source_type` field (it wins).",
            r#"
# Allowed source values: {{sources}}
# Without X-Source-Type or source_type the event lands as unknown.
curl -sS "{{nano_https_url}}" \
  -H "Authorization: Bearer {{token}}" \
  -H "Content-Type: application/json" \
  -H "X-Source-Type: {{example_source}}" \
  -d '{"message": "hello from curl"}'
"#),
        collector("vector-hec-collector", "vector", "Vector", "hec", "toml", "Vector: HEC sink (collector)",
            "Set `.nano_source` on every event (a remap per source) and the `splunk_hec_logs` sink sends it as the HEC sourcetype.",
            r#"
# Allowed values for .nano_source: {{sources}}
# Events without it land as unknown; any other value rejects the batch (403).
[transforms.nano_{{label}}_source]
type = "remap"
inputs = ["my_source"]
source = '.nano_source = "{{example_source}}"'

[sinks.nano_{{label}}]
type = "splunk_hec_logs"
inputs = ["nano_{{label}}_source"]
endpoint = "{{base_url}}"
default_token = "{{token}}"
endpoint_target = "event"
sourcetype = "{{ nano_source }}"
compression = "gzip"
encoding.codec = "json"
"#),
        collector("vector-http-collector", "vector", "Vector", "nano_https", "toml", "Vector: http sink (JSON, collector)",
            "Each event declares its source in a `source_type` field; set it with a remap per source.",
            r#"
# Allowed values for .source_type: {{sources}}
# Events without it land as unknown; any other value rejects the batch (403).
[transforms.nano_{{label}}_source]
type = "remap"
inputs = ["my_source"]
source = '.source_type = "{{example_source}}"'

[sinks.nano_{{label}}]
type = "http"
inputs = ["nano_{{label}}_source"]
uri = "{{nano_https_url}}"
method = "post"
compression = "gzip"
auth.strategy = "bearer"
auth.token = "{{token}}"
encoding.codec = "json"
framing.method = "newline_delimited"
request.headers.Content-Type = "application/x-ndjson"
"#),
        collector("fluent-bit-hec-collector", "fluent_bit", "Fluent Bit", "hec", "ini", "Fluent Bit: HEC output (collector)",
            "HEC output plugin (`Name splunk`). Add a nano_source key to each record (one modify filter per input) and send it as the HEC sourcetype.",
            r#"
# Allowed nano_source values: {{sources}}
# Records without it land as unknown; any other value rejects the batch (403).
[FILTER]
    Name   modify
    Match  my_source.*
    Add    nano_source {{example_source}}

[OUTPUT]
    Name                  splunk
    Match                 *
    Host                  {{hostname}}
    Port                  443
    TLS                   On
    TLS.Verify            On
    Splunk_Token          {{token}}
    Event_Sourcetype_Key  $nano_source
"#),
        collector("fluent-bit-http-collector", "fluent_bit", "Fluent Bit", "nano_https", "ini", "Fluent Bit: http output (collector)",
            "Add a source_type key to each record (one modify filter per input); JSON lines over HTTPS.",
            r#"
# Allowed source_type values: {{sources}}
# Records without it land as unknown; any other value rejects the batch (403).
[FILTER]
    Name   modify
    Match  my_source.*
    Add    source_type {{example_source}}

[OUTPUT]
    Name        http
    Match       *
    Host        {{hostname}}
    Port        443
    URI         /ingest
    Format      json_lines
    Header      Authorization Bearer {{token}}
    TLS         On
    TLS.Verify  On
"#),
        collector("fluent-bit-otlp-collector", "fluent_bit", "Fluent Bit", "otlp_http", "ini", "Fluent Bit: opentelemetry output (collector)",
            "One output per source, each declaring it with the x-nano-source header.",
            r#"
# Allowed x-nano-source values: {{sources}}
# Requests without it land as unknown; any other value rejects the request (403).
[OUTPUT]
    Name        opentelemetry
    Match       my_source.*
    Host        {{hostname}}
    Port        443
    Logs_uri    /v1/logs
    Header      Authorization Bearer {{token}}
    Header      x-nano-source {{example_source}}
    TLS         On
    TLS.Verify  On
"#),
        collector("otel-collector-otlphttp-collector", "otel_collector", "OpenTelemetry Collector", "otlp_http", "yaml",
            "OpenTelemetry Collector: otlphttp exporter (collector)",
            "Declare the source per resource with the nano.source attribute (one resource processor per pipeline), or per exporter with the x-nano-source header. The attribute wins.",
            r#"
# Allowed nano.source values: {{sources}}
# Resources without it (and no x-nano-source header) land as unknown.
processors:
  resource/nano_source:
    attributes:
      - key: nano.source
        value: {{example_source}}
        action: upsert

exporters:
  otlphttp/nano:
    logs_endpoint: {{otlp_logs_url}}
    encoding: proto
    compression: gzip
    headers:
      Authorization: "Bearer {{token}}"
      # One source per exporter instead: x-nano-source: {{example_source}}

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [resource/nano_source]
      exporters: [otlphttp/nano]
"#),
        collector("otel-collector-hec-collector", "otel_collector", "OpenTelemetry Collector", "hec", "yaml",
            "OpenTelemetry Collector: HEC exporter (collector)",
            "The `splunk_hec` exporter sends each record's `com.splunk.sourcetype` attribute (or the exporter default) as the HEC sourcetype.",
            r#"
# Allowed sourcetype values: {{sources}}
# Records without a sourcetype land as unknown; any other value rejects the batch (403).
exporters:
  splunk_hec/nano:
    endpoint: {{hec_url}}
    token: "{{token}}"
    sourcetype: "{{example_source}}"
    tls:
      insecure_skip_verify: false

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [splunk_hec/nano]
"#),
        collector("cribl-hec-collector", "cribl", "Cribl Stream", "hec", "text", "Cribl Stream: HEC destination (collector)",
            "Data > Destinations > HEC-compatible destination > Add Destination. One destination for every source; each event's sourcetype declares it.",
            r#"
Output ID:           nano_{{label}}
Load balancing:      No
HEC endpoint:        {{hec_url}}
Authentication:      Manual
HEC auth token:      {{token}}
Compress:            Yes

Declare each event's source in its sourcetype field. Events from HEC senders
often carry one already; otherwise add an Eval function to the route's pipeline:
  sourcetype = '{{example_source}}'
Allowed sourcetypes: {{sources}}
Events without a sourcetype land as unknown; any other value rejects the batch (403).
"#),
        collector("cribl-webhook-collector", "cribl", "Cribl Stream", "nano_https", "text", "Cribl Stream: Webhook destination (collector)",
            "Data > Destinations > Webhook > Add Destination. Each event's source_type field declares its source.",
            r#"
Output ID:           nano_{{label}}
URL:                 {{nano_https_url}}
Method:              POST
Format:              NDJSON
Compress:            Yes
Authentication type: Auth token
Token:               {{token}}

Declare each event's source with an Eval function on the route's pipeline:
  source_type = '{{example_source}}'
Allowed source_type values: {{sources}}
Events without one land as unknown; any other value rejects the batch (403).
"#),
        collector("cribl-otlp-collector", "cribl", "Cribl Stream", "otlp_http", "text", "Cribl Stream: OpenTelemetry destination (collector)",
            "Data > Destinations > OpenTelemetry > Add Destination. Declare the source per resource (nano.source) or per destination (x-nano-source header).",
            r#"
Output ID:           nano_{{label}}
Protocol:            HTTP
Endpoint:            {{base_url}}
OTLP version:        1.3.1
Compression:         Gzip
Authentication type: Auth token
Token:               {{token}}
Extra HTTP headers:  x-nano-source = {{example_source}}   (one source per destination)

A nano.source resource attribute on the OTLP resource wins over the header.
Allowed values: {{sources}}
Events with neither land as unknown; any other value rejects the request (403).
"#),
    ]
}

/// The full catalog the API serves.
pub fn sender_template_catalog() -> SenderTemplateCatalog {
    SenderTemplateCatalog {
        version: SENDER_TEMPLATES_VERSION,
        placeholders: PLACEHOLDERS
            .iter()
            .map(|(marker, source, description, secret)| SenderTemplatePlaceholder {
                marker: (*marker).into(),
                source: (*source).into(),
                description: (*description).into(),
                secret: *secret,
            })
            .collect(),
        templates: sender_templates(),
    }
}

/// Make a label safe for identifiers in sender configs (`[a-z0-9_]`).
pub fn identifier_label(label: &str) -> String {
    let mut out: String = label
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(48)
        .collect();
    if out.is_empty() {
        out.push_str("ingest");
    }
    out
}

/// Fill every placeholder. The label is reduced to an identifier.
pub fn render(template: &SenderTemplate, values: &SenderTemplateValues) -> String {
    template
        .body
        .replace("{{hostname}}", &values.hostname)
        .replace("{{base_url}}", &values.base_url)
        .replace("{{hec_url}}", &values.hec_url)
        .replace("{{nano_https_url}}", &values.nano_https_url)
        .replace("{{otlp_logs_url}}", &values.otlp_logs_url)
        .replace("{{token}}", &values.token)
        .replace("{{label}}", &identifier_label(&values.label))
        .replace("{{sources}}", &values.sources)
        .replace("{{example_source}}", &values.example_source)
}

/// `{{sources}}` for a collector: its slugs, then its aliases, comma-separated.
pub fn declared_sources(slugs: &[String], aliases: &std::collections::BTreeMap<String, String>) -> String {
    slugs.iter().chain(aliases.keys()).map(String::as_str).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SenderTemplateValues {
        let base = "https://acme.ingest.nano.rs".to_string();
        SenderTemplateValues {
            hostname: base.trim_start_matches("https://").into(),
            hec_url: format!("{base}/services/collector/event"),
            nano_https_url: format!("{base}/ingest"),
            otlp_logs_url: format!("{base}/v1/logs"),
            base_url: base,
            token: "TOKEN-SAMPLE".into(),
            label: "Prod firewall #1".into(),
            sources: "palo_alto_traffic, okta, pan:traffic".into(),
            example_source: "palo_alto_traffic".into(),
        }
    }

    /// `{{name}}` markers (no spaces); sender syntax like Vector's `{{ field }}` is not one.
    fn markers(body: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut rest = body;
        while let Some(start) = rest.find("{{") {
            let end = rest[start..].find("}}").expect("unterminated braces") + start + 2;
            let marker = &rest[start..end];
            if marker[2..marker.len() - 2].bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                out.push(marker);
            } else {
                assert!(marker.starts_with("{{ ") && marker.ends_with(" }}"), "ambiguous braces {marker}");
            }
            rest = &rest[end..];
        }
        out
    }

    #[test]
    fn every_template_uses_only_declared_placeholders_and_renders_completely() {
        let catalog = sender_template_catalog();
        let declared: Vec<&str> = catalog.placeholders.iter().map(|p| p.marker.as_str()).collect();
        for template in &catalog.templates {
            for marker in markers(&template.body) {
                assert!(declared.contains(&marker), "{}: undeclared {marker}", template.id);
            }
            let rendered = render(template, &sample());
            assert!(markers(&rendered).is_empty(), "{}", template.id);
            assert!(rendered.contains("TOKEN-SAMPLE"), "{} never uses the token", template.id);
        }
    }

    #[test]
    fn every_declared_placeholder_is_used_by_a_template() {
        // NAN-2617: `{{hec_raw_url}}` was declared (and documented) but no
        // template used it. A placeholder exists only if a template needs it.
        let catalog = sender_template_catalog();
        for placeholder in &catalog.placeholders {
            assert!(
                catalog.templates.iter().any(|t| markers(&t.body).contains(&placeholder.marker.as_str())),
                "{} is declared but unused",
                placeholder.marker
            );
        }
    }

    #[test]
    fn registry_covers_every_sender_and_protocol_with_unique_ids() {
        let templates = sender_templates();
        let mut ids: Vec<&str> = templates.iter().map(|t| t.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), templates.len());
        for sender in ["curl", "vector", "fluent_bit", "otel_collector", "cribl"] {
            assert!(templates.iter().any(|t| t.sender == sender), "{sender}");
        }
        for protocol in ["hec", "nano_https", "otlp_http"] {
            assert!(templates.iter().any(|t| t.protocol == protocol), "{protocol}");
        }
        for t in &templates {
            assert!(matches!(t.protocol.as_str(), "hec" | "nano_https" | "otlp_http"), "{}", t.id);
            assert!(matches!(t.format.as_str(), "shell" | "toml" | "yaml" | "ini" | "text"), "{}", t.id);
            assert!(t.credential_kinds == vec!["source".to_string()] || t.credential_kinds == vec!["collector".to_string()], "{}", t.id);
            // The auth scheme matches the Worker's per-protocol contract.
            match t.protocol.as_str() {
                "hec" => assert!(!t.body.contains("Bearer"), "{}", t.id),
                _ => assert!(!t.body.contains("Splunk {{token}}"), "{}", t.id),
            }
        }
    }

    #[test]
    fn source_templates_declare_nothing_and_collector_templates_declare_per_protocol() {
        let templates = sender_templates();
        let (sources, collectors): (Vec<_>, Vec<_>) =
            templates.iter().partition(|t| t.credential_kinds == vec!["source".to_string()]);
        for t in &sources {
            // The token fixes the source; declaring one is meaningless.
            let body = t.body.to_ascii_lowercase();
            assert!(!body.contains("sourcetype") && !body.contains("x-nano-source") && !body.contains("source_type")
                && !body.contains("nano.source") && !t.body.contains("{{sources}}"), "{}", t.id);
        }
        // Every (sender, protocol) a source template covers has a collector twin.
        for t in &sources {
            assert!(collectors.iter().any(|c| c.sender == t.sender && c.protocol == t.protocol),
                "no collector template for {} / {}", t.sender, t.protocol);
        }
        for c in &collectors {
            assert!(c.id.ends_with("-collector"), "{}", c.id);
            assert!(c.body.contains("{{sources}}") && c.body.contains("{{example_source}}"), "{}", c.id);
            // Declared where the Worker reads it (design §2.1).
            let body = c.body.to_ascii_lowercase();
            let declares = match c.protocol.as_str() {
                "hec" => body.contains("sourcetype"),
                "nano_https" => body.contains("x-source-type") || body.contains("source_type"),
                "otlp_http" => body.contains("nano.source") || body.contains("x-nano-source"),
                other => panic!("{other}"),
            };
            assert!(declares, "{} does not declare a source for {}", c.id, c.protocol);
            assert!(body.contains("unknown"), "{} must say undeclared events land as unknown", c.id);
        }
        for sender in ["curl", "vector", "fluent_bit", "otel_collector", "cribl"] {
            assert!(collectors.iter().any(|c| c.sender == sender), "{sender}");
        }
    }

    /// The web renders these templates in the browser; its vitest suite runs
    /// against this exact catalog (`nanosiem-web/src/lib/sender-templates.fixture.json`).
    /// Regenerate with `UPDATE_SENDER_TEMPLATE_FIXTURE=1 cargo test -p nanosiem-core --lib ingest_sender_templates`.
    #[test]
    fn web_fixture_matches_the_catalog() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../nanosiem-web/src/lib/sender-templates.fixture.json");
        let fresh = serde_json::to_string_pretty(&sender_template_catalog()).unwrap() + "\n";
        if std::env::var("UPDATE_SENDER_TEMPLATE_FIXTURE").as_deref() == Ok("1") {
            std::fs::write(path, &fresh).unwrap();
            return;
        }
        if !std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../nanosiem-web/package.json")).is_file() {
            eprintln!("skipping sender template fixture check: no web tree");
            return;
        }
        let committed = std::fs::read_to_string(path).expect("sender-templates.fixture.json");
        assert!(committed == fresh,
            "nanosiem-web/src/lib/sender-templates.fixture.json is stale; regenerate with UPDATE_SENDER_TEMPLATE_FIXTURE=1");
    }

    #[test]
    fn collector_snippets_render_the_allowlist_and_keep_sender_syntax() {
        let find = |id: &str| sender_templates().into_iter().find(|t| t.id == id).unwrap();
        let cribl = render(&find("cribl-hec-collector"), &sample());
        assert!(cribl.contains("HEC auth token:      TOKEN-SAMPLE"));
        assert!(cribl.contains("Allowed sourcetypes: palo_alto_traffic, okta, pan:traffic"));
        assert!(cribl.contains("sourcetype = 'palo_alto_traffic'"));
        let vector = render(&find("vector-hec-collector"), &sample());
        assert!(vector.contains("sourcetype = \"{{ nano_source }}\""), "Vector's own template syntax survives");
        assert!(vector.contains(".nano_source = \"palo_alto_traffic\""));
        let otel = render(&find("otel-collector-otlphttp-collector"), &sample());
        assert!(otel.contains("key: nano.source") && otel.contains("value: palo_alto_traffic"));
        let aliases = std::collections::BTreeMap::from([("pan:traffic".to_string(), "palo_alto_traffic".to_string())]);
        assert_eq!(declared_sources(&["palo_alto_traffic".into(), "okta".into()], &aliases), "palo_alto_traffic, okta, pan:traffic");
    }

    #[test]
    fn only_the_token_is_secret_and_labels_become_identifiers() {
        let catalog = sender_template_catalog();
        let secrets: Vec<&str> = catalog.placeholders.iter().filter(|p| p.secret).map(|p| p.marker.as_str()).collect();
        assert_eq!(secrets, vec!["{{token}}"]);
        assert_eq!(identifier_label("Prod firewall #1"), "prod_firewall__1");
        assert_eq!(identifier_label("   "), "ingest");
        let rendered = render(sender_templates().iter().find(|t| t.id == "vector-hec").unwrap(), &sample());
        assert!(rendered.contains("[sinks.nano_prod_firewall__1]"));
    }
}
