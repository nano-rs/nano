// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sender configuration snippets for an ingest token (main's NAN-2593 module,
 * ported to the ClickHouse product by NAN-4922).
 *
 * On main the templates came from the hosted `GET /api/log-sources/sender-templates`.
 * Here the catalog is static and fills in this deployment's ingest endpoint
 * (`GET /api/log-sources/ingest-endpoint`):
 *
 * - HEC: `POST <hec_url>/services/collector/event` on Vector's HEC listener,
 *   `Authorization: Splunk <token>`.
 *   The listener has indexer acknowledgements on, so a request needs an
 *   `X-Splunk-Request-Channel` (any UUID; HEC senders set one themselves).
 * - HTTP JSON: `POST <base>/ingest` through the web edge, `Authorization: Bearer
 *   <token>`, one JSON object, an array or NDJSON.
 * - OTLP/HTTP: `POST <base>/otlp/v1/logs` (protobuf only), `Authorization:
 *   Bearer <token>`, authenticated by the edge's `auth_request`.
 *
 * curl snippets use `--fail-with-body` (NAN-4945): a 401/404 must not look like a
 * send. `-sS` alone printed nothing for an empty 404 (a dev server answering
 * `/ingest`) and exited 0.
 *
 * The token decides the source (NAN-4907), so no template declares a source
 * type. `renderSenderTemplate` fills `{{marker}}` placeholders in the browser;
 * the rendered text carries the plaintext token, so callers keep it in
 * component state, never in a query cache or storage.
 */

import type { IngestEndpoint } from '@/lib/api/types';

export interface SenderTemplate {
  id: string;
  sender: 'curl' | 'vector' | 'fluent_bit' | 'otel_collector' | 'cribl';
  sender_name: string;
  protocol: 'hec' | 'nano_https' | 'otlp_http';
  format: 'shell' | 'toml' | 'yaml' | 'ini' | 'text';
  title: string;
  description: string;
  body: string;
}

/** Values for the template placeholders (`{{hostname}}`, `{{token}}`, ...). */
export interface SenderTemplateValues {
  hostname: string;
  hec_url: string;
  hec_event_url: string;
  /** Vector's HEC listener port. */
  hec_port: string;
  nano_https_url: string;
  /** The web edge's port (443 / 80 when the origin has none). */
  base_port: string;
  /** Fluent Bit `TLS` value for the web edge: `On` / `Off`. */
  base_tls: string;
  otlp_logs_url: string;
  token: string;
  label: string;
}

function urlPort(url: string): string {
  try {
    const u = new URL(url);
    return u.port || (u.protocol === 'https:' ? '443' : '80');
  } catch {
    return '';
  }
}

/**
 * Reduce a token name to an identifier (`[a-z0-9_]`, at most 48 chars,
 * `ingest` when empty), for sender output names.
 */
export function identifierLabel(label: string): string {
  const out = Array.from(label.trim().toLowerCase())
    .map((c) => (/^[a-z0-9]$/.test(c) ? c : '_'))
    .slice(0, 48)
    .join('');
  return out || 'ingest';
}

export function senderValuesFromEndpoint(
  endpoint: Pick<IngestEndpoint, 'hostname' | 'hec_url' | 'hec_event_url' | 'nano_https_url' | 'otlp_logs_url'>,
  credential: { token: string; label: string },
): SenderTemplateValues {
  return {
    hostname: endpoint.hostname,
    hec_url: endpoint.hec_url.replace(/\/+$/, ''),
    hec_event_url: endpoint.hec_event_url,
    hec_port: urlPort(endpoint.hec_url),
    nano_https_url: endpoint.nano_https_url.replace(/\/+$/, ''),
    base_port: urlPort(endpoint.nano_https_url),
    base_tls: endpoint.nano_https_url.startsWith('https:') ? 'On' : 'Off',
    otlp_logs_url: endpoint.otlp_logs_url,
    token: credential.token,
    label: credential.label,
  };
}

/** Fill every known placeholder in one pass (a value containing a marker is never re-expanded). */
export function renderSenderTemplate(template: Pick<SenderTemplate, 'body'>, values: SenderTemplateValues): string {
  const map: Record<string, string> = {
    '{{hostname}}': values.hostname,
    '{{hec_url}}': values.hec_url,
    '{{hec_event_url}}': values.hec_event_url,
    '{{hec_port}}': values.hec_port,
    '{{nano_https_url}}': values.nano_https_url,
    '{{base_port}}': values.base_port,
    '{{base_tls}}': values.base_tls,
    '{{otlp_logs_url}}': values.otlp_logs_url,
    '{{token}}': values.token,
    '{{label}}': identifierLabel(values.label),
  };
  // Sender syntax with spaces (Vector's `"{{ field }}"`) is not a marker and stays.
  return template.body.replace(/\{\{[a-z_]+\}\}/g, (marker) => map[marker] ?? marker);
}

const t = (template: SenderTemplate): SenderTemplate => ({ ...template, body: template.body.replace(/^\n/, '') });

/** The catalog, in display order (sender, then protocol). */
export const SENDER_TEMPLATES: SenderTemplate[] = [
  t({ id: 'curl-hec', sender: 'curl', sender_name: 'curl', protocol: 'hec', format: 'shell',
    title: 'Send a test event (HEC)',
    description: 'One JSON event to the HEC event endpoint. Expect {"text":"Success","code":0}; a wrong URL or token exits non-zero with the error.',
    body: `
curl -sS --fail-with-body "{{hec_event_url}}" \\
  -H "Authorization: Splunk {{token}}" \\
  -H "X-Splunk-Request-Channel: $(uuidgen)" \\
  -H "Content-Type: application/json" \\
  -d '{"event": {"message": "hello from curl"}}'
` }),
  t({ id: 'curl-nano-https', sender: 'curl', sender_name: 'curl', protocol: 'nano_https', format: 'shell',
    title: 'Send a test event (HTTP JSON)',
    description: 'One JSON object (an array or newline-delimited JSON also works). A wrong URL or token exits non-zero with the error.',
    body: `
curl -sS --fail-with-body "{{nano_https_url}}" \\
  -H "Authorization: Bearer {{token}}" \\
  -H "Content-Type: application/json" \\
  -d '{"message": "hello from curl"}'
` }),
  t({ id: 'vector-hec', sender: 'vector', sender_name: 'Vector', protocol: 'hec', format: 'toml',
    title: 'Vector: HEC sink',
    description: 'Add to vector.toml and set `inputs` to your sources. Vector appends /services/collector/event.',
    body: `
[sinks.nano_{{label}}]
type = "splunk_hec_logs"
inputs = ["my_source"]
endpoint = "{{hec_url}}"
default_token = "{{token}}"
endpoint_target = "event"
encoding.codec = "json"
` }),
  t({ id: 'vector-http', sender: 'vector', sender_name: 'Vector', protocol: 'nano_https', format: 'toml',
    title: 'Vector: http sink (JSON)',
    description: 'Newline-delimited JSON with a bearer token.',
    body: `
[sinks.nano_{{label}}]
type = "http"
inputs = ["my_source"]
uri = "{{nano_https_url}}"
method = "post"
auth.strategy = "bearer"
auth.token = "{{token}}"
encoding.codec = "json"
framing.method = "newline_delimited"
request.headers.Content-Type = "application/x-ndjson"
` }),
  t({ id: 'fluent-bit-hec', sender: 'fluent_bit', sender_name: 'Fluent Bit', protocol: 'hec', format: 'ini',
    title: 'Fluent Bit: HEC output',
    description: 'Add to fluent-bit.conf (HEC output plugin, `Name splunk`). Channel is any fixed UUID (acknowledgements are on).',
    body: `
[OUTPUT]
    Name         splunk
    Match        *
    Host         {{hostname}}
    Port         {{hec_port}}
    Splunk_Token {{token}}
    Channel      9f1c2a3b-4d5e-4f60-8a7b-0c1d2e3f4a5b
` }),
  t({ id: 'fluent-bit-http', sender: 'fluent_bit', sender_name: 'Fluent Bit', protocol: 'nano_https', format: 'ini',
    title: 'Fluent Bit: http output (JSON lines)',
    description: 'Newline-delimited JSON with a bearer token, through the web edge.',
    body: `
[OUTPUT]
    Name        http
    Match       *
    Host        {{hostname}}
    Port        {{base_port}}
    URI         /ingest
    Format      json_lines
    Header      Authorization Bearer {{token}}
    TLS         {{base_tls}}
` }),
  t({ id: 'otel-collector-otlphttp', sender: 'otel_collector', sender_name: 'OpenTelemetry Collector', protocol: 'otlp_http', format: 'yaml',
    title: 'OpenTelemetry Collector: otlphttp exporter',
    description: 'Add the exporter and reference it from your logs pipeline. The endpoint accepts protobuf.',
    body: `
exporters:
  otlphttp/nano:
    logs_endpoint: {{otlp_logs_url}}
    encoding: proto
    headers:
      Authorization: "Bearer {{token}}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlphttp/nano]
` }),
  t({ id: 'otel-collector-hec', sender: 'otel_collector', sender_name: 'OpenTelemetry Collector', protocol: 'hec', format: 'yaml',
    title: 'OpenTelemetry Collector: HEC exporter',
    description: 'Sends collector logs as HEC events with the `splunk_hec` exporter.',
    body: `
exporters:
  splunk_hec/nano:
    endpoint: {{hec_event_url}}
    token: "{{token}}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [splunk_hec/nano]
` }),
  t({ id: 'cribl-hec', sender: 'cribl', sender_name: 'Cribl Stream', protocol: 'hec', format: 'text',
    title: 'Cribl Stream: HEC destination',
    description: 'Data > Destinations > HEC-compatible destination > Add Destination. Values for the form.',
    body: `
Output ID:           nano_{{label}}
HEC endpoint:        {{hec_event_url}}
Authentication:      Manual
HEC auth token:      {{token}}
` }),
  t({ id: 'cribl-webhook', sender: 'cribl', sender_name: 'Cribl Stream', protocol: 'nano_https', format: 'text',
    title: 'Cribl Stream: Webhook destination',
    description: 'Data > Destinations > Webhook > Add Destination. Values for the form.',
    body: `
Output ID:           nano_{{label}}
URL:                 {{nano_https_url}}
Method:              POST
Format:              NDJSON
Authentication type: Auth token
Token:               {{token}}
` }),
];

/** Templates usable with a token on this protocol, in catalog order. */
export function templatesForProtocol(protocol: string, catalog: SenderTemplate[] = SENDER_TEMPLATES): SenderTemplate[] {
  return catalog.filter((tpl) => tpl.protocol === protocol);
}
