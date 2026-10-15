// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Sender configuration snippets (NAN-2593, data onboarding design §3.2).
 *
 * Two producers share this module:
 *
 * - Hosted-shared tenants: `renderSenderTemplate` fills the server-side
 *   templates from `GET /api/log-sources/sender-templates` (NAN-2592) with the
 *   tenant's real ingest endpoint and, in the browser only, the one-time token.
 *   The rendered text carries the plaintext token, so callers keep it in
 *   component state and never in a query cache or storage.
 * - Dedicated deployments: `buildConnectionSummary`, moved here unchanged from
 *   `SourceConfigurationDetail` so both surfaces share one module.
 */

import type {
  SenderTemplate,
  SenderTemplateCatalog,
  SourceConfiguration,
  TenantIngestEndpoint,
} from '@/lib/api/types';

// ------------------------------------------------------------ hosted-shared

/** Values for the template placeholders (`{{hostname}}`, `{{token}}`, ...). */
export interface SenderTemplateValues {
  hostname: string;
  base_url: string;
  hec_url: string;
  nano_https_url: string;
  otlp_logs_url: string;
  token: string;
  label: string;
  /** Collector: every name an event may declare (slugs, then aliases), comma-separated. */
  sources: string;
  /** Collector: one allowlisted slug for examples. */
  example_source: string;
}

/**
 * Reduce a credential label to an identifier (`[a-z0-9_]`, at most 48 chars,
 * `ingest` when empty). Mirrors `ingest_sender_templates::identifier_label`.
 */
export function identifierLabel(label: string): string {
  const out = Array.from(label.trim().toLowerCase())
    .map((c) => (/^[a-z0-9]$/.test(c) ? c : '_'))
    .slice(0, 48)
    .join('');
  return out || 'ingest';
}

export function senderValuesFromEndpoint(
  endpoint: Pick<TenantIngestEndpoint, 'hostname' | 'base_url' | 'hec_url' | 'nano_https_url' | 'otlp_logs_url'>,
  credential: { token: string; label: string; sources?: string; exampleSource?: string },
): SenderTemplateValues {
  const base = endpoint.base_url.replace(/\/+$/, '');
  return {
    hostname: endpoint.hostname,
    base_url: base,
    hec_url: endpoint.hec_url,
    nano_https_url: endpoint.nano_https_url,
    otlp_logs_url: endpoint.otlp_logs_url,
    token: credential.token,
    label: credential.label,
    sources: credential.sources ?? '',
    example_source: credential.exampleSource ?? '',
  };
}

/** Fill every known placeholder. The label becomes an identifier, as on the server. */
export function renderSenderTemplate(template: Pick<SenderTemplate, 'body'>, values: SenderTemplateValues): string {
  const map: Record<string, string> = {
    '{{hostname}}': values.hostname,
    '{{base_url}}': values.base_url,
    '{{hec_url}}': values.hec_url,
    '{{nano_https_url}}': values.nano_https_url,
    '{{otlp_logs_url}}': values.otlp_logs_url,
    '{{token}}': values.token,
    '{{label}}': identifierLabel(values.label),
    '{{sources}}': values.sources,
    '{{example_source}}': values.example_source,
  };
  // One pass, so a value that happens to contain a marker is never re-expanded.
  // Sender template syntax with spaces (Vector's `"{{ field }}"`) is not a marker and stays.
  return template.body.replace(/\{\{[a-z_]+\}\}/g, (marker) => map[marker] ?? marker);
}

/** Templates usable with a credential of this protocol and kind, in catalog order. */
export function templatesForCredential(
  catalog: SenderTemplateCatalog | undefined,
  protocol: string,
  kind: string = 'source',
): SenderTemplate[] {
  return (catalog?.templates ?? []).filter((t) => t.protocol === protocol && t.credential_kinds.includes(kind));
}

// ---------------------------------------------------------------- dedicated

export type ConnectionSummaryInput = Pick<SourceConfiguration, 'config_type' | 'connection_config' | 'credential_id'>;

export interface ConnectionSummary {
  method?: string;
  display: string;
  full?: string;
  authLabel?: string;
  auth?: string;
  headers?: Array<{ key: string; value: string; hint?: string }>;
  snippet?: string;
  usesPlaceholderHost: boolean;
}

export function buildConnectionSummary(config: ConnectionSummaryInput): ConnectionSummary {
  const cc = config.connection_config ?? {};
  const HOST = '{your-ingest-host}';
  const usesPlaceholderHost = true;

  switch (config.config_type) {
    case 'http': {
      const port = (cc.port as number | string) ?? 9090;
      const path = (cc.path as string) ?? '/ingest';
      const full = `https://${HOST}:${port}${path}`;
      return {
        method: 'POST',
        full,
        display: `POST ${path}`,
        authLabel: 'Auth',
        auth: 'Bearer ${NANO_INGEST_TOKEN}',
        headers: [
          { key: 'Content-Type', value: 'application/json' },
          {
            key: 'X-Source-Type',
            value: '<source_type>',
            hint: 'matched by routing rules',
          },
        ],
        snippet: [
          `curl -X POST ${full} \\`,
          `  -H 'Authorization: Bearer $NANO_INGEST_TOKEN' \\`,
          `  -H 'Content-Type: application/json' \\`,
          `  -H 'X-Source-Type: aws_cloudtrail' \\`,
          `  -d '{"eventSource":"s3.amazonaws.com",…}'`,
        ].join('\n'),
        usesPlaceholderHost,
      };
    }
    case 'vector': {
      const address = (cc.address as string) ?? `${HOST}:6000`;
      return {
        method: 'SOCKET',
        full: `vector://${address}`,
        display: `Vector ${address.includes(':') ? address : ':6000'}`,
        authLabel: 'Auth',
        auth: 'mTLS (certificate pinned)',
        headers: [],
        snippet: [
          '# In your upstream Vector config:',
          '[sinks.nano]',
          'type      = "vector"',
          `address   = "${address}"`,
          'inputs    = ["your_source"]',
          'tls.enabled = true',
        ].join('\n'),
        usesPlaceholderHost,
      };
    }
    case 'aws_s3': {
      const sqs = (cc.sqs_queue_url as string) ?? `arn:aws:sqs:us-east-1:••••:nano-ingest`;
      return {
        method: 'SQS',
        full: sqs,
        display: 'SQS-driven',
        authLabel: 'Assume role',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : '(no credential attached)',
        headers: [],
        snippet: [
          '# S3 event notifications → SQS → nano poller',
          '# Configure in the S3 bucket properties:',
          'Event type: s3:ObjectCreated:*',
          `Destination: ${sqs}`,
          'Then grant sqs:ReceiveMessage to the assumed role above.',
        ].join('\n'),
        usesPlaceholderHost: false,
      };
    }
    case 'gcp_pubsub': {
      const project = (cc.project as string) ?? '<project>';
      const subscription = (cc.subscription as string) ?? '<subscription>';
      const full = subscription.startsWith('projects/')
        ? subscription
        : `projects/${project}/subscriptions/${subscription}`;
      return {
        method: 'SUB',
        full,
        display: 'Pub/Sub subscription',
        authLabel: 'Service account',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : '(no credential attached)',
        headers: [],
        usesPlaceholderHost: false,
      };
    }
    case 'azure_event_hubs': {
      const hub = (cc.event_hub_name as string) ?? '<event hub>';
      const group = (cc.consumer_group as string) || '$Default';
      const namespace = (cc.namespace as string) || '<from connection string>';
      return {
        method: 'CONSUME',
        full: `namespace=${namespace}  hub=${hub}  group=${group}`,
        display: 'Event Hubs consumer',
        authLabel: 'Auth',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : 'managed identity',
        headers: [],
        usesPlaceholderHost: false,
      };
    }
    case 'kafka': {
      const bootstrap = (cc.bootstrap_servers as string) ?? '<bootstrap>';
      const topics = ((cc.topics as string[]) ?? []).join(', ') || '<topics>';
      return {
        method: 'CONSUME',
        full: `bootstrap=${bootstrap}  topics=${topics}`,
        display: 'Kafka consumer',
        authLabel: 'Auth',
        auth: config.credential_id
          ? `credential ${config.credential_id}`
          : 'SASL_SSL / SCRAM-SHA-512',
        headers: [],
        usesPlaceholderHost: false,
      };
    }
    case 'splunk_hec': {
      const port = (cc.port as number | string) ?? 8088;
      const full = `https://${HOST}:${port}/services/collector/event`;
      return {
        method: 'POST',
        full,
        display: `HEC :${port}`,
        authLabel: 'Auth',
        auth: 'HEC token (rotate via credentials)',
        headers: [{ key: 'Authorization', value: 'Splunk <token>' }],
        snippet: [
          `curl -X POST ${full} \\`,
          `  -H 'Authorization: Splunk $HEC_TOKEN' \\`,
          `  -d '{"event":{…},"sourcetype":"okta:log"}'`,
        ].join('\n'),
        usesPlaceholderHost,
      };
    }
    default:
      return { display: 'No endpoint summary', usesPlaceholderHost: false };
  }
}
