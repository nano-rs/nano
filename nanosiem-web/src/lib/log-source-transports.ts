// SPDX-License-Identifier: AGPL-3.0-or-later

import type { LogSource } from '@/lib/api';

/**
 * Maps the wire value of a log source's transport (or a source-configuration's
 * `config_type`) to the human label shown in the UI. Keep in sync with the
 * Rust `SourceType::label()` mapping in
 * nanosiem-core/src/log_sources/types.rs.
 */
export const SOURCE_TYPE_LABELS: Record<string, string> = {
  routed: 'HTTP',
  http: 'HTTP',
  vector: 'Vector',
  kafka: 'Kafka',
  aws_s3: 'AWS S3',
  aws_sqs: 'AWS SQS',
  gcp_pubsub: 'GCP Pub/Sub',
  azure_event_hubs: 'Azure Event Hubs',
  splunk_hec: 'HEC',
};

/**
 * Resolve the transport label for a log source.
 *
 * Prefers `dispatch_source_config_type` — populated by the backend LEFT JOIN
 * on `source_configurations` (NAN-1084) — because it's authoritative for
 * parsers wired through the NAN-928 "DISPATCH FROM" flow. Falls back to
 * `source_type`, which carries the transport sentinel (`routed`, `kafka`, …)
 * for legacy parser-owned sources.
 */
export function logSourceTransportLabel(
  source: Pick<LogSource, 'dispatch_source_config_type' | 'source_type'> & Partial<Pick<LogSource, 'origin'>>,
): string {
  // NAN-3653: a pulled or connector-fed source shows how the customer
  // connected it ("AWS S3 (SQS)", "Google Workspace"), never the internal
  // transport the platform delivers it over.
  const origin = source.origin?.label?.trim();
  if (origin) return origin;
  const key = source.dispatch_source_config_type ?? source.source_type;
  return SOURCE_TYPE_LABELS[key] ?? INGRESS_PROTOCOL_LABELS[key] ?? key;
}

/**
 * Ingest-route protocols the hosted-shared default source reports as its
 * transport (`dispatch_source_config_type` = the counter protocol).
 */
const INGRESS_PROTOCOL_LABELS: Record<string, string> = {
  hec: 'HEC',
  nano_https: 'HTTPS JSON',
  otlp_http: 'OTLP',
};
