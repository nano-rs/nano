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
  crowdstrike_fdr: 'CrowdStrike FDR',
  gcp_pubsub: 'GCP Pub/Sub',
  azure_event_hubs: 'Azure Event Hubs',
  splunk_hec: 'Splunk HEC',
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
  source: Pick<LogSource, 'dispatch_source_config_type' | 'source_type'>,
): string {
  const key = source.dispatch_source_config_type ?? source.source_type;
  return SOURCE_TYPE_LABELS[key] ?? key;
}

/**
 * NAN-6036: the `ingestion_method` a library parser must be imported with
 * when it is fed by a source configuration of `configType`. This is the web
 * copy of `SOURCE_TYPE_MAP` (moved here from ParserRepositories so the Add
 * source wizard uses the same table) and mirrors the Rust
 * `ingest_transport::dispatch_compatible`: a configuration feeds the method of
 * the same name, except `http`, which feeds `routed`. The import endpoint
 * refuses any other pairing (NAN-943), because a parser bound to the wrong
 * route receives no events.
 *
 * Returns `null` for a configuration type this table does not know, so a
 * caller can refuse it instead of guessing.
 */
const INGESTION_METHOD_FOR_CONFIG_TYPE: Record<string, string> = {
  http: 'routed',
  vector: 'vector',
  otlp: 'otlp',
  splunk_hec: 'splunk_hec',
  kafka: 'kafka',
  aws_s3: 'aws_s3',
  aws_sqs: 'aws_sqs',
  crowdstrike_fdr: 'crowdstrike_fdr',
  gcp_pubsub: 'gcp_pubsub',
  azure_event_hubs: 'azure_event_hubs',
};

export function ingestionMethodForConfigType(configType: string | null | undefined): string | null {
  if (!configType) return null;
  return INGESTION_METHOD_FOR_CONFIG_TYPE[configType] ?? null;
}
