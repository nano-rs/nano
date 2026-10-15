// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Copy-paste sender snippets for open-core ingest tokens (NAN-3806).
 *
 * A token decides the source: every event sent with it lands in the source it
 * is bound to, whatever `sourcetype` / `X-Source-Type` the sender declares. So
 * no snippet declares a type, and a Vector aggregator that forwards several
 * log types uses one sink per type, each with the token bound to that type's
 * source. Tokens are never embedded: snippets reference an environment
 * variable (or `<token>`), so a rendered snippet is safe to copy around.
 *
 * `splunk_hec_logs` is Vector's sink type (a wire literal); user-facing text
 * says "HEC".
 */

import type { BindableSource } from '@/lib/api/ingest-tokens';

export const HEC_PORT = 8088;
export const HTTP_PORT = 8080;

/** `NANO_TOKEN_<ROUTE_KEY>`: the env var a snippet reads a source's token from. */
export function tokenEnvVar(source: Pick<BindableSource, 'route_key'>): string {
  const key = source.route_key
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return `NANO_TOKEN_${key || 'SOURCE'}`;
}

/** A Vector component id for a source's sink / input. */
function componentId(source: Pick<BindableSource, 'route_key'>): string {
  const id = source.route_key
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return id || 'source';
}

export function hecCurl(host: string, source: Pick<BindableSource, 'route_key'>): string {
  const env = tokenEnvVar(source);
  return [
    `curl -sS http://${host}:${HEC_PORT}/services/collector/event \\`,
    `  -H "Authorization: Splunk $${env}" \\`,
    `  -d '{"event": {"message": "hello from nano"}}'`,
  ].join('\n');
}

export function httpCurl(host: string, source: Pick<BindableSource, 'route_key'>): string {
  const env = tokenEnvVar(source);
  return [
    `curl -sS http://${host}:${HTTP_PORT}/ \\`,
    `  -H "Authorization: Bearer $${env}" \\`,
    `  -H "Content-Type: application/json" \\`,
    `  -d '{"message": "hello from nano"}'`,
  ].join('\n');
}

/**
 * A Vector aggregator forwarding several log types: one HEC sink per type,
 * each authenticating with the token bound to that type's source.
 */
export function vectorAggregator(host: string, sources: Pick<BindableSource, 'route_key' | 'name'>[]): string {
  const blocks = sources.map((source) => {
    const id = componentId(source);
    return [
      `# ${source.name}: events land in this source because of the token alone.`,
      `[sinks.nano_${id}]`,
      `type = "splunk_hec_logs"`,
      `inputs = ["${id}_logs"]  # your pipeline for this log type`,
      `endpoint = "http://${host}:${HEC_PORT}"`,
      `default_token = "\${${tokenEnvVar(source)}}"`,
      `encoding.codec = "json"`,
    ].join('\n');
  });
  return [
    '# One sink per log type, each with its own ingest token. The token decides',
    '# the source; a sourcetype on the event is ignored for routing.',
    '',
    blocks.join('\n\n'),
  ].join('\n');
}
