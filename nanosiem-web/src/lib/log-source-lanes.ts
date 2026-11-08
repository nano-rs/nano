// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Log-source lanes on the ClickHouse product (main's NAN-3248 module, trimmed
 * by NAN-4922). Main keyed lanes on hosted lake slugs and added read-only rows
 * for platform-managed lanes; neither exists here. A source's lane is its
 * route key (`source_type`), and its activity comes from the connect status.
 */

import type { LogSource } from '@/lib/api';
import type { LogSourceConnectStatus } from '@/lib/api/log-source-connect';

/** Events arrive (with a bound token) but no parser is published yet. */
export function receivingWithoutParser(
  source: Pick<LogSource, 'deployed'>,
  status: Pick<LogSourceConnectStatus, 'state' | 'events_24h'> | null | undefined,
): boolean {
  if (!status) return false;
  return status.state === 'receiving_unparsed' || (!source.deployed && status.events_24h > 0);
}

/** Subtitle for a log source row: its route key when known, else its match values / transport sentinel. */
export function logSourceSlugLabel(
  source: Pick<LogSource, 'source_type' | 'match_values'>,
  status?: Pick<LogSourceConnectStatus, 'route_key'> | null,
): string {
  return status?.route_key ?? (source.match_values?.length ? source.match_values.join(', ') : source.source_type);
}

/** Chart series that are not ingested sources, with the label the legend shows. */
export const INTERNAL_SERIES: Record<string, { label: string; title: string }> = {
  detection_signal: {
    label: 'detection_signal (detection output)',
    title: 'Internal: signals written by the detection engine, not an ingested log source',
  },
};
