// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3248: log-source "lanes" on the hosted-shared (lean) lake.
 *
 * - A log source's `source_type` is its *transport* (`routed` = HTTP ingest via
 *   the router; router codegen keys on it), not what the data is. On lean the
 *   real identity is the lake source slug(s) (`ingest.source_slugs`, the
 *   backend's `source_labels`), the same slugs the ingest chart is keyed by.
 * - Some lanes are platform-managed and have no tenant log-source entry
 *   (`otlp_log`, `audit`); they get read-only rows built from ingestion history.
 * - `findings` is the detection engine's own output, not an ingested source.
 */

import type { LogSource } from '@/lib/api';
import type { IngestionHistoryPoint, LogSourceIngestSummary } from '@/lib/api/types';

/** Lake source slugs for a log source, or null when the API has none (dedicated deployments). */
export function logSourceSlugs(source: Pick<LogSource, 'ingest'>): string[] | null {
  const slugs = (source.ingest?.source_slugs ?? []).filter((s) => s.trim().length > 0);
  return slugs.length > 0 ? slugs : null;
}

/** Events can arrive before the tenant has activated a parser. */
export function receivingWithoutParser(source: Pick<LogSource, 'deployed' | 'ingest'>,
  activity: { events_last_hour?: number; events_last_24h?: number } | null | undefined = source.ingest): boolean {
  return !source.deployed && ((activity?.events_last_hour ?? 0) > 0 || (activity?.events_last_24h ?? 0) > 0);
}

/** Subtitle for a log source row: its lake slugs when known, else the transport sentinel. */
export function logSourceSlugLabel(source: Pick<LogSource, 'ingest' | 'source_type'>): string {
  return logSourceSlugs(source)?.join(', ') ?? source.source_type;
}

export const PLATFORM_LANES: Record<string, { name: string; transport: string; description: string }> = {
  otlp_log: {
    name: 'OTLP logs',
    transport: 'OTLP',
    description: 'OpenTelemetry logs sent to your OTLP endpoint. Parsed by the platform; there is no tenant parser to edit.',
  },
  audit: {
    name: 'Platform audit',
    transport: 'Internal',
    description: 'nano audit events delivered to your lake by the platform.',
  },
};

/** Chart series that are not ingested sources, with the label the legend shows. */
export const INTERNAL_SERIES: Record<string, { label: string; title: string }> = {
  findings: {
    label: 'findings (detection output)',
    title: 'Internal: findings written by the detection engine, not an ingested log source',
  },
};

export interface PlatformLaneRow {
  slug: string;
  name: string;
  transport: string;
  description: string;
  ingest: LogSourceIngestSummary;
}

const HOUR_MS = 3_600_000;

/**
 * Read-only rows for platform-managed lanes that have data in the ingestion
 * history but no log-source entry claiming their slug.
 */
export function platformLaneRows(
  history: IngestionHistoryPoint[] | null | undefined,
  sources: Pick<LogSource, 'ingest'>[],
  now: number = Date.now(),
): PlatformLaneRow[] {
  if (!history?.length) return [];
  const claimed = new Set(sources.flatMap((s) => logSourceSlugs(s) ?? []));
  const rows: PlatformLaneRow[] = [];
  for (const [slug, lane] of Object.entries(PLATFORM_LANES)) {
    if (claimed.has(slug)) continue;
    let total = 0;
    let lastHour = 0;
    let last: number | null = null;
    for (const p of history) {
      if (p.source_type !== slug || p.count <= 0) continue;
      total += p.count;
      const t = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(p.timestamp) ? p.timestamp : `${p.timestamp}Z`);
      if (Number.isNaN(t)) continue;
      if (now - t <= HOUR_MS) lastHour += p.count;
      if (last === null || t > last) last = t;
    }
    if (total === 0) continue;
    rows.push({
      slug,
      ...lane,
      ingest: {
        source_slugs: [slug],
        events_last_24h: total,
        events_last_hour: lastHour,
        bytes_last_24h: 0,
        parse_failures_24h: 0,
        last_event_at: last === null ? null : new Date(last).toISOString(),
        health_status: last !== null && now - last <= 2 * HOUR_MS ? 'healthy' : 'stale',
      },
    });
  }
  return rows;
}
