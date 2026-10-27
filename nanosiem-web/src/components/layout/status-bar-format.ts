// Pure formatters for the bottom status strip in AppLayout. The SIEM health
// payload can be missing (first load, endpoint down) or partial (older
// backends, a dimension that never scored), so every segment must degrade to
// an em dash or be omitted — never "NaN% ingest" or "platform unknown".

export const EM_DASH = '—';

function finiteNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** "87% ingest", or null (segment omitted) when the score isn't a finite number. */
export function formatIngestScore(
  health: { ingestion_score?: unknown } | null | undefined,
): string | null {
  const score = finiteNumber(health?.ingestion_score);
  return score === null ? null : `${Math.round(score)}% ingest`;
}

/** Platform status label; an em dash when the overall status is missing/blank/unknown. */
export function formatPlatformStatus(
  health: { overall_status?: unknown } | null | undefined,
): string {
  const status = health?.overall_status;
  if (typeof status !== 'string') return EM_DASH;
  const trimmed = status.trim();
  return trimmed === '' || trimmed.toLowerCase() === 'unknown' ? EM_DASH : trimmed;
}

/**
 * "1,234 events/min" from the last hour of ingestion-history points, or null
 * when there is no history. Points whose count isn't finite are skipped.
 */
export function formatEventsPerMin(
  points: ReadonlyArray<{ count?: unknown }> | null | undefined,
): string | null {
  if (!points || points.length === 0) return null;
  let total = 0;
  let counted = 0;
  for (const p of points) {
    const n = finiteNumber(p?.count);
    if (n === null) continue;
    total += n;
    counted += 1;
  }
  if (counted === 0) return null;
  return `${Math.round(total / 60).toLocaleString()} events/min`;
}
