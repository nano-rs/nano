// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5264: how the log source health card reads a parser's fallbacks.
 *
 * A fallback is a record the parser did not really parse but did not report
 * as a failure: it carries the parser's `unmapped.parse_fallback` marker.
 * A record with no event time, or a correctly parsed Base Event (class 0), is not one.
 * Health used to count these as successes, so a source whose every event
 * fell back showed 100% parse success.
 */

/** Above this share of fallbacks in 24h, the source warns. */
export const FALLBACK_WARN_RATE = 0.02;

export interface ParseHealthCounters {
  parse_attempts_24h?: number;
  parse_fallbacks_24h?: number;
  parse_fallback_rate_24h?: number | null;
}

/** The fallback share, or null when there were no production events. */
export function fallbackRate(health: ParseHealthCounters | null | undefined): number | null {
  if (!health) return null;
  if (typeof health.parse_fallback_rate_24h === 'number') return health.parse_fallback_rate_24h;
  const attempts = health.parse_attempts_24h ?? 0;
  if (attempts <= 0) return null;
  return Math.min(1, Math.max(0, (health.parse_fallbacks_24h ?? 0) / attempts));
}

/** True when enough events fell back that the source should warn. */
export function fallbackWarns(health: ParseHealthCounters | null | undefined): boolean {
  const rate = fallbackRate(health);
  return rate != null && rate > FALLBACK_WARN_RATE && (health?.parse_fallbacks_24h ?? 0) > 0;
}

/** `16.67%`, or `<0.01%` for a non-zero share that would otherwise print as 0. */
export function formatShare(rate: number): string {
  if (rate > 0 && rate < 0.0001) return '<0.01%';
  return `${(rate * 100).toFixed(2)}%`;
}
