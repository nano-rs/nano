// SPDX-License-Identifier: AGPL-3.0-or-later
// Pure formatting helpers for threat-intel results (no components, so the
// component modules stay fast-refresh friendly).

import { formatRelativeCompact } from '@/lib/date-utils';
import type {
  ThreatIntelLookupResponse,
  ThreatIntelOrigin,
  ThreatIntelProviderResult,
  ThreatIntelVerdict,
} from '@/lib/api/threat-intel';

/** "On demand · pivt" for pivt, "On demand" for an analyst click,
    "Auto-investigation" for the case runtime. */
export function originLabel(origin: ThreatIntelOrigin): string {
  switch (origin) {
    case 'pivt':
      return 'On demand · pivt';
    case 'auto_investigation':
      return 'Auto-investigation';
    default:
      return 'On demand';
  }
}

export function statusText(r: ThreatIntelProviderResult): string {
  switch (r.status) {
    case 'ok':
      return r.fetched_at ? `fetched ${formatRelativeCompact(r.fetched_at).toLowerCase()}` : 'fetched';
    case 'cached':
      return r.cached_at ? `cached ${formatRelativeCompact(r.cached_at).toLowerCase()}` : 'cached';
    case 'quota_exhausted':
      return r.retry_after_secs != null ? `quota exhausted · retry in ${r.retry_after_secs}s` : 'quota exhausted';
    case 'budget_exhausted':
      return 'budget exhausted';
    case 'auth_failed':
      return 'credential rejected';
    case 'not_configured':
      return 'not configured';
    default:
      return r.message ? `error · ${r.message}` : 'error';
  }
}

/** Case-notebook citation (`ioc_marker`, `kind: threat_intel`) written by
    the auto-investigation runtime, as a lookup response for the table. */
export function citationToResponse(content: Record<string, unknown>): ThreatIntelLookupResponse {
  const rows = Array.isArray(content.citations) ? (content.citations as Record<string, unknown>[]) : [];
  const str = (v: unknown) => (typeof v === 'string' ? v : null);
  const num = (v: unknown) => (typeof v === 'number' ? v : null);
  const results: ThreatIntelProviderResult[] = rows.map((r) => {
    const status = (str(r.status) ?? 'error') as ThreatIntelProviderResult['status'];
    const reason = str(r.reason);
    return {
      provider: str(r.provider) ?? 'unknown',
      provider_name: str(r.provider_name) ?? str(r.provider) ?? 'unknown',
      status,
      verdict: str(r.verdict) as ThreatIntelVerdict | null,
      score: num(r.score),
      link: str(r.link),
      tags: Array.isArray(r.tags) ? (r.tags as unknown[]).filter((t): t is string => typeof t === 'string') : [],
      summary: {},
      fetched_at: str(r.fetched_at),
      cached_at: str(r.cached_at),
      expires_at: null,
      quota_reason: status === 'quota_exhausted' ? reason : null,
      retry_after_secs: null,
      message: status === 'quota_exhausted' ? null : reason,
    };
  });
  return {
    artifact: str(content.value) ?? '',
    artifact_type: (str(content.entity_type) ?? 'hash') as ThreatIntelLookupResponse['artifact_type'],
    origin: (str(content.origin) ?? 'auto_investigation') as ThreatIntelOrigin,
    availability: results.length === 0 ? 'no_provider_configured' : 'available',
    verdict: str(content.verdict) as ThreatIntelVerdict | null,
    score: num(content.score),
    results,
  };
}

/** NAN-3881: the no-match line for the tenant's own indicator sets. */
export function indicatorMissText(sourceCount: number | null): string {
  if (sourceCount == null) return 'No matches in your indicator sources';
  if (sourceCount === 0) return 'No indicator sources published yet';
  return `No matches in ${sourceCount} indicator source${sourceCount === 1 ? '' : 's'}`;
}
