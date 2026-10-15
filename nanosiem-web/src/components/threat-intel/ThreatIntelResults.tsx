// SPDX-License-Identifier: AGPL-3.0-or-later
// Dense per-provider threat-intel results. One row per provider: name,
// verdict, score, status / freshness, link. Values are mono.

import { statusText } from './format';
import { cn } from '@/lib/utils';
import type { ThreatIntelLookupResponse, ThreatIntelVerdict } from '@/lib/api/threat-intel';

const VERDICT_CLS: Record<ThreatIntelVerdict, string> = {
  malicious: 'text-destructive border-destructive/40',
  suspicious: 'text-amber-600 dark:text-amber-400 border-amber-500/40',
  benign: 'text-emerald-600 dark:text-emerald-400 border-emerald-500/40',
  unknown: 'text-muted-foreground border-border',
  not_found: 'text-muted-foreground border-border',
};

export function VerdictChip({ verdict }: { verdict: ThreatIntelVerdict | null }) {
  const v = verdict ?? 'unknown';
  return (
    <span
      data-verdict={v}
      className={cn(
        'inline-flex h-[18px] items-center rounded-sm border px-1 font-mono text-[10.5px] leading-none',
        VERDICT_CLS[v],
      )}
    >
      {v.replace('_', ' ')}
    </span>
  );
}

function safeLink(link: string | null): string | null {
  if (!link) return null;
  try {
    const u = new URL(link);
    return u.protocol === 'https:' ? u.toString() : null;
  } catch {
    return null;
  }
}

export function ThreatIntelResults({ response }: { response: ThreatIntelLookupResponse }) {
  if (response.availability === 'no_provider_configured') {
    // A hint, not an error: the tenant's own indicator sets are searched
    // regardless; external providers are an optional add-on (NAN-3881).
    return (
      <p data-testid="ti-no-provider" className="text-[11px] text-muted-foreground">
        No external provider installed for <span className="font-mono">{response.artifact_type}</span> lookups · add
        one under Marketplace → Agent.
      </p>
    );
  }
  return (
    <table className="w-full border border-border text-[12px]" data-testid="ti-results">
      <thead>
        <tr className="h-6 border-b border-border text-left font-mono text-[10.5px] text-muted-foreground">
          <th className="px-2 font-normal">provider</th>
          <th className="px-2 font-normal">verdict</th>
          <th className="px-2 text-right font-normal">score</th>
          <th className="px-2 font-normal">status</th>
        </tr>
      </thead>
      <tbody>
        {response.results.map((r) => {
          const link = safeLink(r.link);
          return (
            <tr key={r.provider} className="h-7 border-b border-border/60 last:border-b-0 align-middle" data-provider={r.provider}>
              <td className="px-2">
                {link ? (
                  <a href={link} target="_blank" rel="noopener noreferrer" className="hover:underline">
                    {r.provider_name}
                  </a>
                ) : (
                  r.provider_name
                )}
                {r.tags.length > 0 && (
                  <div className="truncate font-mono text-[10.5px] text-muted-foreground" title={r.tags.join(', ')}>
                    {r.tags.slice(0, 4).join(' · ')}
                  </div>
                )}
              </td>
              <td className="px-2">{r.verdict ? <VerdictChip verdict={r.verdict} /> : <span className="font-mono text-[10.5px] text-muted-foreground">—</span>}</td>
              <td className="px-2 text-right font-mono tabular-nums">{r.score ?? '—'}</td>
              <td
                className={cn(
                  'px-2 font-mono text-[10.5px]',
                  r.status === 'quota_exhausted' || r.status === 'auth_failed' || r.status === 'error'
                    ? 'text-amber-600 dark:text-amber-400'
                    : 'text-muted-foreground',
                )}
                data-status={r.status}
              >
                {statusText(r)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
