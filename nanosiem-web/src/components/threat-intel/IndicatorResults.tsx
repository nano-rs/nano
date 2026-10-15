// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-3881: matches in the tenant's own indicator sets (installed IOC feeds
// such as ThreatFox / Tor exit nodes, and published IOC lists), grouped by
// source. Dense; feed names, types, confidence, timestamps and tags are mono.

import { formatRelativeCompact } from '@/lib/date-utils';
import type { IndicatorLookupResponse, IndicatorMatch } from '@/lib/api/threat-intel';
import { indicatorMissText } from './format';

function seen(m: IndicatorMatch): string | null {
  const first = m.first_seen_at ? formatRelativeCompact(m.first_seen_at).toLowerCase() : null;
  const last = m.last_seen_at ? formatRelativeCompact(m.last_seen_at).toLowerCase() : null;
  if (first && last && first !== last) return `first ${first} · last ${last}`;
  if (last) return `seen ${last}`;
  if (first) return `seen ${first}`;
  return null;
}

export function IndicatorResults({ response }: { response: IndicatorLookupResponse }) {
  if (response.sources.length === 0) {
    return (
      <p
        data-testid="ioc-no-match"
        className="border border-border rounded-sm px-2 py-1.5 text-[12px] text-muted-foreground"
        title={response.source_names?.join(', ') || undefined}
      >
        {indicatorMissText(response.source_count)}
      </p>
    );
  }
  return (
    <div className="border border-border rounded-sm" data-testid="ioc-results">
      {response.sources.map((group) => (
        <div key={group.source} data-source={group.source} className="border-b border-border/60 last:border-b-0">
          <div className="flex h-6 items-center justify-between gap-2 px-2">
            <span className="truncate font-mono text-[11.5px]" title={group.source}>
              {group.source}
            </span>
            <span className="shrink-0 font-mono text-[10.5px] text-muted-foreground tabular-nums">
              {group.matches.length === 1 ? '1 match' : `${group.matches.length} matches`}
            </span>
          </div>
          {group.matches.map((m, i) => {
            const label = [m.threat_type, m.malware].filter(Boolean).join(' · ');
            const when = seen(m);
            return (
              <div key={i} className="px-2 pb-1.5 text-[12px]" data-testid="ioc-match">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[10.5px] text-muted-foreground">
                  {m.ioc_type && <span className="text-foreground">{m.ioc_type}</span>}
                  {m.confidence != null && <span className="tabular-nums">conf {m.confidence}</span>}
                  {when && <span>{when}</span>}
                </div>
                {label && <div className="truncate" title={label}>{label}</div>}
                {m.tags.length > 0 && (
                  <div className="truncate font-mono text-[10.5px] text-muted-foreground" title={m.tags.join(', ')}>
                    {m.tags.slice(0, 6).join(' · ')}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}
