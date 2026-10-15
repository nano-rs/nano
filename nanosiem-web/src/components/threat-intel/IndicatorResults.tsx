// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-3881: matches in every IOC source the tenant has enabled (its own IOC
// lists/feeds and its enabled baseline feeds such as ThreatFox / Tor exit
// nodes), grouped by source, plus the list of every source searched with
// match / no-match. Dense; source names, types, confidence, timestamps and
// tags are mono.

import { formatRelativeCompact } from '@/lib/date-utils';
import type { IndicatorLookupResponse, IndicatorMatch, IndicatorSearchedSource } from '@/lib/api/threat-intel';
import { indicatorMissText } from './format';

function seen(m: IndicatorMatch): string | null {
  const first = m.first_seen_at ? formatRelativeCompact(m.first_seen_at).toLowerCase() : null;
  const last = m.last_seen_at ? formatRelativeCompact(m.last_seen_at).toLowerCase() : null;
  if (first && last && first !== last) return `first ${first} · last ${last}`;
  if (last) return `seen ${last}`;
  if (first) return `seen ${first}`;
  return null;
}

/** "searched: ThreatFox · Tor exit nodes · easy_intel", matched sources in
    the foreground with their count, the rest muted. */
function Searched({ searched, unavailable }: { searched: IndicatorSearchedSource[]; unavailable: boolean }) {
  if (searched.length === 0 && !unavailable) return null;
  return (
    <div
      className="mt-1 flex flex-wrap items-baseline gap-x-1.5 gap-y-0.5 font-mono text-[10.5px] text-muted-foreground"
      data-testid="ioc-searched"
    >
      {searched.length > 0 && <span>searched:</span>}
      {searched.map((s, i) => (
        <span key={s.source} data-searched={s.source} data-matched={s.matched ? 'true' : 'false'}>
          <span className={s.matched ? 'text-destructive' : undefined}>{s.source}</span>
          {s.matched && <span className="tabular-nums"> ({s.match_count})</span>}
          {i < searched.length - 1 && <span aria-hidden="true"> ·</span>}
        </span>
      ))}
      {unavailable && (
        <span data-testid="ioc-baseline-unavailable" className="text-amber-600 dark:text-amber-400">
          baseline feeds unavailable, not searched
        </span>
      )}
    </div>
  );
}

/** Older APIs send only `source_names`: derive match state from the groups. */
function searchedOf(response: IndicatorLookupResponse): IndicatorSearchedSource[] {
  if (response.searched) return response.searched;
  const matched = response.sources.map((g) => ({ source: g.source, matched: true, match_count: g.matches.length }));
  const rest = (response.source_names ?? [])
    .filter((n) => !response.sources.some((g) => g.source === n))
    .map((source) => ({ source, matched: false, match_count: 0 }));
  return [...matched, ...rest];
}

export function IndicatorResults({ response }: { response: IndicatorLookupResponse }) {
  const searched = <Searched searched={searchedOf(response)} unavailable={!!response.baseline_feeds_unavailable} />;
  if (response.sources.length === 0) {
    return (
      <div>
        <p
          data-testid="ioc-no-match"
          className="border border-border rounded-sm px-2 py-1.5 text-[12px] text-muted-foreground"
        >
          {indicatorMissText(response.source_count)}
        </p>
        {searched}
      </div>
    );
  }
  return (
    <div>
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
      {searched}
    </div>
  );
}
