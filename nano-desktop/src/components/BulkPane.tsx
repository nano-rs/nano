import { useMemo } from 'react';

import { classifyIndicator, extractWithStats, type Indicator } from '../lib/indicator';
import type { BulkIocHit } from '../lib/types';
import type { Tab } from '../state/tabs';
import { Spinner } from './ui';

/**
 * Bulk IOC lookup: paste a threat report, get the only answer that matters —
 * **which of these have we actually seen?**
 *
 * Every number here comes from a real event match (one `ioc = "…"` search per
 * indicator). Nothing is inferred, and an indicator whose search FAILED is shown
 * as failed rather than as clean: "we didn't see it" and "we couldn't look" are
 * different answers, and only one of them means you can stop worrying.
 */
interface Props {
  tab: Tab;
  onTextChange: (text: string) => void;
  onRun: () => void;
  onOpenIndicator: (indicator: Indicator) => void;
  onInvestigate: (hits: BulkIocHit[]) => void;
}

export function BulkPane({ tab, onTextChange, onRun, onOpenIndicator, onInvestigate }: Props) {
  const bulk = tab.bulk;
  const text = bulk?.text ?? '';

  // Extraction is local and instant — the analyst sees what we found in their
  // paste before committing to a single query.
  const { indicators, duplicates } = useMemo(() => extractWithStats(text), [text]);
  const counts = useMemo(() => countByKind(indicators), [indicators]);

  const hits = bulk?.hits ?? [];
  const running = bulk?.status === 'running';
  const ran = hits.length > 0;
  const seen = hits.filter((hit) => hit.seen);
  const failed = hits.filter((hit) => hit.error);

  return (
    <div className="flex min-h-0 flex-1">
      {/* Left: what was pasted, and what we made of it. */}
      <div className="flex w-[350px] shrink-0 flex-col border-r border-line p-4">
        <div className="text-[10.5px] font-bold tracking-[0.06em] text-t4">
          PASTED LIST · AUTO-PARSED
        </div>

        <div className="mt-1.5 font-mono text-[11px] text-t3">
          {indicators.length} unique
          {duplicates > 0 && <span className="text-t4"> · {duplicates} dupes dropped</span>}
        </div>

        {indicators.length > 0 && (
          <div className="mt-2.5 flex flex-wrap gap-1.5">
            {counts.map(([kind, count]) => (
              <span
                key={kind}
                className={`rounded-[20px] border px-2 py-0.5 font-mono text-[10.5px] ${KIND_STYLE[kind]}`}
              >
                {kind} · {count}
              </span>
            ))}
          </div>
        )}

        <textarea
          value={text}
          onChange={(event) => onTextChange(event.target.value)}
          placeholder={
            'Paste a threat report, an advisory, a chat message…\n\n' +
            'Defanged indicators are fine — evil[.]com and hxxps://… are refanged\n' +
            'automatically, which is how they arrive in real reports.'
          }
          spellCheck={false}
          className="mt-3 min-h-0 flex-1 resize-none rounded-[9px] border border-line-strong bg-input p-3 font-mono text-[11.5px] leading-[1.55] text-t2 outline-none placeholder:text-t4 focus:border-accent"
        />

        <button
          onClick={onRun}
          disabled={indicators.length === 0 || running}
          className="mt-3 shrink-0 rounded-[9px] border border-accent-line bg-accent-fill px-4 py-2.5 text-[12px] font-semibold text-accent disabled:opacity-40"
        >
          {running ? 'Looking up…' : `Look up ${indicators.length || ''} in your data`.trim()}
        </button>
      </div>

      {/* Right: the answer. */}
      <div className="flex min-w-0 flex-1 flex-col overflow-auto p-4">
        {bulk?.error && (
          <div className="rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[12px] text-danger">
            {bulk.error}
          </div>
        )}

        {!ran && !running && !bulk?.error && (
          <div className="mt-16 text-center text-[12.5px] text-t4">
            Paste a list on the left. nano will tell you which of the indicators in it have
            been seen in your own data — and which haven't.
          </div>
        )}

        {running && (
          <div className="flex items-center gap-2 text-[12px] text-t3">
            <Spinner className="text-accent" /> Searching {indicators.length} indicators over the
            last {bulk?.windowDays} days…
          </div>
        )}

        {ran && !running && (
          <>
            <div className="text-[15px] text-t1">
              <span className="font-semibold text-accent">
                {seen.length} of {hits.length}
              </span>{' '}
              seen in your data
            </div>
            <div className="mt-1 font-mono text-[11px] text-t3">
              last {bulk?.windowDays}d ·{' '}
              {seen.reduce((total, hit) => total + hit.events, 0).toLocaleString()} hits total
              {failed.length > 0 && (
                <span className="text-warn"> · {failed.length} could not be checked</span>
              )}
            </div>

            {seen.length > 0 && (
              <button
                onClick={() => onInvestigate(seen)}
                className="mt-3 self-start rounded-[9px] border border-accent-line bg-accent-fill px-3.5 py-2 text-[12px] font-semibold text-accent"
              >
                ✳ Investigate the {seen.length} {seen.length === 1 ? 'match' : 'matches'} with pivt
              </button>
            )}

            <HitsTable hits={hits} onOpen={onOpenIndicator} />

            <div className="mt-3 text-[11px] text-t4">
              An indicator with no hits has not been seen in the window searched. That is not
              the same as "safe" — it means it hasn't shown up here yet.
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function HitsTable({
  hits,
  onOpen,
}: {
  hits: BulkIocHit[];
  onOpen: (indicator: Indicator) => void;
}) {
  // Matches first — the analyst is looking for the needles, not the haystack.
  const ordered = [...hits].sort((a, b) => Number(b.seen) - Number(a.seen) || b.events - a.events);

  return (
    <table className="mt-4 w-full border-collapse text-left">
      <thead>
        <tr>
          {['INDICATOR', 'HITS', 'ASSETS', 'WHERE', 'FIRST–LAST SEEN'].map((heading) => (
            <th
              key={heading}
              className="border-b border-line px-2 py-1.5 text-[10.5px] font-bold tracking-[0.06em] whitespace-nowrap text-t4"
            >
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {ordered.map((hit) => (
          <tr
            key={hit.indicator}
            onClick={() => {
              // The value is already normalized — classify it back into an
              // indicator rather than re-running the freetext extractor on it.
              const indicator = classifyIndicator(hit.indicator);
              if (indicator) onOpen(indicator);
            }}
            className={`cursor-default border-b border-line/50 hover:bg-hover ${
              hit.seen ? '' : 'opacity-55'
            }`}
          >
            <td className="px-2 py-1.5 font-mono text-[11.5px] break-all text-t1">
              {hit.indicator}
            </td>

            {hit.error ? (
              // A failed lookup must never be shown as a clean one.
              <td
                colSpan={4}
                className="px-2 py-1.5 font-mono text-[11.5px] text-warn"
                title={hit.error}
              >
                could not be checked
              </td>
            ) : (
              <>
                <td
                  className={`px-2 py-1.5 font-mono text-[11.5px] ${
                    hit.events > 0 ? 'text-warn' : 'text-t4'
                  }`}
                >
                  {hit.events > 0 ? hit.events.toLocaleString() : '—'}
                </td>
                <td className="px-2 py-1.5 font-mono text-[11.5px] text-t2">
                  {hit.assets > 0 ? hit.assets.toLocaleString() : '—'}
                </td>
                <td className="max-w-[220px] truncate px-2 py-1.5 font-mono text-[11.5px] text-t3">
                  {hit.top_assets.length > 0 ? (
                    hit.top_assets.map((asset) => asset.asset).join(', ')
                  ) : hit.assets > 0 ? (
                    // We KNOW assets saw it (the summary counted them) but we
                    // don't have the list — the second query failed, or this hit
                    // fell outside the asset-lookup cap. "—" would read as
                    // "nowhere", which is the opposite of the truth.
                    <span className="text-t4" title="The asset list wasn't retrieved for this one">
                      not fetched
                    </span>
                  ) : (
                    '—'
                  )}
                </td>
                <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap text-t3">
                  {/* Absent, not epoch-zero: an unseen indicator has no span. */}
                  {hit.first_seen && hit.last_seen
                    ? `${day(hit.first_seen)} – ${day(hit.last_seen)}`
                    : '—'}
                </td>
              </>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const KIND_STYLE: Record<string, string> = {
  ip: 'border-warn/40 bg-warn-soft text-warn',
  domain: 'border-info/40 bg-info/10 text-info',
  hash: 'border-violet/40 bg-violet/10 text-violet',
};

function countByKind(indicators: Indicator[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const indicator of indicators) {
    counts.set(indicator.kind, (counts.get(indicator.kind) ?? 0) + 1);
  }
  return [...counts.entries()];
}

function day(timestamp: string): string {
  const parsed = new Date(timestamp);
  return Number.isNaN(parsed.getTime())
    ? '—'
    : parsed.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
