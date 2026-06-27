// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Campaign list (NAN-1580, list submode). One row per matched indicator,
 * rarest-first, with the indicators that produced no hits collapsed by default.
 * Server-side pagination via "load more". Click a row to pivot to its summary.
 */

import { useState } from 'react';
import { ArrowUpRight, ChevronDown, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { RetroListRow } from '@/lib/api/types';
import { RE_VERDICT, TypeChip, VerdictBadge, rePrevPos, reNum, reFmtD, reAge } from './shared';

function SummaryStat({ n, label, of, accent, muted }: { n: number; label: string; of?: number; accent?: string; muted?: boolean }) {
  return (
    <div className="flex items-baseline gap-1.5">
      <span
        className="font-mono text-[20px] font-bold tabular-nums leading-none"
        style={{ color: muted ? 'var(--color-fg-3)' : accent || 'var(--color-fg)' }}
      >
        {n}
      </span>
      {of != null && <span className="font-mono text-[11px] text-fg-4">/ {of}</span>}
      <span className="text-[10.5px] text-fg-3 uppercase tracking-[0.1em] font-mono font-semibold ml-1">{label}</span>
    </div>
  );
}

function ReTh({ children, right, w }: { children?: React.ReactNode; left?: boolean; right?: boolean; w?: string }) {
  return (
    <th className={cn('py-2 px-3 font-semibold uppercase tracking-[0.12em] text-[9.5px]', right ? 'text-right' : 'text-left', w)}>
      {children}
    </th>
  );
}

export function RetroCampaign({
  rows,
  totalIndicators,
  noHits,
  totalHosts,
  hasMore,
  loadingMore,
  onLoadMore,
  onOpenIndicator,
}: {
  rows: RetroListRow[];
  totalIndicators: number;
  noHits: string[];
  totalHosts: number;
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
  onOpenIndicator: (value: string) => void;
}) {
  const [showNo, setShowNo] = useState(false);
  const noHitsCount = noHits.length;
  const rareN = rows.filter((r) => r.verdict === 'rare').length;

  return (
    <div className="flex-1 min-h-0 overflow-auto">
      {/* matchset summary strip */}
      <div className="px-4 py-3 border-b border-border flex items-center gap-4" style={{ background: 'var(--color-panel)' }}>
        <SummaryStat n={rows.length} label="indicators hit" of={totalIndicators} />
        <span className="w-px h-7 bg-border" />
        <SummaryStat n={rareN} label="rare in env" accent="oklch(64% 0.19 25)" />
        <span className="w-px h-7 bg-border" />
        <SummaryStat n={noHitsCount} label="no hits · collapsed" muted />
        <span className="flex-1" />
        <span className="font-mono text-[10.5px] text-fg-3 flex items-center gap-1.5">
          <ArrowUpRight className="w-[11px] h-[11px] rotate-90" /> sorted rarest-first
        </span>
      </div>

      <table className="w-full font-mono text-[11.5px] border-collapse">
        <thead className="sticky top-0 z-10" style={{ background: 'var(--color-panel)' }}>
          <tr className="border-b border-border text-fg-3">
            <ReTh w="w-[30%]" left>
              indicator
            </ReTh>
            <ReTh>verdict</ReTh>
            <ReTh right>hits</ReTh>
            <ReTh>prevalence</ReTh>
            <ReTh left>first seen</ReTh>
            <ReTh left>last seen</ReTh>
            <ReTh left>field</ReTh>
            <ReTh></ReTh>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const total = r.total_hosts || totalHosts || 0;
            const pct = total > 0 ? (r.hosts / total) * 100 : 0;
            const vc = RE_VERDICT[r.verdict];
            return (
              <tr
                key={`${r.value}:${r.field}`}
                onClick={() => onOpenIndicator(r.value)}
                className="group border-b border-border/50 cursor-pointer hover:bg-brand/5 transition-colors"
              >
                <td className="py-2 px-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className="w-[3px] h-[22px] rounded-full shrink-0"
                      style={{ background: r.verdict === 'common' ? 'transparent' : vc.c }}
                    />
                    <TypeChip t={r.type} />
                    <span className="text-fg truncate">{r.value}</span>
                  </div>
                </td>
                <td className="py-2 px-3">
                  <VerdictBadge v={r.verdict} size="sm" />
                </td>
                <td className="py-2 px-3 text-right text-fg tabular-nums font-semibold">{reNum(r.hits)}</td>
                <td className="py-2 px-3">
                  <div className="flex items-center gap-2">
                    <span className="tabular-nums text-fg-2 w-[58px] shrink-0">
                      {r.hosts} / {total}
                    </span>
                    <div className="h-[5px] flex-1 rounded-full overflow-hidden bg-fg/6 min-w-[40px]">
                      <div className="h-full rounded-full" style={{ width: `${Math.max(3, rePrevPos(pct) * 100)}%`, background: vc.c }} />
                    </div>
                  </div>
                </td>
                <td className="py-2 px-3 text-fg-2 tabular-nums whitespace-nowrap">
                  {reFmtD(r.first_seen)} <span className="text-fg-4">· {reAge(r.first_seen)}d</span>
                </td>
                <td className="py-2 px-3 text-fg-2 tabular-nums whitespace-nowrap">{reFmtD(r.last_seen)}</td>
                <td className="py-2 px-3 text-fg-3">{r.field}</td>
                <td className="py-2 px-3 text-right">
                  <span className="inline-flex items-center gap-1 text-fg-4 group-hover:text-brand transition-colors">
                    <ArrowUpRight className="w-[12px] h-[12px]" />
                  </span>
                </td>
              </tr>
            );
          })}

          {/* collapsed no-hits */}
          {noHitsCount > 0 && (
            <>
              <tr className="border-b border-border/50">
                <td colSpan={8} className="py-0">
                  <button
                    onClick={() => setShowNo((s) => !s)}
                    className="w-full flex items-center gap-2 px-3 py-2 text-fg-3 hover:text-fg hover:bg-fg/3 transition-colors text-left"
                  >
                    <ChevronDown className={cn('w-[12px] h-[12px] transition-transform', showNo && 'rotate-180')} />
                    <span className="text-[11px]">{noHitsCount} indicators · no hits in retention window</span>
                    <span className="text-fg-4 text-[10.5px] normal-case">— clean, collapsed by default</span>
                  </button>
                </td>
              </tr>
              {showNo && (
                <tr>
                  <td colSpan={8} className="px-3 py-2.5" style={{ background: 'var(--color-bg)' }}>
                    <div className="flex flex-wrap gap-1.5">
                      {noHits.map((x) => (
                        <span
                          key={x}
                          className="px-1.5 py-0.5 rounded-[3px] bg-fg/5 text-fg-4 text-[10.5px] line-through decoration-fg-4/40"
                        >
                          {x}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              )}
            </>
          )}
        </tbody>
      </table>

      {hasMore && (
        <div className="flex justify-center py-4">
          <button
            type="button"
            onClick={onLoadMore}
            disabled={loadingMore}
            className="inline-flex items-center gap-1.5 h-8 px-3 rounded-md border border-border bg-fg/[0.02] text-fg-2 hover:text-fg hover:border-border-2 font-mono text-[11px] transition-colors disabled:opacity-60"
          >
            {loadingMore && <Loader2 className="w-[12px] h-[12px] animate-spin" />}
            load more indicators
          </button>
        </div>
      )}
      <div className="h-4" />
    </div>
  );
}
