// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Pivot rollup (NAN-1580, pivot submode). One row per asset / user, oldest
 * first-seen first (triage order). Rows exposed > 90 days carry a red rail.
 * Server-side pagination via "load more". Click a row to pivot to events.
 */

import { ArrowUpRight, Box, User, Users, Info, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { RetroAxis, RetroPivotRow } from '@/lib/api/types';
import { RE_VERDICT, VerdictBadge, reFmtD, reAge } from './shared';

function ReTh({ children, right, w }: { children?: React.ReactNode; left?: boolean; right?: boolean; w?: string }) {
  return (
    <th className={cn('py-2 px-3 font-semibold uppercase tracking-[0.12em] text-[9.5px]', right ? 'text-right' : 'text-left', w)}>
      {children}
    </th>
  );
}

export function RetroPivot({
  axis,
  rows,
  hasMore,
  loadingMore,
  onLoadMore,
  onOpenEntity,
}: {
  axis: RetroAxis;
  rows: RetroPivotRow[];
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
  onOpenEntity: (row: RetroPivotRow) => void;
}) {
  const isUser = axis === 'user';

  return (
    <div className="flex-1 min-h-0 overflow-auto">
      <div className="px-4 py-3 border-b border-border flex items-center gap-3" style={{ background: 'var(--color-panel)' }}>
        <span className="flex items-center gap-1.5 font-mono text-[11px] text-fg-2">
          {isUser ? <Users className="w-[13px] h-[13px] text-brand" /> : <Box className="w-[13px] h-[13px] text-brand" />}
          one row per {isUser ? 'account' : 'asset'} — resolved to {isUser ? 'identity' : 'asset'} model
        </span>
        <span className="flex-1" />
        <span className="font-mono text-[10.5px] flex items-center gap-1.5" style={{ color: 'oklch(64% 0.19 25)' }}>
          <ArrowUpRight className="w-[11px] h-[11px] rotate-180" /> oldest first-seen first — triage order
        </span>
      </div>

      <table className="w-full font-mono text-[11.5px] border-collapse">
        <thead className="sticky top-0 z-10" style={{ background: 'var(--color-panel)' }}>
          <tr className="border-b border-border text-fg-3">
            <ReTh left w="w-[26%]">
              {isUser ? 'user' : 'asset'}
            </ReTh>
            <ReTh right>iocs</ReTh>
            <ReTh left w="w-[28%]">
              indicators
            </ReTh>
            <ReTh>worst verdict</ReTh>
            <ReTh left>first seen</ReTh>
            <ReTh left>last seen</ReTh>
            <ReTh></ReTh>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const vc = RE_VERDICT[r.worst_verdict];
            const age = reAge(r.first_seen);
            const old = age > 90;
            const inds = r.indicators ?? [];
            return (
              <tr
                key={r.id}
                onClick={() => onOpenEntity(r)}
                className="group border-b border-border/50 cursor-pointer hover:bg-brand/5 transition-colors"
              >
                <td className="py-2.5 px-3">
                  <div className="flex items-center gap-2 min-w-0">
                    <span
                      className="w-[3px] h-[26px] rounded-full shrink-0"
                      style={{ background: old ? 'oklch(64% 0.19 25)' : r.worst_verdict === 'common' ? 'transparent' : vc.c }}
                    />
                    {isUser ? (
                      <User className="w-[13px] h-[13px] text-fg-3 shrink-0" />
                    ) : (
                      <Box className="w-[13px] h-[13px] text-fg-3 shrink-0" />
                    )}
                    <div className="min-w-0">
                      <div className="text-fg truncate">{r.name}</div>
                      {r.sub && <div className="text-fg-4 text-[10px] truncate normal-case">{r.sub}</div>}
                    </div>
                  </div>
                </td>
                <td className="py-2.5 px-3 text-right text-fg tabular-nums font-semibold">{r.iocs}</td>
                <td className="py-2.5 px-3">
                  <div className="flex flex-wrap gap-1">
                    {inds.slice(0, 3).map((x) => (
                      <span key={x} className="px-1.5 py-px rounded-[3px] bg-fg/6 text-fg-2 text-[10px] truncate max-w-[120px]">
                        {x}
                      </span>
                    ))}
                    {inds.length > 3 && <span className="px-1 py-px text-fg-4 text-[10px]">+{inds.length - 3}</span>}
                  </div>
                </td>
                <td className="py-2.5 px-3">
                  <VerdictBadge v={r.worst_verdict} size="sm" />
                </td>
                <td className="py-2.5 px-3 whitespace-nowrap">
                  <span className="text-fg-2 tabular-nums">{reFmtD(r.first_seen)}</span>
                  <span
                    className={cn('ml-1.5 tabular-nums', old ? 'font-semibold' : 'text-fg-4')}
                    style={old ? { color: 'oklch(64% 0.19 25)' } : undefined}
                  >
                    · {age}d
                  </span>
                </td>
                <td className="py-2.5 px-3 text-fg-2 tabular-nums whitespace-nowrap">{reFmtD(r.last_seen)}</td>
                <td className="py-2.5 px-3 text-right">
                  <span className="inline-flex items-center gap-1 text-fg-4 group-hover:text-brand transition-colors text-[10.5px] normal-case">
                    open {isUser ? 'user' : 'asset'} <ArrowUpRight className="w-[11px] h-[11px]" />
                  </span>
                </td>
              </tr>
            );
          })}
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
            load more {isUser ? 'users' : 'assets'}
          </button>
        </div>
      )}

      <div className="px-4 py-3 flex items-start gap-2 text-[11px] text-fg-3 leading-snug">
        <Info className="w-[13px] h-[13px] mt-px shrink-0" style={{ color: 'oklch(64% 0.19 25)' }} />
        <span>
          Sorted oldest-first: rows with a red rail have been exposed <span className="text-fg-2 font-semibold">over 90 days</span> —
          ongoing compromise, top of the response list.
        </span>
      </div>
    </div>
  );
}
