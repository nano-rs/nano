// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Single-indicator hunt summary (NAN-1580, summary submode). Verdict hero +
 * prevalence band + matched-fields breakdown + retention timeline + the
 * entities the indicator landed on (click to pivot to events).
 */

import { Sparkles, Info, Box, ArrowUpRight } from 'lucide-react';
import type { RetroIndicator } from '@/lib/api/types';
import {
  RE_VERDICT,
  TypeChip,
  VerdictBadge,
  PrevalenceBand,
  TimelineStrip,
  reNum,
  reFmtD,
  reAge,
} from './shared';

function StatTile({ label, value, sub, accent }: { label: string; value: string; sub: string; accent?: string }) {
  return (
    <div className="rounded-lg border border-border p-3" style={{ background: 'var(--color-panel)' }}>
      <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-fg-3 font-semibold mb-1.5">{label}</div>
      <div className="font-mono text-[19px] font-semibold tabular-nums leading-none" style={{ color: accent || 'var(--color-fg)' }}>
        {value}
      </div>
      <div className="font-mono text-[10px] text-fg-4 mt-1.5">{sub}</div>
    </div>
  );
}

export function RetroSummary({
  indicator: d,
  totalHosts,
  onPivot,
  onOpenIndicator,
}: {
  indicator: RetroIndicator;
  totalHosts: number;
  /** Pivot to events for a top-entity row. */
  onPivot: (value: string) => void;
  /** Pivot to the raw events for the indicator itself (the observable). */
  onOpenIndicator?: (value: string) => void;
}) {
  const total = d.total_hosts || totalHosts || 0;
  const pct = total > 0 ? (d.distinct_hosts / total) * 100 : 0;
  const v = d.verdict;
  const vc = RE_VERDICT[v];
  const maxF = Math.max(1, ...d.matched_fields.map((f) => f[1]));
  const maxE = Math.max(1, ...d.top_entities.map((e) => e.hits));

  return (
    <div className="flex-1 min-h-0 overflow-auto">
      <div className="p-4">
        {/* hero */}
        <div className="grid gap-3" style={{ gridTemplateColumns: '1.15fr 1fr' }}>
          {/* indicator */}
          <div className="rounded-lg border border-border p-4 flex flex-col" style={{ background: 'var(--color-panel)' }}>
            <div className="flex items-center gap-2 mb-2">
              <TypeChip t={d.type} />
              <span className="font-mono text-[10px] text-fg-3 normal-case tracking-normal">indicator</span>
            </div>
            <button
              type="button"
              onClick={() => onOpenIndicator?.(d.value)}
              title="Pivot to events for this indicator"
              className="text-left font-mono text-[26px] font-semibold text-fg tracking-tight leading-none mb-3 break-all hover:text-brand transition-colors cursor-pointer"
            >
              {d.value}
            </button>
            <div className="flex items-center gap-2 text-[11px] text-fg-3 font-mono flex-wrap">
              {d.source && (
                <>
                  <Sparkles className="w-[12px] h-[12px] text-brand" />
                  <span>
                    matched <span className="text-fg-2">{d.source}</span>
                  </span>
                </>
              )}
              {d.campaign && <span className="px-1.5 py-px rounded-[3px] bg-brand/10 text-brand">{d.campaign}</span>}
              {d.confidence > 0 && (
                <>
                  <span className="text-fg-4">·</span>
                  <span>
                    confidence <span className="text-fg-2 tabular-nums">{d.confidence}</span>
                  </span>
                </>
              )}
            </div>
            {/* matched fields */}
            {d.matched_fields.length > 0 && (
              <div className="mt-4 pt-3 border-t border-border">
                <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-fg-3 font-semibold mb-2">matched fields</div>
                <div className="flex flex-col gap-1.5">
                  {d.matched_fields.map(([f, n]) => (
                    <div key={f} className="grid items-center gap-2" style={{ gridTemplateColumns: '88px 1fr 56px' }}>
                      <span className="font-mono text-[11px] text-fg-2 truncate">{f}</span>
                      <div className="h-[7px] rounded-full overflow-hidden bg-fg/6">
                        <div className="h-full rounded-full" style={{ width: `${(n / maxF) * 100}%`, background: 'var(--color-brand)' }} />
                      </div>
                      <span className="font-mono text-[10.5px] text-fg tabular-nums text-right">{reNum(n)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* verdict */}
          <div className="rounded-lg border p-4 flex flex-col justify-between" style={{ background: vc.dim, borderColor: vc.bd }}>
            <div>
              <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] font-semibold mb-1" style={{ color: vc.c }}>
                verdict
              </div>
              <div className="flex items-baseline gap-2.5">
                <span className="font-mono text-[34px] font-bold tracking-tight leading-none" style={{ color: vc.c }}>
                  {vc.label}
                </span>
                <VerdictBadge v={v} size="sm" />
              </div>
              <div className="mt-2 text-[12px] text-fg-2 leading-snug">
                touched <span className="font-semibold text-fg tabular-nums">{d.distinct_hosts}</span> of {total} hosts
                <span className="font-mono text-fg-3"> · {pct.toFixed(2)}%</span>
                {v === 'rare' && ' — rare in environment, worth your time.'}
              </div>
            </div>
            <div className="mt-4">
              <PrevalenceBand hosts={d.distinct_hosts} total={total} verdict={v} />
            </div>
          </div>
        </div>

        {/* stat tiles */}
        <div className="grid grid-cols-4 gap-3 mt-3">
          <StatTile label="hits" value={reNum(d.hits)} sub="events all-time" />
          <StatTile label="distinct hosts" value={`${d.distinct_hosts} / ${total}`} sub="prevalence" accent={vc.c} />
          <StatTile label="first seen" value={reFmtD(d.first_seen)} sub={`${reAge(d.first_seen)}d ago`} accent={vc.c} />
          <StatTile label="last seen" value={reFmtD(d.last_seen)} sub={`${reAge(d.last_seen)}d ago`} />
        </div>

        {/* timeline */}
        <div className="mt-3">
          <TimelineStrip firstSeen={d.first_seen} lastSeen={d.last_seen} />
        </div>
        <div className="mt-2 flex items-start gap-2 px-1 text-[11px] text-fg-3 leading-snug">
          <Info className="w-[13px] h-[13px] mt-px shrink-0" style={{ color: vc.c }} />
          <span>
            First contact <span className="text-fg-2 font-semibold">{reAge(d.first_seen)} days ago</span>. Old first-seen + rare
            prevalence is the signature of an ongoing compromise, not a one-time blip.
          </span>
        </div>

        {/* top entities */}
        {d.top_entities.length > 0 && (
          <div className="mt-3 rounded-lg border border-border overflow-hidden">
            <div className="px-3 py-2 border-b border-border flex items-center gap-2" style={{ background: 'var(--color-panel)' }}>
              <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-fg-3 font-semibold">top entities</span>
              <span className="font-mono text-[10px] text-fg-4 normal-case">where it landed — pivot to investigate</span>
            </div>
            <div className="divide-y divide-border/60">
              {d.top_entities.map((e, i) => (
                <button
                  key={e.id}
                  type="button"
                  onClick={() => onPivot(e.id)}
                  className="group grid items-center gap-3 px-3 py-2 hover:bg-brand/5 transition-colors cursor-pointer w-full text-left"
                  style={{ gridTemplateColumns: '20px 180px 1fr 64px 120px' }}
                >
                  <span className="font-mono text-[9.5px] text-fg-4 tabular-nums text-right">{String(i + 1).padStart(2, '0')}</span>
                  <span className="flex items-center gap-1.5 min-w-0">
                    <Box className="w-[12px] h-[12px] text-fg-3 shrink-0" />
                    <span className="font-mono text-[12px] text-fg truncate">{e.id}</span>
                  </span>
                  <div className="h-[7px] rounded-full overflow-hidden bg-fg/6">
                    <div className="h-full rounded-full" style={{ width: `${(e.hits / maxE) * 100}%`, background: vc.c }} />
                  </div>
                  <span className="font-mono text-[11px] text-fg tabular-nums text-right">{reNum(e.hits)}</span>
                  <span className="flex items-center justify-end gap-1 font-mono text-[10.5px] text-fg-3 group-hover:text-brand transition-colors">
                    investigate <ArrowUpRight className="w-[11px] h-[11px]" />
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="h-6" />
      </div>
    </div>
  );
}
