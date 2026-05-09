// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { LateralMethodGroup, LateralSummary } from './types';
import { ChevronRight } from 'lucide-react';

interface PillProps {
  k: string;
  v: string;
  highlight?: boolean;
}

function Pill({ k, v, highlight }: PillProps) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
      <span className="text-muted-foreground/70">{k}</span>
      <span className={cn('font-mono', highlight ? 'text-primary' : 'text-foreground')}>{v}</span>
    </span>
  );
}

interface LateralTopStripProps {
  summary: LateralSummary | null;
  maxHops: number;
  methods: Set<LateralMethodGroup>;
  windowLabel: string;
  criticalOnly: boolean;
  onSetMaxHops: (n: number) => void;
  onToggleCritical: () => void;
  /** True when the backend returned a non-empty critical path. Disables the
      Critical-path toggle when no critical-band / crown node was reached. */
  hasCriticalPath?: boolean;
  /** Which dimension colors edges: method family (auth/network/process) or
      severity band (critical/high/medium/low). */
  edgeColor?: 'method' | 'severity';
  onSetEdgeColor?: (m: 'method' | 'severity') => void;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

export function LateralTopStrip({
  summary,
  maxHops,
  methods,
  windowLabel,
  criticalOnly,
  onSetMaxHops,
  onToggleCritical,
  hasCriticalPath = true,
  edgeColor = 'method',
  onSetEdgeColor,
  fieldsCount,
  onExpandFields,
}: LateralTopStripProps) {
  const seedId = summary?.seed.id ?? '—';
  const methodsLabel = methods.size === 3 ? 'all' : [...methods].join('+');

  return (
    <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold whitespace-nowrap shrink-0 overflow-x-auto">
      <span className="flex items-center gap-1.5 shrink-0">
        <svg
          viewBox="0 0 24 24"
          className="w-[12px] h-[12px] text-primary"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
        >
          <circle cx="6" cy="6" r="2.2" />
          <circle cx="18" cy="18" r="2.2" />
          <circle cx="18" cy="6" r="2.2" />
          <path d="M8 6h8M18 8v8M8 7.5l10 10" />
        </svg>
        Lateral · <span className="normal-case tracking-normal text-foreground">movement graph</span>
      </span>
      <Pill k="seed" v={seedId} highlight />
      <Pill k="hops" v={`≤ ${maxHops}`} />
      <Pill k="methods" v={methodsLabel} />
      <Pill k="window" v={windowLabel} />
      {criticalOnly && <Pill k="filter" v="critical-path" highlight />}
      {summary?.truncated && (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] normal-case tracking-normal font-semibold whitespace-nowrap"
          style={{
            borderColor: 'oklch(76% 0.15 60 / 0.5)',
            background: 'oklch(76% 0.15 60 / 0.1)',
            color: 'oklch(80% 0.15 60)',
          }}
          title={`Graph pruned to keep the renderer fast. Seed and critical-path nodes always preserved; other nodes ranked by band, role, then event count.`}
        >
          <span className="text-[inherit]/70">truncated</span>
          <span className="font-mono">
            {summary.nodes} / {summary.originalNodes}
          </span>
        </span>
      )}

      {fieldsCount !== undefined && onExpandFields && (
        <button
          onClick={onExpandFields}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal text-muted-foreground/80 hover:text-foreground hover:border-foreground/40"
          title="Expand fields panel"
        >
          <ChevronRight className="w-3 h-3 -rotate-180" strokeWidth={1.5} />
          fields
          <span className="font-mono text-foreground/80">{fieldsCount}</span>
        </button>
      )}

      <span className="flex-1" />

      <span className="flex items-center gap-1.5 normal-case tracking-normal">
        <span className="text-muted-foreground/70">max hops</span>
        {[2, 3, 4].map((n) => (
          <button
            key={n}
            onClick={() => onSetMaxHops(n)}
            className={cn(
              'w-6 h-5 rounded-sm border font-mono text-[10px]',
              maxHops === n
                ? 'border-primary/60 bg-primary/10 text-primary'
                : 'border-border text-muted-foreground/80 hover:text-foreground hover:border-foreground/40'
            )}
          >
            {n}
          </button>
        ))}
      </span>

      {onSetEdgeColor && (
        <span aria-hidden className="h-4 w-px bg-border/80 shrink-0" />
      )}

      {onSetEdgeColor && (
        <span className="flex items-center gap-1 normal-case tracking-normal">
          <span className="text-muted-foreground/70">color</span>
          {(['severity', 'method'] as const).map((m) => (
            <button
              key={m}
              onClick={() => onSetEdgeColor(m)}
              className={cn(
                'h-5 px-1.5 rounded-sm border font-mono text-[10px] capitalize',
                edgeColor === m
                  ? 'border-primary/60 bg-primary/10 text-primary'
                  : 'border-border text-muted-foreground/80 hover:text-foreground hover:border-foreground/40'
              )}
            >
              {m}
            </button>
          ))}
        </span>
      )}

      <span aria-hidden className="h-4 w-px bg-border/80 shrink-0" />

      <button
        onClick={onToggleCritical}
        disabled={!hasCriticalPath}
        title={
          !hasCriticalPath
            ? 'No critical-band or crown asset reached from the seed'
            : undefined
        }
        className={cn(
          'px-2 py-1 rounded-md border font-mono text-[10px] normal-case tracking-normal flex items-center gap-1.5',
          !hasCriticalPath
            ? 'border-border/60 text-muted-foreground/40 cursor-not-allowed'
            : criticalOnly
            ? 'border-[oklch(68%_0.18_28/0.6)] bg-[oklch(68%_0.18_28/0.12)] text-[oklch(72%_0.18_28)]'
            : 'border-border text-muted-foreground/80 hover:text-foreground hover:border-foreground/40'
        )}
      >
        <svg
          viewBox="0 0 16 16"
          className="w-3 h-3"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
        >
          <path d="M3 11l4-8 2 5 4-2-2 5 4 2-5 2-2 -4-3 4-2-4" />
        </svg>
        Critical path
      </button>
    </div>
  );
}
