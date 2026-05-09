// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react';
import { cn } from '@/lib/utils';
import { LATERAL_METHODS } from './helpers';
import type { LateralEdge, LateralMethodGroup } from './types';

interface LateralLegendProps {
  methods: Set<LateralMethodGroup>;
  edges: LateralEdge[];
  onToggleMethod: (id: LateralMethodGroup) => void;
}

export function LateralLegend({ methods, edges, onToggleMethod }: LateralLegendProps) {
  const counts = useMemo(() => {
    const c: Record<LateralMethodGroup, number> = { auth: 0, network: 0, process: 0 };
    for (const e of edges) {
      if (e.method.startsWith('auth-')) c.auth++;
      else if (e.method.startsWith('network-')) c.network++;
      else if (e.method.startsWith('process-')) c.process++;
    }
    return c;
  }, [edges]);

  return (
    <div className="px-3 py-2 border-t border-border flex items-center gap-2 shrink-0 bg-background/40 flex-wrap">
      <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-muted-foreground/70 shrink-0">
        methods
      </span>
      {LATERAL_METHODS.map((m) => {
        const active = methods.has(m.id);
        return (
          <button
            key={m.id}
            onClick={() => onToggleMethod(m.id)}
            className={cn(
              'flex items-center gap-1.5 px-2 py-1 rounded-md border font-mono text-[10.5px] transition-colors',
              active
                ? 'border-foreground/40 bg-foreground/5 text-foreground'
                : 'border-border bg-foreground/[0.02] text-muted-foreground/80 hover:text-foreground hover:border-foreground/40 opacity-60'
            )}
          >
            <span
              className="w-2 h-2 rounded-sm"
              style={{
                background: active ? m.color : 'transparent',
                border: `1px solid ${m.color}`,
              }}
            />
            <span>{m.label}</span>
            <span className="text-muted-foreground/60 normal-case">· {m.sub}</span>
            <span className="text-muted-foreground/60 tabular-nums">· {counts[m.id]}</span>
          </button>
        );
      })}
      <span className="flex-1" />
      <span className="flex items-center gap-3 font-mono text-[10px] text-muted-foreground/70">
        <span className="flex items-center gap-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: 'oklch(68% 0.18 28)' }}
          />
          critical
        </span>
        <span className="flex items-center gap-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: 'oklch(76% 0.15 60)' }}
          />
          high
        </span>
        <span className="flex items-center gap-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: 'oklch(78% 0.14 85)' }}
          />
          medium
        </span>
        <span className="flex items-center gap-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: 'oklch(70% 0.08 220)' }}
          />
          low
        </span>
      </span>
    </div>
  );
}
