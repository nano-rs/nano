// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudOverviewServiceHealth } from '@/lib/api/types';
import { CloudCard, fmtCount } from './shared';

interface ServiceHealthProps {
  services: CloudOverviewServiceHealth[];
  /** Click a service row to scope the base search by cloud_service= */
  onPivotService?: (id: string) => void;
}

export function ServiceHealth({ services, onPivotService }: ServiceHealthProps) {
  return (
    <CloudCard
      title="Service health"
      subtitle="errors · volume · 24h trend"
      accent="oklch(62% 0.18 0)"
    >
      <div className="divide-y divide-border">
        <div className="grid grid-cols-[120px_80px_80px_1fr_120px] gap-3 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/70">
          <span>Service</span>
          <span className="text-right">Events</span>
          <span className="text-right">Error %</span>
          <span>Trend</span>
          <span>Top error</span>
        </div>
        {services.map((s) => {
          const statusTone =
            s.status === 'bad'
              ? 'text-[oklch(72%_0.17_28)]'
              : s.status === 'warn'
              ? 'text-[oklch(80%_0.13_85)]'
              : 'text-muted-foreground/80';
          const max = Math.max(1, ...s.trend);
          const points =
            s.trend.length > 1
              ? s.trend
                  .map((v, i) => `${(i / (s.trend.length - 1)) * 100},${18 - (v / max) * 16}`)
                  .join(' ')
              : '';
          return (
            <button
              key={s.id}
              onClick={() => onPivotService?.(s.id)}
              disabled={!onPivotService}
              className="w-full grid grid-cols-[120px_80px_80px_1fr_120px] gap-3 px-3 py-2 items-center hover:bg-foreground/[0.03] text-left enabled:cursor-pointer enabled:hover:text-primary"
              title={onPivotService ? `Filter by cloud_service=${s.id}` : undefined}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span
                  className="w-1 h-3 rounded-sm shrink-0"
                  style={{ background: s.accent }}
                />
                <span className="font-mono text-[12px] text-foreground truncate">{s.label}</span>
              </div>
              <span className="text-right font-mono text-[11px] text-muted-foreground/80 tabular-nums">
                {fmtCount(s.events)}
              </span>
              <span className={cn('text-right font-mono text-[11px] tabular-nums', statusTone)}>
                {(s.error_rate * 100).toFixed(2)}%
                {s.delta !== 0 && (
                  <span
                    className={cn(
                      'ml-1 text-[9.5px]',
                      s.delta > 0
                        ? 'text-[oklch(72%_0.17_28)]'
                        : 'text-[oklch(72%_0.16_160)]'
                    )}
                  >
                    {s.delta > 0 ? '▲' : '▼'}
                  </span>
                )}
              </span>
              <svg viewBox="0 0 100 18" className="w-full h-[18px]" preserveAspectRatio="none">
                {points && (
                  <polyline fill="none" stroke={s.accent} strokeWidth="1.2" points={points} />
                )}
              </svg>
              <span className="font-mono text-[10.5px] text-muted-foreground/80 truncate">
                {s.top_error ?? '—'}
              </span>
            </button>
          );
        })}
        {services.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] font-mono text-muted-foreground/60">
            No service activity in this window
          </div>
        )}
      </div>
    </CloudCard>
  );
}
