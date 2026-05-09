// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import { User, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudOverviewPrincipal } from '@/lib/api/types';
import { CloudCard, cloudSevTone, fmtCount } from './shared';

type Sort = 'risk' | 'delta' | 'events';

interface RiskyPrincipalsProps {
  principals: CloudOverviewPrincipal[];
  onPick?: (principal: CloudOverviewPrincipal) => void;
}

export function RiskyPrincipals({ principals, onPick }: RiskyPrincipalsProps) {
  const [sort, setSort] = useState<Sort>('risk');
  const sorted = useMemo(() => {
    const s = [...principals];
    if (sort === 'risk') s.sort((a, b) => b.risk - a.risk);
    else if (sort === 'delta') s.sort((a, b) => b.delta - a.delta);
    else s.sort((a, b) => b.events_24h - a.events_24h);
    return s;
  }, [principals, sort]);

  return (
    <CloudCard
      title="Top risky principals"
      subtitle={`${principals.length} ranked`}
      accent="oklch(62% 0.18 28)"
      chip={
        <div className="flex items-center gap-0.5 text-[10px] font-mono">
          {(['risk', 'delta', 'events'] as const).map((k) => (
            <button
              key={k}
              onClick={() => setSort(k)}
              className={cn(
                'px-1.5 py-0.5 rounded',
                sort === k
                  ? 'bg-foreground/10 text-foreground'
                  : 'text-muted-foreground/70 hover:text-muted-foreground'
              )}
            >
              {k}
            </button>
          ))}
        </div>
      }
    >
      <div className="divide-y divide-border">
        <div className="grid grid-cols-[1fr_80px_60px_80px_100px_72px] gap-2 px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/70">
          <span>Principal</span>
          <span className="text-right">Risk</span>
          <span className="text-right">Δ</span>
          <span className="text-right">Events</span>
          <span>Reasons</span>
          <span className="text-right">24h</span>
        </div>
        {sorted.map((p) => {
          const tone = cloudSevTone(p.band);
          const max = Math.max(1, ...p.sparkline);
          const strokeColor =
            p.band === 'critical'
              ? 'oklch(68% 0.18 28)'
              : p.band === 'high'
              ? 'oklch(76% 0.15 60)'
              : p.band === 'medium'
              ? 'oklch(78% 0.14 85)'
              : 'oklch(70% 0.08 220)';
          const points =
            p.sparkline.length > 1
              ? p.sparkline
                  .map((v, i) => `${(i / (p.sparkline.length - 1)) * 48},${16 - (v / max) * 14}`)
                  .join(' ')
              : '';
          return (
            <button
              key={p.id}
              onClick={() => onPick?.(p)}
              className="w-full grid grid-cols-[1fr_80px_60px_80px_100px_72px] gap-2 px-3 py-2 items-center hover:bg-foreground/[0.03] text-left"
            >
              <div className="min-w-0 flex items-center gap-2">
                <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', tone.dot)} />
                {p.type === 'role' ? (
                  <Shield className="w-3 h-3 text-muted-foreground/70 shrink-0" />
                ) : (
                  <User className="w-3 h-3 text-muted-foreground/70 shrink-0" />
                )}
                <span className="font-mono text-[12px] text-foreground truncate">{p.id}</span>
                <span className="text-[10px] font-mono text-muted-foreground/70 truncate">
                  · {p.account}
                </span>
              </div>
              <span
                className={cn(
                  'text-right font-mono tabular-nums text-[13px] font-semibold',
                  tone.text
                )}
              >
                {p.risk}
              </span>
              <span
                className={cn(
                  'text-right font-mono text-[11px]',
                  p.delta > 0
                    ? 'text-[oklch(72%_0.17_28)]'
                    : p.delta < 0
                    ? 'text-[oklch(72%_0.16_160)]'
                    : 'text-muted-foreground/70'
                )}
              >
                {p.delta > 0 ? '+' : ''}
                {p.delta}
              </span>
              <span className="text-right font-mono text-[11px] text-muted-foreground/80 tabular-nums">
                {fmtCount(p.events_24h)}
              </span>
              <span className="flex gap-1 min-w-0 overflow-hidden">
                {p.reasons.slice(0, 2).map((r) => (
                  <span
                    key={r}
                    className={cn(
                      'text-[9.5px] font-mono px-1 py-0.5 rounded truncate',
                      tone.bg,
                      tone.text
                    )}
                  >
                    {r}
                  </span>
                ))}
                {p.reasons.length > 2 && (
                  <span className="text-[9.5px] text-muted-foreground/70">
                    +{p.reasons.length - 2}
                  </span>
                )}
              </span>
              <svg viewBox="0 0 48 16" className="w-[72px] h-[16px] ml-auto" preserveAspectRatio="none">
                {points && (
                  <polyline fill="none" stroke={strokeColor} strokeWidth="1.2" points={points} />
                )}
              </svg>
            </button>
          );
        })}
        {sorted.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] font-mono text-muted-foreground/60">
            No risky principals in this window
          </div>
        )}
      </div>
    </CloudCard>
  );
}
