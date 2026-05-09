// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudOverviewAnomaly, CloudRiskBand } from '@/lib/api/types';
import { CloudCard, cloudSevTone } from './shared';

type Filter = 'all' | CloudRiskBand;
const FILTERS: Filter[] = ['all', 'critical', 'high', 'medium', 'low'];

interface AnomalyFeedProps {
  anomalies: CloudOverviewAnomaly[];
  /** Window label from the overview header (e.g. "last 7d") — shown in the subtitle */
  windowLabel?: string;
  onOpen?: (anomaly: CloudOverviewAnomaly) => void;
}

export function AnomalyFeed({ anomalies, windowLabel, onOpen }: AnomalyFeedProps) {
  const [filter, setFilter] = useState<Filter>('all');
  const filtered = filter === 'all' ? anomalies : anomalies.filter((a) => a.severity === filter);

  return (
    <CloudCard
      title="Anomaly feed"
      subtitle={`${anomalies.length} findings · ${windowLabel ?? 'selected window'}`}
      accent="oklch(70% 0.16 55)"
      chip={
        <div className="flex items-center gap-0.5 text-[10px] font-mono">
          {FILTERS.map((k) => (
            <button
              key={k}
              onClick={() => setFilter(k)}
              className={cn(
                'px-1.5 py-0.5 rounded',
                filter === k
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
      <div className="divide-y divide-border max-h-[360px] overflow-auto">
        {filtered.map((a) => {
          const tone = cloudSevTone(a.severity);
          return (
            <button
              key={a.id}
              onClick={() => onOpen?.(a)}
              className="w-full flex items-start gap-2.5 px-3 py-2 hover:bg-foreground/[0.03] text-left"
            >
              <span className={cn('mt-1 w-1.5 h-1.5 rounded-full shrink-0', tone.dot)} />
              <span className="font-mono text-[10.5px] text-muted-foreground/80 tabular-nums w-[38px] shrink-0 mt-0.5">
                {a.at}
              </span>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={cn(
                      'text-[10px] font-mono uppercase tracking-[0.1em] px-1.5 py-0.5 rounded',
                      tone.bg,
                      tone.text
                    )}
                  >
                    {a.severity}
                  </span>
                  <span className="text-[10px] font-mono text-muted-foreground/70">{a.kind}</span>
                  <span className="text-[12px] text-foreground truncate font-medium">
                    {a.title}
                  </span>
                </div>
                {a.detail && a.detail !== '{}' && (
                  <div className="text-[11.5px] text-muted-foreground/80 mt-0.5 leading-snug">
                    {a.detail}
                  </div>
                )}
                <div className="flex items-center gap-3 mt-1 text-[10px] font-mono text-muted-foreground/70">
                  {a.principal && (
                    <span>
                      principal: <span className="text-muted-foreground/90">{a.principal}</span>
                    </span>
                  )}
                  {a.account && (
                    <span>
                      account: <span className="text-muted-foreground/90">{a.account}</span>
                    </span>
                  )}
                  {a.service && (
                    <span>
                      service: <span className="text-muted-foreground/90">{a.service}</span>
                    </span>
                  )}
                </div>
              </div>
              <ChevronRight className="w-3 h-3 text-muted-foreground/70 mt-1.5 shrink-0" />
            </button>
          );
        })}
        {filtered.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] font-mono text-muted-foreground/60">
            No anomalies match this filter
          </div>
        )}
      </div>
    </CloudCard>
  );
}
