// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import type { CloudOverviewHeader as CloudOverviewHeaderData } from '@/lib/api/types';
import { CloudFact, CloudRiskGauge, cloudSevTone, fmtCount, postureBandForScore } from './shared';

interface CloudOverviewHeaderProps {
  data: CloudOverviewHeaderData;
  /** The full executed query, echoed in the bottom bar (e.g. "| cloud provider=aws") */
  query: string;
}

export function CloudOverviewHeader({ data, query }: CloudOverviewHeaderProps) {
  const band = postureBandForScore(data.posture_score);
  const tone = cloudSevTone(band);
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="p-4">
        <div className="flex items-start gap-5">
          <div className="flex items-start gap-3 min-w-0 flex-1">
            <div className="w-12 h-12 rounded-lg bg-gradient-to-br from-[oklch(68%_0.14_240/0.2)] to-[oklch(68%_0.14_240/0.05)] border border-[oklch(68%_0.14_240/0.35)] flex items-center justify-center shrink-0">
              <svg viewBox="0 0 24 24" className="w-6 h-6 text-[oklch(72%_0.14_240)]" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M3 21V9l9-6 9 6v12" />
                <path d="M9 21v-8h6v8" />
              </svg>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-[20px] font-semibold text-foreground tracking-tight">{data.org}</h1>
                <span className="text-[11px] font-mono text-muted-foreground/70">{data.org_id}</span>
                <span className="text-[10.5px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 text-muted-foreground/70 uppercase tracking-[0.1em]">
                  org
                </span>
                <span className="text-[11px] text-muted-foreground/70">· {data.window_label}</span>
              </div>
              <div className="grid grid-cols-5 gap-x-5 gap-y-2 mt-3 text-[12px]">
                <CloudFact
                  k="Accounts"
                  v={<span className="tabular-nums">{data.accounts}</span>}
                  sub={data.providers.map((p) => p.label).join(' · ')}
                />
                <CloudFact
                  k="Principals"
                  v={<span className="tabular-nums">{data.principals}</span>}
                  sub="iam users + roles"
                />
                <CloudFact
                  k="Regions"
                  v={<span className="tabular-nums">{data.regions}</span>}
                />
                <CloudFact
                  k="Events"
                  v={<span className="tabular-nums">{fmtCount(data.events_total)}</span>}
                  sub={`${fmtCount(data.events_failed)} failed · ${fmtCount(data.events_denied)} denied`}
                />
                <CloudFact
                  k="Open alerts"
                  v={
                    <span className="flex items-baseline gap-2 font-mono">
                      <span className="text-[oklch(72%_0.17_28)] tabular-nums">{data.open_alerts.critical}</span>
                      <span className="text-muted-foreground/50 text-[9px]">crit</span>
                      <span className="text-[oklch(78%_0.14_60)] tabular-nums">{data.open_alerts.high}</span>
                      <span className="text-muted-foreground/50 text-[9px]">high</span>
                      <span className="text-[oklch(80%_0.13_85)] tabular-nums">{data.open_alerts.medium}</span>
                      <span className="text-muted-foreground/50 text-[9px]">med</span>
                    </span>
                  }
                />
              </div>
            </div>
          </div>

          {/* Posture score */}
          <div
            className={cn(
              'rounded-lg border px-3 py-2.5 flex items-center gap-3 shrink-0 w-[260px]',
              tone.border,
              tone.bg
            )}
          >
            <CloudRiskGauge score={data.posture_score} band={band} />
            <div className="flex-1 min-w-0">
              <div className={cn('text-[10px] font-mono uppercase tracking-[0.12em]', tone.text)}>
                Posture · {band}
              </div>
              <div className="flex items-baseline gap-1.5 mt-0.5">
                <span className={cn('text-[20px] font-semibold tabular-nums', tone.text)}>
                  {data.posture_score}
                </span>
                <span className="text-[10px] text-muted-foreground/70">/ 100</span>
                <span
                  className={cn(
                    'text-[10.5px] font-mono ml-1',
                    data.posture_delta > 0
                      ? 'text-[oklch(72%_0.17_28)]'
                      : data.posture_delta < 0
                      ? 'text-[oklch(72%_0.16_160)]'
                      : 'text-muted-foreground/70'
                  )}
                >
                  {data.posture_delta > 0 ? '▲' : data.posture_delta < 0 ? '▼' : '·'}{' '}
                  {Math.abs(data.posture_delta)} ({data.window_label})
                </span>
              </div>
              {data.posture_reason && (
                <div className="text-[10.5px] text-muted-foreground/70 mt-0.5 truncate">
                  {data.posture_reason}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Provider breakdown bar */}
      <div className="px-4 py-2 border-t border-border bg-foreground/[0.02] flex items-center gap-4 text-[11px] font-mono">
        <span className="text-muted-foreground/70 uppercase tracking-[0.12em] text-[10px] font-semibold">
          providers
        </span>
        {data.providers.map((p) => {
          const pct = data.events_total > 0 ? ((p.events / data.events_total) * 100).toFixed(1) : '0.0';
          const dot =
            p.id === 'aws'
              ? 'oklch(70% 0.15 55)'
              : p.id === 'gcp'
              ? 'oklch(68% 0.14 240)'
              : 'oklch(62% 0.16 270)';
          return (
            <div key={p.id} className="flex items-center gap-2">
              <span className="inline-block w-1.5 h-1.5 rounded-full" style={{ background: dot }} />
              <span className="text-foreground">{p.label}</span>
              <span className="text-muted-foreground/70 tabular-nums">{fmtCount(p.events)}</span>
              <span className="text-muted-foreground/50">{pct}%</span>
            </div>
          );
        })}
        <span className="flex-1" />
        <span className="text-muted-foreground/70">
          query: <span className="text-foreground">{query}</span>
        </span>
      </div>
    </div>
  );
}
