// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-483 — per-rule Matches hero (title + analytics strip).
// Ports design-ref/shadcn/matches-hero.jsx. Numeric tiles that require data we
// don't yet expose from the API render a visible "STUB" marker so they surface
// in review — see PR body for the list of unwired pieces.

import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowLeft,
  Pencil,
  Pause,
  Play,
  Copy,
  Bell,
  Activity,
  Clock,
  Users,
  ArrowDownRight,
  ArrowUpRight,
  Minus,
} from 'lucide-react';
import type { DetectionRule } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useDetectionMatches, useRuleDispositionStats } from '@/hooks/use-api';
import { parseUTCTimestamp } from '@/lib/date-utils';
import { SEV_META, normalizeSeverity, primaryTactic, primaryTechnique, meanTimeToDetect, type MatchView } from './helpers';
import { LatencyPill } from './LatencyPill';

// 28-day heat strip — identical algorithm to design-ref/matches-hero.jsx.
function HeatStrip28({ data, height = 18 }: { data: number[]; height?: number }) {
  const max = Math.max(...data, 1);
  return (
    <div className="flex items-center gap-[2px]">
      {data.map((v, i) => {
        const intensity = v === 0 ? 0 : 0.28 + (v / max) * 0.72;
        const today = i === data.length - 1;
        return (
          <div
            key={i}
            title={`${27 - i}d ago · ${v.toLocaleString()} matches`}
            className="w-[6px] rounded-[1px]"
            style={{
              height: `${height}px`,
              background:
                v === 0
                  ? 'color-mix(in srgb, var(--foreground) 5%, transparent)'
                  : `color-mix(in srgb, var(--primary) ${intensity * 100}%, transparent)`,
              outline: today && v > 0 ? '1px solid var(--primary)' : 'none',
              outlineOffset: '0.5px',
            }}
          />
        );
      })}
    </div>
  );
}

// 24-hour bar strip — same heat algorithm as HeatStrip28 but oriented as a
// histogram (bar height) rather than fixed-height tiles, since hourly density
// reads better with vertical bars. Today's bars highlight the current hour.
function HourlyStrip({
  data,
  height = 36,
  currentHour,
}: {
  data: number[];
  height?: number;
  currentHour: number;
}) {
  const max = Math.max(...data, 1);
  return (
    <div className="flex items-end gap-[2px]" style={{ height }}>
      {data.map((v, i) => {
        const intensity = v === 0 ? 0 : 0.28 + (v / max) * 0.72;
        const heightPct = v === 0 ? 10 : 10 + (v / max) * 90;
        const isCurrent = i === currentHour;
        return (
          <div
            key={i}
            title={`${String(i).padStart(2, '0')}:00 · ${v.toLocaleString()} matches`}
            className="w-[4px] rounded-[1px]"
            style={{
              height: `${heightPct}%`,
              background:
                v === 0
                  ? 'color-mix(in srgb, var(--foreground) 8%, transparent)'
                  : `color-mix(in srgb, var(--primary) ${intensity * 100}%, transparent)`,
              outline: isCurrent && v > 0 ? '1px solid var(--primary)' : 'none',
              outlineOffset: '0.5px',
            }}
          />
        );
      })}
    </div>
  );
}

interface MatchesHeroProps {
  rule: DetectionRule;
  views: MatchView[];
  totalMatches: number;
  alertsGenerated: number;
  activity28d: number[];
  onTogglePause: () => void;
  onToggleAlerting: () => void;
  canEdit: boolean;
}

export function MatchesHero({
  rule,
  views,
  totalMatches,
  alertsGenerated,
  activity28d,
  onTogglePause,
  onToggleAlerting,
  canEdit,
}: MatchesHeroProps) {
  const sev = SEV_META[normalizeSeverity(rule.severity)];
  const tactic = primaryTactic(rule);
  const technique = primaryTechnique(rule);

  // Today's hour-by-hour strip — query matches between [00:00 UTC today, now]
  // and bucket client-side. We round `now` down to the minute so the React
  // Query cache key stays stable across re-renders within the same minute.
  const todayWindow = useMemo(() => {
    const now = new Date();
    now.setUTCSeconds(0, 0);
    const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
    return { start_time: start.toISOString(), end_time: now.toISOString(), limit: 10000 };
  }, []);
  const { data: todayMatches } = useDetectionMatches(rule.id, todayWindow);
  const currentHour = useMemo(() => new Date().getUTCHours(), []);
  const hourly24 = useMemo<number[]>(() => {
    const out = Array(24).fill(0);
    const list = todayMatches?.matches || [];
    for (const m of list) {
      try {
        const d = parseUTCTimestamp(m.detected_at);
        const h = d.getUTCHours();
        if (h >= 0 && h < 24) out[h] += 1;
      } catch {
        // skip unparseable timestamps
      }
    }
    return out;
  }, [todayMatches]);
  const todayTotal = hourly24.reduce((a, b) => a + b, 0);

  // 14-day baseline delta — `activity28d` is ordered [27d ago, …, 1d ago, today].
  // We average days -14 through -1 (indexes 13..=26 of a length-28 array) and
  // compare against today's value (last index). Hide when baseline is 0 or
  // there's no data to compare yet.
  const baselineDelta = useMemo<{ pct: number; direction: 'up' | 'down' | 'flat' } | null>(() => {
    if (!activity28d || activity28d.length < 15) return null;
    const today = activity28d[activity28d.length - 1] ?? 0;
    const window = activity28d.slice(activity28d.length - 15, activity28d.length - 1);
    if (window.length === 0) return null;
    const sum = window.reduce((a, b) => a + b, 0);
    const baseline = sum / window.length;
    if (baseline <= 0) return null;
    const pct = ((today - baseline) / baseline) * 100;
    if (Math.abs(pct) < 5) return { pct: 0, direction: 'flat' };
    return { pct, direction: pct > 0 ? 'up' : 'down' };
  }, [activity28d]);

  const uniqueEntities = useMemo(() => {
    const s = new Set<string>();
    for (const v of views) s.add(v.entity.id);
    return s.size;
  }, [views]);

  const uniqueIps = useMemo(() => {
    const s = new Set<string>();
    for (const v of views) for (const ip of v.events.map((e) => (e as Record<string, unknown>)['src_ip'])) {
      if (typeof ip === 'string' && ip) s.add(ip);
    }
    return s.size;
  }, [views]);

  const alertRate = totalMatches > 0 ? ((alertsGenerated / totalMatches) * 100).toFixed(2) : '0.00';
  const mttd = useMemo(() => meanTimeToDetect(views), [views]);

  // NAN-498 — disposition rollup over the last 28d for the FP tile.
  const { data: dispositionStats } = useRuleDispositionStats(rule.id, 28) as { data: import('@/lib/api/types').DispositionStatsResponse | null };
  const fpDisplay = useMemo(() => {
    if (!dispositionStats) return null;
    const { false_positive: fp, total } = dispositionStats;
    if (total === 0) return { count: 0, pct: null as string | null };
    const pct = ((fp / total) * 100).toFixed(1);
    return { count: fp, pct };
  }, [dispositionStats]);

  const { toast } = useToast();

  const copyRuleId = async () => {
    try {
      await navigator.clipboard.writeText(rule.id);
      toast({ title: 'Rule id copied', description: rule.id });
    } catch {
      toast({ title: 'Copy failed', description: 'Clipboard unavailable.', variant: 'destructive' });
    }
  };

  const isPaused = rule.mode === 'paused';
  const isAlerting = rule.mode === 'alerting';

  return (
    <div className="flex flex-col gap-2.5">
      {/* Title row */}
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <Link
              to="/rules"
              className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1 h-6 px-1.5 rounded hover:bg-foreground/5"
            >
              <ArrowLeft className="w-3 h-3" strokeWidth={2} />
              Back to rules
            </Link>
            <span className="text-muted-foreground/60">/</span>
            <div className="flex items-center gap-1.5">
              <span
                className={cn(
                  'w-[6px] h-[6px] rounded-full',
                  !isPaused && 'bg-success animate-pulse',
                  isPaused && 'bg-muted-foreground',
                )}
              />
              <span className="text-[11px] text-foreground">{isPaused ? 'Paused' : 'Live'}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-[6px] h-[6px] rounded-full" style={{ background: sev.color }} />
              <span className="text-[11px] text-foreground">{sev.label} severity</span>
            </div>
            {(tactic || technique) && (
              <span className="font-mono text-[10.5px] text-muted-foreground">
                {tactic && <span>{tactic}</span>}
                {tactic && technique && <span> · </span>}
                {technique && <span className="text-foreground">{technique}</span>}
              </span>
            )}
          </div>

          <h1 className="text-[22px] font-semibold tracking-[-0.01em] text-foreground mt-1.5 font-mono leading-none">
            {rule.name}
          </h1>
          {rule.description && (
            <p className="text-[12px] text-muted-foreground mt-1.5 max-w-[720px] leading-[1.55]">
              {rule.description}
            </p>
          )}

          <div className="mt-2 flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground flex-wrap">
            <span>
              id: <span className="text-foreground">{rule.id}</span>
            </span>
            <span className="text-muted-foreground/60">·</span>
            <span>
              owner: <span className="text-foreground">{rule.author || '—'}</span>
            </span>
            {rule.schedule_cron && (
              <>
                <span className="text-muted-foreground/60">·</span>
                <span>
                  schedule: <span className="text-foreground">{rule.schedule_cron}</span>
                </span>
              </>
            )}
            {rule.lookback_minutes != null && (
              <>
                <span className="text-muted-foreground/60">·</span>
                <span>
                  lookback: <span className="text-foreground">{rule.lookback_minutes}m</span>
                </span>
              </>
            )}
            <span className="text-muted-foreground/60">·</span>
            <span>
              updated: <span className="text-foreground">{rule.updated_at.slice(0, 10)}</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {canEdit && (
            <Link
              to={`/rules/editor/${rule.id}`}
              className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5"
            >
              <Pencil className="w-3.5 h-3.5" strokeWidth={2} />
              Edit
            </Link>
          )}
          <button
            type="button"
            onClick={onTogglePause}
            className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5"
          >
            {isPaused ? <Play className="w-3.5 h-3.5" strokeWidth={2} /> : <Pause className="w-3.5 h-3.5" strokeWidth={2} />}
            {isPaused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            onClick={copyRuleId}
            className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 flex items-center gap-1.5"
            title="Copy rule id"
          >
            <Copy className="w-3.5 h-3.5" strokeWidth={2} />
          </button>
          <button
            type="button"
            onClick={onToggleAlerting}
            disabled={isPaused}
            className={cn(
              'h-8 px-3 rounded-md text-[11.5px] font-medium flex items-center gap-1.5 disabled:opacity-50',
              isAlerting
                ? 'bg-primary text-[var(--brand-ink)] hover:bg-primary/90'
                : 'border border-border text-foreground hover:bg-foreground/5',
            )}
          >
            <Bell className="w-3.5 h-3.5" strokeWidth={2} />
            {isAlerting ? 'Alerting on' : 'Alerting off'}
          </button>
        </div>
      </div>

      {/* Analytics strip — 4 tiles */}
      <div className="rounded-lg border border-border overflow-hidden bg-card">
        <div className="grid grid-cols-[1.1fr_1.4fr_1.4fr_1fr] @max-[1100px]:grid-cols-2 @max-[640px]:grid-cols-1 divide-x divide-border @max-[1100px]:divide-x-0 @max-[1100px]:divide-y">
          {/* Tile 1 — Volume + activity */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Activity className="w-3 h-3" strokeWidth={2} />
              Detection volume
            </div>
            <div className="mt-1.5 flex items-baseline gap-1.5">
              <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">
                {totalMatches.toLocaleString()}
              </span>
              <span className="text-[11px] text-muted-foreground">matches</span>
            </div>
            <div className="text-[10.5px] text-muted-foreground mt-1 flex items-center gap-1.5">
              {baselineDelta ? (
                <span
                  className="inline-flex items-center gap-0.5 font-mono tabular-nums"
                  style={{
                    color:
                      baselineDelta.direction === 'up'
                        ? 'var(--warning)'
                        : baselineDelta.direction === 'down'
                          ? 'var(--success)'
                          : 'var(--muted-foreground)',
                  }}
                  title={`Today vs avg of last 14 days (${baselineDelta.pct >= 0 ? '+' : ''}${baselineDelta.pct.toFixed(0)}%)`}
                >
                  {baselineDelta.direction === 'up' && <ArrowUpRight className="w-3 h-3" strokeWidth={2} />}
                  {baselineDelta.direction === 'down' && <ArrowDownRight className="w-3 h-3" strokeWidth={2} />}
                  {baselineDelta.direction === 'flat' && <Minus className="w-3 h-3" strokeWidth={2} />}
                  {baselineDelta.direction === 'flat'
                    ? 'flat'
                    : `${baselineDelta.pct > 0 ? '+' : ''}${baselineDelta.pct.toFixed(0)}%`}
                </span>
              ) : (
                <span className="text-muted-foreground/60">—</span>
              )}
              <span>vs 14-day baseline · last 28 days</span>
            </div>
            <div className="mt-2.5 flex items-end gap-2">
              <HeatStrip28 data={activity28d} height={18} />
            </div>
            <div className="mt-1 flex items-center justify-between text-[9.5px] font-mono text-muted-foreground/70">
              <span>28d ago</span>
              <span>today</span>
            </div>
          </div>

          {/* Tile 2 — Today by hour */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Clock className="w-3 h-3" strokeWidth={2} />
              Today · hour by hour
            </div>
            <div className="mt-1.5 flex items-baseline gap-1.5">
              <span
                className={cn(
                  'text-[26px] font-semibold tabular-nums leading-none',
                  todayTotal > 0 ? 'text-foreground' : 'text-foreground/40',
                )}
              >
                {todayTotal > 0 ? todayTotal.toLocaleString() : '0'}
              </span>
              <span className="text-[11px] text-muted-foreground">last 24h</span>
            </div>
            <div className="mt-2.5">
              <HourlyStrip data={hourly24} height={36} currentHour={currentHour} />
            </div>
            <div className="mt-1 flex items-center justify-between text-[9.5px] font-mono text-muted-foreground/70">
              <span>00:00</span>
              <span>06:00</span>
              <span>12:00</span>
              <span>18:00</span>
              <span>now</span>
            </div>
          </div>

          {/* Tile 3 — Top firing entities */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Users className="w-3 h-3" strokeWidth={2} />
              Top firing identities
              <span className="ml-auto font-normal text-muted-foreground/70 normal-case tracking-normal text-[10.5px]">
                {uniqueEntities} total
              </span>
            </div>
            <div className="mt-2 flex flex-col gap-1.5">
              <TopEntitiesList views={views} />
            </div>
          </div>

          {/* Tile 4 — Rule health */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Activity className="w-3 h-3" strokeWidth={2} />
              Rule health
            </div>
            <div className="mt-1.5 flex items-baseline gap-1.5">
              <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">
                {alertRate}
              </span>
              <span className="text-[11px] text-muted-foreground">% alert rate</span>
            </div>
            <div className="mt-2 flex flex-col gap-1.5 text-[10.5px] font-mono">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Alerts generated</span>
                <span className="text-foreground tabular-nums">{alertsGenerated}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Disposition FP</span>
                {fpDisplay ? (
                  <span className="text-foreground tabular-nums" title="False positives over the last 28 days">
                    {fpDisplay.count}
                    {fpDisplay.pct !== null && (
                      <span className="text-muted-foreground"> ({fpDisplay.pct}%)</span>
                    )}
                  </span>
                ) : (
                  <span className="text-foreground/50 tabular-nums">—</span>
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Mean time to detect</span>
                {mttd ? (
                  <LatencyPill latency={mttd} />
                ) : (
                  <span className="text-foreground/50 tabular-nums">—</span>
                )}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Unique IPs</span>
                <span className="text-foreground tabular-nums">{uniqueIps}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Last match</span>
                <span className="text-foreground tabular-nums">
                  {views[0] ? views[0].detectedAt.toISOString().slice(11, 19) : '—'}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Inline — not exported, trivial enough.
function TopEntitiesList({ views }: { views: MatchView[] }) {
  const counts = useMemo(() => {
    const m = new Map<string, { entity: MatchView['entity']; count: number }>();
    for (const v of views) {
      const cur = m.get(v.entity.id);
      if (cur) cur.count += 1;
      else m.set(v.entity.id, { entity: v.entity, count: 1 });
    }
    return [...m.values()].sort((a, b) => b.count - a.count).slice(0, 5);
  }, [views]);

  if (counts.length === 0) {
    return (
      <div className="text-[10.5px] text-muted-foreground/70 font-mono py-2">
        No matches to aggregate yet.
      </div>
    );
  }

  const maxCount = Math.max(...counts.map((c) => c.count));

  return (
    <>
      {counts.map((ent) => {
        const width = (ent.count / maxCount) * 100;
        const typeDot =
          ent.entity.type === 'role' ? 'bg-warning'
          : ent.entity.type === 'service' ? 'bg-primary'
          : 'bg-muted-foreground';
        return (
          <div key={ent.entity.id} className="flex items-center gap-2 text-[11px] group cursor-pointer hover:bg-foreground/5 -mx-1 px-1 rounded">
            <span className={cn('w-[5px] h-[5px] rounded-full shrink-0', typeDot)} />
            <span className="font-mono text-foreground w-[130px] truncate">{ent.entity.label}</span>
            <div
              className="flex-1 h-[5px] rounded-full overflow-hidden relative"
              style={{ background: 'color-mix(in srgb, var(--foreground) 6%, transparent)' }}
            >
              <div
                className="h-full rounded-full transition-all"
                style={{ width: `${width}%`, background: 'var(--primary)' }}
              />
            </div>
            <span className="font-mono text-foreground tabular-nums w-[42px] text-right">{ent.count}</span>
          </div>
        );
      })}
    </>
  );
}
