// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — bottom tray. Collapsed one-line status strip (always visible)
// expands on click into three side-by-side cards: Validation / Impact &
// baseline / Version history. Mirrors `design-ref/shadcn/editor-tray.jsx`.

import { useMemo, useState } from 'react';
import {
  Check,
  AlertCircle,
  Circle,
  Layers,
  Play,
  ChevronUp,
  BarChart3,
  TrendingUp,
  TrendingDown,
  Minus,
  Zap,
} from 'lucide-react';
import { Line, LineChart, ResponsiveContainer, Tooltip } from 'recharts';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import type { ValidationState } from '@/components/editor/detection-linter';
import type { DailyStat } from '@/lib/api/types';
import { AutoTuneSettingsPopover } from '@/enterprise/components/rule-editor/AutoTuneSettingsPopover';

export interface RuleVersionSummary {
  id: number | string;
  /** Human label like `v7` — falls back to `#<id>`. */
  label?: string;
  /** Relative time like `4 days ago` — falls back to the raw date. */
  when?: string;
  by?: string;
  msg?: string;
}

interface BottomTrayProps {
  validation: ValidationState | null;
  /** Raw 7d-or-so match count. */
  matchCount?: number;
  /** Short relative label ("12m ago") pulled from `last_run_at`. */
  lastSavedLabel?: string;
  versions?: RuleVersionSummary[];
  /** 28-day history used for the 7-day sparkline + trend in ImpactCard. */
  dailyStats?: DailyStat[];
  /** Rule ID — when present, Tune settings popover opens against it. */
  ruleId?: string;
  /** Read-only surface disables tune-settings save. */
  readOnly?: boolean;
  /** NAN-1688 — present only when the rule is on scheduled mode, editable, and
   * on a dataset that supports the MV path. When set and the backend reports
   * the query real-time eligible, ValidateCard shows a one-click nudge. */
  onSwitchToRealtime?: () => void;
  onOpenTest?: () => void;
  onOpenVersion?: (version: RuleVersionSummary) => void;
}

export function BottomTray({
  validation,
  matchCount,
  lastSavedLabel,
  versions,
  dailyStats,
  ruleId,
  readOnly,
  onSwitchToRealtime,
  onOpenTest,
  onOpenVersion,
}: BottomTrayProps) {
  const [open, setOpen] = useState(true);

  const valStatus: 'valid' | 'invalid' | 'unchecked' = validation
    ? validation.valid
      ? 'valid'
      : 'invalid'
    : 'unchecked';

  const versionCount = versions?.length ?? 0;

  // NAN-1688 — the rule is scheduled but its query shape qualifies for the
  // lower-latency real-time (materialized-view) path. Offer a one-click switch.
  // Self-clears the moment the query stops being eligible (e.g. add `| stats`)
  // or the mode is already real-time — no dismiss state to manage.
  const showRealtimeNudge = Boolean(onSwitchToRealtime && validation?.valid && validation?.realtimeEligible);

  return (
    <div className="border-t border-border bg-[var(--panel)] shrink-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full h-9 flex items-center px-4 gap-4 text-[11.5px] font-mono hover:bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)] transition-colors"
        aria-expanded={open}
        aria-controls="rule-editor-bottom-tray-body"
      >
        <ChevronUp
          className={cn('w-3 h-3 text-muted-foreground shrink-0 transition-transform', open && 'rotate-180')}
          strokeWidth={1.75}
        />

        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          {valStatus === 'valid' ? (
            <Check className="w-3 h-3 text-[var(--success)] shrink-0" strokeWidth={2} />
          ) : valStatus === 'invalid' ? (
            <AlertCircle className="w-3 h-3 text-[var(--destructive)] shrink-0" strokeWidth={2} />
          ) : (
            <Circle className="w-3 h-3 text-muted-foreground shrink-0" strokeWidth={1.5} />
          )}
          <span className={cn(valStatus === 'invalid' ? 'text-[var(--destructive)]' : 'text-foreground/80')}>
            {valStatus === 'valid' ? 'Valid' : valStatus === 'invalid' ? 'Invalid' : 'Unchecked'}
          </span>
          {validation?.matchCount != null && (
            <span className="text-muted-foreground">· {validation.matchCount.toLocaleString()} matches last run</span>
          )}
        </span>

        {matchCount != null && (
          <>
            <Separator orientation="vertical" className="h-4" />
            <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
              <span className="text-muted-foreground">Matches</span>
              <span className="text-foreground font-semibold">{matchCount.toLocaleString()}</span>
            </span>
          </>
        )}

        {versionCount > 0 && (
          <>
            <Separator orientation="vertical" className="h-4" />
            <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
              <Layers className="w-3 h-3 text-muted-foreground shrink-0" strokeWidth={1.75} />
              <span className="text-muted-foreground">
                v{versionCount}
                {lastSavedLabel && <span className="text-muted-foreground/60"> · {lastSavedLabel}</span>}
              </span>
            </span>
          </>
        )}

        {showRealtimeNudge && (
          <>
            <Separator orientation="vertical" className="h-4" />
            <span
              onClick={(e) => {
                e.stopPropagation();
                onSwitchToRealtime?.();
              }}
              title={validation?.realtimeEligibleReason}
              className="inline-flex items-center gap-1.5 whitespace-nowrap text-[var(--primary)] hover:underline cursor-pointer"
            >
              <Zap className="w-3 h-3" strokeWidth={1.75} />
              Eligible for real-time · Switch
            </span>
          </>
        )}

        <div className="flex-1" />

        {ruleId && (
          <>
            <AutoTuneSettingsPopover ruleId={ruleId} disabled={readOnly} />
            <Separator orientation="vertical" className="h-4" />
          </>
        )}

        {onOpenTest && (
          <span
            onClick={(e) => {
              e.stopPropagation();
              onOpenTest();
            }}
            className="inline-flex items-center gap-1.5 whitespace-nowrap text-[var(--primary)] font-semibold hover:underline cursor-pointer"
          >
            <Play className="w-3 h-3" strokeWidth={1.75} />
            Test rule
          </span>
        )}
      </button>

      {open && (
        <div
          id="rule-editor-bottom-tray-body"
          className="px-4 pb-3 pt-1 grid grid-cols-1 md:grid-cols-3 gap-3"
        >
          <ValidateCard
            validation={validation}
            showRealtimeNudge={showRealtimeNudge}
            onSwitchToRealtime={onSwitchToRealtime}
          />
          <ImpactCard matchCount={matchCount} lastSavedLabel={lastSavedLabel} dailyStats={dailyStats} />
          <VersionsCard versions={versions} onOpenVersion={onOpenVersion} />
        </div>
      )}
    </div>
  );
}

function ValidateCard({
  validation,
  showRealtimeNudge,
  onSwitchToRealtime,
}: {
  validation: ValidationState | null;
  showRealtimeNudge?: boolean;
  onSwitchToRealtime?: () => void;
}) {
  const valStatus: 'valid' | 'invalid' | 'unchecked' = validation
    ? validation.valid
      ? 'valid'
      : 'invalid'
    : 'unchecked';
  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <div className="flex items-center gap-2 mb-2">
        {valStatus === 'valid' ? (
          <Check className="w-3.5 h-3.5 text-[var(--success)]" strokeWidth={1.75} />
        ) : valStatus === 'invalid' ? (
          <AlertCircle className="w-3.5 h-3.5 text-[var(--destructive)]" strokeWidth={1.75} />
        ) : (
          <Circle className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={1.75} />
        )}
        <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] font-semibold text-foreground/80">
          Validation
        </div>
        <span
          className="ml-auto inline-flex items-center gap-1 px-1.5 h-5 rounded-[3px] text-[10px] font-mono font-semibold tracking-[0.08em] uppercase"
          style={{
            background:
              valStatus === 'valid'
                ? 'color-mix(in srgb, var(--success) 15%, transparent)'
                : valStatus === 'invalid'
                  ? 'color-mix(in srgb, var(--destructive) 15%, transparent)'
                  : 'color-mix(in srgb, var(--foreground) 8%, transparent)',
            color:
              valStatus === 'valid'
                ? 'var(--success)'
                : valStatus === 'invalid'
                  ? 'var(--destructive)'
                  : 'var(--muted-foreground)',
          }}
        >
          {valStatus}
        </span>
      </div>
      <div className="space-y-1 text-[11.5px]">
        {validation?.error && (
          <div className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--destructive)] mt-1.5 shrink-0" />
            <div className="flex-1 font-mono text-[var(--destructive)]/90 leading-snug whitespace-pre-wrap break-words">
              {validation.error}
            </div>
          </div>
        )}
        {validation?.warning && (
          <div className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--warning)] mt-1.5 shrink-0" />
            <div className="flex-1 font-mono text-[var(--warning)]/90 leading-snug">{validation.warning}</div>
          </div>
        )}
        {validation?.info && (
          <div className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--primary)] mt-1.5 shrink-0" />
            <div className="flex-1 font-mono text-muted-foreground leading-snug">{validation.info}</div>
          </div>
        )}
        {validation?.detectionMode && (
          <div className="flex items-start gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground mt-1.5 shrink-0" />
            <div className="flex-1 font-mono text-muted-foreground leading-snug">
              Executes as <span className="text-foreground">{validation.detectionMode}</span>
              {validation.createsMaterializedView ? ' · creates materialized view' : ''}
            </div>
          </div>
        )}
        {showRealtimeNudge && (
          <div className="mt-2 flex items-start gap-2 rounded-md border border-[color-mix(in_srgb,var(--primary)_35%,var(--border))] bg-[color-mix(in_srgb,var(--primary)_7%,transparent)] px-2.5 py-2">
            <Zap className="w-3.5 h-3.5 text-[var(--primary)] mt-px shrink-0" strokeWidth={1.75} />
            <div className="flex-1 min-w-0">
              <div className="text-[11px] text-foreground/90 leading-snug">
                Eligible for <span className="font-semibold text-[var(--primary)]">real-time</span> — streams via a
                materialized view (10–30s latency) instead of running on a cron schedule.
              </div>
              {onSwitchToRealtime && (
                <button
                  type="button"
                  onClick={onSwitchToRealtime}
                  className="mt-1.5 inline-flex items-center gap-1 h-6 px-2 rounded text-[11px] font-mono font-semibold text-[var(--primary)] bg-[color-mix(in_srgb,var(--primary)_14%,transparent)] hover:bg-[color-mix(in_srgb,var(--primary)_22%,transparent)] transition-colors"
                >
                  Switch to real-time
                </button>
              )}
            </div>
          </div>
        )}
        {!validation && (
          <div className="text-[11px] text-muted-foreground">
            Edit the query to trigger validation. Saved rules re-validate on every save.
          </div>
        )}
        {validation?.valid && !validation.error && !validation.warning && !validation.info && (
          <div className="text-[11px] text-muted-foreground">Parses cleanly against the current schema.</div>
        )}
      </div>
    </div>
  );
}

function ImpactCard({
  matchCount,
  lastSavedLabel,
  dailyStats,
}: {
  matchCount?: number;
  lastSavedLabel?: string;
  dailyStats?: DailyStat[];
}) {
  const { sparkData, last7dTotal, prev7dTotal, trend } = useMemo(() => {
    const stats = dailyStats || [];
    // Order ascending; take the last 14 days — last 7 for the current window,
    // prior 7 for baseline comparison. API already returns sorted descending
    // or ascending depending on route; normalize by date string.
    const sorted = [...stats].sort((a, b) => a.date.localeCompare(b.date));
    const last14 = sorted.slice(-14);
    const last7 = last14.slice(-7);
    const prev7 = last14.slice(0, Math.max(0, last14.length - 7));
    const sum = (rows: DailyStat[]) => rows.reduce((acc, r) => acc + (r.match_count || 0), 0);
    const cur = sum(last7);
    const prev = sum(prev7);
    let trend: 'up' | 'down' | 'flat' = 'flat';
    if (prev === 0 && cur === 0) trend = 'flat';
    else if (prev === 0) trend = cur > 0 ? 'up' : 'flat';
    else if (cur > prev * 1.1) trend = 'up';
    else if (cur < prev * 0.9) trend = 'down';
    return {
      sparkData: last7.map((r) => ({ date: r.date, count: r.match_count || 0 })),
      last7dTotal: cur,
      prev7dTotal: prev,
      trend,
    };
  }, [dailyStats]);

  const trendColor =
    trend === 'up' ? 'var(--destructive)' : trend === 'down' ? 'var(--success)' : 'var(--muted-foreground)';
  const TrendIcon = trend === 'up' ? TrendingUp : trend === 'down' ? TrendingDown : Minus;
  const deltaPct = prev7dTotal > 0 ? Math.round(((last7dTotal - prev7dTotal) / prev7dTotal) * 100) : null;

  return (
    <div className="rounded-lg border border-border bg-card p-3">
      <div className="flex items-center gap-2 mb-2">
        <BarChart3 className="w-3.5 h-3.5 text-[var(--primary)]" strokeWidth={1.75} />
        <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] font-semibold text-foreground/80">
          Impact &amp; baseline
        </div>
        <span className="ml-auto text-[10px] font-mono text-muted-foreground">last 7d</span>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <div className="text-[9.5px] font-mono text-muted-foreground uppercase tracking-[0.08em]">Total matches</div>
          <div className="text-[18px] font-mono font-semibold text-foreground">
            {matchCount != null ? matchCount.toLocaleString() : '—'}
          </div>
          <div className="text-[10px] font-mono text-muted-foreground">
            {matchCount === 0 ? 'never fired' : lastSavedLabel ? `last run ${lastSavedLabel}` : 'all-time'}
          </div>
        </div>
        <div>
          <div className="text-[9.5px] font-mono text-muted-foreground uppercase tracking-[0.08em]">7d trend</div>
          <div className="flex items-baseline gap-1.5">
            <div className="text-[18px] font-mono font-semibold text-foreground">
              {last7dTotal.toLocaleString()}
            </div>
            <div className="inline-flex items-center gap-0.5 text-[10px] font-mono" style={{ color: trendColor }}>
              <TrendIcon className="w-3 h-3" strokeWidth={1.75} />
              {deltaPct !== null ? `${deltaPct > 0 ? '+' : ''}${deltaPct}%` : 'new'}
            </div>
          </div>
          {sparkData.length > 0 ? (
            <div className="h-6 mt-1">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={sparkData} margin={{ top: 1, right: 1, bottom: 1, left: 1 }}>
                  <Line
                    type="monotone"
                    dataKey="count"
                    stroke="var(--primary)"
                    strokeWidth={1.5}
                    dot={false}
                    activeDot={{ r: 2, strokeWidth: 0, fill: 'var(--primary)' }}
                    isAnimationActive={false}
                  />
                  <Tooltip
                    cursor={false}
                    contentStyle={{
                      background: 'var(--card)',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: 10,
                      fontFamily: 'var(--font-mono)',
                      padding: '2px 6px',
                    }}
                    formatter={(value) => {
                      const coerced = typeof value === 'number' ? value : Number(value);
                      const n = Number.isFinite(coerced) ? coerced : 0;
                      return [`${n.toLocaleString()} matches`, ''];
                    }}
                    labelFormatter={(v) => String(v)}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="text-[10px] font-mono text-muted-foreground mt-1">no recent activity</div>
          )}
        </div>
      </div>
    </div>
  );
}

function VersionsCard({
  versions,
  onOpenVersion,
}: {
  versions?: RuleVersionSummary[];
  onOpenVersion?: (version: RuleVersionSummary) => void;
}) {
  const slice = (versions || []).slice(0, 4);
  return (
    <div className="rounded-lg border border-border bg-card p-3 flex flex-col">
      <div className="flex items-center gap-2 mb-2">
        <Layers className="w-3.5 h-3.5 text-[var(--warning)]" strokeWidth={1.75} />
        <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] font-semibold text-foreground/80">
          Version history
        </div>
        {versions && versions.length > 0 && (
          <span className="ml-auto text-[10.5px] font-mono text-muted-foreground">
            {versions.length} versions
          </span>
        )}
      </div>
      {slice.length === 0 ? (
        <div className="text-[11px] text-muted-foreground">No version history yet. First save creates v1.</div>
      ) : (
        <div className="space-y-1.5">
          {slice.map((v, i) => {
            const rowContent = (
              <>
                <div className="flex flex-col items-center shrink-0 pt-0.5">
                  <div
                    className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      i === 0
                        ? 'bg-[var(--primary)] ring-2 ring-[color-mix(in_srgb,var(--primary)_30%,transparent)]'
                        : 'bg-muted-foreground',
                    )}
                  />
                  {i < slice.length - 1 && <div className="w-px h-4 bg-border mt-0.5" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline gap-1.5">
                    <span className="font-mono text-foreground font-semibold">{v.label || `#${v.id}`}</span>
                    {v.when && (
                      <>
                        <span className="text-muted-foreground/60 text-[10px]">·</span>
                        <span className="font-mono text-muted-foreground text-[10.5px]">{v.when}</span>
                      </>
                    )}
                    {v.by && (
                      <>
                        <span className="text-muted-foreground/60 text-[10px]">·</span>
                        <span className="font-mono text-muted-foreground text-[10.5px] truncate">{v.by}</span>
                      </>
                    )}
                  </div>
                  {v.msg && <div className="text-[11px] text-foreground/80 truncate">{v.msg}</div>}
                </div>
                {onOpenVersion && (
                  <span
                    aria-hidden="true"
                    className="opacity-0 group-hover:opacity-100 text-muted-foreground text-[10.5px] shrink-0 self-center"
                  >
                    →
                  </span>
                )}
              </>
            );
            return onOpenVersion ? (
              <button
                key={v.id}
                type="button"
                onClick={() => onOpenVersion(v)}
                aria-label={`Open ${v.label || `version ${v.id}`} in inspector`}
                className="w-full text-left flex items-start gap-2 text-[11px] group rounded-md px-1.5 py-1 -mx-1.5 hover:bg-foreground/[0.04] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--primary)]/60 transition-colors cursor-pointer"
              >
                {rowContent}
              </button>
            ) : (
              <div key={v.id} className="flex items-start gap-2 text-[11px] group">
                {rowContent}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
