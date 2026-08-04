// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-482 — 4-cell overview strip for the Rules dashboard.
// Port of design-ref/shadcn/rules-overview.jsx. Velocity spark + peak-hour
// callout remain placeholder-today; Fleet health was wired to real data in
// NAN-612 (see /api/rules/fleet-health).

import { useMemo, type ReactNode } from 'react';
import { AlertTriangle, ArrowRight } from 'lucide-react';
import type { DetectionRule, FleetHealthSummary, AlertVelocityBucket } from '@/lib/api/types';
import { SEV_META, bandOf, type SeverityKey } from './helpers';

interface RulesOverviewProps {
  rules: DetectionRule[];
  silentCount: number;
  alerts24h: number;
  /** Dense desktop treatment: keeps all four signals in view without pushing
   *  the rule inventory below the fold on a short Tauri window. */
  compact?: boolean;
  /**
   * Fleet-health rollup over the schedulable rule fleet (NAN-612).
   * Pass `null`/`undefined` while loading or on error — the Fleet health cell
   * falls back to em-dashes, matching the original placeholder layout.
   */
  fleetHealth?: FleetHealthSummary | null;
  /**
   * NAN-1019: hourly alert-velocity buckets (24h, chronological) powering
   * the FIRING NOW sparkline. `undefined` while loading; the spark renders
   * a flat baseline. Empty array also renders the baseline.
   */
  velocity?: AlertVelocityBucket[] | null;
  onReviewSilent?: () => void;
}

// Dot matrix — each dot = one rule. Color by severity, dim if silent/staging.
function FleetMatrix({ rules }: { rules: DetectionRule[] }) {
  const ordered = useMemo(() => {
    const order: Record<string, number> = { firing: 0, active: 1, silent: 2, staging: 3, disabled: 4 };
    return [...rules].sort((a, b) => order[bandOf(a)] - order[bandOf(b)]);
  }, [rules]);

  return (
    <div className="mt-2 grid grid-cols-[repeat(auto-fill,minmax(9px,1fr))] gap-[3px] max-w-[260px]">
      {ordered.map((r, i) => {
        const band = bandOf(r);
        const alive = band === 'firing' || band === 'active';
        const sevKey = (r.severity === 'informational' ? 'info' : r.severity) as SeverityKey;
        const sev = SEV_META[sevKey] || SEV_META.low;
        return (
          <div
            key={`${r.id}-${i}`}
            title={`${r.name} · ${sev.label} · ${band}`}
            className="w-[8px] h-[8px] rounded-[1.5px]"
            style={{
              background: alive ? sev.color : 'color-mix(in srgb, var(--foreground) 10%, transparent)',
              boxShadow: band === 'firing' ? `0 0 4px ${sev.color}` : 'none',
            }}
          />
        );
      })}
    </div>
  );
}

// 24-hour velocity bars. NAN-1019: wired to `/api/alerts/velocity` instead
// of the hard-coded fake series. When no buckets are loaded yet (or when a
// quiet tenant has zero alerts in the window), all bars render at the
// minimum height (faint outline) — same shape, honest data.
function VelocitySpark({ buckets, compact = false }: { buckets?: AlertVelocityBucket[] | null; compact?: boolean }) {
  // Server returns one bucket per hour over the requested window, but be
  // defensive about empty / missing data — fall back to 24 zeros so the
  // sparkline still occupies its layout slot.
  const bars: number[] = useMemo(() => {
    if (!buckets || buckets.length === 0) return Array(24).fill(0);
    return buckets.map((b) => b.count);
  }, [buckets]);
  const max = Math.max(...bars, 1);
  return (
    <div className={`flex items-end gap-[2px] ${compact ? 'h-[18px]' : 'h-[28px]'}`}>
      {bars.map((v, i) => (
        <div
          key={i}
          className="w-[3px] rounded-[1px]"
          style={{
            height: `${Math.max(2, (v / max) * 100)}%`,
            background:
              v >= max * 0.7
                ? 'var(--primary)'
                : v > 0
                  ? 'color-mix(in srgb, var(--primary) 50%, transparent)'
                  : 'color-mix(in srgb, var(--foreground) 10%, transparent)',
          }}
        />
      ))}
    </div>
  );
}

export function RulesOverview({ rules, silentCount, alerts24h, fleetHealth, velocity, onReviewSilent, compact = false }: RulesOverviewProps) {
  const byBand = useMemo(() => {
    const acc: Record<string, number> = { firing: 0, active: 0, silent: 0, staging: 0, disabled: 0 };
    rules.forEach((r) => { acc[bandOf(r)]++; });
    return acc;
  }, [rules]);

  const bySev = useMemo(() => {
    const acc: Record<SeverityKey, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    rules.forEach((r) => {
      const k = (r.severity === 'informational' ? 'info' : r.severity) as SeverityKey;
      if (k in acc) acc[k]++;
    });
    return acc;
  }, [rules]);

  const live = rules.filter((r) => r.mode === 'live' || r.mode === 'alerting').length;
  const total = rules.length || 1;

  if (compact) {
    return (
      <CompactRulesOverview
        live={live}
        total={rules.length}
        silentCount={silentCount}
        alerts24h={alerts24h}
        fleetHealth={fleetHealth ?? null}
        velocity={velocity}
        byBand={byBand}
        bySev={bySev}
        onReviewSilent={onReviewSilent}
      />
    );
  }

  return (
    <div
      className="rounded-lg border border-border overflow-hidden"
      style={{ background: 'var(--border)', containerType: 'inline-size' }}
    >
      <div className="grid grid-cols-[1fr_1fr_1fr_1fr] @max-[1100px]:grid-cols-2 @max-[640px]:grid-cols-1 gap-px">
        {/* Cell 1 — Detection fleet */}
        <div className="p-3.5 flex flex-col bg-card">
          <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
            Detection fleet
          </div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">{live}</span>
            <span className="text-[11px] text-muted-foreground">live</span>
            <span className="text-muted-foreground/60 mx-0.5">·</span>
            <span className="text-[11px] text-muted-foreground tabular-nums">{rules.length} total</span>
          </div>
          <FleetMatrix rules={rules} />
          <div
            className="mt-2.5 h-[6px] rounded-full overflow-hidden flex"
            style={{ background: 'color-mix(in srgb, var(--foreground) 5%, transparent)' }}
          >
            {(['critical', 'high', 'medium', 'low'] as SeverityKey[]).map((k) => {
              const pct = ((bySev[k] || 0) / total) * 100;
              if (pct === 0) return null;
              return <div key={k} style={{ width: `${pct}%`, background: SEV_META[k].color }} />;
            })}
          </div>
          <div className="mt-2 grid grid-cols-4 gap-1.5 text-[10.5px] font-mono">
            {(['critical', 'high', 'medium', 'low'] as SeverityKey[]).map((k) => (
              <div key={k}>
                <div className="flex items-center gap-1 text-muted-foreground/80">
                  <span
                    className="w-[5px] h-[5px] rounded-full shrink-0"
                    style={{ background: SEV_META[k].color }}
                  />
                  <span className="truncate">{SEV_META[k].label}</span>
                </div>
                <div className="text-foreground tabular-nums mt-0.5">{bySev[k] || 0}</div>
              </div>
            ))}
          </div>
          <div className="mt-2 text-[10.5px] text-muted-foreground leading-[1.5]">
            <span className="text-foreground font-medium">{byBand.firing + byBand.active}</span> active ·{' '}
            <span className="text-foreground font-medium">{byBand.silent}</span> silent ·{' '}
            <span className="text-foreground font-medium">{byBand.staging + byBand.disabled}</span> staged
          </div>
        </div>

        {/* Cell 2 — Firing now */}
        <div className="p-3.5 relative bg-card">
          <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold flex items-center gap-1.5">
            <span className="w-[5px] h-[5px] rounded-full bg-destructive animate-pulse" />
            Firing now
          </div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">
              {byBand.firing}
            </span>
            <span className="text-[11px] text-muted-foreground">rules</span>
          </div>
          <div className="mt-2.5 flex items-end justify-between">
            <div className="flex flex-col gap-0.5">
              <div className="font-mono text-[9.5px] uppercase tracking-[0.1em] text-muted-foreground/70">
                last 24h alerts
              </div>
              <div className="text-[14px] tabular-nums font-semibold text-foreground">
                {alerts24h.toLocaleString()}
              </div>
            </div>
            <VelocitySpark buckets={velocity} />
          </div>
          <div className="mt-2 text-[10.5px] text-muted-foreground">
            24h velocity trend
          </div>
        </div>

        {/* Cell 3 — Needs review */}
        <div className="p-3.5 relative bg-card">
          <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold flex items-center gap-1.5">
            <AlertTriangle className="w-3 h-3 text-warning" strokeWidth={2} />
            Needs review
          </div>
          <div className="flex items-baseline gap-1.5 mt-1">
            <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">
              {silentCount}
            </span>
            <span className="text-[11px] text-muted-foreground">silent rules</span>
          </div>
          <div className="mt-2 text-[10.5px] text-muted-foreground leading-[1.5]">
            No matches in <span className="text-foreground font-medium">30+ days</span>. Review to confirm
            they're tuned, not broken.
          </div>
          {silentCount > 0 && (
            <button
              type="button"
              onClick={onReviewSilent}
              className="mt-2.5 text-[11px] text-primary hover:underline flex items-center gap-1"
            >
              Review silent rules
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Cell 4 — Fleet health (NAN-612). Backed by /api/rules/fleet-health.
            Counts are over the schedulable fleet (Live/Alerting + scheduled +
            has cron). When `fleetHealth` is null/undefined or `total` is 0,
            we fall back to em-dashes — same shape as the original placeholder. */}
        <FleetHealthCell fleetHealth={fleetHealth ?? null} />
      </div>
    </div>
  );
}

/**
 * Desktop-sized overview. The full web dashboard's dot matrix is useful on a
 * tall page, but hundreds of dim silent-rule dots consume most of a short
 * desktop viewport while looking like blank space. This variant keeps the same
 * four decisions in one scan line and leaves the inventory visible below it.
 */
function CompactRulesOverview({
  live,
  total,
  silentCount,
  alerts24h,
  fleetHealth,
  velocity,
  byBand,
  bySev,
  onReviewSilent,
}: {
  live: number;
  total: number;
  silentCount: number;
  alerts24h: number;
  fleetHealth: FleetHealthSummary | null;
  velocity?: AlertVelocityBucket[] | null;
  byBand: Record<string, number>;
  bySev: Record<SeverityKey, number>;
  onReviewSilent?: () => void;
}) {
  const healthTotal = fleetHealth?.total ?? 0;
  const hasHealth = fleetHealth != null && healthTotal > 0;
  const healthPct = hasHealth
    ? Math.round(((fleetHealth?.healthy ?? 0) / healthTotal) * 100)
    : null;

  return (
    <div
      className="overflow-hidden rounded-lg border border-border"
      style={{ background: 'var(--border)', containerType: 'inline-size' }}
      data-density="compact"
    >
      <div className="grid grid-cols-4 gap-px @max-[820px]:grid-cols-2 @max-[480px]:grid-cols-1">
        <div className="min-w-0 bg-card px-3 py-2.5">
          <OverviewLabel>Detection fleet</OverviewLabel>
          <div className="mt-1 flex items-baseline gap-1.5">
            <OverviewValue>{live}</OverviewValue>
            <span className="text-[10.5px] text-muted-foreground">live</span>
            <span className="text-muted-foreground/50">·</span>
            <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
              {total} total
            </span>
          </div>
          <div
            className="mt-2 flex h-1 overflow-hidden rounded-full"
            style={{ background: 'color-mix(in srgb, var(--foreground) 5%, transparent)' }}
          >
            {(['critical', 'high', 'medium', 'low'] as SeverityKey[]).map((key) => {
              const width = ((bySev[key] || 0) / Math.max(total, 1)) * 100;
              return width > 0
                ? <span key={key} style={{ width: `${width}%`, background: SEV_META[key].color }} />
                : null;
            })}
          </div>
          <div className="mt-1.5 flex min-w-0 flex-wrap gap-x-2.5 gap-y-0.5 font-mono text-[9.5px] text-muted-foreground">
            {(['critical', 'high', 'medium', 'low'] as SeverityKey[]).map((key) => {
              const shortLabel = key === 'critical' ? 'crit' : key === 'medium' ? 'med' : key;
              return (
                <span key={key} className="inline-flex items-center gap-1 whitespace-nowrap">
                  <span className="size-[5px] rounded-full" style={{ background: SEV_META[key].color }} />
                  {bySev[key] || 0} {shortLabel}
                </span>
              );
            })}
          </div>
        </div>

        <div className="min-w-0 bg-card px-3 py-2.5">
          <OverviewLabel>
            <span className="size-[5px] rounded-full bg-destructive animate-pulse" />
            Firing now
          </OverviewLabel>
          <div className="mt-1 flex items-end justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-baseline gap-1.5">
                <OverviewValue>{byBand.firing}</OverviewValue>
                <span className="text-[10.5px] text-muted-foreground">rules</span>
              </div>
              <div className="mt-1 font-mono text-[9.5px] text-muted-foreground whitespace-nowrap">
                <span className="text-foreground tabular-nums">{alerts24h.toLocaleString()}</span> alerts · 24h
              </div>
            </div>
            <VelocitySpark buckets={velocity} compact />
          </div>
        </div>

        <div className="min-w-0 bg-card px-3 py-2.5">
          <OverviewLabel>
            <AlertTriangle className="size-3 text-warning" strokeWidth={2} />
            Needs review
          </OverviewLabel>
          <div className="mt-1 flex items-baseline gap-1.5">
            <OverviewValue>{silentCount}</OverviewValue>
            <span className="text-[10.5px] text-muted-foreground">silent rules</span>
          </div>
          <div className="mt-1.5 flex min-w-0 items-center justify-between gap-2 text-[9.5px]">
            <span className="truncate text-muted-foreground">No matches in 30+ days</span>
            {silentCount > 0 && (
              <button
                type="button"
                onClick={onReviewSilent}
                className="inline-flex shrink-0 items-center gap-0.5 text-primary hover:underline"
              >
                Review <ArrowRight className="size-2.5" />
              </button>
            )}
          </div>
        </div>

        <div className="min-w-0 bg-card px-3 py-2.5">
          <OverviewLabel>Fleet health</OverviewLabel>
          <div className="mt-1 flex items-baseline gap-1.5">
            <OverviewValue>{healthPct ?? '—'}</OverviewValue>
            {healthPct != null && <span className="text-[12px] text-muted-foreground">%</span>}
            {hasHealth && (
              <span className="font-mono text-[9.5px] text-muted-foreground tabular-nums">
                · {healthTotal} scheduled
              </span>
            )}
          </div>
          <div className="mt-1.5 flex items-center gap-3 font-mono text-[9.5px] text-muted-foreground">
            <HealthDatum label="Healthy" value={hasHealth ? fleetHealth?.healthy ?? 0 : '—'} color="var(--success)" />
            <HealthDatum label="Slow" value={hasHealth ? fleetHealth?.slow ?? 0 : '—'} color="var(--warning)" />
            <HealthDatum label="Errors" value={hasHealth ? fleetHealth?.errors ?? 0 : '—'} color="var(--destructive)" />
          </div>
          {!hasHealth && (
            <div className="mt-1 truncate text-[9.5px] text-muted-foreground/70">
              No scheduled runs yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function OverviewLabel({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
      {children}
    </div>
  );
}

function OverviewValue({ children }: { children: ReactNode }) {
  return (
    <span className="text-[22px] font-semibold leading-none text-foreground tabular-nums">
      {children}
    </span>
  );
}

function HealthDatum({ label, value, color }: { label: string; value: number | string; color: string }) {
  return (
    <span className="inline-flex min-w-0 items-center gap-1 whitespace-nowrap">
      <span className="size-[5px] shrink-0 rounded-full" style={{ background: color }} />
      <span className="truncate">{label}</span>
      <span className="text-foreground tabular-nums">{value}</span>
    </span>
  );
}

// Tri-segment progress bar (green / amber / red) sized proportionally so a
// reviewer can read the mix at a glance. Empty (pending) rules in the fleet
// — those without a `last_run_at` — show as the empty remainder of the bar.
function FleetHealthCell({ fleetHealth }: { fleetHealth: FleetHealthSummary | null }) {
  const total = fleetHealth?.total ?? 0;
  const healthy = fleetHealth?.healthy ?? 0;
  const slow = fleetHealth?.slow ?? 0;
  const errors = fleetHealth?.errors ?? 0;

  // Empty state: no fleet data yet, nothing scheduled, or endpoint failed.
  // Behave exactly like the original placeholder so the layout doesn't shift.
  const hasData = fleetHealth != null && total > 0;
  const pct = hasData ? Math.round((healthy / total) * 100) : null;

  const healthyPct = hasData ? (healthy / total) * 100 : 0;
  const slowPct = hasData ? (slow / total) * 100 : 0;
  const errorPct = hasData ? (errors / total) * 100 : 0;

  const footer = !hasData
    ? 'Scheduler health — no scheduled rules yet.'
    : `Healthy: recent run on schedule, fast. Slow: last run ≥ 5s. Errors: scheduler stuck.`;

  return (
    <div className="p-3.5 relative bg-card">
      <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
        Fleet health
      </div>
      <div className="flex items-baseline gap-1.5 mt-1">
        <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">
          {pct == null ? '—' : pct}
        </span>
        <span className="text-[14px] text-muted-foreground">%</span>
        {hasData && (
          <>
            <span className="text-muted-foreground/60 mx-0.5">·</span>
            <span className="text-[11px] text-muted-foreground tabular-nums">{total} scheduled</span>
          </>
        )}
      </div>
      <div
        className="mt-2.5 h-[6px] rounded-full overflow-hidden flex"
        style={{ background: 'color-mix(in srgb, var(--foreground) 5%, transparent)' }}
      >
        {healthyPct > 0 && (
          <div style={{ width: `${healthyPct}%`, background: 'var(--success)' }} />
        )}
        {slowPct > 0 && (
          <div style={{ width: `${slowPct}%`, background: 'var(--warning)' }} />
        )}
        {errorPct > 0 && (
          <div style={{ width: `${errorPct}%`, background: 'var(--destructive)' }} />
        )}
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2 text-[10.5px] font-mono">
        <div>
          <div className="flex items-center gap-1 text-muted-foreground/80">
            <span className="w-[5px] h-[5px] rounded-full shrink-0" style={{ background: 'var(--success)' }} />
            <span>Healthy</span>
          </div>
          <div className="text-foreground tabular-nums mt-0.5">
            {hasData ? healthy : '—'}
          </div>
        </div>
        <div>
          <div className="flex items-center gap-1 text-muted-foreground/80">
            <span className="w-[5px] h-[5px] rounded-full shrink-0" style={{ background: 'var(--warning)' }} />
            <span>Slow</span>
          </div>
          <div className="text-foreground tabular-nums mt-0.5">
            {hasData ? slow : '—'}
          </div>
        </div>
        <div>
          <div className="flex items-center gap-1 text-muted-foreground/80">
            <span className="w-[5px] h-[5px] rounded-full shrink-0" style={{ background: 'var(--destructive)' }} />
            <span>Errors</span>
          </div>
          <div className="text-foreground tabular-nums mt-0.5">
            {hasData ? errors : '—'}
          </div>
        </div>
      </div>
      <div
        className="mt-2 text-[10.5px] text-muted-foreground/70 leading-[1.4]"
        title={hasData ? footer : undefined}
      >
        {footer}
      </div>
    </div>
  );
}
