// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-568 — SIEM Health page. Ported to Wave 18+ aesthetic.
 *
 * Source of truth: design-ref/siem-health.html.
 *
 * Pipeline-spine model: Ingestion → Parsing → Enrichment → Detection → Alerting.
 * Score dial + status pill in header; clickable spine drives stage-detail panel
 * below; AI narrative + ranked recommendations sit two-up under the spine.
 *
 * Data sources (all from /api/siem-health/reports/latest):
 *   - overall_score / dimension scores → score dial + spine status tones
 *   - metrics.ingestion (silent_sources, source_volumes) → ingestion stage detail
 *   - metrics.parsing (field_coverage, high_ext_sources) → parsing stage detail
 *   - metrics.enrichment (geoip/asn/ioc/identity fill, per_source_coverage) → enrichment stage detail
 *   - metrics.detection (stale_rules, noisy_rules, alerts_24h_by_severity) → detection stage detail
 *   - metrics.alerting (volume + delta, by_status, mtta, webhook health, routing) → alerting stage detail
 *   - summary (markdown) → narrative
 *   - dimension_details.{ingestion,parsing,enrichment,detection,alerting} → per-stage analysis prose
 *   - recommendations[] → ranked actions
 *
 * Deferred (need new collector code, future wave): per-stage sparkline series,
 * 24h throughput heatmap, structured anomaly timeline, structured narrative
 * paragraphs with stage citation chips, recommendations with action labels /
 * ETA / target stage. Stages without backing data render with an "n/a — not
 * yet measured" subline (for old reports generated before NAN-569).
 */

import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Bell,
  Clock,
  Download,
  HeartPulse,
  Info,
  Layers,
  RefreshCw,
  RotateCcw,
  Shield,
  Sparkles,
  X,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useToast } from '@/hooks/use-toast';
import { Markdown } from '@/components/ui/markdown';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import type {
  CollectedMetrics,
  FindingSuppression,
  Recommendation,
  SiemHealthReport,
} from '@/lib/api/siem-health';
import { cn } from '@/lib/utils';

/* ============================================================================
   TONE / TOKENS
   ============================================================================ */

type Tone = 'critical' | 'high' | 'medium' | 'good' | 'fg' | 'fg-2' | 'fg-3';
type StageStatus = 'down' | 'degraded' | 'idle' | 'ok' | 'unknown';

const TONE_FG: Record<Tone, string> = {
  critical: 'text-red-400',
  high: 'text-amber-400',
  medium: 'text-yellow-400',
  good: 'text-emerald-400',
  fg: 'text-foreground',
  'fg-2': 'text-muted-foreground',
  'fg-3': 'text-muted-foreground/70',
};

const TONE_BG: Record<Tone, string> = {
  critical: 'bg-red-500/10 border-red-500/30',
  high: 'bg-amber-500/10 border-amber-500/30',
  medium: 'bg-yellow-500/10 border-yellow-500/25',
  good: 'bg-emerald-500/10 border-emerald-500/30',
  fg: 'bg-foreground/5 border-border',
  'fg-2': 'bg-foreground/5 border-border',
  'fg-3': 'bg-foreground/5 border-border',
};

const TONE_DOT: Record<Tone, string> = {
  critical: 'oklch(62% 0.22 18)',
  high: 'oklch(72% 0.18 28)',
  medium: 'oklch(80% 0.15 78)',
  good: 'oklch(70% 0.16 160)',
  fg: '#A8ACB4',
  'fg-2': '#A8ACB4',
  'fg-3': '#6A6F78',
};

const STATUS_META: Record<
  StageStatus,
  { tone: Tone; label: string; pulse: boolean }
> = {
  down: { tone: 'critical', label: 'DOWN', pulse: true },
  degraded: { tone: 'high', label: 'DEGRADED', pulse: true },
  idle: { tone: 'medium', label: 'IDLE', pulse: false },
  ok: { tone: 'good', label: 'HEALTHY', pulse: false },
  unknown: { tone: 'fg-3', label: 'N/A', pulse: false },
};

function statusFromScore(score: number | null | undefined): StageStatus {
  if (score == null) return 'unknown';
  if (score >= 80) return 'ok';
  if (score >= 50) return 'idle';
  if (score >= 25) return 'degraded';
  return 'down';
}

function priorityToTone(priority: string): Tone {
  switch (priority) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    default:
      return 'fg-2';
  }
}

/* ============================================================================
   PRIMITIVES
   ============================================================================ */

function Eyebrow({
  icon: Icon,
  children,
  className,
}: {
  icon?: LucideIcon;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80',
        className,
      )}
    >
      {Icon && <Icon className="h-[11px] w-[11px]" />}
      {children}
    </div>
  );
}

function Eyebrow2({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground/80',
        className,
      )}
    >
      {children}
    </div>
  );
}

function StatusPill({ status }: { status: StageStatus }) {
  const m = STATUS_META[status];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-[0.1em]',
        TONE_FG[m.tone],
        TONE_BG[m.tone],
      )}
    >
      <span className="relative flex h-1.5 w-1.5">
        {m.pulse && (
          <span
            className="absolute inset-0 animate-ping rounded-full opacity-50"
            style={{ background: TONE_DOT[m.tone] }}
          />
        )}
        <span
          className="relative h-1.5 w-1.5 rounded-full"
          style={{ background: TONE_DOT[m.tone] }}
        />
      </span>
      {m.label}
    </span>
  );
}

function SevPill({
  priority,
  size = 'sm',
}: {
  priority: string;
  size?: 'xs' | 'sm';
}) {
  const tone = priorityToTone(priority);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded border font-mono font-semibold uppercase tracking-[0.08em]',
        size === 'xs' ? 'px-1 py-px text-[9px]' : 'px-1.5 py-0.5 text-[9.5px]',
        TONE_FG[tone],
        TONE_BG[tone],
      )}
    >
      <span
        className="h-[6px] w-[6px] shrink-0 rounded-full"
        style={{ background: TONE_DOT[tone] }}
      />
      {priority}
    </span>
  );
}

function ScoreDial({
  value,
  tone,
  size = 84,
}: {
  value: number;
  tone: Tone;
  size?: number;
}) {
  const r = size / 2 - 7;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(1, value / 100));
  const dash = pct * c;
  const color = TONE_DOT[tone];
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke="var(--card)"
          strokeWidth="6"
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={color}
          strokeWidth="6"
          fill="none"
          strokeDasharray={`${dash} ${c - dash}`}
          strokeLinecap="round"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span
          className={cn(
            'font-semibold leading-none tabular-nums',
            TONE_FG[tone],
          )}
          style={{ fontSize: '26px' }}
        >
          {value}
        </span>
        <span className="mt-1 font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">
          / 100
        </span>
      </div>
    </div>
  );
}

const PROSE_CLASSES =
  'prose prose-sm prose-invert max-w-none text-[12.5px] leading-[1.55] [&_h1]:text-[13px] [&_h2]:text-[12.5px] [&_h3]:text-[12px] [&_p]:my-2 [&_p:first-child]:mt-0 [&_p:last-child]:mb-0 [&_ul]:my-2 [&_li]:my-0.5';

/* ============================================================================
   STAGE MODEL — derived from API report
   ============================================================================ */

type StageId = 'ingestion' | 'parsing' | 'enrichment' | 'detection' | 'alerting';

interface StageView {
  id: StageId;
  label: string;
  icon: LucideIcon;
  status: StageStatus;
  headline: string;
  subline: string;
  /** Optional contextual note rendered below stage detail metrics. */
  note?: string;
}

function buildStages(
  report: SiemHealthReport | null | undefined,
): StageView[] {
  const m: CollectedMetrics | null = report?.metrics ?? null;
  const ing = m?.ingestion ?? null;
  const enr = m?.enrichment ?? null;
  const det = m?.detection ?? null;
  const alr = m?.alerting ?? null;

  const ingTotal = ing?.total_events_24h ?? 0;
  const ingPrior = ing?.total_events_prior_24h ?? 0;
  const ingDelta =
    ingPrior > 0
      ? Math.round(((ingTotal - ingPrior) / ingPrior) * 100)
      : null;
  const silentCount = ing?.silent_sources?.length ?? 0;

  const parseFailHigh = (m?.parsing?.high_ext_sources?.length ?? 0) > 0;
  const parsedTotal = ingTotal; // proxy — parsing throughput tracks ingestion in this build

  const ruleCount = det?.total_enabled_rules ?? 0;
  const alertSeverityTotal =
    det?.alerts_24h_by_severity?.reduce((acc, a) => acc + a.count, 0) ?? 0;
  const staleCount = det?.stale_rules?.length ?? 0;

  const alrTotal = alr?.total_alerts_24h ?? 0;
  const alrPrior = alr?.total_alerts_prior_24h ?? 0;
  const alrDelta =
    alrPrior > 0 ? Math.round(((alrTotal - alrPrior) / alrPrior) * 100) : null;

  return [
    {
      id: 'ingestion',
      label: 'Ingestion',
      icon: Download,
      status: report ? statusFromScore(report.ingestion_score) : 'unknown',
      headline: ing
        ? `${formatCompact(ingTotal)} evt`
        : '—',
      subline: ing
        ? silentCount > 0
          ? `${silentCount} source${silentCount === 1 ? '' : 's'} silent · 24h ${signed(ingDelta)}`
          : `${ing.source_volumes.length} sources active · 24h ${signed(ingDelta)}`
        : 'no ingestion metrics',
    },
    {
      id: 'parsing',
      label: 'Parsing',
      icon: Layers,
      status: report ? statusFromScore(report.parsing_score) : 'unknown',
      headline: m?.parsing
        ? `${formatCompact(parsedTotal)} evt`
        : '—',
      subline: m?.parsing
        ? parseFailHigh
          ? `${m.parsing.high_ext_sources.length} sources rely on ext`
          : `${m.parsing.field_coverage.length} schemas tracked`
        : 'no parsing metrics',
    },
    {
      id: 'enrichment',
      label: 'Enrichment',
      icon: Sparkles,
      status: statusFromScore(report?.enrichment_score ?? null),
      headline: enr
        ? `${Math.round(enr.geoip_fill_pct)}% geo`
        : '—',
      subline: enr
        ? `ASN ${Math.round(enr.asn_fill_pct)}% · IOC ${Math.round(enr.ioc_hit_pct)}% · identity ${Math.round(enr.identity_fill_pct)}%`
        : 'not yet measured',
    },
    {
      id: 'detection',
      label: 'Detection',
      icon: Shield,
      status: report ? statusFromScore(report.detection_score) : 'unknown',
      headline: det ? `${ruleCount} rules` : '—',
      subline: det
        ? staleCount > 0
          ? `${staleCount} stale · ${alertSeverityTotal} alerts in 24h`
          : `${alertSeverityTotal} alerts in 24h`
        : 'no detection metrics',
    },
    {
      id: 'alerting',
      label: 'Alerting',
      icon: Bell,
      status: statusFromScore(report?.alerting_score ?? null),
      headline: alr ? `${alrTotal} alerts` : '—',
      subline: alr
        ? alr.mean_mtta_minutes != null
          ? `MTTA ${formatMinutes(alr.mean_mtta_minutes)} · 24h ${signed(alrDelta)}`
          : `24h ${signed(alrDelta)} · no acks yet`
        : 'not yet measured',
    },
  ];
}

function formatMinutes(minutes: number): string {
  if (minutes < 1) return `${Math.round(minutes * 60)}s`;
  if (minutes < 60) return `${Math.round(minutes)}m`;
  const hours = minutes / 60;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function formatCompact(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function signed(delta: number | null | undefined): string {
  if (delta == null) return '—';
  if (delta === 0) return '0%';
  return `${delta > 0 ? '+' : ''}${delta}%`;
}

/* ============================================================================
   PIPELINE SPINE
   ============================================================================ */

function PipelineSpine({
  stages,
  activeId,
  onSelect,
}: {
  stages: StageView[];
  activeId: StageId;
  onSelect: (id: StageId) => void;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card">
      <div className="relative">
        <div
          className="absolute left-0 right-0 top-[42px] h-px"
          // NAN-618 / NAN-619: was `var(--border)`, which read as a hard
          // split in light theme. Foreground-at-low-alpha (3%) equalizes
          // perceived weight across themes — barely-there ambient seam.
          style={{
            background:
              'linear-gradient(90deg, transparent, color-mix(in srgb, var(--foreground) 3%, transparent) 8%, color-mix(in srgb, var(--foreground) 3%, transparent) 92%, transparent)',
          }}
        />
        <div
          className="relative grid"
          style={{ gridTemplateColumns: `repeat(${stages.length}, minmax(0,1fr))` }}
        >
          {stages.map((s, i) => {
            const Icon = s.icon;
            const tone = STATUS_META[s.status].tone;
            const isActive = activeId === s.id;
            return (
              <button
                key={s.id}
                type="button"
                onClick={() => onSelect(s.id)}
                className={cn(
                  'group relative px-4 pt-4 pb-3.5 text-left transition-colors',
                  isActive
                    ? 'bg-foreground/[.025]'
                    : 'hover:bg-foreground/[.02]',
                  i < stages.length - 1 && 'border-r border-border',
                )}
              >
                {isActive && (
                  <div
                    className="absolute bottom-0 left-0 right-0 h-[2px]"
                    style={{ background: TONE_DOT[tone] }}
                  />
                )}
                <div className="relative z-10 mb-2.5 flex items-center gap-2.5">
                  <div
                    className={cn(
                      'flex h-8 w-8 items-center justify-center rounded-lg border',
                      TONE_BG[tone],
                    )}
                  >
                    <Icon className={cn('h-[14px] w-[14px]', TONE_FG[tone])} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[12.5px] font-medium leading-tight text-foreground">
                      {s.label}
                    </div>
                    <Eyebrow2 className="mt-0.5">
                      stage {String(i + 1).padStart(2, '0')}
                    </Eyebrow2>
                  </div>
                  <StatusPill status={s.status} />
                </div>
                <div className="flex items-end justify-between gap-3">
                  <div className="min-w-0">
                    <div
                      className={cn(
                        'font-semibold leading-none tabular-nums',
                        TONE_FG[tone],
                      )}
                      style={{ fontSize: '22px' }}
                    >
                      {s.headline}
                    </div>
                    <div className="mt-1.5 truncate text-[11px] text-muted-foreground">
                      {s.subline}
                    </div>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
   NARRATIVE
   ============================================================================ */

function Narrative({
  summary,
  asOf,
  loading,
  onRefresh,
}: {
  summary: string;
  asOf: string | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  return (
    <div className="rounded-xl border border-border bg-card p-5">
      <div className="mb-3 flex items-center gap-2">
        <div className="flex h-6 w-6 items-center justify-center rounded-md border border-primary/40 bg-primary/15">
          <Sparkles className="h-[12px] w-[12px] text-primary" />
        </div>
        <Eyebrow2>Health narrative · auto-generated</Eyebrow2>
        {asOf && (
          <>
            <span className="font-mono text-[10px] text-muted-foreground/40">
              ·
            </span>
            <span className="font-mono text-[10px] text-muted-foreground">
              {asOf}
            </span>
          </>
        )}
        <span className="flex-1" />
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className={cn(
            'flex h-6 items-center gap-1 rounded px-2 font-mono text-[10.5px] text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
            loading && 'opacity-60',
          )}
        >
          <RefreshCw
            className={cn('h-[10px] w-[10px]', loading && 'animate-spin')}
          />
          re-analyze
        </button>
      </div>
      {summary ? (
        <div className={PROSE_CLASSES}>
          <Markdown>{summary}</Markdown>
        </div>
      ) : (
        <p className="text-[12.5px] text-muted-foreground">
          No narrative available yet.
        </p>
      )}
    </div>
  );
}

/* ============================================================================
   RECOMMENDATIONS
   ============================================================================ */

function Recommendations({
  items,
  suppressedTitles,
  suppressions,
  canManage,
  onSuppress,
  onUndo,
  isMutating,
}: {
  items: Recommendation[];
  suppressedTitles: Set<string>;
  suppressions: FindingSuppression[];
  canManage: boolean;
  onSuppress: (title: string, reason: string) => void;
  onUndo: (id: string) => void;
  isMutating: boolean;
}) {
  // NAN-615: filter out suppressed classes optimistically. The backend's
  // prompt injection prevents them on the next run; this hides them now so
  // the UI doesn't lag a report cycle behind the user's action.
  const visibleItems = useMemo(
    () => items.filter((r) => !suppressedTitles.has(r.title)),
    [items, suppressedTitles]
  );
  const suppressedHere = items.length - visibleItems.length;
  const [showSuppressed, setShowSuppressed] = useState(false);

  return (
    <div className="rounded-xl border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        <div className="flex h-5 w-5 items-center justify-center rounded-md border border-primary/40 bg-primary/15">
          <Sparkles className="h-[10px] w-[10px] text-primary" />
        </div>
        <Eyebrow2>Recommended actions</Eyebrow2>
        <span className="font-mono text-[10px] text-muted-foreground/40">·</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">
          {visibleItems.length} ranked by priority
        </span>
      </div>
      {visibleItems.length === 0 ? (
        <div className="px-4 py-8 text-center">
          <Sparkles className="mx-auto mb-2 h-5 w-5 text-muted-foreground/40" />
          <p className="text-[12px] text-muted-foreground">
            No recommendations at this time.
          </p>
        </div>
      ) : (
        <div className="divide-y divide-border">
          {visibleItems.map((rec, i) => (
            <div key={i} className="group p-4 hover:bg-foreground/[.015]">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 w-5 font-mono text-[10px] tabular-nums text-muted-foreground/40">
                  {String(i + 1).padStart(2, '0')}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="mb-1 flex items-center gap-2">
                    <SevPill priority={rec.priority} size="xs" />
                    <h4 className="text-[12.5px] font-semibold text-foreground">
                      {rec.title}
                    </h4>
                    {canManage && (
                      <SuppressFindingButton
                        title={rec.title}
                        onSuppress={onSuppress}
                        isMutating={isMutating}
                      />
                    )}
                  </div>
                  <p
                    className="text-[11.5px] leading-[1.5] text-muted-foreground"
                    style={{ textWrap: 'pretty' }}
                  >
                    {rec.description}
                  </p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      {(suppressedHere > 0 || suppressions.length > 0) && (
        <div className="border-t border-border">
          <button
            type="button"
            onClick={() => setShowSuppressed((s) => !s)}
            className="flex w-full items-center gap-2 px-4 py-2.5 text-left hover:bg-foreground/[.015]"
          >
            <span className="font-mono text-[10.5px] text-muted-foreground">
              {suppressions.length} suppressed
              {suppressedHere > 0 && ` (${suppressedHere} from this report)`}
            </span>
            <span className="flex-1" />
            <span className="font-mono text-[10.5px] text-muted-foreground/70">
              {showSuppressed ? 'hide' : 'show'}
            </span>
          </button>
          {showSuppressed && (
            <div className="divide-y divide-border border-t border-border">
              {suppressions.length === 0 ? (
                <div className="px-4 py-3 text-[11.5px] text-muted-foreground">
                  None active.
                </div>
              ) : (
                suppressions.map((s) => (
                  <div key={s.id} className="p-4 hover:bg-foreground/[.015]">
                    <div className="flex items-start gap-3">
                      <div className="min-w-0 flex-1">
                        <h4 className="text-[12px] font-semibold text-foreground/80">
                          {s.title}
                        </h4>
                        <p
                          className="mt-1 text-[11px] leading-[1.5] text-muted-foreground"
                          style={{ textWrap: 'pretty' }}
                        >
                          <span className="text-muted-foreground/60">
                            reason:
                          </span>{' '}
                          {s.reason}
                        </p>
                      </div>
                      {canManage && (
                        <button
                          type="button"
                          onClick={() => onUndo(s.id)}
                          disabled={isMutating}
                          className="flex items-center gap-1 rounded-md border border-border px-2 py-1 font-mono text-[10px] text-muted-foreground hover:bg-foreground/[.04] hover:text-foreground disabled:opacity-50"
                          title="Re-enable this finding class"
                        >
                          <RotateCcw className="h-3 w-3" />
                          undo
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** NAN-615: per-finding "Not an issue" affordance — captures a reason that
 * gets fed back into the AI prompt on subsequent runs. Hover-revealed to
 * keep the recommendations list dense; opens a small popover for the reason
 * input rather than a full modal. */
function SuppressFindingButton({
  title,
  onSuppress,
  isMutating,
}: {
  title: string;
  onSuppress: (title: string, reason: string) => void;
  isMutating: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label="Mark as not an issue"
          className="ml-auto flex h-5 w-5 shrink-0 items-center justify-center rounded-md border border-transparent text-muted-foreground/0 hover:border-border hover:text-muted-foreground group-hover:text-muted-foreground/60"
          title="Not an issue — suppress this finding class"
        >
          <X className="h-[11px] w-[11px]" />
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-3">
        <div className="mb-2 text-[11px] font-semibold text-foreground">
          Mark this as not an issue
        </div>
        <p className="mb-2 text-[10.5px] leading-[1.4] text-muted-foreground">
          The AI will stop raising this class of finding. Your reason is fed
          into the prompt so it can re-raise it later if the metric materially
          regresses.
        </p>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="e.g. windows_sysmon process events legitimately don't have src_ip"
          rows={3}
          maxLength={500}
          className="w-full resize-none rounded-md border border-border bg-background p-2 text-[11px] outline-none focus:border-primary/50"
        />
        <div className="mt-2 flex items-center gap-2">
          <span className="font-mono text-[9.5px] text-muted-foreground/50">
            {reason.length}/500
          </span>
          <span className="flex-1" />
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="rounded-md border border-border px-2 py-1 text-[10.5px] text-muted-foreground hover:bg-foreground/[.04]"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={reason.trim().length === 0 || isMutating}
            onClick={() => {
              onSuppress(title, reason.trim());
              setReason('');
              setOpen(false);
            }}
            className="rounded-md bg-foreground px-2 py-1 text-[10.5px] font-medium text-background hover:bg-foreground/90 disabled:opacity-50"
          >
            Suppress
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

/* ============================================================================
   STAGE DETAIL
   ============================================================================ */

function StageDetail({
  stage,
  report,
}: {
  stage: StageView;
  report: SiemHealthReport;
}) {
  const tone = STATUS_META[stage.status].tone;
  const Icon = stage.icon;
  const detail =
    stage.id === 'ingestion'
      ? report.dimension_details?.ingestion
      : stage.id === 'parsing'
        ? report.dimension_details?.parsing
        : stage.id === 'enrichment'
          ? report.dimension_details?.enrichment
          : stage.id === 'detection'
            ? report.dimension_details?.detection
            : stage.id === 'alerting'
              ? report.dimension_details?.alerting
              : null;

  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card">
      <div
        className="flex items-center gap-3 border-b border-border bg-card/40 px-5 py-4"
      >
        <div
          className={cn(
            'flex h-9 w-9 items-center justify-center rounded-lg border',
            TONE_BG[tone],
          )}
        >
          <Icon className={cn('h-[16px] w-[16px]', TONE_FG[tone])} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-[15px] font-semibold text-foreground">
              {stage.label}
            </h3>
            <StatusPill status={stage.status} />
          </div>
          <div className="mt-0.5 text-[11.5px] text-muted-foreground">
            {stage.subline}
          </div>
        </div>
      </div>

      {/* Stage-specific content */}
      {stage.id === 'ingestion' && (
        <IngestionDetail metrics={report.metrics?.ingestion} />
      )}
      {stage.id === 'parsing' && (
        <ParsingDetail metrics={report.metrics?.parsing} />
      )}
      {stage.id === 'enrichment' && (
        <EnrichmentDetail metrics={report.metrics?.enrichment} />
      )}
      {stage.id === 'detection' && (
        <DetectionDetail metrics={report.metrics?.detection} />
      )}
      {stage.id === 'alerting' && (
        <AlertingDetail metrics={report.metrics?.alerting} />
      )}

      {/* Per-dimension narrative */}
      {detail && (
        <div className="border-t border-border px-5 py-4">
          <Eyebrow2 className="mb-2">Analysis</Eyebrow2>
          <div className={PROSE_CLASSES}>
            <Markdown>{detail}</Markdown>
          </div>
        </div>
      )}

      {stage.note && (
        <div className="flex items-start gap-2.5 border-t border-border bg-card/40 px-5 py-3.5">
          <Info className="mt-0.5 h-[13px] w-[13px] shrink-0 text-muted-foreground/70" />
          <p className="text-[12px] leading-relaxed text-muted-foreground">
            {stage.note}
          </p>
        </div>
      )}
    </div>
  );
}

function IngestionDetail({
  metrics,
}: {
  metrics?: CollectedMetrics['ingestion'];
}) {
  if (!metrics) return <EmptyDetail label="ingestion" />;
  const total = metrics.total_events_24h;
  const prior = metrics.total_events_prior_24h;
  const delta = prior > 0 ? Math.round(((total - prior) / prior) * 100) : null;
  // NAN-1405: insert-path integrity signals (NAN-1404 silent-loss probes).
  // Optional — reports stored before NAN-1405 lack the block; hidden when the
  // probes could not run (missing system-table grants).
  const ii = metrics.insert_integrity;
  const insertsWithoutParts =
    !!ii && ii.logs_inserts_1h >= 10 && ii.new_parts_1h === 0;
  // NAN-1407: failing/stale dict-staging refreshes — stale enrichment, not
  // loss (rows keep landing with the last good snapshot).
  const staleRefreshes = ii?.stale_dict_refreshes ?? [];
  const integrityRows: Array<{
    key: string;
    label: string;
    value: string;
    bad: boolean;
  }> =
    ii && ii.probes_available
      ? [
          {
            key: 'failed-dicts',
            label: 'FAILED enrichment dictionaries',
            value:
              ii.failed_logs_dictionaries.length > 0
                ? ii.failed_logs_dictionaries.map((d) => d.name).join(', ')
                : 'none',
            bad: ii.failed_logs_dictionaries.length > 0,
          },
          {
            key: 'inserts-vs-parts',
            label: 'INSERTs vs new parts on disk (1h)',
            value: `${ii.logs_inserts_1h.toLocaleString()} inserts · ${ii.new_parts_1h.toLocaleString()} parts`,
            bad: insertsWithoutParts,
          },
          ...(ii.async_insert_failures_1h !== null
            ? [
                {
                  key: 'flush-failures',
                  label: 'Async-insert flush failures (1h)',
                  value: ii.async_insert_failures_1h.toLocaleString(),
                  bad: ii.async_insert_failures_1h > 0,
                },
              ]
            : []),
          {
            key: 'oom',
            label: 'MEMORY_LIMIT_EXCEEDED (24h)',
            value: ii.memory_limit_errors.toLocaleString(),
            bad: ii.memory_limit_errors > 0,
          },
          {
            key: 'dict-update-fail',
            label: 'CACHE_DICTIONARY_UPDATE_FAIL (24h)',
            value: ii.cache_dictionary_update_fails.toLocaleString(),
            bad: ii.cache_dictionary_update_fails > 0,
          },
          {
            key: 'stale-dict-refresh',
            label: 'Stale dictionary refreshes (staging MVs)',
            value:
              staleRefreshes.length > 0
                ? staleRefreshes.map((r) => r.view).join(', ')
                : 'none',
            bad: staleRefreshes.length > 0,
          },
        ]
      : [];
  const integrityBadCount = integrityRows.filter((r) => r.bad).length;
  return (
    <>
      <MetricsGrid
        items={[
          {
            label: 'Events / 24h',
            value: total.toLocaleString(),
            delta,
            tone: deltaTone(delta),
          },
          {
            label: 'Prior 24h',
            value: prior.toLocaleString(),
            tone: 'fg-2',
          },
          {
            label: 'Active sources',
            value: `${metrics.source_volumes.length}`,
            tone: 'fg',
          },
          {
            label: 'Silent sources',
            value: `${metrics.silent_sources.length}`,
            tone: metrics.silent_sources.length > 0 ? 'critical' : 'good',
          },
        ]}
      />
      {integrityRows.length > 0 && (
        <SubPanel
          title="Insert integrity"
          subtitle={
            integrityBadCount > 0
              ? `${integrityBadCount} storage-layer signal${integrityBadCount === 1 ? '' : 's'} firing — possible silent loss`
              : 'storage-layer loss probes · all clear'
          }
        >
          <div className="divide-y divide-border">
            {integrityRows.map((row) => (
              <div
                key={row.key}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <span
                  className="h-[6px] w-[6px] shrink-0 rounded-full"
                  style={{
                    background: row.bad ? TONE_DOT.critical : TONE_DOT.good,
                  }}
                />
                <span className="flex-1 truncate text-[12px] text-foreground">
                  {row.label}
                </span>
                <span
                  className={cn(
                    'max-w-[360px] truncate text-right font-mono text-[11px] tabular-nums',
                    row.bad ? 'text-red-400' : 'text-muted-foreground',
                  )}
                  title={row.value}
                >
                  {row.value}
                </span>
              </div>
            ))}
            {ii?.last_async_insert_error && (
              <div className="px-5 py-2.5">
                <div className="mb-1 font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  last flush exception
                </div>
                <div className="break-all font-mono text-[11px] text-red-400">
                  {ii.last_async_insert_error}
                </div>
              </div>
            )}
          </div>
        </SubPanel>
      )}
      {metrics.silent_sources.length > 0 && (
        <SubPanel
          title="Silent sources"
          subtitle={`${metrics.silent_sources.length} fell silent in last 24h`}
        >
          <div className="divide-y divide-border">
            {metrics.silent_sources.map((src) => (
              <div
                key={src}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <span
                  className="h-[6px] w-[6px] shrink-0 rounded-full"
                  style={{ background: TONE_DOT.critical }}
                />
                <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                  {src}
                </span>
                <span className="rounded bg-foreground/5 px-1.5 py-px font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  silent
                </span>
              </div>
            ))}
          </div>
        </SubPanel>
      )}
      {metrics.source_volumes.length > 0 && (
        <SubPanel
          title="Active sources"
          subtitle={`${metrics.source_volumes.length} types · sorted by volume`}
        >
          <div className="divide-y divide-border">
            {[...metrics.source_volumes]
              .sort((a, b) => b.count_24h - a.count_24h)
              .slice(0, 12)
              .map((sv) => (
              <div
                key={sv.source_type}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <span
                  className="h-[6px] w-[6px] shrink-0 rounded-full"
                  style={{
                    background:
                      sv.change_pct < -50
                        ? TONE_DOT.critical
                        : sv.change_pct < -10
                          ? TONE_DOT.high
                          : TONE_DOT.good,
                  }}
                />
                <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                  {sv.source_type}
                </span>
                <span className="w-[100px] text-right font-mono text-[11px] tabular-nums text-muted-foreground">
                  {sv.count_24h.toLocaleString()}
                </span>
                <span className="w-[100px] text-right font-mono text-[11px] tabular-nums text-muted-foreground/60">
                  prior {sv.count_prior_24h.toLocaleString()}
                </span>
                <span
                  className={cn(
                    'w-[60px] text-right font-mono text-[11px] tabular-nums',
                    sv.change_pct < 0
                      ? 'text-red-400'
                      : sv.change_pct > 0
                        ? 'text-emerald-400'
                        : 'text-muted-foreground',
                  )}
                >
                  {signed(Math.round(sv.change_pct))}
                </span>
              </div>
            ))}
          </div>
        </SubPanel>
      )}
    </>
  );
}

function ParsingDetail({
  metrics,
}: {
  metrics?: CollectedMetrics['parsing'];
}) {
  if (!metrics) return <EmptyDetail label="parsing" />;
  const cov = metrics.field_coverage;
  const avgUser =
    cov.length > 0
      ? Math.round(
          cov.reduce((acc, c) => acc + c.user_filled_pct, 0) / cov.length,
        )
      : null;
  const avgIp =
    cov.length > 0
      ? Math.round(
          cov.reduce((acc, c) => acc + c.src_ip_filled_pct, 0) / cov.length,
        )
      : null;
  return (
    <>
      <MetricsGrid
        items={[
          {
            label: 'Schemas tracked',
            value: `${cov.length}`,
            tone: 'fg',
          },
          {
            label: 'Avg user fill',
            value: avgUser != null ? `${avgUser}%` : '—',
            tone: coverageTone(avgUser),
          },
          {
            label: 'Avg src_ip fill',
            value: avgIp != null ? `${avgIp}%` : '—',
            tone: coverageTone(avgIp),
          },
          {
            label: 'High-ext sources',
            value: `${metrics.high_ext_sources.length}`,
            tone:
              metrics.high_ext_sources.length > 0 ? 'high' : 'good',
          },
        ]}
      />
      {cov.length > 0 && (
        <SubPanel
          title="Field coverage"
          subtitle={`${cov.length} sources · per-field fill rate`}
        >
          <div className="divide-y divide-border">
            {cov.slice(0, 12).map((c) => (
              <div
                key={c.source_type}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                  {c.source_type}
                </span>
                <CoverageCell
                  label="user"
                  pct={c.user_filled_pct}
                />
                <CoverageCell
                  label="src_ip"
                  pct={c.src_ip_filled_pct}
                />
                <CoverageCell
                  label="event_type"
                  pct={c.event_type_filled_pct}
                />
                <CoverageCell
                  label="msg"
                  pct={c.message_filled_pct}
                />
              </div>
            ))}
          </div>
        </SubPanel>
      )}
    </>
  );
}

function DetectionDetail({
  metrics,
}: {
  metrics?: CollectedMetrics['detection'];
}) {
  if (!metrics) return <EmptyDetail label="detection" />;
  const alertTotal = metrics.alerts_24h_by_severity.reduce(
    (acc, a) => acc + a.count,
    0,
  );
  return (
    <>
      <MetricsGrid
        items={[
          {
            label: 'Active rules',
            value: `${metrics.total_enabled_rules}`,
            tone: 'fg',
          },
          {
            label: 'Stale rules',
            value: `${metrics.stale_rules.length}`,
            tone: metrics.stale_rules.length > 0 ? 'medium' : 'good',
          },
          {
            label: 'Noisy rules',
            value: `${metrics.noisy_rules.length}`,
            tone: metrics.noisy_rules.length > 0 ? 'high' : 'good',
          },
          {
            label: 'Alerts / 24h',
            value: `${alertTotal}`,
            tone: 'fg',
          },
        ]}
      />
      {metrics.alerts_24h_by_severity.length > 0 && (
        <SubPanel
          title="Alerts by severity"
          subtitle="last 24h"
        >
          <div className="flex flex-wrap gap-2 px-5 py-3">
            {metrics.alerts_24h_by_severity.map((a) => (
              <div
                key={a.severity}
                className={cn(
                  'flex items-center gap-2 rounded border px-2.5 py-1',
                  TONE_BG[priorityToTone(a.severity)],
                )}
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  {a.severity}
                </span>
                <span
                  className={cn(
                    'font-mono text-[12px] font-semibold tabular-nums',
                    TONE_FG[priorityToTone(a.severity)],
                  )}
                >
                  {a.count}
                </span>
              </div>
            ))}
          </div>
        </SubPanel>
      )}
      {metrics.stale_rules.length > 0 && (
        <SubPanel
          title="Stale rules"
          subtitle={`${metrics.stale_rules.length} haven't matched in 30d+`}
        >
          <div className="divide-y divide-border">
            {metrics.stale_rules.slice(0, 10).map((r) => (
              <div
                key={r.rule_name}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <span
                  className="h-[6px] w-[6px] shrink-0 rounded-full"
                  style={{ background: TONE_DOT.medium }}
                />
                <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                  {r.rule_name}
                </span>
                <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                  {r.days_since_match}d since match
                </span>
              </div>
            ))}
          </div>
        </SubPanel>
      )}
      {metrics.noisy_rules.length > 0 && (
        <SubPanel
          title="Noisy rules"
          subtitle={`${metrics.noisy_rules.length} firing heavily`}
        >
          <div className="divide-y divide-border">
            {metrics.noisy_rules.slice(0, 10).map((r) => (
              <div
                key={r.rule_name}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <SevPill priority={r.severity} size="xs" />
                <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                  {r.rule_name}
                </span>
                <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                  {r.matches_24h.toLocaleString()} matches/24h
                </span>
              </div>
            ))}
          </div>
        </SubPanel>
      )}
    </>
  );
}

function EnrichmentDetail({
  metrics,
}: {
  metrics?: CollectedMetrics['enrichment'];
}) {
  if (!metrics) return <EmptyDetail label="enrichment" />;
  return (
    <>
      <MetricsGrid
        items={[
          {
            label: 'GeoIP fill',
            value: `${Math.round(metrics.geoip_fill_pct)}%`,
            tone: coverageTone(metrics.geoip_fill_pct),
          },
          {
            label: 'ASN fill',
            value: `${Math.round(metrics.asn_fill_pct)}%`,
            tone: coverageTone(metrics.asn_fill_pct),
          },
          {
            label: 'IOC hit rate',
            value: `${metrics.ioc_hit_pct.toFixed(2)}%`,
            tone: 'fg',
          },
          {
            label: 'Identity fill',
            value: `${Math.round(metrics.identity_fill_pct)}%`,
            tone: coverageTone(metrics.identity_fill_pct),
          },
        ]}
      />
      {metrics.per_source_coverage.length > 0 && (
        <SubPanel
          title="Per-source coverage"
          subtitle={`top ${metrics.per_source_coverage.length} sources by volume · last 24h`}
        >
          <div className="divide-y divide-border">
            {metrics.per_source_coverage.slice(0, 12).map((sv) => (
              <div
                key={sv.source_type}
                className="flex items-center gap-3 px-5 py-2.5 hover:bg-foreground/[.02]"
              >
                <span className="flex-1 truncate font-mono text-[12px] text-foreground">
                  {sv.source_type}
                </span>
                <span className="w-[80px] text-right font-mono text-[11px] tabular-nums text-muted-foreground">
                  {sv.total_events.toLocaleString()}
                </span>
                <CoverageCell label="geo" pct={sv.geoip_pct} />
                <CoverageCell label="ioc" pct={sv.ioc_pct} />
                <CoverageCell label="id" pct={sv.identity_pct} />
              </div>
            ))}
          </div>
        </SubPanel>
      )}
    </>
  );
}

function AlertingDetail({
  metrics,
}: {
  metrics?: CollectedMetrics['alerting'];
}) {
  if (!metrics) return <EmptyDetail label="alerting" />;
  const total = metrics.total_alerts_24h;
  const prior = metrics.total_alerts_prior_24h;
  const delta =
    prior > 0 ? Math.round(((total - prior) / prior) * 100) : null;
  return (
    <>
      <MetricsGrid
        items={[
          {
            label: 'Alerts / 24h',
            value: total.toLocaleString(),
            delta,
            tone: total === 0 && prior > 0 ? 'critical' : 'fg',
          },
          {
            label: 'MTTA',
            value:
              metrics.mean_mtta_minutes != null
                ? formatMinutes(metrics.mean_mtta_minutes)
                : '—',
            tone:
              metrics.mean_mtta_minutes == null
                ? 'fg-2'
                : metrics.mean_mtta_minutes > 240
                  ? 'critical'
                  : metrics.mean_mtta_minutes > 60
                    ? 'high'
                    : 'good',
          },
          {
            label: 'Webhook success',
            value:
              metrics.webhook_success_pct != null
                ? `${Math.round(metrics.webhook_success_pct)}%`
                : '—',
            tone:
              metrics.webhook_success_pct == null
                ? 'fg-2'
                : metrics.webhook_success_pct < 80
                  ? 'critical'
                  : metrics.webhook_success_pct < 95
                    ? 'high'
                    : 'good',
          },
          {
            label: 'Routing rules',
            value: `${metrics.active_routing_rules}`,
            tone: metrics.active_routing_rules > 0 ? 'good' : 'medium',
          },
        ]}
      />
      {metrics.by_status.length > 0 && (
        <SubPanel title="Alerts by status" subtitle="last 24h">
          <div className="flex flex-wrap gap-2 px-5 py-3">
            {metrics.by_status.map((s) => (
              <div
                key={s.status}
                className="flex items-center gap-2 rounded border border-border bg-foreground/5 px-2.5 py-1"
              >
                <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  {s.status}
                </span>
                <span className="font-mono text-[12px] font-semibold tabular-nums text-foreground">
                  {s.count}
                </span>
              </div>
            ))}
          </div>
        </SubPanel>
      )}
      <SubPanel title="Routing & delivery" subtitle="current state">
        <div className="grid grid-cols-2 gap-4 px-5 py-3 text-[12px] md:grid-cols-4">
          <div>
            <Eyebrow2>Active webhooks</Eyebrow2>
            <div className="mt-1 font-mono text-[16px] font-semibold tabular-nums text-foreground">
              {metrics.active_webhooks}
            </div>
          </div>
          <div>
            <Eyebrow2>Deliveries / 24h</Eyebrow2>
            <div className="mt-1 font-mono text-[16px] font-semibold tabular-nums text-foreground">
              {metrics.webhook_deliveries_24h.toLocaleString()}
            </div>
          </div>
          <div>
            <Eyebrow2>Routing rules</Eyebrow2>
            <div className="mt-1 font-mono text-[16px] font-semibold tabular-nums text-foreground">
              {metrics.active_routing_rules}
            </div>
          </div>
          <div>
            <Eyebrow2>Prior 24h volume</Eyebrow2>
            <div className="mt-1 font-mono text-[16px] font-semibold tabular-nums text-muted-foreground">
              {prior.toLocaleString()}
            </div>
          </div>
        </div>
      </SubPanel>
    </>
  );
}

function EmptyDetail({ label }: { label: string }) {
  return (
    <div className="px-5 py-8 text-center text-[12.5px] text-muted-foreground">
      No {label} metrics in the latest report.
    </div>
  );
}

interface MetricSpec {
  label: string;
  value: string;
  delta?: number | null;
  tone: Tone;
}

function MetricsGrid({ items }: { items: MetricSpec[] }) {
  return (
    <div className="grid grid-cols-4 border-b border-border">
      {items.map((m, i) => (
        <div
          key={m.label}
          className={cn(
            'px-4 py-3.5',
            i < items.length - 1 && 'border-r border-border',
          )}
        >
          <Eyebrow2>{m.label}</Eyebrow2>
          <div
            className={cn(
              'mt-1.5 font-semibold tabular-nums',
              TONE_FG[m.tone],
            )}
            style={{ fontSize: '20px', lineHeight: '1.05' }}
          >
            {m.value}
          </div>
          {m.delta != null && (
            <div
              className={cn(
                'mt-1 font-mono text-[10.5px]',
                m.delta < 0
                  ? 'text-red-400'
                  : m.delta > 0
                    ? 'text-emerald-400'
                    : 'text-muted-foreground',
              )}
            >
              {signed(m.delta)} · 24h
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function deltaTone(delta: number | null | undefined): Tone {
  if (delta == null) return 'fg-2';
  if (delta < -50) return 'critical';
  if (delta < -10) return 'high';
  if (delta < 0) return 'medium';
  return 'good';
}

function coverageTone(pct: number | null): Tone {
  if (pct == null) return 'fg-2';
  if (pct >= 80) return 'good';
  if (pct >= 50) return 'medium';
  return 'high';
}

function CoverageCell({ label, pct }: { label: string; pct: number }) {
  const tone = coverageTone(pct);
  return (
    <div className="flex items-center gap-1.5">
      <span className="font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground/70">
        {label}
      </span>
      <span
        className={cn(
          'w-[34px] text-right font-mono text-[11px] tabular-nums',
          TONE_FG[tone],
        )}
      >
        {Math.round(pct)}%
      </span>
    </div>
  );
}

function SubPanel({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="border-b border-border last:border-b-0">
      <div className="flex items-center gap-2 border-b border-border bg-card/40 px-5 py-3">
        <Eyebrow2>{title}</Eyebrow2>
        {subtitle && (
          <>
            <span className="font-mono text-[10px] text-muted-foreground/40">
              ·
            </span>
            <span className="font-mono text-[10.5px] text-muted-foreground">
              {subtitle}
            </span>
          </>
        )}
      </div>
      {children}
    </div>
  );
}

/* ============================================================================
   PAGE
   ============================================================================ */

export function SiemHealth() {
  useDocumentTitle('SIEM Health');
  useBreadcrumbTitle('SIEM Health');

  const queryClient = useQueryClient();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const isAdmin = hasPermission('settings:system');

  const { data: report, isLoading } = useQuery({
    queryKey: ['siem-health', 'latest'],
    queryFn: () => api.getSiemHealthLatest(),
    retry: false,
  });

  const triggerMutation = useMutation({
    mutationFn: () => api.triggerSiemHealthCheck(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['siem-health'] });
    },
  });

  // NAN-615: load active finding suppressions so we can hide already-judged
  // findings from the rendered list and let admins manage them inline.
  const { data: suppressionsResp } = useQuery({
    queryKey: ['siem-health', 'suppressions'],
    queryFn: () => api.siemHealth.listSuppressions(false),
    retry: false,
  });
  const suppressions = useMemo(
    () => suppressionsResp?.suppressions ?? [],
    [suppressionsResp]
  );
  const suppressedTitles = useMemo(
    () => new Set(suppressions.map((s) => s.title)),
    [suppressions]
  );

  const suppressMutation = useMutation({
    mutationFn: ({ title, reason }: { title: string; reason: string }) =>
      api.siemHealth.createSuppression(title, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['siem-health', 'suppressions'],
      });
    },
    onError: () => {
      toast({
        title: 'Could not suppress finding',
        description: 'Try again, or contact an admin if the issue persists.',
        variant: 'destructive',
      });
    },
  });

  const undoSuppressionMutation = useMutation({
    mutationFn: (id: string) => api.siemHealth.deactivateSuppression(id),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['siem-health', 'suppressions'],
      });
    },
    onError: () => {
      toast({
        title: 'Could not re-enable finding',
        description: 'Try again, or contact an admin if the issue persists.',
        variant: 'destructive',
      });
    },
  });

  const [activeStage, setActiveStage] = useState<StageId>('ingestion');

  const stages = useMemo(() => buildStages(report), [report]);
  const overallTone: Tone = report
    ? statusFromScore(report.overall_score) === 'ok'
      ? 'good'
      : statusFromScore(report.overall_score) === 'idle'
        ? 'medium'
        : statusFromScore(report.overall_score) === 'degraded'
          ? 'high'
          : 'critical'
    : 'fg-2';
  const overallStatus: StageStatus = report
    ? statusFromScore(report.overall_score)
    : 'unknown';
  const activeStageView =
    stages.find((s) => s.id === activeStage) ?? stages[0];

  /* ---- Loading ---- */
  if (isLoading) {
    return (
      <div className="flex flex-col px-6 pt-5 pb-6">
        <div className="flex items-end gap-3">
          <div>
            <Eyebrow icon={HeartPulse}>SIEM health</Eyebrow>
            <h1 className="mt-1 text-[20px] font-semibold tracking-[-0.015em] text-foreground">
              Loading latest health report…
            </h1>
          </div>
        </div>
        <div className="mt-8 flex items-center justify-center py-16">
          <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  /* ---- No report yet ---- */
  if (!report) {
    return (
      <div className="flex flex-col px-6 pt-5 pb-6">
        <div className="flex items-end gap-3">
          <div className="min-w-0">
            <Eyebrow icon={HeartPulse}>SIEM health</Eyebrow>
            <h1 className="mt-1 text-[20px] font-semibold tracking-[-0.015em] text-foreground">
              No health reports yet
            </h1>
            <p className="mt-0.5 text-[12px] text-muted-foreground">
              Health checks run automatically every 12 hours.
              {isAdmin ? ' You can also trigger one manually below.' : ''}
            </p>
          </div>
        </div>
        <div className="mt-8 rounded-xl border border-border bg-card px-6 py-12 text-center">
          <HeartPulse className="mx-auto mb-3 h-8 w-8 text-muted-foreground/40" />
          <p className="text-[13px] text-foreground">
            Once a health check completes, this page will surface ingestion,
            parsing, and detection signals across the pipeline.
          </p>
          {isAdmin && (
            <button
              type="button"
              onClick={() => triggerMutation.mutate()}
              disabled={triggerMutation.isPending}
              className="mt-4 inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-[11.5px] font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60"
            >
              <RefreshCw
                className={cn(
                  'h-[12px] w-[12px]',
                  triggerMutation.isPending && 'animate-spin',
                )}
              />
              {triggerMutation.isPending
                ? 'Running…'
                : 'Run first health check'}
            </button>
          )}
        </div>
      </div>
    );
  }

  /* ---- Populated ---- */
  // NAN-1007: UTC formatting to match the rest of the platform
  // (case detail, log sources, etc.) — analysts work across timezones.
  const checkedAt = new Date(report.created_at)
    .toISOString()
    .replace('T', ' ')
    .slice(0, 19) + ' UTC';
  const overallLabel =
    overallStatus === 'ok'
      ? 'healthy'
      : overallStatus === 'idle'
        ? 'warming'
        : overallStatus === 'degraded'
          ? 'degraded'
          : overallStatus === 'down'
            ? 'silent'
            : '—';

  return (
    <div className="flex flex-col px-6 pt-5 pb-6">
      {/* Header */}
      <div className="flex items-end justify-between gap-4">
        <div className="flex min-w-0 items-center gap-4">
          <ScoreDial value={report.overall_score} tone={overallTone} size={84} />
          <div>
            <Eyebrow icon={HeartPulse}>SIEM health</Eyebrow>
            <h1 className="mt-1 flex items-center gap-2.5 text-[20px] font-semibold tracking-[-0.015em] text-foreground">
              Pipeline is{' '}
              <span className={TONE_FG[overallTone]}>{overallLabel}</span>
              <StatusPill status={overallStatus} />
            </h1>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-[12px] text-muted-foreground">
              <span>
                Score{' '}
                <span className="font-mono tabular-nums text-foreground">
                  {report.overall_score}
                </span>
              </span>
              <span className="text-muted-foreground/40">·</span>
              <span className="flex items-center gap-1 font-mono">
                <Clock className="h-3 w-3" />
                {checkedAt}
              </span>
              {report.duration_ms != null && (
                <>
                  <span className="text-muted-foreground/40">·</span>
                  <span className="font-mono">
                    completed in{' '}
                    <span className="text-foreground">
                      {report.duration_ms}ms
                    </span>
                  </span>
                </>
              )}
            </p>
          </div>
        </div>
        {isAdmin && (
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={() => triggerMutation.mutate()}
              disabled={triggerMutation.isPending}
              className="flex h-8 items-center gap-1.5 rounded-md bg-primary px-3 text-[11.5px] font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-60"
            >
              <RefreshCw
                className={cn(
                  'h-[12px] w-[12px]',
                  triggerMutation.isPending && 'animate-spin',
                )}
              />
              {triggerMutation.isPending ? 'Running…' : 'Run health check'}
            </button>
          </div>
        )}
      </div>

      {/* Pipeline spine */}
      <div className="mt-4">
        <PipelineSpine
          stages={stages}
          activeId={activeStage}
          onSelect={setActiveStage}
        />
      </div>

      {/* Two-up: narrative + recommendations */}
      <div
        className="mt-4 grid gap-4"
        style={{
          gridTemplateColumns: 'minmax(0, 1.6fr) minmax(0, 1fr)',
        }}
      >
        <Narrative
          summary={report.summary}
          asOf={checkedAt}
          loading={triggerMutation.isPending}
          onRefresh={() => triggerMutation.mutate()}
        />
        <Recommendations
          items={report.recommendations}
          suppressedTitles={suppressedTitles}
          suppressions={suppressions}
          canManage={isAdmin}
          isMutating={
            suppressMutation.isPending || undoSuppressionMutation.isPending
          }
          onSuppress={(title, reason) =>
            suppressMutation.mutate({ title, reason })
          }
          onUndo={(id) => undoSuppressionMutation.mutate(id)}
        />
      </div>

      {/* Stage detail */}
      <div className="mt-4">
        {activeStageView && (
          <StageDetail stage={activeStageView} report={report} />
        )}
      </div>

      {/* Footer hint */}
      <div className="mt-3 flex items-center font-mono text-[10.5px] tabular-nums text-muted-foreground">
        health checks run every{' '}
        <span className="px-1 text-foreground">12h</span>
        <span className="mx-2 text-muted-foreground/40">·</span>
        narrative regenerated when scores change materially
        <span className="flex-1" />
        <span>click a stage to drill in</span>
      </div>
    </div>
  );
}

export { SiemHealth as default };
