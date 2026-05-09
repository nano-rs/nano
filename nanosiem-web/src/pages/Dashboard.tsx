// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Home page (NAN-370)
 *
 * Ported from design-ref/shadcn/home-view.jsx. Real-data SIEM home:
 *  - 4-card pulse strip (state of the house)
 *  - Hero with greeting + PIVT intake + suggestion chips (preserved from
 *    the prior "AI Concierge" implementation — types text, AI routes to
 *    a notebook or search)
 *  - Two columns: My Work (cases, notebooks) + Fleet signal (audit feed,
 *    noisy rules)
 *  - Ingest sparkline + team activity feed
 *
 * Tokens: new kit palette (NAN-369). Mono is intentional for IDs, counts,
 * timestamps, and rule names — it's part of the visual language.
 */

import { useState, useRef, useEffect, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight,
  Loader2,
  ArrowUpRight,
  ChevronRight,
  Sparkles,
  Clock,
  Edit3,
  LineChart,
  GitBranch,
  BookOpen,
  ActivitySquare,
} from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { QuickPivotIntake } from '@/components/dashboard/QuickPivotIntake';
import {
  useMelodStatus,
  useMyCases,
  useUnassignedCases,
  useRecentNotebooks,
  useSiemHealthLatest,
  useDetectionHealthSummary,
  useNoisyRules,
  useIngestionHistory,
  useAuditLog,
} from '@/hooks/use-api';
import { useMitreCoverage } from '@/hooks/useMitreData';
import {
  PIVT_CHAT_MESSAGE_EVENT,
  type PivtChatMessageDetail,
} from '@/enterprise/components/pivt/commands/router';
import type { CaseSummary, NotebookSummary, AuditLogEntry, NoisyRule } from '@/lib/api';
import { HomeDemoHint } from '@/components/DemoHints';
import { cn } from '@/lib/utils';

// ============================================================================
// Helpers
// ============================================================================

function formatCompactAge(dateLike: string | Date): string {
  const date = typeof dateLike === 'string' ? new Date(dateLike) : dateLike;
  const diffMs = Date.now() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'now';
  if (diffMins < 60) return `${diffMins}m`;
  if (diffHours < 24) return `${diffHours}h`;
  if (diffDays < 30) return `${diffDays}d`;
  return `${Math.floor(diffDays / 30)}mo`;
}

type Tone = 'good' | 'attention' | 'warn' | 'danger' | 'neutral';

const toneBg: Record<Tone, string> = {
  good: 'bg-[color-mix(in_srgb,var(--success)_10%,transparent)] text-[var(--success)] border-[color-mix(in_srgb,var(--success)_30%,transparent)]',
  attention: 'bg-primary/10 text-primary border-primary/30',
  warn: 'bg-[color-mix(in_srgb,var(--warning)_12%,transparent)] text-[var(--warning)] border-[color-mix(in_srgb,var(--warning)_30%,transparent)]',
  danger: 'bg-destructive/12 text-destructive border-destructive/30',
  neutral: 'bg-[var(--card-2)] text-muted-foreground border-border',
};

const toneDot: Record<Tone, string> = {
  good: 'bg-[var(--success)]',
  attention: 'bg-primary',
  warn: 'bg-[var(--warning)]',
  danger: 'bg-destructive',
  neutral: 'bg-muted-foreground',
};

const sevAccent: Record<string, string> = {
  critical: 'border-l-destructive',
  high: 'border-l-[var(--warning)]',
  medium: 'border-l-primary',
  low: 'border-l-muted-foreground',
};

// ============================================================================
// Pulse strip (4 cards at top)
// ============================================================================

interface Pulse {
  id: string;
  label: string;
  value: string | number;
  unit?: string;
  status: Tone;
  delta: string;
  hint: string;
  href?: string;
}

function PulseCard({ p }: { p: Pulse }) {
  const toneCls = toneBg[p.status];
  const className = 'group relative rounded-lg border border-border/60 bg-card px-3.5 py-3 flex flex-col gap-1.5 hover:border-[var(--border-2)] transition-colors min-h-[84px]';
  const body = (
    <>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={cn('w-1.5 h-1.5 rounded-full', toneDot[p.status])} />
          <span className="text-[11px] uppercase tracking-[0.08em] text-muted-foreground font-medium">{p.label}</span>
        </div>
        <ArrowUpRight className="w-3 h-3 text-muted-foreground/60 group-hover:text-muted-foreground transition-colors" />
      </div>
      <div className="flex items-baseline gap-1.5 mt-0.5">
        <span className="text-[22px] text-foreground font-semibold leading-none tracking-tight">{p.value}</span>
        {p.unit && <span className="text-[11px] text-muted-foreground">{p.unit}</span>}
      </div>
      <div className="flex items-center gap-1.5 mt-auto">
        <span className={cn('inline-flex items-center rounded-sm px-1.5 py-0.5 text-[10px] font-mono border', toneCls)}>
          {p.delta}
        </span>
      </div>
      <div className="text-[10.5px] text-muted-foreground/80 leading-snug mt-0.5">{p.hint}</div>
    </>
  );
  return p.href
    ? <Link to={p.href} className={className}>{body}</Link>
    : <div className={className}>{body}</div>;
}

// Stable empty CoverageFilters so useMitreCoverage's effect deps don't churn.
const NO_COVERAGE_FILTERS = { severity: [], mode: [] };

function PulseStrip() {
  const { data: myCases } = useMyCases(20);
  const { data: health } = useDetectionHealthSummary();
  const { data: siemHealth } = useSiemHealthLatest();
  const { data: coverage } = useMitreCoverage(NO_COVERAGE_FILTERS);

  const forYouCount = (myCases?.length ?? 0) + (health?.needs_tuning ?? 0);

  const ingestStatus: Tone = siemHealth?.overall_status === 'healthy' ? 'good'
    : siemHealth?.overall_status === 'degraded' ? 'warn'
    : siemHealth?.overall_status ? 'danger' : 'neutral';

  const detStatus: Tone = (health?.noisy_count ?? 0) + (health?.silent_count ?? 0) > 0 ? 'warn' : 'good';

  // MITRE coverage roll-up: count tactics with at least one uncovered
  // technique + techniques with zero rules. Tone is `good` when fully
  // covered, `warn` for partial gaps, `danger` for >5 uncovered tactics.
  const uncoveredTactics = useMemo(
    () => (coverage?.tactics ?? []).filter((t) => t.covered_techniques < t.total_techniques),
    [coverage]
  );
  const uncoveredTechniques = useMemo(
    () => (coverage?.techniques ?? []).filter((t) => t.rule_count === 0).length,
    [coverage]
  );
  const coverageStatus: Tone = !coverage
    ? 'neutral'
    : uncoveredTactics.length === 0
    ? 'good'
    : uncoveredTactics.length > 5
    ? 'danger'
    : 'warn';
  const coverageDelta = !coverage
    ? '—'
    : uncoveredTactics.length === 0
    ? `${coverage.summary.covered_techniques}/${coverage.summary.total_techniques} techniques`
    : `${uncoveredTactics
        .slice(0, 3)
        .map((t) => t.tactic_name)
        .join(', ')}${uncoveredTactics.length > 3 ? ` +${uncoveredTactics.length - 3}` : ''}`;
  const coverageHint = !coverage
    ? 'click to explore gaps'
    : uncoveredTechniques === 0
    ? 'every technique has a live rule'
    : `${uncoveredTechniques} technique${uncoveredTechniques === 1 ? '' : 's'} with no live rule`;

  const pulses: Pulse[] = [
    {
      id: 'mine',
      label: 'For you today',
      value: forYouCount,
      unit: 'items',
      status: forYouCount > 0 ? 'attention' : 'neutral',
      delta: `${myCases?.length ?? 0} cases, ${health?.needs_tuning ?? 0} tuning`,
      hint: forYouCount === 0 ? 'nothing needs your attention' : 'click to open your queue',
      href: '/cases?filter=my',
    },
    {
      id: 'ingest',
      label: 'Ingest',
      value: siemHealth?.overall_status
        ? siemHealth.overall_status.charAt(0).toUpperCase() + siemHealth.overall_status.slice(1)
        : '—',
      status: ingestStatus,
      delta: siemHealth ? `${Math.round(siemHealth.ingestion_score)}% ingestion score` : '—',
      hint: 'log source health',
      href: '/ingestion/log-sources',
    },
    {
      id: 'detections',
      label: 'Detection health',
      value: health ? `${health.noisy_count + health.silent_count} need tuning` : '—',
      status: detStatus,
      delta: health ? `${health.noisy_count} noisy · ${health.silent_count} silent >7d` : '—',
      hint: 'click to open triage queue',
      href: '/rules/tuning',
    },
    {
      id: 'coverage',
      label: 'MITRE coverage',
      value: coverage ? uncoveredTactics.length : '—',
      unit: coverage ? (uncoveredTactics.length === 1 ? 'tactic uncovered' : 'tactics uncovered') : undefined,
      status: coverageStatus,
      delta: coverageDelta,
      hint: coverageHint,
      href: '/rules/coverage',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
      {pulses.map((p) => (
        <PulseCard key={p.id} p={p} />
      ))}
    </div>
  );
}

// ============================================================================
// Hero (greeting + PIVT intake + chips) — preserved from prior implementation
// ============================================================================

function greetingFor() {
  const h = new Date().getHours();
  if (h < 5) return 'Up late';
  if (h < 12) return 'Good morning';
  if (h < 17) return 'Good afternoon';
  return 'Good evening';
}

function HeroIntake({ attentionCount }: { attentionCount: number | null }) {
  const navigate = useNavigate();
  const { hasPermission, user } = useAuth();
  const [input, setInput] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const { data: melodStatus } = useMelodStatus();

  const aiAvailable = melodStatus?.connected === true;
  const canViewCases = hasPermission('cases:view');
  const canSearch = hasPermission('search:view');
  const canCreateDetections = hasPermission('detections:create');
  const canUseAi = hasPermission('melod:notebook');

  const firstName = user?.name?.split(' ')[0] || '';

  useEffect(() => {
    const timer = setTimeout(() => inputRef.current?.focus(), 100);
    return () => clearTimeout(timer);
  }, []);

  // Accepts an override so "Catch me up" (and chips in future) can submit atomically
  // without racing against the input setState.
  //
  // AI path delegates to PIVT via `pivt:chat-message`. PivtPanelBody owns
  // the round trip (notebook create + chat poll + thread continuity) and
  // pops the panel open via its own `setOpen(true)` so the response
  // streams in visibly. Earlier this page reimplemented that flow inline
  // and silently fired the LLM behind a still-collapsed panel — the
  // analyst saw the input clear with no feedback.
  const submit = (overrideText?: string) => {
    const text = (overrideText ?? input).trim();
    if (!text || isProcessing) return;
    setInput(text);
    if (canUseAi && aiAvailable) {
      window.dispatchEvent(
        new CustomEvent<PivtChatMessageDetail>(PIVT_CHAT_MESSAGE_EVENT, {
          detail: { text },
        })
      );
      // Brief visual ack — the heavy lifting now happens inside PIVT,
      // so we just clear the input and let the panel surface progress.
      setIsProcessing(true);
      setInput('');
      setTimeout(() => setIsProcessing(false), 250);
      return;
    }
    if (canSearch) {
      navigate(`/search?q=${encodeURIComponent(text)}`);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  const chips: (string | null)[] = [
    canViewCases ? 'Catch me up on my open cases' : null,
    "What's been noisy in the last 24 hours?",
    canCreateDetections ? 'Help me write a new detection' : null,
    'Search for suspicious authentication activity',
  ];
  const suggestions = chips.filter((c): c is string => !!c);

  return (
    <div className="flex flex-col items-center gap-3 py-4">
      <div className="text-center">
        <div className="text-[22px] font-semibold tracking-tight text-foreground leading-none">
          {greetingFor()}{firstName ? `, ${firstName}` : ''}
        </div>
        <div className="text-[12.5px] text-muted-foreground mt-1.5">
          {attentionCount && attentionCount > 0 ? (
            <>
              {attentionCount} {attentionCount === 1 ? 'thing needs' : 'things need'} your attention today.{' '}
              <button
                onClick={() => submit('Catch me up on my open cases')}
                className="text-primary hover:underline"
                disabled={isProcessing}
              >
                Catch me up
              </button>
            </>
          ) : (
            'How can we start today?'
          )}
        </div>
      </div>

      <div className="w-full max-w-[640px]">
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <div className="px-3 py-1.5 border-b border-border flex items-center gap-2">
            <span className="text-[10px] uppercase tracking-[0.12em] font-medium text-primary">PIVT intake</span>
            <span className="text-muted-foreground/60">::</span>
            <span className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground">Notebook or Search</span>
            <span className="ml-auto text-[10px] font-mono text-muted-foreground/60">⌘K</span>
          </div>
          <div className="flex items-center gap-2 px-3 py-2.5">
            <div className="w-6 h-6 rounded-md bg-primary/15 flex items-center justify-center shrink-0">
              <PivtIcon className="h-3 w-3 text-primary" />
            </div>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask anything — investigate, search, hunt, detect…"
              disabled={isProcessing}
              rows={1}
              className="flex-1 bg-transparent text-foreground text-[13.5px] placeholder:text-muted-foreground/60 resize-none outline-none min-h-[20px] max-h-[120px] leading-5"
              style={{ fieldSizing: 'content' } as React.CSSProperties}
            />
            <button
              onClick={() => submit()}
              disabled={!input.trim() || isProcessing}
              className="w-7 h-7 rounded-md bg-primary/15 hover:bg-primary/25 flex items-center justify-center transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              {isProcessing ? <Loader2 className="w-3.5 h-3.5 text-primary animate-spin" /> : <ArrowRight className="w-3.5 h-3.5 text-primary" />}
            </button>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-1.5 justify-center max-w-[720px] mt-0.5">
        {suggestions.map((s) => (
          <button
            key={s}
            onClick={() => {
              setInput(s);
              inputRef.current?.focus();
            }}
            className="px-2.5 h-6 rounded-full border border-border bg-card hover:bg-[var(--card-2)] hover:border-[var(--border-2)] text-[11.5px] text-muted-foreground transition-colors"
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}

// ============================================================================
// Section header (eyebrow + count + action)
// ============================================================================

function SectionHead({
  eyebrow,
  count,
  action,
  href,
}: {
  eyebrow: string;
  count?: number;
  action?: string;
  href?: string;
}) {
  return (
    <div className="flex items-center gap-2 mb-2 px-0.5">
      <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">{eyebrow}</span>
      {count != null && (
        <span className="font-mono text-[10px] text-muted-foreground/60 tabular-nums">{count}</span>
      )}
      <div className="flex-1 h-px bg-border/60 mx-1" />
      {action && (
        <Link to={href || '#'} className="text-[10.5px] text-muted-foreground hover:text-foreground flex items-center gap-0.5">
          {action}
          <ChevronRight className="w-2.5 h-2.5" />
        </Link>
      )}
    </div>
  );
}

// ============================================================================
// My Work column
// ============================================================================

function CaseRow({ c, dense }: { c: CaseSummary; dense?: boolean }) {
  const sev = (c.severity ?? 'low').toLowerCase();
  const accent = sevAccent[sev] || sevAccent.low;
  return (
    <Link
      to={`/cases/${c.id}`}
      className={cn(
        'group grid gap-2 items-center border-l-2 border-y border-r border-border/50 rounded-r bg-card hover:border-[var(--border-2)] transition-colors grid-cols-[auto_1fr_auto] px-2.5',
        dense ? 'py-1.5' : 'py-2',
        accent,
      )}
    >
      <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">#{c.case_number}</span>
      <div className="min-w-0">
        <div className="text-[12.5px] text-foreground truncate leading-tight">{c.title}</div>
        <div className="text-[10.5px] text-muted-foreground mt-0.5 flex items-center gap-1.5">
          <span className="capitalize">{(c.status ?? '').replace('_', ' ') || 'open'}</span>
          <span className="text-muted-foreground/50">·</span>
          <span className="font-mono">{c.alert_count} alerts</span>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
          {formatCompactAge(c.last_activity_at || c.created_at)}
        </span>
        <ChevronRight className="w-3 h-3 text-muted-foreground/50 group-hover:text-muted-foreground transition-colors" />
      </div>
    </Link>
  );
}

function NotebookRow({ n }: { n: NotebookSummary }) {
  return (
    <Link
      to={`/notebooks/${n.id}`}
      className="group flex items-center gap-2 px-2.5 py-1.5 rounded border border-border/50 bg-card hover:border-[var(--border-2)] transition-colors"
    >
      <BookOpen className="w-3 h-3 text-muted-foreground shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="text-[12px] text-foreground truncate leading-tight">{n.title}</div>
        <div className="text-[10.5px] text-muted-foreground mt-0.5">
          <span>{n.entry_count} entries</span>
          <span className="text-muted-foreground/50 mx-1">·</span>
          <span>{formatCompactAge(n.updated_at)}</span>
        </div>
      </div>
      <ChevronRight className="w-3 h-3 text-muted-foreground/50 group-hover:text-muted-foreground transition-colors" />
    </Link>
  );
}

function MyWorkColumn() {
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  const canViewCases = hasPermission('cases:view') && capabilities.cases;
  const canViewNotebooks = hasPermission('notebooks:view') && capabilities.notebooks;

  const { data: myCases } = useMyCases(5);
  const { data: unassigned } = useUnassignedCases(5);
  const { data: notebooks } = useRecentNotebooks(3);

  const myList = (myCases ?? []).filter((c) => c.status !== 'resolved' && c.status !== 'closed');
  const unassignedList = unassigned ?? [];

  // Open-core builds with neither capability render nothing — drops the
  // empty column out of the dashboard grid entirely (FleetColumn fills the row).
  if (!canViewCases && !canViewNotebooks) return null;

  return (
    <div className="flex flex-col gap-4">
      {canViewCases && (
        <div>
          <SectionHead eyebrow="My cases" count={myList.length} action="view all" href="/cases?filter=my" />
          {myList.length === 0 ? (
            <div className="text-[11.5px] text-muted-foreground/70 px-1">No active cases assigned.</div>
          ) : (
            <div className="flex flex-col gap-1">
              {myList.map((c) => <CaseRow key={c.id} c={c} />)}
            </div>
          )}
        </div>
      )}

      {canViewCases && (
        <div>
          <SectionHead eyebrow="Unassigned" count={unassignedList.length} action="triage queue" href="/cases?status=open,in_progress,pending" />
          {unassignedList.length === 0 ? (
            <div className="text-[11.5px] text-muted-foreground/70 px-1">No unassigned cases.</div>
          ) : (
            <div className="flex flex-col gap-1">
              {unassignedList.map((c) => <CaseRow key={c.id} c={c} dense />)}
            </div>
          )}
        </div>
      )}

      {canViewNotebooks && (
        <div>
          <SectionHead eyebrow="Resume" count={notebooks?.length} action="all notebooks" href="/notebooks" />
          {!notebooks || notebooks.length === 0 ? (
            <div className="text-[11.5px] text-muted-foreground/70 px-1">No recent notebooks.</div>
          ) : (
            <div className="flex flex-col gap-1">
              {notebooks.map((n) => <NotebookRow key={n.id} n={n} />)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Fleet signal column
// ============================================================================

/** Map an audit log entry to a fleet-change visual kind. Best-effort pattern matching
 *  against source/action; extend as new event types land in the audit schema. */
function fleetKindFor(a: AuditLogEntry): { icon: typeof Sparkles; tone: string } {
  const action = (a.action ?? '').toLowerCase();
  const source = (a.source ?? '').toLowerCase();
  if (source === 'detection' && action.includes('tuning')) return { icon: Sparkles, tone: 'text-primary' };
  if (action.includes('silenc') || action.includes('paus')) return { icon: Clock, tone: 'text-[var(--warning)]' };
  if (action.includes('edit') || action.includes('update')) return { icon: Edit3, tone: 'text-muted-foreground' };
  if (source === 'coverage' || action.includes('coverage')) return { icon: LineChart, tone: 'text-[var(--success)]' };
  if (source.includes('repo')) return { icon: GitBranch, tone: 'text-muted-foreground' };
  return { icon: ActivitySquare, tone: 'text-muted-foreground/70' };
}

function FleetChangeRow({ a }: { a: AuditLogEntry }) {
  const { icon: Icon, tone } = fleetKindFor(a);
  return (
    <div className="group flex items-start gap-2.5 px-2.5 py-2 rounded border border-border/50 bg-card hover:border-[var(--border-2)] transition-colors">
      <div className={cn('w-6 h-6 rounded-md bg-[var(--card-2)] flex items-center justify-center shrink-0', tone)}>
        <Icon className="w-3 h-3" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="text-[12.5px] text-foreground leading-tight truncate">
            {a.resource_name || a.action || 'activity'}
          </span>
          <span className="font-mono text-[10px] text-muted-foreground/70 ml-auto shrink-0">
            {formatCompactAge(a.timestamp)}
          </span>
        </div>
        <div className="text-[10.5px] text-muted-foreground mt-0.5 truncate">
          <span className="font-mono">{a.user_name || a.source || 'system'}</span>
          {a.action && <><span className="text-muted-foreground/50 mx-1">·</span><span>{a.action}</span></>}
        </div>
      </div>
    </div>
  );
}

function NoisyRuleRow({ r }: { r: NoisyRule }) {
  const trendUp = r.trend === 'up';
  return (
    <Link
      to={`/rules/${r.rule_id}`}
      className="group flex items-center gap-2.5 px-2.5 py-1.5 hover:bg-[var(--card-2)] transition-colors"
    >
      <div className="flex-1 min-w-0">
        <div className="text-[12px] font-mono text-foreground truncate">{r.rule_name}</div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <span className="text-[10.5px] text-muted-foreground tabular-nums">
          <span className="font-mono">{r.match_count.toLocaleString()}</span>
          <span className="text-muted-foreground/60"> matches</span>
        </span>
        {trendUp && <ArrowUpRight className="w-2.5 h-2.5 text-[var(--warning)]" />}
      </div>
    </Link>
  );
}

function FleetColumn() {
  // "Fleet — last 24h": audit log tail of system-level changes. We can't perfectly
  // filter to rule-only events here without a richer API; surface everything recent
  // and let the visual kind heuristic classify.
  const since = useMemo(() => {
    const d = new Date();
    d.setHours(d.getHours() - 24);
    return d.toISOString();
  }, []);
  const { data: audit } = useAuditLog({ start_time: since, limit: 6 });
  const { data: noisy } = useNoisyRules(5);

  const changes = audit?.logs ?? [];
  const rules = noisy?.rules ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div>
        <SectionHead eyebrow="Fleet — last 24h" count={changes.length} action="activity log" href="/audit" />
        {changes.length === 0 ? (
          <div className="text-[11.5px] text-muted-foreground/70 px-1">No fleet activity in the last 24h.</div>
        ) : (
          <div className="flex flex-col gap-1">
            {changes.map((a) => <FleetChangeRow key={a.id} a={a} />)}
          </div>
        )}
      </div>

      <div>
        <SectionHead eyebrow="Noisiest rules" count={rules.length} action="tuning queue" href="/rules/tuning" />
        {rules.length === 0 ? (
          <div className="text-[11.5px] text-muted-foreground/70 px-1">No noisy rules right now.</div>
        ) : (
          <div className="rounded border border-border/50 bg-card divide-y divide-border/50">
            {rules.map((r) => <NoisyRuleRow key={r.rule_id} r={r} />)}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Ingest sparkline
// ============================================================================

function IngestSpark() {
  const { data: history } = useIngestionHistory(24);

  // Aggregate across source_types per hour so the bars represent total events/hour.
  const bars = useMemo(() => {
    if (!history || history.length === 0) return [] as { ts: string; count: number }[];
    const byHour = new Map<string, number>();
    for (const p of history) {
      const h = p.timestamp.slice(0, 13); // YYYY-MM-DDTHH
      byHour.set(h, (byHour.get(h) ?? 0) + p.count);
    }
    return Array.from(byHour.entries())
      .map(([ts, count]) => ({ ts, count }))
      .sort((a, b) => a.ts.localeCompare(b.ts))
      .slice(-24);
  }, [history]);

  const max = Math.max(1, ...bars.map((b) => b.count));
  const latest = bars[bars.length - 1]?.count ?? 0;
  const total = bars.reduce((s, b) => s + b.count, 0);

  return (
    <div className="rounded border border-border/50 bg-card px-3 py-2">
      <div className="flex items-baseline gap-2">
        <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Ingest · last 24h</span>
        <span className="ml-auto font-mono text-[10.5px] text-foreground/80 tabular-nums">
          {Math.round(latest / 60).toLocaleString()}/min
        </span>
      </div>
      <div className="flex items-end gap-[2px] h-[26px] mt-1.5">
        {bars.length === 0
          ? <div className="flex-1 text-[10.5px] text-muted-foreground/60">No data yet.</div>
          : bars.map((b) => (
            <div
              key={b.ts}
              className="flex-1 bg-[var(--success)]/70 rounded-sm min-h-[2px]"
              style={{ height: `${(b.count / max) * 100}%` }}
              title={`${b.ts} · ${b.count.toLocaleString()}`}
            />
          ))}
      </div>
      <div className="flex items-center gap-1.5 mt-1.5 text-[10.5px] text-muted-foreground">
        <span className="w-1 h-1 rounded-full bg-[var(--success)]" />
        <span>{bars.length}h window</span>
        <span className="text-muted-foreground/50">·</span>
        <span className="font-mono tabular-nums">{total.toLocaleString()} total events</span>
      </div>
    </div>
  );
}

// ============================================================================
// Activity feed
// ============================================================================

function ActivityRow({ a }: { a: AuditLogEntry }) {
  return (
    <div className="flex items-center gap-2 py-1.5 text-[11.5px]">
      <span className={cn('w-1 h-1 rounded-full shrink-0', a.success ? 'bg-[var(--success)]' : 'bg-destructive')} />
      <span className="font-mono text-muted-foreground/70 tabular-nums w-[38px] shrink-0">
        {formatCompactAge(a.timestamp)}
      </span>
      <span className="font-mono text-muted-foreground shrink-0 max-w-[120px] truncate">
        {a.user_name || 'system'}
      </span>
      <span className="shrink-0 text-foreground/90">{a.action || '—'}</span>
      <span className="text-muted-foreground truncate">{a.resource_name || ''}</span>
    </div>
  );
}

function ActivityFeed() {
  const { data: audit } = useAuditLog({ limit: 7 });
  const rows = audit?.logs ?? [];

  return (
    <div>
      <SectionHead eyebrow="Team activity" action="full audit log" href="/audit" />
      {rows.length === 0 ? (
        <div className="text-[11.5px] text-muted-foreground/70 px-1">No recent activity.</div>
      ) : (
        <div className="rounded border border-border/50 bg-card px-3 py-1 divide-y divide-border/60">
          {rows.map((a) => <ActivityRow key={a.id} a={a} />)}
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Page
// ============================================================================

export function Dashboard() {
  useDocumentTitle('Home');
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();

  // Attention count = current user's open cases. Drives the hero subtitle
  // ("N things need your attention today. Catch me up"). In open-core builds
  // (no cases capability) the count is null → the hero falls back to its
  // generic copy.
  const { data: myCases } = useMyCases(20);
  const attentionCount = capabilities.cases && myCases
    ? myCases.filter((c) => c.status !== 'resolved' && c.status !== 'closed').length
    : null;

  // MyWorkColumn renders null when neither cases nor notebooks is available;
  // collapse the two-column grid to single column so FleetColumn doesn't
  // float in column 1 with column 2 blank.
  const showMyWork =
    (hasPermission('cases:view') && capabilities.cases) ||
    (hasPermission('notebooks:view') && capabilities.notebooks);

  return (
    <div className="h-full overflow-y-auto scrollbar-thin">
      <div className="max-w-[1280px] mx-auto px-3 md:px-6 py-5 flex flex-col gap-5">
        <PulseStrip />
        {capabilities.melod
          ? <HeroIntake attentionCount={attentionCount} />
          : <QuickPivotIntake />}
        <div className={cn('grid grid-cols-1 gap-6 pt-2', showMyWork && 'md:grid-cols-2')}>
          {showMyWork && <MyWorkColumn />}
          <FleetColumn />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-[280px_1fr] gap-6 pt-2">
          <IngestSpark />
          <ActivityFeed />
        </div>
        <HomeDemoHint />
        <div className="h-4" />
      </div>
    </div>
  );
}
