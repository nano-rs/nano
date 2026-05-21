// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-506 — alert detail hero. Mirrors design-ref/matches.html via
// MatchesHero density (title row + 4-tile analytics strip), adapted for the
// single-alert surface: trigger summary, triage state, top entities,
// detection context. No 28d heat / hourly strips — those are rule-scoped.

import { useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Bell,
  BookOpen,
  Clock,
  ExternalLink,
  Pause,
  Play,
  Users,
  Zap,
} from 'lucide-react';
import type { DetectionRule } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import {
  SEV_META,
  classifyLatency,
  eventLatency,
  extractEventTime,
  extractEntity,
  formatLatency,
  normalizeSeverity,
  primaryTactic,
  primaryTechnique,
  type Latency,
} from '@/components/matches/helpers';
import { LatencyPill } from '@/components/matches/LatencyPill';

interface AlertHeroAlert {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: string;
  status: 'open' | 'acknowledged' | 'closed';
  disposition?: 'true_positive' | 'false_positive' | 'benign';
  matchedEventCount: number;
  matchedEvents: Record<string, unknown>[];
  timestamp: Date;
  acknowledgedAt?: Date;
  acknowledgedBy?: string;
  closedAt?: Date;
  closedBy?: string;
  triageVerdict?: string;
}

interface AlertHeroProps {
  alert: AlertHeroAlert;
  rule: DetectionRule | null;
  linkedNotebookCount: number;
}

const VERDICT_LABEL: Record<string, string> = {
  true_positive: 'True positive',
  likely_true_positive: 'Likely TP',
  false_positive: 'False positive',
  likely_false_positive: 'Likely FP',
  needs_investigation: 'Needs review',
  benign: 'Benign',
};

const VERDICT_TONE: Record<string, string> = {
  true_positive: 'var(--destructive)',
  likely_true_positive: 'var(--destructive)',
  false_positive: 'var(--success)',
  likely_false_positive: 'var(--success)',
  needs_investigation: 'var(--warning)',
  benign: 'var(--muted-foreground)',
};

const DISPOSITION_LABEL: Record<string, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign',
};

function fmtTimeShort(d: Date): string {
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

export function AlertHero({
  alert,
  rule,
  linkedNotebookCount,
}: AlertHeroProps) {
  const navigate = useNavigate();
  // NAN-968: Back button uses browser-back when there's history (so analysts
  // return to whatever surface they came from — /alerts, /inbox, or a search
  // result), falling back to /alerts as the canonical alert queue.
  const handleBack = () => {
    // Note: local `window` var on line 136 shadows the global — use globalThis.
    if (globalThis.window?.history?.length > 1) {
      navigate(-1);
    } else {
      navigate('/alerts');
    }
  };
  const sev = SEV_META[normalizeSeverity(alert.severity)];
  const tactic = primaryTactic(rule);
  const technique = primaryTechnique(rule);

  const isOpen = alert.status === 'open';
  const isAcked = alert.status === 'acknowledged';
  const isClosed = alert.status === 'closed';

  const statusTone = isOpen
    ? 'var(--destructive)'
    : isAcked
      ? 'var(--warning)'
      : 'var(--success)';
  const statusLabel = isOpen ? 'Open' : isAcked ? 'Acknowledged' : 'Closed';

  // Per-event latency aggregates over the matched events.
  const latencies = useMemo<Latency[]>(() => {
    const out: Latency[] = [];
    for (const e of alert.matchedEvents || []) {
      const l = eventLatency(e, alert.timestamp);
      if (l && Number.isFinite(l.ms) && l.ms >= 0) out.push(l);
    }
    return out;
  }, [alert.matchedEvents, alert.timestamp]);

  const avgLatency = useMemo<Latency | null>(() => {
    if (latencies.length === 0) return null;
    const avg = latencies.reduce((a, b) => a + b.ms, 0) / latencies.length;
    return { ms: avg, level: classifyLatency(avg), formatted: formatLatency(avg) };
  }, [latencies]);

  // Event time window (first → last) when we can pull at least one timestamp.
  const window = useMemo(() => {
    const ts: number[] = [];
    for (const e of alert.matchedEvents || []) {
      const t = extractEventTime(e);
      if (t) ts.push(t.getTime());
    }
    if (ts.length === 0) return null;
    const first = new Date(Math.min(...ts));
    const last = new Date(Math.max(...ts));
    return { first, last, durationMs: last.getTime() - first.getTime() };
  }, [alert.matchedEvents]);

  // Top entities derived from the matched events. Counts unique identities.
  const topEntities = useMemo(() => {
    const m = new Map<string, { label: string; type: string; count: number }>();
    for (const e of alert.matchedEvents || []) {
      const ent = extractEntity([e]);
      if (ent.id === 'unknown') continue;
      const cur = m.get(ent.id);
      if (cur) cur.count += 1;
      else m.set(ent.id, { label: ent.label, type: ent.type, count: 1 });
    }
    return [...m.entries()]
      .map(([id, v]) => ({ id, ...v }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [alert.matchedEvents]);

  return (
    <div className="flex flex-col gap-2.5">
      {/* Title row */}
      <div className="flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              type="button"
              onClick={handleBack}
              className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1 h-6 px-1.5 rounded hover:bg-foreground/5"
            >
              <ArrowLeft className="w-3 h-3" strokeWidth={2} />
              Back
            </button>
            <span className="text-muted-foreground/60">/</span>

            <div className="flex items-center gap-1.5">
              <span
                className={cn(
                  'w-[6px] h-[6px] rounded-full',
                  isOpen && 'animate-pulse',
                )}
                style={{ background: statusTone }}
              />
              <span className="text-[11px] text-foreground">{statusLabel}</span>
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
            {alert.ruleName}
          </h1>
          <p className="text-[12px] text-muted-foreground mt-1.5 max-w-[720px] leading-[1.55]">
            Alert triggered on {fmtTimeShort(alert.timestamp)} ·{' '}
            {alert.matchedEventCount} matched event{alert.matchedEventCount === 1 ? '' : 's'}
          </p>

          <div className="mt-2 flex items-center gap-3 font-mono text-[10.5px] text-muted-foreground flex-wrap">
            <span>
              alert: <span className="text-foreground">{alert.id}</span>
            </span>
            <span className="text-muted-foreground/60">·</span>
            <span>
              rule: <span className="text-foreground">{alert.ruleId}</span>
            </span>
            {rule?.author && (
              <>
                <span className="text-muted-foreground/60">·</span>
                <span>
                  owner: <span className="text-foreground">{rule.author}</span>
                </span>
              </>
            )}
            {rule?.schedule_cron && (
              <>
                <span className="text-muted-foreground/60">·</span>
                <span>
                  schedule: <span className="text-foreground">{rule.schedule_cron}</span>
                </span>
              </>
            )}
          </div>
        </div>

      </div>

      {/* Analytics strip — 4 tiles */}
      <div className="rounded-lg border border-border overflow-hidden bg-card">
        <div className="grid grid-cols-[1.1fr_1.4fr_1.4fr_1fr] @max-[1100px]:grid-cols-2 @max-[640px]:grid-cols-1 divide-x divide-border @max-[1100px]:divide-x-0 @max-[1100px]:divide-y">
          {/* Tile 1 — Trigger summary */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Zap className="w-3 h-3" strokeWidth={2} />
              Trigger summary
            </div>
            <div className="mt-1.5 flex items-baseline gap-1.5">
              <span className="text-[26px] font-semibold text-foreground tabular-nums leading-none">
                {alert.matchedEventCount.toLocaleString()}
              </span>
              <span className="text-[11px] text-muted-foreground">
                event{alert.matchedEventCount === 1 ? '' : 's'}
              </span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <span className="text-[10.5px] text-muted-foreground">Avg latency</span>
              {avgLatency ? (
                <LatencyPill latency={avgLatency} />
              ) : (
                <span className="text-foreground/50 font-mono text-[10.5px]">—</span>
              )}
            </div>
            {window && (
              <div className="mt-1.5 font-mono text-[10px] text-muted-foreground">
                <div className="flex items-center justify-between">
                  <span>first event</span>
                  <span className="text-foreground">{window.first.toISOString().slice(11, 19)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>last event</span>
                  <span className="text-foreground">{window.last.toISOString().slice(11, 19)}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>span</span>
                  <span className="text-foreground tabular-nums">
                    {window.durationMs > 0 ? formatLatency(window.durationMs) : '—'}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Tile 2 — Triage state */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Clock className="w-3 h-3" strokeWidth={2} />
              Triage
            </div>
            <div className="mt-1.5 flex items-center gap-1.5">
              <span className="w-[6px] h-[6px] rounded-full" style={{ background: statusTone }} />
              <span className="text-[14px] text-foreground capitalize">{statusLabel}</span>
            </div>

            {alert.triageVerdict && (
              <div className="mt-2 flex items-center gap-2 text-[10.5px]">
                <span className="text-muted-foreground">AI verdict</span>
                <span
                  className="font-mono uppercase tracking-[0.08em] text-[9.5px] font-semibold px-1.5 py-[1px] rounded-sm"
                  style={{
                    background: `color-mix(in srgb, ${VERDICT_TONE[alert.triageVerdict] ?? 'var(--muted-foreground)'} 14%, transparent)`,
                    color: VERDICT_TONE[alert.triageVerdict] ?? 'var(--muted-foreground)',
                  }}
                >
                  {VERDICT_LABEL[alert.triageVerdict] ?? alert.triageVerdict}
                </span>
              </div>
            )}

            <div className="mt-2 flex flex-col gap-1 font-mono text-[10.5px]">
              {alert.acknowledgedAt && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">acked</span>
                  <span className="text-foreground tabular-nums truncate">
                    {alert.acknowledgedAt.toISOString().slice(0, 19).replace('T', ' ')}
                  </span>
                </div>
              )}
              {alert.acknowledgedBy && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">by</span>
                  <span className="text-foreground truncate">{alert.acknowledgedBy}</span>
                </div>
              )}
              {alert.closedAt && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">closed</span>
                  <span className="text-foreground tabular-nums truncate">
                    {alert.closedAt.toISOString().slice(0, 19).replace('T', ' ')}
                  </span>
                </div>
              )}
              {alert.closedBy && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">by</span>
                  <span className="text-foreground truncate">{alert.closedBy}</span>
                </div>
              )}
              {isClosed && alert.disposition && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">disposition</span>
                  <span className="text-foreground">
                    {DISPOSITION_LABEL[alert.disposition] ?? alert.disposition}
                  </span>
                </div>
              )}
              {!alert.acknowledgedAt && !alert.closedAt && (
                <div className="text-muted-foreground/60">No triage actions yet.</div>
              )}
            </div>
          </div>

          {/* Tile 3 — Top entities */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Users className="w-3 h-3" strokeWidth={2} />
              Top identities
              <span className="ml-auto font-normal text-muted-foreground/70 normal-case tracking-normal text-[10.5px]">
                {topEntities.length} unique
              </span>
            </div>
            <div className="mt-2 flex flex-col gap-1.5">
              {topEntities.length === 0 ? (
                <div className="text-[10.5px] text-muted-foreground/70 font-mono py-2">
                  No entities resolved from events.
                </div>
              ) : (
                topEntities.map((ent) => {
                  const max = topEntities[0].count;
                  const width = (ent.count / max) * 100;
                  const typeDot =
                    ent.type === 'role' ? 'bg-warning'
                    : ent.type === 'service' ? 'bg-primary'
                    : 'bg-muted-foreground';
                  return (
                    <div
                      key={ent.id}
                      className="flex items-center gap-2 text-[11px] -mx-1 px-1 rounded"
                    >
                      <span className={cn('w-[5px] h-[5px] rounded-full shrink-0', typeDot)} />
                      <span className="font-mono text-foreground w-[130px] truncate">
                        {ent.label}
                      </span>
                      <div
                        className="flex-1 h-[5px] rounded-full overflow-hidden relative"
                        style={{ background: 'color-mix(in srgb, var(--foreground) 6%, transparent)' }}
                      >
                        <div
                          className="h-full rounded-full transition-all"
                          style={{ width: `${width}%`, background: 'var(--primary)' }}
                        />
                      </div>
                      <span className="font-mono text-foreground tabular-nums w-[42px] text-right">
                        {ent.count}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Tile 4 — Detection context */}
          <div className="p-3.5 flex flex-col">
            <div className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              <Bell className="w-3 h-3" strokeWidth={2} />
              Detection context
            </div>
            {rule ? (
              <div className="mt-2 flex flex-col gap-1.5 font-mono text-[10.5px]">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">mode</span>
                  <span className="text-foreground inline-flex items-center gap-1">
                    {rule.mode === 'paused'
                      ? <Pause className="w-3 h-3" strokeWidth={2} />
                      : <Play className="w-3 h-3" strokeWidth={2} />}
                    {rule.mode}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">severity</span>
                  <span className="text-foreground">{rule.severity}</span>
                </div>
                {rule.lookback_minutes != null && (
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-muted-foreground">lookback</span>
                    <span className="text-foreground">{rule.lookback_minutes}m</span>
                  </div>
                )}
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground">linked notebooks</span>
                  <span className="text-foreground inline-flex items-center gap-1 tabular-nums">
                    <BookOpen className="w-3 h-3" strokeWidth={2} />
                    {linkedNotebookCount}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 pt-1">
                  <Link
                    to={`/rules/${alert.ruleId}`}
                    className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
                  >
                    Open rule
                    <ExternalLink className="w-3 h-3" strokeWidth={2} />
                  </Link>
                </div>
              </div>
            ) : (
              <div className="mt-2 text-[10.5px] text-muted-foreground/70 font-mono">
                Loading rule context…
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
