// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-506 — alert detail redesign. Mirrors the Matches port density (11.5px
// body, 10.5px mono meta, 1px borders, no shadows) and reuses the matches/
// EventViewer + LatencyPill primitives. Single-alert surface (no list pane).
//
// NAN-746 (Phase 5 Stream B): the notebook tab + the meloD-gated AI summary
// flow are dropped — both were enterprise-only. The page now ships in core
// and is the canonical alert detail surface for open builds.

import { useEffect, useMemo } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Calendar,
  Code,
  ExternalLink,
  FileText,
  Loader2,
  Zap,
} from 'lucide-react';

import {
  fromApiAlert,
  useAlert,
  useDetection,
} from '@/hooks/use-api';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { useRecordActivity } from '@/hooks/useRecentActivity';
import { cn } from '@/lib/utils';
import { QueryHighlight } from '@/lib/syntax-highlight';

import { AlertHero } from '@/components/alerts/AlertHero';
import { MonitorAlertHero } from '@/components/alerts/MonitorAlertHero';
import { parseMonitorAlert } from '@/components/alerts/monitorAlert';
import { AlertTriageBar } from '@/components/alerts/AlertTriageBar';
import { AssociateCaseButton } from '@/components/alerts/AssociateCaseButton';
import { EventViewer } from '@/components/matches/EventViewer';

type TabId = 'events' | 'rule' | 'timeline';

function fmtUTC(d: Date): string {
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

export function AlertDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: apiAlert, loading, error, refetch: refetchAlert } = useAlert(id);
  // Memoize the camelized view: `fromApiAlert` allocates a new object on
  // every call, which would make `alert` a fresh reference each render and
  // cascade through every effect that depends on it (recordView, notebook
  // capture, etc.).
  const alert = useMemo(() => (apiAlert ? fromApiAlert(apiAlert) : null), [apiAlert]);

  // NAN-1547: observability monitor alerts (metric_monitor / slo / synthetic)
  // ride the same alert spine but carry `rule_id = NULL` + a breach payload in
  // matched_events. Branch on `kind` so they render a monitor surface instead
  // of the rule-centric "Unknown Rule" view.
  const monitor = useMemo(() => (apiAlert ? parseMonitorAlert(apiAlert) : null), [apiAlert]);
  const isMonitor = monitor != null;

  // NAN-1792: risk notables also carry rule_id = NULL; derive the title from
  // the payload entity instead of falling back to "Unknown Rule".
  const riskNotableTitle = useMemo(() => {
    if (apiAlert?.kind !== 'risk_notable') return null;
    const first = Array.isArray(apiAlert.matched_events) ? apiAlert.matched_events[0] : undefined;
    const entity =
      first && typeof first === 'object' ? (first as Record<string, unknown>).entity : undefined;
    return typeof entity === 'string' && entity.length > 0
      ? `Risk alert — ${entity}`
      : 'Risk alert';
  }, [apiAlert]);

  const displayName = monitor ? monitor.title : riskNotableTitle ?? alert?.ruleName ?? null;

  // Monitor alerts have no rule; `alert.ruleId` is undefined so `useDetection`
  // no-ops. The rule fetch only matters for detection alerts.
  const { data: apiRule } = useDetection(alert?.ruleId);
  // The Rule tab pulls `query` and `narrative` directly off the raw API
  // type — `fromApiDetection` is unused here.

  useDocumentTitle(displayName ? `Alert · ${displayName}` : 'Alert', [alert?.id]);
  useBreadcrumbTitle(displayName ? `Alert · ${displayName}` : null);

  const { recordView } = useRecordActivity();

  const matchedEvents = useMemo(
    () => apiAlert?.matched_events ?? [],
    [apiAlert?.matched_events],
  );

  // Track view for recent activity once per alert id.
  useEffect(() => {
    if (alert && id) {
      recordView('alert', id, displayName || 'Alert', {
        rule_name: displayName,
        severity: alert.severity,
        status: alert.status,
      });
    }
  }, [alert?.id, id, recordView, alert, displayName]);

  if (loading) {
    return (
      <div className="p-12 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="p-8 max-w-[520px] mx-auto">
        <div className="rounded-lg border border-destructive/30 bg-destructive/[0.05] p-5 flex flex-col gap-2">
          <div className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="w-4 h-4" strokeWidth={2} />
            <span className="text-[13px] font-medium">Alert not found</span>
          </div>
          <p className="text-[11.5px] text-muted-foreground">
            {error?.message || 'This alert may have been archived or the id is invalid.'}
          </p>
          <div>
            <button
              type="button"
              onClick={() => navigate('/alerts')}
              className="h-7 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5"
            >
              Back to alerts
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Monitor alerts have no rule logic; the breach context lives in the hero +
  // the payload. Risk notables (NAN-1792) likewise have no single rule — the
  // payload carries the per-rule score breakdown. Detection alerts keep the
  // full Matched events / Rule / Timeline set.
  const tabs: Array<{ id: TabId; label: string; count?: number }> = isMonitor
    ? [
        { id: 'events',   label: 'Breach payload', count: matchedEvents.length },
        { id: 'timeline', label: 'Timeline' },
      ]
    : riskNotableTitle != null
    ? [
        { id: 'events',   label: 'Matched events', count: matchedEvents.length },
        { id: 'timeline', label: 'Timeline' },
      ]
    : [
        { id: 'events',   label: 'Matched events', count: matchedEvents.length },
        { id: 'rule',     label: 'Rule logic' },
        { id: 'timeline', label: 'Timeline' },
      ];
  const requestedTab = (searchParams.get('tab') || 'events') as TabId;
  // Guard against a stale ?tab=rule deep link on a monitor alert.
  const activeTab: TabId = tabs.some((t) => t.id === requestedTab) ? requestedTab : 'events';

  return (
    <div
      className="-m-3 flex h-[calc(100%+1.5rem)] min-h-0 flex-col overflow-y-auto"
      style={{ containerType: 'inline-size' }}
    >
      <div className="pt-3 pb-4 shrink-0 px-4">
        {monitor ? (
          <MonitorAlertHero
            alert={{
              id: alert.id,
              severity: alert.severity,
              status: alert.status as 'open' | 'acknowledged' | 'closed',
              disposition: alert.disposition,
              timestamp: alert.timestamp,
              acknowledgedAt: alert.acknowledgedAt,
              acknowledgedBy: alert.acknowledgedBy,
              closedAt: alert.closedAt,
              closedBy: alert.closedBy,
              triageVerdict: alert.triageVerdict,
            }}
            monitor={monitor}
          />
        ) : (
          <AlertHero
            alert={{
              id: alert.id,
              ruleId: alert.ruleId,
              // Risk notables have no rule; surface the derived title instead
              // of "Unknown Rule" (NAN-1792).
              ruleName: alert.ruleName ?? riskNotableTitle ?? undefined,
              severity: alert.severity,
              status: alert.status as 'open' | 'acknowledged' | 'closed',
              disposition: alert.disposition,
              matchedEventCount: alert.matchedEventCount,
              matchedEvents,
              timestamp: alert.timestamp,
              acknowledgedAt: alert.acknowledgedAt,
              acknowledgedBy: alert.acknowledgedBy,
              closedAt: alert.closedAt,
              closedBy: alert.closedBy,
              triageVerdict: alert.triageVerdict,
            }}
            rule={apiRule}
            linkedNotebookCount={0}
          />
        )}
        {/* NAN-967: triage CTAs (Acknowledge / Assign / Close) — were
            previously only reachable from the /alerts list row icons. */}
        <div className="flex items-center flex-wrap gap-2">
          <AlertTriageBar
            alertId={alert.id}
            ruleName={displayName ?? 'Alert'}
            status={alert.status as 'open' | 'acknowledged' | 'closed'}
            currentAssignee={apiAlert?.assigned_to ?? null}
            onActionComplete={refetchAlert}
            bypassCasesSuppression={isMonitor}
          />
          {/* NAN-1552: reverse entry point — attach this alert to a case
              (enterprise; self-gates). Works for detection + monitor alerts. */}
          <AssociateCaseButton alertId={alert.id} onAssociated={refetchAlert} />
        </div>
      </div>

      {/* Tab bar — sticky inside the page scroll container. */}
      <div
        className="border-b border-border flex items-center gap-0 shrink-0 sticky top-0 z-20 backdrop-blur px-4"
        style={{ background: 'color-mix(in srgb, var(--background) 88%, transparent)' }}
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() =>
              setSearchParams((prev) => {
                prev.set('tab', t.id);
                return prev;
              })
            }
            aria-current={activeTab === t.id ? 'page' : undefined}
            className={cn(
              'h-9 px-3 text-[12px] flex items-center gap-1.5 border-b-2 -mb-px transition-colors',
              activeTab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {t.label}
            {t.count !== undefined && (
              <span
                className={cn(
                  'font-mono text-[10px] tabular-nums rounded px-[5px] py-[1px]',
                  activeTab === t.id
                    ? 'bg-primary/15 text-primary'
                    : 'text-muted-foreground/70',
                )}
              >
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 min-h-0 px-4 py-4">
        {activeTab === 'events' &&
          (monitor ? (
            <MonitorBreachTab events={matchedEvents} />
          ) : (
            <EventsTab events={matchedEvents} alertTimestamp={alert.timestamp} />
          ))}
        {activeTab === 'rule' && (
          <RuleTab apiRule={apiRule} />
        )}
        {activeTab === 'timeline' && (
          <TimelineTab alert={alert} />
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Tab content
// ------------------------------------------------------------------

function EventsTab({
  events,
  alertTimestamp,
}: {
  events: Record<string, unknown>[];
  alertTimestamp: Date;
}) {
  if (events.length === 0) {
    return (
      <div className="rounded-md border border-border bg-card p-8 text-center">
        <Zap className="w-10 h-10 mx-auto text-muted-foreground/50 mb-3" strokeWidth={1.5} />
        <p className="text-[12px] text-muted-foreground">No event details available.</p>
        <p className="text-[10.5px] text-muted-foreground/70 mt-1">
          Events may have been archived or stripped during ingest.
        </p>
      </div>
    );
  }
  return (
    <EventViewer
      events={events}
      matchDetectedAt={alertTimestamp}
      hoveredId={null}
      onHover={() => {}}
    />
  );
}

// NAN-1547: monitor alerts pack a single breach object in matched_events rather
// than security log events. The EventViewer's "key fields" / latency framing is
// meaningless for that, so render the payload as a plain key/value sheet.
function fmtBreachValue(v: unknown): string {
  if (v == null) return '—';
  if (typeof v === 'string') return v.length ? v : '—';
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  return JSON.stringify(v);
}

function BreachCard({ payload, index }: { payload: Record<string, unknown>; index?: number }) {
  const entries = Object.entries(payload);
  return (
    <div className="rounded-md border border-border bg-card overflow-hidden">
      <div className="px-3.5 py-2.5 border-b border-border flex items-center gap-2">
        <Activity className="w-3 h-3 text-muted-foreground" strokeWidth={2} />
        <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
          Breach payload{index ? ` · ${index}` : ''}
        </span>
      </div>
      <div className="p-3.5 grid grid-cols-1 @min-[680px]:grid-cols-2 gap-x-10 font-mono text-[11px]">
        {entries.map(([k, v]) => (
          <div
            key={k}
            className="flex items-start justify-between gap-4 py-1.5 border-b border-border/40"
          >
            <span className="text-muted-foreground shrink-0">{k}</span>
            <span className="text-foreground text-right break-all">{fmtBreachValue(v)}</span>
          </div>
        ))}
      </div>
      <details className="border-t border-border">
        <summary className="px-3.5 py-2 cursor-pointer font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground select-none">
          Raw JSON
        </summary>
        <pre className="px-3.5 pb-3.5 pt-1 overflow-auto font-mono text-[10.5px] leading-[1.5] text-foreground/90">
          {JSON.stringify(payload, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function MonitorBreachTab({ events }: { events: Record<string, unknown>[] }) {
  if (events.length === 0) {
    return (
      <div className="rounded-md border border-border bg-card p-8 text-center">
        <Zap className="w-10 h-10 mx-auto text-muted-foreground/50 mb-3" strokeWidth={1.5} />
        <p className="text-[12px] text-muted-foreground">No breach payload available.</p>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {events.map((payload, i) => (
        <BreachCard
          key={i}
          payload={payload}
          index={events.length > 1 ? i + 1 : undefined}
        />
      ))}
    </div>
  );
}

function RuleTab({
  apiRule,
}: {
  apiRule: ReturnType<typeof useDetection>['data'];
}) {
  const ruleNarrative = apiRule?.narrative;
  if (!apiRule) {
    return (
      <div className="p-6 text-center">
        <Loader2 className="w-5 h-5 animate-spin mx-auto text-muted-foreground" />
        <p className="text-[11.5px] text-muted-foreground mt-2">Loading rule details…</p>
      </div>
    );
  }
  const tactics = apiRule.mitre_tactics || [];
  const techniques = apiRule.mitre_techniques || [];
  return (
    <div className="grid grid-cols-1 @min-[960px]:grid-cols-[1fr_320px] gap-4">
      <div className="flex flex-col gap-4">
        <section>
          <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1.5 inline-flex items-center gap-1.5">
            <Code className="w-3 h-3" strokeWidth={2} />
            Query
          </div>
          <div className="rounded-md border border-border bg-card p-3 overflow-auto font-mono text-[11.5px] leading-[1.55]">
            <QueryHighlight code={apiRule.query} />
          </div>
        </section>

        {ruleNarrative && (
          <section>
            <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1.5 inline-flex items-center gap-1.5">
              <FileText className="w-3 h-3" strokeWidth={2} />
              Narrative
            </div>
            <div className="rounded-md border border-border bg-card p-3 text-[12px] text-foreground leading-[1.55]">
              {ruleNarrative}
            </div>
          </section>
        )}

        {(tactics.length > 0 || techniques.length > 0) && (
          <section>
            <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1.5">
              MITRE ATT&amp;CK
            </div>
            <div className="rounded-md border border-border bg-card p-3 flex flex-col gap-3">
              {tactics.length > 0 && (
                <div>
                  <div className="text-[10.5px] text-muted-foreground mb-1">Tactics</div>
                  <div className="flex flex-wrap gap-1.5">
                    {tactics.map((t) => (
                      <span
                        key={t}
                        className="font-mono text-[10.5px] h-[18px] inline-flex items-center px-1.5 rounded-sm"
                        style={{
                          background: 'color-mix(in srgb, var(--primary) 12%, transparent)',
                          color: 'var(--primary)',
                        }}
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {techniques.length > 0 && (
                <div>
                  <div className="text-[10.5px] text-muted-foreground mb-1">Techniques</div>
                  <div className="flex flex-wrap gap-1.5">
                    {techniques.map((t) => (
                      <span
                        key={t}
                        className="font-mono text-[10.5px] h-[18px] inline-flex items-center px-1.5 rounded-sm"
                        style={{
                          background: 'color-mix(in srgb, var(--foreground) 8%, transparent)',
                          color: 'var(--foreground)',
                        }}
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </section>
        )}
      </div>

      <aside className="flex flex-col gap-3">
        <div className="rounded-md border border-border bg-card p-3 flex flex-col gap-1.5 font-mono text-[10.5px]">
          <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-1 not-italic">
            Metadata
          </div>
          <Meta label="rule id" value={apiRule.id} />
          <Meta label="author" value={apiRule.author || '—'} />
          <Meta label="severity" value={apiRule.severity} />
          <Meta label="mode" value={apiRule.mode} />
          {apiRule.schedule_cron && <Meta label="schedule" value={apiRule.schedule_cron} />}
          {apiRule.lookback_minutes != null && (
            <Meta label="lookback" value={`${apiRule.lookback_minutes}m`} />
          )}
          <Meta label="updated" value={apiRule.updated_at.slice(0, 10)} />
        </div>

        <Link
          to={`/rules/${apiRule.id}`}
          className="h-8 px-2.5 rounded-md border border-border text-[11.5px] text-foreground hover:bg-foreground/5 inline-flex items-center justify-center gap-1.5"
        >
          Open rule
          <ExternalLink className="w-3.5 h-3.5" strokeWidth={2} />
        </Link>
      </aside>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-foreground truncate max-w-[180px]">{value}</span>
    </div>
  );
}

function TimelineTab({ alert }: { alert: NonNullable<ReturnType<typeof fromApiAlert>> }) {
  const items: Array<{
    label: string;
    at?: Date;
    by?: string;
    tone: string;
    detail?: string;
    pending?: boolean;
  }> = [
    {
      label: 'Alert triggered',
      at: alert.timestamp,
      tone: 'var(--destructive)',
      detail: `${alert.matchedEventCount} matched event${alert.matchedEventCount === 1 ? '' : 's'}`,
    },
  ];
  if (alert.acknowledgedAt) {
    items.push({
      label: 'Acknowledged',
      at: alert.acknowledgedAt,
      by: alert.acknowledgedBy,
      tone: 'var(--warning)',
    });
  } else if (alert.status === 'open') {
    items.push({ label: 'Awaiting acknowledgement', tone: 'var(--muted-foreground)', pending: true });
  }
  if (alert.closedAt) {
    items.push({
      label: 'Closed',
      at: alert.closedAt,
      by: alert.closedBy,
      tone: 'var(--success)',
      detail: alert.disposition?.replace('_', ' '),
    });
  } else if (alert.status === 'acknowledged') {
    items.push({ label: 'Awaiting closure', tone: 'var(--muted-foreground)', pending: true });
  }

  return (
    <div className="rounded-md border border-border bg-card p-4">
      <div className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground font-semibold mb-3 inline-flex items-center gap-1.5">
        <Calendar className="w-3 h-3" strokeWidth={2} />
        Lifecycle
      </div>
      <ol className="flex flex-col gap-3">
        {items.map((it, i) => (
          <li
            key={`${it.label}-${i}`}
            className={cn('flex items-start gap-3', it.pending && 'opacity-60')}
          >
            <span
              className={cn(
                'w-[7px] h-[7px] rounded-full mt-[6px] shrink-0',
                it.pending && 'border border-dashed',
              )}
              style={{
                background: it.pending ? 'transparent' : it.tone,
                borderColor: it.pending ? it.tone : undefined,
              }}
            />
            <div className="flex-1 min-w-0">
              <div className="text-[12px] text-foreground">{it.label}</div>
              <div className="mt-0.5 flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground">
                {it.at && <span className="text-foreground tabular-nums">{fmtUTC(it.at)}</span>}
                {it.by && (
                  <>
                    <span className="text-muted-foreground/60">·</span>
                    <span>by {it.by}</span>
                  </>
                )}
                {it.detail && (
                  <>
                    <span className="text-muted-foreground/60">·</span>
                    <span className="text-foreground">{it.detail}</span>
                  </>
                )}
              </div>
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}

export default AlertDetail;
