// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * AlertsMonitors (NAN-1536) — the Alerts/Monitors surface for the Observability
 * console.
 *
 * Ported from the design handoff's obs-alerts.jsx (Alerts/Monitors section).
 * The design is mock-fixture driven (OBS_MONITORS); here we ADAPT nano's REAL
 * alerting subsystem into the design's monitor shape client-side — there is NO
 * new alert backend. Data comes from:
 *   - api.getAlertCounts()    → the summary header counts
 *   - api.listAlerts({...})   → the monitors table + active incidents
 *   - api.getAlertVelocity()  → the shared hourly eval sparkline
 *
 * Mapping (detection alert → monitor):
 *   status 'new'          → 'alerting'  (firing, unhandled)
 *   status 'acknowledged' → 'warn'      (triaged, being worked)
 *   status 'closed'       → 'ok'        (resolved)
 * Each alert's rule fills the monitor name/scope; severity drives tone; the
 * created_at age fills the "for" duration.
 */

import { useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, Bell, CircleCheck, Eye, Search as SearchIcon } from 'lucide-react';

import { useAlertCounts, useAlerts } from '@/hooks/use-api';
import type { Alert } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  MONITOR_KINDS as MONITOR_KIND_TUPLE,
  MONITOR_KIND_LABEL,
  comparatorSymbol,
  formatMetricValue,
  monitorScope,
  parseMonitorAlert,
  type MonitorAlertView,
  type MonitorKind,
} from '@/components/alerts/monitorAlert';
import { SegmentedSev, FilterSelect } from '@/components/rules/RulesToolbarChips';
import { normalizeSeverity } from '@/components/matches/helpers';

// ---------------------------------------------------------------------------
// adapter — alert → monitor
// ---------------------------------------------------------------------------

type MonStatus = 'alerting' | 'warn' | 'ok';

type Disposition = 'true_positive' | 'false_positive' | 'benign';

interface Monitor {
  id: string;
  name: string;
  kind?: MonitorKind; // undefined only for a stray detection row
  kindLabel: string; // 'Metric monitor' | 'SLO' | 'Synthetic check'
  scope: string; // metric (with agg) for metric/slo, target URL for synthetic
  /** Big breach figure — the actual value / observed status. */
  breachPrimary: string;
  /** Breach context — the comparator+threshold / expected status. */
  breachSecondary: string;
  status: MonStatus;
  sev: Alert['severity'];
  for: string; // human age, or '—'
}

const STATUS_OF: Record<Alert['status'], MonStatus> = {
  new: 'alerting',
  acknowledged: 'warn',
  closed: 'ok',
};

const MON_STATUS: Record<MonStatus, { dot: string; text: string; label: string; bg: string }> = {
  alerting: { dot: 'bg-danger', text: 'text-danger', label: 'Firing', bg: 'bg-danger/12 border-danger/30' },
  warn: { dot: 'bg-warn', text: 'text-warn', label: 'Acknowledged', bg: 'bg-warn/12 border-warn/30' },
  ok: { dot: 'bg-good', text: 'text-good', label: 'Resolved', bg: 'bg-good/10 border-good/30' },
};

const SEV_TONE: Record<Alert['severity'], string> = {
  critical: 'text-danger',
  high: 'text-warn',
  medium: 'text-warn',
  low: 'text-fg-3',
  informational: 'text-fg-3',
};

/** Compact age, e.g. "14m", "3h", "2d". '—' when unparseable. */
function ageOf(iso?: string): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

/** Breach figures off a parsed monitor payload. */
function breachFigures(m: MonitorAlertView): { primary: string; secondary: string } {
  if (m.kind === 'synthetic') {
    const observed = m.observedStatus && m.observedStatus > 0 ? String(m.observedStatus) : 'down';
    return { primary: observed, secondary: `exp ${m.expectedStatus ?? '—'}` };
  }
  return {
    primary: formatMetricValue(m.value),
    secondary: `${comparatorSymbol(m.comparator)} ${formatMetricValue(m.threshold)}`,
  };
}

function toMonitor(a: Alert): Monitor {
  // NAN-1547: read the monitor's identity + breach from the spine payload, not
  // the (NULL) rule. Falls back to rule fields for any stray detection row.
  const mv = parseMonitorAlert(a);
  const figures = mv ? breachFigures(mv) : { primary: '—', secondary: '' };
  return {
    id: a.id,
    name: mv?.title ?? a.rule_name ?? a.rule_id ?? a.id,
    kind: mv?.kind,
    kindLabel: mv ? MONITOR_KIND_LABEL[mv.kind] : 'Monitor',
    scope: mv ? monitorScope(mv) : a.rule_id ?? '—',
    breachPrimary: figures.primary,
    breachSecondary: figures.secondary,
    status: STATUS_OF[a.status],
    sev: a.severity,
    for: a.status === 'new' ? ageOf(a.created_at) : '—',
  };
}

// NAN-1541: this surface shows OBSERVABILITY monitor alerts ONLY. Security
// detection alerts live on the SIEM /alerts page. The unified alert spine
// discriminates by `kind`; we scope every read here to the monitor kinds so
// detection alerts never leak into the Observability console. (Sourced from the
// shared tuple in monitorAlert.ts so the kind list has one home.)
const MONITOR_KINDS: string[] = [...MONITOR_KIND_TUPLE];

// ---------------------------------------------------------------------------

type FilterKey = 'all' | 'new' | 'acknowledged' | 'closed';

const SUMMARY: Array<{ k: Exclude<FilterKey, 'all'> | 'total'; label: string; tone: 'danger' | 'warn' | 'good' | 'brand' }> = [
  { k: 'new', label: 'Firing', tone: 'danger' },
  { k: 'acknowledged', label: 'Acknowledged', tone: 'warn' },
  { k: 'closed', label: 'Resolved', tone: 'good' },
  // O55 (NAN-1721): this card reads `counts.total` from `useAlertCounts` — the
  // total monitor-alert count, NOT a count of monitors. Label it honestly.
  { k: 'total', label: 'Total alerts', tone: 'brand' },
];

const HEALTH_BG: Record<'danger' | 'warn' | 'good' | 'brand', string> = {
  danger: 'bg-danger/12 border-danger/30',
  warn: 'bg-warn/12 border-warn/30',
  good: 'bg-good/10 border-good/30',
  brand: 'bg-brand/10 border-brand/30',
};
const HEALTH_DOT: Record<'danger' | 'warn' | 'good' | 'brand', string> = {
  danger: 'bg-danger',
  warn: 'bg-warn',
  good: 'bg-good',
  brand: 'bg-brand',
};

// NAN-1547: client-side search/filter over the fetched slice. The status filter
// stays server-side (the summary cards); kind/severity/text refine the result
// in-memory — instant, and the slice is already bounded at 200 rows.
type SevFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type KindFilter = 'all' | MonitorKind;

const KIND_OPTIONS: Array<{ id: KindFilter; label: string }> = [
  { id: 'all', label: 'All kinds' },
  { id: 'metric_monitor', label: MONITOR_KIND_LABEL.metric_monitor },
  { id: 'slo', label: MONITOR_KIND_LABEL.slo },
  { id: 'synthetic', label: MONITOR_KIND_LABEL.synthetic },
];

export function AlertsMonitors() {
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { toast } = useToast();
  const [filter, setFilter] = useState<FilterKey>('all');
  const [query, setQuery] = useState('');
  const [kindFilter, setKindFilter] = useState<KindFilter>('all');
  const [sevFilter, setSevFilter] = useState<SevFilter>('all');

  // Triage gating by permission only. Unlike the SIEM Alerts page, this surface
  // is monitor-only (MONITOR_KINDS) — observability monitor alerts never enter
  // the Cases workflow, so the NAN-1066 cases-suppression does NOT apply here
  // (NAN-1547). Otherwise cases-enabled tenants would have no way to ack/close
  // a firing monitor at all.
  const canAck = hasPermission('alerts:acknowledge');
  const canClose = hasPermission('alerts:close');
  const showActions = canAck || canClose;

  const [actionBusy, setActionBusy] = useState(false);
  const [closeDialog, setCloseDialog] = useState<{ id: string; name?: string } | null>(null);
  const [closeDisposition, setCloseDisposition] = useState<Disposition>('true_positive');

  const { data: counts, refetch: refetchCounts } = useAlertCounts(MONITOR_KINDS);
  // The table re-queries when the status filter changes; 'all' fetches the
  // recent slice unfiltered. Bounded by the backend default limit.
  const {
    data: alerts,
    loading,
    refetch: refetchAlerts,
  } = useAlerts(
    filter === 'all'
      ? { kinds: MONITOR_KINDS, limit: 200 }
      : { status: filter, kinds: MONITOR_KINDS, limit: 200 },
  );

  const monitors = useMemo(() => (alerts ?? []).map(toMonitor), [alerts]);
  // Active = unhandled, high-urgency alerts. Pulled separately so the banner is
  // stable regardless of the table filter.
  const { data: activeAlerts, refetch: refetchActive } = useAlerts({
    status: 'new',
    kinds: MONITOR_KINDS,
    limit: 50,
  });
  const active = useMemo(
    () =>
      (activeAlerts ?? [])
        .filter((a) => a.severity === 'critical' || a.severity === 'high')
        .map(toMonitor),
    [activeAlerts],
  );

  // Client-side refinement (text / kind / severity), applied to both the table
  // and the active-incidents banner so they stay in sync.
  const q = query.trim().toLowerCase();
  const matchesFilters = useCallback(
    (m: Monitor) => {
      if (kindFilter !== 'all' && m.kind !== kindFilter) return false;
      if (sevFilter !== 'all' && normalizeSeverity(m.sev) !== sevFilter) return false;
      if (q && !`${m.name} ${m.scope}`.toLowerCase().includes(q)) return false;
      return true;
    },
    [kindFilter, sevFilter, q],
  );
  const hasFilters = q !== '' || kindFilter !== 'all' || sevFilter !== 'all';
  const clearFilters = () => {
    setQuery('');
    setKindFilter('all');
    setSevFilter('all');
  };

  const visibleMonitors = useMemo(
    () => monitors.filter(matchesFilters),
    [monitors, matchesFilters],
  );
  const visibleActive = useMemo(() => active.filter(matchesFilters), [active, matchesFilters]);

  // --- inline triage (ack / close) --------------------------------------
  const refetch = useCallback(() => {
    refetchAlerts();
    refetchCounts();
    refetchActive();
  }, [refetchAlerts, refetchCounts, refetchActive]);

  const runAction = useCallback(
    async (id: string, runner: (id: string) => Promise<unknown>, label: string) => {
      setActionBusy(true);
      try {
        await runner(id);
        toast({ title: `${label} monitor alert` });
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`${label} failed for ${id}:`, err);
        toast({ title: `${label} failed`, variant: 'destructive' });
      } finally {
        setActionBusy(false);
        refetch();
      }
    },
    [refetch, toast],
  );

  const acknowledge = useCallback(
    (id: string) => runAction(id, (i) => api.acknowledgeAlert(i), 'Acknowledged'),
    [runAction],
  );

  const confirmClose = useCallback(async () => {
    const target = closeDialog;
    setCloseDialog(null);
    if (!target) return;
    await runAction(
      target.id,
      (i) => api.closeAlert(i, { disposition: closeDisposition }),
      'Closed',
    );
  }, [closeDialog, closeDisposition, runAction]);

  const summary = SUMMARY.map((s) => ({
    ...s,
    v:
      s.k === 'total'
        ? counts?.total ?? 0
        : s.k === 'new'
          ? counts?.new ?? 0
          : s.k === 'acknowledged'
            ? counts?.acknowledged ?? 0
            : counts?.closed ?? 0,
  }));

  const onSummaryClick = (k: (typeof SUMMARY)[number]['k']) => {
    if (k === 'total') {
      setFilter('all');
      return;
    }
    setFilter((cur) => (cur === k ? 'all' : k));
  };

  // Shared column template — the trailing actions column only exists when the
  // viewer can triage (keeps the table from reserving dead space otherwise).
  // O55 (NAN-1721): the per-row "Eval" sparkline column was dropped (it showed
  // the same global velocity on every row), so its 56px track is gone too.
  const gridCols = showActions
    ? '18px minmax(0,1.4fr) 88px minmax(120px,1.3fr) 72px minmax(110px,1fr) 64px'
    : '18px minmax(0,1.4fr) 88px minmax(120px,1.3fr) 72px minmax(110px,1fr)';

  return (
    <div className="flex flex-col gap-3.5">
      {/* summary cards */}
      <div className="grid grid-cols-4 gap-2.5">
        {summary.map((s) => {
          const activeFilter = filter === s.k;
          return (
            <button
              key={s.k}
              onClick={() => onSummaryClick(s.k)}
              className={cn(
                'rounded-lg border bg-card px-3.5 py-3 flex flex-col gap-1.5 text-left transition-colors',
                activeFilter ? HEALTH_BG[s.tone] : 'border-border hover:border-border-2',
              )}
            >
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    'w-1.5 h-1.5 rounded-full',
                    HEALTH_DOT[s.tone],
                    s.tone === 'danger' && s.v > 0 && 'animate-pulse',
                  )}
                />
                <span className="text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium">{s.label}</span>
              </div>
              <span
                className={cn(
                  'text-[26px] font-mono font-semibold leading-none tabular-nums',
                  s.v > 0
                    ? s.tone === 'danger'
                      ? 'text-danger'
                      : s.tone === 'warn'
                        ? 'text-warn'
                        : 'text-fg'
                    : 'text-fg',
                )}
              >
                {s.v}
              </span>
            </button>
          );
        })}
      </div>

      {/* toolbar — text search + kind + severity (client-side refine) */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[180px] max-w-[320px]">
          <SearchIcon className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search monitors…"
            className="h-8 w-full pl-8 pr-3 rounded-md border border-border bg-transparent text-[11.5px] text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-primary/60"
          />
        </div>
        <FilterSelect<KindFilter>
          label="Kind"
          value={kindFilter}
          options={KIND_OPTIONS}
          onChange={setKindFilter}
        />
        <SegmentedSev value={sevFilter} onChange={setSevFilter} />
        {hasFilters && (
          <button onClick={clearFilters} className="text-[11px] text-fg-3 hover:text-brand h-8 px-1.5">
            clear
          </button>
        )}
      </div>

      {/* active incidents */}
      {visibleActive.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-danger">Active · firing now</span>
            <span className="font-mono text-[10px] text-fg-4">{visibleActive.length}</span>
            <div className="flex-1 h-px bg-border/60" />
          </div>
          <div className="grid grid-cols-2 gap-2.5">
            {visibleActive.map((m) => (
              <button
                key={m.id}
                onClick={() => navigate(`/alerts/${m.id}`)}
                className="rounded-lg border border-danger/30 bg-danger/[0.06] p-3 flex flex-col gap-2.5 text-left transition-colors hover:border-danger/50"
              >
                <div className="flex items-start gap-2.5">
                  <span className="w-6 h-6 rounded-md bg-danger/15 text-danger flex items-center justify-center shrink-0 mt-0.5">
                    <AlertTriangle className="w-[13px] h-[13px]" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] text-fg font-medium leading-tight truncate">{m.name}</div>
                    <div className="flex items-center gap-2 mt-1 text-[10.5px] text-fg-3">
                      <span className={cn('font-mono uppercase tracking-wider', SEV_TONE[m.sev])}>{m.sev}</span>
                      <span className="text-fg-4">·</span>
                      <span className="font-mono text-fg-2 truncate">{m.scope}</span>
                      <span className="text-fg-4">·</span>
                      <span className="font-mono">firing {m.for}</span>
                    </div>
                  </div>
                </div>
                {/* O55 (NAN-1721): dropped the per-incident velocity sparkline —
                    it plotted the single global alert-velocity series on every
                    card, implying a per-incident trend that didn't exist. */}
                <div className="flex items-center justify-end">
                  <div className="text-right shrink-0">
                    <div className="font-mono text-[15px] text-danger tabular-nums leading-none">{m.breachPrimary}</div>
                    <div className="font-mono text-[9.5px] text-fg-4 mt-0.5">{m.breachSecondary || 'breach'}</div>
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* monitors table */}
      <div className="rounded-lg border border-border bg-card overflow-hidden">
        <div className="px-3.5 py-2.5 border-b border-border flex items-center gap-2">
          <Bell className="w-[13px] h-[13px] text-brand" />
          <span className="font-mono text-[10.5px] uppercase tracking-[0.12em] text-fg-2 font-semibold">Monitors</span>
          <span className="text-[10.5px] text-fg-4">
            {visibleMonitors.length}
            {hasFilters ? ` of ${monitors.length}` : counts ? ` of ${counts.total}` : ''}
          </span>
          <div className="flex-1" />
          {filter !== 'all' && (
            <button onClick={() => setFilter('all')} className="text-[11px] text-fg-3 hover:text-brand">
              clear filter
            </button>
          )}
        </div>
        <div
          className="grid gap-3 px-3.5 py-2 border-b border-border bg-panel/40 font-mono text-[9px] uppercase tracking-[0.1em] text-fg-4"
          style={{ gridTemplateColumns: gridCols }}
        >
          <span />
          <span>Monitor</span>
          <span>Kind</span>
          <span>Metric / target</span>
          <span>Severity</span>
          <span className="text-right">Breach</span>
          {showActions && <span className="text-right">Actions</span>}
        </div>

        {loading && monitors.length === 0 && (
          <div className="px-3.5 py-8 text-center text-[12px] text-fg-3">Loading monitors…</div>
        )}
        {!loading && visibleMonitors.length === 0 && (
          <div className="px-3.5 py-8 text-center text-[12px] text-fg-3">
            {monitors.length === 0
              ? `No alerts ${filter === 'all' ? 'yet' : `with status “${filter}”`}.`
              : 'No monitors match your search.'}
          </div>
        )}

        {visibleMonitors.map((m) => {
          const st = MON_STATUS[m.status];
          const open = () => navigate(`/alerts/${m.id}`);
          // Ack only an unhandled (firing) alert; close anything not already
          // resolved. Both stop propagation so they don't open the detail.
          const canAckRow = canAck && m.status === 'alerting';
          const canCloseRow = canClose && m.status !== 'ok';
          return (
            <div
              key={m.id}
              role="button"
              tabIndex={0}
              onClick={open}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  open();
                }
              }}
              className="group w-full grid gap-3 px-3.5 py-2 border-b border-border/50 hover:bg-foreground/[0.03] items-center text-left cursor-pointer"
              style={{ gridTemplateColumns: gridCols }}
            >
              <span className="flex justify-center">
                <span className={cn('w-2 h-2 rounded-full', st.dot, m.status === 'alerting' && 'animate-pulse')} />
              </span>
              <div className="min-w-0">
                <div className="text-[12px] text-fg truncate">{m.name}</div>
                <div className={cn('text-[10px]', st.text)}>
                  {st.label}
                  {m.for !== '—' && ` · ${m.for}`}
                </div>
              </div>
              <span className="font-mono text-[10px] text-fg-3 uppercase tracking-wider truncate">{m.kindLabel}</span>
              <span className="font-mono text-[11px] text-fg-2 truncate">{m.scope}</span>
              <span className={cn('text-[10.5px] font-mono uppercase tracking-wider', SEV_TONE[m.sev])}>{m.sev}</span>
              <span className="text-right font-mono text-[11px] tabular-nums truncate">
                <span className={cn(m.status === 'alerting' ? 'text-danger' : 'text-fg')}>{m.breachPrimary}</span>
                {m.breachSecondary && <span className="text-fg-4"> {m.breachSecondary}</span>}
              </span>
              {showActions && (
                <span className="flex justify-end items-center gap-0.5">
                  {canAckRow && (
                    <button
                      type="button"
                      title="Acknowledge"
                      disabled={actionBusy}
                      onClick={(e) => {
                        e.stopPropagation();
                        acknowledge(m.id);
                      }}
                      className="h-6 w-6 rounded flex items-center justify-center text-fg-3 hover:text-fg hover:bg-foreground/5 disabled:opacity-40"
                    >
                      <Eye className="w-3.5 h-3.5" strokeWidth={2} />
                    </button>
                  )}
                  {canCloseRow && (
                    <button
                      type="button"
                      title="Resolve / close"
                      disabled={actionBusy}
                      onClick={(e) => {
                        e.stopPropagation();
                        setCloseDisposition('true_positive');
                        setCloseDialog({ id: m.id, name: m.name });
                      }}
                      className="h-6 w-6 rounded flex items-center justify-center text-fg-3 hover:text-good hover:bg-foreground/5 disabled:opacity-40"
                    >
                      <CircleCheck className="w-3.5 h-3.5" strokeWidth={2} />
                    </button>
                  )}
                  {/* Resolved rows have no pending action — show a muted marker
                      so the column stays aligned rather than empty. */}
                  {m.status === 'ok' && (
                    <span
                      title="Resolved"
                      className="h-6 w-6 flex items-center justify-center text-good/45"
                    >
                      <CircleCheck className="w-3.5 h-3.5" strokeWidth={2} />
                    </span>
                  )}
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Close-with-disposition dialog (mirrors the SIEM Alerts page). */}
      <Dialog open={closeDialog != null} onOpenChange={(o) => !o && setCloseDialog(null)}>
        <DialogContent className="sm:max-w-[420px]">
          <DialogHeader>
            <DialogTitle className="text-[14px]">Close monitor alert</DialogTitle>
            <DialogDescription className="text-[11.5px]">
              {closeDialog?.name ? (
                <span className="font-mono">{closeDialog.name}</span>
              ) : (
                'Pick a disposition. The alert lifecycle records who closed it and how.'
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="mon-close-disposition" className="text-[11.5px]">Disposition</Label>
            <Select value={closeDisposition} onValueChange={(v) => setCloseDisposition(v as Disposition)}>
              <SelectTrigger id="mon-close-disposition" className="h-8 text-[11.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true_positive" className="text-[11.5px]">True positive</SelectItem>
                <SelectItem value="false_positive" className="text-[11.5px]">False positive (noise)</SelectItem>
                <SelectItem value="benign" className="text-[11.5px]">Benign</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setCloseDialog(null)} className="h-8 text-[11.5px]">
              Cancel
            </Button>
            <Button size="sm" onClick={confirmClose} className="h-8 text-[11.5px]" disabled={actionBusy}>
              Close alert
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default AlertsMonitors;
