// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-746 — open-core triage list page.
//
// Mirrors the dense-table pattern of `enterprise/pages/Cases.tsx` (single-px
// borders, mono on IDs/timestamps/counts, 28px row height, no shadows) but
// strips every cases-coupled hook: no playbooks, no notebooks, no shadow
// investigation, no AI triage hints. The page is the open-edition analyst
// inbox — list, filter, ack, close, assign.
//
// Backend already exists in `nanosiem-api/src/handlers/alerts.rs`. The TS
// `BulkAlertRequest` is missing the `user` field the backend bulk endpoint
// requires, so bulk ack / close fan out to single-call mutations here. That
// keeps us off the broken bulk path without touching the API client surface
// shared with other callers.
//
// Density per CLAUDE.md UI conventions cookbook:
//   - 11.5px body / 10.5px mono meta
//   - h-9 row, 1px border
//   - mono on alert id, rule name, event count, timestamps
//   - severity / status as tone-tinted pills (no big colored backgrounds)

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Check,
  CircleCheck,
  Clock,
  Eye,
  Loader2,
  RefreshCw,
  Search as SearchIcon,
  UserPlus,
  X,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { useAuth } from '@/contexts/AuthContext';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { Alert as ApiAlert, AlertCounts } from '@/lib/api/types';
import { cn } from '@/lib/utils';

type StatusFilter = 'all' | 'new' | 'acknowledged' | 'closed';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'informational';
type TimeRangeFilter = '1h' | '24h' | '7d' | '30d' | 'all';
type SortField = 'created_at' | 'severity' | 'status' | 'rule_name' | 'matched_event_count';
type SortDirection = 'asc' | 'desc';
type Disposition = 'true_positive' | 'false_positive' | 'benign';

const PAGE_SIZE = 100;

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

const STATUS_ORDER: Record<string, number> = {
  new: 0,
  acknowledged: 1,
  closed: 2,
};

const SEVERITY_PILL: Record<string, string> = {
  critical: 'bg-destructive/15 text-destructive border-destructive/30',
  high: 'bg-accent-orange/15 text-accent-orange border-accent-orange/30',
  medium: 'bg-accent-yellow/15 text-accent-yellow border-accent-yellow/30',
  low: 'bg-accent-blue/15 text-accent-blue border-accent-blue/30',
  informational: 'bg-muted/40 text-muted-foreground border-border',
};

const STATUS_PILL: Record<string, string> = {
  new: 'bg-destructive/12 text-destructive border-destructive/30',
  acknowledged: 'bg-accent-yellow/15 text-accent-yellow border-accent-yellow/30',
  closed: 'bg-accent-green/15 text-accent-green border-accent-green/30',
};

function shortSeverity(s: string): string {
  if (s === 'critical') return 'CRIT';
  if (s === 'high') return 'HIGH';
  if (s === 'medium') return 'MED';
  if (s === 'low') return 'LOW';
  if (s === 'informational') return 'INFO';
  return s.toUpperCase();
}

function shortStatus(s: string): string {
  if (s === 'new') return 'New';
  if (s === 'acknowledged') return 'Ack';
  if (s === 'closed') return 'Closed';
  return s;
}

function fmtAge(iso: string): string {
  const now = Date.now();
  const ts = new Date(iso).getTime();
  if (!Number.isFinite(ts)) return '—';
  const seconds = Math.max(0, Math.floor((now - ts) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d`;
  const months = Math.floor(days / 30);
  return `${months}mo`;
}

function fmtUTC(iso: string): string {
  return iso.replace('T', ' ').slice(0, 19) + ' UTC';
}

function shortAlertId(id: string): string {
  // typeids look like alert_<base32>; show alert_<first 6 of suffix>
  if (id.startsWith('alert_')) {
    const suffix = id.slice('alert_'.length);
    return `alert_${suffix.slice(0, 6)}`;
  }
  return id.slice(0, 12);
}

function timeRangeCutoff(range: TimeRangeFilter): number | null {
  const now = Date.now();
  switch (range) {
    case '1h':
      return now - 1 * 60 * 60 * 1000;
    case '24h':
      return now - 24 * 60 * 60 * 1000;
    case '7d':
      return now - 7 * 24 * 60 * 60 * 1000;
    case '30d':
      return now - 30 * 24 * 60 * 60 * 1000;
    case 'all':
    default:
      return null;
  }
}

export function Alerts() {
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const { toast } = useToast();

  useDocumentTitle('Alerts');

  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [timeRangeFilter, setTimeRangeFilter] = useState<TimeRangeFilter>('24h');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  const [alerts, setAlerts] = useState<ApiAlert[]>([]);
  const [counts, setCounts] = useState<AlertCounts | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [actionBusy, setActionBusy] = useState(false);

  // Close-with-disposition dialog state. Single-id when invoked from a row;
  // null `id` means "apply to current selection" from the bulk bar.
  const [closeDialog, setCloseDialog] = useState<
    { id: string | null; ruleName?: string } | null
  >(null);
  const [closeDisposition, setCloseDisposition] = useState<Disposition>('true_positive');

  // Assign dialog — a tiny username input. Open-core has no assignee picker
  // (no enterprise user directory hook in this surface yet), so we accept a
  // free-form login name; the backend records whatever string we send.
  const [assignDialog, setAssignDialog] = useState<{ id: string; ruleName?: string } | null>(null);
  const [assignTo, setAssignTo] = useState('');

  const canAck = hasPermission('alerts:acknowledge');
  const canClose = hasPermission('alerts:close');
  const canAssign = hasPermission('alerts:assign');

  const fetchAlerts = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const params: Parameters<typeof api.listAlerts>[0] = {
        limit: PAGE_SIZE,
      };
      if (statusFilter !== 'all') params.status = statusFilter;
      if (severityFilter !== 'all') params.severity = severityFilter;
      const data = await api.listAlerts(params);
      setAlerts(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err as Error);
      // eslint-disable-next-line no-console
      console.error('Failed to fetch alerts:', err);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter, severityFilter]);

  const fetchCounts = useCallback(async () => {
    try {
      const data = await api.getAlertCounts();
      setCounts(data);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to fetch alert counts:', err);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  useEffect(() => {
    fetchCounts();
  }, [fetchCounts]);

  // Reset selection when filters change.
  useEffect(() => {
    setSelected(new Set());
  }, [statusFilter, severityFilter, timeRangeFilter, searchQuery]);

  const refetch = useCallback(() => {
    fetchAlerts();
    fetchCounts();
  }, [fetchAlerts, fetchCounts]);

  const filteredAlerts = useMemo(() => {
    const cutoff = timeRangeCutoff(timeRangeFilter);
    const q = searchQuery.trim().toLowerCase();
    let out = alerts;
    if (cutoff != null) {
      out = out.filter((a) => {
        const ts = new Date(a.created_at).getTime();
        return Number.isFinite(ts) && ts >= cutoff;
      });
    }
    if (q.length > 0) {
      out = out.filter((a) => {
        const name = (a.rule_name || '').toLowerCase();
        return name.includes(q) || a.id.toLowerCase().includes(q);
      });
    }
    const dir = sortDirection === 'asc' ? 1 : -1;
    out = [...out].sort((a, b) => {
      switch (sortField) {
        case 'severity':
          return ((SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)) * dir;
        case 'status':
          return ((STATUS_ORDER[a.status] ?? 99) - (STATUS_ORDER[b.status] ?? 99)) * dir;
        case 'rule_name':
          return (a.rule_name || '').localeCompare(b.rule_name || '') * dir;
        case 'matched_event_count':
          return (
            ((a.matched_event_count ?? a.matched_events?.length ?? 0) -
              (b.matched_event_count ?? b.matched_events?.length ?? 0)) *
            dir
          );
        case 'created_at':
        default: {
          const ta = new Date(a.created_at).getTime();
          const tb = new Date(b.created_at).getTime();
          return (ta - tb) * dir;
        }
      }
    });
    return out;
  }, [alerts, timeRangeFilter, searchQuery, sortField, sortDirection]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const allVisibleSelected =
    filteredAlerts.length > 0 && filteredAlerts.every((a) => selected.has(a.id));

  const toggleAll = () => {
    if (allVisibleSelected) {
      setSelected(new Set());
    } else {
      setSelected(new Set(filteredAlerts.map((a) => a.id)));
    }
  };

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const runOnIds = useCallback(
    async (ids: string[], runner: (id: string) => Promise<unknown>, action: string) => {
      if (ids.length === 0) return;
      setActionBusy(true);
      let succeeded = 0;
      let failed = 0;
      for (const id of ids) {
        try {
          await runner(id);
          succeeded += 1;
        } catch (err) {
          failed += 1;
          // eslint-disable-next-line no-console
          console.error(`${action} failed for ${id}:`, err);
        }
      }
      if (failed > 0) {
        toast({
          title: `${action}: ${succeeded} ok, ${failed} failed`,
          variant: 'destructive',
        });
      } else {
        toast({ title: `${action}: ${succeeded} alert${succeeded === 1 ? '' : 's'}` });
      }
      setSelected(new Set());
      setActionBusy(false);
      refetch();
    },
    [refetch, toast],
  );

  const acknowledgeOne = useCallback(
    async (id: string) => {
      await runOnIds([id], (i) => api.acknowledgeAlert(i), 'Acknowledged');
    },
    [runOnIds],
  );

  const acknowledgeBulk = useCallback(async () => {
    await runOnIds(Array.from(selected), (i) => api.acknowledgeAlert(i), 'Acknowledged');
  }, [runOnIds, selected]);

  const closeBulk = useCallback(async () => {
    const ids = closeDialog?.id ? [closeDialog.id] : Array.from(selected);
    setCloseDialog(null);
    await runOnIds(
      ids,
      (i) => api.closeAlert(i, { disposition: closeDisposition }),
      'Closed',
    );
  }, [closeDialog, closeDisposition, runOnIds, selected]);

  const submitAssign = useCallback(async () => {
    const target = assignDialog;
    const assignee = assignTo.trim();
    if (!target || !assignee) {
      setAssignDialog(null);
      setAssignTo('');
      return;
    }
    setAssignDialog(null);
    setAssignTo('');
    setActionBusy(true);
    try {
      await api.assignAlert(target.id, assignee);
      toast({ title: `Assigned to ${assignee}` });
      refetch();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('Failed to assign alert:', err);
      toast({ title: 'Assign failed', variant: 'destructive' });
    } finally {
      setActionBusy(false);
    }
  }, [assignDialog, assignTo, refetch, toast]);

  const selectionCount = selected.size;
  const showBulkBar = selectionCount > 0;

  return (
    <div className="space-y-3 p-3">
      {/* Header — eyebrow, title, meta. The TopBar renders the breadcrumb. */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/60 pb-3">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
            Detection
          </div>
          <div className="mt-0.5 flex items-center gap-2">
            <h1 className="text-[18px] font-semibold leading-tight text-foreground">Alerts</h1>
            {counts && (
              <span className="font-mono text-[11px] tabular-nums text-muted-foreground">
                · {counts.total.toLocaleString()} total
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <Button
            variant="outline"
            size="sm"
            onClick={refetch}
            disabled={isLoading || actionBusy}
            className="h-8 border-border text-[11.5px]"
          >
            <RefreshCw className={cn('mr-1.5 h-3 w-3', isLoading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stat tiles — click reveals the alerts behind each number by setting
          status + expanding the time range to all-time. The counts come from
          a lifetime-totals endpoint, so the default 24h window otherwise hides
          everything the tile is advertising. */}
      {counts && (
        <div className="grid gap-2 md:grid-cols-4">
          <StatTile
            label="Total"
            value={counts.total}
            icon={AlertTriangle}
            tint="text-muted-foreground"
            onClick={() => {
              setStatusFilter('all');
              setTimeRangeFilter('all');
            }}
            ariaLabel="Show all alerts (all time)"
          />
          <StatTile
            label="New"
            value={counts.new}
            icon={AlertTriangle}
            tint="text-destructive"
            onClick={() => {
              setStatusFilter('new');
              setTimeRangeFilter('all');
            }}
            ariaLabel="Show new alerts (all time)"
          />
          <StatTile
            label="Acknowledged"
            value={counts.acknowledged}
            icon={Clock}
            tint="text-accent-yellow"
            onClick={() => {
              setStatusFilter('acknowledged');
              setTimeRangeFilter('all');
            }}
            ariaLabel="Show acknowledged alerts (all time)"
          />
          <StatTile
            label="Closed"
            value={counts.closed}
            icon={CircleCheck}
            tint="text-accent-green"
            onClick={() => {
              setStatusFilter('closed');
              setTimeRangeFilter('all');
            }}
            ariaLabel="Show closed alerts (all time)"
          />
        </div>
      )}

      {/* Filter row */}
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
        <div className="relative">
          <SearchIcon className="absolute left-2.5 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search rule or alert id…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-8 w-64 border-border bg-[var(--card-2)] pl-7 text-[11.5px]"
          />
        </div>
        <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v as StatusFilter)}>
          <SelectTrigger className="h-8 w-32 border-border bg-[var(--card-2)] text-[11.5px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All status</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="acknowledged">Acknowledged</SelectItem>
            <SelectItem value="closed">Closed</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as SeverityFilter)}>
          <SelectTrigger className="h-8 w-32 border-border bg-[var(--card-2)] text-[11.5px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="informational">Informational</SelectItem>
          </SelectContent>
        </Select>
        <Select value={timeRangeFilter} onValueChange={(v) => setTimeRangeFilter(v as TimeRangeFilter)}>
          <SelectTrigger className="h-8 w-32 border-border bg-[var(--card-2)] text-[11.5px]">
            <SelectValue placeholder="Time" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1h">Last 1h</SelectItem>
            <SelectItem value="24h">Last 24h</SelectItem>
            <SelectItem value="7d">Last 7d</SelectItem>
            <SelectItem value="30d">Last 30d</SelectItem>
            <SelectItem value="all">All time</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex-1" />
        <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
          {filteredAlerts.length.toLocaleString()}
          {filteredAlerts.length !== alerts.length ? ` of ${alerts.length.toLocaleString()}` : ''} shown
        </div>
      </div>

      {/* Bulk action bar — appears above the table when something is selected. */}
      {showBulkBar && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-primary/40 bg-primary/[0.04] px-3 py-2">
          <span className="font-mono text-[11px] tabular-nums text-foreground">
            {selectionCount} selected
          </span>
          <span className="text-muted-foreground/40 select-none">·</span>
          <Button
            variant="outline"
            size="sm"
            disabled={!canAck || actionBusy}
            onClick={acknowledgeBulk}
            className="h-7 border-border text-[11px]"
          >
            <Check className="mr-1.5 h-3 w-3" />
            Acknowledge
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!canClose || actionBusy}
            onClick={() => setCloseDialog({ id: null })}
            className="h-7 border-border text-[11px]"
          >
            <CircleCheck className="mr-1.5 h-3 w-3" />
            Close…
          </Button>
          <div className="flex-1" />
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelected(new Set())}
            className="h-7 text-[11px] text-muted-foreground hover:text-foreground"
          >
            <X className="mr-1.5 h-3 w-3" />
            Clear
          </Button>
        </div>
      )}

      {/* Loading / error / empty / table */}
      {isLoading && (
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}
      {error && !isLoading && (
        <div className="rounded-md border border-destructive/30 bg-destructive/[0.05] p-4">
          <div className="flex items-center gap-2 text-destructive">
            <AlertTriangle className="h-4 w-4" strokeWidth={2} />
            <span className="text-[12px] font-medium">Failed to load alerts</span>
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">{error.message}</p>
        </div>
      )}

      {!isLoading && !error && (
        <div className="overflow-hidden rounded-md border border-border bg-card">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="w-[34px] pl-3">
                  <Checkbox
                    checked={allVisibleSelected}
                    onCheckedChange={toggleAll}
                    className="h-3.5 w-3.5"
                    aria-label="Select all"
                  />
                </TableHead>
                <SortHeader field="severity" current={sortField} dir={sortDirection} onSort={handleSort} className="w-[80px]">
                  Sev
                </SortHeader>
                <SortHeader field="status" current={sortField} dir={sortDirection} onSort={handleSort} className="w-[96px]">
                  Status
                </SortHeader>
                <TableHead className="w-[140px] font-mono text-[10.5px] uppercase tracking-[0.1em] text-muted-foreground">
                  Alert
                </TableHead>
                <SortHeader field="rule_name" current={sortField} dir={sortDirection} onSort={handleSort}>
                  Rule
                </SortHeader>
                <SortHeader field="matched_event_count" current={sortField} dir={sortDirection} onSort={handleSort} className="w-[80px]">
                  Events
                </SortHeader>
                <TableHead className="w-[120px] font-mono text-[10.5px] uppercase tracking-[0.1em] text-muted-foreground">
                  Assignee
                </TableHead>
                <SortHeader field="created_at" current={sortField} dir={sortDirection} onSort={handleSort} className="w-[80px]">
                  Age
                </SortHeader>
                <TableHead className="w-[120px]" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAlerts.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={9}
                    className="py-10 text-center text-[11.5px] text-muted-foreground"
                  >
                    No alerts match the current filters.
                  </TableCell>
                </TableRow>
              ) : (
                filteredAlerts.map((alert) => {
                  const isSelected = selected.has(alert.id);
                  const eventCount = alert.matched_event_count ?? alert.matched_events?.length ?? 0;
                  const ruleName = alert.rule_name || 'Unknown rule';
                  return (
                    <TableRow
                      key={alert.id}
                      data-selected={isSelected}
                      className={cn(
                        'group h-9 cursor-pointer border-border transition-colors',
                        isSelected ? 'bg-primary/10 hover:bg-primary/12' : 'hover:bg-muted/50',
                      )}
                      onClick={() => navigate(`/alerts/${alert.id}`)}
                    >
                      <TableCell className="pl-3" onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={isSelected}
                          onCheckedChange={() => toggleOne(alert.id)}
                          className="h-3.5 w-3.5"
                          aria-label={`Select ${shortAlertId(alert.id)}`}
                        />
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn(
                            'inline-flex h-[18px] items-center rounded-sm border px-1.5 font-mono text-[10px] font-semibold tracking-wide',
                            SEVERITY_PILL[alert.severity] || SEVERITY_PILL.informational,
                          )}
                        >
                          {shortSeverity(alert.severity)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn(
                            'inline-flex h-[18px] items-center rounded-sm border px-1.5 font-mono text-[10px]',
                            STATUS_PILL[alert.status] || STATUS_PILL.new,
                          )}
                        >
                          {shortStatus(alert.status)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span
                          className="font-mono text-[11px] tabular-nums text-foreground"
                          title={alert.id}
                        >
                          {shortAlertId(alert.id)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Link
                          to={`/alerts/${alert.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="font-mono text-[11.5px] text-foreground hover:text-primary truncate inline-block max-w-[420px] align-middle"
                          title={ruleName}
                        >
                          {ruleName}
                        </Link>
                      </TableCell>
                      <TableCell>
                        <span className="font-mono text-[11px] tabular-nums text-foreground">
                          {eventCount.toLocaleString()}
                        </span>
                      </TableCell>
                      <TableCell>
                        {alert.assigned_to ? (
                          <span className="font-mono text-[10.5px] text-foreground truncate inline-block max-w-[110px]">
                            {alert.assigned_to}
                          </span>
                        ) : (
                          <span className="font-mono text-[10.5px] text-muted-foreground/70">
                            unassigned
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span
                          className="font-mono text-[10.5px] tabular-nums text-muted-foreground"
                          title={fmtUTC(alert.created_at)}
                        >
                          {fmtAge(alert.created_at)}
                        </span>
                      </TableCell>
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1 opacity-60 transition-opacity group-hover:opacity-100">
                          {alert.status === 'new' && canAck && (
                            <button
                              type="button"
                              onClick={() => acknowledgeOne(alert.id)}
                              disabled={actionBusy}
                              title="Acknowledge"
                              className="inline-flex h-6 w-6 items-center justify-center rounded-sm border border-border bg-card text-muted-foreground hover:text-foreground"
                            >
                              <Check className="h-3 w-3" />
                            </button>
                          )}
                          {alert.status !== 'closed' && canClose && (
                            <button
                              type="button"
                              onClick={() =>
                                setCloseDialog({ id: alert.id, ruleName: alert.rule_name })
                              }
                              disabled={actionBusy}
                              title="Close"
                              className="inline-flex h-6 w-6 items-center justify-center rounded-sm border border-border bg-card text-muted-foreground hover:text-foreground"
                            >
                              <CircleCheck className="h-3 w-3" />
                            </button>
                          )}
                          {alert.status !== 'closed' && canAssign && (
                            <button
                              type="button"
                              onClick={() => {
                                setAssignDialog({ id: alert.id, ruleName: alert.rule_name });
                                setAssignTo(alert.assigned_to || '');
                              }}
                              disabled={actionBusy}
                              title="Assign"
                              className="inline-flex h-6 w-6 items-center justify-center rounded-sm border border-border bg-card text-muted-foreground hover:text-foreground"
                            >
                              <UserPlus className="h-3 w-3" />
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => navigate(`/alerts/${alert.id}`)}
                            title="Open"
                            className="inline-flex h-6 w-6 items-center justify-center rounded-sm border border-border bg-card text-muted-foreground hover:text-foreground"
                          >
                            <Eye className="h-3 w-3" />
                          </button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      )}

      {/* Close dialog */}
      <Dialog open={closeDialog != null} onOpenChange={(o) => !o && setCloseDialog(null)}>
        <DialogContent className="sm:max-w-[420px]">
          <DialogHeader>
            <DialogTitle className="text-[14px]">
              {closeDialog?.id ? 'Close alert' : `Close ${selectionCount} alert${selectionCount === 1 ? '' : 's'}`}
            </DialogTitle>
            <DialogDescription className="text-[11.5px]">
              {closeDialog?.ruleName ? (
                <span className="font-mono">{closeDialog.ruleName}</span>
              ) : (
                'Pick a disposition. The alert lifecycle records who closed it and how.'
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="close-disposition" className="text-[11.5px]">Disposition</Label>
            <Select
              value={closeDisposition}
              onValueChange={(v) => setCloseDisposition(v as Disposition)}
            >
              <SelectTrigger id="close-disposition" className="h-8 text-[11.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="true_positive">True positive</SelectItem>
                <SelectItem value="false_positive">False positive</SelectItem>
                <SelectItem value="benign">Benign</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setCloseDialog(null)} className="h-8 text-[11.5px]">
              Cancel
            </Button>
            <Button size="sm" onClick={closeBulk} className="h-8 text-[11.5px]" disabled={actionBusy}>
              Close alert{closeDialog?.id ? '' : 's'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Assign dialog */}
      <Dialog open={assignDialog != null} onOpenChange={(o) => !o && setAssignDialog(null)}>
        <DialogContent className="sm:max-w-[400px]">
          <DialogHeader>
            <DialogTitle className="text-[14px]">Assign alert</DialogTitle>
            <DialogDescription className="text-[11.5px]">
              {assignDialog?.ruleName ? (
                <span className="font-mono">{assignDialog.ruleName}</span>
              ) : (
                'Pick the analyst who owns this alert.'
              )}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="assign-to" className="text-[11.5px]">Assignee (username)</Label>
            <Input
              id="assign-to"
              value={assignTo}
              autoFocus
              placeholder="analyst.name"
              onChange={(e) => setAssignTo(e.target.value)}
              className="h-8 text-[11.5px] font-mono"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && assignTo.trim()) submitAssign();
              }}
            />
          </div>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setAssignDialog(null)} className="h-8 text-[11.5px]">
              Cancel
            </Button>
            <Button size="sm" onClick={submitAssign} className="h-8 text-[11.5px]" disabled={actionBusy || !assignTo.trim()}>
              Assign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ---------- Sub-components ----------

function StatTile({
  label,
  value,
  icon: Icon,
  tint,
  onClick,
  ariaLabel,
}: {
  label: string;
  value: string | number;
  icon: typeof AlertTriangle;
  tint: string;
  onClick?: () => void;
  ariaLabel?: string;
}) {
  const body = (
    <>
      <div>
        <div className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground">
          {label}
        </div>
        <div className="mt-0.5 font-mono text-[18px] font-semibold tabular-nums text-foreground">
          {value}
        </div>
      </div>
      <Icon className={cn('h-4 w-4', tint)} />
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        aria-label={ariaLabel}
        className={cn(
          'flex w-full items-center justify-between rounded-md border border-border bg-card px-3 py-2.5 text-left',
          'transition-colors hover:border-foreground/25 hover:bg-[var(--card-2)]',
          'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        )}
      >
        {body}
      </button>
    );
  }

  return (
    <div className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2.5">
      {body}
    </div>
  );
}

function SortHeader({
  field,
  current,
  dir,
  onSort,
  children,
  className,
}: {
  field: SortField;
  current: SortField;
  dir: SortDirection;
  onSort: (field: SortField) => void;
  children: React.ReactNode;
  className?: string;
}) {
  const active = current === field;
  return (
    <TableHead
      className={cn(
        'cursor-pointer select-none font-mono text-[10.5px] uppercase tracking-[0.1em]',
        active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
        className,
      )}
      onClick={() => onSort(field)}
    >
      <div className="flex items-center">
        {children}
        {active ? (
          dir === 'asc' ? (
            <ArrowUp className="ml-1 h-3 w-3" />
          ) : (
            <ArrowDown className="ml-1 h-3 w-3" />
          )
        ) : (
          <ArrowUpDown className="ml-1 h-3 w-3 opacity-40" />
        )}
      </div>
    </TableHead>
  );
}

export default Alerts;
