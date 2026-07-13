// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Reports (NAN-1793)
 *
 * Scheduled report definitions — a saved SEARCH query or a DASHBOARD run on a
 * cron to generate downloadable artifacts (CSV/HTML). Each definition expands to
 * its run history; each run expands to its downloadable artifacts.
 *
 * Density pass: 10.5-11px mono row meta, colored status pills, single 1px
 * borders, no shadows (matches Settings/AuditLog + Dashboards).
 */

import { Fragment, useCallback, useEffect, useState } from 'react';
import {
  CalendarClock,
  ChevronDown,
  ChevronRight,
  Download,
  Globe,
  Loader2,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Trash2,
  User as UserIcon,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { ScheduleReportDialog } from '@/components/reports/ScheduleReportDialog';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api } from '@/lib/api';
import { formatUTC } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import type { ReportArtifactMeta, ReportDefinition, ReportRun } from '@/lib/api';

type FilterTab = 'mine' | 'all';

function statusPillCls(status?: string): string {
  switch (status) {
    case 'success':
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
    case 'failed':
      return 'bg-red-500/10 text-red-400 border-red-500/20';
    case 'running':
      return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    default:
      return 'bg-muted/40 text-muted-foreground border-border';
  }
}

function StatusPill({ status }: { status?: string }) {
  return (
    <span
      className={cn(
        'font-mono text-[10px] font-semibold tracking-[0.08em] uppercase px-1.5 py-0.5 rounded border',
        statusPillCls(status),
      )}
    >
      {status || 'never'}
    </span>
  );
}

function formatDuration(ms?: number): string {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function formatSchedule(cron: string): string {
  return cron;
}

/** Per-run row: expands to load artifacts (the runs list returns none). */
function RunRow({ run }: { run: ReportRun }) {
  const { toast } = useToast();
  const [expanded, setExpanded] = useState(false);
  const [artifacts, setArtifacts] = useState<ReportArtifactMeta[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const toggle = async () => {
    const next = !expanded;
    setExpanded(next);
    if (next && artifacts === null && !loading) {
      setLoading(true);
      try {
        const detail = await api.reports.getReportRun(run.id);
        setArtifacts(detail.artifacts);
      } catch (err) {
        toast({
          title: 'Error',
          description: err instanceof Error ? err.message : 'Failed to load run artifacts',
          variant: 'destructive',
        });
        setArtifacts([]);
      } finally {
        setLoading(false);
      }
    }
  };

  const handleDownload = async (a: ReportArtifactMeta) => {
    setDownloadingId(a.id);
    try {
      await api.reports.downloadArtifact(a.id, a.filename);
    } catch (err) {
      toast({
        title: 'Download failed',
        description: err instanceof Error ? err.message : 'Failed to download artifact',
        variant: 'destructive',
      });
    } finally {
      setDownloadingId(null);
    }
  };

  const hasArtifacts = run.status === 'success';

  return (
    <>
      <tr
        className={cn('hover:bg-foreground/[0.025] transition-colors', hasArtifacts && 'cursor-pointer')}
        onClick={hasArtifacts ? toggle : undefined}
      >
        <td className="px-3 py-1.5 w-6">
          {hasArtifacts ? (
            expanded ? (
              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/70" />
            )
          ) : null}
        </td>
        <td className="px-3 py-1.5">
          <StatusPill status={run.status} />
        </td>
        <td className="px-3 py-1.5">
          <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
            {formatUTC(run.started_at)}
          </span>
        </td>
        <td className="px-3 py-1.5">
          <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
            {formatDuration(run.duration_ms)}
          </span>
        </td>
        <td className="px-3 py-1.5">
          <span className="font-mono text-[10.5px] text-foreground tabular-nums">
            {run.row_count != null ? run.row_count.toLocaleString() : '—'}
          </span>
        </td>
        <td className="px-3 py-1.5">
          <span className="font-mono text-[10px] uppercase tracking-wide text-muted-foreground/80">
            {run.triggered_by}
          </span>
        </td>
        <td className="px-3 py-1.5">
          {(run.truncated || run.artifact_truncated) && (
            <span className="font-mono text-[9.5px] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border bg-yellow-500/10 text-yellow-400 border-yellow-500/20">
              truncated
            </span>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-foreground/[0.015]">
          <td />
          <td colSpan={6} className="px-3 py-2">
            {loading ? (
              <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Loading artifacts…
              </div>
            ) : run.error ? (
              <div className="text-[11px] text-red-400 font-mono">{run.error}</div>
            ) : artifacts && artifacts.length > 0 ? (
              <div className="flex flex-wrap items-center gap-2">
                {artifacts.map((a) => (
                  <button
                    key={a.id}
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleDownload(a);
                    }}
                    disabled={downloadingId === a.id}
                    className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded border border-border bg-card hover:bg-foreground/5 text-[11px] text-foreground transition-colors disabled:opacity-50"
                    title={a.filename}
                  >
                    {downloadingId === a.id ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      <Download className="w-3 h-3 text-muted-foreground" />
                    )}
                    <span className="font-mono text-[10px] font-semibold uppercase tracking-wide">
                      {a.kind}
                    </span>
                    <span className="font-mono text-[9.5px] text-muted-foreground/70 tabular-nums">
                      {formatBytes(a.size_bytes)}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="text-[11px] text-muted-foreground">No artifacts for this run.</div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

/** Run history for a definition — loaded on expand. */
function ReportRunHistory({ reportId }: { reportId: string }) {
  const { toast } = useToast();
  const [runs, setRuns] = useState<ReportRun[] | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api.reports
      .getReportRuns(reportId)
      .then((r) => {
        if (active) setRuns(r);
      })
      .catch((err) => {
        if (active) {
          toast({
            title: 'Error',
            description: err instanceof Error ? err.message : 'Failed to load run history',
            variant: 'destructive',
          });
          setRuns([]);
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [reportId, toast]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 px-4 py-4 text-[11px] text-muted-foreground">
        <Loader2 className="w-3.5 h-3.5 animate-spin" />
        Loading run history…
      </div>
    );
  }

  if (!runs || runs.length === 0) {
    return (
      <div className="px-4 py-4 text-[11.5px] text-muted-foreground">
        No runs yet. Trigger one with <span className="text-foreground">Run now</span>.
      </div>
    );
  }

  return (
    <div className="border-t border-border bg-card/30">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border">
            <th className="w-6 px-3 py-2" />
            <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24">Status</th>
            <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-56">Started</th>
            <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24">Duration</th>
            <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24">Rows</th>
            <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24">Trigger</th>
            <th className="text-left px-3 py-2 text-[11px] text-muted-foreground">Flags</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border/60">
          {runs.map((run) => (
            <RunRow key={run.id} run={run} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Reports() {
  useDocumentTitle('Reports');
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const isAdmin = hasPermission('settings:system');

  const [filter, setFilter] = useState<FilterTab>('mine');
  const [reports, setReports] = useState<ReportDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<ReportDefinition | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<ReportDefinition | null>(null);
  const [deleting, setDeleting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const rs = await api.reports.listReports(filter);
      setReports(rs);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  const handleRunNow = async (r: ReportDefinition) => {
    setBusyId(r.id);
    try {
      await api.reports.runReport(r.id);
      toast({ title: 'Run started', description: `"${r.name}" is generating a report.` });
      // Give the backend a moment to record the run before refetching.
      setTimeout(() => {
        load();
      }, 1500);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to trigger run',
        variant: 'destructive',
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleToggleEnabled = async (r: ReportDefinition) => {
    setBusyId(r.id);
    try {
      await api.reports.updateReport(r.id, { enabled: !r.enabled });
      toast({
        title: r.enabled ? 'Report disabled' : 'Report enabled',
        description: `"${r.name}" is now ${r.enabled ? 'paused' : 'active'}.`,
      });
      load();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update report',
        variant: 'destructive',
      });
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.reports.deleteReport(deleteTarget.id);
      toast({ title: 'Report deleted', description: `"${deleteTarget.name}" was deleted.` });
      setDeleteTarget(null);
      if (expandedId === deleteTarget.id) setExpandedId(null);
      load();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete report',
        variant: 'destructive',
      });
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="flex-1 overflow-auto p-4 flex flex-col gap-4">
      {/* Eyebrow + title row */}
      <div className="flex items-start gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <CalendarClock className="w-[12px] h-[12px] text-primary" />
            <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              Scheduled Reports
            </span>
          </div>
          <div className="text-[22px] font-semibold text-foreground tracking-[-0.01em]">Reports</div>
          <div className="text-[12.5px] text-muted-foreground mt-1">
            Schedule saved searches and dashboards to generate downloadable report artifacts.
          </div>
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Button variant="outline" size="sm" className="h-[30px]" onClick={() => load()}>
            <RefreshCw className="w-[12px] h-[12px]" />
            Refresh
          </Button>
          <Button size="sm" className="h-[30px]" onClick={() => setCreateOpen(true)}>
            <Plus className="w-[12px] h-[12px]" />
            New report
          </Button>
        </div>
      </div>

      {/* Filter tabs (All is admin-only) */}
      {isAdmin && (
        <div className="flex items-center gap-3 flex-wrap">
          <div className="inline-flex items-center p-0.5 rounded-md border border-border bg-foreground/[0.03]">
            {([
              { id: 'mine' as const, label: 'My reports', icon: UserIcon },
              { id: 'all' as const, label: 'All', icon: Globe },
            ]).map((t) => {
              const active = filter === t.id;
              const I = t.icon;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setFilter(t.id)}
                  className={cn(
                    'h-[26px] px-2.5 rounded-[4px] flex items-center gap-1.5 text-[12px] font-medium transition-colors',
                    active ? 'bg-card text-foreground' : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  <I className={cn('w-[12px] h-[12px]', active && 'text-primary')} />
                  <span>{t.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Body */}
      {loading ? (
        <div className="flex items-center justify-center py-16">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-[12px] text-destructive">
          {error}
        </div>
      ) : reports.length === 0 ? (
        <div className="flex flex-col items-center gap-4 py-14 text-center">
          <CalendarClock className="w-10 h-10 text-muted-foreground/40" />
          <div>
            <div className="text-[13px] text-foreground font-medium">No scheduled reports yet</div>
            <div className="text-[11.5px] text-muted-foreground mt-1">
              Create a report to run a saved search or dashboard on a schedule.
            </div>
          </div>
          <Button size="sm" className="h-[30px]" onClick={() => setCreateOpen(true)}>
            <Plus className="w-[12px] h-[12px]" />
            New report
          </Button>
        </div>
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border bg-card/50">
                <th className="w-6 px-3 py-2" />
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground">Name</th>
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24">Source</th>
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-40">Schedule</th>
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-56">Last run</th>
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-32">Owner</th>
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-20">Enabled</th>
                <th className="text-left px-3 py-2 text-[11px] text-muted-foreground w-24"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {reports.map((r) => {
                const isExpanded = expandedId === r.id;
                return (
                  <Fragment key={r.id}>
                    <tr
                      className="hover:bg-foreground/[0.025] cursor-pointer transition-colors"
                      onClick={() => setExpandedId(isExpanded ? null : r.id)}
                    >
                      <td className="px-3 py-1.5 w-6">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/70" />
                        )}
                      </td>
                      <td className="px-3 py-1.5">
                        <div className="text-[12.5px] text-foreground font-medium truncate max-w-[280px]">
                          {r.name}
                        </div>
                        <div className="font-mono text-[10px] text-muted-foreground/70">{r.id}</div>
                      </td>
                      <td className="px-3 py-1.5">
                        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border border-border bg-muted/40 text-muted-foreground">
                          {r.source_type}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        <span className="font-mono text-[10.5px] text-foreground tabular-nums">
                          {formatSchedule(r.cron_expression)}
                        </span>
                      </td>
                      <td className="px-3 py-1.5">
                        <div className="flex items-center gap-2">
                          <StatusPill status={r.last_run_status} />
                          {r.last_run_at && (
                            <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                              {formatUTC(r.last_run_at)}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-1.5">
                        <span className="font-mono text-[10.5px] text-muted-foreground truncate max-w-[110px] inline-block align-bottom">
                          {r.owner_name || '—'}
                        </span>
                      </td>
                      <td className="px-3 py-1.5" onClick={(e) => e.stopPropagation()}>
                        <Switch
                          checked={r.enabled}
                          disabled={busyId === r.id}
                          onCheckedChange={() => handleToggleEnabled(r)}
                          className="h-4 w-7"
                          aria-label={r.enabled ? 'Disable report' : 'Enable report'}
                        />
                      </td>
                      <td className="px-3 py-1.5" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center gap-1 justify-end">
                          <button
                            type="button"
                            onClick={() => handleRunNow(r)}
                            disabled={busyId === r.id}
                            className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground disabled:opacity-50"
                            title="Run now"
                            aria-label="Run now"
                          >
                            {busyId === r.id ? (
                              <Loader2 className="w-[13px] h-[13px] animate-spin" />
                            ) : (
                              <Play className="w-[13px] h-[13px]" />
                            )}
                          </button>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <button
                                type="button"
                                className="p-1 rounded hover:bg-foreground/10 text-muted-foreground hover:text-foreground"
                                aria-label="More actions"
                              >
                                <ChevronDown className="w-[13px] h-[13px]" />
                              </button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="bg-popover border-border">
                              <DropdownMenuItem
                                onClick={() => setEditTarget(r)}
                                className="text-[12px] cursor-pointer"
                              >
                                <Pencil className="w-[12px] h-[12px] mr-2" />
                                Edit
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => handleToggleEnabled(r)}
                                className="text-[12px] cursor-pointer"
                              >
                                <RefreshCw className="w-[12px] h-[12px] mr-2" />
                                {r.enabled ? 'Disable' : 'Enable'}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                onClick={() => setDeleteTarget(r)}
                                className="text-rose-400 focus:text-rose-400 focus:bg-rose-500/10 text-[12px] cursor-pointer"
                              >
                                <Trash2 className="w-[12px] h-[12px] mr-2" />
                                Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={8} className="p-0">
                          <ReportRunHistory reportId={r.id} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Create dialog — SEARCH report (user types the query) */}
      <ScheduleReportDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        preset={{ source_type: 'search' }}
        onSaved={load}
      />

      {/* Edit dialog */}
      {editTarget && (
        <ScheduleReportDialog
          open={!!editTarget}
          onOpenChange={(o) => {
            if (!o) setEditTarget(null);
          }}
          preset={{
            source_type: editTarget.source_type,
            source_query: editTarget.source_query,
            source_dashboard_id: editTarget.source_dashboard_id,
          }}
          editing={editTarget}
          onSaved={load}
        />
      )}

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(o) => {
          if (!o) setDeleteTarget(null);
        }}
        title="Delete report"
        description={
          <>
            Delete{' '}
            <span className="text-foreground font-medium">{deleteTarget?.name}</span> and all its runs
            and artifacts? This cannot be undone.
          </>
        }
        confirmLabel="Delete"
        variant="danger"
        loading={deleting}
        loadingLabel="Deleting"
        onConfirm={handleDelete}
      />
    </div>
  );
}
