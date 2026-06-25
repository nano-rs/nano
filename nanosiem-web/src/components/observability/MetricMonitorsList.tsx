// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MetricMonitorsList (NAN-1540)
 *
 * Compact list of saved metric monitors under the explorer. Each row shows the
 * query summary + breach test + cadence, with enable-toggle and delete. Reads
 * via api.observability.listMetricMonitors; mutations via update/delete.
 */

import { useCallback, useEffect, useState } from 'react';
import { Bell, Loader2, Pencil, Trash2 } from 'lucide-react';

import { api } from '@/lib/api';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import type { MetricMonitor, MetricMonitorRequest } from '@/lib/api/types';
import { MetricMonitorDialog } from './MetricMonitorDialog';

const COMPARATOR_SYMBOL: Record<string, string> = { gt: '>', gte: '≥', lt: '<', lte: '≤' };

function fmtSecs(s: number): string {
  if (s % 86400 === 0) return `${s / 86400}d`;
  if (s % 3600 === 0) return `${s / 3600}h`;
  if (s % 60 === 0) return `${s / 60}m`;
  return `${s}s`;
}

export interface MetricMonitorsListProps {
  /** Bump to trigger a reload (the explorer increments after creating one). */
  reloadKey?: number;
}

export function MetricMonitorsList({ reloadKey = 0 }: MetricMonitorsListProps) {
  const [monitors, setMonitors] = useState<MetricMonitor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<MetricMonitor | null>(null);
  const [editMonitor, setEditMonitor] = useState<MetricMonitor | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api.observability
      .listMetricMonitors()
      .then((r) => setMonitors(r.monitors))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load monitors'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load, reloadKey]);

  const toggleEnabled = async (m: MetricMonitor) => {
    setBusyId(m.id);
    const input: MetricMonitorRequest = {
      name: m.name,
      metric_name: m.metric_name,
      agg: m.agg,
      group_by: m.group_by,
      filters: m.filters,
      comparator: m.comparator,
      threshold: m.threshold,
      window_secs: m.window_secs,
      eval_interval_secs: m.eval_interval_secs,
      enabled: !m.enabled,
    };
    try {
      await api.observability.updateMetricMonitor(m.id, input);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to update monitor');
    } finally {
      setBusyId(null);
    }
  };

  const doDelete = async (m: MetricMonitor) => {
    setBusyId(m.id);
    try {
      await api.observability.deleteMetricMonitor(m.id);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to delete monitor');
    } finally {
      setBusyId(null);
      setConfirmDelete(null);
    }
  };

  return (
    <div className="rounded-md border border-border bg-card overflow-hidden">
      <div className="px-3 py-2 border-b border-border flex items-center gap-2">
        <Bell className="w-[12px] h-[12px] text-fg-3" />
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-fg-3">
          Metric monitors
        </span>
        <div className="flex-1" />
        {loading ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin text-fg-4" />
        ) : (
          <span className="font-mono text-[10.5px] text-fg-4 tabular-nums">
            {monitors.length}
          </span>
        )}
      </div>

      {error && (
        <div className="px-3 py-2 text-[11px] text-destructive flex items-center gap-1.5">
          {error}
        </div>
      )}

      {!loading && monitors.length === 0 && !error && (
        <div className="px-3 py-4 text-[11.5px] text-fg-3">
          No monitors yet. Build a query above and click{' '}
          <span className="text-fg-2">Create monitor</span> to alert on it.
        </div>
      )}

      <div className="divide-y divide-border">
        {monitors.map((m) => {
          const summary = [
            `${m.agg}(${m.metric_name})`,
            m.group_by ? `by ${m.group_by}` : null,
            ...m.filters.map((f) => `${f.key}=${f.value}`),
          ]
            .filter(Boolean)
            .join(' · ');
          return (
            <div key={m.id} className="px-3 py-2 flex items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="text-[12px] text-foreground truncate">{m.name}</div>
                <div className="font-mono text-[10.5px] text-fg-3 truncate">
                  {summary}{' '}
                  <span className="text-fg-2">
                    {COMPARATOR_SYMBOL[m.comparator] ?? m.comparator} {m.threshold}
                  </span>{' '}
                  · over {fmtSecs(m.window_secs)} · every {fmtSecs(m.eval_interval_secs)}
                </div>
              </div>

              {/* enable toggle */}
              <button
                type="button"
                onClick={() => toggleEnabled(m)}
                disabled={busyId === m.id}
                className={
                  'shrink-0 inline-flex items-center h-5 w-9 rounded-full transition-colors disabled:opacity-50 ' +
                  (m.enabled ? 'bg-primary/70' : 'bg-foreground/15')
                }
                aria-label={m.enabled ? 'Disable monitor' : 'Enable monitor'}
              >
                <span
                  className={
                    'inline-block h-4 w-4 rounded-full bg-bg shadow transition-transform ' +
                    (m.enabled ? 'translate-x-[18px]' : 'translate-x-[2px]')
                  }
                />
              </button>

              <button
                type="button"
                onClick={() => setEditMonitor(m)}
                disabled={busyId === m.id}
                className="shrink-0 text-fg-4 hover:text-foreground w-6 h-6 flex items-center justify-center rounded hover:bg-foreground/5 transition-colors disabled:opacity-50"
                aria-label="Edit monitor"
              >
                <Pencil className="w-3.5 h-3.5" />
              </button>

              <button
                type="button"
                onClick={() => setConfirmDelete(m)}
                disabled={busyId === m.id}
                className="shrink-0 text-fg-4 hover:text-destructive w-6 h-6 flex items-center justify-center rounded hover:bg-foreground/5 transition-colors disabled:opacity-50"
                aria-label="Delete monitor"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>

      <MetricMonitorDialog
        open={editMonitor != null}
        onOpenChange={(o) => !o && setEditMonitor(null)}
        monitor={editMonitor}
        onCreated={load}
      />

      <ConfirmDialog
        open={confirmDelete != null}
        onOpenChange={(o) => !o && setConfirmDelete(null)}
        title="Delete monitor?"
        description={
          confirmDelete
            ? `"${confirmDelete.name}" will stop evaluating and be removed.`
            : ''
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => confirmDelete && doDelete(confirmDelete)}
      />
    </div>
  );
}

export default MetricMonitorsList;
