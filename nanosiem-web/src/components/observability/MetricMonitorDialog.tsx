// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MetricMonitorDialog (NAN-1540, edit NAN-1540c)
 *
 * Create or edit a metric monitor. In create mode the metric / agg / group_by /
 * filters come from the explorer's current query (`seed`); in edit mode they are
 * reconstructed from the existing `monitor` (which carries the same fields). The
 * metric query is shown read-only as a query summary; the analyst supplies the
 * breach test (comparator + threshold) and the evaluation cadence. On submit it
 * POSTs (create) or PUTs (edit) to api.observability.create/updateMetricMonitor.
 *
 * Mirrors SloEditorDialog's dense create/edit form layout + inline error surface.
 */

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { api } from '@/lib/api';
import type {
  MetricAgg,
  MetricFilter,
  MetricMonitor,
  MetricMonitorComparator,
  MetricMonitorRequest,
} from '@/lib/api/types';

const FIELD_LABEL = 'text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium';

const COMPARATOR_LABEL: Record<MetricMonitorComparator, string> = {
  gt: '>',
  gte: '≥',
  lt: '<',
  lte: '≤',
};

const WINDOW_OPTS: Array<[label: string, secs: number]> = [
  ['5m', 300],
  ['15m', 900],
  ['1h', 3600],
  ['6h', 21600],
  ['24h', 86400],
];

const INTERVAL_OPTS: Array<[label: string, secs: number]> = [
  ['30s', 30],
  ['1m', 60],
  ['5m', 300],
  ['15m', 900],
  ['1h', 3600],
];

/** The metric query the monitor will evaluate (prefilled from the explorer). */
export interface MonitorQuerySeed {
  metric_name: string;
  agg: MetricAgg;
  group_by?: string;
  filters: MetricFilter[];
}

/** Reconstruct the read-only query seed from an existing monitor (edit mode). */
function seedFromMonitor(m: MetricMonitor): MonitorQuerySeed {
  return {
    metric_name: m.metric_name,
    agg: m.agg,
    group_by: m.group_by,
    filters: m.filters,
  };
}

export interface MetricMonitorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /**
   * The metric query to monitor (create mode). Required unless `monitor` is set,
   * in which case the query is reconstructed from the monitor.
   */
  seed?: MonitorQuerySeed;
  /** When set, the dialog edits an existing monitor; otherwise it creates one. */
  monitor?: MetricMonitor | null;
  /** Called after a successful create/update so the parent can refresh its list. */
  onCreated?: () => void;
}

export function MetricMonitorDialog({
  open,
  onOpenChange,
  seed,
  monitor,
  onCreated,
}: MetricMonitorDialogProps) {
  const editing = monitor != null;
  // The metric query backing the monitor: from the explorer seed (create) or
  // reconstructed from the monitor (edit). Falls back to an empty seed so the
  // component never reads undefined fields.
  const querySeed: MonitorQuerySeed =
    monitor != null
      ? seedFromMonitor(monitor)
      : seed ?? { metric_name: '', agg: 'count', group_by: undefined, filters: [] };

  const [name, setName] = useState('');
  const [comparator, setComparator] = useState<MetricMonitorComparator>('gt');
  const [threshold, setThreshold] = useState('0');
  const [windowSecs, setWindowSecs] = useState(900);
  const [intervalSecs, setIntervalSecs] = useState(60);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      if (monitor != null) {
        setName(monitor.name);
        setComparator(monitor.comparator);
        setThreshold(String(monitor.threshold));
        setWindowSecs(monitor.window_secs);
        setIntervalSecs(monitor.eval_interval_secs);
      } else {
        setName(`${querySeed.metric_name} ${querySeed.agg} alert`);
        setComparator('gt');
        setThreshold('0');
        setWindowSecs(900);
        setIntervalSecs(60);
      }
      setError(null);
    }
    // querySeed is derived from monitor/seed; depend on the stable identity fields.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, monitor, querySeed.metric_name, querySeed.agg]);

  const thresholdNum = Number(threshold);
  const thresholdValid = threshold.trim() !== '' && Number.isFinite(thresholdNum);
  const valid = name.trim().length > 0 && thresholdValid;

  const handleSubmit = async () => {
    if (!valid || submitting) return;
    setSubmitting(true);
    setError(null);
    const input: MetricMonitorRequest = {
      name: name.trim(),
      metric_name: querySeed.metric_name,
      agg: querySeed.agg,
      group_by: querySeed.group_by || undefined,
      filters: querySeed.filters,
      comparator,
      threshold: thresholdNum,
      window_secs: windowSecs,
      eval_interval_secs: intervalSecs,
      // Preserve the existing enabled state on edit; new monitors start enabled.
      enabled: monitor != null ? monitor.enabled : true,
    };
    try {
      if (monitor != null) {
        await api.observability.updateMetricMonitor(monitor.id, input);
      } else {
        await api.observability.createMetricMonitor(input);
      }
      onCreated?.();
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const querySummary = [
    `${querySeed.agg}(${querySeed.metric_name})`,
    querySeed.group_by ? `by ${querySeed.group_by}` : null,
    ...querySeed.filters.map((f) => `${f.key}=${f.value}`),
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-[460px] flex flex-col overflow-y-auto gap-0 p-0 bg-card border-border text-foreground">
        <SheetHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <SheetTitle>{editing ? 'Edit metric monitor' : 'New metric monitor'}</SheetTitle>
          <SheetDescription>
            Evaluate the aggregate over a trailing window and alert when it breaches.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-3.5 px-5 py-4">
          {/* Query summary (prefilled, read-only) */}
          <div className="rounded-md border border-border bg-foreground/[0.03] px-3 py-2">
            <div className={FIELD_LABEL}>Query</div>
            <div className="mt-1 font-mono text-[11.5px] text-fg-2 break-words">
              {querySummary}
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="mon-name" className={FIELD_LABEL}>
              Name
            </Label>
            <Input
              id="mon-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="p95 checkout latency too high"
              autoFocus
            />
          </div>

          {/* breach test */}
          <div className="flex flex-col gap-1.5">
            <Label className={FIELD_LABEL}>Alert when value is</Label>
            <div className="grid grid-cols-[110px_1fr] gap-2">
              <Select
                value={comparator}
                onValueChange={(v) => setComparator(v as MetricMonitorComparator)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(Object.keys(COMPARATOR_LABEL) as MetricMonitorComparator[]).map((c) => (
                    <SelectItem key={c} value={c}>
                      <span className="font-mono">{COMPARATOR_LABEL[c]}</span>
                      <span className="text-fg-3 ml-1.5 text-[10px]">{c}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Input
                type="number"
                inputMode="decimal"
                step="any"
                value={threshold}
                onChange={(e) => setThreshold(e.target.value)}
                placeholder="threshold"
                className="font-mono tabular-nums"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label className={FIELD_LABEL}>Window</Label>
              <Select
                value={String(windowSecs)}
                onValueChange={(v) => setWindowSecs(Number(v))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {WINDOW_OPTS.map(([label, secs]) => (
                    <SelectItem key={secs} value={String(secs)}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label className={FIELD_LABEL}>Check every</Label>
              <Select
                value={String(intervalSecs)}
                onValueChange={(v) => setIntervalSecs(Number(v))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {INTERVAL_OPTS.map(([label, secs]) => (
                    <SelectItem key={secs} value={String(secs)}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {error != null && (
            <div className="rounded-md border border-danger/30 bg-danger/[0.06] px-3 py-2 text-[11px] text-danger">
              {error}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <Button
            variant="outline"
            className="h-8 text-[11.5px]"
            onClick={() => onOpenChange(false)}
            disabled={submitting}
          >
            Cancel
          </Button>
          <Button
            className="h-8 gap-1.5 text-[11.5px]"
            onClick={handleSubmit}
            disabled={!valid || submitting}
          >
            {submitting && <Loader2 className="h-[11px] w-[11px] animate-spin" />}
            {editing ? 'Save changes' : 'Create monitor'}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default MetricMonitorDialog;
