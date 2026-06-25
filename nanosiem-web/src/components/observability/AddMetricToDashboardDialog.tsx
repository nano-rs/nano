// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * AddMetricToDashboardDialog (NAN-1540)
 *
 * Persists the explorer's current metric query as an `obs_metric` dashboard
 * widget — either appended to an existing dashboard or in a new one. Delegates
 * the panel/layout mechanics to the dashboard `addMetricToDashboard` helper
 * (components/dashboard/metric-widget.ts) so the explorer never reaches into
 * dashboard internals.
 */

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
import { useDashboards } from '@/hooks/use-api';
import { addMetricToDashboard } from '@/components/dashboard';
import type { MetricWidgetConfig } from '@/lib/api/types';

const FIELD_LABEL = 'text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium';

export interface AddMetricToDashboardDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The metric query to save (already in the dashboard widget shape). */
  metricConfig: MetricWidgetConfig;
  /** Default panel title (e.g. the metric name). */
  defaultTitle: string;
}

export function AddMetricToDashboardDialog({
  open,
  onOpenChange,
  metricConfig,
  defaultTitle,
}: AddMetricToDashboardDialogProps) {
  const navigate = useNavigate();
  const { data: dashboards } = useDashboards('my');

  const [mode, setMode] = useState<'existing' | 'new'>('new');
  const [dashboardId, setDashboardId] = useState('');
  const [newName, setNewName] = useState('Metrics');
  const [title, setTitle] = useState(defaultTitle);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      const has = (dashboards?.length ?? 0) > 0;
      setMode(has ? 'existing' : 'new');
      setDashboardId(dashboards?.[0]?.id ?? '');
      setNewName('Metrics');
      setTitle(defaultTitle);
      setError(null);
    }
  }, [open, dashboards, defaultTitle]);

  const valid = mode === 'existing' ? dashboardId !== '' : newName.trim().length > 0;

  const handleSave = async () => {
    if (!valid || saving) return;
    setSaving(true);
    setError(null);
    try {
      const id = await addMetricToDashboard({
        dashboardId: mode === 'existing' ? dashboardId : undefined,
        newDashboardName: mode === 'new' ? newName : undefined,
        title,
        metricConfig,
      });
      onOpenChange(false);
      navigate(`/dashboards/${id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-[460px] flex flex-col overflow-y-auto gap-0 p-0 bg-card border-border text-foreground">
        <SheetHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <SheetTitle>Add to dashboard</SheetTitle>
          <SheetDescription>
            Save this metric query as a panel on a dashboard.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-3.5 px-5 py-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="metric-panel-title" className={FIELD_LABEL}>
              Panel title
            </Label>
            <Input
              id="metric-panel-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={defaultTitle}
              autoFocus
            />
          </div>

          {/* destination toggle */}
          <div className="flex items-center gap-px rounded-md bg-foreground/5 border border-border p-0.5 self-start">
            {(['existing', 'new'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setMode(m)}
                disabled={m === 'existing' && (dashboards?.length ?? 0) === 0}
                className={
                  'px-2.5 py-1 rounded-[3px] text-[11px] transition-colors disabled:opacity-40 ' +
                  (mode === m
                    ? 'bg-primary/15 text-primary font-semibold'
                    : 'text-fg-3 hover:text-foreground')
                }
              >
                {m === 'existing' ? 'Existing' : 'New'}
              </button>
            ))}
          </div>

          {mode === 'existing' ? (
            <div className="flex flex-col gap-1.5">
              <Label className={FIELD_LABEL}>Dashboard</Label>
              <Select value={dashboardId} onValueChange={setDashboardId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select dashboard" />
                </SelectTrigger>
                <SelectContent>
                  {(dashboards ?? []).map((d) => (
                    <SelectItem key={d.id} value={d.id}>
                      {d.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="metric-new-dash" className={FIELD_LABEL}>
                New dashboard name
              </Label>
              <Input
                id="metric-new-dash"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Metrics"
              />
            </div>
          )}

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
            disabled={saving}
          >
            Cancel
          </Button>
          <Button
            className="h-8 gap-1.5 text-[11.5px]"
            onClick={handleSave}
            disabled={!valid || saving}
          >
            {saving && <Loader2 className="h-[11px] w-[11px] animate-spin" />}
            Add panel
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default AddMetricToDashboardDialog;
