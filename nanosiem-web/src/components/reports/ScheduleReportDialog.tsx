// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ScheduleReportDialog (NAN-1793)
 *
 * Create/edit a scheduled report from a SEARCH query or a DASHBOARD, presented
 * as a right-side flyout (NAN-1796). Opened from the Reports page ("New
 * report"), the dashboard viewer overflow menu, and the saved-queries palette.
 * In edit mode the source TYPE (search/dashboard) is fixed, but a search
 * report's query is editable — UpdateReportRequest carries `source_query`.
 */

import { useEffect, useMemo, useState } from 'react';
import { CalendarClock, Loader2 } from 'lucide-react';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import type {
  CreateReportRequest,
  ReportDefinition,
  ReportSourceType,
  UpdateReportRequest,
} from '@/lib/api';

export interface ScheduleReportPreset {
  source_type: ReportSourceType;
  source_query?: string;
  source_dashboard_id?: string;
  dashboard_name?: string;
  saved_query_id?: number;
  defaultName?: string;
}

interface ScheduleReportDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  preset: ScheduleReportPreset;
  editing?: ReportDefinition;
  onSaved?: () => void;
}

const TIME_RANGE_PRESETS: { label: string; seconds: number }[] = [
  { label: 'Last 1 hour', seconds: 3600 },
  { label: 'Last 6 hours', seconds: 21600 },
  { label: 'Last 24 hours', seconds: 86400 },
  { label: 'Last 7 days', seconds: 604800 },
  { label: 'Last 30 days', seconds: 2592000 },
];

const CRON_PRESETS: { label: string; expr: string }[] = [
  { label: 'Every hour', expr: '0 * * * *' },
  { label: 'Daily 08:00', expr: '0 8 * * *' },
  { label: 'Weekly Mon 08:00', expr: '0 8 * * 1' },
];

const DEFAULT_CRON = '0 8 * * *';
const DEFAULT_TIME_RANGE = 86400;
const DEFAULT_RETENTION = 20;

export function ScheduleReportDialog({
  open,
  onOpenChange,
  preset,
  editing,
  onSaved,
}: ScheduleReportDialogProps) {
  const { toast } = useToast();

  const sourceType: ReportSourceType = editing?.source_type ?? preset.source_type;

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [sourceQuery, setSourceQuery] = useState('');
  const [timeRange, setTimeRange] = useState<number>(DEFAULT_TIME_RANGE);
  const [cron, setCron] = useState(DEFAULT_CRON);
  const [enabled, setEnabled] = useState(true);
  const [retentionRuns, setRetentionRuns] = useState<number>(DEFAULT_RETENTION);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Re-seed the form whenever the dialog is (re)opened so a shared instance
  // never leaks state across different presets/definitions.
  useEffect(() => {
    if (!open) return;
    setName(editing?.name ?? preset.defaultName ?? '');
    setDescription(editing?.description ?? '');
    setSourceQuery(editing?.source_query ?? preset.source_query ?? '');
    setTimeRange(editing?.time_range_seconds ?? DEFAULT_TIME_RANGE);
    setCron(editing?.cron_expression ?? DEFAULT_CRON);
    setEnabled(editing?.enabled ?? true);
    setRetentionRuns(editing?.retention_runs ?? DEFAULT_RETENTION);
    setError(null);
  }, [open, editing, preset]);

  const dashboardName = editing ? undefined : preset.dashboard_name;

  const canSubmit = useMemo(() => {
    if (!name.trim()) return false;
    if (!cron.trim()) return false;
    // A search report always needs a query — including on edit (blanking the
    // stored query is rejected server-side too).
    if (sourceType === 'search' && !sourceQuery.trim()) return false;
    return true;
  }, [name, cron, sourceType, sourceQuery]);

  const handleSubmit = async () => {
    if (!canSubmit || saving) return;
    setSaving(true);
    setError(null);

    // Clamp retention into the backend's accepted 1..100 range.
    const retention = Math.min(100, Math.max(1, Math.round(retentionRuns) || DEFAULT_RETENTION));

    try {
      if (editing) {
        const req: UpdateReportRequest = {
          name: name.trim(),
          description: description.trim() ? description.trim() : null,
          source_query: sourceType === 'search' ? sourceQuery.trim() : undefined,
          time_range_seconds: timeRange,
          cron_expression: cron.trim(),
          enabled,
          retention_runs: retention,
        };
        await api.reports.updateReport(editing.id, req);
        toast({ title: 'Report updated', description: `"${name.trim()}" was updated.` });
      } else {
        const req: CreateReportRequest = {
          name: name.trim(),
          description: description.trim() || undefined,
          source_type: sourceType,
          time_range_seconds: timeRange,
          cron_expression: cron.trim(),
          enabled,
          retention_runs: retention,
        };
        if (sourceType === 'search') {
          req.source_query = sourceQuery.trim();
          if (preset.saved_query_id != null) req.saved_query_id = preset.saved_query_id;
        } else {
          req.source_dashboard_id = preset.source_dashboard_id;
        }
        await api.reports.createReport(req);
        toast({ title: 'Report scheduled', description: `"${name.trim()}" was created.` });
      }
      onOpenChange(false);
      onSaved?.();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to save report';
      setError(message);
      toast({ title: 'Error', description: message, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="flex w-[520px] flex-col gap-0 border-l border-border bg-card p-0 sm:w-[560px]">
        <SheetHeader className="border-b border-border px-5 py-4 space-y-0">
          <SheetTitle className="flex items-center gap-2 text-[14px] font-semibold text-foreground">
            <CalendarClock className="w-4 h-4 text-primary" />
            {editing ? 'Edit scheduled report' : 'Schedule report'}
          </SheetTitle>
        </SheetHeader>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          {/* Source summary */}
          <div className="rounded-md border border-border bg-foreground/[0.02] px-3 py-2 flex items-center gap-2">
            <span className="font-mono text-[9.5px] uppercase tracking-[0.12em] text-muted-foreground/80">
              Source
            </span>
            <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.08em] px-1.5 py-0.5 rounded border border-primary/20 bg-primary/10 text-primary">
              {sourceType}
            </span>
            {sourceType === 'dashboard' && dashboardName && (
              <span className="text-[11.5px] text-foreground truncate">{dashboardName}</span>
            )}
          </div>

          {/* Name */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground">Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Weekly auth failures report"
              className="h-8 text-[12px] border-border"
            />
          </div>

          {/* Description */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground">Description (optional)</label>
            <Textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What this report covers…"
              className="min-h-[52px] text-[12px] border-border"
            />
          </div>

          {/* Search query (search source; editable on create AND edit) */}
          {sourceType === 'search' && (
            <div className="space-y-1.5">
              <label className="text-[11px] text-muted-foreground">Query</label>
              <Textarea
                value={sourceQuery}
                onChange={(e) => setSourceQuery(e.target.value)}
                placeholder='auth_result="failure" | stats count by user'
                className="min-h-[64px] font-mono text-[11.5px] border-border"
              />
            </div>
          )}

          {/* Time range */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground">Time range (lookback)</label>
            <Select value={String(timeRange)} onValueChange={(v) => setTimeRange(Number(v))}>
              <SelectTrigger className="h-8 text-[12px] border-border">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TIME_RANGE_PRESETS.map((p) => (
                  <SelectItem key={p.seconds} value={String(p.seconds)} className="text-[12px]">
                    {p.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Schedule (cron) */}
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground">Schedule (cron)</label>
            <Input
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              placeholder="0 8 * * *"
              className="h-8 font-mono text-[12px] tabular-nums border-border"
            />
            <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
              {CRON_PRESETS.map((p) => (
                <button
                  key={p.expr}
                  type="button"
                  onClick={() => setCron(p.expr)}
                  className={cn(
                    'px-2 py-1 rounded border text-[10.5px] transition-colors',
                    cron.trim() === p.expr
                      ? 'border-primary/40 bg-primary/10 text-primary'
                      : 'border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5',
                  )}
                >
                  {p.label}
                  <span className="ml-1.5 font-mono text-[9.5px] text-muted-foreground/70">{p.expr}</span>
                </button>
              ))}
            </div>
            <p className="text-[10.5px] text-muted-foreground/70">
              Standard 5-field or 6-field cron.
            </p>
          </div>

          {/* Retention + enabled */}
          <div className="flex items-end gap-4">
            <div className="space-y-1.5">
              <label className="text-[11px] text-muted-foreground">Runs to keep</label>
              <Input
                type="number"
                min={1}
                max={100}
                value={retentionRuns}
                onChange={(e) => setRetentionRuns(Number(e.target.value))}
                className="h-8 w-24 font-mono text-[12px] tabular-nums border-border"
              />
            </div>
            <label className="flex items-center gap-2 pb-2 cursor-pointer select-none">
              <Checkbox
                checked={enabled}
                onCheckedChange={(v) => setEnabled(v === true)}
              />
              <span className="text-[12px] text-foreground">Enabled</span>
            </label>
          </div>

          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-[11.5px] text-destructive">
              {error}
            </div>
          )}
        </div>

        <div className="border-t border-border px-5 py-3 flex items-center justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            className="h-8 text-[11.5px]"
            onClick={() => onOpenChange(false)}
            disabled={saving}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 gap-1.5 text-[11.5px]"
            onClick={handleSubmit}
            disabled={!canSubmit || saving}
          >
            {saving && <Loader2 className="w-[11px] h-[11px] animate-spin" />}
            {editing ? 'Save changes' : 'Schedule report'}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}
