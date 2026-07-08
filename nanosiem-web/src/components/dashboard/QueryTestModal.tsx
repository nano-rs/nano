// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * QueryTestModal Component
 *
 * Enhanced query testing modal for dashboard panels.
 * Shows actual visualization preview of query results.
 * Provides:
 * - Date range picker with presets
 * - Actual visualization preview (bar, line, table, etc.)
 * - Execution metrics (time, row count)
 * - Query validation feedback
 */

import { useState, useCallback, useMemo } from 'react';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Loader2,
  Play,
  Search,
  Clock,
  AlertTriangle,
  CircleCheck,
  Database,
  ChartColumn,
} from 'lucide-react';
import { subHours, subDays } from 'date-fns';
import { api } from '@/lib/api';
import type { VisualizationType, VisualizationConfig } from '@/lib/api';
import { VisualizationRenderer } from './VisualizationRenderer';
import { substituteVariables } from './variable-substitution';

interface QueryTestModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  query: string;
  queryMode: 'piped' | 'sql';
  /** Visualization type to preview */
  visualizationType: VisualizationType;
  /** Visualization configuration */
  visualizationConfig?: VisualizationConfig;
  /** Variable values to substitute in query - if empty, $var patterns get replaced with * */
  variables?: Record<string, string>;
  onTestResult?: (result: {
    valid: boolean;
    rowCount?: number;
    executionTime?: number;
    error?: string;
  }) => void;
}

// Time range presets
const TIME_PRESETS = [
  { label: 'Last 1 hour', value: '1h', getRange: () => ({ start: subHours(new Date(), 1), end: new Date() }) },
  { label: 'Last 4 hours', value: '4h', getRange: () => ({ start: subHours(new Date(), 4), end: new Date() }) },
  { label: 'Last 24 hours', value: '24h', getRange: () => ({ start: subDays(new Date(), 1), end: new Date() }) },
  { label: 'Last 7 days', value: '7d', getRange: () => ({ start: subDays(new Date(), 7), end: new Date() }) },
];

export function QueryTestModal({
  open,
  onOpenChange,
  query,
  queryMode,
  visualizationType,
  visualizationConfig,
  variables,
  onTestResult,
}: QueryTestModalProps) {
  const [timePreset, setTimePreset] = useState('24h');
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [testData, setTestData] = useState<{
    results: Record<string, unknown>[];
    totalCount: number;
    executionTime: number;
  } | null>(null);

  // Get time range from preset
  const getTimeRange = useCallback(() => {
    const preset = TIME_PRESETS.find(p => p.value === timePreset);
    if (!preset) return TIME_PRESETS[2].getRange(); // Default to 24h
    return preset.getRange();
  }, [timePreset]);

  const handleRunTest = useCallback(async () => {
    if (!query.trim()) return;

    const range = getTimeRange();
    const timeRange = {
      start: range.start.toISOString(),
      end: range.end.toISOString(),
    };

    // Substitute variables client-side with the SHARED module (CONTRACT 5) so
    // the preview matches exactly what the saved dashboard view runs. Only the
    // defined variable names (the keys of `variables`) are substituted; the
    // already-substituted query is sent WITHOUT `variables` so the server does
    // not re-substitute (which would diverge from the view — DSH21 parity).
    const substitutedQuery = substituteVariables(query, variables ?? {}, Object.keys(variables ?? {}));

    try {
      setTestError(null);
      setTestData(null);
      setTesting(true);

      // Use panelQuery API - returns flat records that VisualizationRenderer expects
      const response = await api.panelQuery({
        query: substitutedQuery,
        query_mode: queryMode,
        time_range: timeRange,
      });

      setTestData({
        results: response.results,
        totalCount: response.total_count,
        executionTime: response.execution_time_ms,
      });

      onTestResult?.({
        valid: true,
        rowCount: response.total_count,
        executionTime: response.execution_time_ms,
      });
    } catch (err: unknown) {
      const errorMsg = (err as Error).message || 'Query execution failed';
      setTestError(errorMsg);
      onTestResult?.({ valid: false, error: errorMsg });
    } finally {
      setTesting(false);
    }
  }, [query, queryMode, getTimeRange, onTestResult, variables]);

  // Transform results for VisualizationRenderer
  const vizData = useMemo(() => {
    if (!testData?.results.length) return [];
    return testData.results;
  }, [testData]);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[760px] max-w-[min(760px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
      >
        <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
          <Search className="w-[13px] h-[13px] text-primary" />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              Preview Panel
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5 flex items-center gap-1.5">
              Type <span className="font-mono text-foreground/80">{visualizationType}</span> · {queryMode}
            </div>
          </div>
        </div>
        <SheetHeader className="hidden">
          <SheetTitle>Preview Panel</SheetTitle>
          <SheetDescription>
            Run the query and preview the {visualizationType} visualization.
          </SheetDescription>
        </SheetHeader>

        <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border shrink-0">
          <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
            Time range
          </Label>
          <Select value={timePreset} onValueChange={setTimePreset}>
            <SelectTrigger className="h-[28px] w-[140px] text-[12px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {TIME_PRESETS.map(preset => (
                <SelectItem key={preset.value} value={preset.value} className="text-[12px]">
                  {preset.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Button
            size="sm"
            className="h-[28px] gap-1.5"
            onClick={handleRunTest}
            disabled={testing || !query.trim()}
          >
            {testing ? <Loader2 className="w-[12px] h-[12px] animate-spin" /> : <Play className="w-[12px] h-[12px]" />}
            Run preview
          </Button>

          {testData && (
            <div className="flex items-center gap-3 ml-auto font-mono text-[10.5px] text-muted-foreground">
              <span className="flex items-center gap-1 tabular-nums">
                <Database className="w-[12px] h-[12px]" />
                {testData.totalCount.toLocaleString()} rows
              </span>
              <span className="text-muted-foreground/50">·</span>
              <span className="flex items-center gap-1 tabular-nums">
                <Clock className="w-[12px] h-[12px]" />
                {testData.executionTime}ms
              </span>
              <CircleCheck className="w-[12px] h-[12px] text-emerald-400" />
            </div>
          )}
        </div>

        <div className="flex-1 min-h-[400px] overflow-auto">
          {testError && (
            <div className="m-3 rounded-md bg-rose-500/10 border border-rose-500/30 px-3 py-2 flex items-start gap-2">
              <AlertTriangle className="w-[13px] h-[13px] text-rose-400 shrink-0 mt-0.5" />
              <p className="text-[11.5px] text-rose-400 break-all">{testError}</p>
            </div>
          )}

          {testing && (
            <div className="h-full flex items-center justify-center">
              <div className="flex flex-col items-center gap-2 text-muted-foreground">
                <Loader2 className="w-6 h-6 animate-spin text-primary" />
                <p className="text-[12px]">Running query…</p>
              </div>
            </div>
          )}

          {testData && testData.results.length > 0 && !testing && (
            <div className="p-3 h-full">
              <VisualizationRenderer
                type={visualizationType}
                data={vizData}
                config={visualizationConfig || {}}
              />
            </div>
          )}

          {testData && testData.results.length === 0 && !testing && (
            <div className="h-full flex items-center justify-center">
              <div className="rounded-md bg-amber-500/10 border border-amber-500/30 px-4 py-3 text-center max-w-md flex flex-col items-center gap-2">
                <AlertTriangle className="w-6 h-6 text-amber-400" />
                <p className="text-[12px] text-amber-400">
                  No results found. Try expanding the time range or adjusting your query.
                </p>
              </div>
            </div>
          )}

          {!testData && !testError && !testing && (
            <div className="h-full flex items-center justify-center">
              <div className="text-center flex flex-col items-center gap-2">
                <ChartColumn className="w-10 h-10 text-muted-foreground/30" />
                <p className="text-[12px] text-muted-foreground">
                  Click <span className="font-semibold text-foreground">Run preview</span> to see how your panel will look.
                </p>
              </div>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default QueryTestModal;
