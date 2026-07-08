// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * PanelEditor Component
 * 
 * Dialog for configuring individual panel settings including:
 * - Query input with mode toggle (piped/SQL)
 * - Visualization type selector
 * - Type-specific configuration options
 * - Time range mode selector (dashboard/custom)
 * - Drilldown configuration
 * 
 * Requirements: 3.2, 3.3, 4.1, 4.4, 6.6
 */

import { useState, useCallback, useMemo } from 'react';
import { Sheet, SheetContent } from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NumberInput } from '@/components/ui/number-input';
import { Label } from '@/components/ui/label';
import { QueryEditor } from '@/components/editor';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  ChartColumn,
  LineChart,
  PieChart,
  Table,
  Activity,
  Hash,
  Clock,
  Save,
  X,
  CircleAlert,
  CircleCheck,
  FlaskConical,
  Layers,
  Loader2,
} from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { Textarea } from '@/components/ui/textarea';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { api } from '@/lib/api';
import type { MelodApiResponse } from '@/lib/api';
import { useMelodJob } from '@/enterprise/hooks/use-melod-job';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { QueryTestModal } from './QueryTestModal';
import { type TimeRangeValue } from '@/hooks/use-api';
import {
  hydrateDashboardTimeRange,
  serializeDashboardTimeRange,
} from '@/lib/dashboard-time-range';
import type {
  PanelConfig,
  VisualizationType,
  VisualizationConfig,
  TimeRange,
  SerializedTimeRange,
} from '@/lib/api';

export interface PanelEditorProps {
  panel?: PanelConfig;
  onSave: (panel: PanelConfig) => void;
  onCancel: () => void;
  /** Variable values to use for query testing */
  variables?: Record<string, string>;
}

const VISUALIZATION_TYPES: { value: VisualizationType; label: string; icon: React.ReactNode; description: string }[] = [
  { value: 'bar', label: 'Bar Chart', icon: <ChartColumn className="w-4 h-4" />, description: 'Compare values' },
  { value: 'line', label: 'Line Chart', icon: <LineChart className="w-4 h-4" />, description: 'Show trends' },
  { value: 'area', label: 'Area Chart', icon: <Activity className="w-4 h-4" />, description: 'Show volume' },
  { value: 'pie', label: 'Pie Chart', icon: <PieChart className="w-4 h-4" />, description: 'Show proportions' },
  { value: 'table', label: 'Table', icon: <Table className="w-4 h-4" />, description: 'Display rows' },
  { value: 'single_value', label: 'Single Value', icon: <Hash className="w-4 h-4" />, description: 'Single metric' },
  { value: 'timeline', label: 'Timeline', icon: <Activity className="w-4 h-4" />, description: 'Events over time' },
  // NAN-708: 'tree' (uses `| tree`) and 'flow' (uses `| funnel`) removed from
  // the picker — those commands have dedicated nanosiem pages and are
  // rejected by the panel_query handler at runtime (see
  // `validate_panel_query_commands` in nanosiem-core). Keeping them in the
  // picker would let users author panels that fail at refresh time.
  { value: 'ranked_bar', label: 'Ranked Bar', icon: <ChartColumn className="w-4 h-4" />, description: 'Top/rare value analysis' },
  { value: 'transaction', label: 'Transaction', icon: <Layers className="w-4 h-4" />, description: 'Grouped event sequences' },
];

function generateTempId(): string {
  return `temp-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

// DSH25: a panel's custom range is now persisted as a RELATIVE SerializedTimeRange
// (e.g. { type: 'preset', preset: 'Last 7 days' }) so "Last 7 days" stays a
// rolling window instead of being frozen to absolute save-time timestamps.
// Older panels persisted an absolute { start, end } — hydrate both shapes.
function hydratePanelCustomRange(cr: TimeRange | undefined): TimeRangeValue {
  if (!cr) return { type: 'preset', preset: 'Last 24 hours' };
  if ('type' in cr) {
    return hydrateDashboardTimeRange(cr as unknown as SerializedTimeRange);
  }
  return { type: 'custom', start: new Date(cr.start), end: new Date(cr.end) };
}

export function PanelEditor({ panel, onSave, onCancel, variables }: PanelEditorProps) {
  const [title, setTitle] = useState(panel?.title || '');
  const [query, setQuery] = useState(panel?.query || '');
  const [queryMode, setQueryMode] = useState<'piped' | 'sql'>(panel?.queryMode || 'piped');
  const [visualizationType, setVisualizationType] = useState<VisualizationType>(
    panel?.visualizationType || 'bar'
  );
  const [visualizationConfig, setVisualizationConfig] = useState<VisualizationConfig>(
    panel?.visualizationConfig || {}
  );
  const [timeRangeMode, setTimeRangeMode] = useState<'dashboard' | 'custom'>(
    panel?.timeRangeMode || 'dashboard'
  );
  const [customTimeRange, setCustomTimeRange] = useState<TimeRangeValue>(() =>
    hydratePanelCustomRange(panel?.customTimeRange),
  );
  const [drilldownEnabled, setDrilldownEnabled] = useState(panel?.drilldownEnabled ?? true);
  const [drilldownTemplate, setDrilldownTemplate] = useState(panel?.drilldownTemplate || '');
  const [showDiscardConfirm, setShowDiscardConfirm] = useState(false);
  const [queryTestResult, setQueryTestResult] = useState<{
    status: 'idle' | 'success' | 'error';
    message?: string;
    rowCount?: number;
    executionTime?: number;
  }>({ status: 'idle' });
  const [showTestModal, setShowTestModal] = useState(false);
  const [activeTab, setActiveTab] = useState('query');

  // AI assistance state
  const [showAiInput, setShowAiInput] = useState(false);
  const [aiPrompt, setAiPrompt] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const queryJob = useMelodJob<MelodApiResponse>();

  const isValid = useMemo(() => title.trim().length > 0 && query.trim().length > 0, [title, query]);

  // DSH47: track whether the form differs from what it opened with, so an
  // Escape / overlay-click / Cancel doesn't silently discard a whole panel of
  // edits. (customTimeRange is intentionally excluded — comparing hydrated Date
  // objects is noisy; the fields below cover the discard-worthy signals.)
  const initialSnapshot = useMemo(
    () =>
      JSON.stringify({
        title: (panel?.title || '').trim(),
        query: (panel?.query || '').trim(),
        queryMode: panel?.queryMode || 'piped',
        visualizationType: panel?.visualizationType || 'bar',
        visualizationConfig: panel?.visualizationConfig || {},
        timeRangeMode: panel?.timeRangeMode || 'dashboard',
        drilldownEnabled: panel?.drilldownEnabled ?? true,
        drilldownTemplate: (panel?.drilldownTemplate || '').trim(),
      }),
    [panel],
  );
  const isDirty = useMemo(
    () =>
      JSON.stringify({
        title: title.trim(),
        query: query.trim(),
        queryMode,
        visualizationType,
        visualizationConfig,
        timeRangeMode,
        drilldownEnabled,
        drilldownTemplate: drilldownTemplate.trim(),
      }) !== initialSnapshot,
    [title, query, queryMode, visualizationType, visualizationConfig, timeRangeMode, drilldownEnabled, drilldownTemplate, initialSnapshot],
  );

  // DSH47: close the sheet only after a dirty-confirm.
  const handleRequestClose = useCallback(() => {
    if (isDirty) {
      setShowDiscardConfirm(true);
    } else {
      onCancel();
    }
  }, [isDirty, onCancel]);

  const handleTestResult = useCallback((result: { 
    valid: boolean; 
    rowCount?: number; 
    executionTime?: number;
    error?: string;
  }) => {
    if (result.valid) {
      setQueryTestResult({
        status: 'success',
        message: 'Query executed successfully',
        rowCount: result.rowCount,
        executionTime: result.executionTime,
      });
    } else {
      setQueryTestResult({
        status: 'error',
        message: result.error || 'Query execution failed',
      });
    }
  }, []);

  const handleSave = useCallback(() => {
    if (!isValid) return;
    const panelConfig: PanelConfig = {
      id: panel?.id || generateTempId(),
      title: title.trim(),
      query: query.trim(),
      queryMode,
      visualizationType,
      visualizationConfig,
      timeRangeMode,
      // DSH25: persist the RELATIVE range (preset stays rolling); resolved to
      // absolute at query time in the view/editor. Runtime shape is a
      // SerializedTimeRange; PanelConfig types it as TimeRange for back-compat.
      customTimeRange:
        timeRangeMode === 'custom'
          ? (serializeDashboardTimeRange(customTimeRange) as unknown as TimeRange)
          : undefined,
      drilldownEnabled,
      drilldownTemplate: drilldownTemplate.trim() || undefined,
    };
    onSave(panelConfig);
  }, [panel?.id, title, query, queryMode, visualizationType, visualizationConfig, 
      timeRangeMode, customTimeRange, drilldownEnabled, drilldownTemplate, isValid, onSave]);

  const updateVisualizationConfig = useCallback((key: string, value: unknown) => {
    setVisualizationConfig(prev => ({ ...prev, [key]: value }));
  }, []);

  // Handle AI query generation
  const handleAskAi = useCallback(async () => {
    if (!aiPrompt.trim()) return;

    setAiLoading(true);
    setAiError(null);

    try {
      const response = await queryJob.start(() => api.melodBuildQuery({
        message: aiPrompt,
        query_mode: queryMode === 'sql' ? 'advanced' : 'standard',
        time_range: {
          start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          end: new Date().toISOString(),
        },
      }));

      if (response.query) {
        // Use nPL query for standard mode, SQL for advanced mode
        const generatedQuery = queryMode === 'sql' ? response.query.sql_query : response.query.npl_query;
        setQuery(generatedQuery);
        setShowAiInput(false);
        setAiPrompt('');
      } else {
        setAiError('Failed to generate query');
      }
    } catch (err) {
      setAiError((err as Error).message || 'Failed to generate query');
    } finally {
      setAiLoading(false);
    }
  }, [aiPrompt, queryMode, queryJob]);

  return (
    <>
    <Sheet open onOpenChange={open => { if (!open) handleRequestClose(); }}>
      <SheetContent
        side="right"
        className="w-[680px] max-w-[min(680px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
      >
        <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2 shrink-0">
          <ChartColumn className="w-[13px] h-[13px] text-primary" />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              {panel ? 'Edit Panel' : 'Add Panel'}
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              Configure the query, visualization, and settings.
            </div>
          </div>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
              Panel title
            </Label>
            <Input
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder="Enter panel title"
              className="h-[30px] text-[12.5px]"
            />
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="h-[28px] p-0.5">
              <TabsTrigger value="query" className="h-[24px] px-3 text-[12px]">Query</TabsTrigger>
              <TabsTrigger value="visualization" className="h-[24px] px-3 text-[12px]">Visualization</TabsTrigger>
              <TabsTrigger value="settings" className="h-[24px] px-3 text-[12px]">Settings</TabsTrigger>
            </TabsList>

            <TabsContent value="query" className="flex flex-col gap-3 mt-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                    Query mode
                  </Label>
                  <div className="inline-flex items-center p-0.5 rounded-md border border-border bg-foreground/[0.03]">
                    <button
                      type="button"
                      onClick={() => setQueryMode('piped')}
                      className={`h-[22px] px-2.5 rounded-[3px] text-[11.5px] font-medium transition-colors ${
                        queryMode === 'piped'
                          ? 'bg-card text-foreground shadow-[0_1px_3px_rgba(0,0,0,0.1)]'
                          : 'text-muted-foreground hover:text-foreground'
                      }`}
                    >
                      Piped
                    </button>
                    <button
                      type="button"
                      onClick={() => setQueryMode('sql')}
                      className={`h-[22px] px-2.5 rounded-[3px] text-[11.5px] font-medium transition-colors ${
                        queryMode === 'sql'
                          ? 'bg-card text-foreground shadow-[0_1px_3px_rgba(0,0,0,0.1)]'
                          : 'text-muted-foreground hover:text-foreground'
                      }`}
                    >
                      SQL
                    </button>
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowAiInput(!showAiInput)}
                  className="h-[26px] gap-1.5 border-primary/40 text-primary hover:bg-primary/5 hover:text-primary"
                >
                  <PivtIcon className="w-[12px] h-[12px]" />
                  Ask AI
                </Button>
              </div>

              {showAiInput && (
                <div className="rounded-md border border-primary/30 bg-primary/[0.06] p-3 flex flex-col gap-2">
                  <div className="flex items-center gap-1.5">
                    <PivtIcon className="w-[12px] h-[12px] text-primary" />
                    <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-primary font-semibold">
                      Describe what you want to query
                    </Label>
                  </div>
                  <Textarea
                    value={aiPrompt}
                    onChange={e => setAiPrompt(e.target.value)}
                    placeholder="e.g., Top 10 source IPs with failed login attempts in the last 24h"
                    className="text-[12px] min-h-[72px] resize-none"
                  />
                  {aiError && (
                    <p className="text-[11.5px] text-rose-400 flex items-center gap-1.5">
                      <CircleAlert className="w-[11px] h-[11px]" />
                      {aiError}
                    </p>
                  )}
                  <div className="flex justify-end gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-[26px]"
                      onClick={() => {
                        setShowAiInput(false);
                        setAiPrompt('');
                        setAiError(null);
                      }}
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      className="h-[26px] gap-1.5"
                      onClick={handleAskAi}
                      disabled={!aiPrompt.trim() || aiLoading}
                    >
                      {aiLoading ? (
                        <>
                          <Loader2 className="w-[12px] h-[12px] animate-spin" />
                          Generating…
                        </>
                      ) : (
                        <>
                          <PivtIcon className="w-[12px] h-[12px]" />
                          Generate query
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              )}

              <div className="flex flex-col gap-1.5">
                <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                  Query
                </Label>
                <QueryEditor
                  value={query}
                  onChange={setQuery}
                  placeholder={queryMode === 'piped'
                    ? 'source_type="apache" | stats count by status_code'
                    : 'SELECT status_code, COUNT(*) as count FROM logs GROUP BY status_code'
                  }
                  minHeight={120}
                  maxHeight={300}
                  onSubmit={() => query.trim() && setShowTestModal(true)}
                />
                {queryMode === 'sql' && (
                  <p className="text-[10.5px] leading-relaxed text-muted-foreground">
                    Raw SQL isn't bound to the dashboard time range unless you say
                    so. Use{' '}
                    <code className="font-mono text-[10.5px] text-foreground">
                      $__timeFilter(timestamp)
                    </code>{' '}
                    in a{' '}
                    <span className="font-mono">WHERE</span> clause (or{' '}
                    <code className="font-mono text-[10.5px] text-foreground">
                      $__timeFrom
                    </code>
                    {' / '}
                    <code className="font-mono text-[10.5px] text-foreground">
                      $__timeTo
                    </code>
                    ) to scope the panel to the picker.
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-[26px] gap-1.5"
                  onClick={() => setShowTestModal(true)}
                  disabled={!query.trim()}
                >
                  <FlaskConical className="w-[12px] h-[12px]" />
                  Test query
                </Button>
                {queryTestResult.status !== 'idle' && (
                  <div className={`flex items-center gap-1.5 text-[11.5px] ${
                    queryTestResult.status === 'success' ? 'text-emerald-400' : 'text-rose-400'
                  }`}>
                    {queryTestResult.status === 'success' && <CircleCheck className="w-[12px] h-[12px]" />}
                    {queryTestResult.status === 'error' && <CircleAlert className="w-[12px] h-[12px]" />}
                    <span className="font-mono">
                      {queryTestResult.message}
                      {queryTestResult.rowCount !== undefined && ` (${queryTestResult.rowCount.toLocaleString()} rows)`}
                      {queryTestResult.executionTime !== undefined && ` in ${queryTestResult.executionTime}ms`}
                    </span>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="visualization" className="flex flex-col gap-4 mt-3">
              <div className="flex flex-col gap-1.5">
                <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                  Visualization type
                </Label>
                <div className="grid grid-cols-4 gap-1.5">
                  {VISUALIZATION_TYPES.map(type => {
                    const selected = visualizationType === type.value;
                    return (
                      <button
                        key={type.value}
                        type="button"
                        onClick={() => setVisualizationType(type.value)}
                        className={`px-2 py-2 rounded-md border transition-colors text-left ${
                          selected
                            ? 'border-primary bg-primary/10'
                            : 'border-border hover:border-primary/40 hover:bg-foreground/[0.03]'
                        }`}
                      >
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span className={selected ? 'text-primary' : 'text-muted-foreground'}>
                            {type.icon}
                          </span>
                          <span className={`text-[12px] font-semibold ${
                            selected ? 'text-primary' : 'text-foreground'
                          }`}>
                            {type.label}
                          </span>
                        </div>
                        <p className="text-[10.5px] text-muted-foreground leading-[1.35]">{type.description}</p>
                      </button>
                    );
                  })}
                </div>
              </div>
              <VisualizationConfigEditor
                type={visualizationType}
                config={visualizationConfig}
                onChange={updateVisualizationConfig}
              />
            </TabsContent>

            <TabsContent value="settings" className="flex flex-col gap-4 mt-3">
              <div className="flex flex-col gap-1.5">
                <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                  Time range
                </Label>
                <div className="flex items-center gap-2 flex-wrap">
                  <Select value={timeRangeMode} onValueChange={v => setTimeRangeMode(v as 'dashboard' | 'custom')}>
                    <SelectTrigger className="h-[28px] w-[200px] text-[12px] gap-1.5">
                      <Clock className="w-[12px] h-[12px] text-muted-foreground" />
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="dashboard" className="text-[12px]">Use dashboard time</SelectItem>
                      <SelectItem value="custom" className="text-[12px]">Custom time range</SelectItem>
                    </SelectContent>
                  </Select>
                  {timeRangeMode === 'custom' && (
                    <div className="[&_button]:h-[28px] [&_button]:text-[12px]">
                      <DateTimeRangePicker value={customTimeRange} onChange={setCustomTimeRange} />
                    </div>
                  )}
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                <div className="flex items-center justify-between">
                  <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                    Enable drilldown
                  </Label>
                  <Switch checked={drilldownEnabled} onCheckedChange={setDrilldownEnabled} />
                </div>
                {drilldownEnabled && (
                  <div className="flex flex-col gap-1.5 mt-1">
                    <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
                      Custom drilldown query (optional)
                    </Label>
                    <Input
                      value={drilldownTemplate}
                      onChange={e => setDrilldownTemplate(e.target.value)}
                      placeholder="e.g., source_type=$source_type status_code=$value"
                      className="h-[30px] text-[12px] font-mono"
                    />
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </div>

        <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
          <Button variant="ghost" size="sm" className="h-[28px] gap-1.5" onClick={handleRequestClose}>
            <X className="w-[12px] h-[12px]" />
            Cancel
          </Button>
          <Button size="sm" className="h-[28px] gap-1.5" onClick={handleSave} disabled={!isValid}>
            <Save className="w-[12px] h-[12px]" />
            {panel ? 'Update panel' : 'Add panel'}
          </Button>
        </div>
      </SheetContent>

      <QueryTestModal
        open={showTestModal}
        onOpenChange={setShowTestModal}
        query={query}
        queryMode={queryMode}
        visualizationType={visualizationType}
        visualizationConfig={visualizationConfig}
        variables={variables}
        onTestResult={handleTestResult}
      />
    </Sheet>

    {/* DSH47: confirm before discarding an edited panel (Escape / overlay / Cancel). */}
    <ConfirmDialog
      open={showDiscardConfirm}
      onOpenChange={setShowDiscardConfirm}
      variant="danger"
      title="Discard panel changes?"
      description="You have unsaved changes to this panel. Discard them?"
      confirmLabel="Discard changes"
      cancelLabel="Keep editing"
      onConfirm={() => {
        setShowDiscardConfirm(false);
        onCancel();
      }}
    />
    </>
  );
}

interface VisualizationConfigEditorProps {
  type: VisualizationType;
  config: VisualizationConfig;
  onChange: (key: string, value: unknown) => void;
}

// Shared row chrome for the per-viz config: label + control on one line
function ConfigRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 min-h-[28px]">
      <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
        {label}
      </Label>
      {children}
    </div>
  );
}

function ConfigField({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold">
        {label}
      </Label>
      {children}
      {hint && <p className="text-[10.5px] text-muted-foreground">{hint}</p>}
    </div>
  );
}

function VisualizationConfigEditor({ type, config, onChange }: VisualizationConfigEditorProps) {
  switch (type) {
    case 'bar':
      return (
        <div className="flex flex-col gap-3">
          <ConfigRow label="Orientation">
            <Select value={config.orientation || 'vertical'} onValueChange={v => onChange('orientation', v)}>
              <SelectTrigger className="h-[28px] w-[140px] text-[12px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="vertical" className="text-[12px]">Vertical</SelectItem>
                <SelectItem value="horizontal" className="text-[12px]">Horizontal</SelectItem>
              </SelectContent>
            </Select>
          </ConfigRow>
          <ConfigRow label="Stacked">
            <Switch checked={config.stacked || false} onCheckedChange={v => onChange('stacked', v)} />
          </ConfigRow>
        </div>
      );
    case 'line':
      return (
        <div className="flex flex-col gap-3">
          <ConfigRow label="Show points">
            <Switch checked={config.showPoints !== false} onCheckedChange={v => onChange('showPoints', v)} />
          </ConfigRow>
          <ConfigRow label="Smooth lines">
            <Switch checked={config.smooth || false} onCheckedChange={v => onChange('smooth', v)} />
          </ConfigRow>
        </div>
      );
    case 'area':
      return (
        <div className="flex flex-col gap-3">
          <ConfigRow label="Smooth lines">
            <Switch checked={config.smooth || false} onCheckedChange={v => onChange('smooth', v)} />
          </ConfigRow>
          <ConfigField label="Fill opacity">
            <Input
              type="number" min="0" max="1" step="0.1"
              value={config.fillOpacity ?? 0.3}
              onChange={e => onChange('fillOpacity', parseFloat(e.target.value))}
              className="h-[28px] w-[100px] text-[12px]"
            />
          </ConfigField>
        </div>
      );
    case 'pie':
      return (
        <div className="flex flex-col gap-3">
          <ConfigRow label="Show labels">
            <Switch checked={config.showLabels !== false} onCheckedChange={v => onChange('showLabels', v)} />
          </ConfigRow>
          <ConfigRow label="Donut style">
            <Switch checked={config.donut || false} onCheckedChange={v => onChange('donut', v)} />
          </ConfigRow>
        </div>
      );
    case 'table':
      return (
        <div className="flex flex-col gap-3">
          <ConfigField label="Page size">
            <NumberInput
              min={5}
              max={100}
              value={config.pageSize ?? 10}
              onChange={v => onChange('pageSize', v)}
              className="h-[28px] w-[100px] text-[12px]"
            />
          </ConfigField>
        </div>
      );
    case 'single_value':
      return (
        <div className="flex flex-col gap-3">
          <ConfigField label="Unit">
            <Input
              value={config.unit || ''}
              onChange={e => onChange('unit', e.target.value)}
              placeholder="e.g., ms, %, events"
              className="h-[28px] w-[140px] text-[12px]"
            />
          </ConfigField>
          <ConfigRow label="Show trend">
            <Switch checked={config.showTrend || false} onCheckedChange={v => onChange('showTrend', v)} />
          </ConfigRow>
        </div>
      );
    case 'timeline':
      return (
        <div className="flex flex-col gap-3">
          <ConfigField label="Bucket size">
            <Select value={config.bucketSize || 'auto'} onValueChange={v => onChange('bucketSize', v)}>
              <SelectTrigger className="h-[28px] w-[140px] text-[12px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="auto" className="text-[12px]">Auto</SelectItem>
                <SelectItem value="1m" className="text-[12px]">1 minute</SelectItem>
                <SelectItem value="5m" className="text-[12px]">5 minutes</SelectItem>
                <SelectItem value="15m" className="text-[12px]">15 minutes</SelectItem>
                <SelectItem value="1h" className="text-[12px]">1 hour</SelectItem>
                <SelectItem value="1d" className="text-[12px]">1 day</SelectItem>
              </SelectContent>
            </Select>
          </ConfigField>
          <ConfigRow label="Smooth lines">
            <Switch checked={config.smooth !== false} onCheckedChange={v => onChange('smooth', v)} />
          </ConfigRow>
        </div>
      );
    case 'tree':
      return (
        <div className="flex flex-col gap-3">
          <ConfigField label="Parent field">
            <Input
              value={config.parentField || ''}
              onChange={e => onChange('parentField', e.target.value)}
              placeholder="e.g., parent_process_id"
              className="h-[28px] text-[12px] font-mono"
            />
          </ConfigField>
          <ConfigField label="Child field">
            <Input
              value={config.childField || ''}
              onChange={e => onChange('childField', e.target.value)}
              placeholder="e.g., process_id"
              className="h-[28px] text-[12px] font-mono"
            />
          </ConfigField>
          <ConfigField label="Label field">
            <Input
              value={config.labelField || ''}
              onChange={e => onChange('labelField', e.target.value)}
              placeholder="e.g., process_name"
              className="h-[28px] text-[12px] font-mono"
            />
          </ConfigField>
        </div>
      );
    case 'ranked_bar':
      return (
        <div className="flex flex-col gap-3">
          <ConfigRow label="Orientation">
            <Select value={config.orientation || 'horizontal'} onValueChange={v => onChange('orientation', v)}>
              <SelectTrigger className="h-[28px] w-[140px] text-[12px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="horizontal" className="text-[12px]">Horizontal</SelectItem>
                <SelectItem value="vertical" className="text-[12px]">Vertical</SelectItem>
              </SelectContent>
            </Select>
          </ConfigRow>
          <ConfigRow label="Show percentages">
            <Switch checked={config.showPercent !== false} onCheckedChange={v => onChange('showPercent', v)} />
          </ConfigRow>
        </div>
      );
    case 'transaction':
      return (
        <div className="flex flex-col gap-3">
          <ConfigField
            label="Max events shown"
            hint="Maximum events to show per transaction card."
          >
            <NumberInput
              min={5}
              max={100}
              value={config.maxEventsShown ?? 20}
              onChange={v => onChange('maxEventsShown', v)}
              className="h-[28px] w-[100px] text-[12px]"
            />
          </ConfigField>
        </div>
      );
    case 'flow':
      return (
        <div className="flex flex-col gap-3">
          <ConfigField
            label="Flow type"
            hint="Auto-detect infers from query results."
          >
            <Select value={config.flowType || 'auto'} onValueChange={v => onChange('flowType', v)}>
              <SelectTrigger className="h-[28px] w-[160px] text-[12px]"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="auto" className="text-[12px]">Auto-detect</SelectItem>
                <SelectItem value="funnel" className="text-[12px]">Funnel</SelectItem>
                <SelectItem value="sequence" className="text-[12px]">Sequence</SelectItem>
              </SelectContent>
            </Select>
          </ConfigField>
        </div>
      );
    default:
      return null;
  }
}

export default PanelEditor;
