// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { Percent, TrendingDown } from 'lucide-react';

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface FlowVisualizationProps {
  results: SearchResult[];
  onDrilldown?: (filters: Record<string, unknown>) => void;
  /** 'funnel' shows conversion funnel, 'sequence' shows flow nodes */
  mode?: 'funnel' | 'sequence';
}

// Chart colors for flow stages
const FLOW_COLORS = [
  '#38bdf8', // cyan
  '#34d399', // green
  '#fbbf24', // amber
  '#f472b6', // pink
  '#a78bfa', // violet
  '#fb923c', // orange
  '#22d3ee', // cyan-light
  '#e879f9', // fuchsia
];

// Format numbers with abbreviations
function formatNumber(value: number): string {
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(value % 1_000_000 === 0 ? 0 : 1)}M`;
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(value % 1_000 === 0 ? 0 : 1)}K`;
  }
  return value.toLocaleString();
}

interface FunnelStage {
  level: number;
  name: string;
  count: number;
  percent: number;
  dropoff: number;
  dropoffPercent: number;
}

function FunnelVisualization({ results, onDrilldown }: { results: SearchResult[]; onDrilldown?: FlowVisualizationProps['onDrilldown'] }) {
  // Transform funnel results into stages
  // Funnel command returns: funnel_level, count
  const stages: FunnelStage[] = React.useMemo(() => {
    if (!results.length) return [];

    // Sort by funnel_level
    const sorted = [...results].sort((a, b) => {
      const levelA = Number(a.fields.funnel_level ?? 0);
      const levelB = Number(b.fields.funnel_level ?? 0);
      return levelA - levelB;
    });

    // Get the initial count (level 1 or highest level count)
    const initialCount = sorted.reduce((max, r) => {
      const count = Number(r.fields.count ?? 0);
      return Math.max(max, count);
    }, 0);

    // Build stages array
    const stages: FunnelStage[] = [];
    let prevCount = initialCount;

    for (const result of sorted) {
      const level = Number(result.fields.funnel_level ?? stages.length + 1);
      const count = Number(result.fields.count ?? 0);
      const percent = initialCount > 0 ? (count / initialCount) * 100 : 0;
      const dropoff = prevCount - count;
      const dropoffPercent = prevCount > 0 ? (dropoff / prevCount) * 100 : 0;

      // Use step_name from backend if available, otherwise fall back to "Step N"
      const stepName = result.fields.step_name;
      const name = stepName && stepName !== 'none'
        ? String(stepName)
        : `Step ${level}`;

      stages.push({
        level,
        name,
        count,
        percent,
        dropoff,
        dropoffPercent,
      });

      prevCount = count;
    }

    return stages;
  }, [results]);

  if (!stages.length) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <p className="search-console-section-header justify-center"><TrendingDown />Funnel Trace</p>
        <p className="mt-3 text-sm text-foreground">No funnel stages returned</p>
        <p className="text-xs mt-1">Check the funnel definition or broaden the search scope.</p>
      </div>
    );
  }

  const maxCount = Math.max(...stages.map(s => s.count));

  return (
    <div className="space-y-6">
      <div>
        <div className="search-console-section-header"><TrendingDown />Funnel Trace</div>
        <div className="search-console-section-meta mt-2">
          {stages.length} step{stages.length !== 1 ? 's' : ''} in funnel
        </div>
      </div>

      {/* Funnel visualization */}
      <div className="space-y-3">
        {stages.map((stage, idx) => {
          const widthPercent = maxCount > 0 ? (stage.count / maxCount) * 100 : 0;
          const minWidth = 20; // Minimum width so small bars are visible

          return (
            <div key={stage.level}>
              {/* Stage bar */}
              <div
                className="relative cursor-pointer group"
                onClick={() => onDrilldown?.({ funnel_level: stage.level })}
              >
                <div
                  className="h-12 rounded-lg flex items-center justify-between px-4 transition-all duration-300 group-hover:opacity-80"
                  style={{
                    backgroundColor: FLOW_COLORS[idx % FLOW_COLORS.length],
                    width: `${Math.max(widthPercent, minWidth)}%`,
                  }}
                >
                  <span className="text-sm font-medium text-white truncate">
                    {stage.name}
                  </span>
                  <span className="text-sm font-bold text-white">
                    {formatNumber(stage.count)}
                  </span>
                </div>

                {/* Conversion percentage badge */}
                <div className="absolute -right-16 top-1/2 -translate-y-1/2 flex items-center gap-1 text-xs text-muted-foreground">
                  <Percent className="w-3 h-3" />
                  {stage.percent.toFixed(1)}%
                </div>
              </div>

              {/* Dropoff indicator between stages */}
              {idx < stages.length - 1 && stage.dropoff > 0 && (
                <div className="flex items-center justify-center py-1">
                  <div className="flex items-center gap-2 text-xs text-red-400/80">
                    <TrendingDown className="w-3 h-3" />
                    <span>-{formatNumber(stage.dropoff)} ({stage.dropoffPercent.toFixed(1)}% dropoff)</span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Summary table */}
      <div className="border border-border rounded-lg overflow-hidden mt-6">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              <th className="text-left px-3 py-2 text-xs font-medium text-muted-foreground uppercase">Step</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground uppercase">Count</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground uppercase">% of Total</th>
              <th className="text-right px-3 py-2 text-xs font-medium text-muted-foreground uppercase">Dropoff</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {stages.map((stage, idx) => (
              <tr
                key={stage.level}
                className={`hover:bg-accent/50 transition-colors ${onDrilldown ? 'cursor-pointer' : ''} ${idx % 2 === 0 ? 'bg-muted/10' : ''}`}
                onClick={() => onDrilldown?.({ funnel_level: stage.level })}
              >
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2 h-2 rounded-sm shrink-0"
                      style={{ backgroundColor: FLOW_COLORS[idx % FLOW_COLORS.length] }}
                    />
                    <span className="font-medium">{stage.name}</span>
                  </div>
                </td>
                <td className="text-right px-3 py-2 font-mono text-primary">
                  {stage.count.toLocaleString()}
                </td>
                <td className="text-right px-3 py-2 font-mono text-muted-foreground">
                  {stage.percent.toFixed(1)}%
                </td>
                <td className="text-right px-3 py-2 font-mono text-red-400/80">
                  {idx > 0 ? `-${stage.dropoff.toLocaleString()}` : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {onDrilldown && (
        <p className="text-xs text-muted-foreground mt-2">
          Click a step to drill down into events at that stage
        </p>
      )}
    </div>
  );
}

interface SequenceMatch {
  groupFields: Record<string, string>;
  steps: Array<{
    stepNum: number;
    time: string;
    eventId: string;
    capturedFields: Record<string, string>;
  }>;
  sequenceCount: number;
  durationSeconds: number;
}

// Parse step fields from result (step1_time, step1_event_id, step1_url_domain, etc.)
function parseSequenceResult(fields: Record<string, unknown>): SequenceMatch {
  const groupFields: Record<string, string> = {};
  const stepData: Record<number, { time?: string; eventId?: string; fields: Record<string, string> }> = {};

  // Known metadata fields to exclude from group fields
  const metaFields = new Set([
    'sequence_count', 'sequence_duration_seconds', 'maxspan_seconds', 'timestamp'
  ]);

  for (const [key, value] of Object.entries(fields)) {
    const strValue = value != null ? String(value) : '';

    // Check if this is a step field (step1_time, step2_url_domain, etc.)
    const stepMatch = key.match(/^step(\d+)_(.+)$/);
    if (stepMatch) {
      const stepNum = parseInt(stepMatch[1], 10);
      const fieldName = stepMatch[2];

      if (!stepData[stepNum]) {
        stepData[stepNum] = { fields: {} };
      }

      if (fieldName === 'time') {
        stepData[stepNum].time = strValue;
      } else if (fieldName === 'event_id') {
        stepData[stepNum].eventId = strValue;
      } else {
        stepData[stepNum].fields[fieldName] = strValue;
      }
    } else if (!metaFields.has(key) && !key.startsWith('step')) {
      // This is a group-by field
      groupFields[key] = strValue;
    }
  }

  // Convert stepData to sorted array
  const steps = Object.entries(stepData)
    .sort(([a], [b]) => parseInt(a) - parseInt(b))
    .map(([num, data]) => ({
      stepNum: parseInt(num),
      time: data.time || '',
      eventId: data.eventId || '',
      capturedFields: data.fields,
    }));

  return {
    groupFields,
    steps,
    sequenceCount: Number(fields.sequence_count ?? 0),
    durationSeconds: Number(fields.sequence_duration_seconds ?? 0),
  };
}

// Format timestamp for display
function formatStepTime(time: string): string {
  if (!time) return '-';
  try {
    const date = new Date(time.replace(' ', 'T') + 'Z');
    return date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return time;
  }
}

function SequenceVisualization({ results, onDrilldown }: { results: SearchResult[]; onDrilldown?: FlowVisualizationProps['onDrilldown'] }) {
  const [expandedRows, setExpandedRows] = React.useState<Set<number>>(new Set());

  // Parse sequence results into rich structure
  const sequences: SequenceMatch[] = React.useMemo(() => {
    if (!results.length) return [];
    return results.slice(0, 50).map(r => parseSequenceResult(r.fields || {}));
  }, [results]);

  const toggleRow = (idx: number) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(idx)) {
        next.delete(idx);
      } else {
        next.add(idx);
      }
      return next;
    });
  };

  if (!sequences.length) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <p className="search-console-section-header justify-center"><Percent />Sequence Trace</p>
        <p className="mt-3 text-sm text-foreground">No sequence matches returned</p>
        <p className="text-xs mt-1">Relax the sequence constraints or widen the time range.</p>
      </div>
    );
  }

  const maxCount = Math.max(...sequences.map(s => s.sequenceCount));
  const numSteps = sequences[0]?.steps.length || 0;

  return (
    <div className="flex flex-col min-h-0 min-w-0 overflow-hidden space-y-4">
      <div>
        <div className="search-console-section-header"><Percent />Sequence Trace</div>
        <div className="search-console-section-meta mt-2">
          {results.length} match{results.length !== 1 ? 'es' : ''}
          {results.length > 50 && ` · top 50 shown`}
          {' · '}{numSteps} steps
        </div>
      </div>

      {/* Sequence results - card-based for better handling of many steps */}
      <div className="space-y-2">
        {sequences.map((seq, idx) => {
          const isExpanded = expandedRows.has(idx);
          return (
            <div
              key={idx}
              className="border border-border rounded-lg overflow-hidden bg-card"
            >
              {/* Summary row - always visible */}
              <div
                className="flex items-center gap-4 px-4 py-3 cursor-pointer hover:bg-accent/30 transition-colors"
                onClick={() => toggleRow(idx)}
              >
                {/* Expand indicator */}
                <div className="text-muted-foreground">
                  {isExpanded ? '▼' : '▶'}
                </div>

                {/* Entity info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 flex-wrap">
                    {Object.entries(seq.groupFields).map(([key, value]) => (
                      <span key={key} className="inline-flex items-center gap-1">
                        <span className="text-xs text-muted-foreground">{key}:</span>
                        <span className="font-mono text-sm font-medium truncate max-w-[200px]" title={value}>
                          {value}
                        </span>
                      </span>
                    ))}
                  </div>
                </div>

                {/* Step timeline preview */}
                <div className="hidden sm:flex items-center gap-1">
                  {seq.steps.map((step, stepIdx) => (
                    <React.Fragment key={stepIdx}>
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: FLOW_COLORS[stepIdx % FLOW_COLORS.length] }}
                        title={`Step ${stepIdx + 1}: ${formatStepTime(step.time)}`}
                      />
                      {stepIdx < seq.steps.length - 1 && (
                        <div className="w-4 h-0.5 bg-muted-foreground/30" />
                      )}
                    </React.Fragment>
                  ))}
                </div>

                {/* Duration */}
                <div className="text-sm text-muted-foreground whitespace-nowrap">
                  {seq.durationSeconds > 0 ? `${seq.durationSeconds}s` : '< 1s'}
                </div>

                {/* Count with bar */}
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-medium text-primary">
                    {seq.sequenceCount.toLocaleString()}
                  </span>
                  <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary/60"
                      style={{ width: `${(seq.sequenceCount / maxCount) * 100}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Expanded step details */}
              {isExpanded && (
                <div className="border-t border-border bg-muted/10 px-4 py-3">
                  <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${Math.min(numSteps, 4)}, 1fr)` }}>
                    {seq.steps.map((step, stepIdx) => (
                      <div
                        key={stepIdx}
                        className="bg-background rounded-lg p-3 border border-border"
                      >
                        {/* Step header */}
                        <div className="flex items-center gap-2 mb-2 pb-2 border-b border-border">
                          <div
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: FLOW_COLORS[stepIdx % FLOW_COLORS.length] }}
                          />
                          <span className="text-xs font-medium">Step {step.stepNum}</span>
                        </div>

                        {/* Timestamp */}
                        <div className="text-xs text-muted-foreground mb-2">
                          {formatStepTime(step.time)}
                        </div>

                        {/* Captured fields */}
                        <div className="space-y-1">
                          {Object.entries(step.capturedFields).map(([key, value]) => (
                            <div key={key} className="flex items-start gap-1">
                              <span className="text-xs text-muted-foreground shrink-0">{key}:</span>
                              <span
                                className="font-mono text-xs break-all"
                                title={value}
                              >
                                {value.length > 50 ? value.slice(0, 50) + '...' : value}
                              </span>
                            </div>
                          ))}
                        </div>

                        {/* Drill-down link */}
                        {step.eventId && (
                          <button
                            className="text-xs text-primary hover:underline mt-2"
                            onClick={(e) => {
                              e.stopPropagation();
                              onDrilldown?.({ id: step.eventId });
                            }}
                          >
                            View event →
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {onDrilldown && (
        <p className="text-xs text-muted-foreground mt-2">
          Click a row to expand step details, or "View event" to see full event
        </p>
      )}
    </div>
  );
}

export function FlowVisualization({ results, onDrilldown, mode }: FlowVisualizationProps) {
  // Auto-detect mode based on results if not specified
  const detectedMode = React.useMemo(() => {
    if (mode) return mode;
    if (!results.length) return 'funnel';

    const fields = results[0].fields || {};
    // Funnel results have funnel_level field
    if ('funnel_level' in fields) return 'funnel';
    // Sequence results have sequence_count field
    if ('sequence_count' in fields) return 'sequence';

    return 'funnel';
  }, [results, mode]);

  if (detectedMode === 'funnel') {
    return <FunnelVisualization results={results} onDrilldown={onDrilldown} />;
  }

  return <SequenceVisualization results={results} onDrilldown={onDrilldown} />;
}
