// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * VisualizationRenderer Component
 * 
 * Renders different visualization types based on configuration.
 * Supports bar, line, area, pie charts using Recharts,
 * table visualization with sorting and pagination,
 * single value metric with thresholds, and timeline visualization.
 * 
 * Requirements: 3.1, 3.4, 3.5, 3.6, 3.7, 3.8
 */

import { useState, useMemo } from 'react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { Button } from '@/components/ui/button';
import { ChevronUp, ChevronDown, ChevronLeft, ChevronRight, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import type { VisualizationType, VisualizationConfig, TableColumnConfig } from '@/lib/api';
import type { DrilldownFilter } from './Panel';
import { TreeVisualization, type TreeNode } from '@/components/search/TreeVisualization';
import { RankedBarChart } from '@/components/search/RankedBarChart';
import { TransactionCards } from '@/components/search/TransactionCards';
import { FlowVisualization } from '@/components/search/FlowVisualization';

// Chart color palette matching the dark theme
// Uses CSS variable colors from index.css for consistency
// Primary colors: blue, green, yellow, red (matching chart-1 through chart-5)
// Extended palette for additional series
const CHART_COLORS = [
  '#3b82f6', // blue-500 (primary)
  '#22c55e', // green-500
  '#eab308', // yellow-500
  '#ef4444', // red-500
  '#a855f7', // purple-500
  '#06b6d4', // cyan-500
  '#f97316', // orange-500
  '#ec4899', // pink-500
];

// Consistent axis styling for dark theme
const AXIS_STYLE = {
  stroke: '#6b7280', // gray-500
  fontSize: 10,
  fontFamily: 'var(--font-mono)',
  tickLine: false,
  axisLine: false,
};

// Tooltip styling - uses CSS variables for theme awareness
const TOOLTIP_STYLE: React.CSSProperties = {
  backgroundColor: 'var(--popover)',
  border: '1px solid var(--border)',
  borderRadius: '0.75rem', // rounded-xl
  color: 'var(--popover-foreground)',
  fontFamily: 'var(--font-mono)',
  fontSize: '11px',
};

// Label styling for tooltips
const TOOLTIP_LABEL_STYLE: React.CSSProperties = {
  color: 'var(--muted-foreground)',
  fontFamily: 'var(--font-mono)',
  fontSize: '10px',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
};

// Compact format for fixed-size containers (donut center, single-value KPI).
// Below 10k stays comma-separated for legibility; above uses 5.5M / 12.3K so the
// digits fit inside the donut hole instead of being clipped by the ring.
function formatCompactNumber(n: number): string {
  if (Math.abs(n) < 10_000) return n.toLocaleString();
  return new Intl.NumberFormat('en-US', {
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(n);
}

/**
 * Detect and pivot split-by data format for timechart queries
 *
 * Input format (row-based, from `| timechart count by action`):
 *   [{ time_bucket: "10:00", action: "cache_miss", count: 45 },
 *    { time_bucket: "10:00", action: "cache_hit", count: 120 }]
 *
 * Output format (columnar, for multi-series charts):
 *   [{ time_bucket: "10:00", cache_miss: 45, cache_hit: 120 }]
 */
function pivotSplitByData(data: Record<string, unknown>[]): {
  data: Record<string, unknown>[];
  labelKey: string;
  valueKeys: string[];
  wasPivoted: boolean;
} {
  if (!data.length) {
    return { data: [], labelKey: '', valueKeys: [], wasPivoted: false };
  }

  const keys = Object.keys(data[0]);
  const numericKeys = keys.filter(k => typeof data[0][k] === 'number');
  const stringKeys = keys.filter(k => typeof data[0][k] === 'string');

  // Find time-like key for label
  const timeKeys = stringKeys.filter(k =>
    k.includes('time') || k.includes('bucket') || k.includes('_time')
  );
  const labelKey = timeKeys[0] || stringKeys[0] || keys[0];

  // Detect split-by pattern: one time column + one split column + one numeric column
  const nonLabelStringKeys = stringKeys.filter(k => k !== labelKey);
  const isSplitByFormat = nonLabelStringKeys.length === 1 && numericKeys.length === 1;

  if (!isSplitByFormat) {
    // Not split-by format, return as-is
    const valueKeys = numericKeys.length > 0 ? numericKeys : keys.filter(k => k !== labelKey);
    return { data, labelKey, valueKeys, wasPivoted: false };
  }

  // Pivot the data
  const splitField = nonLabelStringKeys[0];
  const valueField = numericKeys[0];

  const pivotMap = new Map<string, Record<string, unknown>>();
  const allSplitValues = new Set<string>();

  data.forEach((row) => {
    const labelValue = String(row[labelKey] ?? '');
    const splitValue = String(row[splitField] ?? 'unknown');
    const numValue = Number(row[valueField] ?? 0);

    allSplitValues.add(splitValue);

    if (!pivotMap.has(labelValue)) {
      pivotMap.set(labelValue, { [labelKey]: row[labelKey] });
    }

    const dataPoint = pivotMap.get(labelValue)!;
    dataPoint[splitValue] = numValue;
  });

  // Convert to array and ensure all split values are present
  const splitValueKeys = Array.from(allSplitValues).sort();
  const pivotedData = Array.from(pivotMap.values()).map((point) => {
    splitValueKeys.forEach(key => {
      if (!(key in point)) {
        point[key] = 0;
      }
    });
    return point;
  });

  return { data: pivotedData, labelKey, valueKeys: splitValueKeys, wasPivoted: true };
}

export interface VisualizationRendererProps {
  type: VisualizationType;
  config: VisualizationConfig;
  data: Record<string, unknown>[];
  onDrilldown?: (filter: DrilldownFilter) => void;
}

export function VisualizationRenderer({
  type,
  config,
  data,
  onDrilldown,
}: VisualizationRendererProps) {
  switch (type) {
    case 'bar':
      return <BarVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'line':
      return <LineVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'area':
      return <AreaVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'pie':
      return <PieVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'table':
      return <TableVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'single_value':
      return <SingleValueVisualization data={data} config={config} />;
    case 'timeline':
      return <TimelineVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'tree':
      return <DashboardTreeVisualization data={data} config={config} onDrilldown={onDrilldown} />;
    case 'ranked_bar':
      return <DashboardRankedBarChart data={data} onDrilldown={onDrilldown} />;
    case 'transaction':
      return <DashboardTransactionCards data={data} onDrilldown={onDrilldown} />;
    case 'flow':
      return <DashboardFlowVisualization data={data} onDrilldown={onDrilldown} />;
    default:
      return <TableVisualization data={data} config={config} onDrilldown={onDrilldown} />;
  }
}

// Helper to extract grouping fields (non-numeric fields) from data entry
// This is used for drilldown to include all group-by field values
function extractGroupingFields(entry: Record<string, unknown>): DrilldownFilter[] {
  const filters: DrilldownFilter[] = [];
  for (const [key, value] of Object.entries(entry)) {
    // Skip numeric values (these are typically aggregation results like count, sum, etc.)
    if (typeof value === 'number') continue;
    // Skip null/undefined values
    if (value === null || value === undefined) continue;
    // Include string and other non-numeric values as filters
    filters.push({
      field: key,
      value: String(value),
      operator: '=',
    });
  }
  return filters;
}

// Bar Chart Visualization
interface ChartVisualizationProps {
  data: Record<string, unknown>[];
  config: VisualizationConfig;
  onDrilldown?: (filter: DrilldownFilter) => void;
}

function BarVisualization({ data, config, onDrilldown }: ChartVisualizationProps) {
  // Pivot split-by data if needed (e.g., timechart count by action)
  const { data: pivotedData, labelKey, valueKeys } = useMemo(
    () => pivotSplitByData(data),
    [data]
  );

  const isHorizontal = config?.orientation === 'horizontal';

  // Limit data for bar charts - too many bars makes them unreadable
  // Horizontal bars: max 15 (they need vertical space)
  // Vertical bars: max 20 (they need horizontal space)
  const maxBars = isHorizontal ? 15 : 20;
  const displayData = pivotedData.length > maxBars ? pivotedData.slice(0, maxBars) : pivotedData;
  const isLimited = pivotedData.length > maxBars;

  // Calculate dynamic Y-axis width for horizontal charts based on label length
  const maxLabelLength = isHorizontal 
    ? Math.max(...displayData.map(d => String(d[labelKey] || '').length))
    : 0;
  const yAxisWidth = isHorizontal ? Math.min(Math.max(maxLabelLength * 7, 80), 200) : 60;

  // Handle click on bar - extracts all grouping fields for drilldown
  const handleBarClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;
    
    // Get all grouping fields (non-numeric) for comprehensive drilldown
    const filters = extractGroupingFields(entry);
    
    // If we have filters, use the first one (primary grouping field)
    // The full entry data is available for more complex drilldown scenarios
    if (filters.length > 0) {
      onDrilldown(filters[0]);
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart 
            data={displayData} 
            layout={isHorizontal ? 'vertical' : 'horizontal'}
            onClick={(e) => {
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              const payload = (e as any)?.activePayload?.[0]?.payload;
              if (payload) handleBarClick(payload as Record<string, unknown>);
            }}
            margin={{ top: 5, right: 20, left: 10, bottom: isHorizontal ? 5 : 20 }}
          >
            {isHorizontal ? (
              <>
                <XAxis
                  type="number"
                  {...AXIS_STYLE}
                  tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
                  tickFormatter={formatCompactNumber}
                />
                <YAxis
                  dataKey={labelKey}
                  type="category"
                  {...AXIS_STYLE}
                  width={yAxisWidth}
                  tick={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                  tickFormatter={(value) => String(value).length > 25 ? String(value).substring(0, 22) + '...' : String(value)}
                />
              </>
            ) : (
              <>
                <XAxis
                  dataKey={labelKey}
                  {...AXIS_STYLE}
                  tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
                  interval="preserveStartEnd"
                  angle={-30}
                  textAnchor="end"
                  height={56}
                />
                <YAxis
                  {...AXIS_STYLE}
                  tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
                  tickFormatter={formatCompactNumber}
                  width={56}
                />
              </>
            )}
            <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} cursor={false} />
            {valueKeys.length > 1 && <Legend wrapperStyle={{ color: '#9ca3af', fontFamily: 'var(--font-mono)', fontSize: '11px' }} />}
            {valueKeys.map((key, i) => (
              <Bar
                key={key}
                dataKey={key}
                fill={CHART_COLORS[i % CHART_COLORS.length]}
                radius={isHorizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]}
                stackId={config?.stacked ? 'stack' : undefined}
                cursor={onDrilldown ? 'pointer' : 'default'}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      {isLimited && (
        <div className="py-1 text-center text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
          Showing top {maxBars} of {data.length} results
        </div>
      )}
    </div>
  );
}

// Line Chart Visualization
function LineVisualization({ data, config, onDrilldown }: ChartVisualizationProps) {
  // Pivot split-by data if needed (e.g., timechart count by action)
  const { data: chartData, labelKey, valueKeys } = useMemo(
    () => pivotSplitByData(data),
    [data]
  );

  // Handle click on line point - extracts all grouping fields for drilldown
  const handlePointClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;

    // Get all grouping fields (non-numeric) for comprehensive drilldown
    const filters = extractGroupingFields(entry);

    if (filters.length > 0) {
      onDrilldown(filters[0]);
    }
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart
        data={chartData}
        margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
        onClick={(e) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const payload = (e as any)?.activePayload?.[0]?.payload;
          if (payload) handlePointClick(payload as Record<string, unknown>);
        }}
      >
        <XAxis
          dataKey={labelKey}
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          interval="preserveStartEnd"
          minTickGap={32}
        />
        <YAxis
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          tickFormatter={formatCompactNumber}
          width={56}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} />
        {valueKeys.length > 1 && <Legend wrapperStyle={{ color: '#9ca3af', fontFamily: 'var(--font-mono)', fontSize: '11px' }} />}
        {valueKeys.map((key, i) => (
          <Line
            key={key}
            type={config?.smooth ? 'monotone' : 'linear'}
            dataKey={key}
            stroke={CHART_COLORS[i % CHART_COLORS.length]}
            strokeWidth={2}
            dot={config?.showPoints !== false}
            activeDot={{ r: 6, cursor: onDrilldown ? 'pointer' : 'default' }}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}

// Area Chart Visualization
function AreaVisualization({ data, config, onDrilldown }: ChartVisualizationProps) {
  // Pivot split-by data if needed (e.g., timechart count by action)
  const { data: chartData, labelKey, valueKeys } = useMemo(
    () => pivotSplitByData(data),
    [data]
  );

  // Handle click on area point - extracts all grouping fields for drilldown
  const handlePointClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;

    // Get all grouping fields (non-numeric) for comprehensive drilldown
    const filters = extractGroupingFields(entry);

    if (filters.length > 0) {
      onDrilldown(filters[0]);
    }
  };

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart
        data={chartData}
        margin={{ top: 5, right: 20, left: 10, bottom: 5 }}
        onClick={(e) => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const payload = (e as any)?.activePayload?.[0]?.payload;
          if (payload) handlePointClick(payload as Record<string, unknown>);
        }}
      >
        <XAxis
          dataKey={labelKey}
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          interval="preserveStartEnd"
          minTickGap={32}
        />
        <YAxis
          {...AXIS_STYLE}
          tick={{ fill: '#9ca3af', fontFamily: 'var(--font-mono)' }}
          tickFormatter={formatCompactNumber}
          width={56}
        />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={TOOLTIP_LABEL_STYLE} />
        {valueKeys.length > 1 && <Legend wrapperStyle={{ color: '#9ca3af', fontFamily: 'var(--font-mono)', fontSize: '11px' }} />}
        {valueKeys.map((key, i) => (
          <Area
            key={key}
            type={config?.smooth ? 'monotone' : 'linear'}
            dataKey={key}
            stroke={CHART_COLORS[i % CHART_COLORS.length]}
            fill={CHART_COLORS[i % CHART_COLORS.length]}
            fillOpacity={config?.fillOpacity ?? 0.3}
            activeDot={{ r: 6, cursor: onDrilldown ? 'pointer' : 'default' }}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

// Pie Chart Visualization
function PieVisualization({ data, config, onDrilldown }: ChartVisualizationProps) {
  const keys = Object.keys(data[0] || {});
  
  // Find the numeric field (value) and string field (label)
  // The value field should be numeric, the label field should be the category
  let valueKey = keys[1];
  let labelKey = keys[0];
  
  // Check if we need to swap - if first key's value is numeric, it's likely the value
  if (data[0] && typeof data[0][keys[0]] === 'number' && typeof data[0][keys[1]] !== 'number') {
    valueKey = keys[0];
    labelKey = keys[1];
  }

  // Calculate total for center display
  const total = data.reduce((sum, item) => sum + (Number(item[valueKey]) || 0), 0);

  // Check if labels should be shown (default to false for clean donut look)
  const showLabels = config?.showLabels === true;

  // Handle click on pie slice - extracts all grouping fields for drilldown
  const handleSliceClick = (entry: Record<string, unknown>) => {
    if (!onDrilldown) return;
    
    // Get all grouping fields (non-numeric) for comprehensive drilldown
    const filters = extractGroupingFields(entry);
    
    if (filters.length > 0) {
      onDrilldown(filters[0]);
    }
  };

  // Custom label renderer for outside labels
  const renderLabel = showLabels ? (props: {
    cx?: number;
    cy?: number;
    midAngle?: number;
    outerRadius?: number;
    name?: string;
    percent?: number;
  }) => {
    const { cx = 0, cy = 0, midAngle = 0, outerRadius = 0, name = '', percent = 0 } = props;
    const RADIAN = Math.PI / 180;
    const radius = outerRadius * 1.2;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);

    return (
      <text
        x={x}
        y={y}
        fill="#f3f4f6"
        textAnchor={x > cx ? 'start' : 'end'}
        dominantBaseline="central"
        style={{ fontSize: '11px' }}
      >
        {`${name || 'null'} (${(percent * 100).toFixed(0)}%)`}
      </text>
    );
  } : false;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={data}
          dataKey={valueKey}
          nameKey={labelKey}
          cx="50%"
          cy="50%"
          innerRadius="60%"
          outerRadius={showLabels ? "70%" : "85%"}
          paddingAngle={0}
          strokeWidth={0}
          label={renderLabel}
          labelLine={showLabels}
          onClick={(_, index) => handleSliceClick(data[index])}
          cursor={onDrilldown ? 'pointer' : 'default'}
        >
          {data.map((_, i) => (
            <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} stroke="none" />
          ))}
        </Pie>
        <Tooltip 
          contentStyle={TOOLTIP_STYLE} 
          itemStyle={{ color: '#f3f4f6', fontFamily: 'var(--font-mono)', fontSize: '11px' }}
          formatter={(value, name) => {
            const coerced = typeof value === 'number' ? value : Number(value);
            const n = Number.isFinite(coerced) ? coerced : 0;
            return [
              `${n.toLocaleString()} (${((n / total) * 100).toFixed(1)}%)`,
              (typeof name === 'string' ? name : String(name ?? '')) || 'null',
            ];
          }}
        />
        {/* Center text showing total */}
        <text
          x="50%"
          y="46%"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '24px', fontWeight: 'bold', fill: '#f3f4f6', fontFamily: 'var(--font-mono)' }}
        >
          {formatCompactNumber(total)}
        </text>
        <text
          x="50%"
          y="56%"
          textAnchor="middle"
          dominantBaseline="middle"
          style={{ fontSize: '11px', fill: '#9ca3af', fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', textTransform: 'uppercase' }}
        >
          Total
        </text>
      </PieChart>
    </ResponsiveContainer>
  );
}

// Table Visualization with sorting and pagination
function TableVisualization({ data, config, onDrilldown }: ChartVisualizationProps) {
  const [sortField, setSortField] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [currentPage, setCurrentPage] = useState(0);
  
  const pageSize = config?.pageSize || 10;
  
  // Generate columns from config or data
  const columns: TableColumnConfig[] = useMemo(() => {
    if (config?.columns && config.columns.length > 0) {
      return config.columns;
    }
    return Object.keys(data[0] || {}).map(key => ({
      field: key,
      label: key,
      sortable: true,
    }));
  }, [config?.columns, data]);

  // Sort data
  const sortedData = useMemo(() => {
    if (!sortField) return data;
    
    return [...data].sort((a, b) => {
      const aVal = a[sortField];
      const bVal = b[sortField];
      
      if (aVal === bVal) return 0;
      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;
      
      const comparison = aVal < bVal ? -1 : 1;
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [data, sortField, sortDirection]);

  // Paginate data
  const paginatedData = useMemo(() => {
    const start = currentPage * pageSize;
    return sortedData.slice(start, start + pageSize);
  }, [sortedData, currentPage, pageSize]);

  const totalPages = Math.ceil(data.length / pageSize);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // Handle click on table row - extracts all grouping fields for drilldown
  const handleRowClick = (row: Record<string, unknown>) => {
    if (!onDrilldown) return;
    
    // Get all grouping fields (non-numeric) for comprehensive drilldown
    const filters = extractGroupingFields(row);
    
    // Use the first filter (primary grouping field)
    if (filters.length > 0) {
      onDrilldown(filters[0]);
    }
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-card">
            <tr className="border-b border-border">
              {columns.map((col) => (
                <th 
                  key={col.field} 
                  className={`p-2 text-left text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground font-medium ${
                    col.sortable ? 'cursor-pointer hover:text-primary' : ''
                  }`}
                  style={col.width ? { width: col.width } : undefined}
                  onClick={() => col.sortable && handleSort(col.field)}
                >
                  <div className="flex items-center gap-1">
                    {col.label}
                    {col.sortable && sortField === col.field && (
                      sortDirection === 'asc' 
                        ? <ChevronUp className="w-3 h-3" />
                        : <ChevronDown className="w-3 h-3" />
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginatedData.map((row, i) => (
              <tr 
                key={i} 
                className={`border-b border-border hover:bg-accent/50 ${
                  onDrilldown ? 'cursor-pointer' : ''
                }`}
                onClick={() => handleRowClick(row)}
              >
                {columns.map((col) => (
                  <td key={col.field} className="p-2 font-mono text-[13px] text-foreground">
                    {formatCellValue(row[col.field])}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      
      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2 border-t border-border mt-2">
          <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Showing {currentPage * pageSize + 1}-{Math.min((currentPage + 1) * pageSize, data.length)} of {data.length}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
              disabled={currentPage === 0}
              className="h-7 w-7 p-0 text-muted-foreground"
            >
              <ChevronLeft className="w-4 h-4" />
            </Button>
            <span className="px-2 text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              {currentPage + 1} / {totalPages}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={currentPage >= totalPages - 1}
              className="h-7 w-7 p-0 text-muted-foreground"
            >
              <ChevronRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// Single Value Metric Visualization
interface SingleValueProps {
  data: Record<string, unknown>[];
  config: VisualizationConfig;
}

function SingleValueVisualization({ data, config }: SingleValueProps) {
  const keys = Object.keys(data[0] || {});
  const valueKey = keys.find(k => typeof data[0][k] === 'number') || keys[0];
  const value = data[0]?.[valueKey];
  
  // Calculate trend if we have multiple data points
  const trend = useMemo(() => {
    if (!config?.showTrend || data.length < 2) return null;
    
    const current = Number(data[0]?.[valueKey]) || 0;
    const previous = Number(data[1]?.[valueKey]) || 0;
    
    if (previous === 0) return null;
    
    const percentChange = ((current - previous) / previous) * 100;
    return {
      direction: percentChange > 0 ? 'up' : percentChange < 0 ? 'down' : 'flat',
      value: Math.abs(percentChange).toFixed(1),
    };
  }, [data, valueKey, config?.showTrend]);

  // Determine color based on thresholds
  const getColor = (val: unknown): string => {
    if (!config?.thresholds || typeof val !== 'number') {
      return 'text-foreground';
    }
    
    // Sort thresholds descending
    const sortedThresholds = [...config.thresholds].sort((a, b) => b.value - a.value);
    
    for (const threshold of sortedThresholds) {
      if (val >= threshold.value) {
        // Handle both direct color classes and color names
        if (threshold.color.startsWith('text-') || threshold.color.startsWith('#')) {
          return threshold.color;
        }
        return `text-${threshold.color}-500`;
      }
    }
    
    return 'text-foreground';
  };

  const colorClass = getColor(value);
  const displayValue = typeof value === 'number'
    ? formatCompactNumber(value)
    : String(value ?? '-');

  return (
    <div className="h-full flex flex-col items-center justify-center">
      <div className={`font-mono text-4xl font-bold ${colorClass}`}>
        {displayValue}
        {config?.unit && (
          <span className="ml-1 text-lg text-muted-foreground">{config.unit}</span>
        )}
      </div>
      
      {trend && (
        <div className={`mt-2 flex items-center gap-1 font-mono text-xs uppercase tracking-[0.12em] ${
          trend.direction === 'up' ? 'text-green-400' :
          trend.direction === 'down' ? 'text-red-400' :
          'text-muted-foreground'
        }`}>
          {trend.direction === 'up' && <TrendingUp className="w-4 h-4" />}
          {trend.direction === 'down' && <TrendingDown className="w-4 h-4" />}
          {trend.direction === 'flat' && <Minus className="w-4 h-4" />}
          <span>{trend.value}%</span>
        </div>
      )}
    </div>
  );
}

// Timeline Visualization (essentially an area chart with time on X axis)
function TimelineVisualization({ data, config, onDrilldown }: ChartVisualizationProps) {
  // Timeline is an area chart with specific styling for time-based data
  return (
    <AreaVisualization 
      data={data} 
      config={{ 
        ...config, 
        fillOpacity: config?.fillOpacity ?? 0.5,
        smooth: config?.smooth ?? true,
      }} 
      onDrilldown={onDrilldown}
    />
  );
}

// Numbers render unformatted (no thousands separators) so dest_port / src_port /
// numeric IDs match search-result rendering in PaginatedTable.formatCellValue.
function formatCellValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '-';
  }
  if (typeof value === 'boolean') {
    return value ? 'Yes' : 'No';
  }
  if (value instanceof Date) {
    return value.toLocaleString();
  }
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }
  return String(value);
}

// Dashboard wrapper for TreeVisualization
// Adapts the search tree component to work with dashboard data format
interface DashboardTreeProps {
  data: Record<string, unknown>[];
  config: VisualizationConfig;
  onDrilldown?: (filter: DrilldownFilter) => void;
}

function DashboardTreeVisualization({ data, config, onDrilldown }: DashboardTreeProps) {
  // Tree config from visualization config (TreeConfig uses snake_case)
  const treeConfig = {
    parent_field: config?.parentField || 'parent_id',
    child_field: config?.childField || 'id',
    label_field: config?.labelField || 'name',
  };

  // Build tree nodes from flat data
  const nodes = useMemo((): TreeNode[] => {
    if (!data.length) return [];

    const { parent_field, child_field, label_field } = treeConfig;

    const nodeMap = new Map<string, TreeNode>();
    const rootNodes: TreeNode[] = [];

    // First pass: create all nodes
    for (const row of data) {
      const id = String(row[child_field] ?? '');
      const label = String(row[label_field] ?? id);

      nodeMap.set(id, {
        id,
        label,
        _data: row,
        children: [],
      });
    }

    // Second pass: build tree structure
    for (const row of data) {
      const id = String(row[child_field] ?? '');
      const parentId = row[parent_field] != null ? String(row[parent_field]) : null;
      const node = nodeMap.get(id);

      if (!node) continue;

      if (parentId && nodeMap.has(parentId)) {
        const parent = nodeMap.get(parentId)!;
        parent.children = parent.children || [];
        parent.children.push(node);
      } else {
        // No parent or parent not in data = root node
        rootNodes.push(node);
      }
    }

    return rootNodes;
  }, [data, treeConfig]);

  const handleFilter = onDrilldown
    ? (field: string, value: string) => {
        onDrilldown({ field, value, operator: '=' });
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <TreeVisualization
        nodes={nodes}
        config={treeConfig}
        onFilter={handleFilter}
      />
    </div>
  );
}

// Dashboard wrapper for RankedBarChart
interface DashboardRankedBarProps {
  data: Record<string, unknown>[];
  onDrilldown?: (filter: DrilldownFilter) => void;
}

function DashboardRankedBarChart({ data, onDrilldown }: DashboardRankedBarProps) {
  // Convert dashboard data format to search result format
  const searchResults = data.map((row, idx) => ({
    id: String(idx),
    timestamp: new Date(),
    source: 'dashboard',
    fields: row,
  }));

  const handleDrilldown = onDrilldown
    ? (filters: Record<string, unknown>) => {
        const entries = Object.entries(filters);
        if (entries.length > 0) {
          const [field, value] = entries[0];
          onDrilldown({ field, value: String(value), operator: '=' });
        }
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <RankedBarChart results={searchResults} onDrilldown={handleDrilldown} />
    </div>
  );
}

// Dashboard wrapper for TransactionCards
interface DashboardTransactionProps {
  data: Record<string, unknown>[];
  onDrilldown?: (filter: DrilldownFilter) => void;
}

function DashboardTransactionCards({ data, onDrilldown }: DashboardTransactionProps) {
  // Convert dashboard data format to search result format
  const searchResults = data.map((row, idx) => ({
    id: String(idx),
    timestamp: new Date(),
    source: 'dashboard',
    fields: row,
  }));

  const handleDrilldown = onDrilldown
    ? (filters: Record<string, unknown>) => {
        const entries = Object.entries(filters);
        if (entries.length > 0) {
          const [field, value] = entries[0];
          onDrilldown({ field, value: String(value), operator: '=' });
        }
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <TransactionCards
        results={searchResults}
        onDrilldown={handleDrilldown}
      />
    </div>
  );
}

// Dashboard wrapper for FlowVisualization
interface DashboardFlowProps {
  data: Record<string, unknown>[];
  onDrilldown?: (filter: DrilldownFilter) => void;
}

function DashboardFlowVisualization({ data, onDrilldown }: DashboardFlowProps) {
  // Convert dashboard data format to search result format
  const searchResults = data.map((row, idx) => ({
    id: String(idx),
    timestamp: new Date(),
    source: 'dashboard',
    fields: row,
  }));

  const handleDrilldown = onDrilldown
    ? (filters: Record<string, unknown>) => {
        const entries = Object.entries(filters);
        if (entries.length > 0) {
          const [field, value] = entries[0];
          onDrilldown({ field, value: String(value), operator: '=' });
        }
      }
    : undefined;

  return (
    <div className="h-full overflow-auto">
      <FlowVisualization results={searchResults} onDrilldown={handleDrilldown} />
    </div>
  );
}

export default VisualizationRenderer;
