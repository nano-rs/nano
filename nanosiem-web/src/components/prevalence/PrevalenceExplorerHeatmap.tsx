// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo, useState } from 'react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import type { ArtifactExplorerItem } from '@/lib/api/types';

interface PrevalenceExplorerHeatmapProps {
  artifacts: ArtifactExplorerItem[];
  timeWindow: string;
  onArtifactClick?: (artifact: ArtifactExplorerItem) => void;
}

/** Build 30 date columns for the heatmap — always shows last 30 days */
function buildDateColumns(): { iso: string; label: string }[] {
  const days: { iso: string; label: string }[] = [];
  const now = new Date();

  for (let i = 29; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const iso = d.toISOString().slice(0, 10);
    const label = `${d.getMonth() + 1}/${d.getDate()}`;
    days.push({ iso, label });
  }
  return days;
}

/**
 * Artifact Prevalence Explorer Heatmap
 *
 * CSS Grid heatmap showing artifact activity over time.
 * Y-axis: artifact names, X-axis: dates (bottom), cells: square colored blocks.
 * Red scale for rare artifacts, blue scale for common ones.
 */
export function PrevalenceExplorerHeatmap({
  artifacts,
  timeWindow: _timeWindow,
  onArtifactClick,
}: PrevalenceExplorerHeatmapProps) {
  const [hoveredCell, setHoveredCell] = useState<{ row: number; col: number } | null>(null);

  const { dateColumns, grid, globalMax } = useMemo(() => {
    const cols = buildDateColumns();

    let max = 1;
    const rows = artifacts.map((artifact) => {
      const countMap = new Map<string, number>();
      for (const dc of artifact.daily_counts) {
        countMap.set(dc.date, dc.count);
      }
      const cells = cols.map((col) => {
        const value = countMap.get(col.iso) ?? 0;
        if (value > max) max = value;
        return value;
      });
      return { artifact, cells };
    });

    return { dateColumns: cols, grid: rows, globalMax: max };
  }, [artifacts]);

  if (artifacts.length === 0) {
    return (
      <div className="p-8 text-center text-muted-foreground text-sm">
        No artifacts to display in heatmap
      </div>
    );
  }

  const showEveryNth = dateColumns.length > 14 ? Math.ceil(dateColumns.length / 10) : 1;

  return (
    <TooltipProvider delayDuration={100}>
      <div className="overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Artifact rows */}
          <div className="space-y-[2px]">
            {grid.map((row, rowIdx) => (
              <div
                key={row.artifact.artifact}
                className="flex items-center gap-1 group cursor-pointer hover:bg-accent/30 rounded-lg transition-colors"
                onClick={() => onArtifactClick?.(row.artifact)}
              >
                {/* Artifact label */}
                <Tooltip>
                  <TooltipTrigger asChild>
                    <div className="w-[176px] flex-shrink-0 truncate text-xs font-mono text-muted-foreground group-hover:text-foreground px-2 py-0.5 transition-colors">
                      {row.artifact.artifact}
                    </div>
                  </TooltipTrigger>
                  <TooltipContent side="right" className="bg-card border-border max-w-xs">
                    <p className="font-mono text-xs break-all">{row.artifact.artifact}</p>
                    <p className="text-muted-foreground text-[10px] mt-1">
                      {row.artifact.host_count} hosts &middot; {row.artifact.total_occurrences} total
                    </p>
                  </TooltipContent>
                </Tooltip>

                {/* Heatmap cells */}
                <div className="flex flex-1 gap-[2px]">
                  {row.cells.map((value, colIdx) => {
                    const intensity = value / globalMax;
                    const isRare = row.artifact.is_rare;
                    const isHovered = hoveredCell?.row === rowIdx && hoveredCell?.col === colIdx;

                    return (
                      <Tooltip key={colIdx}>
                        <TooltipTrigger asChild>
                          <div
                            className="flex-1 rounded-[2px] transition-all"
                            style={{
                              height: '28px',
                              backgroundColor:
                                value === 0
                                  ? 'var(--heatmap-empty, oklch(0.25 0 0))'
                                  : isRare
                                    ? `oklch(0.55 ${0.08 + intensity * 0.15} 25 / ${0.25 + intensity * 0.75})`
                                    : `oklch(0.6 ${0.06 + intensity * 0.12} 250 / ${0.2 + intensity * 0.8})`,
                              transform: isHovered ? 'scale(1.1)' : undefined,
                              zIndex: isHovered ? 10 : undefined,
                            }}
                            onMouseEnter={() => setHoveredCell({ row: rowIdx, col: colIdx })}
                            onMouseLeave={() => setHoveredCell(null)}
                          />
                        </TooltipTrigger>
                        <TooltipContent
                          side="top"
                          className="bg-card border-border text-xs px-2 py-1"
                        >
                          <p className="font-mono text-[10px] text-muted-foreground truncate max-w-[200px]">
                            {row.artifact.artifact}
                          </p>
                          <p className="text-muted-foreground">{dateColumns[colIdx].label}</p>
                          <p className="text-foreground font-medium">{value.toLocaleString()} events</p>
                        </TooltipContent>
                      </Tooltip>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>

          {/* Date labels — bottom */}
          <div className="flex items-start mt-1 pl-[180px] gap-[2px]">
            {dateColumns.map((col, i) => (
              <div
                key={col.iso}
                className="flex-1 text-center text-[10px] text-muted-foreground leading-tight"
              >
                {i % showEveryNth === 0 ? col.label : ''}
              </div>
            ))}
          </div>

          {/* Legend */}
          <div className="flex items-center justify-end gap-4 mt-2 px-2">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: 'oklch(0.55 0.20 25 / 0.8)' }} />
              <span className="text-[10px] text-muted-foreground">Rare</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: 'oklch(0.6 0.15 250 / 0.8)' }} />
              <span className="text-[10px] text-muted-foreground">Common</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: 'var(--heatmap-empty, oklch(0.25 0 0))' }} />
              <span className="text-[10px] text-muted-foreground">No activity</span>
            </div>
          </div>
        </div>
      </div>
    </TooltipProvider>
  );
}
