// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

interface HeatmapDay {
  value: number;
  date: string; // display label like "3/18"
}

interface RuleActivityHeatmapProps {
  data: HeatmapDay[];
  className?: string;
}

/**
 * Compact 28-day activity heatmap for detection rules.
 * Renders a 4-row x 7-col grid where color intensity encodes firing frequency.
 * Theme-aware: uses primary blue in dark mode, deeper blue in light mode.
 */
export function RuleActivityHeatmap({ data, className = '' }: RuleActivityHeatmapProps) {
  const { maxValue, cells } = useMemo(() => {
    const max = data.reduce((m, d) => d.value > m ? d.value : m, 1);
    return { maxValue: max, cells: data };
  }, [data]);

  return (
    <TooltipProvider delayDuration={150}>
      <div className={`flex gap-px ${className}`}>
        {cells.map((cell, i) => {
          const intensity = cell.value / maxValue;
          return (
            <Tooltip key={i}>
              <TooltipTrigger asChild>
                <div
                  className="w-2 h-6 rounded-[2px] transition-colors"
                  style={{
                    backgroundColor: cell.value === 0
                      ? 'var(--heatmap-empty, oklch(0.25 0 0))'
                      : `oklch(from var(--primary) l c h / ${0.15 + intensity * 0.85})`,
                  }}
                />
              </TooltipTrigger>
              <TooltipContent
                side="top"
                className="bg-card border-border text-xs px-2 py-1"
              >
                <p className="text-muted-foreground">{cell.date}</p>
                <p className="text-foreground font-medium">{cell.value} events</p>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}
