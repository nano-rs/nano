// SPDX-License-Identifier: AGPL-3.0-or-later

import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';

interface TierUsageBarProps {
  label: string;
  current: number;
  limit: number | null;
  className?: string;
}

/**
 * Compact usage indicator showing current/max with a colored progress bar.
 * Only renders when there's a limit (non-null). Hidden on Unrestricted tier.
 *
 * Colors: green (0-79%), yellow (80-94%), red (95-100%)
 */
export function TierUsageBar({ label, current, limit, className }: TierUsageBarProps) {
  if (limit === null || limit === undefined) return null;

  const percent = Math.min(Math.round((current / limit) * 100), 100);

  const barColor = percent >= 95
    ? 'bg-red-400 dark:bg-red-400'
    : percent >= 80
    ? 'bg-yellow-400 dark:bg-yellow-400'
    : 'bg-emerald-400 dark:bg-emerald-400';

  const textColor = percent >= 95
    ? 'text-red-400'
    : percent >= 80
    ? 'text-yellow-400'
    : 'text-muted-foreground/70';

  const tooltipText = percent >= 95
    ? `You've reached your ${label} limit. Upgrade your plan for more.`
    : percent >= 80
    ? `You're approaching your ${label} limit. Upgrade your plan for more.`
    : `Using ${current} of ${limit} ${label}. Upgrade your plan for more.`;

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div className={cn('flex items-center gap-2 text-xs cursor-default', className)}>
            <span className={cn('tabular-nums whitespace-nowrap', textColor)}>
              {current} / {limit} {label}
            </span>
            <div className="w-20 h-1.5 rounded-full bg-border overflow-hidden">
              <div
                className={cn('h-full rounded-full transition-all', barColor)}
                style={{ width: `${percent}%` }}
              />
            </div>
          </div>
        </TooltipTrigger>
        <TooltipContent>
          <p>{tooltipText}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
