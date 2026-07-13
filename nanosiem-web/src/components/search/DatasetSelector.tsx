// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Layers, ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SearchDataset } from '@/lib/api/types';

interface DatasetSelectorProps {
  value: SearchDataset;
  onChange: (value: SearchDataset) => void;
  disabled?: boolean;
}

const OPTIONS: { value: SearchDataset; label: string; description: string }[] = [
  { value: 'logs', label: 'Logs', description: 'UDM / OCSF events' },
  { value: 'spans', label: 'Traces', description: 'OTLP spans' },
  { value: 'metrics', label: 'Metrics', description: 'OTLP metrics' },
  { value: 'risk', label: 'Risk', description: 'Accumulated entity risk' },
];

/**
 * Compact dropdown-card selector for the observability dataset the nPL pipeline
 * runs against (NAN-1555). Mirrors the `PrevalenceSlider` "Rarity" control —
 * a single chip-button that opens a popover card — so it sits inline in the
 * footer chip row next to Rarity instead of consuming a full segmented row.
 */
export function DatasetSelector({ value, onChange, disabled }: DatasetSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const current = OPTIONS.find((o) => o.value === value) ?? OPTIONS[0];
  const isNonDefault = value !== 'logs';

  return (
    <TooltipProvider>
      <Tooltip>
        <Popover open={isOpen} onOpenChange={setIsOpen}>
          <TooltipTrigger asChild>
            <PopoverTrigger asChild>
              <button
                type="button"
                disabled={disabled}
                className={cn(
                  'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border transition-colors whitespace-nowrap shrink-0 font-mono text-[11px]',
                  isNonDefault
                    ? 'border-primary/30 bg-primary/8 text-primary hover:bg-primary/14'
                    : 'border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground',
                  disabled && 'opacity-50 cursor-not-allowed'
                )}
              >
                <Layers className="w-[11px] h-[11px]" />
                Dataset
                <span
                  className={cn(
                    'rounded-sm text-[9.5px] px-1 font-semibold',
                    isNonDefault ? 'bg-primary/15 text-primary' : 'bg-foreground/[0.06] text-muted-foreground'
                  )}
                >
                  {current.label}
                </span>
                <ChevronDown className="w-[10px] h-[10px]" />
              </button>
            </PopoverTrigger>
          </TooltipTrigger>
          <PopoverContent
            align="end"
            className="w-[260px] p-0 overflow-hidden rounded-md border border-border bg-popover shadow-[0_20px_60px_rgba(0,0,0,0.5)]"
          >
            {/* Header */}
            <div className="px-3 pt-2.5 pb-2 border-b border-border flex items-center justify-between font-mono">
              <span className="text-[10.5px] tracking-[0.12em] uppercase text-muted-foreground font-semibold">
                Dataset
              </span>
              <span
                className={cn(
                  'text-[10.5px] font-medium',
                  isNonDefault ? 'text-primary' : 'text-muted-foreground/70'
                )}
              >
                {current.label.toLowerCase()}
              </span>
            </div>

            {/* Options */}
            <div className="px-1.5 py-1.5">
              <div className="flex flex-col gap-px">
                {OPTIONS.map((opt) => {
                  const active = value === opt.value;
                  return (
                    <button
                      key={opt.value}
                      onClick={() => {
                        onChange(opt.value);
                        setIsOpen(false);
                      }}
                      disabled={disabled}
                      className={cn(
                        'px-2.5 py-1.5 text-[12px] rounded-sm cursor-pointer flex items-center justify-between transition-colors',
                        active
                          ? 'bg-primary/10 text-primary'
                          : 'text-foreground/80 hover:bg-foreground/[0.04] hover:text-foreground'
                      )}
                    >
                      <span className="font-medium">{opt.label}</span>
                      <span className="flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground/70">
                        {opt.description}
                        {active && <span className="w-1 h-1 rounded-full bg-primary" />}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Info — dataset-specific note (replaces the old inline tips) */}
            <div className="border-t border-border px-3 py-2 font-mono text-[10px] text-muted-foreground/70 leading-relaxed">
              {value === 'metrics' ? (
                <>
                  Metric data points. The{' '}
                  <RouterLink to="/observability/metrics" className="text-primary hover:underline">
                    Metrics explorer
                  </RouterLink>{' '}
                  is the primary surface.
                </>
              ) : value === 'spans' ? (
                <>
                  OTLP spans return as rows — see the{' '}
                  <RouterLink to="/observability/traces" className="text-primary hover:underline">
                    Traces explorer
                  </RouterLink>{' '}
                  for waterfalls.
                </>
              ) : value === 'risk' ? (
                <>
                  One row per scored entity — score_24h / score_7d, findings, distinct
                  rules and tactics over fixed 24h / 7d windows.
                </>
              ) : (
                <>Normalized logs (UDM/OCSF) — the default search plane.</>
              )}
            </div>
          </PopoverContent>
          <TooltipContent side="bottom">
            <p>Query dataset</p>
            <p className="text-xs text-primary-foreground/70">Logs, OTLP traces, metrics, or accumulated risk</p>
          </TooltipContent>
        </Popover>
      </Tooltip>
    </TooltipProvider>
  );
}
