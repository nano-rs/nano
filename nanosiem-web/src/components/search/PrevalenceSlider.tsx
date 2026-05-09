// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useState, useRef, useEffect } from 'react';
import { Slider } from '@/components/ui/slider';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { Filter, ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PrevalenceSliderProps {
  value: number; // 0-100, default 100 (show all)
  onChange: (value: number) => void;
  disabled?: boolean;
}

const PRESETS = [
  { label: 'Very Rare', value: 10, description: '<5 hosts' },
  { label: 'Rare', value: 25, description: '<12 hosts' },
  { label: 'Uncommon', value: 50, description: '<25 hosts' },
  { label: 'All', value: 100, description: 'no filter' },
];

export function PrevalenceSlider({ value, onChange, disabled }: PrevalenceSliderProps) {
  const [isOpen, setIsOpen] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [localValue, setLocalValue] = useState(value);

  useEffect(() => {
    setLocalValue(value);
  }, [value]);

  const handleSliderChange = useCallback(
    (newValue: number[]) => {
      const val = newValue[0];
      setLocalValue(val);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(() => onChange(val), 300);
    },
    [onChange]
  );

  useEffect(() => () => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
  }, []);

  const handlePresetClick = useCallback(
    (presetValue: number) => {
      setLocalValue(presetValue);
      onChange(presetValue);
      setIsOpen(false);
    },
    [onChange]
  );

  const getDisplayLabel = () => {
    if (localValue >= 100) return 'All';
    if (localValue <= 10) return 'Very Rare';
    if (localValue <= 25) return 'Rare';
    if (localValue <= 50) return 'Uncommon';
    return `<${localValue}`;
  };

  const isFiltering = localValue < 100;

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
                  isFiltering
                    ? 'border-primary/30 bg-primary/8 text-primary hover:bg-primary/14'
                    : 'border-border bg-foreground/[0.02] text-muted-foreground hover:border-border/80 hover:text-foreground',
                  disabled && 'opacity-50 cursor-not-allowed'
                )}
              >
                <Filter className="w-[11px] h-[11px]" />
                Rarity
                {isFiltering && (
                  <span className="rounded-sm bg-primary/15 text-primary text-[9.5px] px-1 font-semibold tabular-nums">
                    {getDisplayLabel()}
                  </span>
                )}
                <ChevronDown className="w-[10px] h-[10px]" />
              </button>
            </PopoverTrigger>
          </TooltipTrigger>
          <PopoverContent
            align="end"
            className="w-[280px] p-0 overflow-hidden rounded-md border border-border bg-popover shadow-[0_20px_60px_rgba(0,0,0,0.5)]"
          >
            {/* Header */}
            <div className="px-3 pt-2.5 pb-2 border-b border-border flex items-center justify-between font-mono">
              <span className="text-[10.5px] tracking-[0.12em] uppercase text-muted-foreground font-semibold">
                Rarity Filter
              </span>
              <span
                className={cn(
                  'text-[10.5px] tabular-nums font-medium',
                  isFiltering ? 'text-primary' : 'text-muted-foreground/70'
                )}
              >
                {isFiltering ? `<${localValue}%` : 'all'}
              </span>
            </div>

            {/* Slider */}
            <div className="px-3 pt-3 pb-3">
              <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/60 font-semibold mb-2">
                <span>rare only</span>
                <span>all</span>
              </div>
              <Slider
                value={[localValue]}
                onValueChange={handleSliderChange}
                min={0}
                max={100}
                step={5}
                disabled={disabled}
                className="w-full"
              />
            </div>

            {/* Presets */}
            <div className="border-t border-border px-1.5 py-1.5">
              <div className="px-2 pt-1 pb-1 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/60 font-semibold">
                Presets
              </div>
              <div className="flex flex-col gap-px">
                {PRESETS.map((preset) => {
                  const active = localValue === preset.value;
                  return (
                    <button
                      key={preset.value}
                      onClick={() => handlePresetClick(preset.value)}
                      disabled={disabled}
                      className={cn(
                        'px-2.5 py-1.5 text-[12px] rounded-sm cursor-pointer flex items-center justify-between transition-colors',
                        active
                          ? 'bg-primary/10 text-primary'
                          : 'text-foreground/80 hover:bg-foreground/[0.04] hover:text-foreground'
                      )}
                    >
                      <span className="font-medium">{preset.label}</span>
                      <span className="flex items-center gap-2 font-mono text-[10.5px] text-muted-foreground/70">
                        {preset.description}
                        {active && <span className="w-1 h-1 rounded-full bg-primary" />}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Info */}
            <div className="border-t border-border px-3 py-2 font-mono text-[10px] text-muted-foreground/70 leading-relaxed">
              Rarity is derived from how common an artifact is across your environment. Lower values surface rarer artifacts first.
            </div>
          </PopoverContent>
          <TooltipContent side="bottom">
            <p>Filter by artifact rarity</p>
            <p className="text-xs text-primary-foreground/70">Surface rare hashes, domains, or IPs</p>
          </TooltipContent>
        </Popover>
      </Tooltip>
    </TooltipProvider>
  );
}
