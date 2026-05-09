// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-505 — searchable combobox for picking a destination source type, with
// a "suggested" badge for the recommended target. Reused by the per-rule
// preview pane and the bulk-import drawer.

import { useState } from 'react';
import { Check, ChevronsUpDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';

interface Props {
  value: string;
  onSelect: (value: string) => void;
  sourceTypes: string[];
  placeholder?: string;
  suggestedType?: string;
  allowSkip?: boolean;
  className?: string;
  size?: 'sm' | 'md';
  /**
   * When true, the trigger renders in a warning style + a "custom" badge to
   * call out that the user has overridden a default. Caller decides — usually
   * `value && value !== upstreamDefault`.
   */
  overridden?: boolean;
}

export function SourceTypeCombobox({
  value,
  onSelect,
  sourceTypes,
  placeholder = 'Select source type…',
  suggestedType,
  allowSkip,
  className,
  size = 'md',
  overridden,
}: Props) {
  const [open, setOpen] = useState(false);
  const display = value === '__skip__' ? 'Skip (keep original)' : value;
  const heightCls = size === 'sm' ? 'h-[22px]' : 'h-[26px]';

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          role="combobox"
          aria-expanded={open}
          className={cn(
            'inline-flex items-center justify-between gap-1.5 rounded-md border px-2 text-[11px] font-mono focus:outline-none focus:border-primary',
            heightCls,
            overridden
              ? 'border-warning/50 bg-warning/10 text-warning ring-1 ring-warning/20 hover:bg-warning/15'
              : 'border-border bg-card text-foreground/80 hover:border-border/80 hover:bg-muted/40',
            !value && 'text-muted-foreground',
            className,
          )}
        >
          <span className="truncate flex items-center gap-1.5">
            {value ? display : placeholder}
            {overridden && (
              <span
                className={cn(
                  'shrink-0 rounded font-mono uppercase tracking-wider border',
                  size === 'sm'
                    ? 'text-[8.5px] px-1 leading-[10px] py-px'
                    : 'text-[9px] px-1 leading-[12px] py-px',
                  'border-warning/50 text-warning bg-warning/10',
                )}
              >
                custom
              </span>
            )}
          </span>
          <ChevronsUpDown className="w-[11px] h-[11px] shrink-0 opacity-50" strokeWidth={1.5} />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-[260px] p-0" align="start">
        <Command>
          <CommandInput
            placeholder="Search source types…"
            className="h-8 text-[11.5px]"
          />
          <CommandList>
            <CommandEmpty className="py-3 text-[11.5px] text-muted-foreground">
              No source types found.
            </CommandEmpty>
            <CommandGroup>
              {allowSkip && (
                <CommandItem
                  value="__skip__"
                  onSelect={() => {
                    onSelect('__skip__');
                    setOpen(false);
                  }}
                  className="text-[11.5px] text-muted-foreground"
                >
                  <Check
                    className={cn(
                      'mr-1.5 h-3 w-3',
                      value === '__skip__' ? 'opacity-100' : 'opacity-0',
                    )}
                  />
                  Skip (keep original)
                </CommandItem>
              )}
              {sourceTypes.map((s) => (
                <CommandItem
                  key={s}
                  value={s}
                  onSelect={() => {
                    onSelect(s);
                    setOpen(false);
                  }}
                  className="text-[11.5px] font-mono"
                >
                  <Check
                    className={cn(
                      'mr-1.5 h-3 w-3',
                      value === s ? 'opacity-100' : 'opacity-0',
                    )}
                  />
                  {s}
                  {suggestedType === s && (
                    <span className="ml-auto text-[9.5px] text-success/80 font-mono uppercase tracking-wider">
                      suggested
                    </span>
                  )}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
