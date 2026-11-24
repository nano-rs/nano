// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5839: searchable timezone picker for a log source.
 *
 * The setting applies only to timestamps that carry no offset of their own;
 * the parser reads such a clock in this zone and stores true UTC. Options:
 * UTC (default), every fixed offset the server accepts, and every IANA zone
 * the browser knows (grouped by region, with its current offset).
 *
 * Built on the repo's Radix Popover (portaled, collision-aware, Escape closes
 * and returns focus to the trigger) and cmdk Command (combobox input outside
 * the listbox, arrow keys + Enter, groups as `role="group"`), like
 * `SourceTypeCombobox`.
 */
import { useMemo, useState } from 'react';
import { Check, ChevronDown, Clock } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command';
import { cn } from '@/lib/utils';
import {
  DEFAULT_SOURCE_TIMEZONE,
  SOURCE_TIMEZONE_HELP,
  currentOffset,
  filterTimezoneGroups,
  timezoneDisplay,
  timezoneGroups,
} from '@/lib/source-timezones';

export function TimezonePicker({
  value,
  onChange,
  placement = 'down',
  disabled = false,
}: {
  value: string;
  onChange: (v: string) => void;
  /** Preferred side; Radix flips it when there is no room. */
  placement?: 'up' | 'down';
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const current = value && value.trim() ? value : DEFAULT_SOURCE_TIMEZONE;

  const all = useMemo(() => (open ? timezoneGroups() : []), [open]);
  const groups = useMemo(() => filterTimezoneGroups(all, q), [all, q]);
  const hint = currentOffset(current);

  const setOpenAndReset = (next: boolean) => {
    setOpen(next);
    if (!next) setQ('');
  };

  return (
    <Popover open={open} onOpenChange={setOpenAndReset}>
      <PopoverTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          role="combobox"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-label={`Timezone: ${timezoneDisplay(current)}`}
          className="h-7 px-2 rounded-[4px] border border-border bg-card hover:bg-foreground/[0.04] inline-flex items-center gap-1.5 text-[11.5px] text-foreground/80 disabled:opacity-50"
        >
          <Clock className="w-3 h-3 text-muted-foreground" strokeWidth={1.5} />
          <span className="font-mono">{timezoneDisplay(current)}</span>
          {current !== DEFAULT_SOURCE_TIMEZONE && hint && (
            <>
              <span className="text-muted-foreground/60">·</span>
              <span className="font-mono text-[10.5px] text-muted-foreground">{hint}</span>
            </>
          )}
          <ChevronDown
            className={cn('w-3 h-3 text-muted-foreground ml-0.5 transition-transform', open && 'rotate-180')}
            strokeWidth={1.5}
          />
        </button>
      </PopoverTrigger>
      <PopoverContent
        side={placement === 'up' ? 'top' : 'bottom'}
        align="end"
        collisionPadding={16}
        className="w-[min(320px,calc(100vw-32px))] p-0"
      >
        <Command shouldFilter={false} label="Timezones">
          <CommandInput
            value={q}
            onValueChange={setQ}
            placeholder="Search zones or offsets (New_York, -05:00)"
            aria-label="Search timezones"
            className="h-8 text-[11.5px]"
          />
          <CommandList label="Timezones" className="max-h-[min(300px,var(--radix-popover-content-available-height,300px))]">
            <CommandEmpty>
              <span className="text-[11px] text-muted-foreground">No matches</span>
            </CommandEmpty>
            {groups.map((g) => (
              <CommandGroup
                key={g.region}
                heading={g.region}
                className="[&_[cmdk-group-heading]]:text-[9.5px] [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[0.14em]"
              >
                {g.items.map((it) => (
                  <CommandItem
                    key={it.id}
                    value={it.id}
                    onSelect={() => {
                      onChange(it.id);
                      setOpenAndReset(false);
                    }}
                    data-current={current === it.id ? 'true' : undefined}
                    className={cn('h-6 py-0 gap-2', current === it.id && 'bg-primary/10')}
                  >
                    <span className="font-mono text-[11.5px] text-foreground flex-1 truncate">{it.label}</span>
                    <span className="text-[10.5px] font-mono text-muted-foreground">{it.hint}</span>
                    <Check
                      className={cn('w-3 h-3 text-primary', current === it.id ? 'opacity-100' : 'opacity-0')}
                      strokeWidth={1.5}
                    />
                  </CommandItem>
                ))}
              </CommandGroup>
            ))}
          </CommandList>
        </Command>
        <div className="border-t border-border px-2.5 py-1.5 text-[10.5px] text-muted-foreground leading-relaxed">
          {SOURCE_TIMEZONE_HELP}
        </div>
      </PopoverContent>
    </Popover>
  );
}
