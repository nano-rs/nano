// SPDX-License-Identifier: AGPL-3.0-or-later
import * as React from 'react';
import { format, isValid, parse } from 'date-fns';
import { CalendarDays } from 'lucide-react';
import { DayFlag, SelectionState, UI } from 'react-day-picker';
import { Button } from '@/components/ui/button';
import { Calendar } from '@/components/ui/calendar';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';

const DAY = 'yyyy-MM-dd';

// Same dense grid as the time-range picker's custom calendar (mono 11px days,
// 28px cells, caption-flanking nav), reduced to single-day selection.
const denseDayGrid = {
  [UI.Month]: 'space-y-2 min-w-0 relative',
  [UI.MonthCaption]: 'flex items-center justify-center px-0.5 pb-1',
  [UI.CaptionLabel]: 'text-[12px] font-semibold font-mono tracking-wide text-foreground',
  [UI.Nav]: 'flex items-center',
  [UI.PreviousMonthButton]: 'h-5 w-5 p-0 rounded hover:bg-foreground/5 text-muted-foreground inline-flex items-center justify-center absolute top-0 left-0.5',
  [UI.NextMonthButton]: 'h-5 w-5 p-0 rounded hover:bg-foreground/5 text-muted-foreground inline-flex items-center justify-center absolute top-0 right-0.5',
  [UI.MonthGrid]: 'w-full border-collapse',
  [UI.Weekdays]: 'flex',
  [UI.Weekday]: 'w-7 text-center text-muted-foreground/60 text-[9px] font-mono font-semibold py-1 uppercase tracking-[0.08em]',
  [UI.Week]: 'flex w-full mt-0.5',
  [UI.Day]: 'w-7 relative p-0 text-center font-mono text-[11px]',
  [UI.DayButton]: 'h-7 w-7 p-0 font-normal text-foreground hover:bg-foreground/5 rounded-sm inline-flex items-center justify-center transition-colors',
  [SelectionState.selected]: '[&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:font-semibold [&>button]:hover:bg-primary [&>button]:hover:text-primary-foreground',
  [DayFlag.today]: '[&>button]:relative [&>button]:after:absolute [&>button]:after:bottom-0.5 [&>button]:after:left-1/2 [&>button]:after:-translate-x-1/2 [&>button]:after:w-[3px] [&>button]:after:h-[3px] [&>button]:after:rounded-full [&>button]:after:bg-primary',
  [DayFlag.outside]: '[&>button]:text-muted-foreground/30',
  [DayFlag.disabled]: '[&>button]:!text-muted-foreground/30 [&>button]:!cursor-not-allowed [&>button]:hover:!bg-transparent',
  [DayFlag.hidden]: 'invisible',
};

/** `YYYY-MM-DD` → local Date, or undefined when empty / malformed. */
function parseDay(value: string | null | undefined): Date | undefined {
  if (!value) return undefined;
  const date = parse(value, DAY, new Date());
  return isValid(date) ? date : undefined;
}

export interface DatePickerProps {
  /** Calendar day as `YYYY-MM-DD`, or null when unset. Controlled. */
  value: string | null;
  onChange: (value: string | null) => void;
  placeholder?: string;
  disabled?: boolean;
  /** Show a "Clear" action in the popover when a day is set (default true). */
  clearable?: boolean;
  align?: 'start' | 'center' | 'end';
  className?: string;
  id?: string;
  'aria-label'?: string;
}

/**
 * Single-day picker: a compact mono trigger that opens the shared `Calendar`
 * (the same day grid the time-range picker uses) in a popover. Values are
 * plain `YYYY-MM-DD` calendar days with no time zone, matching the API.
 */
export function DatePicker({ value, onChange, placeholder = 'Pick a date', disabled, clearable = true, align = 'start', className, id, ...aria }: DatePickerProps) {
  const [open, setOpen] = React.useState(false);
  const selected = parseDay(value);
  return <Popover open={open} onOpenChange={setOpen}>
    <PopoverTrigger asChild>
      <Button id={id} type="button" variant="outline" disabled={disabled} aria-label={aria['aria-label']}
        className={cn('h-8 justify-start gap-2 px-2.5 font-mono text-[12px] font-normal', !selected && 'text-muted-foreground', className)}>
        <CalendarDays className="size-3.5 shrink-0 opacity-60" strokeWidth={1.5} aria-hidden="true" />
        <span className="truncate">{selected ? format(selected, DAY) : placeholder}</span>
      </Button>
    </PopoverTrigger>
    <PopoverContent className="w-auto p-2" align={align}>
      <Calendar mode="single" navLayout="around" className="p-0" classNames={denseDayGrid} selected={selected} defaultMonth={selected}
        onSelect={day => { if (day) onChange(format(day, DAY)); setOpen(false); }} />
      {clearable && selected && <div className="mt-2 flex justify-end border-t border-border pt-1.5">
        <Button type="button" variant="ghost" className="h-6 px-2 text-[11px]" onClick={() => { onChange(null); setOpen(false); }}>Clear</Button>
      </div>}
    </PopoverContent>
  </Popover>;
}
