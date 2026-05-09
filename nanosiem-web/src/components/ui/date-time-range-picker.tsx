// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import { format } from 'date-fns';
import { formatInTimeZone } from 'date-fns-tz';
import { ArrowRight, ChevronDown, Clock } from 'lucide-react';
import { DayFlag, SelectionState, UI } from 'react-day-picker';
import { Calendar } from '@/components/ui/calendar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import { useIsMobile } from '@/hooks/use-mobile';
import { toApiTimeRange, type TimeRangeValue } from '@/hooks/use-api';

interface DateTimeRangePickerProps {
  value: TimeRangeValue;
  onChange: (value: TimeRangeValue) => void;
  className?: string;
  variant?: 'default' | 'search';
  aiMode?: boolean;
  /** Popover alignment (default: "end" on desktop, "center" on mobile) */
  align?: 'start' | 'center' | 'end';
  /** Initial mode when popover opens (default: "custom" on desktop, "presets" on mobile) */
  defaultMode?: 'presets' | 'custom';
  /** Optional uppercase mono label rendered inside the trigger before the
      time value (e.g. "against"). When set, the trigger also shows a
      trailing chevron for popover affordance. Used by surfaces that want
      the label fused into the same pill as the value (rule-test drawer). */
  labelPrefix?: string;
  /** Optional hard cap on the selectable range, in days (NAN-742). When
      set: presets longer than the cap are hidden, and once the user has
      anchored a date in the custom calendar, dates more than `maxRangeDays`
      from that anchor become disabled. Default `undefined` = unconstrained,
      so existing call sites (Search, Dashboards, etc.) are unaffected.
      Used by the rule-test drawer to mirror the backend's 14-day cap. */
  maxRangeDays?: number;
}

// Presets organized by category — mirrors mockup `CalendarPopover` grouping
// (Relative = duration-from-now, Absolute = calendar-boundaried). Preset
// labels preserved from the pre-redesign impl so the parser in time-range.ts
// and saved searches keep working.
const presetCategories = [
  {
    label: 'Relative',
    presets: [
      { label: 'Last 5 minutes', value: 'Last 5 minutes' },
      { label: 'Last 15 minutes', value: 'Last 15 minutes' },
      { label: 'Last 30 minutes', value: 'Last 30 minutes' },
      { label: 'Last hour', value: 'Last hour' },
      { label: 'Last 4 hours', value: 'Last 4 hours' },
      { label: 'Last 12 hours', value: 'Last 12 hours' },
      { label: 'Last 24 hours', value: 'Last 24 hours' },
      { label: 'Last 7 days', value: 'Last 7 days' },
      { label: 'Last 30 days', value: 'Last 30 days' },
      { label: 'Last 90 days', value: 'Last 90 days' },
    ],
  },
  {
    label: 'Absolute',
    presets: [
      { label: 'Today', value: 'Today' },
      { label: 'Yesterday', value: 'Yesterday' },
      { label: 'This week', value: 'This week' },
      { label: 'Previous week', value: 'Previous week' },
      { label: 'All time', value: 'All time' },
    ],
  },
];

// Compute a preset's duration in days by running it through the same parser
// the rest of the app uses. Runs on every render of the constrained picker
// (rare — `maxRangeDays` is opt-in, only the rule tester uses it today), and
// the categories list is short, so the work is negligible.
function presetDurationDays(presetValue: string): number {
  try {
    const range = toApiTimeRange(presetValue);
    return (
      (new Date(range.end).getTime() - new Date(range.start).getTime()) / 86_400_000
    );
  } catch {
    return Infinity; // unknown preset → treat as too-long, hide it under any cap
  }
}

export function DateTimeRangePicker({ value, onChange, className, variant = 'default', aiMode = false, align, defaultMode, labelPrefix, maxRangeDays }: DateTimeRangePickerProps) {
  const [open, setOpen] = React.useState(false);
  const isMobile = useIsMobile();
  // Always show custom picker expanded by default (desktop), presets first on mobile
  const [mode, setMode] = React.useState<'presets' | 'custom'>(defaultMode || 'custom');
  // Mobile custom: which field is being picked
  const [mobileCustomStep, setMobileCustomStep] = React.useState<'start' | 'end'>('start');
  const [startDate, setStartDate] = React.useState<Date | undefined>(value.start);
  const [endDate, setEndDate] = React.useState<Date | undefined>(value.end);
  const [startTime, setStartTime] = React.useState(value.start ? format(value.start, 'HH:mm:ss') : '00:00:00');
  const [endTime, setEndTime] = React.useState(value.end ? format(value.end, 'HH:mm:ss') : '23:59:59');

  // Transient warning shown when a range click exceeds `maxRangeDays`. We
  // reject the click in `onSelect` (keeping the previous valid selection)
  // rather than letting react-day-picker's `max` wipe the whole range, and
  // surface this little message so the user understands why their click
  // didn't take.
  const [capWarning, setCapWarning] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!capWarning) return;
    const t = setTimeout(() => setCapWarning(null), 3500);
    return () => clearTimeout(t);
  }, [capWarning]);

  // Filter presets that exceed the cap when one is set. Computed inside the
  // component so it picks up `maxRangeDays` reactively. Also drops any whole
  // category that ends up empty after filtering, so the heading doesn't
  // dangle.
  const visiblePresetCategories = React.useMemo(() => {
    if (maxRangeDays === undefined) return presetCategories;
    return presetCategories
      .map((category) => ({
        ...category,
        presets: category.presets.filter(
          (p) => presetDurationDays(p.value) <= maxRangeDays,
        ),
      }))
      .filter((category) => category.presets.length > 0);
  }, [maxRangeDays]);

  // Sync internal state when value prop changes externally (e.g., from chart selection)
  React.useEffect(() => {
    if (value.type === 'custom' && value.start && value.end) {
      setStartDate(value.start);
      setEndDate(value.end);
      setStartTime(formatInTimeZone(value.start, 'UTC', 'HH:mm:ss'));
      setEndTime(formatInTimeZone(value.end, 'UTC', 'HH:mm:ss'));
    }
  }, [value.type, value.start?.getTime(), value.end?.getTime()]);

  // Desktop: open to custom view with presets on the left
  // Mobile: open to presets (simpler, most common use case)
  React.useEffect(() => {
    if (open) {
      setMode(isMobile ? 'presets' : 'custom');
      setMobileCustomStep('start');
    }
  }, [open, isMobile]);

  // Initialize dates when opening if not set
  React.useEffect(() => {
    if (open && !startDate) {
      const now = new Date();
      setStartDate(new Date(now.getTime() - 24 * 60 * 60 * 1000));
      setEndDate(now);
    }
  }, [open, startDate]);

  const displayValue = React.useMemo(() => {
    if (value.type === 'preset' && value.preset) {
      return value.preset;
    }
    if (value.type === 'custom' && value.start && value.end) {
      return `${formatInTimeZone(value.start, 'UTC', 'MMM d, HH:mm')} - ${formatInTimeZone(value.end, 'UTC', 'MMM d, HH:mm')} UTC`;
    }
    return 'Select time range';
  }, [value]);

  const handlePresetSelect = (preset: string) => {
    setMode('presets');
    // Include refreshedAt to ensure re-selecting the same preset triggers a fresh search
    onChange({ type: 'preset', preset, refreshedAt: Date.now() });
    setOpen(false);
  };

  const handleCustomClick = () => {
    // Legacy handler kept for the mobile layout. Desktop now always shows the
    // calendar, so this only fires on the mobile "Custom range..." link.
    setMode('custom');
  };

  const parseTime = (timeStr: string): [number, number, number] => {
    const parts = timeStr.split(':').map(Number);
    return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
  };

  const handleApplyCustom = () => {
    if (startDate && endDate) {
      const [startHour, startMin, startSec] = parseTime(startTime);
      const [endHour, endMin, endSec] = parseTime(endTime);
      
      // Create UTC dates from the selected calendar dates and times
      const start = new Date(Date.UTC(
        startDate.getFullYear(),
        startDate.getMonth(),
        startDate.getDate(),
        startHour,
        startMin,
        startSec,
        0
      ));
      
      const end = new Date(Date.UTC(
        endDate.getFullYear(),
        endDate.getMonth(),
        endDate.getDate(),
        endHour,
        endMin,
        endSec,
        999
      ));
      
      onChange({ type: 'custom', start, end });
      setOpen(false);
    }
  };

  const isPresetSelected = (preset: string) => {
    // Only show preset as selected if we're NOT in custom mode
    return mode !== 'custom' && value.type === 'preset' && value.preset === preset;
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className={cn(
            variant === 'search'
              ? 'h-[34px] rounded-md border px-3 justify-center text-left font-mono text-[12px] transition-colors'
              : 'h-[44px] rounded-lg border px-3 justify-center text-left font-medium text-sm transition-all duration-500 ease-out',
            aiMode
              ? 'bg-ai-bg-subtle border-ai-border text-ai hover:bg-ai-bg'
              : 'bg-card border-border text-foreground hover:bg-card',
            className
          )}
        >
          <Clock className={cn('mr-2', variant === 'search' ? 'w-[13px] h-[13px]' : 'w-4 h-4', aiMode ? 'text-ai' : 'text-muted-foreground')} />
          {labelPrefix && (
            <span className="mr-1.5 font-mono text-[10.5px] uppercase tracking-[0.08em] text-muted-foreground">
              {labelPrefix}
            </span>
          )}
          <span className="truncate">{displayValue}</span>
          {labelPrefix && (
            <ChevronDown className="ml-1.5 w-[11px] h-[11px] text-muted-foreground/70 shrink-0" />
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className={cn(
          "p-0 bg-popover border-border-2 rounded-xl shadow-[0_40px_100px_rgba(0,0,0,0.6)] overflow-hidden",
          isMobile ? "w-[calc(100vw-2rem)]" : "w-[640px] max-w-[calc(100vw-16px)]"
        )}
        align={align || (isMobile ? "center" : "end")}
        sideOffset={8}
      >
        {isMobile ? (
          /* ── Mobile layout: presets list or single stacked calendar ── */
          <div className="max-h-[70vh] overflow-y-auto">
            {mode === 'presets' ? (
              <div className="p-3 space-y-3">
                {visiblePresetCategories.map((category, idx) => (
                  <div key={category.label}>
                    <div className="text-[10px] font-sans uppercase tracking-[0.08em] text-muted-foreground px-2 mb-1">{category.label}</div>
                    <div className="space-y-0.5">
                      {category.presets.map((preset) => (
                        <button
                          key={preset.value}
                          onClick={() => handlePresetSelect(preset.value)}
                          className={cn(
                            'w-full text-left px-3 py-2.5 text-sm rounded-lg transition-colors',
                            isPresetSelected(preset.value)
                              ? 'bg-primary/20 text-primary font-medium'
                              : 'text-foreground hover:bg-accent/50'
                          )}
                        >
                          {preset.label}
                        </button>
                      ))}
                    </div>
                    {idx < presetCategories.length - 1 && (
                      <div className="border-t border-border mt-3" />
                    )}
                  </div>
                ))}
                <div className="border-t border-border pt-2">
                  <button
                    onClick={handleCustomClick}
                    className="w-full text-left px-3 py-2.5 text-sm rounded-lg transition-colors text-foreground hover:bg-accent/50"
                  >
                    Custom range...
                  </button>
                </div>
              </div>
            ) : (
              <div className="p-4 space-y-3">
                <div className="text-xs font-sans text-muted-foreground text-center">All times are in UTC</div>
                {/* Step tabs */}
                <div className="flex rounded-lg bg-muted/30 p-0.5">
                  <button
                    onClick={() => setMobileCustomStep('start')}
                    className={cn('flex-1 py-1.5 text-xs font-sans font-medium rounded-md transition-all', mobileCustomStep === 'start' ? 'bg-accent text-foreground' : 'text-muted-foreground')}
                  >
                    Start {startDate && <span className="text-[10px] opacity-70">({format(startDate, 'MMM d')})</span>}
                  </button>
                  <button
                    onClick={() => setMobileCustomStep('end')}
                    className={cn('flex-1 py-1.5 text-xs font-sans font-medium rounded-md transition-all', mobileCustomStep === 'end' ? 'bg-accent text-foreground' : 'text-muted-foreground')}
                  >
                    End {endDate && <span className="text-[10px] opacity-70">({format(endDate, 'MMM d')})</span>}
                  </button>
                </div>
                {/* Single calendar */}
                <Calendar
                  mode="single"
                  showOutsideDays={false}
                  selected={mobileCustomStep === 'start' ? startDate : endDate}
                  onSelect={(date) => {
                    if (mobileCustomStep === 'start') {
                      // Re-anchoring start: if there's an existing end and
                      // the new start would exceed the cap, reject and warn.
                      // (The disabled predicate already greys the same
                      // dates out — this is the click-time backstop in case
                      // the predicate ever drifts.)
                      if (
                        maxRangeDays !== undefined &&
                        date &&
                        endDate &&
                        (endDate.getTime() - date.getTime()) / 86_400_000 > maxRangeDays
                      ) {
                        setCapWarning(
                          `Range capped at ${maxRangeDays} days — kept your previous selection.`,
                        );
                        return;
                      }
                      setCapWarning(null);
                      setStartDate(date);
                      setMobileCustomStep('end');
                    } else {
                      // Picking end: same backstop in the forward direction.
                      if (
                        maxRangeDays !== undefined &&
                        date &&
                        startDate &&
                        (date.getTime() - startDate.getTime()) / 86_400_000 > maxRangeDays
                      ) {
                        setCapWarning(
                          `Range capped at ${maxRangeDays} days — kept your previous selection.`,
                        );
                        return;
                      }
                      setCapWarning(null);
                      setEndDate(date);
                    }
                  }}
                  disabled={(date) => {
                    const now = new Date();
                    const utcToday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23, 59, 59, 999));
                    if (date > utcToday) return true;
                    // End picker: disable anything before start, AND (when
                    // capped) anything more than `maxRangeDays` after start.
                    if (mobileCustomStep === 'end' && startDate) {
                      if (date < startDate) return true;
                      if (maxRangeDays !== undefined) {
                        const diffDays =
                          (date.getTime() - startDate.getTime()) / 86_400_000;
                        if (diffDays > maxRangeDays) return true;
                      }
                    }
                    // Start picker: when capped and an end is already set,
                    // mirror the constraint backwards so re-anchoring the
                    // start can't widen the range past the cap.
                    if (mobileCustomStep === 'start' && endDate && maxRangeDays !== undefined) {
                      const diffDays =
                        (endDate.getTime() - date.getTime()) / 86_400_000;
                      if (diffDays > maxRangeDays) return true;
                    }
                    return false;
                  }}
                  className="rounded-lg border border-border"
                  classNames={{
                    [UI.CaptionLabel]: 'text-sm font-sans font-medium text-foreground',
                    [UI.PreviousMonthButton]: 'h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100 border border-border text-muted-foreground hover:text-primary rounded-md inline-flex items-center justify-center',
                    [UI.NextMonthButton]: 'h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100 border border-border text-muted-foreground hover:text-primary rounded-md inline-flex items-center justify-center',
                    [UI.Weekday]: 'text-muted-foreground rounded-md w-8 font-sans font-normal text-[0.8rem]',
                    [UI.DayButton]: 'h-8 w-8 p-0 font-normal text-foreground hover:bg-accent rounded-md inline-flex items-center justify-center',
                    [SelectionState.selected]: '[&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:hover:bg-primary [&>button]:hover:text-primary [&>button]:focus:bg-primary [&>button]:focus:text-foreground',
                    [DayFlag.today]: '[&>button]:bg-accent [&>button]:text-foreground',
                    [DayFlag.outside]: 'text-muted-foreground opacity-50',
                    [DayFlag.disabled]: 'text-muted-foreground opacity-50',
                  }}
                />
                {capWarning && (
                  <div
                    role="status"
                    className="px-2 py-1.5 rounded-sm border border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[11px] font-mono text-foreground/85"
                  >
                    {capWarning}
                  </div>
                )}
                {/* Time input */}
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                  <Input
                    type="text"
                    value={mobileCustomStep === 'start' ? startTime : endTime}
                    onChange={(e) => mobileCustomStep === 'start' ? setStartTime(e.target.value) : setEndTime(e.target.value)}
                    placeholder={mobileCustomStep === 'start' ? '00:00:00' : '23:59:59'}
                    className="bg-background border-border text-foreground rounded-lg h-8 text-sm font-mono flex-1"
                  />
                </div>
                <div className="flex justify-between gap-2 pt-2 border-t border-border">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setMode('presets')}
                    className="text-muted-foreground hover:text-primary hover:bg-accent/50 rounded-lg"
                  >
                    Back
                  </Button>
                  <div className="flex gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setOpen(false)}
                      className="text-muted-foreground hover:text-primary hover:bg-accent/50 rounded-lg"
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={handleApplyCustom}
                      disabled={!startDate || !endDate}
                      className="bg-primary hover:bg-primary/90 rounded-lg"
                    >
                      Apply
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* ── Desktop layout: mockup CalendarPopover — 170px sidebar + 2-month range calendar ── */
          <div className="grid grid-cols-[170px_1fr] overflow-hidden">
            <div
              className="border-r border-border p-1.5 flex flex-col gap-px max-h-[480px] overflow-y-auto"
              style={{ background: 'var(--panel)' }}
            >
              {visiblePresetCategories.map((category) => (
                <React.Fragment key={category.label}>
                  <div className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground/60 px-2.5 pt-2 pb-1 font-semibold">
                    {category.label}
                  </div>
                  {category.presets.map((preset) => {
                    const active = isPresetSelected(preset.value);
                    return (
                      <button
                        key={preset.value}
                        onClick={() => handlePresetSelect(preset.value)}
                        className={cn(
                          'px-2.5 py-1.5 text-[12px] rounded-sm flex items-center justify-between transition-colors',
                          active
                            ? 'bg-primary/10 text-primary'
                            : 'text-foreground hover:bg-foreground/5'
                        )}
                      >
                        <span>{preset.label}</span>
                        {active && <span className="w-1 h-1 rounded-full bg-primary" />}
                      </button>
                    );
                  })}
                </React.Fragment>
              ))}
            </div>

            <div className="px-3 py-2 min-w-0 flex flex-col">
              <Calendar
                mode="range"
                numberOfMonths={2}
                navLayout="around"
                showOutsideDays={false}
                selected={startDate && endDate ? { from: startDate, to: endDate } : undefined}
                onSelect={(range) => {
                  // Cap enforcement: if the new range exceeds maxRangeDays,
                  // reject it and keep the previous valid selection.
                  // react-day-picker has a `max` prop, but it wipes the
                  // whole selection on overflow, which feels punitive — the
                  // user just has to start over. We'd rather preserve their
                  // anchor and surface a small "still capped at N days"
                  // hint that auto-dismisses.
                  if (
                    maxRangeDays !== undefined &&
                    range?.from &&
                    range?.to
                  ) {
                    const days =
                      (range.to.getTime() - range.from.getTime()) / 86_400_000;
                    if (days > maxRangeDays) {
                      setCapWarning(
                        `Range capped at ${maxRangeDays} days — kept your previous selection.`,
                      );
                      return;
                    }
                  }
                  setCapWarning(null);
                  setStartDate(range?.from);
                  setEndDate(range?.to);
                }}
                disabled={(date) => {
                  const now = new Date();
                  const utcToday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 23, 59, 59, 999));
                  return date > utcToday;
                }}
                className="p-0"
                classNames={{
                  [UI.Months]: 'flex flex-row gap-5',
                  // `relative` is the positioning anchor for the
                  // PreviousMonthButton/NextMonthButton, which v9 renders as
                  // siblings (not children) of MonthCaption when navLayout="around".
                  [UI.Month]: 'space-y-2 min-w-0 relative',
                  [UI.MonthCaption]: 'flex items-center justify-center px-0.5 pb-1',
                  [UI.CaptionLabel]: 'text-[12px] font-semibold font-mono tracking-wide text-foreground',
                  [UI.Nav]: 'flex items-center',
                  // v9 split nav_button into Previous/Next; merge shared
                  // styling with the position-specific absolute placement.
                  // `top-0` aligns the button vertically with the caption row.
                  [UI.PreviousMonthButton]:
                    'h-5 w-5 p-0 rounded hover:bg-foreground/5 text-muted-foreground inline-flex items-center justify-center opacity-100 absolute top-0 left-0.5',
                  [UI.NextMonthButton]:
                    'h-5 w-5 p-0 rounded hover:bg-foreground/5 text-muted-foreground inline-flex items-center justify-center opacity-100 absolute top-0 right-0.5',
                  [UI.MonthGrid]: 'w-full border-collapse',
                  [UI.Weekdays]: 'flex',
                  [UI.Weekday]:
                    'w-7 text-center text-muted-foreground/60 text-[9px] font-mono font-semibold py-1 uppercase tracking-[0.08em]',
                  [UI.Week]: 'flex w-full mt-0.5',
                  // Day is the cell wrapper in v9 (was `cell` in v8). Range
                  // middle gets the row tint directly via SelectionState below.
                  // NOTE: v9 puts aria-selected on UI.Day (was on the button in
                  // v8), so any aria-selected: variant here would override the
                  // SelectionState.range_middle bg-primary/10 tint.
                  [UI.Day]:
                    'w-7 relative p-0 text-center font-mono text-[11px]',
                  [UI.DayButton]:
                    'h-7 w-7 p-0 font-normal text-foreground hover:bg-foreground/5 rounded-sm inline-flex items-center justify-center transition-colors aria-selected:opacity-100',
                  // SelectionState classes are applied to UI.Day (the cell);
                  // we use [&>button]: to push button-level styling so adjacent
                  // selected days fuse into a single pill.
                  [SelectionState.range_start]:
                    'rounded-l-sm rounded-r-none [&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:font-semibold [&>button]:rounded-l-sm [&>button]:rounded-r-none [&>button]:hover:bg-primary [&>button]:hover:text-primary-foreground',
                  [SelectionState.range_end]:
                    'rounded-r-sm rounded-l-none [&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:font-semibold [&>button]:rounded-r-sm [&>button]:rounded-l-none [&>button]:hover:bg-primary [&>button]:hover:text-primary-foreground',
                  [SelectionState.range_middle]:
                    'bg-primary/10 [&>button]:!bg-transparent [&>button]:!text-primary [&>button]:hover:!bg-primary/15 [&>button]:rounded-none',
                  [SelectionState.selected]:
                    '[&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:hover:bg-primary [&>button]:hover:text-primary-foreground',
                  [DayFlag.today]:
                    '[&>button]:relative [&>button]:after:absolute [&>button]:after:bottom-0.5 [&>button]:after:left-1/2 [&>button]:after:-translate-x-1/2 [&>button]:after:w-[3px] [&>button]:after:h-[3px] [&>button]:after:rounded-full [&>button]:after:bg-primary',
                  [DayFlag.outside]: '[&>button]:text-muted-foreground/30',
                  // Disabled styling has to push through to the button via
                  // [&>button]: — UI.DayButton's base `text-foreground` wins
                  // over a cell-level color and the cursor only matters on
                  // the actual click target.
                  [DayFlag.disabled]:
                    '[&>button]:!text-muted-foreground/30 [&>button]:!cursor-not-allowed [&>button]:hover:!bg-transparent',
                  [DayFlag.hidden]: 'invisible',
                }}
              />

              {/* inputs row — From / To / timezone */}
              <div className="border-t border-border mt-2 pt-2 grid grid-cols-[1fr_auto_1fr] items-end gap-2">
                <DateTimeField
                  label="From"
                  date={startDate}
                  time={startTime}
                  onDateChange={(d) => {
                    if (
                      maxRangeDays !== undefined &&
                      d &&
                      endDate &&
                      (endDate.getTime() - d.getTime()) / 86_400_000 > maxRangeDays
                    ) {
                      setCapWarning(
                        `Range capped at ${maxRangeDays} days — kept your previous selection.`,
                      );
                      return;
                    }
                    setCapWarning(null);
                    setStartDate(d);
                  }}
                  onTimeChange={setStartTime}
                />
                {/* Arrow sits centered against the input box's vertical
                    middle. The grid row is taller than the input because the
                    DateTimeField stacks a "FROM" label above its input box;
                    matching the input box's ~28px height with `h-7` and
                    `self-end` puts the arrow's center on the input center. */}
                <span className="flex h-7 items-center justify-center text-muted-foreground/50 self-end">
                  <ArrowRight className="w-3.5 h-3.5" strokeWidth={1.75} />
                </span>
                <DateTimeField
                  label="To"
                  date={endDate}
                  time={endTime}
                  onDateChange={(d) => {
                    if (
                      maxRangeDays !== undefined &&
                      d &&
                      startDate &&
                      (d.getTime() - startDate.getTime()) / 86_400_000 > maxRangeDays
                    ) {
                      setCapWarning(
                        `Range capped at ${maxRangeDays} days — kept your previous selection.`,
                      );
                      return;
                    }
                    setCapWarning(null);
                    setEndDate(d);
                  }}
                  onTimeChange={setEndTime}
                />
              </div>

              {capWarning && (
                <div
                  role="status"
                  className="mt-2 px-2 py-1.5 rounded-sm border border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[11px] font-mono text-foreground/85"
                >
                  {capWarning}
                </div>
              )}

              <div className="mt-2 flex items-center justify-between gap-2">
                <div className="text-[10.5px] font-mono text-muted-foreground/70 uppercase tracking-[0.1em]">UTC</div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setOpen(false)}
                    className="h-8 px-3 rounded-md text-[12px] text-foreground/80 hover:bg-foreground/5"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleApplyCustom}
                    disabled={!startDate || !endDate}
                    className={cn(
                      'h-8 px-3 rounded-md text-[12px] font-semibold',
                      startDate && endDate
                        ? 'bg-primary text-primary-foreground hover:bg-primary/90'
                        : 'bg-foreground/5 text-muted-foreground cursor-not-allowed'
                    )}
                  >
                    Apply
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </PopoverContent>
    </Popover>
  );
}

/* Inline date + time cell used in the custom-range inputs row.
   Shape mirrors mockup `DateTimeInput` (query-block.jsx:177). */
interface DateTimeFieldProps {
  label: string;
  date: Date | undefined;
  time: string;
  onDateChange: (date: Date | undefined) => void;
  onTimeChange: (time: string) => void;
}

function DateTimeField({ label, date, time, onDateChange, onTimeChange }: DateTimeFieldProps) {
  const dateVal = date
    ? `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
    : '';
  // The mockup shows HH:MM; our internal state is HH:mm:ss. Display the leading
  // HH:MM slice for parity and keep the seconds in state.
  const timeHm = time.slice(0, 5);
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <span className="text-muted-foreground/70 text-[9.5px] uppercase tracking-[0.14em] font-mono font-semibold">
        {label}
      </span>
      <div className="flex items-center gap-1 border border-border-2 rounded-md px-1.5 py-1 bg-background focus-within:border-primary/50 focus-within:ring-1 focus-within:ring-primary/25">
        <input
          type="date"
          value={dateVal}
          onChange={(e) => {
            const [y, mo, da] = e.target.value.split('-').map(Number);
            if (!y || !mo || !da) { onDateChange(undefined); return; }
            const d = new Date(date ?? new Date());
            d.setFullYear(y, mo - 1, da);
            onDateChange(d);
          }}
          className="bg-transparent outline-none font-mono text-[11.5px] text-foreground flex-1 min-w-0 [&::-webkit-calendar-picker-indicator]:hidden [&::-webkit-calendar-picker-indicator]:appearance-none"
        />
        <span className="w-px h-4 bg-border-2" />
        <input
          type="text"
          value={timeHm}
          onChange={(e) => {
            const v = e.target.value;
            if (!/^\d{0,2}:?\d{0,2}$/.test(v)) return;
            // Pad to HH:mm:ss for internal state
            const parts = v.split(':');
            const hh = (parts[0] ?? '00').padStart(2, '0').slice(0, 2);
            const mm = (parts[1] ?? '00').padStart(2, '0').slice(0, 2);
            onTimeChange(`${hh}:${mm}:00`);
          }}
          maxLength={5}
          placeholder="HH:MM"
          className="bg-transparent outline-none font-mono text-[11.5px] text-foreground w-[44px] shrink-0 text-center tabular-nums"
        />
      </div>
    </div>
  );
}
