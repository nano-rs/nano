// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 PR 4 — TestDrawer.
//
// Bottom-anchored drawer that slides up over the editor content area and
// runs the current rule query against a configurable time window. Mirrors
// `design-ref/shadcn/editor-test-drawer.jsx` — a dimmed backdrop over the
// whole editor row (rail + main + inspector), then a drawer pinned to the
// bottom at 64% of the row height.
//
//   ┌ header: time-range popover | stats strip | live toggle | re-run | close
//   ├ sparkline: matches-by-day histogram with tooltip
//   ├ body: [event stream (left)] | [selected-event detail (right)]
//   └ footer: inline "last run" + hint
//
// Live mode polls `testDetection` / `testQuery` at a fixed interval (20s)
// so authors can watch a fresh rule catch live traffic without babysitting
// the Run button. Esc closes the drawer.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  X,
  Terminal,
  RefreshCw,
  Play,
  Loader2,
  Database,
  ArrowLeft,
  Check,
  Undo2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { DateTimeRangePicker } from '@/components/ui/date-time-range-picker';
import { cn } from '@/lib/utils';
import type { TestDetectionResult, TimeRange } from '@/lib/api/types';
import { toApiTimeRange, type TimeRangeValue } from '@/hooks/use-api';
import { QueryEditor } from '@/components/editor';
import { isClickHouseDefault } from '@/lib/utils';
// Reuse the Matches extractors so rows + detail pane pick the same canonical
// fields (action / entity / src_ip / region / timestamp) as `/rules/:id/matches`.
import {
  extractAction,
  extractEntity,
  extractEventTime,
  extractIp,
  extractRegion,
} from '@/components/matches/helpers';

// Mirror `components/matches/EventViewer.PREVIEW_KEYS` so TestDrawer rows pick
// the same first-N non-empty fields the /rules/:id/matches page surfaces.
// Keep this list in sync with that one — any change there should land here too.
const PREVIEW_KEYS = [
  'user',
  'src_ip',
  'dest_ip',
  'src_host',
  'dest_host',
  'http_method',
  'http_status_code',
  'status_code',
  'url',
  'event_type',
  'event_id',
  'process_name',
  'file_hash',
  'file_path',
  // OCSF promoted (dotted) columns — NAN-1241; mirror of EventViewer.tsx. Under
  // OCSF the row carries these instead of the UDM names; UDM rows never populate
  // them, so the UDM preview is byte-identical.
  'user.name',
  'actor.user.name',
  'src_endpoint.ip',
  'dst_endpoint.ip',
  'src_endpoint.hostname',
  'dst_endpoint.hostname',
  'http_request.http_method',
  'http_response.code',
  'url.url_string',
  'actor.process.name',
  'file.hashes.sha256',
  'file.name',
  'file.path',
  'eventName',
  'sourceIPAddress',
  'source_type',
];
const PREVIEW_MAX = 5;
const FIELD_PREVIEW_MAX = 260;

function getFieldValue(event: Record<string, unknown>, field: string): string {
  const parts = field.split('.');
  let v: unknown = event;
  for (const p of parts) {
    if (v === null || v === undefined || typeof v !== 'object') return '';
    v = (v as Record<string, unknown>)[p];
  }
  if (isClickHouseDefault(v, field)) return '';
  const s = typeof v === 'object' ? JSON.stringify(v) : String(v);
  return s.length > FIELD_PREVIEW_MAX ? `${s.slice(0, FIELD_PREVIEW_MAX)}…` : s;
}

// 1h matches Google SecOps' "Run rule against historical data" default and
// keeps drawer-open cheap (NAN-741). The tester now evaluates each cron tick
// independently, so a 24h default with a 5-min cron rule = 288 fanout queries
// just to look at the drawer. Explicit longer ranges are an opt-in click.
const DEFAULT_TIME_RANGE: TimeRangeValue = { type: 'preset', preset: 'Last hour' };

// Hard cap on the test range, mirroring the backend's `MAX_TEST_RANGE_DAYS`.
// Surface inline so the user sees it before they submit; the backend returns
// 400 with an identical message if anything slips through.
const MAX_TEST_RANGE_DAYS = 14;

// Extract a start/end pair to pass to the test endpoint — drives both the
// request payload and the sparkline bucket range.
function resolveRange(value: TimeRangeValue): TimeRange {
  return toApiTimeRange(value);
}

function rangeSpanDays(range: TimeRange): number {
  const start = new Date(range.start).getTime();
  const end = new Date(range.end).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return 7;
  return Math.max(1, Math.ceil((end - start) / 86400000));
}

interface TestDrawerProps {
  open: boolean;
  onClose: () => void;
  /** The current editor query body (unsaved drafts ok). Feeds the seed value
   *  of the drawer's working copy every time the drawer opens, but once open
   *  the working copy is independent — user exploration isn't clobbered by
   *  upstream edits. `Reset to editor` pulls in the parent's current value. */
  query: string;
  /** If present and the working copy matches `query`, the saved-rule test
   *  endpoint runs (more accurate). Any divergence falls back to the
   *  unsaved `testQuery` path. */
  ruleId?: string;
  /** `useTestDetection` mutation. Now accepts an explicit `timeRange` —
   *  NAN-741 added stepped per-window evaluation to `/api/rules/{id}/test`,
   *  so the saved-rule endpoint is used whenever the working copy still
   *  matches the persisted rule, regardless of the chosen preset. */
  runSavedTest: (args: {
    id: string;
    days?: number;
    timeRange?: TimeRange;
  }) => Promise<TestDetectionResult>;
  /** `useTestQuery` mutation. Takes an explicit `timeRange` when set, so the
   *  full Search date picker range (incl. custom absolute windows) is honored. */
  runUnsavedTest: (args: {
    query: string;
    days?: number;
    timeRange?: TimeRange;
  }) => Promise<TestDetectionResult>;
  /** Commits the drawer's working-copy query back into the editor's YAML
   *  body. Leaves the drawer open so the analyst can keep iterating. */
  onApplyQuery?: (query: string) => void;
}

export function TestDrawer({
  open,
  onClose,
  query,
  ruleId,
  runSavedTest,
  runUnsavedTest,
  onApplyQuery,
}: TestDrawerProps) {
  const [timeRange, setTimeRange] = useState<TimeRangeValue>(DEFAULT_TIME_RANGE);
  const [run, setRun] = useState<TestDetectionResult | null>(null);
  const [running, setRunning] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [liveMode, setLiveMode] = useState(false);
  const [lastRunAt, setLastRunAt] = useState<Date | null>(null);
  const [workingQuery, setWorkingQuery] = useState(query);
  const runRef = useRef<() => Promise<void>>(null);
  const wasOpenRef = useRef(false);

  // Drawer height as a percentage of the editor row. Resets to 64% on each
  // open — persistence is a follow-up. Drag handle at the top edge mutates
  // this via pointer events; clamp to 25–90% so the drawer can neither
  // collapse to a sliver nor swallow the editor entirely.
  const [heightPct, setHeightPct] = useState(64);
  const dragRef = useRef<{ startY: number; startPct: number } | null>(null);

  const onResizeDown = (e: React.PointerEvent<HTMLDivElement>) => {
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    dragRef.current = { startY: e.clientY, startPct: heightPct };
  };
  const onResizeMove = (e: React.PointerEvent<HTMLDivElement>) => {
    if (!dragRef.current) return;
    const parent = e.currentTarget.parentElement as HTMLElement | null;
    const containerH = parent?.clientHeight ?? window.innerHeight;
    const deltaPct = ((dragRef.current.startY - e.clientY) / containerH) * 100;
    const next = Math.max(25, Math.min(90, dragRef.current.startPct + deltaPct));
    setHeightPct(next);
  };
  const onResizeUp = (e: React.PointerEvent<HTMLDivElement>) => {
    (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    dragRef.current = null;
  };

  // Seed the working copy on open — a closed→open transition pulls whatever
  // the editor currently has. While open, edits to `query` (e.g., the author
  // typed in CODE) don't clobber the drawer; `Reset to editor` does that.
  useEffect(() => {
    if (open && !wasOpenRef.current) {
      setWorkingQuery(query);
    }
    wasOpenRef.current = open;
  }, [open, query]);

  const queryDirty = workingQuery.trim() !== query.trim();

  // Range exceeds the 14-day backend cap. Block the run client-side so the
  // user sees inline feedback in the drawer instead of a transient toast
  // after a wasted round-trip.
  const apiRange = resolveRange(timeRange);
  const rangeDays =
    (new Date(apiRange.end).getTime() - new Date(apiRange.start).getTime()) / 86400000;
  const rangeTooLong = rangeDays > MAX_TEST_RANGE_DAYS;

  const runOnce = useCallback(async () => {
    if (!workingQuery.trim()) return;
    if (rangeTooLong) return;
    setRunning(true);
    try {
      const days = rangeSpanDays(apiRange);
      // The saved-rule endpoint now performs its own stepped per-window
      // evaluation against the saved rule's `schedule_cron` + `lookback_minutes`
      // (NAN-741), so it's safe to use any time the working copy still matches
      // the persisted rule — we don't need to detour through the unsaved path
      // just because the user picked a non-default preset.
      const useSaved = !!ruleId && !queryDirty;
      const result = useSaved
        ? await runSavedTest({ id: ruleId, days, timeRange: apiRange })
        : await runUnsavedTest({ query: workingQuery, timeRange: apiRange });
      setRun(result);
      setLastRunAt(new Date());
      if (selectedIndex !== null && result.sample_events[selectedIndex] == null) {
        setSelectedIndex(result.sample_events.length > 0 ? 0 : null);
      } else if (selectedIndex === null && result.sample_events.length > 0) {
        setSelectedIndex(0);
      }
    } catch {
      // Swallow — parent already surfaces validation toasts via handleRunTest;
      // a silent failure here keeps the drawer chrome intact for a retry.
    } finally {
      setRunning(false);
    }
  }, [
    workingQuery,
    ruleId,
    queryDirty,
    apiRange,
    rangeTooLong,
    runSavedTest,
    runUnsavedTest,
    selectedIndex,
  ]);

  runRef.current = runOnce;

  // No auto-run: opening the drawer or changing the time range should NOT
  // fire a query. The user picks a window and clicks Run. Live mode below
  // is opt-in. (NAN-781)

  // Live polling — 20s interval.
  useEffect(() => {
    if (!open || !liveMode) return;
    const tick = setInterval(() => {
      if (runRef.current) void runRef.current();
    }, 20000);
    return () => clearInterval(tick);
  }, [open, liveMode]);

  // Esc to close.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const events = run?.sample_events || [];
  const selected = selectedIndex != null ? events[selectedIndex] : null;

  return (
    <>
      {/* No backdrop — the editor row stays fully visible/readable while
          the drawer is open. Esc + the close button in the drawer header
          handle dismissal. */}

      {/* Drawer — slides up from the bottom of the editor row. */}
      <div
        className={cn(
          'absolute left-0 right-0 bottom-0 z-50 flex flex-col bg-[var(--panel)] transition-transform duration-300 ease-out',
          // Border-t and shadow are both gated on `open`: the 2px primary
          // border is the drawer's visual "lip" and would peek above the
          // BottomTray as a random green stripe when offscreen, and the
          // upward shadow on a translated element renders at the translated
          // position — leaking a dark fringe above the editor row in light
          // theme (NAN-621).
          open
            ? 'translate-y-0 border-t-2 border-[var(--primary)]/60 shadow-[0_-2px_8px_-4px_rgba(0,0,0,0.12)]'
            : 'translate-y-full pointer-events-none border-t-0',
        )}
        style={{ height: `${heightPct}%` }}
        role="dialog"
        aria-label="Test rule drawer"
        aria-hidden={!open}
      >
      <div
        className="h-1.5 cursor-ns-resize bg-border/50 hover:bg-primary/40 transition-colors shrink-0"
        onPointerDown={onResizeDown}
        onPointerMove={onResizeMove}
        onPointerUp={onResizeUp}
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize test drawer"
      />
      <TestDrawerHeader
        timeRange={timeRange}
        onTimeRangeChange={setTimeRange}
        run={run}
        lastRunAt={lastRunAt}
        running={running}
        liveMode={liveMode}
        onToggleLive={() => setLiveMode((v) => !v)}
        onRerun={() => {
          void runOnce();
        }}
        onClose={onClose}
        queryDirty={queryDirty}
      />

      <QueryPane
        value={workingQuery}
        onChange={setWorkingQuery}
        onRun={() => void runOnce()}
        onApply={
          onApplyQuery && queryDirty
            ? () => {
                onApplyQuery(workingQuery);
              }
            : undefined
        }
        onReset={queryDirty ? () => setWorkingQuery(query) : undefined}
        dirty={queryDirty}
        running={running}
      />

      {rangeTooLong && (
        <div
          role="alert"
          className="px-4 py-2 border-b border-border bg-[var(--warning)]/10 text-[12px] text-[var(--warning-fg,var(--foreground))]"
        >
          <span className="font-medium">Range too long.</span>{' '}
          The rule tester evaluates each cron tick across the selected window, so it&apos;s
          capped at {MAX_TEST_RANGE_DAYS} days. Pick a shorter range to run.
        </div>
      )}

      <TestSparkline result={run} />

      <div className="flex-1 min-h-0 flex">
        <div className="flex-1 min-w-0 border-r border-border flex flex-col min-h-0">
          <div className="px-3 py-1.5 border-b border-border text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Matched events
            {events.length > 0 && <span className="normal-case tracking-normal ml-2">· {events.length} shown</span>}
          </div>
          <ScrollArea className="flex-1 min-h-0">
            {running && !run ? (
              <div className="h-48 flex items-center justify-center text-muted-foreground">
                <Loader2 className="w-5 h-5 animate-spin" strokeWidth={1.75} />
              </div>
            ) : events.length === 0 ? (
              <div className="h-48 flex items-center justify-center text-[11.5px] text-muted-foreground px-6 text-center">
                {run ? 'No matches in this window.' : 'Run a test to see events.'}
              </div>
            ) : (
              events.map((e, i) => (
                <EventRow
                  key={i}
                  event={e}
                  selected={i === selectedIndex}
                  onSelect={() => setSelectedIndex(i)}
                  index={i}
                />
              ))
            )}
          </ScrollArea>
        </div>

        <div className="w-[420px] shrink-0 flex flex-col min-h-0 bg-background/40">
          <div className="px-3 py-1.5 border-b border-border text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Event detail
          </div>
          <ScrollArea className="flex-1 min-h-0">
            {selected ? <EventDetail event={selected} /> : (
              <div className="p-6 text-[11.5px] text-muted-foreground text-center">
                {events.length > 0 ? 'Pick an event on the left.' : 'No event selected.'}
              </div>
            )}
          </ScrollArea>
        </div>
      </div>
      </div>
    </>
  );
}

/* ============ Editable query pane ============ */

function QueryPane({
  value,
  onChange,
  onRun,
  onApply,
  onReset,
  dirty,
  running,
}: {
  value: string;
  onChange: (v: string) => void;
  onRun: () => void;
  onApply?: () => void;
  onReset?: () => void;
  dirty: boolean;
  running: boolean;
}) {
  return (
    <div className="border-b border-border bg-background shrink-0">
      <div className="h-7 px-3 flex items-center gap-2 border-b border-border/60 text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
        <ArrowLeft className="w-3 h-3 rotate-[-90deg]" strokeWidth={1.75} />
        Working query
        {dirty ? (
          <span className="normal-case tracking-normal text-[var(--warning)] flex items-center gap-1">
            · modified — not yet applied to editor
          </span>
        ) : (
          <span className="normal-case tracking-normal text-muted-foreground/70">
            · synced with editor
          </span>
        )}
        <div className="flex-1" />
        <span className="normal-case tracking-normal text-muted-foreground/70">⌘↵ run</span>
        {onReset && (
          <button
            type="button"
            onClick={onReset}
            className="inline-flex items-center gap-1 h-5 px-1.5 rounded-[3px] text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] normal-case tracking-normal"
            title="Revert working copy to the editor's current query"
          >
            <Undo2 className="w-2.5 h-2.5" strokeWidth={1.75} />
            reset
          </button>
        )}
        {onApply && (
          <button
            type="button"
            onClick={onApply}
            disabled={running}
            className={cn(
              'inline-flex items-center gap-1 h-5 px-2 rounded-[3px] text-[10px] font-mono font-semibold uppercase tracking-[0.08em] border transition-colors',
              'border-[var(--primary)]/40 bg-[color-mix(in_srgb,var(--primary)_12%,transparent)] text-[var(--primary)] hover:bg-[color-mix(in_srgb,var(--primary)_20%,transparent)]',
              running && 'opacity-60 cursor-not-allowed',
            )}
            title="Write the working copy back into the editor's YAML body"
          >
            <Check className="w-2.5 h-2.5" strokeWidth={2} />
            Apply to editor
          </button>
        )}
      </div>
      <div className="max-h-[160px] overflow-auto">
        <QueryEditor
          value={value}
          onChange={onChange}
          onSubmit={onRun}
          minHeight={60}
          maxHeight={160}
          fontSize={11.5}
          placeholder="// write or paste a detection query"
        />
      </div>
    </div>
  );
}

/* ============ Header ============ */

function TestDrawerHeader({
  timeRange,
  onTimeRangeChange,
  run,
  lastRunAt,
  running,
  liveMode,
  onToggleLive,
  onRerun,
  onClose,
  queryDirty,
}: {
  timeRange: TimeRangeValue;
  onTimeRangeChange: (v: TimeRangeValue) => void;
  run: TestDetectionResult | null;
  lastRunAt: Date | null;
  running: boolean;
  liveMode: boolean;
  onToggleLive: () => void;
  onRerun: () => void;
  onClose: () => void;
  queryDirty: boolean;
}) {
  const matched = run?.total_matches ?? 0;
  const sampled = run?.sample_events.length ?? 0;
  const ms = run?.execution_time_ms ?? 0;

  return (
    <div className="h-10 shrink-0 flex items-center px-4 gap-3 border-b border-border bg-[var(--panel)]">
      <div className="flex items-center gap-2 shrink-0">
        <Terminal className="w-3.5 h-3.5 text-[var(--primary)]" strokeWidth={1.75} />
        <span className="text-[11.5px] font-mono font-semibold uppercase tracking-[0.12em] text-foreground">
          Test rule
        </span>
        {queryDirty && (
          <span
            className="inline-flex items-center gap-1 h-5 px-1.5 rounded-[3px] text-[9.5px] font-mono font-semibold tracking-[0.08em] uppercase text-[var(--warning)]"
            style={{ background: 'color-mix(in srgb, var(--warning) 15%, transparent)' }}
            title="Working query differs from the editor"
          >
            <span className="w-1 h-1 rounded-full bg-[var(--warning)]" />
            modified
          </span>
        )}
      </div>

      <Separator orientation="vertical" className="h-5" />

      <DateTimeRangePicker
        value={timeRange}
        onChange={onTimeRangeChange}
        variant="search"
        align="start"
        labelPrefix="against"
        maxRangeDays={MAX_TEST_RANGE_DAYS}
      />

      <Button
        variant="outline"
        size="sm"
        onClick={onRerun}
        disabled={running}
        className="h-6 text-[10.5px] px-2 gap-1 font-mono"
      >
        {running ? (
          <Loader2 className="w-3 h-3 animate-spin" strokeWidth={1.75} />
        ) : (
          <RefreshCw className="w-3 h-3" strokeWidth={1.75} />
        )}
        {running ? 'Running' : lastRunAt ? 'Re-run' : 'Run'}
      </Button>

      <button
        type="button"
        onClick={onToggleLive}
        className={cn(
          'inline-flex items-center gap-1.5 h-6 px-2 rounded-[4px] border transition-colors',
          liveMode
            ? 'border-[var(--success)]/40 bg-[color-mix(in_srgb,var(--success)_10%,transparent)] text-[var(--success)]'
            : 'border-border text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)]',
        )}
        title={liveMode ? 'Live polling on' : 'Click to poll every 20s'}
      >
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full',
            liveMode ? 'bg-[var(--success)] animate-pulse' : 'bg-muted-foreground',
          )}
        />
        <span className="text-[10.5px] font-mono uppercase tracking-[0.08em] font-semibold">Live</span>
      </button>

      <div className="flex-1 min-w-0" />

      <div className="flex items-center gap-3 text-[11px] font-mono text-muted-foreground overflow-hidden min-w-0">
        <span className="whitespace-nowrap">
          <span className="text-[var(--destructive)] font-semibold">{matched.toLocaleString()}</span>{' '}
          <span className="text-muted-foreground/80">matched</span>
        </span>
        <Separator orientation="vertical" className="h-3" />
        <span className="whitespace-nowrap">
          <span className="text-foreground">{sampled}</span>{' '}
          <span className="text-muted-foreground/80">sampled</span>
        </span>
        <Separator orientation="vertical" className="h-3" />
        <span className="whitespace-nowrap text-muted-foreground/70">{ms}ms</span>
        {lastRunAt && (
          <>
            <Separator orientation="vertical" className="h-3" />
            <span className="whitespace-nowrap text-muted-foreground/70">
              {lastRunAt.toLocaleTimeString()}
            </span>
          </>
        )}
      </div>

      <Separator orientation="vertical" className="h-5" />

      <button
        type="button"
        onClick={onClose}
        className="h-6 w-6 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-muted-foreground hover:text-foreground inline-flex items-center justify-center"
        title="Close (Esc)"
        aria-label="Close test drawer"
      >
        <X className="w-3.5 h-3.5" strokeWidth={1.75} />
      </button>
    </div>
  );
}

type Bucket = { count: number; ratio: number; label: string };
type SparklineMode = 'empty' | 'day' | 'hour' | 'minute' | 'total';
type SparklineData = {
  buckets: Bucket[];
  mode: SparklineMode;
  startLabel: string;
  endLabel: string;
};

const EMPTY_SPARKLINE: SparklineData = { buckets: [], mode: 'empty', startLabel: '', endLabel: '' };

// Bucket sizes that produce clean axis labels. Pick the smallest interval
// where the window fits in ≤ 30 buckets.
const NICE_BUCKETS_MS = [60_000, 300_000, 900_000, 3_600_000, 21_600_000, 86_400_000]; // 1m,5m,15m,1h,6h,1d

function pickBucketSize(windowMs: number): number {
  for (const b of NICE_BUCKETS_MS) {
    if (windowMs / b <= 30) return b;
  }
  return NICE_BUCKETS_MS[NICE_BUCKETS_MS.length - 1];
}

function bucketModeFor(bucketMs: number): 'minute' | 'hour' | 'day' {
  if (bucketMs >= 86_400_000) return 'day';
  if (bucketMs >= 3_600_000) return 'hour';
  return 'minute';
}

function makeRangeFormatter(bucketMs: number): (ms: number) => string {
  const includeDay = bucketMs >= 86_400_000;
  return (ms: number) => {
    const d = new Date(ms);
    const dayPart = includeDay
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : '';
    const timePart = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
    return dayPart ? `${dayPart} ${timePart}` : timePart;
  };
}

// Multi-day window: prefer the API's per-day buckets.
function bucketsFromMatchesByDay(byDate: { date: string; count: number }[]): SparklineData {
  const max = Math.max(...byDate.map((b) => b.count), 1);
  return {
    buckets: byDate.map((b) => ({ count: b.count, ratio: b.count / max, label: b.date })),
    mode: 'day',
    startLabel: byDate[0].date,
    endLabel: byDate[byDate.length - 1].date,
  };
}

// Sub-daily window: prefer the API's adaptive buckets when present. The
// backend computes these from the pre-aggregation filter so even aggregated
// rules (`... | stats count by src_ip`) get a real histogram.
function bucketsFromMatchesByBucket(
  byBucket: { bucket_start: string; count: number }[],
  bucketSeconds: number,
): SparklineData {
  const bucketMs = bucketSeconds * 1000;
  const fmt = makeRangeFormatter(bucketMs);
  const max = Math.max(...byBucket.map((b) => b.count), 1);
  const startMs = new Date(byBucket[0].bucket_start).getTime();
  const endMs = new Date(byBucket[byBucket.length - 1].bucket_start).getTime() + bucketMs;
  return {
    buckets: byBucket.map((b) => ({
      count: b.count,
      ratio: b.count / max,
      label: fmt(new Date(b.bucket_start).getTime()),
    })),
    mode: bucketModeFor(bucketMs),
    startLabel: fmt(startMs),
    endLabel: fmt(endMs),
  };
}

// Sub-daily window: bucket sample_events client-side. Falls back to a single
// total-bar when no event has an extractable timestamp (typical of stats
// query results, which don't carry per-event timestamps).
function bucketsFromSampleEvents(result: TestDetectionResult): SparklineData {
  if (result.total_matches === 0) return EMPTY_SPARKLINE;

  const start = new Date(result.time_range.start).getTime();
  const end = new Date(result.time_range.end).getTime();
  const windowMs = end - start;
  if (!Number.isFinite(windowMs) || windowMs <= 0) return EMPTY_SPARKLINE;

  const bucketMs = pickBucketSize(windowMs);
  const numBuckets = Math.max(1, Math.ceil(windowMs / bucketMs));
  const counts = new Array<number>(numBuckets).fill(0);
  let bucketed = 0;
  for (const e of result.sample_events) {
    const t = extractEventTime(e);
    if (!t) continue;
    const offset = t.getTime() - start;
    if (offset < 0 || offset > windowMs) continue;
    counts[Math.min(Math.floor(offset / bucketMs), numBuckets - 1)]++;
    bucketed++;
  }

  const fmt = makeRangeFormatter(bucketMs);

  if (bucketed === 0) {
    return {
      buckets: [{ count: result.total_matches, ratio: 1, label: 'window total' }],
      mode: 'total',
      startLabel: fmt(start),
      endLabel: fmt(end),
    };
  }

  const max = Math.max(...counts, 1);
  return {
    buckets: counts.map((c, i) => ({ count: c, ratio: c / max, label: fmt(start + i * bucketMs) })),
    mode: bucketModeFor(bucketMs),
    startLabel: fmt(start),
    endLabel: fmt(end),
  };
}

function TestSparkline({ result }: { result: TestDetectionResult | null }) {
  const { buckets, mode, startLabel, endLabel } = useMemo<SparklineData>(() => {
    if (!result) return EMPTY_SPARKLINE;
    const byBucket = result.matches_by_bucket ?? [];
    const bucketSecs = result.bucket_size_seconds ?? 0;
    // Prefer adaptive buckets when present and sub-daily — they're computed
    // from the pre-aggregation filter so aggregated rules get a real histogram.
    if (byBucket.length > 0 && bucketSecs > 0 && bucketSecs < 86_400) {
      return bucketsFromMatchesByBucket(byBucket, bucketSecs);
    }
    const byDate = result.matches_by_day || [];
    if (byDate.length > 0) return bucketsFromMatchesByDay(byDate);
    if (byBucket.length > 0 && bucketSecs > 0) {
      // Fall through to bucket-based rendering even at daily granularity if the
      // back-compat matches_by_day field is empty.
      return bucketsFromMatchesByBucket(byBucket, bucketSecs);
    }
    return bucketsFromSampleEvents(result);
  }, [result]);

  const headerLabel = mode === 'day'
    ? 'Matches per day'
    : mode === 'hour'
      ? 'Matches per hour'
      : mode === 'minute'
        ? 'Matches per minute'
        : mode === 'total'
          ? 'Matches in window'
          : 'Matches per day';

  return (
    <div className="border-b border-border px-4 py-2 shrink-0">
      <div className="flex items-center gap-3 mb-1.5">
        <span className="text-[9.5px] font-mono text-muted-foreground uppercase tracking-[0.12em]">
          {headerLabel}
        </span>
        {buckets.length > 0 && (
          <>
            <span className="text-[10px] font-mono text-muted-foreground/70">{startLabel}</span>
            <div className="flex-1 border-t border-dashed border-border/60" />
            <span className="text-[10px] font-mono text-muted-foreground/70">{endLabel}</span>
          </>
        )}
      </div>
      <div className="relative h-10 flex items-stretch gap-[2px]">
        {buckets.length === 0 ? (
          <div className="w-full flex items-center justify-center text-[10.5px] font-mono text-muted-foreground/70">
            {result ? 'no matches in window' : '—'}
          </div>
        ) : (
          buckets.map((b, i) => (
            <div key={i} className="flex-1 relative group">
              <div
                className="absolute bottom-0 left-0 right-0 rounded-[1px] bg-[var(--destructive)]/80"
                style={{ height: `${Math.max(b.ratio * 100, 2)}%` }}
              />
              <div className="absolute -top-6 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 pointer-events-none px-1.5 py-0.5 rounded-sm bg-card border border-border text-[10px] font-mono whitespace-nowrap z-10 shadow-lg">
                <span className="text-[var(--destructive)]">
                  {b.count} match{b.count === 1 ? '' : 'es'}
                </span>
                <span className="text-muted-foreground"> · {b.label}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Entity glyph mirrors `/rules/:id/matches` so analysts see the same U/H/R/I
// tag when pivoting between list + test harness.
function EventEntityGlyph({ type }: { type: ReturnType<typeof extractEntity>['type'] }) {
  const color =
    type === 'role'
      ? 'var(--warning)'
      : type === 'service'
        ? 'var(--primary)'
        : 'color-mix(in srgb, var(--foreground) 60%, transparent)';
  const letter =
    type === 'role' ? 'R' : type === 'service' ? 'S' : type === 'host' ? 'H' : type === 'ip' ? 'I' : 'U';
  return (
    <div
      className="w-[18px] h-[18px] rounded-[3px] flex items-center justify-center font-mono text-[9.5px] font-bold shrink-0"
      style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}
    >
      {letter}
    </div>
  );
}

function EventRow({
  event,
  selected,
  onSelect,
  index,
}: {
  event: Record<string, unknown>;
  selected: boolean;
  onSelect: () => void;
  index: number;
}) {
  const time = extractEventTime(event);
  const entity = extractEntity([event]);

  // Same PREVIEW_KEYS walk the Matches EventViewer does — picks the first N
  // non-empty UDM fields so rows read the same across log sources.
  const previewPairs: Array<[string, string]> = [];
  for (const k of PREVIEW_KEYS) {
    if (previewPairs.length >= PREVIEW_MAX) break;
    const v = getFieldValue(event, k);
    if (v) previewPairs.push([k, v]);
  }

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'w-full text-left px-3 py-2 border-l-2 border-b border-border/60 transition-colors',
        selected
          ? 'bg-[color-mix(in_srgb,var(--primary)_6%,transparent)] border-l-[var(--primary)]'
          : 'border-l-transparent hover:bg-[color-mix(in_srgb,var(--foreground)_2.5%,transparent)]',
      )}
    >
      <div className="flex items-start gap-2">
        <span className="w-[6px] h-[6px] rounded-full bg-[var(--destructive)] shrink-0 mt-[5px]" />
        <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums w-[28px] shrink-0 pt-[1px]">
          #{index + 1}
        </span>
        <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums w-[200px] shrink-0 pt-[1px]">
          {time ? time.toISOString() : '—'}
        </span>
        <div className="shrink-0 pt-[1px]">
          <EventEntityGlyph type={entity.type} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 font-mono text-[10.5px] leading-[1.45]">
            {previewPairs.length === 0 ? (
              <span className="text-muted-foreground/60">no key fields</span>
            ) : (
              previewPairs.map(([k, v]) => (
                <span key={k} className="inline-flex items-baseline gap-1 min-w-0">
                  <span className="text-muted-foreground/80 shrink-0">{k}:</span>
                  <span className="text-foreground truncate max-w-[220px]">{v}</span>
                </span>
              ))
            )}
          </div>
        </div>
      </div>
    </button>
  );
}

function EventDetail({ event }: { event: Record<string, unknown> }) {
  // Canonical match fields — same set the Matches page surfaces on each row.
  const time = extractEventTime(event);
  const action = extractAction(event);
  const entity = extractEntity([event]);
  const ip = extractIp(event);
  const region = extractRegion(event);
  const canonical: Array<[string, string | undefined]> = [
    ['timestamp', time?.toISOString()],
    ['event_type', action],
    [entity.type === 'other' ? 'entity' : entity.type, entity.label !== 'unknown' ? entity.label : undefined],
    ['src_ip', ip],
    ['region', region],
  ].filter((pair): pair is [string, string] => typeof pair[1] === 'string' && pair[1].length > 0);

  // Split keys into "top" vs "nested" for a readable layout.
  const entries = Object.entries(event).sort(([a], [b]) => a.localeCompare(b));
  const flat = entries.filter(([, v]) => typeof v !== 'object' || v === null);
  const nested = entries.filter(([, v]) => typeof v === 'object' && v !== null);

  return (
    <div className="p-3 space-y-3">
      {canonical.length > 0 && (
        <>
          <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.12em] text-[var(--primary)]">
            <Check className="w-3 h-3" strokeWidth={1.75} />
            Match fields
            <span className="ml-auto normal-case tracking-normal text-muted-foreground/70">canonical</span>
          </div>
          <dl
            className="space-y-1 font-mono text-[11px] p-2 rounded border"
            style={{
              borderColor: 'color-mix(in srgb, var(--primary) 30%, transparent)',
              background: 'color-mix(in srgb, var(--primary) 6%, transparent)',
            }}
          >
            {canonical.map(([k, v]) => (
              <div key={k} className="flex items-baseline gap-2">
                <dt className="text-muted-foreground shrink-0 min-w-[90px] truncate">{k}</dt>
                <dd className="text-foreground break-all">{v}</dd>
              </div>
            ))}
          </dl>
        </>
      )}

      <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
        <Database className="w-3 h-3" strokeWidth={1.75} />
        All top-level fields
        <span className="ml-auto normal-case tracking-normal">{flat.length}</span>
      </div>
      <dl className="space-y-1 font-mono text-[11px]">
        {flat.map(([k, v]) => (
          <div key={k} className="flex items-baseline gap-2">
            <dt className="text-muted-foreground shrink-0 min-w-[120px] truncate">{k}</dt>
            <dd className="text-foreground break-all">{formatValue(v)}</dd>
          </div>
        ))}
      </dl>

      {nested.length > 0 && (
        <>
          <Separator />
          <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
            Nested
            <span className="ml-auto normal-case tracking-normal">{nested.length}</span>
          </div>
          {nested.map(([k, v]) => (
            <div key={k}>
              <div className="text-[10.5px] font-mono text-muted-foreground mb-1">{k}</div>
              <pre className="font-mono text-[10.5px] leading-[1.5] bg-[color-mix(in_srgb,var(--foreground)_3%,transparent)] border border-border rounded p-2 whitespace-pre-wrap break-all max-h-[240px] overflow-auto">
                {JSON.stringify(v, null, 2)}
              </pre>
            </div>
          ))}
        </>
      )}

      <div className="pt-2 border-t border-border flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
        <Play className="w-2.5 h-2.5" strokeWidth={1.75} />
        Clause attribution lands when the backend exposes per-field match
        context (tracked separately; not required for triage).
      </div>
    </div>
  );
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean' || typeof v === 'number') return String(v);
  if (typeof v === 'string') return v;
  return JSON.stringify(v);
}
