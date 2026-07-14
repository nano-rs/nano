import { useMemo } from 'react';

import { extractKeywordsFromQuery } from '@/components/search/keyword-highlight';
import { toApiTimeRange, type TimeRangeValue } from '@/lib/time-range';

import { EventList } from './EventList';
import { SearchEmptyState } from './SearchEmptyState';
import { Histogram } from './Histogram';
import { QueryBar } from './QueryBar';
import { ResultsTable } from './ResultsTable';
import { TimeRangePicker } from './TimeRangePicker';
import { Spinner } from './ui';
import type { SchemaProfile } from '../lib/types';
import type { Tab } from '../state/tabs';

const DAY_MS = 24 * 60 * 60 * 1000;

interface Props {
  tab: Tab;
  profile: SchemaProfile;
  onQueryChange: (query: string) => void;
  onRangeChange: (range: TimeRangeValue) => void;
  onRun: (bypass?: boolean) => void;
  /** Runs a query the bar doesn't hold yet (an empty-state starter). */
  onRunQuery: (query: string) => void;
  onCancel: () => void;
  /** Promote a preview-capped agent tab to a full run. */
  onRunFull: () => void;
  /** Bubbled up so pivt sees whichever event the analyst has open. */
  onExpandedChange: (event: Record<string, unknown> | null) => void;
}

/** The body of one tab: query bar, histogram, results. */
export function SearchPane({
  tab,
  profile,
  onQueryChange,
  onRangeChange,
  onRun,
  onRunQuery,
  onCancel,
  onRunFull,
  onExpandedChange,
}: Props) {
  // Highlight terms come from the query that produced these rows, not the one
  // being typed — otherwise the marks shift while the user edits.
  const keywords = useMemo(() => extractKeywordsFromQuery(tab.ranQuery), [tab.ranQuery]);

  // A window longer than a day needs the date on every row; a short one would
  // just repeat today's date on all of them.
  const withDate = tab.ranRange
    ? new Date(tab.ranRange.end).getTime() - new Date(tab.ranRange.start).getTime() > DAY_MS
    : false;

  const running = tab.status === 'running';
  // The server classifies the result; metadata lands after the rows for plain
  // searches, so default to the events view until told otherwise.
  const isEventsView = (tab.metadata?.display_type ?? 'events') === 'events';

  return (
    <>
      {/* items-start: the query bar is resizable, and the picker/Run button
          should stay put at the top rather than ride down with it. */}
      <div className="flex items-start gap-2.5 px-[18px] pt-3.5">
        <QueryBar
          // Remount per tab: CodeMirror owns its document, so reusing one editor
          // across tabs would carry the previous tab's text into the next.
          key={tab.id}
          value={tab.query}
          onChange={onQueryChange}
          onRun={() => onRun()}
        />
        <TimeRangePicker value={tab.range} onChange={onRangeChange} />
        <button
          onClick={() => (running ? onCancel() : onRun())}
          className="shrink-0 rounded-[9px] border border-accent-line bg-accent-fill px-4 py-2.5 text-[12px] font-semibold text-accent"
        >
          {running ? 'Cancel' : 'Run'}
        </button>
      </div>

      {/* A mirrored agent search holds ten rows on purpose. Saying so — and
          offering the full run — stops a preview being mistaken for the answer. */}
      {tab.preview && (
        <div className="mx-[18px] mt-3 flex items-center gap-2 rounded-[9px] border border-accent-line bg-accent-soft px-3.5 py-2 text-[11.5px] text-t2">
          <span className="shrink-0 text-accent">✳</span>
          <span className="min-w-0">
            pivt ran this. Showing a {tab.limit}-row preview, not the full result set.
          </span>
          <button
            onClick={onRunFull}
            className="ml-auto shrink-0 rounded-[6px] border border-accent-line px-2 py-1 font-semibold text-accent hover:bg-hover"
          >
            Run the full search
          </button>
        </div>
      )}

      <StatusLine tab={tab} onRefresh={() => onRun(true)} />

      {tab.metadata?.histogram && <Histogram buckets={tab.metadata.histogram} />}

      {tab.rows.length === 0 ? (
        <SearchEmptyState
          status={tab.status}
          range={toApiTimeRange(tab.range)}
          rangeLabel={rangeLabel(tab)}
          onRunQuery={onRunQuery}
        />
      ) : isEventsView ? (
        // Raw events: message up front, fields on expand.
        <EventList
          rows={tab.rows}
          profile={profile}
          keywords={keywords}
          withDate={withDate}
          onExpandedChange={onExpandedChange}
        />
      ) : (
        // Aggregates (| stats, | table, | top) are tabular, not log lines.
        <ResultsTable
          rows={tab.rows}
          columnOrder={tab.metadata?.column_order}
          withDate={withDate}
        />
      )}
    </>
  );
}

function StatusLine({ tab, onRefresh }: { tab: Tab; onRefresh: () => void }) {
  if (tab.status === 'idle') return <div className="h-3" />;

  if (tab.status === 'error') {
    return (
      <div className="mx-[18px] mt-3 rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[12px] text-danger">
        {tab.error}
      </div>
    );
  }

  const { metadata, cache, rows, status } = tab;

  return (
    <div className="flex items-center gap-3 px-[18px] pt-3 pb-1 font-mono text-[11px] text-t3">
      {status === 'running' && <Spinner className="text-accent" />}
      <span>
        {rows.length.toLocaleString()}
        {metadata && metadata.total_count > rows.length
          ? ` of ${metadata.total_count.toLocaleString()}`
          : ''}{' '}
        events
      </span>
      {metadata && <span>· {metadata.execution_time_ms.toLocaleString()} ms</span>}
      {/* A cached result must say so rather than pass itself off as live. */}
      {cache?.hit && status !== 'running' && (
        <span className="flex items-center gap-1.5">
          · cached
          {cache.age_secs != null && ` ${cache.age_secs}s ago`} ·
          <button onClick={onRefresh} className="text-accent hover:opacity-80">
            refresh
          </button>
        </span>
      )}
      {metadata?.warnings?.map((warning) => (
        <span key={warning.message} className="text-warn">
          · {warning.message}
        </span>
      ))}
    </div>
  );
}


/** What the analyst chose, in their words — "Last 24 hours", not two timestamps. */
function rangeLabel(tab: Tab): string {
  if (tab.range.type === 'preset') return tab.range.preset ?? 'the selected window';
  return 'the selected window';
}
