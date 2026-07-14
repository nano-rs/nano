import { useEffect, useState } from 'react';

import { api } from '../lib/ipc';
import type { TabStatus } from '../state/tabs';

/**
 * The pane before (and after) a search. Three genuinely different situations,
 * and conflating them is how an analyst ends up staring at "no results" when the
 * real problem is that nothing has run yet.
 *
 * The idle state earns its space by being useful: it lists the source types
 * actually present in the selected window — clickable — so the first query is a
 * click, not a guess about what's in the data.
 */
interface Props {
  status: TabStatus;
  /** Resolved window, so the source-type list matches what a search would find. */
  range: { start: string; end: string };
  rangeLabel: string;
  onRunQuery: (query: string) => void;
}

const STARTERS = [
  { query: '*', label: 'Everything in the window' },
  { query: '* | stats count by source_type', label: 'Count events by source' },
  { query: '* | rare user', label: 'Rare users' },
];

export function SearchEmptyState({ status, range, rangeLabel, onRunQuery }: Props) {
  if (status === 'running') {
    return (
      <Centered>
        <div className="text-[12.5px] text-t3">Running…</div>
      </Centered>
    );
  }

  if (status === 'done') {
    return (
      <Centered>
        <div className="text-[15px] font-semibold text-t1">No events matched</div>
        <p className="mt-2 max-w-[380px] text-center text-[12.5px] leading-[1.6] text-t3">
          Nothing in <span className="font-mono text-t2">{rangeLabel}</span> matched this query.
          Widen the time range, or loosen a filter.
        </p>
      </Centered>
    );
  }

  // status === 'error' renders in the status line, not here.
  if (status === 'error') return <Centered>{null}</Centered>;

  return (
    <Centered>
      <div className="w-full max-w-[520px]">
        <div className="text-center">
          <div className="text-[15px] font-semibold text-t1">Search your data</div>
          <p className="mt-1.5 text-[12.5px] text-t3">
            Write nPL in the bar above, or start from one of these.
          </p>
        </div>

        <div className="mt-6 overflow-hidden rounded-[10px] border border-line bg-inset">
          {STARTERS.map((starter) => (
            <button
              key={starter.query}
              onClick={() => onRunQuery(starter.query)}
              className="flex w-full items-center gap-3 border-b border-line px-4 py-2.5 text-left last:border-b-0 hover:bg-hover"
            >
              <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-accent">
                {starter.query}
              </span>
              <span className="shrink-0 text-[11.5px] text-t4">{starter.label}</span>
            </button>
          ))}
        </div>

        <SourceTypes range={range} onRunQuery={onRunQuery} />

        <div className="mt-6 flex flex-wrap justify-center gap-x-4 gap-y-1.5 font-mono text-[10.5px] text-t4">
          <span>⏎ run</span>
          <span>⇥ suggestions</span>
          <span>⌘I pivt</span>
          <span>⌘J terminal</span>
          <span>⌘T new tab</span>
        </div>
      </div>
    </Centered>
  );
}

/**
 * The source types actually present in this window, with their event counts.
 * Only rendered when the server returns some — an empty deployment shouldn't be
 * shown an empty box implying it should have data.
 */
function SourceTypes({
  range,
  onRunQuery,
}: {
  range: { start: string; end: string };
  onRunQuery: (query: string) => void;
}) {
  const [sources, setSources] = useState<[string, number][]>([]);

  useEffect(() => {
    let cancelled = false;
    void api
      .sourceTypes(range.start, range.end)
      .then((values) => {
        if (!cancelled) setSources(values.slice(0, 8));
      })
      .catch(() => {
        // Nothing to show is a fine outcome; the starters still work.
      });
    return () => {
      cancelled = true;
    };
  }, [range.start, range.end]);

  if (sources.length === 0) return null;

  return (
    <div className="mt-6">
      <div className="mb-2 text-center text-[10.5px] font-bold tracking-[0.08em] text-t4 uppercase">
        In this window
      </div>
      <div className="flex flex-wrap justify-center gap-1.5">
        {sources.map(([source, count]) => (
          <button
            key={source}
            onClick={() => onRunQuery(`source_type="${source}"`)}
            className="flex items-center gap-2 rounded-[20px] border border-line-strong bg-raised px-3 py-1 font-mono text-[11px] text-t2 hover:border-accent-line hover:text-accent"
          >
            {source}
            <span className="text-t4">{count.toLocaleString()}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-6 pb-10">{children}</div>
  );
}
