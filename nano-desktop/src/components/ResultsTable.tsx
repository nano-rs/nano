import { Fragment, useMemo, useState } from 'react';

import { cellClass, deriveColumns, formatCell, isTimeColumn } from '../lib/columns';
import { formatTimestamp } from '../lib/time';

interface Props {
  rows: Record<string, unknown>[];
  columnOrder?: string[];
  /** Long windows need the date on each row; short ones would just repeat it. */
  withDate: boolean;
}

export function ResultsTable({ rows, columnOrder, withDate }: Props) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const columns = useMemo(() => deriveColumns(rows, columnOrder), [rows, columnOrder]);

  const template = columns
    .map((column) => (isTimeColumn(column) ? '190px' : 'minmax(120px, 1fr)'))
    .join(' ');

  return (
    <div className="mx-[18px] mt-1.5 mb-[14px] min-h-0 flex-1 overflow-auto rounded-[10px] border border-line bg-inset">
      <div
        style={{ gridTemplateColumns: template }}
        className="sticky top-0 z-10 grid gap-x-3.5 border-b border-line bg-inset px-4 py-2.5 text-[10.5px] font-bold tracking-[0.06em] text-t4 backdrop-blur-sm"
      >
        {columns.map((column) => (
          <span key={column} className="truncate uppercase">
            {column}
          </span>
        ))}
      </div>

      {rows.map((row, index) => (
        <Fragment key={index}>
          <div
            onClick={() => setExpanded(expanded === index ? null : index)}
            style={{ gridTemplateColumns: template }}
            className={`grid cursor-pointer gap-x-3.5 border-b border-line px-4 py-2.5 font-mono text-[12.5px] hover:bg-hover ${
              expanded === index ? 'bg-accent-soft' : ''
            }`}
          >
            {columns.map((column) => {
              const value = row[column];
              return (
                <span
                  key={column}
                  title={formatCell(value)}
                  className={`truncate ${cellClass(column, value)}`}
                >
                  {isTimeColumn(column) ? formatTimestamp(value, withDate) : formatCell(value)}
                </span>
              );
            })}
          </div>
          {expanded === index && <RawEvent row={row} />}
        </Fragment>
      ))}
    </div>
  );
}

/** Mock 2b's inspector, reduced to its core: the raw event, syntax-coloured. */
function RawEvent({ row }: { row: Record<string, unknown> }) {
  return (
    <div className="border-b border-line bg-black/25 px-4 py-3">
      <div className="mb-2 text-[10.5px] font-bold tracking-[0.06em] text-t4">RAW EVENT</div>
      <pre className="overflow-x-auto font-mono text-[11.5px] leading-[1.6] whitespace-pre-wrap text-t2">
        {highlight(JSON.stringify(row, null, 2))}
      </pre>
    </div>
  );
}

const TOKENS = /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|(\b(?:true|false|null)\b)|(-?\d+\.?\d*)/g;

function highlight(json: string) {
  const parts: React.ReactNode[] = [];
  let cursor = 0;

  for (const match of json.matchAll(TOKENS)) {
    const [text, key, string, literal] = match;
    const start = match.index;
    if (start > cursor) parts.push(json.slice(cursor, start));

    const className = key
      ? 'text-info'
      : string
        ? 'text-violet'
        : literal
          ? 'text-info'
          : 'text-warn';
    parts.push(
      <span key={start} className={className}>
        {text}
      </span>
    );
    cursor = start + text.length;
  }

  if (cursor < json.length) parts.push(json.slice(cursor));
  return parts;
}
