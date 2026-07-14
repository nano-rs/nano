import { useMemo, useState } from 'react';

import {
  buildFieldCategories,
  flattenEventFields,
  splitFieldKey,
} from '@/components/search/event-flatten';
import { highlightText } from '@/components/search/keyword-highlight';

import { formatValue, keyChipSpecs } from '../lib/schema';
import { formatTimestamp } from '../lib/time';
import type { SchemaProfile } from '../lib/types';

/** Long messages get cut here; the row stays scannable and "…" reveals the rest. */
const MESSAGE_CLAMP = 500;
const VALUE_CLAMP = 200;

/**
 * The events view: one row per event showing the raw `message`, expanding to the
 * event's fields grouped by category.
 *
 * Field flattening and categorization are imported from the web app rather than
 * reimplemented, so both surfaces render the same event identically — including
 * the OCSF `event`/`unmapped` expansion and the suppression of ClickHouse
 * defaults and internal `*_unified` columns.
 */
export function EventList({
  rows,
  profile,
  keywords,
  withDate,
  onExpandedChange,
}: {
  rows: Record<string, unknown>[];
  profile: SchemaProfile;
  /** Search terms from the executed query, marked in yellow wherever they appear. */
  keywords: string[];
  withDate: boolean;
  /** The most recently expanded event — pivt is shown whatever the analyst opened. */
  onExpandedChange?: (event: Record<string, unknown> | null) => void;
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  function toggle(index: number) {
    setExpanded((current) => {
      const next = new Set(current);
      if (next.has(index)) {
        next.delete(index);
        onExpandedChange?.(null);
      } else {
        next.add(index);
        onExpandedChange?.(rows[index] ?? null);
      }
      return next;
    });
  }

  return (
    <div className="mx-[18px] mt-1.5 mb-[14px] min-h-0 flex-1 overflow-auto rounded-[10px] border border-line bg-inset">
      {rows.map((row, index) => (
        <EventRow
          key={index}
          row={row}
          profile={profile}
          keywords={keywords}
          withDate={withDate}
          isExpanded={expanded.has(index)}
          onToggle={() => toggle(index)}
        />
      ))}
    </div>
  );
}

function EventRow({
  row,
  profile,
  keywords,
  withDate,
  isExpanded,
  onToggle,
}: {
  row: Record<string, unknown>;
  profile: SchemaProfile;
  keywords: string[];
  withDate: boolean;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const [showFullMessage, setShowFullMessage] = useState(false);

  const message = formatValue(row.message);
  const clamped = !showFullMessage && message.length > MESSAGE_CLAMP;
  const body = clamped ? message.slice(0, MESSAGE_CLAMP) : message;

  const chips = keyChipSpecs(profile.isOcsf)
    .map((spec) => ({ ...spec, value: row[spec.field] }))
    .filter((chip) => chip.value !== undefined && chip.value !== null && chip.value !== '');

  return (
    <div
      onClick={onToggle}
      className={`cursor-pointer border-b border-line px-3.5 py-2.5 hover:bg-hover ${
        isExpanded ? 'border-l-2 border-l-accent bg-accent-soft/40' : ''
      }`}
    >
      <div className="mb-1 flex items-center gap-1.5 font-mono text-[11.5px] text-t3">
        <span className={`transition-transform ${isExpanded ? 'rotate-90 text-accent' : ''}`}>›</span>
        <span>{formatTimestamp(row.timestamp, withDate)}</span>
      </div>

      {body && (
        <div className="font-mono text-[12px] leading-[1.55] break-words whitespace-pre-wrap text-t1">
          {keywords.length > 0 ? highlightText(body, keywords) : body}
          {clamped && (
            <button
              onClick={(event) => {
                event.stopPropagation();
                setShowFullMessage(true);
              }}
              className="ml-1 rounded-[3px] px-1 align-baseline text-t3 hover:bg-white/10 hover:text-accent"
              title="Show the rest"
            >
              …
            </button>
          )}
        </div>
      )}

      {/* The summary chips duplicate what the expanded view shows in full, so
          they'd be noise once it's open. */}
      {chips.length > 0 && !isExpanded && (
        <div className="mt-2.5 flex flex-wrap gap-1 font-mono text-[10.5px]">
          {chips.map((chip) => (
            <span
              key={chip.label}
              className={`inline-flex overflow-hidden rounded-[3px] border ${
                chip.accent ? 'border-accent-line' : 'border-line-strong'
              }`}
            >
              <span
                className={`border-r px-1.5 ${
                  chip.accent
                    ? 'border-accent-line bg-accent-soft text-accent'
                    : 'border-line-strong bg-white/[0.03] text-t4'
                }`}
              >
                {chip.label}
              </span>
              <span className={`px-1.5 ${chip.accent ? 'font-semibold text-accent' : 'text-t2'}`}>
                {String(chip.value)}
              </span>
            </span>
          ))}
        </div>
      )}

      {isExpanded && <EventFields row={row} profile={profile} keywords={keywords} />}
    </div>
  );
}

/** Category label → token colour. The web app's palette classes don't exist here. */
const CATEGORY_COLOR: Record<string, string> = {
  Core: 'text-t3',
  Unmapped: 'text-t4',
};

function EventFields({
  row,
  profile,
  keywords,
}: {
  row: Record<string, unknown>;
  profile: SchemaProfile;
  keywords: string[];
}) {
  const categories = useMemo(() => {
    const flattened = flattenEventFields(row, profile.isOcsf, '', profile.knownFields);
    return buildFieldCategories(flattened, profile.knownFields, profile.isOcsf);
  }, [row, profile]);

  if (categories.length === 0) {
    return <div className="mt-3 border-t border-line pt-3 text-[11.5px] text-t4">No fields.</div>;
  }

  return (
    <div className="mt-3 space-y-2 border-t border-line pt-3" onClick={(e) => e.stopPropagation()}>
      {categories.map((category) => (
        <div key={category.label}>
          <div
            className={`py-1 text-[10px] font-semibold tracking-wider uppercase ${
              CATEGORY_COLOR[category.label] ?? 'text-accent'
            }`}
          >
            {category.label}
            <span className="ml-1 text-t4">({category.fields.length})</span>
          </div>

          <div className="font-mono text-[11.5px]">
            {category.fields.map(([key, value]) => (
              <FieldRow key={key} name={key} value={value} keywords={keywords} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function FieldRow({
  name,
  value,
  keywords,
}: {
  name: string;
  value: unknown;
  keywords: string[];
}) {
  const [showFull, setShowFull] = useState(false);
  const [copied, setCopied] = useState(false);

  const formatted = formatValue(value);
  const clamped = !showFull && formatted.length > VALUE_CLAMP;
  const shown = clamped ? formatted.slice(0, VALUE_CLAMP) : formatted;
  const { namespace, leaf } = splitFieldKey(name);

  return (
    <div className="group flex items-start gap-3 py-1 hover:bg-hover">
      <div className="flex w-56 shrink-0 items-start gap-1 text-t4">
        <span className="leading-tight break-all" title={name}>
          {namespace && <span className="opacity-50">{namespace}</span>}
          {leaf}
        </span>
        <button
          onClick={() => {
            void navigator.clipboard.writeText(formatted);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="shrink-0 opacity-0 group-hover:opacity-100"
          title="Copy value"
        >
          {copied ? <span className="text-accent">✓</span> : <span className="text-t4">⧉</span>}
        </button>
      </div>

      <div className="min-w-0 flex-1 break-all whitespace-pre-wrap text-t2">
        {keywords.length > 0 ? highlightText(shown, keywords) : shown}
        {clamped && (
          <button
            onClick={() => setShowFull(true)}
            className="ml-1 rounded-[3px] px-1 text-t3 hover:bg-white/10 hover:text-accent"
            title="Show the rest"
          >
            …
          </button>
        )}
      </div>
    </div>
  );
}
