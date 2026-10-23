// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react';
import { flattened } from '@/lib/pipeline-event-fields';
import { ClipboardPaste, History, Info, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import type {
  PipelineLaneInput,
  PipelinePreview,
  PipelinePreviewEvent,
  PipelineSample,
} from '@/lib/pipeline-types';
import {
  JsonInspector,
  PipelineLoading,
  PipelineNotice,
  PipelineStateBadge,
} from './PipelineCommon';
import { cn } from '@/lib/utils';
import { DEFAULT_RECENT_EVENTS, MAX_RECENT_EVENTS } from '@/lib/api/pipelines';
import { PREVIEW_SCOPE_DETAILS, PREVIEW_SCOPE_NOTE } from '@/lib/pipeline-model';

const PASTE_PLACEHOLDER = '{"EventID":1,"Image":"C:\\Windows\\System32\\cmd.exe"}\n<134>Oct  9 10:00:00 fw01 action=allow src=10.0.0.5';

/** First line of an input's raw message (or its JSON) for a dense list row. */
function inputSummary(input: unknown): string {
  const raw =
    input && typeof input === 'object' && 'message' in input && typeof input.message === 'string'
      ? input.message
      : JSON.stringify(input) ?? '';
  return raw.split('\n', 1)[0];
}

/** NAN-3452: one muted line about preview scope; the detail lives behind the icon. */
function PreviewScopeNote({ extra }: { extra?: string }) {
  return (
    <div className="flex items-center gap-1 text-[10.5px] text-muted-foreground">
      <span className="min-w-0 truncate" title={extra}>
        {PREVIEW_SCOPE_NOTE}
        {extra && ` ${extra}`}
      </span>
      <TooltipProvider delayDuration={150}>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              aria-label="What draft preview excludes"
              className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded-sm hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <Info className="h-3 w-3" strokeWidth={1.5} />
            </button>
          </TooltipTrigger>
          <TooltipContent side="bottom" align="start" className="max-w-80 space-y-1 text-[11px]">
            {PREVIEW_SCOPE_DETAILS.map((line) => (
              <p key={line}>{line}</p>
            ))}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    </div>
  );
}

/** NAN-3447: the two ways to get preview input without a live capture. */
function SampleSources({
  primary,
  disabled,
  loading,
  count,
  onCountChange,
  onLoadRecent,
  onPasteSample,
}: {
  primary: boolean;
  /** Held by the panel so the toolbar and empty-state copies share it. */
  count: string;
  onCountChange: (count: string) => void;
  disabled: boolean;
  loading: boolean;
  onLoadRecent?: (limit: number) => void;
  onPasteSample?: (text: string) => void;
}) {
  const [pasting, setPasting] = useState(false);
  const [text, setText] = useState('');
  const [pasteError, setPasteError] = useState<string | null>(null);
  const limit = Number(count);
  const validCount =
    Number.isInteger(limit) && limit >= 1 && limit <= MAX_RECENT_EVENTS;
  const size = primary ? 'h-7 text-[11.5px]' : 'h-6 px-2 text-[10.5px]';
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        {onLoadRecent && (
          <>
            <Button
              variant={primary ? 'default' : 'outline'}
              className={size}
              disabled={disabled || loading || !validCount}
              onClick={() => onLoadRecent(limit)}
            >
              <History
                className={cn('h-3.5 w-3.5', loading && 'animate-pulse')}
                strokeWidth={1.5}
              />
              {loading ? 'Loading…' : 'Load recent events'}
            </Button>
            <Input
              type="number"
              aria-label="Recent events to load"
              title={`Newest stored events to load (1–${MAX_RECENT_EVENTS})`}
              min={1}
              max={MAX_RECENT_EVENTS}
              className={cn('w-14 font-mono', primary ? 'h-7 text-[11.5px]' : 'h-6 text-[10.5px]')}
              value={count}
              disabled={disabled || loading}
              onChange={(event) => onCountChange(event.target.value)}
            />
          </>
        )}
        {onPasteSample && (
          <Button
            variant={primary ? 'secondary' : 'ghost'}
            className={size}
            disabled={disabled}
            aria-expanded={pasting}
            onClick={() => {
              setPasting((open) => !open);
              setPasteError(null);
            }}
          >
            <ClipboardPaste className="h-3.5 w-3.5" strokeWidth={1.5} />
            Paste sample
          </Button>
        )}
      </div>
      {onLoadRecent && !validCount && (
        <p role="alert" className="text-[10.5px] text-destructive">
          Load 1–{MAX_RECENT_EVENTS} recent events.
        </p>
      )}
      {pasting && onPasteSample && (
        <form
          className="space-y-1.5"
          onSubmit={(event) => {
            event.preventDefault();
            try {
              onPasteSample(text);
              setPasting(false);
              setText('');
              setPasteError(null);
            } catch (cause) {
              setPasteError(cause instanceof Error ? cause.message : String(cause));
            }
          }}
        >
          <textarea
            aria-label="Raw events to paste"
            className="block h-28 w-full resize-y rounded-md border border-border bg-input px-2 py-1.5 font-mono text-[11px] leading-snug"
            placeholder={PASTE_PLACEHOLDER}
            spellCheck={false}
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
          <div className="flex items-center gap-1.5">
            <Button type="submit" className="h-6 px-2 text-[10.5px]" disabled={!text.trim()}>
              Use as input
            </Button>
            <Button
              type="button"
              variant="ghost"
              className="h-6 px-2 text-[10.5px]"
              onClick={() => {
                setPasting(false);
                setPasteError(null);
              }}
            >
              Cancel
            </Button>
            <span className="ml-auto font-mono text-[10px] text-muted-foreground">
              one event per line · or a JSON array · max {MAX_RECENT_EVENTS}
            </span>
          </div>
          {pasteError && (
            <p role="alert" className="text-[10.5px] text-destructive">
              {pasteError}
            </p>
          )}
        </form>
      )}
    </div>
  );
}

function FieldDiff({
  input,
  output,
  search,
}: {
  input: unknown;
  output: unknown;
  search: string;
}) {
  const before = flattened(input),
    after = flattened(output);
  const paths = [...new Set([...before.keys(), ...after.keys()])].filter(
    (path) => path.toLowerCase().includes(search.toLowerCase())
  );
  return (
    <table className="w-full table-fixed text-left font-mono text-[10.5px]">
      <thead className="sticky top-0 bg-panel text-muted-foreground">
        <tr className="h-7 border-b border-border">
          <th className="w-[30%] px-2 font-medium">Field</th>
          <th className="w-[35%] px-2 font-medium">IN</th>
          <th className="w-[35%] px-2 font-medium">OUT</th>
        </tr>
      </thead>
      <tbody>
        {paths.map((path) => {
          const state = !before.has(path)
            ? 'added'
            : !after.has(path)
              ? 'removed'
              : before.get(path) !== after.get(path)
                ? 'changed'
                : 'same';
          return (
            <tr
              key={path}
              className={cn(
                'border-b border-border align-top',
                state === 'added'
                  ? 'bg-success/5'
                  : state === 'removed'
                    ? 'bg-destructive/5'
                    : state === 'changed'
                      ? 'bg-warning/5'
                      : ''
              )}
            >
              <td className="break-all px-2 py-1">
                <span className="mr-1 text-muted-foreground">
                  {state === 'same'
                    ? '='
                    : state === 'added'
                      ? '+'
                      : state === 'removed'
                        ? '−'
                        : '~'}
                </span>
                {path.slice(2)}
                <span className="sr-only"> {state}</span>
              </td>
              <td className="break-all px-2 py-1">{before.get(path) ?? '—'}</td>
              <td className="break-all px-2 py-1">{after.get(path) ?? '—'}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/**
 * NAN-3625: which input the sample events arrived on, for "Input is" routes.
 * "As recorded" uses each stored event's platform input (recent events);
 * captures and pasted samples have none until an input is chosen here.
 */
function PreviewInputSelect({
  laneInputs,
  routedInputs,
  value,
  onChange,
}: {
  laneInputs: PipelineLaneInput[];
  routedInputs: string[];
  value: string | null;
  onChange: (input: string | null) => void;
}) {
  const listed = new Set(laneInputs.map((input) => input.id));
  const options = [
    ...laneInputs.map((input) => ({ id: input.id, label: `${input.label} · ${input.id}` })),
    ...routedInputs.filter((id) => !listed.has(id)).map((id) => ({ id, label: id })),
  ];
  return (
    <label className="flex items-center gap-2 text-[11px] text-muted-foreground">
      <span className="shrink-0">Preview as input</span>
      <select
        aria-label="Preview as input"
        className="h-7 min-w-0 flex-1 rounded-md border border-border bg-input px-2 font-mono text-[11px]"
        value={value ?? ''}
        onChange={(event) => onChange(event.target.value || null)}
      >
        <option value="">As recorded (stored events only)</option>
        {options.map((option) => (
          <option key={option.id} value={option.id}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}

export function PipelinePreviewPanel({
  sample,
  samples,
  preview,
  revision,
  pending,
  canViewEvents,
  available,
  unavailableReason,
  error,
  selectedStepId,
  onSampleSelect,
  onPreview,
  onLoadRecent,
  onPasteSample,
  loadingRecent = false,
  sampleNotice,
  sampleError,
  laneInputs = [],
  routedInputs = [],
  previewInput = null,
  onPreviewInputChange,
}: {
  sample?: PipelineSample | null;
  samples: PipelineSample[];
  preview?: (PipelinePreview & { warnings?: string[] }) | null;
  revision: number;
  pending: boolean;
  canViewEvents: boolean;
  available: boolean;
  unavailableReason?: string;
  /** The last preview run failed; cleared by the next successful run. */
  error?: string | null;
  selectedStepId: string | null;
  onSampleSelect: (sample: PipelineSample) => void;
  onPreview: () => void;
  /** NAN-3447: load the source's newest stored raw events as browser-only input. */
  onLoadRecent?: (limit: number) => void;
  /** NAN-3447: use pasted raw events as browser-only input; throws on unusable text. */
  onPasteSample?: (text: string) => void;
  loadingRecent?: boolean;
  /** The last load found nothing to use. */
  sampleNotice?: string | null;
  /** The last load failed. */
  sampleError?: string | null;
  laneInputs?: PipelineLaneInput[];
  routedInputs?: string[];
  previewInput?: string | null;
  onPreviewInputChange?: (input: string | null) => void;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inputIndex, setInputIndex] = useState(0);
  const [recentCount, setRecentCount] = useState(String(DEFAULT_RECENT_EVENTS));
  const sampleId = sample?.id;
  useEffect(() => setInputIndex(0), [sampleId]);
  const [outputIndex, setOutputIndex] = useState(0);
  const [view, setView] = useState<'diff' | 'in' | 'out'>('diff');
  const [search, setSearch] = useState('');
  const [traceMode, setTraceMode] = useState<'final' | 'selected'>('final');
  if (!canViewEvents)
    return (
      <div className="p-3">
        <PipelineNotice title="Source-event permission required">
          Your role can read configuration, but cannot view captured or
          previewed event payloads.
        </PipelineNotice>
      </div>
    );
  const rows = preview?.events ?? [];
  const selected =
    rows.find((event) => event.inputId === selectedId) ?? rows[0];
  const traceIndex =
    traceMode === 'selected' && selectedStepId
      ? (selected?.trace?.findIndex((item) => item.stepId === selectedStepId) ??
        -1)
      : -1;
  const trace = traceIndex >= 0 ? selected?.trace?.[traceIndex] : undefined;
  const previousTrace =
    traceIndex > 0 ? selected?.trace?.[traceIndex - 1] : undefined;
  const stepInputAvailable =
    traceIndex === 0 || previousTrace?.outputs.length === 1;
  const input =
    trace && traceIndex > 0 && stepInputAvailable
      ? previousTrace!.outputs[0]
      : selected?.input;
  const outputs = trace?.outputs ?? selected?.outputs ?? [];
  const output =
    outputs[Math.min(outputIndex, Math.max(0, outputs.length - 1))];
  const outcomeText: Partial<Record<PipelinePreviewEvent['outcome'], string>> =
    {
      filtered: 'Filtered by the draft pipeline.',
      sampled_out: 'Sampled out by the draft pipeline.',
      error: selected?.error ?? 'Processing failed for this input.',
      pending: 'No output yet; waiting for flush.',
      combined: 'Combined with other input events.',
    };
  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* NAN-3452: notices scroll inside this block so they never push the
          panel past the editor's height. */}
      <div className="max-h-[45%] shrink-0 space-y-2 overflow-y-auto border-b border-border p-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[10.5px] text-muted-foreground">
            Computed draft · edit {preview?.revision ?? revision}
            {preview?.stale && ` · current draft edit ${revision}`}
          </span>
          <span className="ml-auto font-mono text-[10px] text-muted-foreground">
            {sample
              ? `${sample.name} · ${sample.events.length} inputs`
              : 'No input sample selected'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <select
            aria-label="Input sample"
            className="h-7 min-w-0 flex-1 rounded-md border border-border bg-input px-2 text-[11.5px]"
            value={sample?.id ?? ''}
            onChange={(event) => {
              const chosen = samples.find(
                (item) => item.id === event.target.value
              );
              if (chosen) {
                setSelectedId(null);
                setOutputIndex(0);
                setInputIndex(0);
                onSampleSelect(chosen);
              }
            }}
          >
            <option value="">Choose saved input sample</option>
            {sample && !samples.some((item) => item.id === sample.id) && (
              <option value={sample.id}>{sample.name}</option>
            )}
            {samples.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
          <Button
            variant="outline"
            className="h-7 text-[11.5px]"
            onClick={onPreview}
            disabled={!sample || !available || pending}
          >
            <RefreshCw
              className={cn('h-3.5 w-3.5', pending && 'animate-spin')}
              strokeWidth={1.5}
            />
            Run preview
          </Button>
        </div>
        {onPreviewInputChange && (laneInputs.length > 0 || routedInputs.length > 0) && (
          <PreviewInputSelect
            laneInputs={laneInputs}
            routedInputs={routedInputs}
            value={previewInput}
            onChange={onPreviewInputChange}
          />
        )}
        {sample && (onLoadRecent || onPasteSample) && (
          <SampleSources
            primary={false}
            disabled={pending}
            loading={loadingRecent}
            count={recentCount}
            onCountChange={setRecentCount}
            onLoadRecent={onLoadRecent}
            onPasteSample={onPasteSample}
          />
        )}
        {sampleNotice && (
          <PipelineNotice title="No recent events">{sampleNotice}</PipelineNotice>
        )}
        {sampleError && (
          <PipelineNotice title="Recent events could not be loaded" tone="error">
            {sampleError}
          </PipelineNotice>
        )}
        {!available && (
          <PipelineNotice title="Runtime preview unavailable">
            {unavailableReason ??
              'The runtime has not advertised preview support. Captures and saved samples remain inspectable.'}
          </PipelineNotice>
        )}
        {available && <PreviewScopeNote extra={unavailableReason} />}
        {available && error && (
          <PipelineNotice title="Preview failed" tone="error">
            {error}
          </PipelineNotice>
        )}
        {preview?.warnings?.map((warning, index) => (
          <p key={index} className="text-[10.5px] text-warning">{warning}</p>
        ))}
        {preview?.stale && (
          <PipelineNotice title="Preview out of date" tone="warning">
            These results belong to an earlier draft. Run preview to evaluate
            the current revision.
          </PipelineNotice>
        )}
        {preview && (
          <div className="flex flex-wrap gap-3 font-mono text-[10.5px] text-muted-foreground">
            <span>
              Sample results · {preview.inputCount} IN → {preview.outputCount}{' '}
              OUT
            </span>
            <span>Isolated preview state</span>
          </div>
        )}
      </div>
      {pending && (
        <PipelineLoading label="Evaluating the frozen input sample…" />
      )}
      {!preview ? (
        <div className="min-h-0 flex-1 overflow-auto">
          {sample?.events.length ? (
            <>
              <div className="border-b border-border px-3 py-2 font-mono text-[10.5px] text-muted-foreground">
                {sample.origin === 'recent' || sample.origin === 'pasted'
                  ? 'Browser-only input'
                  : 'Frozen input'}{' '}
                · {sample.events.length} events · output has not been computed
              </div>
              <div
                className="max-h-[160px] overflow-auto border-b border-border"
                role="listbox"
                aria-label="Preview inputs"
              >
                {sample.events.map((event, index) => (
                  <button
                    key={event.id}
                    role="option"
                    aria-selected={index === Math.min(inputIndex, sample.events.length - 1)}
                    onClick={() => setInputIndex(index)}
                    className={cn(
                      'flex h-6 w-full items-center gap-2 border-b border-border px-3 text-left font-mono text-[10.5px]',
                      index === Math.min(inputIndex, sample.events.length - 1)
                        ? 'bg-primary/10'
                        : 'hover:bg-accent'
                    )}
                  >
                    <span className="w-6 shrink-0 text-muted-foreground">{index + 1}</span>
                    <span className="min-w-0 flex-1 truncate">{inputSummary(event.input)}</span>
                    {event.capturedAt && (
                      <span className="shrink-0 text-[10px] text-muted-foreground">{event.capturedAt}</span>
                    )}
                  </button>
                ))}
              </div>
              <JsonInspector
                value={sample.events[Math.min(inputIndex, sample.events.length - 1)].input}
              />
            </>
          ) : (
            <div className="space-y-3 p-3" data-testid="pipeline-preview-empty">
              <div className="space-y-1">
                <p className="text-[12px] font-medium text-foreground">No preview input yet</p>
                <p className="text-[11.5px] text-muted-foreground">
                  Preview runs this draft on raw events before any parsing. Load
                  the newest events stored for this source, or paste raw events
                  — one per line, or a JSON array. Input stays in this browser and
                  is never saved; draft preview never changes production.
                </p>
                {samples.length > 0 && (
                  <p className="text-[11px] text-muted-foreground">
                    Saved input samples are also available in the list above.
                  </p>
                )}
              </div>
              {(onLoadRecent || onPasteSample) && (
                <SampleSources
                  primary
                  disabled={pending}
                  loading={loadingRecent}
                  count={recentCount}
                  onCountChange={setRecentCount}
                  onLoadRecent={onLoadRecent}
                  onPasteSample={onPasteSample}
                />
              )}
            </div>
          )}
        </div>
      ) : (
        <>
          <div
            className="min-h-[96px] max-h-[160px] shrink-0 overflow-auto border-b border-border"
            role="listbox"
            aria-label="Preview input outcomes"
          >
            {rows.map((event) => (
              <button
                key={event.inputId}
                role="option"
                aria-selected={event.inputId === selected?.inputId}
                onClick={() => {
                  setSelectedId(event.inputId);
                  setOutputIndex(0);
                }}
                className={cn(
                  'flex min-h-7 w-full items-center gap-2 border-b border-border px-3 text-left text-[11px]',
                  event.inputId === selected?.inputId
                    ? 'bg-primary/10'
                    : 'hover:bg-accent'
                )}
              >
                <span className="min-w-0 flex-1 truncate font-mono">
                  {event.inputId}
                </span>
                <PipelineStateBadge state={event.outcome} />
                <span className="font-mono text-[10px] text-muted-foreground">
                  {event.outputs.length} out
                </span>
              </button>
            ))}
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-border px-2 py-1">
            {(['in', 'out', 'diff'] as const).map((mode) => (
              <Button
                key={mode}
                variant={view === mode ? 'secondary' : 'ghost'}
                className="h-6 px-2 text-[10.5px]"
                aria-pressed={view === mode}
                onClick={() => setView(mode)}
              >
                {mode.toUpperCase()}
              </Button>
            ))}
            {outputs.length > 1 && (
              <select
                aria-label="Output event"
                className="ml-1 h-6 rounded-sm border border-border bg-input text-[10.5px]"
                value={outputIndex}
                onChange={(event) => setOutputIndex(Number(event.target.value))}
              >
                {outputs.map((_, index) => (
                  <option key={index} value={index}>
                    Output {index + 1}/{outputs.length}
                  </option>
                ))}
              </select>
            )}
            {selectedStepId && (
              <select
                aria-label="Preview stage"
                className="h-6 max-w-40 rounded-sm border border-border bg-input text-[10.5px]"
                value={traceMode}
                onChange={(event) => {
                  setTraceMode(event.target.value as 'final' | 'selected');
                  setOutputIndex(0);
                }}
              >
                <option value="final">Final output</option>
                <option value="selected">Selected step</option>
              </select>
            )}
            <Input
              aria-label="Search preview fields"
              className="ml-auto h-6 w-32 text-[10.5px]"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Find field…"
            />
          </div>
          {traceMode === 'selected' && selectedStepId && (
            <div className="border-b border-border px-3 py-1 font-mono text-[10px] text-muted-foreground">
              {trace
                ? stepInputAvailable
                  ? `Prefix before → prefix through step ${selectedStepId}`
                  : `Input → after step ${selectedStepId} · per-step input unavailable`
                : 'Final output · selected step trace unavailable'}
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-auto">
            {selected && output === undefined && view !== 'in' ? (
              <div className="p-3">
                <PipelineNotice
                  title={
                    selected.outcome === 'pending'
                      ? 'Waiting for flush'
                      : 'No output event'
                  }
                  tone={selected.outcome === 'error' ? 'error' : 'neutral'}
                >
                  {outcomeText[selected.outcome] ??
                    'This input did not produce an output.'}
                </PipelineNotice>
              </div>
            ) : view === 'diff' ? (
              <FieldDiff input={input} output={output} search={search} />
            ) : (
              <JsonInspector value={view === 'in' ? input : output} />
            )}
          </div>
          <div className="flex h-6 shrink-0 items-center gap-3 border-t border-border px-3 font-mono text-[10px] text-muted-foreground">
            <span>+ added</span>
            <span>~ changed</span>
            <span>− removed</span>
            <span>= unchanged</span>
          </div>
        </>
      )}
    </div>
  );
}
