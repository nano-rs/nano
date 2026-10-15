// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from 'react';
import { Eye, Square } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type {
  PipelineCapabilities,
  PipelineCapture,
  PipelineCaptureOptions,
} from '@/lib/pipeline-types';
import { JsonInspector, PipelineField, PipelineNotice } from './PipelineCommon';
import { formatUTC, formatUTCShort } from '@/lib/date-utils';
import { cn } from '@/lib/utils';
import { Checkbox } from '@/components/ui/checkbox';

const CAPTURE_MESSAGES: Record<PipelineCapture['state'], [string, string]> = {
  ready: [
    'Ready to capture',
    'Observe a bounded sample of decoded incoming events before your processing steps.',
  ],
  connecting: [
    'Connecting to live input',
    'Waiting for the runtime to accept the capture session.',
  ],
  capturing: [
    'Capturing live input',
    'Events are observed from the active runtime. Freeze to preview draft changes.',
  ],
  completed: [
    'Capture completed',
    'The bounded sample is ready for draft preview.',
  ],
  stopped: [
    'Capture stopped',
    'Collected events remain available for inspection and draft preview.',
  ],
  no_traffic: [
    'No source traffic observed during this capture',
    'Retry after the source starts sending events.',
  ],
  no_matches: [
    'No observed matches',
    'The source had observations, but none matched the capture filter.',
  ],
  limit: [
    'Capture limit reached',
    'The bounded sample may cover only part of the incoming traffic.',
  ],
  interrupted: [
    'Capture connection interrupted',
    'This sample is incomplete. Retry starts a new capture session.',
  ],
  release_changed: [
    'Active release changed',
    'The retained sample belongs to its original release. Start a new capture to observe the new release.',
  ],
  unavailable: [
    'Live capture unavailable',
    'Saved input samples can still be used for draft preview.',
  ],
  forbidden: [
    'Source-event permission required',
    'Your role can inspect configuration, but cannot view source event payloads.',
  ],
  expired: [
    'Captured events expired',
    'Capture snapshots are kept for 10 minutes and then purged. Capture again to observe current traffic.',
  ],
  failed: [
    'Capture failed',
    'The runtime did not complete this capture. Retained events are marked incomplete.',
  ],
};

export function PipelineCapturePanel({
  sourceId,
  sourceName,
  activeRevision,
  capture,
  capabilities,
  canCapture,
  busy,
  onStart,
  onStop,
  onFreeze,
  onSaveSample,
  canSaveSample = false,
}: {
  sourceId: string;
  sourceName: string;
  activeRevision: number | null;
  capture?: PipelineCapture | null;
  capabilities: PipelineCapabilities;
  canCapture: boolean;
  busy: boolean;
  onStart: (options: PipelineCaptureOptions) => void;
  onStop: () => void;
  onFreeze: () => void;
  onSaveSample?: () => void;
  canSaveSample?: boolean;
}) {
  const [duration, setDuration] = useState('30');
  const [limit, setLimit] = useState('100');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [follow, setFollow] = useState(true);
  const list = useRef<HTMLDivElement>(null);
  const events = canCapture ? (capture?.events ?? []) : [];
  const state = !canCapture
    ? 'forbidden'
    : !capabilities.capture.available
      ? 'unavailable'
      : (capture?.state ?? 'ready');
  const running = state === 'capturing' || state === 'connecting';
  const maxDuration = capabilities.capture.maxDurationSeconds ?? 120;
  const maxEvents = capabilities.capture.maxEvents ?? 500;
  const valid =
    Number.isInteger(Number(duration)) &&
    Number(duration) >= 1 &&
    Number(duration) <= maxDuration &&
    Number.isInteger(Number(limit)) &&
    Number(limit) >= 1 &&
    Number(limit) <= maxEvents;
  const selected = events.find((event) => event.id === selectedId) ?? events[0];
  useEffect(() => {
    if (follow && list.current)
      list.current.scrollTop = list.current.scrollHeight;
  }, [events.length, follow]);
  const [title, explanation] = CAPTURE_MESSAGES[state];
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 space-y-2 border-b border-border p-3">
        <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
          <span className="font-medium">{sourceName}</span>
          <span
            className="font-mono text-[10px] text-muted-foreground"
            title={capture?.activeBundleSha256 ?? undefined}
          >
            Observed input ·{' '}
            {capture?.sessionId
              ? capture.activeBundleSha256
                ? `bundle ${capture.activeBundleSha256.slice(0, 12)}`
                : 'captured runtime bundle'
              : activeRevision === null
                ? 'active version unknown'
                : `active version ${activeRevision}`}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <PipelineField
            label="Duration (seconds)"
            hint={`Maximum ${maxDuration}s`}
          >
            <Input
              type="number"
              min={1}
              max={maxDuration}
              className="h-7 font-mono"
              value={duration}
              disabled={
                running || !canCapture || !capabilities.capture.available
              }
              onChange={(event) => setDuration(event.target.value)}
            />
          </PipelineField>
          <PipelineField
            label="Capture up to (events)"
            hint={`Maximum ${maxEvents} events`}
          >
            <Input
              type="number"
              min={1}
              max={maxEvents}
              className="h-7 font-mono"
              value={limit}
              disabled={
                running || !canCapture || !capabilities.capture.available
              }
              onChange={(event) => setLimit(event.target.value)}
            />
          </PipelineField>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {!running ? (
            <Button
              className="h-7 text-[11.5px]"
              disabled={
                !canCapture || !capabilities.capture.available || !valid || busy
              }
              onClick={() => {
                setSelectedId(null);
                onStart({
                  sourceId,
                  point: 'input',
                  durationSeconds: Number(duration),
                  eventLimit: Number(limit),
                });
              }}
            >
              <Eye className="h-3.5 w-3.5" strokeWidth={1.5} />
              {state === 'ready' ? 'Start capture' : 'Capture again'}
            </Button>
          ) : (
            <Button
              variant="outline"
              className="h-7 text-[11.5px]"
              onClick={onStop}
              disabled={busy}
            >
              <Square className="h-3 w-3" strokeWidth={1.5} />
              Stop capture
            </Button>
          )}
          <Button
            variant="outline"
            className="h-7 text-[11.5px]"
            disabled={!canCapture || events.length === 0 || busy}
            onClick={onFreeze}
          >
            Freeze and preview
          </Button>
          {onSaveSample && (
            <Button
              variant="ghost"
              className="h-7 text-[11.5px]"
              disabled={
                !canCapture ||
                !canSaveSample ||
                running ||
                events.length === 0 ||
                busy
              }
              title={
                !canSaveSample
                  ? 'Freeze this input sample and ensure you have pipeline edit permission before saving.'
                  : undefined
              }
              onClick={onSaveSample}
            >
              Save as sample
            </Button>
          )}
        </div>
        {!valid && (
          <p role="alert" className="text-[10.5px] text-destructive">
            Enter whole numbers within the capture limits.
          </p>
        )}
        {capabilities.capture.maxBytes && (
          <p className="font-mono text-[10px] text-muted-foreground">
            Sample byte limit ·{' '}
            {Math.floor(capabilities.capture.maxBytes / 1024)} KiB
          </p>
        )}
        <PipelineNotice
          title={title}
          tone={
            state === 'failed' || state === 'interrupted'
              ? 'error'
              : state === 'expired'
                ? 'warning'
                : 'neutral'
          }
        >
          {capture?.reason ?? capabilities.capture.reason ?? explanation}
        </PipelineNotice>
        {capture?.startedAt && canCapture && (
          <div className="flex flex-wrap gap-x-2 font-mono text-[10px] text-muted-foreground">
            <span>
              Started{' '}
              <time
                dateTime={capture.startedAt}
                title={formatUTC(capture.startedAt)}
              >
                {formatUTCShort(capture.startedAt)}
              </time>
            </span>
            <span>
              {capture.observedEvents ?? events.length} observed
              {capture.observedEvents !== undefined &&
                capture.observedEvents !== events.length &&
                ` · ${events.length} loaded`}
            </span>
            {capture.retainUntil && state !== 'expired' && (
              <span>
                Held until{' '}
                <time
                  dateTime={capture.retainUntil}
                  title={formatUTC(capture.retainUntil)}
                >
                  {formatUTCShort(capture.retainUntil)}
                </time>
              </span>
            )}
          </div>
        )}
      </div>
      {canCapture && events.length > 0 && (
        <div className="grid min-h-0 flex-1 grid-rows-[minmax(120px,35%)_1fr]">
          <div className="flex min-h-0 flex-col border-b border-border">
            <div className="flex h-7 shrink-0 items-center justify-between border-b border-border px-2.5 text-[10.5px] text-muted-foreground">
              <span className="font-mono">
                Observed events · {events.length}
              </span>
              <label className="flex items-center gap-1.5">
                <Checkbox
                  checked={follow}
                  onCheckedChange={(checked) => setFollow(checked === true)}
                  className="h-3.5 w-3.5"
                />
                Follow live
              </label>
            </div>
            <div
              ref={list}
              role="listbox"
              aria-label="Captured events"
              className="min-h-0 flex-1 overflow-auto"
            >
              {events.map((event, index) => (
                <button
                  key={event.id}
                  role="option"
                  aria-selected={selected?.id === event.id}
                  className={cn(
                    'flex h-7 w-full items-center gap-2 border-b border-border px-2.5 text-left font-mono text-[10.5px] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring',
                    selected?.id === event.id
                      ? 'bg-primary/10 text-primary'
                      : 'hover:bg-accent'
                  )}
                  onClick={() => {
                    setSelectedId(event.id);
                    setFollow(false);
                  }}
                  onKeyDown={(key) => {
                    if (key.key === 'ArrowDown' || key.key === 'ArrowUp') {
                      key.preventDefault();
                      const sibling =
                        events[index + (key.key === 'ArrowDown' ? 1 : -1)];
                      if (sibling) {
                        setSelectedId(sibling.id);
                        setFollow(false);
                        (
                          key.currentTarget.parentElement?.children[
                            index + (key.key === 'ArrowDown' ? 1 : -1)
                          ] as HTMLElement
                        )?.focus();
                      }
                    }
                  }}
                >
                  <span className="w-5 text-muted-foreground">{index + 1}</span>
                  <span className="truncate">{event.id}</span>
                  <span className="ml-auto truncate text-[10px] text-muted-foreground">
                    {event.capturedAt ?? ''}
                  </span>
                </button>
              ))}
            </div>
          </div>
          <div className="min-h-0 overflow-auto">
            <JsonInspector value={selected?.input} />
          </div>
        </div>
      )}
    </div>
  );
}
