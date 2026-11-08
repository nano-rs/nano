// SPDX-License-Identifier: AGPL-3.0-or-later

// Live tap (NAN-4919): one blocking `POST /pipe-tap` that captures events
// entering this source's pipeline on the local Vector for a bounded window.
// Events are redacted server-side and held in browser memory only.

import { useEffect, useState } from 'react';
import { Eye, Radio, Square } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { PipelineCapabilities, PipelineTap, PipelineTapOptions } from '@/lib/pipeline-types';
import { TAP_DEFAULT_EVENTS, TAP_DEFAULT_SECONDS } from '@/lib/api/pipelines';
import { JsonInspector, PipelineField, PipelineNotice } from './PipelineCommon';
import { cn } from '@/lib/utils';

const TAP_MESSAGES: Record<PipelineTap['state'], [string, string]> = {
  ready: ['Ready to tap', 'Capture a bounded sample of events as they enter this pipeline, before your steps run.'],
  capturing: ['Tapping live input', 'Waiting for the capture window to close. Cancel to stop early; nothing is kept.'],
  completed: ['Tap completed', 'Use these events as the preview input to see what your draft does to them.'],
  no_traffic: ['No events during the window', 'The source sent nothing while the tap ran. Retry after it starts sending events.'],
  cancelled: ['Tap cancelled', 'No events were kept.'],
  busy: ['Live tap is busy', 'Another tap is running.'],
  unavailable: ['Live tap unavailable', 'Load recent events or paste a sample instead.'],
  forbidden: ['Source-event permission required', 'Live tap reads raw events and requires search:execute on this source.'],
  failed: ['Tap failed', 'The tap did not complete.'],
};
const ENDED: Record<string, string> = {
  deadline: 'window closed',
  max_events: 'event limit reached',
  max_bytes: 'byte limit reached',
  stream_closed: 'stream closed early',
};

function inputSummary(input: unknown): string {
  const raw = input && typeof input === 'object' && 'message' in input && typeof input.message === 'string' ? input.message : JSON.stringify(input) ?? '';
  return raw.split('\n', 1)[0];
}

/** Seconds left in a running capture, ticking once a second. */
function useCountdown(tap: PipelineTap): number | null {
  const [now, setNow] = useState(() => Date.now());
  const running = tap.state === 'capturing' && !!tap.startedAt && !!tap.seconds;
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(timer);
  }, [running]);
  if (!running) return null;
  return Math.max(0, tap.seconds! - Math.floor((now - tap.startedAt!) / 1000));
}

export function PipelineTapPanel({
  sourceName,
  tap,
  capabilities,
  canTap,
  onStart,
  onCancel,
  onPreview,
}: {
  sourceName: string;
  tap: PipelineTap;
  capabilities: PipelineCapabilities;
  canTap: boolean;
  onStart: (options: PipelineTapOptions) => void;
  onCancel: () => void;
  onPreview: () => void;
}) {
  const [seconds, setSeconds] = useState(String(TAP_DEFAULT_SECONDS));
  const [limit, setLimit] = useState(String(TAP_DEFAULT_EVENTS));
  const [selected, setSelected] = useState(0);
  const remaining = useCountdown(tap);
  const state: PipelineTap['state'] = !canTap ? 'forbidden' : !capabilities.tap.available && tap.state === 'ready' ? 'unavailable' : tap.state;
  const running = state === 'capturing';
  const valid = Number.isInteger(Number(seconds)) && Number(seconds) >= 1 && Number(seconds) <= capabilities.tap.maxSeconds
    && Number.isInteger(Number(limit)) && Number(limit) >= 1 && Number(limit) <= capabilities.tap.maxEvents;
  const [title, fallback] = TAP_MESSAGES[state];
  const explanation = state === 'unavailable' ? (capabilities.tap.reason ?? tap.reason ?? fallback) : (tap.reason ?? fallback);
  const events = canTap ? tap.events : [];
  const progress = running && tap.seconds ? ((tap.seconds - (remaining ?? tap.seconds)) / tap.seconds) * 100 : 0;
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 space-y-2 border-b border-border p-3">
        <div className="flex flex-wrap items-center gap-2 text-[11.5px]">
          <span className="font-medium">{sourceName}</span>
          <span className="font-mono text-[10px] text-muted-foreground">
            {tap.component ? `tapped ${tap.component}` : 'pre-parse input · redacted · not stored'}
          </span>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <div className="w-28">
            <PipelineField label={`Window (1–${capabilities.tap.maxSeconds} s)`}>
              <Input type="number" min={1} max={capabilities.tap.maxSeconds} className="h-7 font-mono text-[11.5px]" value={seconds} disabled={running} onChange={(event) => setSeconds(event.target.value)} />
            </PipelineField>
          </div>
          <div className="w-32">
            <PipelineField label={`Events (1–${capabilities.tap.maxEvents})`}>
              <Input type="number" min={1} max={capabilities.tap.maxEvents} className="h-7 font-mono text-[11.5px]" value={limit} disabled={running} onChange={(event) => setLimit(event.target.value)} />
            </PipelineField>
          </div>
          {running ? (
            <Button variant="outline" className="h-7 text-[11.5px]" onClick={onCancel}>
              <Square className="h-3 w-3" strokeWidth={1.5} />
              Cancel
            </Button>
          ) : (
            <Button className="h-7 text-[11.5px]" disabled={!canTap || !capabilities.tap.available || !valid} onClick={() => onStart({ seconds: Number(seconds), maxEvents: Number(limit) })}>
              <Radio className="h-3.5 w-3.5" strokeWidth={1.5} />
              {tap.state === 'ready' ? 'Start live tap' : 'Tap again'}
            </Button>
          )}
          {state === 'completed' && (
            <Button variant="outline" className="h-7 text-[11.5px]" onClick={onPreview}>
              <Eye className="h-3.5 w-3.5" strokeWidth={1.5} />
              Preview these events
            </Button>
          )}
        </div>
        {running && (
          <div className="space-y-1" role="status" aria-live="polite">
            <div className="h-1 w-full overflow-hidden rounded-sm bg-muted" aria-hidden="true">
              <div className="h-full bg-primary transition-[width] duration-200" style={{ width: `${progress}%` }} />
            </div>
            <p className="font-mono text-[10.5px] text-muted-foreground">
              Capturing · <span data-testid="tap-remaining">{remaining ?? tap.seconds}</span>s left of {tap.seconds}s
            </p>
          </div>
        )}
        {!running && (
          <PipelineNotice title={title} tone={state === 'failed' ? 'error' : state === 'busy' || state === 'unavailable' ? 'warning' : 'neutral'}>
            {explanation}
          </PipelineNotice>
        )}
        {state === 'completed' && (
          <div className="flex flex-wrap gap-3 font-mono text-[10.5px] text-muted-foreground">
            <span>{events.length} events</span>
            {tap.ended && <span>{ENDED[tap.ended] ?? tap.ended}</span>}
            {!!tap.droppedOversize && <span className="text-warning">{tap.droppedOversize} skipped (over 64 KiB)</span>}
          </div>
        )}
      </div>
      {events.length > 0 && (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="max-h-[180px] shrink-0 overflow-auto border-b border-border" role="listbox" aria-label="Tapped events">
            {events.map((event, index) => (
              <button
                key={event.id}
                type="button"
                role="option"
                aria-selected={index === selected}
                onClick={() => setSelected(index)}
                className={cn('flex h-6 w-full items-center gap-2 border-b border-border px-3 text-left font-mono text-[10.5px]', index === selected ? 'bg-primary/10' : 'hover:bg-accent')}
              >
                <span className="w-6 shrink-0 text-muted-foreground">{index + 1}</span>
                <span className="min-w-0 flex-1 truncate">{inputSummary(event.input)}</span>
                {event.nanoInput && <span className="shrink-0 text-[10px] text-muted-foreground">{event.nanoInput}</span>}
              </button>
            ))}
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
            <JsonInspector value={events[Math.min(selected, events.length - 1)]?.input} />
          </div>
        </div>
      )}
    </div>
  );
}
