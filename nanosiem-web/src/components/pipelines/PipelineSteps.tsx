// SPDX-License-Identifier: AGPL-3.0-or-later

import { useId, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  ChevronRight,
  ChevronsDownUp,
  ChevronsUpDown,
  Copy,
  PanelLeftClose,
  Plus,
  Trash2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { safeRandomUUID } from '@/lib/uuid';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { VrlEditor } from '@/components/editor/VrlEditor';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';
import type { PipelineLaneInput, PipelineStep, PipelineStepKind } from '@/lib/pipeline-types';
import { compileStep, type PipelineStepStatus } from '@/lib/pipeline-model';
import { PipelineField, PipelineNotice } from './PipelineCommon';
import { STEP_LABELS, newPipelineStep } from './pipeline-catalog';
import { RouteBranches } from './RouteBranches';
import { Checkbox } from '@/components/ui/checkbox';

/** Auto: only the selected step is open. Explicit toggles override until the selection changes. */
type CollapseMode = 'auto' | 'all' | 'none';

export function PipelineStepList({
  steps,
  selectedId,
  supportedSteps,
  readOnly,
  status = {},
  onSelect,
  onChange,
  onConfigure,
  onCollapsePanel,
}: {
  steps: PipelineStep[];
  selectedId: string | null;
  supportedSteps: PipelineStepKind[];
  readOnly: boolean;
  status?: Record<string, PipelineStepStatus>;
  onSelect: (id: string) => void;
  onChange: (steps: PipelineStep[]) => void;
  onConfigure: () => void;
  /** Collapse the whole step column to a rail. */
  onCollapsePanel?: () => void;
}) {
  const [dragId, setDragId] = useState<string | null>(null);
  const [mode, setMode] = useState<CollapseMode>('auto');
  const [overrides, setOverrides] = useState<Record<string, boolean>>({});
  // Selecting (or adding) a step re-arms auto-collapse: it opens, the rest fold.
  const [lastSelected, setLastSelected] = useState(selectedId);
  if (lastSelected !== selectedId) {
    setLastSelected(selectedId);
    setMode('auto');
    setOverrides({});
  }
  const isOpen = (id: string) =>
    overrides[id] ??
    (mode === 'all' ? true : mode === 'none' ? false : id === selectedId);
  const toggle = (id: string) =>
    setOverrides((current) => ({ ...current, [id]: !isOpen(id) }));
  const setAll = (next: CollapseMode) => {
    setMode(next);
    setOverrides({});
  };
  const allOpen = steps.length > 0 && steps.every((step) => isOpen(step.id));
  const move = (id: string, offset: number) => {
    const from = steps.findIndex((step) => step.id === id),
      to = from + offset;
    if (readOnly || from < 0 || to < 0 || to >= steps.length) return;
    const next = [...steps];
    [next[from], next[to]] = [next[to], next[from]];
    onChange(next);
  };
  const duplicate = (step: PipelineStep) => {
    if (readOnly) return;
    const duplicateStep = {
      ...structuredClone(step),
      id: safeRandomUUID(),
      name: `${step.name} copy`,
    };
    const next = [...steps];
    next.splice(steps.indexOf(step) + 1, 0, duplicateStep);
    onChange(next);
    onSelect(duplicateStep.id);
  };
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-9 shrink-0 items-center gap-1 border-b border-border pl-3 pr-1.5 text-[11.5px] font-medium">
        <span className="min-w-0 truncate">Processing steps</span>
        <span className="font-mono text-[10.5px] text-muted-foreground">
          {steps.length}
        </span>
        <span className="ml-auto" />
        {steps.length > 0 && (
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-muted-foreground"
            aria-label={allOpen ? 'Collapse all steps' : 'Expand all steps'}
            title={allOpen ? 'Collapse all steps' : 'Expand all steps'}
            onClick={() => setAll(allOpen ? 'none' : 'all')}
          >
            {allOpen ? (
              <ChevronsDownUp className="h-3.5 w-3.5" strokeWidth={1.5} />
            ) : (
              <ChevronsUpDown className="h-3.5 w-3.5" strokeWidth={1.5} />
            )}
          </Button>
        )}
        {onCollapsePanel && (
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-muted-foreground"
            aria-label="Collapse step list"
            title="Collapse step list"
            onClick={onCollapsePanel}
          >
            <PanelLeftClose className="h-3.5 w-3.5" strokeWidth={1.5} />
          </Button>
        )}
      </div>
      <div
        role="listbox"
        aria-label="Processing steps"
        className="min-h-0 flex-1 overflow-y-auto py-1"
      >
        {steps.length === 0 && (
          <p className="p-3 text-[11.5px] text-muted-foreground">
            No processing steps — events pass through unchanged.
          </p>
        )}
        {steps.map((step, index) => {
          const open = isOpen(step.id);
          const result = status[step.id];
          return (
            <div
              key={step.id}
              data-collapsed={open ? undefined : ''}
              role="option"
              aria-selected={selectedId === step.id}
              tabIndex={
                selectedId === step.id || (!selectedId && index === 0) ? 0 : -1
              }
              draggable={!readOnly}
              onDragStart={(event) => {
                setDragId(step.id);
                event.dataTransfer.effectAllowed = 'move';
              }}
              onDragEnd={() => setDragId(null)}
              onDragOver={(event) => {
                if (!readOnly) event.preventDefault();
              }}
              onDrop={(event) => {
                event.preventDefault();
                if (readOnly || !dragId || dragId === step.id) return;
                const moved = steps.find((item) => item.id === dragId);
                if (!moved) return;
                const next = steps.filter((item) => item.id !== dragId);
                next.splice(
                  next.findIndex((item) => item.id === step.id),
                  0,
                  moved
                );
                onChange(next);
                setDragId(null);
              }}
              onClick={() => onSelect(step.id)}
              onKeyDown={(event) => {
                if ((event.target as HTMLElement) !== event.currentTarget)
                  return;
                if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
                  event.preventDefault();
                  const direction = event.key === 'ArrowUp' ? -1 : 1;
                  if (event.altKey) move(step.id, direction);
                  else {
                    const next = steps[index + direction];
                    if (next) {
                      onSelect(next.id);
                      document
                        .getElementById(`pipeline-step-${next.id}`)
                        ?.focus();
                    }
                  }
                }
                if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
                  event.preventDefault();
                  if (open !== (event.key === 'ArrowRight')) toggle(step.id);
                }
                if (event.key === 'Enter') {
                  event.preventDefault();
                  onSelect(step.id);
                  onConfigure();
                }
                if (event.key === ' ' && !readOnly) {
                  event.preventDefault();
                  onChange(
                    steps.map((item) =>
                      item.id === step.id
                        ? { ...item, enabled: !item.enabled }
                        : item
                    )
                  );
                }
                if (event.key === 'Delete' && !readOnly)
                  onChange(steps.filter((item) => item.id !== step.id));
                if (
                  (event.ctrlKey || event.metaKey) &&
                  event.key === 'd' &&
                  !readOnly
                ) {
                  event.preventDefault();
                  duplicate(step);
                }
              }}
              id={`pipeline-step-${step.id}`}
              className={cn(
                'group border-l-2 pl-1 pr-2.5 outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-ring',
                open ? 'py-1.5' : 'py-0.5',
                selectedId === step.id
                  ? 'border-primary bg-primary/5'
                  : 'border-transparent hover:bg-accent/60',
                !step.enabled && 'opacity-60'
              )}
            >
              <div className="flex h-6 items-center gap-1">
                <button
                  type="button"
                  tabIndex={-1}
                  aria-expanded={open}
                  aria-label={`${open ? 'Collapse' : 'Expand'} ${step.name}`}
                  className="flex h-5 w-4 shrink-0 items-center justify-center text-muted-foreground hover:text-foreground"
                  onClick={(event) => {
                    event.stopPropagation();
                    toggle(step.id);
                  }}
                >
                  <ChevronRight
                    className={cn(
                      'h-3 w-3 transition-transform',
                      open && 'rotate-90'
                    )}
                    strokeWidth={1.5}
                  />
                </button>
                <span className="w-4 shrink-0 font-mono text-[10px] text-muted-foreground">
                  {index + 1}
                </span>
                <span className="min-w-0 flex-1 truncate text-[12px] font-medium">
                  {step.name}
                </span>
                {!open && (
                  <span className="shrink-0 font-mono text-[10px] text-muted-foreground">
                    {STEP_LABELS[step.kind]}
                  </span>
                )}
                {!open && <StepStatusBadge status={result} />}
                <Checkbox
                  aria-label={`Enable ${step.name}`}
                  checked={step.enabled}
                  disabled={readOnly}
                  onClick={(event) => event.stopPropagation()}
                  onCheckedChange={(checked) =>
                    onChange(
                      steps.map((item) =>
                        item.id === step.id
                          ? { ...item, enabled: checked === true }
                          : item
                      )
                    )
                  }
                  className="h-3.5 w-3.5"
                />
              </div>
              {open && (
                <>
                  <div className="mt-0.5 flex items-center gap-1 pl-9 font-mono text-[10px] text-muted-foreground">
                    <span>{STEP_LABELS[step.kind]}</span>
                    {result && (result.errors > 0 || result.changed > 0) && (
                      <span
                        className={cn(result.errors > 0 && 'text-destructive')}
                      >
                        ·{' '}
                        {result.errors > 0
                          ? `${result.errors} error${result.errors === 1 ? '' : 's'}`
                          : `${result.changed} changed`}
                      </span>
                    )}
                    {step.condition && (
                      <span title={step.condition}>· conditional</span>
                    )}
                    {!supportedSteps.includes(step.kind) && (
                      <span className="text-warning">· unavailable</span>
                    )}
                  </div>
                  {!readOnly && (
                    <div
                      className="mt-1 flex justify-end gap-0.5"
                      onClick={(event) => event.stopPropagation()}
                    >
                      {[
                        {
                          Icon: ArrowUp,
                          label: 'Move up',
                          disabled: index === 0,
                          action: () => move(step.id, -1),
                        },
                        {
                          Icon: ArrowDown,
                          label: 'Move down',
                          disabled: index === steps.length - 1,
                          action: () => move(step.id, 1),
                        },
                        {
                          Icon: Copy,
                          label: 'Duplicate',
                          action: () => duplicate(step),
                        },
                        {
                          Icon: Trash2,
                          label: 'Delete',
                          action: () =>
                            onChange(
                              steps.filter((item) => item.id !== step.id)
                            ),
                        },
                      ].map(({ Icon, label, disabled, action }) => (
                        <Button
                          key={label}
                          variant="ghost"
                          size="icon"
                          className="h-5 w-5"
                          disabled={disabled}
                          aria-label={`${label} ${step.name}`}
                          onClick={action}
                        >
                          <Icon className="h-3 w-3" strokeWidth={1.5} />
                        </Button>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          );
        })}
      </div>
      <div className="shrink-0 border-t border-border p-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="h-7 w-full text-[11.5px]"
              disabled={readOnly}
            >
              <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
              Add step
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-56">
            {(Object.entries(STEP_LABELS) as [PipelineStepKind, string][]).map(
              ([kind, label]) => (
                <DropdownMenuItem
                  key={kind}
                  disabled={!supportedSteps.includes(kind)}
                  className="text-[11.5px]"
                  onSelect={() => {
                    const step = newPipelineStep(kind);
                    onChange([...steps, step]);
                    onSelect(step.id);
                    onConfigure();
                  }}
                >
                  {label}
                  {!supportedSteps.includes(kind) && (
                    <span className="ml-auto text-[10px] text-muted-foreground">
                      unavailable
                    </span>
                  )}
                </DropdownMenuItem>
              )
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  );
}

function StepStatusBadge({ status }: { status?: PipelineStepStatus }) {
  if (!status) return null;
  if (status.errors > 0)
    return (
      <span
        className="shrink-0 font-mono text-[10px] text-destructive"
        title={`${status.errors} preview input${status.errors === 1 ? '' : 's'} failed at this step`}
      >
        {status.errors} err
      </span>
    );
  if (status.changed > 0)
    return (
      <span
        className="shrink-0 font-mono text-[10px] text-muted-foreground"
        title={`Changed ${status.changed} preview event${status.changed === 1 ? '' : 's'}`}
      >
        Δ{status.changed}
      </span>
    );
  return null;
}

export function PipelineStepSettings({
  step,
  readOnly,
  supported,
  onChange,
  laneInputs = [],
  mixedInputs = false,
}: {
  step: PipelineStep | undefined;
  readOnly: boolean;
  supported: boolean;
  onChange: (step: PipelineStep) => void;
  /** NAN-3625: the lane's inputs, for "Input is" route branches. */
  laneInputs?: PipelineLaneInput[];
  /** NAN-3621: the lane has push (or connector) and pull inputs, so it runs in more than one Vector process. */
  mixedInputs?: boolean;
}) {
  const id = useId();
  if (!step)
    return (
      <p className="p-3 text-[11.5px] text-muted-foreground">
        Select a step to configure it.
      </p>
    );
  const config = step.config;
  let generated = '';
  try { if (supported) generated = compileStep(step); } catch (error) { generated = error instanceof Error ? error.message : String(error); }
  const set = (key: string, value: unknown) =>
    onChange({ ...step, config: { ...config, [key]: value } });
  const text = (key: string, label: string, placeholder?: string) => (
    <PipelineField label={label}>
      <Input
        className="h-7 font-mono text-[11.5px]"
        disabled={readOnly || !supported}
        value={String(config[key] ?? '')}
        placeholder={placeholder}
        onChange={(event) => set(key, event.target.value)}
      />
    </PipelineField>
  );
  const number = (key: string, label: string, min = 1, max?: number) => (
    <PipelineField label={label}>
      <Input
        type="number"
        min={min}
        max={max}
        className="h-7 font-mono text-[11.5px]"
        disabled={readOnly || !supported}
        value={typeof config[key] === 'number' ? max !== undefined && ((step.kind === 'combine' && key === 'timeoutSec') || (step.kind === 'dedupe' && key === 'cacheEvents')) ? Math.min(config[key], max) : config[key] : ''}
        onChange={(event) =>
          set(key, event.target.value === '' ? '' : Number(event.target.value))
        }
      />
    </PipelineField>
  );
  const select = (key: string, label: string, options: [string, string][]) => (
    <PipelineField label={label}>
      <select
        className="h-7 w-full rounded-md border border-border bg-input px-2 text-[12px] text-foreground"
        disabled={readOnly || !supported}
        value={String(config[key] ?? options[0][0])}
        onChange={(event) => set(key, event.target.value)}
      >
        {options.map(([value, name]) => (
          <option key={value} value={value}>
            {name}
          </option>
        ))}
      </select>
    </PipelineField>
  );
  const fields = (key: string, label: string) => (
    <PipelineField label={label} hint="Comma-separated field paths">
      <Input
        className="h-7 font-mono text-[11.5px]"
        disabled={readOnly || !supported}
        value={
          Array.isArray(config[key])
            ? (config[key] as unknown[]).join(', ')
            : ''
        }
        onChange={(event) =>
          set(
            key,
            event.target.value
              .split(',')
              .map((value) => value.trim())
              .filter(Boolean)
          )
        }
      />
    </PipelineField>
  );
  const json = (key: string, label: string) => (
    <JsonConfigField
      key={`${step.id}-${key}`}
      label={label}
      value={config[key]}
      disabled={readOnly || !supported}
      onChange={(value) => set(key, value)}
    />
  );
  return (
    <div className="flex min-h-0 flex-col gap-3 p-3 text-[12px]">
      <div className="font-mono text-[10.5px] text-muted-foreground">
        {STEP_LABELS[step.kind]}
      </div>
      {!supported && (
        <PipelineNotice title="Unavailable in this runtime" tone="warning">
          This step can be inspected, but cannot be released until the tenant
          runtime supports it.
        </PipelineNotice>
      )}
      {readOnly && (
        <PipelineNotice title="Read-only configuration">
          Editing requires pipeline edit permission.
        </PipelineNotice>
      )}
      <PipelineField label="Step name">
        <Input
          id={`${id}-name`}
          className="h-8 text-[12px] font-medium"
          disabled={readOnly}
          value={step.name}
          onChange={(event) => onChange({ ...step, name: event.target.value })}
        />
      </PipelineField>
      <PipelineField
        label="Execution condition"
        hint="Leave blank to run on every event."
      >
        <Input
          className="h-7 font-mono text-[11.5px]"
          disabled={readOnly || !supported}
          value={step.condition ?? ''}
          onChange={(event) =>
            onChange({ ...step, condition: event.target.value })
          }
          placeholder={'.event.action == "deny"'}
        />
      </PipelineField>
      <div className="border-t border-border" />
      {mixedInputs && (step.kind === 'dedupe' || step.kind === 'combine') && (
        <PipelineNotice title="Push and pull inputs keep separate state" tone="warning">
          This lane has both push and cloud pull inputs. Pull events run these steps in the pull container&apos;s own Vector process, so {step.kind === 'dedupe' ? 'a duplicate that arrives once by push and once by pull is not removed' : 'events from push and pull inputs are never combined into the same group'}.
        </PipelineNotice>
      )}
      {step.kind === 'parse' && (
        <>
          {select('format', 'Format', [['json', 'JSON']])}
          {text('field', 'Input field', 'message')}
          <p className="text-[10.5px] text-muted-foreground">
            JSON fields merge into the event. Validate to see the exact compiled
            VRL.
          </p>
        </>
      )}
      {step.kind === 'fields' && (
        <>
          {select('operation', 'Operation', [
            ['rename', 'Rename'],
            ['remove', 'Remove'],
            ['set', 'Static value'],
            ['batch', 'Multiple operations'],
          ])}
          {text('field', 'Field path')}
          {config.operation === 'rename' && text('target', 'Target field')}
          {config.operation === 'set' && json('value', 'JSON value')}
          {config.operation === 'batch' && json('operations', 'Field operations')}
        </>
      )}
      {step.kind === 'rename' && (
        <>
          {text('field', 'Field path')}
          {text('target', 'Target field')}
        </>
      )}
      {step.kind === 'remove' && text('field', 'Field path')}
      {step.kind === 'set' && (
        <>
          {text('field', 'Field path')}
          {json('value', 'JSON value')}
        </>
      )}
      {step.kind === 'redact' && (
        <>
          {fields('fields', 'Fields')}
          {text('replacement', 'Replacement')}
        </>
      )}
      {step.kind === 'mask' && (
        <>
          {fields('fields', 'Fields')}
          {select('operation', 'Operation', [
            ['replace', 'Redact'],
            ['hash', 'Hash'],
            ['partial', 'Partial mask'],
          ])}
          {config.operation === 'hash' && select('algorithm', 'Hash algorithm', [['sha256', 'SHA-256'], ['md5', 'MD5']])}
          {config.operation === 'partial' && <>
            {number('keepStart', 'Visible leading characters', 0, 64)}
            {number('keepEnd', 'Visible trailing characters', 0, 64)}
          </>}
          {config.operation !== 'hash' && text('replacement', 'Replacement')}
        </>
      )}
      {step.kind === 'split' && (
        <>
          {text('field', 'Array field')}
          {text('as', 'Output field')}
          {fields('keep', 'Retained context fields')}
          {number('max', 'Maximum outputs per input', 1, 1000)}
          <PipelineNotice title="One input can produce several outputs">
            Every output retains its input lineage in sample preview. Exceeding the limit reports a processing error; items are not silently truncated.
          </PipelineNotice>
        </>
      )}
      {step.kind === 'combine' && (
        <>
          {fields('keys', 'Group keys')}
          {text('countField', 'Count field')}
          {json('merge', 'Merge rules')}
          <p className="text-[10.5px] text-muted-foreground">At most 64 tracked group keys. Overflow flushes the oldest key; idle expiry is capped at five seconds, including larger saved limits.</p>
          {number('maxEvents', 'Maximum events per group')}
          {number('timeoutSec', 'Flush timeout (seconds)', 1, 5)}
          <PipelineNotice title="Stateful preview">
            Preview starts with empty state and flushes partial groups at the end of the sample. Production flushes at the event limit or idle timeout, per Vector instance. Push and cloud pull inputs are grouped separately.
          </PipelineNotice>
        </>
      )}
      {step.kind === 'filter' && (
        <>
          {text('predicate', 'Predicate')}
          {select('action', 'Matching events', [
            ['drop', 'Drop'],
            ['keep', 'Keep only'],
          ])}
        </>
      )}
      {step.kind === 'sample' && (
        <>
          {number('ratio', 'Keep 1 in every N events', 1, 1000000)}
          {text('groupBy', 'Consistent sampling key')}
          {text('exempt', 'Always keep condition (optional)')}
          <PipelineNotice
            title={`Keep 1 in ${config.ratio ?? 10} matching events`}
          >
            The selected key is hashed deterministically; equal keys share a decision. This changes production event delivery. Capture limits only bound
            the sample you inspect.
          </PipelineNotice>
        </>
      )}
      {step.kind === 'lookup' && (
        <>
          {text('table', 'Lookup name')}
          {text('version', 'Lookup version')}
          {json('rows', 'Lookup snapshot rows')}
          <p className="text-[10.5px] text-muted-foreground">String-valued rows are saved with the pipeline and pinned to its release.</p>
          {json('match', 'Match fields')}
          {json('outputs', 'Output mappings')}
          {select('missing', 'Missing match', [
            ['leave', 'Leave unchanged'],
            ['error', 'Report error'],
          ])}
        </>
      )}
      {step.kind === 'dedupe' && (
        <>
          {fields('fields', 'Comparison fields')}
          {number('cacheEvents', 'Maximum cached events', 1, 5000)}
          <p className="text-[10.5px] text-muted-foreground">LRU cache of SHA-256 signatures, capped at 5,000 entries per Vector instance. Larger saved limits are capped when compiled. State clears on restart. Push and cloud pull inputs run in separate Vector processes and dedupe separately.</p>
          {'ttlSec' in config && <Button disabled={readOnly} className="h-7 text-[11px]" onClick={() => { const native = { ...config }; delete native.ttlSec; onChange({ ...step, config: native }); }}>Use native LRU cache and remove prototype TTL</Button>}
        </>
      )}
      {step.kind === 'route' && (
        <>
          {select('mode', 'Matching behavior', [
            ['first', 'First match'],
            ['fanout', 'Fan out to all matches'],
          ])}
          <RouteBranches routes={config.routes} inputs={laneInputs} disabled={readOnly || !supported} onChange={(routes) => set('routes', routes)} />
          {text('field', 'Branch label field')}
          {select('fallback', 'Unmatched events', [['keep', 'Keep'], ['drop', 'Drop']])}
          <p className="text-[10.5px] text-muted-foreground">
            Each kept branch is tagged and continues to Nano Lake. Fan-out produces one copy per kept matching branch; external destinations are unavailable.
            &ldquo;Input is&rdquo; matches the input the platform recorded at ingress, not fields in the event, and must come before any Combine step.
          </p>
        </>
      )}
      {step.kind !== 'vrl' && supported && (
        <PipelineField label={['dedupe', 'combine', 'route', 'lookup'].includes(step.kind) ? 'Generated Vector configuration' : 'Generated VRL'}>
          <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all border border-border p-2 font-mono text-[10.5px]">{generated}</pre>
        </PipelineField>
      )}
      {step.kind === 'vrl' && (
        <PipelineField
          label="Vector Remap Language"
          hint="Compiled and tested by the tenant runtime."
        >
          <VrlEditor
            className={cn(
              'h-60 rounded-md border border-border',
              (readOnly || !supported) && 'opacity-80'
            )}
            ariaLabel="Vector Remap Language"
            readOnly={readOnly || !supported}
            value={String(config.code ?? '')}
            onChange={(code) => set('code', code)}
          />
        </PipelineField>
      )}
    </div>
  );
}

function JsonConfigField({
  label,
  value,
  disabled,
  onChange,
}: {
  label: string;
  value: unknown;
  disabled: boolean;
  onChange: (value: unknown) => void;
}) {
  const [text, setText] = useState(JSON.stringify(value ?? [], null, 2));
  const [error, setError] = useState<string | null>(null);
  return (
    <PipelineField label={label} hint="JSON configuration">
      <Textarea
        value={text}
        disabled={disabled}
        className="min-h-24 font-mono text-[11px]"
        onChange={(event) => {
          setText(event.target.value);
          try {
            const parsed: unknown = JSON.parse(event.target.value);
            onChange(parsed);
            setError(null);
          } catch {
            setError('Enter valid JSON before leaving this field.');
          }
        }}
        aria-invalid={!!error}
      />
      {error && (
        <span
          role="alert"
          className="mt-1 block text-[10.5px] text-destructive"
        >
          {error}
        </span>
      )}
    </PipelineField>
  );
}
