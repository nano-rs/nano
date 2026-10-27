// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useRef, useState } from 'react';
import {
  Check,
  Clock,
  PanelLeftOpen,
  Save,
  Settings2,
  Upload,
} from 'lucide-react';
import { PivtIcon } from '@/components/icons/PivtIcon';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { DetailSheet } from '@/components/ui/detail-sheet';
import { PipelineNotice, PipelinePageHeader } from './PipelineCommon';
import { PipelineStepList, PipelineStepSettings } from './PipelineSteps';
import { PipelineCapturePanel } from './PipelineCapture';
import { PipelinePreviewPanel } from './PipelinePreview';
import { PipelineInputsPanel } from './PipelineInputs';
import { pipeInputCount } from '@/lib/api/pipelines';
import type { PipelineEditorProps } from './types';
import type {
  PipelineConflict,
  PipelineDraft,
  PipelineOperation,
} from '@/lib/pipeline-types';
import { compilePipeline, serializePipeline, stepPreviewStatus } from '@/lib/pipeline-model';
import { cn } from '@/lib/utils';

/** Editor-surface operations; publish and rollback report in their own sheets. */
const EDITOR_ERROR_TITLES: Partial<Record<PipelineOperation, string>> = {
  save: 'Draft could not be saved',
  validate: 'Validation could not run',
  review: 'Release review blocked',
  capture: 'Capture request failed',
  stop: 'Capture could not be stopped',
  sample: 'Sample could not be saved',
  reload: 'Latest draft could not be loaded',
  discard: 'Draft could not be discarded',
};

function localVrl(draft: PipelineDraft): string {
  try {
    return draft.steps.some(step => step.enabled && ['dedupe', 'combine', 'route', 'lookup'].includes(step.kind)) ? serializePipeline(draft) : compilePipeline(draft);
  } catch {
    // An unfinished step cannot compile yet; keep the step configuration.
    return JSON.stringify(draft.steps, null, 2);
  }
}

function PipelineConflictNotice({
  conflict,
  draft,
  dirty,
  canEdit,
  busy,
  detail,
  onReloadLatest,
  onKeepLocalEdits,
  onDiscardDraft,
}: {
  conflict: PipelineConflict;
  draft: PipelineDraft;
  dirty: boolean;
  canEdit: boolean;
  busy: boolean;
  detail?: string;
  onReloadLatest?: () => void;
  onKeepLocalEdits?: () => void;
  onDiscardDraft?: () => void;
}) {
  const [confirm, setConfirm] = useState<'reload' | 'discard' | null>(null);
  const [copied, setCopied] = useState<'copied' | 'failed' | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(localVrl(draft));
      setCopied('copied');
    } catch {
      setCopied('failed');
    }
  };
  return (
    <PipelineNotice title="This pipeline changed on the server" tone="warning">
      <p>{conflict.message}</p>
      {detail && (
        <p className="font-mono text-[10.5px] text-muted-foreground">
          {detail}
        </p>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Button
          variant="outline"
          className="h-6 px-2 text-[11px]"
          disabled={busy || !onReloadLatest}
          onClick={() => (dirty ? setConfirm('reload') : onReloadLatest?.())}
        >
          {busy ? 'Working…' : 'Reload latest'}
        </Button>
        {dirty && canEdit && onKeepLocalEdits && (
          <Button
            variant="ghost"
            className="h-6 px-2 text-[11px]"
            disabled={busy}
            onClick={onKeepLocalEdits}
            title="Move your edits onto the latest saved draft; the next Save replaces it."
          >
            Keep my edits
          </Button>
        )}
        {dirty && (
          <Button
            variant="ghost"
            className="h-6 px-2 text-[11px]"
            onClick={() => void copy()}
          >
            {copied === 'copied'
              ? 'Copied'
              : copied === 'failed'
                ? 'Copy failed'
                : draft.steps.some(step => step.enabled && ['dedupe', 'combine', 'route', 'lookup'].includes(step.kind)) ? 'Copy my processing plan' : 'Copy my VRL'}
          </Button>
        )}
        {canEdit && onDiscardDraft && (
          <Button
            variant="ghost"
            className="h-6 px-2 text-[11px] text-destructive"
            disabled={busy}
            onClick={() => setConfirm('discard')}
          >
            Discard my draft
          </Button>
        )}
      </div>
      <ConfirmDialog
        open={confirm === 'reload'}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Discard your unsaved edits?"
        description="Reload latest replaces this editor with the draft currently saved on the server. Copy your VRL first if you want to keep it."
        confirmLabel="Discard and reload"
        variant="warning"
        onConfirm={() => {
          setConfirm(null);
          onReloadLatest?.();
        }}
      />
      <ConfirmDialog
        open={confirm === 'discard'}
        onOpenChange={(open) => !open && setConfirm(null)}
        title="Discard the saved draft?"
        description="This resets the pipeline to the active published version. Saved changes that have not been published, including any made by other editors, and your unsaved edits are discarded. Production is not changed."
        confirmLabel="Discard draft"
        variant="danger"
        onConfirm={() => {
          setConfirm(null);
          onDiscardDraft?.();
        }}
      />
    </PipelineNotice>
  );
}

/** NAN-3452: panel widths survive reloads; storage can be absent or throw. */
const STEPS_WIDTH_KEY = 'nano.pipe.editor.stepsWidth';
const SETTINGS_WIDTH_KEY = 'nano.pipe.editor.settingsWidth';
const STEPS_COLLAPSED_KEY = 'nano.pipe.editor.stepsCollapsed';
const STEPS_MIN = 180;
const STEPS_MAX = 360;
const SETTINGS_MIN = 300;
/** The preview keeps at least this much room; the settings panel gets the rest. */
const PREVIEW_MIN = 360;
const RAIL_WIDTH = 32;

function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStored(key: string, value: string) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Private mode or blocked storage: the width just resets next visit.
  }
}

function storedWidth(key: string, fallback: number, min: number): number {
  const value = Number(readStored(key));
  return Number.isFinite(value) && value >= min ? value : fallback;
}

function PanelResizer({
  value,
  onChange,
  min,
  max,
  label,
}: {
  value: number;
  onChange: (value: number) => void;
  min: number;
  max: number;
  label: string;
}) {
  const drag = useRef<{ x: number; value: number } | null>(null);
  const clamp = (next: number) => Math.max(min, Math.min(max, next));
  return (
    <div
      role="separator"
      aria-label={label}
      aria-orientation="vertical"
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={value}
      tabIndex={0}
      className="z-10 -mx-0.5 w-1 shrink-0 cursor-col-resize touch-none hover:bg-primary/40 focus-visible:bg-primary/50 focus-visible:outline-none"
      onPointerDown={(event) => {
        drag.current = { x: event.clientX, value };
        event.currentTarget.setPointerCapture(event.pointerId);
      }}
      onPointerMove={(event) => {
        if (drag.current)
          onChange(clamp(drag.current.value + event.clientX - drag.current.x));
      }}
      onPointerUp={() => {
        drag.current = null;
      }}
      onPointerCancel={() => {
        drag.current = null;
      }}
      onKeyDown={(event) => {
        if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
          event.preventDefault();
          onChange(
            clamp(
              value +
                (event.key === 'ArrowLeft' ? -1 : 1) *
                  (event.shiftKey ? 40 : 10)
            )
          );
        }
      }}
    />
  );
}

export function PipelineEditor(props: PipelineEditorProps) {
  const {
    pipeline,
    draft,
    capabilities,
    permissions,
    dirty,
    busy,
    errors = {},
    conflict = null,
    capabilitiesError,
    previewError,
    validation,
    capture,
    samples,
    sample,
    preview,
    previewPending,
    onDraftChange,
    onSave,
    onValidate,
    onReview,
    onHistory,
    onCaptureStart,
    onCaptureStop,
    onFreeze,
    onSampleSelect,
    onPreview,
    onSaveSample,
    canSaveSample,
    onLoadRecent,
    onPasteSample,
    sampleNotice,
    inputs,
    onAssistant,
    onSelectedStepChange,
    onReloadLatest,
    onKeepLocalEdits,
    onDiscardDraft,
    onRetryCapabilities,
    laneInputs = [],
    routedInputs = [],
    previewInput = null,
    onPreviewInputChange,
  } = props;
  const [selectedId, setSelectedId] = useState<string | null>(
    draft.steps[0]?.id ?? null
  );
  // Without a capture runner the preview tab (load recent / paste) is the way
  // in. Decided once, when capabilities first resolve, so it never flips later.
  const [mode, setMode] = useState<'capture' | 'preview'>('capture');
  const modeDecided = useRef(false);
  const captureAvailable = capabilities.capture.available;
  const runtimeResolved = capabilities.runtime !== 'loading';
  useEffect(() => {
    if (modeDecided.current || !runtimeResolved) return;
    modeDecided.current = true;
    if (!captureAvailable) setMode('preview');
  }, [runtimeResolved, captureAvailable]);
  const [stepsWidth, setStepsWidth] = useState(() =>
    Math.min(STEPS_MAX, storedWidth(STEPS_WIDTH_KEY, 220, STEPS_MIN))
  );
  const [settingsWidth, setSettingsWidth] = useState(() =>
    storedWidth(SETTINGS_WIDTH_KEY, 380, SETTINGS_MIN)
  );
  const [stepsCollapsed, setStepsCollapsed] = useState(
    () => readStored(STEPS_COLLAPSED_KEY) === '1'
  );
  useEffect(() => writeStored(STEPS_WIDTH_KEY, String(stepsWidth)), [stepsWidth]);
  useEffect(
    () => writeStored(SETTINGS_WIDTH_KEY, String(settingsWidth)),
    [settingsWidth]
  );
  useEffect(
    () => writeStored(STEPS_COLLAPSED_KEY, stepsCollapsed ? '1' : '0'),
    [stepsCollapsed]
  );
  const [width, setWidth] = useState(1100);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [inputsOpen, setInputsOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!root.current || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver((entries) =>
      setWidth(entries[0].contentRect.width)
    );
    observer.observe(root.current);
    return () => observer.disconnect();
  }, []);
  const stepsColumn = stepsCollapsed ? RAIL_WIDTH : stepsWidth;
  // The settings panel may grow until the preview reaches its minimum. Compact
  // mode depends only on the minimums, so widening settings never hides it.
  const settingsMax = Math.max(SETTINGS_MIN, width - stepsColumn - PREVIEW_MIN);
  const settingsShown = Math.min(settingsWidth, settingsMax);
  const compact = width < stepsColumn + SETTINGS_MIN + PREVIEW_MIN;
  const stepStatus = stepPreviewStatus(preview);
  const selected =
    draft.steps.find((step) => step.id === selectedId) ?? draft.steps[0];
  const selectedStepId = selected?.id ?? null;
  useEffect(() => {
    onSelectedStepChange?.(selectedStepId);
  }, [onSelectedStepChange, selectedStepId]);
  const readOnly = !permissions.edit;
  // Release managers can review and publish a draft saved by an editor.
  const canReview = permissions.edit || permissions.release;
  const saving = busy === 'save';
  // The conflict notice carries save/review failures caused by the conflict.
  const editorErrors = (
    Object.keys(EDITOR_ERROR_TITLES) as PipelineOperation[]
  ).filter(
    (operation) =>
      errors[operation] &&
      !(conflict && (operation === 'save' || operation === 'review'))
  );
  const conflictDetail = conflict
    ? (errors.save ?? errors.review ?? undefined)
    : undefined;
  const banners =
    !!conflict ||
    editorErrors.length > 0 ||
    !!capabilitiesError ||
    !!validation;
  const settings = (
    <PipelineStepSettings
      key={selected?.id ?? 'empty'}
      step={selected}
      readOnly={readOnly}
      laneInputs={laneInputs}
      supported={
        !!selected && capabilities.supportedSteps.includes(selected.kind)
      }
      mixedInputs={!!inputs?.inputs?.mixed_processes}
      onChange={(step) =>
        onDraftChange({
          ...draft,
          steps: draft.steps.map((item) => (item.id === step.id ? step : item)),
        })
      }
    />
  );
  return (
    // NAN-3452: the editor owns exactly the shell's height and clips; every
    // panel scrolls inside itself, so nothing overflows into the app shell's
    // scroll container (which let the whole editor scroll off into blank).
    <section
      ref={root}
      className="flex h-full min-h-0 min-w-0 flex-col overflow-hidden text-foreground"
    >
      <PipelinePageHeader
        title={pipeline.name}
        meta={
          <>
            <span>
              Active{' '}
              {pipeline.activeRevision === null
                ? 'version unknown'
                : `version ${pipeline.activeRevision}`}
            </span>
            <span>
              Draft edit {draft.revision} ·{' '}
              {dirty
                ? 'unsaved changes'
                : pipeline.hasDraft
                  ? 'saved'
                  : 'no changes'}
            </span>
            <span>Source {pipeline.sourceName}</span>
            <span>Saving does not publish</span>
          </>
        }
        actions={
          <>
            <Button variant="ghost" onClick={onHistory}>
              <Clock className="h-3.5 w-3.5" strokeWidth={1.5} />
              History
            </Button>
            {/* A disabled button swallows hover, so the reason sits on a wrapper. */}
            <span
              className="inline-flex"
              title={
                capabilities.ai && onAssistant
                  ? 'Ask pivt about this pipeline'
                  : (capabilities.aiReason ?? 'pivt is unavailable')
              }
            >
              <Button
                variant="ghost"
                disabled={!capabilities.ai || !onAssistant}
                onClick={() => onAssistant?.(selected?.id ?? null)}
              >
                <PivtIcon className="h-3.5 w-3.5 text-primary" />
                pivt
              </Button>
            </span>
            <Button
              variant="outline"
              disabled={readOnly || !dirty || !!busy || !!conflict}
              onClick={onSave}
              title={
                conflict ? 'Resolve the server change before saving' : undefined
              }
            >
              <Save className="h-3.5 w-3.5" strokeWidth={1.5} />
              {saving ? 'Saving…' : 'Save draft'}
            </Button>
            <Button
              variant="outline"
              disabled={!canReview || dirty || !!busy}
              onClick={onValidate}
              title={dirty ? 'Save the draft before validating' : undefined}
            >
              <Check className="h-3.5 w-3.5" strokeWidth={1.5} />
              {busy === 'validate' ? 'Validating…' : 'Validate'}
            </Button>
            <Button
              disabled={!canReview || dirty || !!busy || !!conflict}
              onClick={onReview}
              title={
                conflict
                  ? 'Resolve the server change before reviewing a release'
                  : dirty
                    ? 'Save the draft before reviewing a release'
                    : undefined
              }
            >
              <Upload className="h-3.5 w-3.5" strokeWidth={1.5} />
              Review release
            </Button>
          </>
        }
      />
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border bg-panel/50 px-4 py-2 font-mono text-[10.5px]">
        {inputs ? (
          <button
            type="button"
            aria-expanded={inputsOpen}
            aria-controls="pipeline-inputs-panel"
            onClick={() => setInputsOpen((open) => !open)}
            className={cn(
              'rounded-sm border px-2 py-1 hover:bg-accent',
              inputsOpen ? 'border-primary/30 bg-primary/5' : 'border-border'
            )}
          >
            Inputs ·{' '}
            {inputs.loading ? '…' : inputs.error ? '!' : pipeInputCount(inputs.inputs)}
          </button>
        ) : (
          <span className="rounded-sm border border-border px-2 py-1">
            {pipeline.sourceName}
          </span>
        )}
        <span className="text-muted-foreground">→</span>
        <span className="rounded-sm border border-primary/30 bg-primary/5 px-2 py-1">
          Steps · {draft.steps.length}
        </span>
        <span className="text-muted-foreground">→</span>
        <span className="rounded-sm border border-border px-2 py-1 text-muted-foreground">
          Platform output guards · managed
        </span>
        <span className="text-muted-foreground">→</span>
        <span>Nano Lake</span>
      </div>
      {inputs && inputsOpen && (
        <div
          id="pipeline-inputs-panel"
          aria-label="Pipeline inputs"
          role="region"
          className="max-h-[35%] shrink-0 overflow-y-auto border-b border-border py-1"
        >
          <PipelineInputsPanel {...inputs} />
        </div>
      )}
      {banners && (
        <div className="max-h-[35%] shrink-0 space-y-2 overflow-y-auto border-b border-border px-4 py-2">
          {conflict && (
            <PipelineConflictNotice
              conflict={conflict}
              draft={draft}
              dirty={dirty}
              canEdit={!readOnly}
              busy={busy === 'reload' || busy === 'discard'}
              detail={conflictDetail}
              onReloadLatest={onReloadLatest}
              onKeepLocalEdits={onKeepLocalEdits}
              onDiscardDraft={onDiscardDraft}
            />
          )}
          {editorErrors.map((operation) => (
            <PipelineNotice
              key={operation}
              title={EDITOR_ERROR_TITLES[operation]!}
              tone="error"
            >
              {errors[operation]}
            </PipelineNotice>
          ))}
          {capabilitiesError && (
            <PipelineNotice
              title="Runtime capabilities unavailable"
              tone="warning"
            >
              <p>{capabilitiesError}</p>
              <p>
                Preview and capture stay off until they load. Editing, saving,
                and publishing still work.
              </p>
              {onRetryCapabilities && (
                <Button
                  variant="outline"
                  className="mt-2 h-6 px-2 text-[11px]"
                  onClick={onRetryCapabilities}
                >
                  Retry
                </Button>
              )}
            </PipelineNotice>
          )}
          {validation && (
            <PipelineNotice
              title={
                validation.valid ? 'Validation passed' : 'Validation failed'
              }
              tone={validation.valid ? 'neutral' : 'error'}
            >
              {validation.errors.map((finding, index) => (
                <p key={`error-${index}`}>{finding}</p>
              ))}
              {validation.warnings.map((finding, index) => (
                <p key={`warning-${index}`}>{finding}</p>
              ))}
            </PipelineNotice>
          )}
        </div>
      )}
      <div className="flex min-h-0 flex-1 overflow-hidden">
        {stepsCollapsed ? (
          <div
            style={{ width: RAIL_WIDTH }}
            className="flex min-h-0 shrink-0 flex-col items-center gap-0.5 overflow-y-auto border-r border-border py-1"
          >
            <Button
              variant="ghost"
              size="icon"
              className="h-6 w-6 text-muted-foreground"
              aria-label="Expand step list"
              title="Expand step list"
              onClick={() => setStepsCollapsed(false)}
            >
              <PanelLeftOpen className="h-3.5 w-3.5" strokeWidth={1.5} />
            </Button>
            {draft.steps.map((step, index) => (
              <button
                key={step.id}
                type="button"
                title={step.name}
                aria-label={`Select ${step.name}`}
                aria-pressed={selected?.id === step.id}
                onClick={() => setSelectedId(step.id)}
                className={cn(
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-sm font-mono text-[10px]',
                  selected?.id === step.id
                    ? 'bg-primary/10 text-foreground'
                    : 'text-muted-foreground hover:bg-accent',
                  stepStatus[step.id]?.errors && 'text-destructive'
                )}
              >
                {index + 1}
              </button>
            ))}
          </div>
        ) : (
          <>
            <div
              style={{ width: stepsWidth }}
              className="min-h-0 shrink-0 overflow-hidden border-r border-border"
            >
              <PipelineStepList
                steps={draft.steps}
                selectedId={selected?.id ?? null}
                supportedSteps={capabilities.supportedSteps}
                readOnly={readOnly || !!busy}
                status={stepStatus}
                onSelect={setSelectedId}
                onChange={(steps) => onDraftChange({ ...draft, steps })}
                onConfigure={() => setSettingsOpen(true)}
                onCollapsePanel={() => setStepsCollapsed(true)}
              />
            </div>
            <PanelResizer
              value={stepsWidth}
              onChange={setStepsWidth}
              min={STEPS_MIN}
              max={STEPS_MAX}
              label="Resize processing steps"
            />
          </>
        )}
        {!compact && (
          <>
            <div
              style={{ width: settingsShown }}
              className="min-h-0 shrink-0 overflow-auto border-r border-border bg-panel/40"
            >
              {settings}
            </div>
            <PanelResizer
              value={settingsShown}
              onChange={setSettingsWidth}
              min={SETTINGS_MIN}
              max={settingsMax}
              label="Resize step settings"
            />
          </>
        )}
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          <div className="flex h-9 shrink-0 items-center gap-1 border-b border-border px-2">
            <div
              className="flex h-full items-center gap-1"
              role="tablist"
              aria-label="Capture and preview"
            >
              {(['capture', 'preview'] as const).map((value) => (
                <button
                  key={value}
                  role="tab"
                  aria-selected={mode === value}
                  aria-controls={`pipeline-${value}-panel`}
                  id={`pipeline-${value}-tab`}
                  type="button"
                  onClick={() => {
                    modeDecided.current = true;
                    setMode(value);
                  }}
                  onKeyDown={(event) => {
                    if (
                      event.key === 'ArrowLeft' ||
                      event.key === 'ArrowRight'
                    ) {
                      event.preventDefault();
                      const next = value === 'capture' ? 'preview' : 'capture';
                      modeDecided.current = true;
                      setMode(next);
                      document.getElementById(`pipeline-${next}-tab`)?.focus();
                    }
                  }}
                  className={cn(
                    'flex h-9 items-center gap-1.5 border-b-2 px-2 text-[12px]',
                    mode === value
                      ? 'border-primary font-medium text-foreground'
                      : 'border-transparent text-muted-foreground hover:text-foreground'
                  )}
                >
                  {value === 'capture' ? 'Live capture' : 'Draft preview'}
                  <span className="hidden font-mono text-[9.5px] text-muted-foreground xl:inline">
                    {value === 'capture' ? 'observed' : 'computed'}
                  </span>
                </button>
              ))}
            </div>
            {compact && (
              <Button
                variant="ghost"
                className="ml-auto h-6 px-1.5 text-[11px]"
                onClick={() => setSettingsOpen(true)}
              >
                <Settings2 className="h-3 w-3" strokeWidth={1.5} />
                Settings
              </Button>
            )}
          </div>
          <div
            role="tabpanel"
            id={`pipeline-${mode}-panel`}
            aria-labelledby={`pipeline-${mode}-tab`}
            className="min-h-0 flex-1 overflow-auto"
          >
            {mode === 'capture' ? (
              <PipelineCapturePanel
                sourceId={pipeline.sourceId}
                sourceName={pipeline.sourceName}
                activeRevision={pipeline.activeRevision}
                capture={capture}
                capabilities={capabilities}
                canCapture={permissions.capture}
                busy={!!busy}
                onStart={onCaptureStart}
                onStop={onCaptureStop}
                onFreeze={() => {
                  onFreeze();
                  modeDecided.current = true;
                  setMode('preview');
                }}
                onSaveSample={onSaveSample}
                canSaveSample={canSaveSample}
              />
            ) : (
              <PipelinePreviewPanel
                sample={sample}
                samples={samples}
                preview={preview}
                revision={draft.revision}
                pending={!!previewPending}
                canViewEvents={permissions.capture}
                available={capabilities.preview}
                unavailableReason={capabilities.previewReason}
                error={previewError}
                selectedStepId={selected?.id ?? null}
                onSampleSelect={onSampleSelect}
                onPreview={onPreview}
                onLoadRecent={onLoadRecent}
                onPasteSample={onPasteSample}
                loadingRecent={busy === 'load'}
                sampleNotice={sampleNotice}
                sampleError={errors.load}
                laneInputs={laneInputs}
                routedInputs={routedInputs}
                previewInput={previewInput}
                onPreviewInputChange={onPreviewInputChange}
              />
            )}
          </div>
        </div>
      </div>
      <DetailSheet
        open={settingsOpen && compact}
        onOpenChange={setSettingsOpen}
        size="sm"
        title={selected?.name ?? 'Step settings'}
        breadcrumb={['Pipelines', pipeline.name]}
        description="Changes update the draft. Save and review a release to change production."
        bodyClassName="p-0"
      >
        {settings}
      </DetailSheet>
    </section>
  );
}
