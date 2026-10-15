// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3453: pure context + apply helpers for pivt on the Pipe page.
//
// The Pipe page reuses the meloD parser-edit agent (`POST /api/melod/parser/edit`):
// - `current_vrl` is the ONE step being edited (or `.` when drafting a new step),
// - `base_parser_vrl` is the compiled VRL of the enabled steps that run before it,
//   so the agent's runtime test chains base → step exactly like the pipeline,
// - `sample_logs` are the raw messages of the page's selected sample,
// - `message` frames the pipe: source, ordered steps, selection, last preview
//   error / trace, and the analyst's request.
// Nothing here talks to the network; the enterprise wizard sends the request
// only when the analyst asks pivt something.

import { compileStep } from './pipeline-model';
import { safeRandomUUID } from './uuid';
import type { CapturedEvent, PipelineDraft, PipelinePreview, PipelineStep } from './pipeline-types';

/** Edit the selected step in place, or draft a new step after it. */
export type PipePivtMode = 'edit' | 'draft';

/** Where an accepted proposal lands. */
export type PipePivtTarget =
  | { kind: 'replace'; stepId: string }
  | { kind: 'insert'; afterStepId: string | null };

export interface PipePivtContextInput {
  sourceName: string;
  sourceType?: string;
  draft: PipelineDraft;
  /** Step the analyst had selected; null/unknown falls back to the first step. */
  selectedStepId: string | null;
  mode: PipePivtMode;
  sample?: { events: CapturedEvent[] } | null;
  preview?: PipelinePreview | null;
  previewError?: string | null;
}

export interface PipePivtContext {
  target: PipePivtTarget;
  /** The step being edited (edit mode) or the insertion anchor (draft mode). */
  step: PipelineStep | null;
  stepIndex: number;
  /** VRL the proposal is diffed against and that `current_vrl` carries. */
  currentVrl: string;
  /** Compiled enabled steps that run before the target, or undefined at the head. */
  baseVrl?: string;
  sampleLogs: string[];
  /** Last preview error or failing trace, already trimmed. */
  previewIssue?: string;
  /** Step names/kinds whose VRL could not compile and was left out of `baseVrl`. */
  skipped: string[];
}

export const PIPE_PIVT_MAX_SAMPLES = 5;
const MAX_SAMPLE_BYTES = 8 * 1024;
const MAX_ISSUE_CHARS = 2000;
const MAX_FOLLOWING_VRL_CHARS = 4000;
/** The parser-edit endpoint caps `message` at 16 KiB. */
const MAX_MESSAGE_CHARS = 15 * 1024;
const MAX_REQUEST_CHARS = 4 * 1024;
export const NEW_STEP_PLACEHOLDER = '.';

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}\n… (truncated)` : value;
}

/** VRL of one step without its condition wrapper (the condition stays on the step). */
export function stepBodyVrl(step: PipelineStep): string {
  if (step.kind === 'vrl') return typeof step.config.code === 'string' ? step.config.code : '';
  return compileStep({ ...step, condition: undefined });
}

function safeBody(step: PipelineStep): string | null {
  try {
    return stepBodyVrl(step);
  } catch {
    return null;
  }
}

/** Raw message for one sample event: `.message` when it is text, else the JSON input. */
export function sampleLog(event: CapturedEvent): string {
  const input = event.input;
  if (typeof input === 'string') return input;
  if (input && typeof input === 'object' && typeof (input as { message?: unknown }).message === 'string') {
    return (input as { message: string }).message;
  }
  try {
    return JSON.stringify(input) ?? '';
  } catch {
    return '';
  }
}

export function pipeSampleLogs(sample: { events: CapturedEvent[] } | null | undefined): string[] {
  return (sample?.events ?? [])
    .map(sampleLog)
    .filter((log) => log.trim().length > 0 && log.length <= MAX_SAMPLE_BYTES)
    .slice(0, PIPE_PIVT_MAX_SAMPLES);
}

/** The most useful failure from the last preview: request error, else the first errored event. */
export function previewIssue(
  preview: PipelinePreview | null | undefined,
  previewError: string | null | undefined,
  stepId?: string,
): string | undefined {
  if (previewError?.trim()) return clip(previewError.trim(), MAX_ISSUE_CHARS);
  if (!preview) return undefined;
  const failed = preview.events.find((event) => event.outcome === 'error' || event.error || event.trace?.some((t) => t.error));
  if (!failed) return undefined;
  const lines: string[] = [];
  if (failed.error) lines.push(`Event ${failed.inputId}: ${failed.error}`);
  for (const entry of failed.trace ?? []) {
    if (entry.error) lines.push(`step ${entry.stepId}${entry.stepId === stepId ? ' (selected)' : ''}: ${entry.error}`);
  }
  return lines.length ? clip(lines.join('\n'), MAX_ISSUE_CHARS) : undefined;
}

export function buildPipePivtContext(input: PipePivtContextInput): PipePivtContext {
  const { draft, mode } = input;
  const steps = draft.steps;
  let stepIndex = steps.findIndex((step) => step.id === input.selectedStepId);
  if (stepIndex < 0) stepIndex = mode === 'draft' ? steps.length - 1 : 0;
  const step = steps[stepIndex] ?? null;
  // Edit: everything before the step. Draft: everything up to and including the anchor.
  const baseEnd = mode === 'edit' ? stepIndex : stepIndex + 1;
  const skipped: string[] = [];
  const base: string[] = [];
  for (const prior of steps.slice(0, Math.max(0, baseEnd))) {
    if (!prior.enabled) continue;
    try {
      base.push(compileStep(prior));
    } catch {
      skipped.push(`${prior.name} (${prior.kind})`);
    }
  }
  const target: PipePivtTarget = mode === 'edit' && step
    ? { kind: 'replace', stepId: step.id }
    : { kind: 'insert', afterStepId: step?.id ?? null };
  const currentVrl = target.kind === 'replace' && step ? (safeBody(step) ?? '') : NEW_STEP_PLACEHOLDER;
  return {
    target,
    step,
    stepIndex,
    currentVrl: currentVrl.trim() ? currentVrl : NEW_STEP_PLACEHOLDER,
    baseVrl: base.length ? base.join('\n\n') : undefined,
    sampleLogs: pipeSampleLogs(input.sample),
    previewIssue: previewIssue(input.preview, input.previewError, step?.id),
    skipped,
  };
}

/** Frame the analyst's request with the pipe context for the parser-edit agent. */
export function buildPipePivtMessage(input: PipePivtContextInput, context: PipePivtContext, request: string): string {
  const steps = input.draft.steps;
  const lines: string[] = [
    `You are helping edit a Nano Pipe pipeline for log source "${input.sourceName}"${input.sourceType ? ` (source type ${input.sourceType})` : ''}.`,
    'A pipeline is an ordered list of VRL processing steps; each step runs on the output of the previous one.',
  ];
  if (context.target.kind === 'replace' && context.step) {
    lines.push(
      `You are editing ONLY step ${context.stepIndex + 1} of ${steps.length}, "${context.step.name}" (${context.step.kind}).`,
      'The read-only base VRL (if shown) is the compiled output of the enabled steps that run before it. The Current VRL is this step alone.',
      'If you change code, return the COMPLETE VRL for this one step only. Never repeat earlier or later steps.',
    );
    if (context.step.condition?.trim()) lines.push(`This step only runs when its condition is true: ${context.step.condition.trim()}`);
    if (context.step.kind !== 'vrl') lines.push(`This is a structured ${context.step.kind} step shown as its compiled VRL; accepted code turns it into an advanced VRL step.`);
  } else {
    const anchor = context.step ? `after step ${context.stepIndex + 1}, "${context.step.name}"` : 'as the first step';
    lines.push(
      `You are drafting a NEW step to insert ${anchor}.`,
      'The read-only base VRL (if shown) is the compiled output of the enabled steps that run before the new step.',
      `The Current VRL "${NEW_STEP_PLACEHOLDER}" is a placeholder. Replace it with the complete VRL for the new step only.`,
    );
  }
  lines.push('', 'Pipeline steps in order:');
  steps.forEach((step, index) => {
    const marker = context.step?.id === step.id ? (context.target.kind === 'replace' ? '  <- editing' : '  <- new step goes after this') : '';
    lines.push(`${index + 1}. [${step.enabled ? 'on' : 'off'}] ${step.name} (${step.kind})${step.condition?.trim() ? ` if ${step.condition.trim()}` : ''}${marker}`);
  });
  if (context.skipped.length) lines.push(`Not compiled into the base (incomplete): ${context.skipped.join(', ')}`);
  const following = steps.slice(context.stepIndex + 1).filter((step) => step.enabled);
  if (following.length) {
    const body = following
      .map((step) => {
        const vrl = safeBody(step);
        return vrl === null ? null : `# step: ${step.name} (${step.kind})\n${vrl}`;
      })
      .filter((vrl): vrl is string => vrl !== null)
      .join('\n\n');
    if (body) lines.push('', 'Later steps (read-only, run after):', '```vrl', clip(body, MAX_FOLLOWING_VRL_CHARS), '```');
  }
  if (context.previewIssue) lines.push('', 'Last draft preview error / trace:', '```', context.previewIssue, '```');
  if (!context.sampleLogs.length) lines.push('', 'No sample events were attached.');
  // Clip the context, never the request: the analyst's ask always reaches the agent.
  const ask = `\n\n## Request\n${clip(request.trim(), MAX_REQUEST_CHARS)}`;
  return clip(lines.join('\n'), MAX_MESSAGE_CHARS - ask.length - 20) + ask;
}

/** Text the proposal is diffed against for this target in the given draft, or null if the target is gone. */
export function targetVrl(draft: PipelineDraft, target: PipePivtTarget): string | null {
  if (target.kind === 'insert') {
    if (target.afterStepId !== null && !draft.steps.some((step) => step.id === target.afterStepId)) return null;
    return NEW_STEP_PLACEHOLDER;
  }
  const step = draft.steps.find((item) => item.id === target.stepId);
  if (!step) return null;
  const body = safeBody(step);
  return body === null ? null : body.trim() ? body : NEW_STEP_PLACEHOLDER;
}

/**
 * Apply an accepted proposal to the draft. Replacing a structured step turns it
 * into an advanced VRL step (keeping its name, enabled flag and condition);
 * inserting adds a new VRL step after the anchor. Returns null when the target
 * no longer exists.
 */
export function applyPipeVrl(
  draft: PipelineDraft,
  target: PipePivtTarget,
  vrl: string,
  newId: () => string = () => safeRandomUUID(),
  newName = 'pivt step',
): PipelineDraft | null {
  if (target.kind === 'replace') {
    const index = draft.steps.findIndex((step) => step.id === target.stepId);
    if (index < 0) return null;
    const current = draft.steps[index];
    const next: PipelineStep = { ...current, kind: 'vrl', config: { code: vrl } };
    return { ...draft, steps: draft.steps.map((step, i) => (i === index ? next : step)) };
  }
  const anchor = target.afterStepId === null ? -1 : draft.steps.findIndex((step) => step.id === target.afterStepId);
  if (target.afterStepId !== null && anchor < 0) return null;
  const step: PipelineStep = { id: newId(), name: newName, kind: 'vrl', enabled: true, config: { code: vrl } };
  const steps = [...draft.steps];
  steps.splice(anchor + 1, 0, step);
  return { ...draft, steps };
}
