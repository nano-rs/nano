// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import {
  applyPipeVrl,
  buildPipePivtContext,
  buildPipePivtMessage,
  NEW_STEP_PLACEHOLDER,
  pipeSampleLogs,
  previewIssue,
  targetVrl,
  type PipePivtContextInput,
} from './pipe-pivt';
import type { PipelineDraft, PipelinePreview } from './pipeline-types';

const draft: PipelineDraft = {
  name: 'Firewall',
  description: '',
  revision: 3,
  steps: [
    { id: 'p', name: 'Parse JSON', kind: 'parse', enabled: true, config: { format: 'json', field: 'message' } },
    { id: 'off', name: 'Disabled', kind: 'vrl', enabled: false, config: { code: '.never = 1' } },
    { id: 'v', name: 'Tag', kind: 'vrl', enabled: true, condition: 'exists(.user)', config: { code: '.tagged = true' } },
    { id: 'f', name: 'Rename', kind: 'fields', enabled: true, config: { operation: 'rename', field: 'a', target: 'b' } },
  ],
};

const input = (overrides: Partial<PipePivtContextInput> = {}): PipePivtContextInput => ({
  sourceName: 'Firewall',
  sourceType: 'fw',
  draft,
  selectedStepId: 'v',
  mode: 'edit',
  sample: { events: [{ id: '1', input: { message: '{"user":"bob"}', source_type: 'fw' } }, { id: '2', input: { raw: 1 } }] },
  ...overrides,
});

describe('buildPipePivtContext', () => {
  it('edits the selected step against the compiled enabled steps before it', () => {
    const context = buildPipePivtContext(input());
    expect(context.target).toEqual({ kind: 'replace', stepId: 'v' });
    // The step body without its condition wrapper: the condition stays on the step.
    expect(context.currentVrl).toBe('.tagged = true');
    expect(context.baseVrl).toContain('parse_json!');
    expect(context.baseVrl).not.toContain('.never');
    expect(context.sampleLogs).toEqual(['{"user":"bob"}', '{"raw":1}']);
  });

  it('drafts a new step after the anchor with a placeholder and the anchor in the base', () => {
    const context = buildPipePivtContext(input({ mode: 'draft' }));
    expect(context.target).toEqual({ kind: 'insert', afterStepId: 'v' });
    expect(context.currentVrl).toBe(NEW_STEP_PLACEHOLDER);
    expect(context.baseVrl).toContain('if exists(.user)');
  });

  it('has no base for the first step and falls back to it for an unknown selection', () => {
    const context = buildPipePivtContext(input({ selectedStepId: 'gone' }));
    expect(context.step?.id).toBe('p');
    expect(context.baseVrl).toBeUndefined();
  });

  it('drafts the first step of an empty pipeline', () => {
    const context = buildPipePivtContext(input({ draft: { ...draft, steps: [] }, selectedStepId: null }));
    expect(context.target).toEqual({ kind: 'insert', afterStepId: null });
  });

  it('leaves incomplete prior steps out of the base and names them', () => {
    const broken = { ...draft, steps: [{ id: 'x', name: 'Empty', kind: 'vrl' as const, enabled: true, config: { code: '' } }, draft.steps[2]] };
    const context = buildPipePivtContext(input({ draft: broken }));
    expect(context.baseVrl).toBeUndefined();
    expect(context.skipped).toEqual(['Empty (vrl)']);
  });

  it('sends no samples when none are attached', () => {
    expect(buildPipePivtContext(input({ sample: null })).sampleLogs).toEqual([]);
  });
});

describe('pipe context helpers', () => {
  it('caps sample logs at five', () => {
    const events = Array.from({ length: 9 }, (_, i) => ({ id: String(i), input: { message: `m${i}` } }));
    expect(pipeSampleLogs({ events })).toHaveLength(5);
  });

  it('prefers the preview request error, else the first errored event trace', () => {
    const preview: PipelinePreview = {
      revision: 1, fingerprint: 'f', inputCount: 1, outputCount: 0, stale: false,
      events: [{ inputId: 'e1', input: {}, outputs: [], outcome: 'error', error: 'aborted', trace: [{ stepId: 'v', outputs: [], error: 'function call error' }] }],
    };
    expect(previewIssue(preview, 'worker down')).toBe('worker down');
    const issue = previewIssue(preview, null, 'v');
    expect(issue).toContain('Event e1: aborted');
    expect(issue).toContain('step v (selected): function call error');
  });

  it('frames the request with source, ordered steps, selection and preview error', () => {
    const ctx = input({ previewError: 'compile error at line 2' });
    const message = buildPipePivtMessage(ctx, buildPipePivtContext(ctx), 'Fix it');
    expect(message).toContain('log source "Firewall" (source type fw)');
    expect(message).toContain('step 3 of 4, "Tag" (vrl)');
    expect(message).toContain('only runs when its condition is true: exists(.user)');
    expect(message).toMatch(/3\. \[on\] Tag \(vrl\) if exists\(\.user\)\s+<- editing/);
    expect(message).toContain('2. [off] Disabled');
    expect(message).toContain('Later steps (read-only, run after)');
    expect(message).toContain('compile error at line 2');
    expect(message.trim().endsWith('Fix it')).toBe(true);
  });

  it('clips oversized context but always keeps the request', () => {
    const huge = { ...draft, steps: [...draft.steps, { id: 'big', name: 'Big', kind: 'vrl' as const, enabled: true, config: { code: '.x = 1\n'.repeat(5000) } }] };
    const ctx = input({ draft: huge, previewError: 'e'.repeat(5000) });
    const message = buildPipePivtMessage(ctx, buildPipePivtContext(ctx), 'Keep me');
    expect(message.length).toBeLessThanOrEqual(15 * 1024);
    expect(message.endsWith('## Request\nKeep me')).toBe(true);
  });
});

describe('applyPipeVrl', () => {
  it('replaces a VRL step body and keeps its name, flag and condition', () => {
    const next = applyPipeVrl(draft, { kind: 'replace', stepId: 'v' }, '.tagged = "yes"')!;
    expect(next.steps[2]).toEqual({ ...draft.steps[2], config: { code: '.tagged = "yes"' } });
    expect(next.steps).toHaveLength(4);
  });

  it('turns a structured step into an advanced VRL step', () => {
    const next = applyPipeVrl(draft, { kind: 'replace', stepId: 'f' }, '.b = del(.a)')!;
    expect(next.steps[3]).toMatchObject({ id: 'f', name: 'Rename', kind: 'vrl', config: { code: '.b = del(.a)' } });
  });

  it('inserts a new enabled VRL step after the anchor or first', () => {
    const after = applyPipeVrl(draft, { kind: 'insert', afterStepId: 'p' }, '.x = 1', () => 'new')!;
    expect(after.steps.map((s) => s.id)).toEqual(['p', 'new', 'off', 'v', 'f']);
    expect(after.steps[1]).toMatchObject({ kind: 'vrl', enabled: true, config: { code: '.x = 1' } });
    const first = applyPipeVrl(draft, { kind: 'insert', afterStepId: null }, '.x = 1', () => 'new')!;
    expect(first.steps[0].id).toBe('new');
  });

  it('refuses a target that no longer exists', () => {
    expect(applyPipeVrl(draft, { kind: 'replace', stepId: 'gone' }, '.')).toBeNull();
    expect(applyPipeVrl(draft, { kind: 'insert', afterStepId: 'gone' }, '.')).toBeNull();
    expect(targetVrl(draft, { kind: 'replace', stepId: 'gone' })).toBeNull();
    expect(targetVrl(draft, { kind: 'replace', stepId: 'v' })).toBe('.tagged = true');
  });
});
