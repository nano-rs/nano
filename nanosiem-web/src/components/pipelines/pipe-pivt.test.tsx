// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-3453 / NAN-4609: pivt on the Pipe page — the editor button, the
// selected step it reports, and the page bridge pivt applies VRL through.
// The panel conversation itself is covered in pages/__tests__/pipe-pivt-panel.test.tsx.

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, renderHook, screen } from '@testing-library/react';
import type { PipelineCapabilities, PipelineDraft } from '@/lib/pipeline-types';
import type { PipelineEditorProps } from './types';
import {
  PIPE_VRL_GONE_ERROR,
  PIPE_VRL_READ_ONLY_ERROR,
  PIPE_VRL_STALE_ERROR,
  applyPipeVrlOnPage,
  readPipePivtContext,
  usePipePivtBridge,
  type PivtPipeSnapshot,
} from '@/hooks/use-pipe-pivt-bridge';

vi.mock('@/contexts/PageContext', () => ({ usePageContext: () => ({ pageKey: 'pipelines' }) }));

import { PipelineEditor } from './PipelineEditor';
import { pipePivtUnavailableReason } from './usePipePivt';

beforeAll(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} }),
  });
});
afterEach(cleanup);

const draft: PipelineDraft = {
  name: 'Firewall',
  description: '',
  revision: 4,
  steps: [
    { id: 'p', name: 'Parse JSON', kind: 'parse', enabled: true, config: { format: 'json', field: 'message' } },
    { id: 'v', name: 'Tag', kind: 'vrl', enabled: true, config: { code: '.tagged = true' } },
  ],
};
const capabilities: PipelineCapabilities = {
  supportedSteps: ['vrl', 'parse'],
  capture: { available: false },
  preview: true,
  ai: false,
};

describe('Pipe editor pivt button', () => {
  const props = (overrides: Partial<PipelineEditorProps> = {}): PipelineEditorProps => ({
    pipeline: { id: 's1', name: 'Firewall', description: '', sourceId: 's1', sourceName: 'Firewall', sourceType: 'fw', activeRevision: 3, draftRevision: 4, hasDraft: true, health: 'healthy', latestRelease: null },
    draft, capabilities, permissions: { view: true, edit: true, capture: true, release: true }, dirty: false, samples: [],
    onDraftChange: vi.fn(), onSave: vi.fn(), onValidate: vi.fn(), onReview: vi.fn(), onHistory: vi.fn(), onCaptureStart: vi.fn(), onCaptureStop: vi.fn(),
    onFreeze: vi.fn(), onSampleSelect: vi.fn(), onPreview: vi.fn(), ...overrides,
  });

  it('is disabled with the reason when pivt is unavailable', () => {
    render(<PipelineEditor {...props({ capabilities: { ...capabilities, aiReason: 'pivt is part of nano Enterprise' } })} />);
    const button = screen.getByRole('button', { name: 'pivt' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.parentElement?.getAttribute('title')).toBe('pivt is part of nano Enterprise');
    expect(screen.queryByRole('button', { name: 'Assistant' })).toBeNull();
  });

  it('opens pivt on the selected step', () => {
    const onAssistant = vi.fn();
    render(<PipelineEditor {...props({ capabilities: { ...capabilities, ai: true }, onAssistant })} />);
    fireEvent.click(screen.getByRole('button', { name: 'pivt' }));
    expect(onAssistant).toHaveBeenCalledWith('p');
  });

  it('reports the selected step to the page (what @pipe works on)', () => {
    const onSelectedStepChange = vi.fn();
    render(<PipelineEditor {...props({ onSelectedStepChange })} />);
    expect(onSelectedStepChange).toHaveBeenLastCalledWith('p');
    fireEvent.click(screen.getAllByText('Tag')[0]);
    expect(onSelectedStepChange).toHaveBeenLastCalledWith('v');
  });

  it('names why pivt is off', () => {
    expect(pipePivtUnavailableReason('open', false, false)).toMatch(/Enterprise/);
    expect(pipePivtUnavailableReason('enterprise', false, true)).toMatch(/not enabled/);
    expect(pipePivtUnavailableReason('enterprise', true, false)).toMatch(/melod:parser/);
    expect(pipePivtUnavailableReason('enterprise', true, true)).toBeNull();
  });
});

describe('Pipe page bridge (NAN-4609)', () => {
  const snap = (overrides: Partial<PivtPipeSnapshot> = {}): PivtPipeSnapshot => ({
    sourceId: 's1', sourceName: 'Firewall', sourceType: 'fw', draft, selectedStepId: 'v', sample: null, preview: null,
    previewError: null, canApply: true, unavailableReason: null, ...overrides,
  });

  it('answers the context probe only while mounted', () => {
    const { unmount } = renderHook(() => usePipePivtBridge({ snapshot: snap(), onApply: vi.fn() }));
    expect(readPipePivtContext()?.selectedStepId).toBe('v');
    unmount();
    expect(readPipePivtContext()).toBeNull();
  });

  it('applies a replace to the draft, unsaved, and refuses a stale one', () => {
    const onApply = vi.fn();
    renderHook(() => usePipePivtBridge({ snapshot: snap(), onApply }));
    expect(applyPipeVrlOnPage('s1', { kind: 'replace', stepId: 'v' }, '.tagged = false', '.x = 1')).toEqual({
      applied: false, insertedStepId: undefined, error: PIPE_VRL_STALE_ERROR,
    });
    expect(onApply).not.toHaveBeenCalled();
    expect(applyPipeVrlOnPage('s1', { kind: 'replace', stepId: 'v' }, '.tagged = true', '.tagged = "yes"').applied).toBe(true);
    expect(onApply.mock.calls[0][0].steps[1]).toMatchObject({ id: 'v', kind: 'vrl', config: { code: '.tagged = "yes"' } });
  });

  it('inserts after the anchor and names the new step', () => {
    const onApply = vi.fn();
    renderHook(() => usePipePivtBridge({ snapshot: snap(), onApply }));
    const result = applyPipeVrlOnPage('s1', { kind: 'insert', afterStepId: 'p' }, '.', '.new = 1');
    expect(result.applied).toBe(true);
    const steps = onApply.mock.calls[0][0].steps;
    expect(steps.map((s: { id: string }) => s.id)).toEqual(['p', result.insertedStepId, 'v']);
  });

  it('refuses without edit access, for a gone step, and ignores another pipeline', () => {
    const onApply = vi.fn();
    const { rerender } = renderHook((props: { s: PivtPipeSnapshot }) => usePipePivtBridge({ snapshot: props.s, onApply }), {
      initialProps: { s: snap({ canApply: false }) },
    });
    expect(applyPipeVrlOnPage('s1', { kind: 'replace', stepId: 'v' }, '.tagged = true', '.x').error).toBe(PIPE_VRL_READ_ONLY_ERROR);
    rerender({ s: snap() });
    expect(applyPipeVrlOnPage('s1', { kind: 'replace', stepId: 'gone' }, '.', '.x').error).toBe(PIPE_VRL_GONE_ERROR);
    expect(applyPipeVrlOnPage('s2', { kind: 'replace', stepId: 'v' }, '.tagged = true', '.x')).toEqual({ applied: false, insertedStepId: undefined, error: undefined });
    expect(onApply).not.toHaveBeenCalled();
  });
});
