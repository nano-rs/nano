// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-3453: pivt on the Pipe page — editor button, `@pipe` routing, the
// `pivt:open-pipe-wizard` listener, and the wizard's diff → accept/reject flow.

import type { ReactNode } from 'react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import type { MelodEditParserResponse } from '@/lib/api';
import type { PipelineCapabilities, PipelineDraft } from '@/lib/pipeline-types';
import type { PipelineEditorProps } from './types';

const melodEditParser = vi.fn();
let nextResponse: MelodEditParserResponse;
vi.mock('@/lib/api', () => ({ api: { melodEditParser: (...args: unknown[]) => melodEditParser(...args) } }));
vi.mock('@/enterprise/hooks/use-melod-job', () => ({
  useMelodJob: () => ({
    start: async (fn: () => Promise<unknown>) => {
      await fn();
      return nextResponse;
    },
    loading: false,
    progress: null,
    result: null,
    error: null,
    reset: () => {},
  }),
}));
vi.mock('@/components/ui/markdown', () => ({ Markdown: ({ children }: { children: ReactNode }) => <div>{children}</div> }));
vi.mock('@/contexts/PageContext', () => ({ usePageContext: () => ({ pageKey: 'pipelines' }) }));

import { PipelineEditor } from './PipelineEditor';
import { pipePivtUnavailableReason } from './usePipePivt';
import { PipePivtWizard, type PipePivtWizardProps } from '@/enterprise/components/pipelines/PipePivtWizard';
import { PIPE_WIZARD_EVENT, usePipeWizardListener } from '@/hooks/use-pipe-wizard-listener';
import { usePivtCommands, PIVT_OPEN_PIPE_WIZARD } from '@/enterprise/components/pivt/commands/router';
import { PIVT_OPEN_PIPE_WIZARD as STUB_PIPE_EVENT } from '@/enterprise-stubs/components/pivt/commands/router';

beforeAll(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} }),
  });
});
beforeEach(() => {
  melodEditParser.mockReset();
  melodEditParser.mockResolvedValue({ job_id: 'job-1', status: 'running' });
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

  it('names why pivt is off', () => {
    expect(pipePivtUnavailableReason('open', false, false)).toMatch(/Enterprise/);
    expect(pipePivtUnavailableReason('enterprise', false, true)).toMatch(/not enabled/);
    expect(pipePivtUnavailableReason('enterprise', true, false)).toMatch(/melod:parser/);
    expect(pipePivtUnavailableReason('enterprise', true, true)).toBeNull();
  });
});

describe('pivt:open-pipe-wizard', () => {
  it('keeps the event name identical in the enterprise router and the open stub', () => {
    expect(PIVT_OPEN_PIPE_WIZARD).toBe(PIPE_WIZARD_EVENT);
    expect(STUB_PIPE_EVENT).toBe(PIPE_WIZARD_EVENT);
  });

  it('opens for the open pipeline only and carries step + prompt', () => {
    const { result } = renderHook(() => usePipeWizardListener('s1', true));
    act(() => {
      window.dispatchEvent(new CustomEvent(PIPE_WIZARD_EVENT, { detail: { sourceId: 'other' } }));
    });
    expect(result.current.request).toBeNull();
    act(() => {
      window.dispatchEvent(new CustomEvent(PIPE_WIZARD_EVENT, { detail: { stepId: 'v', prompt: 'explain' } }));
    });
    expect(result.current.request).toEqual({ seq: 1, stepId: 'v', prompt: 'explain' });
  });

  it('does not listen when pivt is unavailable', () => {
    const { result } = renderHook(() => usePipeWizardListener('s1', false));
    act(() => {
      window.dispatchEvent(new CustomEvent(PIPE_WIZARD_EVENT, { detail: {} }));
    });
    expect(result.current.request).toBeNull();
  });

  it('@pipe dispatches the wizard event on a pipeline page', () => {
    window.history.pushState({}, '', '/ingestion/pipelines/s1');
    const seen = vi.fn();
    window.addEventListener(PIPE_WIZARD_EVENT, seen);
    const { result } = renderHook(() => usePivtCommands(), { wrapper: ({ children }) => <MemoryRouter>{children}</MemoryRouter> });
    const outcome = result.current.dispatch('@pipe fix the error');
    window.removeEventListener(PIPE_WIZARD_EVENT, seen);
    expect(outcome).toEqual({ handled: true, action: 'open pipe assistant' });
    expect((seen.mock.calls[0][0] as CustomEvent).detail).toEqual({ prompt: 'fix the error' });
    window.history.pushState({}, '', '/');
  });
});

describe('PipePivtWizard', () => {
  const wizardProps = (overrides: Partial<PipePivtWizardProps> = {}): PipePivtWizardProps => ({
    open: true,
    onOpenChange: vi.fn(),
    openSeq: 1,
    sourceId: '11111111-1111-1111-1111-111111111111',
    sourceName: 'Firewall',
    sourceType: 'fw',
    draft,
    initialStepId: 'v',
    sample: { name: 'Recent events', events: [{ id: '1', input: { message: '{"user":"bob"}' } }] },
    previewError: 'function call error for "parse_json"',
    canApply: true,
    onApply: vi.fn(),
    ...overrides,
  });

  it('sends the step, prior steps, samples and preview error only on request', async () => {
    nextResponse = { session_id: 'sess', message: 'This step tags events.' };
    render(<PipePivtWizard {...wizardProps()} />);
    expect(melodEditParser).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Explain this step' }));
    await screen.findByText('This step tags events.');
    const request = melodEditParser.mock.calls[0][0];
    expect(request.parser_id).toBe('11111111-1111-1111-1111-111111111111');
    expect(request.current_vrl).toBe('.tagged = true');
    expect(request.base_parser_vrl).toContain('parse_json!');
    expect(request.sample_logs).toEqual(['{"user":"bob"}']);
    expect(request.message).toContain('function call error for "parse_json"');
    expect(request.message).toContain('Explain this step');
    // An explanation proposes no code.
    expect(screen.queryByRole('region', { name: 'pivt proposal' })).toBeNull();
  });

  it('omits samples when the analyst detaches them', async () => {
    nextResponse = { session_id: 'sess', message: 'ok' };
    render(<PipePivtWizard {...wizardProps()} />);
    fireEvent.click(screen.getByRole('checkbox'));
    fireEvent.click(screen.getByRole('button', { name: 'Explain this step' }));
    await screen.findByText('ok');
    expect(melodEditParser.mock.calls[0][0].sample_logs).toBeUndefined();
  });

  it('shows a diff and applies only on accept', async () => {
    nextResponse = { session_id: 'sess', message: 'Fixed.', updated_vrl: '.tagged = "yes"', validation: { valid: true, errors: [] } };
    const onApply = vi.fn();
    render(<PipePivtWizard {...wizardProps({ onApply })} />);
    fireEvent.click(screen.getByRole('button', { name: 'Fix the preview error' }));
    await screen.findByRole('region', { name: 'pivt proposal' });
    const diff = screen.getByTestId('pipe-pivt-diff').textContent ?? '';
    expect(diff).toContain('- .tagged = true');
    expect(diff).toContain('+ .tagged = "yes"');
    expect(onApply).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Apply to step' }));
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(onApply.mock.calls[0][0].steps[1]).toMatchObject({ id: 'v', kind: 'vrl', config: { code: '.tagged = "yes"' } });
    expect(screen.queryByRole('region', { name: 'pivt proposal' })).toBeNull();
  });

  it('discards a rejected proposal without touching the draft', async () => {
    nextResponse = { session_id: 'sess', message: 'Fixed.', updated_vrl: '.tagged = 2' };
    const onApply = vi.fn();
    render(<PipePivtWizard {...wizardProps({ onApply })} />);
    fireEvent.click(screen.getByRole('button', { name: 'Fix the preview error' }));
    await screen.findByRole('region', { name: 'pivt proposal' });
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    expect(onApply).not.toHaveBeenCalled();
    expect(screen.getByText(/Rejected the proposal/)).toBeTruthy();
  });

  it('drafts a new step and inserts it after the selected one', async () => {
    nextResponse = { session_id: 'sess', message: 'Drafted.', updated_vrl: '.region = "us"' };
    const onApply = vi.fn();
    render(<PipePivtWizard {...wizardProps({ onApply, initialStepId: 'p' })} />);
    fireEvent.click(screen.getByRole('radio', { name: 'New step after' }));
    fireEvent.click(screen.getByRole('button', { name: 'Draft a step from the sample events' }));
    await screen.findByRole('region', { name: 'pivt proposal' });
    expect(melodEditParser.mock.calls[0][0].current_vrl).toBe('.');
    fireEvent.click(screen.getByRole('button', { name: 'Insert step' }));
    const next = onApply.mock.calls[0][0] as PipelineDraft;
    expect(next.steps.map((s) => s.id).slice(0, 1)).toEqual(['p']);
    expect(next.steps[1]).toMatchObject({ kind: 'vrl', config: { code: '.region = "us"' } });
    expect(next.steps[2].id).toBe('v');
  });

  it('blocks a stale proposal and read-only viewers', async () => {
    nextResponse = { session_id: 'sess', message: 'Fixed.', updated_vrl: '.tagged = 3' };
    const { rerender } = render(<PipePivtWizard {...wizardProps()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Fix the preview error' }));
    await screen.findByRole('region', { name: 'pivt proposal' });
    const changed = { ...draft, steps: [draft.steps[0], { ...draft.steps[1], config: { code: '.edited = 1' } }] };
    rerender(<PipePivtWizard {...wizardProps({ draft: changed })} />);
    await waitFor(() => expect((screen.getByRole('button', { name: 'Apply to step' }) as HTMLButtonElement).disabled).toBe(true));
    expect(screen.getByText(/changed after pivt proposed/)).toBeTruthy();
    rerender(<PipePivtWizard {...wizardProps({ canApply: false })} />);
    expect((screen.getByRole('button', { name: 'Apply to step' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/Requires permission/)).toBeTruthy();
  });
});
