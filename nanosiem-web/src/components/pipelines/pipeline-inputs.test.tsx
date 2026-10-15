// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/** NAN-3621: pipeline inputs (push credentials, connector feeds, cloud pull sources). */

import type { ReactNode } from 'react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PipeLaneInputs, PipeLaneInputSummary } from '@/lib/api/pipelines';
import { pipeInputCount, pipeInputTotal, pipelinesForSlug } from '@/lib/api/pipelines';
import { PipelineInputsPanel } from './PipelineInputs';
import { PipelineEditor } from './PipelineEditor';
import { PipelineList } from './PipelineList';
import { PipelineStepSettings } from './PipelineSteps';
import type { PipelineEditorProps } from './types';
import type { PipelineCapabilities, PipelineSummary } from '@/lib/pipeline-types';

const mocks = vi.hoisted(() => ({ inputs: vi.fn(), inputSummary: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ tenantRuntime: { key: 'tenant-a:user-1' }, hasPermission: () => true }),
}));
vi.mock('@/lib/api', () => ({ api: { pipelines: { inputs: mocks.inputs, inputSummary: mocks.inputSummary } } }));

const SOURCE = 'lsrc_01h455vb4pex5vsknk084sn02q';
const INPUTS: PipeLaneInputs = {
  log_source_id: SOURCE,
  source_slugs: ['aws_cloudtrail'],
  push: [{ credential_id: 'c0ffee00-0000-4000-8000-000000000001', label: 'Collector HEC', kind: 'hec', protocol: 'hec', credential_kind: 'source', writes: ['aws_cloudtrail'], implicit: false, last_seen_at: '2026-10-11T12:00:00Z' }],
  pull: [{ id: '11111111-2222-4333-8444-555555555555', name: 'Trail queue', provider: 'aws_s3_sqs', source_slug: 'aws_cloudtrail', state: 'failed', last_error: 'AccessDenied on sqs:ReceiveMessage', updated_at: '2026-10-11T11:00:00Z' }],
  connectors: [{ id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', name: 'Okta system log', connector: 'okta', source_slug: 'aws_cloudtrail', enabled: true, status: 'success', last_run_at: '2026-10-11T11:30:00Z', last_success_at: '2026-10-11T11:30:00Z', last_error: null, next_run_at: '2026-10-11T12:30:00Z', marketplace: true, ingest_credential_id: 'f33d0000-0000-4000-8000-000000000009' }],
  mixed_processes: true,
};
const capabilities: PipelineCapabilities = { supportedSteps: ['vrl'], capture: { available: true, maxEvents: 100, maxDurationSeconds: 30 }, preview: true, ai: false };

beforeAll(() => {
  Object.defineProperty(window, 'matchMedia', { writable: true, value: () => ({ matches: false, addEventListener: () => {}, removeEventListener: () => {} }) });
});
beforeEach(() => vi.clearAllMocks());
afterEach(cleanup);

const routed = (node: ReactNode) => render(<MemoryRouter>{node}</MemoryRouter>);

describe('Inputs panel', () => {
  it('lists every input with a link to the page that manages it', () => {
    routed(<PipelineInputsPanel inputs={INPUTS} />);
    const push = screen.getByTestId(`input-push-${INPUTS.push[0].credential_id}`);
    expect(within(push).getByText('push · HEC')).toBeTruthy();
    expect(within(push).getByRole('link', { name: 'Collector HEC' }).getAttribute('href')).toBe('/ingestion/log-sources/credentials');
    const feed = screen.getByTestId(`input-connector-${INPUTS.connectors[0].id}`);
    expect(within(feed).getByRole('link', { name: 'Okta system log' }).getAttribute('href')).toBe('/marketplace?slug=okta');
    const pull = screen.getByTestId(`input-pull-${INPUTS.pull[0].id}`);
    expect(within(pull).getByRole('link', { name: 'Trail queue' }).getAttribute('href')).toBe('/ingestion/log-sources/cloud-pull');
    expect(within(pull).getByText('pull · S3 via SQS')).toBeTruthy();
    expect(within(pull).getByText('failed')).toBeTruthy();
    expect(within(pull).getByText('AccessDenied on sqs:ReceiveMessage')).toBeTruthy();
  });

  it('explains an empty lane, the default source, an old backend and a failure', () => {
    const empty = { ...INPUTS, push: [], pull: [], connectors: [], mixed_processes: false };
    const { unmount } = routed(<PipelineInputsPanel inputs={empty} />);
    expect(screen.getByText(/No input writes/)).toBeTruthy();
    expect(screen.getByRole('link', { name: 'add a cloud pull source' })).toBeTruthy();
    unmount();
    routed(<PipelineInputsPanel inputs={{ ...empty, source_slugs: [] }} />);
    expect(screen.getByText(/default source has no lane label/)).toBeTruthy();
    cleanup();
    routed(<PipelineInputsPanel inputs={null} />);
    expect(screen.getByText(/does not report pipeline inputs/)).toBeTruthy();
    cleanup();
    routed(<PipelineInputsPanel inputs={undefined} error="permission denied" />);
    expect(screen.getByRole('alert').textContent).toContain('permission denied');
  });

  it('counts inputs across kinds', () => {
    expect(pipeInputCount(INPUTS)).toBe(3);
    expect(pipeInputCount(null)).toBe(0);
    expect(pipeInputTotal({ push: 2, pull: 1, connectors: 0 })).toBe(3);
  });
});

describe('Editor inputs strip', () => {
  const props = (overrides: Partial<PipelineEditorProps> = {}): PipelineEditorProps => ({
    pipeline: { id: SOURCE, name: 'CloudTrail', description: '', sourceId: SOURCE, sourceName: 'CloudTrail', sourceType: 'aws_cloudtrail', activeRevision: 3, draftRevision: 4, hasDraft: false, health: 'healthy', latestRelease: null },
    draft: { name: 'CloudTrail', description: '', revision: 4, steps: [{ id: 'vrl', name: 'Parser', kind: 'vrl', enabled: true, config: { code: '.ok = true' } }] },
    capabilities, permissions: { view: true, edit: true, capture: true, release: true }, dirty: false, samples: [],
    onDraftChange: vi.fn(), onSave: vi.fn(), onValidate: vi.fn(), onReview: vi.fn(), onHistory: vi.fn(), onCaptureStart: vi.fn(), onCaptureStop: vi.fn(),
    onFreeze: vi.fn(), onSampleSelect: vi.fn(), onPreview: vi.fn(), ...overrides,
  });

  it('shows the input count and opens the Inputs panel', () => {
    routed(<PipelineEditor {...props({ inputs: { inputs: INPUTS } })} />);
    const toggle = screen.getByRole('button', { name: /Inputs · 3/ });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByRole('region', { name: 'Pipeline inputs' })).toBeNull();
    fireEvent.click(toggle);
    const panel = screen.getByRole('region', { name: 'Pipeline inputs' });
    expect(within(panel).getByRole('link', { name: 'Trail queue' })).toBeTruthy();
  });

  it('keeps the source chip when inputs are not wired', () => {
    routed(<PipelineEditor {...props()} />);
    expect(screen.queryByRole('button', { name: /Inputs ·/ })).toBeNull();
  });
});

describe('Pipelines list inputs column', () => {
  const pipeline: PipelineSummary = { id: SOURCE, name: 'CloudTrail', description: '', sourceId: SOURCE, sourceName: 'CloudTrail', sourceType: 'aws_cloudtrail', activeRevision: 3, draftRevision: 4, hasDraft: false, health: 'healthy', latestRelease: null };
  const base = { pipelines: [pipeline], loading: false, canCreate: true, onCreate: vi.fn(), onOpen: vi.fn(), onRetry: vi.fn() };

  it('shows the total and the pull share per pipeline', () => {
    render(<PipelineList {...base} inputCounts={{ [SOURCE]: { log_source_id: SOURCE, source_slugs: ['aws_cloudtrail'], push: 1, pull: 2, connectors: 1, mixed_processes: true } }} />);
    const cell = screen.getByTestId(`pipeline-inputs-${SOURCE}`);
    expect(cell.textContent).toBe('42 pull');
    expect(cell.getAttribute('title')).toBe('1 push · 2 pull · 1 connector');
  });

  it('shows a dash when counts are unavailable', () => {
    render(<PipelineList {...base} />);
    expect(screen.getByRole('columnheader', { name: 'Inputs' })).toBeTruthy();
    expect(screen.queryByTestId(`pipeline-inputs-${SOURCE}`)).toBeNull();
  });
});

describe('Pipe inputs hooks and lane lookup', () => {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{children}</QueryClientProvider>
  );

  it('loads one lane and answers null on an older backend (404)', async () => {
    const { usePipeLaneInputs } = await import('@/hooks/use-pipe-inputs');
    mocks.inputs.mockResolvedValueOnce(INPUTS);
    const first = renderHook(() => usePipeLaneInputs(SOURCE), { wrapper });
    await waitFor(() => expect(first.result.current.data).toEqual(INPUTS));
    expect(mocks.inputs).toHaveBeenCalledWith(SOURCE, expect.anything());
    mocks.inputs.mockRejectedValueOnce(Object.assign(new Error('Not found'), { status: 404 }));
    const missing = renderHook(() => usePipeLaneInputs(SOURCE), { wrapper });
    await waitFor(() => expect(missing.result.current.isSuccess).toBe(true));
    expect(missing.result.current.data).toBeNull();
  });

  it('surfaces other failures and does not query without a source', async () => {
    const { usePipeLaneInputs, usePipeInputSummary } = await import('@/hooks/use-pipe-inputs');
    mocks.inputSummary.mockRejectedValueOnce(Object.assign(new Error('forbidden'), { status: 403 }));
    const summary = renderHook(() => usePipeInputSummary(), { wrapper });
    await waitFor(() => expect(summary.result.current.error?.message).toBe('forbidden'));
    renderHook(() => usePipeLaneInputs(undefined), { wrapper });
    expect(mocks.inputs).not.toHaveBeenCalled();
  });

  it('normalizes the typed inputs into routable inputs (NAN-3625)', async () => {
    const { laneInputsFrom } = await import('@/lib/api/pipelines');
    const ids = laneInputsFrom(INPUTS).map((input) => [input.kind, input.id]);
    expect(ids).toContainEqual(['feed', 'push:f33d0000-0000-4000-8000-000000000009']);
    expect(ids).toContainEqual(['pull', `pull:${INPUTS.pull[0].id}`]);
    expect(ids).toContainEqual(['push', `push:${INPUTS.push[0].credential_id}`]);
  });

  it('maps a lane label back to its pipeline', () => {
    const summary: PipeLaneInputSummary = { sources: [
      { log_source_id: 'lsrc_a', source_slugs: ['aws_cloudtrail'], push: 0, pull: 1, connectors: 0, mixed_processes: false },
      { log_source_id: 'lsrc_b', source_slugs: ['okta'], push: 1, pull: 0, connectors: 0, mixed_processes: false },
    ] };
    expect(pipelinesForSlug(summary, 'AWS_CloudTrail ')).toEqual(['lsrc_a']);
    expect(pipelinesForSlug(summary, 'gcp_audit')).toEqual([]);
    expect(pipelinesForSlug(undefined, 'okta')).toEqual([]);
  });
});

describe('Per-process state warning on dedupe and combine', () => {
  const step = (kind: 'dedupe' | 'combine' | 'vrl') => ({ id: kind, name: kind, kind, enabled: true, config: kind === 'dedupe' ? { fields: ['message'], cacheEvents: 1000 } : kind === 'combine' ? { keys: ['src_endpoint.ip'], merge: {}, maxEvents: 100, timeoutSec: 5 } : { code: '.' } });
  const title = 'Push and pull inputs keep separate state';

  it('warns on dedupe and combine when the lane mixes push and pull inputs', () => {
    const { unmount } = render(<PipelineStepSettings step={step('dedupe')} readOnly={false} supported onChange={vi.fn()} mixedInputs />);
    expect(screen.getByText(title)).toBeTruthy();
    expect(screen.getByText(/duplicate that arrives once by push and once by pull is not removed/)).toBeTruthy();
    unmount();
    render(<PipelineStepSettings step={step('combine')} readOnly={false} supported onChange={vi.fn()} mixedInputs />);
    expect(screen.getByText(/never combined into the same group/)).toBeTruthy();
  });

  it('stays quiet for other steps and for single-process lanes', () => {
    const { unmount } = render(<PipelineStepSettings step={step('vrl')} readOnly={false} supported onChange={vi.fn()} mixedInputs />);
    expect(screen.queryByText(title)).toBeNull();
    unmount();
    render(<PipelineStepSettings step={step('dedupe')} readOnly={false} supported onChange={vi.fn()} />);
    expect(screen.queryByText(title)).toBeNull();
  });

  it('passes the lane mix from the editor inputs to the step settings', () => {
    const editorProps: PipelineEditorProps = {
      pipeline: { id: SOURCE, name: 'CloudTrail', description: '', sourceId: SOURCE, sourceName: 'CloudTrail', sourceType: 'aws_cloudtrail', activeRevision: 3, draftRevision: 4, hasDraft: false, health: 'healthy', latestRelease: null },
      draft: { name: 'CloudTrail', description: '', revision: 4, steps: [step('dedupe')] as PipelineEditorProps['draft']['steps'] },
      capabilities: { ...capabilities, supportedSteps: ['dedupe'] }, permissions: { view: true, edit: true, capture: true, release: true }, dirty: false, samples: [],
      onDraftChange: vi.fn(), onSave: vi.fn(), onValidate: vi.fn(), onReview: vi.fn(), onHistory: vi.fn(), onCaptureStart: vi.fn(), onCaptureStop: vi.fn(),
      onFreeze: vi.fn(), onSampleSelect: vi.fn(), onPreview: vi.fn(),
    };
    const { unmount } = routed(<PipelineEditor {...editorProps} inputs={{ inputs: INPUTS }} />);
    expect(screen.getAllByText(title).length).toBeGreaterThan(0);
    unmount();
    routed(<PipelineEditor {...editorProps} inputs={{ inputs: { ...INPUTS, pull: [], mixed_processes: false } }} />);
    expect(screen.queryByText(title)).toBeNull();
  });
});
