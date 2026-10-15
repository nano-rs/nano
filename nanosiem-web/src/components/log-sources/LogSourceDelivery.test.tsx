// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3661: Log Source → Delivery panel (pull sources + connector feeds into the lane). */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { PipeConnectorInput, PipeLaneInputs, PipePullInput } from '@/lib/api/pipelines';
import { LogSourceDeliveryPanel, skippedBacklogNote } from './LogSourceDelivery';

const mocks = vi.hoisted(() => ({ retry: vi.fn(), resume: vi.fn() }));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ user: { id: 'u', active_tenant: { id: 't' } }, hasPermission: () => true }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  api: { pullSources: { retry: mocks.retry, resume: mocks.resume, pause: vi.fn(), remove: vi.fn() } },
  ApiClientError: class extends Error {},
}));

const at = new Date(Date.now() - 20 * 60_000).toISOString();

function pull(over: Partial<PipePullInput>): PipePullInput {
  return {
    id: 'pull-1', name: 'CloudTrail org', provider: 'aws_s3_sqs', source_slug: 'aws_cloudtrail', state: 'active',
    last_error: null, verified_at: at, updated_at: at, ...over,
  };
}

function feed(over: Partial<PipeConnectorInput>): PipeConnectorInput {
  return {
    id: 'feed-1', name: 'Workspace audit', connector: 'google-workspace', source_slug: 'gws_audit', enabled: true,
    status: 'success', last_run_at: at, last_success_at: at, last_error: null, next_run_at: at, marketplace: true,
    ingest_credential_id: null, ...over,
  };
}

function inputs(pulls: PipePullInput[], feeds: PipeConnectorInput[] = []): PipeLaneInputs {
  return { log_source_id: 'lsrc_x', source_slugs: ['aws_cloudtrail'], push: [], pull: pulls, connectors: feeds, mixed_processes: false };
}

function renderPanel(props: Partial<Parameters<typeof LogSourceDeliveryPanel>[0]> & { inputs: PipeLaneInputs | null | undefined }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <LogSourceDeliveryPanel canEdit {...props} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('LogSourceDeliveryPanel', () => {
  it('shows a healthy pull with its last verification and no error', () => {
    renderPanel({ inputs: inputs([pull({})]) });
    const row = screen.getByTestId('delivery-pull-pull-1');
    expect(within(row).getByTestId('pull-state').textContent).toBe('active');
    expect(within(row).getByTestId('delivery-last-success').textContent).not.toBe('not verified');
    expect(within(row).queryByTestId('delivery-error')).toBeNull();
    expect(screen.queryByTestId('delivery-attention')).toBeNull();
    expect(within(row).queryByRole('button', { name: /retry/i })).toBeNull();
  });

  it('shows a failed AWS pull with the code in mono, the ExternalId hint, and Retry', async () => {
    mocks.retry.mockResolvedValue(pull({ state: 'pending_verification' }));
    renderPanel({
      inputs: inputs([pull({ state: 'failed', verified_at: null, last_error: 'assume_role_denied: the broker could not assume the role' })]),
      hintContext: { externalId: 'nano-ext-42' },
    });
    const row = screen.getByTestId('delivery-pull-pull-1');
    expect(within(row).getByTestId('pull-state').textContent).toBe('failed');
    expect(within(row).getByTestId('delivery-last-success').textContent).toBe('not verified');
    const code = within(row).getByTestId('delivery-error-code');
    expect(code.textContent).toBe('assume_role_denied');
    expect(code.className).toContain('font-mono');
    expect(within(row).getByTestId('delivery-error-hint').textContent).toContain('nano-ext-42');
    expect(within(row).getByRole('link', { name: /open aws setup/i }).getAttribute('href')).toBe('/ingestion/log-sources/cloud-pull?provider=aws');
    expect(screen.getByTestId('delivery-attention').textContent).toBe('1 delivery failed');
    fireEvent.click(within(row).getByRole('button', { name: /retry verification for cloudtrail org/i }));
    await waitFor(() => expect(mocks.retry).toHaveBeenCalledWith('pull-1'));
  });

  it('shows a GCP project denial with its hint and the GCP setup link', () => {
    renderPanel({ inputs: inputs([pull({ provider: 'gcp_pubsub', state: 'failed', last_error: 'gcp_project_denied: x' })]) });
    const row = screen.getByTestId('delivery-pull-pull-1');
    expect(within(row).getByText('pull · GCP Pub/Sub')).toBeTruthy();
    expect(within(row).getByTestId('delivery-error-hint').textContent).toMatch(/GCP project can't be used/);
    expect(within(row).getByRole('link', { name: /open gcp setup/i }).getAttribute('href')).toContain('provider=gcp');
  });

  it('shows a blocked pull (no parser lane) without a retry button', () => {
    renderPanel({ inputs: inputs([pull({ state: 'pending_bundle', last_error: 'no_parser_lane: aws_cloudtrail has no parser' })]) });
    const row = screen.getByTestId('delivery-pull-pull-1');
    expect(within(row).getByTestId('pull-state').textContent).toBe('blocked');
    expect(within(row).getByTestId('delivery-error-hint').textContent).toMatch(/No parser serves this lane/);
    expect(within(row).queryByRole('button', { name: /retry/i })).toBeNull();
    expect(screen.getByTestId('delivery-attention').textContent).toBe('1 delivery blocked');
  });

  it('shows a paused pull with Resume', async () => {
    mocks.resume.mockResolvedValue(pull({ state: 'pending_verification' }));
    renderPanel({ inputs: inputs([pull({ state: 'paused' })]) });
    const row = screen.getByTestId('delivery-pull-pull-1');
    fireEvent.click(within(row).getByRole('button', { name: /resume cloudtrail org/i }));
    await waitFor(() => expect(mocks.resume).toHaveBeenCalledWith('pull-1'));
    expect(screen.getByTestId('delivery-attention').textContent).toBe('1 delivery paused');
  });

  it('hides retry and resume without log_sources:edit', () => {
    renderPanel({ canEdit: false, inputs: inputs([pull({ state: 'failed', last_error: 'queue_not_found: x' })]) });
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull();
    expect(screen.getByRole('link', { name: 'Cloud pull' })).toBeTruthy();
  });

  it('shows a failed connector feed with its collector link, and a disabled one', () => {
    renderPanel({
      inputs: inputs([], [
        feed({ status: 'failed', last_error: 'Collection failed; check configuration and provider access' }),
        feed({ id: 'feed-2', enabled: false, status: 'disabled' }),
      ]),
    });
    const failed = screen.getByTestId('delivery-connector-feed-1');
    expect(within(failed).getByText('failed')).toBeTruthy();
    expect(within(failed).getByTestId('delivery-error-hint').textContent).toMatch(/Open the collector/);
    expect(within(failed).getByRole('link', { name: 'Collector' }).getAttribute('href')).toBe('/marketplace?slug=google-workspace');
    expect(within(screen.getByTestId('delivery-connector-feed-2')).getByText(/Enable it on the collector page/)).toBeTruthy();
    expect(screen.getByTestId('delivery-attention').textContent).toBe('2 deliveries failed');
  });

  it('shows accepted counts and says when the lake does not report refusals', () => {
    renderPanel({ inputs: inputs([]), health: { events_last_hour: 1200, events_last_24h: 34567, last_event_at: at } });
    expect(screen.getByTestId('delivery-empty')).toBeTruthy();
    expect(screen.getByTestId('delivery-accepted-1h').textContent).toBe((1200).toLocaleString());
    expect(screen.getByTestId('delivery-accepted-24h').textContent).toBe((34567).toLocaleString());
    expect(screen.getByTestId('delivery-refused-unrecorded').textContent).toBe('refused per source: not reported by this lake');
  });

  it('shows a lean refused-only source like any other: accepted 0, refused with its cause (NAN-3662)', () => {
    renderPanel({
      inputs: inputs([]),
      health: {
        events_last_hour: 0, events_last_24h: 0, last_event_at: null,
        refused_events_24h: 100, last_refusal: { reason: 'ocsf_constraint_failed', field: 'device' },
      },
    });
    expect(screen.getByTestId('delivery-accepted-24h').textContent).toBe('0');
    expect(screen.queryByTestId('delivery-refused-unrecorded')).toBeNull();
    expect(screen.getByTestId('delivery-refused-attention').getAttribute('title'))
      .toBe('100 events refused by OCSF validation (constraint_failed at device)');
  });

  it('notes a point-forward skip on the pull row as neutral information, not a refusal (NAN-3604)', () => {
    renderPanel({ inputs: inputs([pull({ skipped_backlog: 1234 })]), health: { events_last_24h: 5, refused_events_24h: 0 } });
    const note = screen.getByTestId('delivery-skipped-backlog');
    expect(note.textContent).toBe(`${(1234).toLocaleString()} pre-activation messages skipped (point-forward start)`);
    expect(note.className).toContain('text-muted-foreground');
    expect(note.className).not.toMatch(/red|amber|orange|destructive/);
    expect(screen.queryByTestId('delivery-refused-attention')).toBeNull();
    expect(screen.queryByTestId('delivery-attention')).toBeNull();
  });

  it('shows no skip note when the backend does not report it or nothing was skipped', () => {
    renderPanel({ inputs: inputs([pull({}), pull({ id: 'pull-2', skipped_backlog: 0 })]) });
    expect(screen.queryByTestId('delivery-skipped-backlog')).toBeNull();
    expect(skippedBacklogNote(1)).toBe('1 pre-activation message skipped (point-forward start)');
    expect(skippedBacklogNote(null)).toBeNull();
    expect(skippedBacklogNote(undefined)).toBeNull();
  });

  it('shows refused rows per source as a delivery problem with the value-free cause (NAN-3680)', () => {
    renderPanel({
      inputs: inputs([]),
      health: {
        events_last_hour: 0, events_last_24h: 0, last_event_at: null,
        refused_events_24h: 100, last_refusal: { reason: 'ocsf_constraint_failed', field: 'device' },
      },
    });
    expect(screen.queryByTestId('delivery-refused-unrecorded')).toBeNull();
    expect(screen.getByTestId('delivery-refused-24h').textContent).toContain('100');
    expect(screen.getByTestId('delivery-refused-cause').textContent).toBe(' (constraint_failed at device)');
    const attention = screen.getByTestId('delivery-refused-attention');
    expect(attention.getAttribute('title')).toBe('100 events refused by OCSF validation (constraint_failed at device)');
  });

  it('shows a recorded zero without raising attention', () => {
    renderPanel({ inputs: inputs([]), health: { events_last_hour: 5, events_last_24h: 50, refused_events_24h: 0 } });
    expect(screen.getByTestId('delivery-refused-24h').textContent).toContain('0');
    expect(screen.queryByTestId('delivery-refused-attention')).toBeNull();
    expect(screen.queryByTestId('delivery-refused-cause')).toBeNull();
  });

  it('renders an older backend (no endpoint) quietly', () => {
    renderPanel({ inputs: null });
    expect(screen.getByText(/does not report deliveries yet/)).toBeTruthy();
  });

  it('never renders a secret-looking value from setup context beyond the ExternalId', () => {
    renderPanel({ inputs: inputs([pull({ state: 'failed', last_error: 'queue_access_denied: x' })]), hintContext: { externalId: 'nano-ext-42' } });
    expect(screen.getByTestId('log-source-delivery').textContent).not.toContain('nano-ext-42');
  });
});
