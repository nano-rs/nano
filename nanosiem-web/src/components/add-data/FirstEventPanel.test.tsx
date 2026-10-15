// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-2599: the first-event panel polls until searchable and explains refusals. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { IngestCredentialActivity } from '@/lib/api/types';
import { FirstEventPanel } from './FirstEventPanel';

const mocks = vi.hoisted(() => ({ getActivity: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getIngestCredentialActivity: mocks.getActivity } }));

const issuedAt = new Date(Date.now() - 20_000).toISOString();
const secs = (s: number) => new Date(Date.parse(issuedAt) + s * 1000).toISOString();
function activity(state: 'waiting' | 'received' | 'searchable', over: Partial<IngestCredentialActivity> = {}): IngestCredentialActivity {
  return {
    credential_id: 'cred-1', window_hours: 1, redacted: false,
    edge: state === 'waiting' ? null : {
      first_accepted_at: secs(3), last_accepted_at: secs(3), last_rejected_at: null, last_rejection_class: null, last_rejection_status: null,
      requests_24h: 2, events_24h: 20, bytes_24h: 2000, unknown_event_requests_24h: 0, sampled_at: null, recorded_at: null,
    },
    lake: { events: state === 'searchable' ? 20 : 0, bytes: 0, parse_failures: 0, first_event_at: null, last_event_at: null,
      first_searchable_at: state === 'searchable' ? secs(50) : null, last_searchable_at: null,
      sources: state === 'searchable' ? [{ source_slug: 'fw', protocol: 'hec', events: 20, bytes: 0, parse_failures: 0, first_event_at: secs(3), last_event_at: secs(3) }] : [],
      hours: [] },
    first_event: {
      received_at_edge: state === 'waiting' ? null : secs(3),
      searchable_at: state === 'searchable' ? secs(50) : null,
      state,
    },
    ...over,
  };
}

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <FirstEventPanel credentialId="cred-1" issuedAt={issuedAt} sourceSlugs={['fw']} parserHref="/ingestion/log-sources/ls_1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

beforeEach(() => mocks.getActivity.mockReset());
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe('FirstEventPanel', () => {
  it('polls through waiting → received → searchable, then stops', async () => {
    mocks.getActivity
      .mockResolvedValueOnce(activity('waiting'))
      .mockResolvedValueOnce(activity('received'))
      .mockResolvedValue(activity('searchable'));
    renderPanel();
    const step = (k: string) => screen.getByTestId(`first-event-step-${k}`).getAttribute('data-state');
    await waitFor(() => expect(step('received')).toBe('active'));
    await waitFor(() => expect(step('received')).toBe('done'), { timeout: 5000 });
    await waitFor(() => expect(step('searchable')).toBe('done'), { timeout: 5000 });
    expect(mocks.getActivity).toHaveBeenCalledWith('cred-1', 1);
    expect(within(screen.getByTestId('first-event-step-searchable')).getByText('+47 s')).toBeTruthy();
    const link = screen.getByTestId('first-event-search-link');
    expect(decodeURIComponent(link.getAttribute('href')!)).toContain('metadata.log_source="fw"');
    const calls = mocks.getActivity.mock.calls.length;
    await new Promise((r) => setTimeout(r, 3500));
    expect(mocks.getActivity.mock.calls.length).toBe(calls);
  }, 15000);

  it('maps a refusal and parse failures to hints with a parser link', async () => {
    const a = activity('received');
    a.edge = { ...a.edge!, last_rejected_at: secs(10), last_rejection_class: 'source_not_allowed', last_rejection_status: 403 };
    a.lake = { ...a.lake, events: 5, parse_failures: 2 };
    mocks.getActivity.mockResolvedValue(a);
    renderPanel();
    expect(await screen.findByTestId('first-event-hint-source_not_allowed')).toBeTruthy();
    expect(screen.getByTestId('first-event-hint-parse_failures')).toBeTruthy();
    expect(screen.getByTestId('first-event-parser-link').getAttribute('href')).toBe('/ingestion/log-sources/ls_1');
  });
});
