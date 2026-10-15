// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-3807: OCSF bucket drop source status on Ingestion → Credentials (open core). */
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const calls = vi.hoisted(() => ({ list: vi.fn(), files: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { landingSources: calls } }));

import { ADD_LANDING_SOURCE_COMMAND, LandingSourcesPanel, keyTail } from './LandingSourcesPanel';

const SOURCE = {
  source_id: '6f1e0b8f-6a52-4c55-9a3e-2f1d7c9b1a01',
  name: 'tenzir-edge',
  route_key: 'tenzir_edge',
  credential_id: '9a3e6f1e-0b8f-4c55-6a52-2f1d7c9b1a01',
  state: 'active',
  created_at: '2026-10-13T16:00:00Z',
  files_accepted: 1200,
  files_refused: 3,
  files_in_progress: 1,
  rows_accepted: 4500000,
  rows_refused: 17,
  redeliveries: 0,
  last_seen_at: '2026-10-14T12:00:00Z',
  last_finished_at: '2026-10-14T12:00:05Z',
  last_refusal_reason: 'not_ocsf_json',
  last_refusal_at: '2026-10-14T11:00:00Z',
};

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <LandingSourcesPanel />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  calls.list.mockResolvedValue({ sources: [SOURCE] });
  calls.files.mockResolvedValue({
    files: [
      {
        id: 7,
        object_key: `landing-ocsf-v1/tenant_id=t/source=${SOURCE.source_id}/2026/10/14/batch-0001.json.zst`,
        etag: 'e1',
        source_id: SOURCE.source_id,
        size_bytes: 1024,
        state: 'refused',
        rows_accepted: 0,
        rows_refused: 17,
        reason: 'not_ocsf_json',
        attempts: 1,
        redeliveries: 0,
        first_seen_at: '2026-10-14T11:00:00Z',
        finished_at: '2026-10-14T11:00:02Z',
      },
    ],
  });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('renders one dense row per source with counts and the last refusal code', async () => {
  renderPanel();
  const row = await screen.findByTestId('landing-source-row');
  expect(screen.getByText('Bucket drop sources (Tenzir)')).toBeTruthy();
  expect(within(row).getByText('tenzir-edge')).toBeTruthy();
  expect(within(row).getByText('tenzir_edge')).toBeTruthy();
  expect(within(row).getByText('not_ocsf_json')).toBeTruthy();
  expect(row.textContent).toContain('4,500,000');
  expect(row.textContent).toContain('2026-10-14 12:00');
  expect(document.body.textContent).not.toMatch(/splunk/i);
});

it('expands to the recent files of a source', async () => {
  renderPanel();
  const row = await screen.findByTestId('landing-source-row');
  fireEvent.click(within(row).getByRole('button', { name: /Show files for tenzir-edge/ }));
  const fileRow = await screen.findByTestId('landing-file-row');
  await waitFor(() => expect(calls.files).toHaveBeenCalledWith(SOURCE.source_id, { limit: 25 }));
  expect(within(fileRow).getByText('2026/10/14/batch-0001.json.zst')).toBeTruthy();
  expect(within(fileRow).getByText('refused')).toBeTruthy();
});

it('shows the CLI command when there are no sources', async () => {
  calls.list.mockResolvedValue({ sources: [] });
  renderPanel();
  const empty = await screen.findByTestId('landing-sources-empty');
  expect(empty.textContent).toContain(ADD_LANDING_SOURCE_COMMAND);
  expect(ADD_LANDING_SOURCE_COMMAND).toBe('docker compose run --rm lean-landing-admin add --name <name>');
});

it('trims object keys to the part below the source folder', () => {
  expect(keyTail('landing-ocsf-v1/tenant_id=t/source=abc/x/y.json')).toBe('x/y.json');
  expect(keyTail('short.json')).toBe('short.json');
  expect(keyTail('a'.repeat(80))).toBe(`…${'a'.repeat(64)}`);
});
