// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-5005: the CrowdStrike FDR source form writes the connection_config keys
 * the backend validates (queue_url, region, start_from, checksum, tuning) and
 * binds an AWS credential.
 */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error { status?: number },
  api: {
    listCredentials: async () => ({ credentials: [] }),
    listSourceConfigs: async () => [],
    connectorFeeds: { list: async () => [], listSpecs: async () => [] },
    listCredentialVersions: async () => ({ versions: [] }),
  },
}));
import { SourceConfigForm } from './SourceConfigForm';

afterEach(cleanup);

function renderForm(config: Record<string, unknown> = {}) {
  const onConfigChange = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <SourceConfigForm
          sourceType="crowdstrike_fdr"
          config={config}
          onConfigChange={onConfigChange}
          credentialId={undefined}
          onCredentialChange={vi.fn()}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return onConfigChange;
}

it('edits the FDR queue URL', () => {
  const onConfigChange = renderForm({ start_from: 'beginning' });
  const queue = screen.getByPlaceholderText(/cs-mav-cannon-queue/);
  fireEvent.change(queue, { target: { value: 'https://sqs.us-west-2.amazonaws.com/1/q' } });
  expect(onConfigChange).toHaveBeenLastCalledWith({
    start_from: 'beginning',
    queue_url: 'https://sqs.us-west-2.amazonaws.com/1/q',
  });
});

it('defaults to reading the region from the queue URL and starting from the beginning', () => {
  renderForm();
  expect(screen.getByText('From queue URL')).toBeTruthy();
  expect(screen.getByText('Everything on the queue (default)')).toBeTruthy();
});

it('clears an emptied tuning number instead of sending 0', () => {
  const onConfigChange = renderForm({ file_concurrency: 8 });
  fireEvent.change(screen.getByPlaceholderText('4'), { target: { value: '' } });
  expect(onConfigChange).toHaveBeenLastCalledWith({ file_concurrency: undefined });
});

it('binds an AWS credential', async () => {
  renderForm();
  expect(await screen.findByText(/None \(use environment \/ IAM role\)/)).toBeTruthy();
});
