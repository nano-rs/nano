// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-4941: a pull source's credential is entered, rotated and managed in
 * place from its picker; the secret is only ever shown masked.
 */
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  ApiClientError: class extends Error { status?: number },
  api: {
    listCredentials: async () => ({
      credentials: [
        { id: 'cred_aws', name: 'AWS prod', provider: 'aws_s3', active_version: 3, created_at: '', updated_at: '' },
        { id: 'cred_gcp', name: 'GCP prod', provider: 'gcp_pubsub', active_version: 1, created_at: '', updated_at: '' },
      ],
    }),
    listSourceConfigs: async () => [],
    connectorFeeds: { list: async () => [], listSpecs: async () => [] },
    listCredentialVersions: async () => ({ versions: [] }),
  },
}));
import { CredentialPicker, credentialProviderFor } from './CredentialPicker';

afterEach(cleanup);

function renderPicker(value?: string) {
  const onChange = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter><CredentialPicker provider="aws_s3" value={value} onChange={onChange} /></MemoryRouter>
    </QueryClientProvider>,
  );
  return onChange;
}

it('maps source configuration types to the credential provider they read with', () => {
  expect(credentialProviderFor('aws_sqs')).toBe('aws_s3');
  expect(credentialProviderFor('azure_event_hubs')).toBe('azure_event_hubs');
  expect(credentialProviderFor('http')).toBeNull();
});

it('enters a new secret inline, with the provider locked to the picker', async () => {
  renderPicker();
  fireEvent.click(await screen.findByRole('button', { name: /Enter new/ }));
  const sheet = await screen.findByTestId('add-credential-sheet');
  expect(within(sheet).getByRole('button', { name: /AWS S3/ })).toBeTruthy();
  expect(within(sheet).queryByRole('button', { name: /GCP Pub\/Sub/ })).toBeNull();
});

it('shows the selected credential masked, with rotate and manage in place', async () => {
  renderPicker('cred_aws');
  const selected = await screen.findByTestId('credential-picker-selected');
  expect(selected.textContent).toContain('••••');
  expect(selected.textContent).toContain('v3');
  fireEvent.click(within(selected).getByRole('button', { name: /Rotate/ }));
  // The rotate form, activating the next version.
  expect(await screen.findByRole('button', { name: /Rotate & activate v4/ })).toBeTruthy();
});
