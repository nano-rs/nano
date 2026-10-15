// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { expect, test, vi } from 'vitest';
import { LookupUrlAllowlist } from './LookupUrlAllowlist';

const mock = vi.hoisted(() => ({
  getLookupUrlAllowlist: vi.fn(), addLookupUrlHost: vi.fn(), removeLookupUrlHost: vi.fn(),
}));
vi.mock('@/lib/api', () => ({ api: { lookupUrlAllowlist: { get: mock.getLookupUrlAllowlist, add: mock.addLookupUrlHost, remove: mock.removeLookupUrlHost } } }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ user: { deployment_mode: 'enterprise_shared' } }) }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));

test('shows empty default, inline validation, attribution and removal', async () => {
  mock.getLookupUrlAllowlist.mockResolvedValue({ entries: [] });
  mock.addLookupUrlHost.mockRejectedValueOnce(new Error('internal hostnames are forbidden'));
  mock.addLookupUrlHost.mockResolvedValueOnce({});
  mock.removeLookupUrlHost.mockResolvedValue({});
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><LookupUrlAllowlist /></QueryClientProvider>);
  await screen.findByText('No hosts allowed.');
  fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'a.internal' } });
  fireEvent.click(screen.getByText('Add host'));
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'internal hostnames are forbidden');
  mock.getLookupUrlAllowlist.mockResolvedValue({ entries: [{ host: 'intel.example.com', note: 'Daily intel', created_by: 'admin-uuid', created_at: '2026-10-02T12:00:00Z' }] });
  fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'intel.example.com' } });
  fireEvent.change(screen.getByLabelText('Note'), { target: { value: 'Daily intel' } });
  await waitFor(() => expect((screen.getByText('Add host') as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(screen.getByText('Add host'));
  await screen.findByText('admin-uuid');
  expect(mock.addLookupUrlHost).toHaveBeenLastCalledWith('intel.example.com', 'Daily intel');
  fireEvent.click(screen.getByLabelText('Remove intel.example.com'));
  await waitFor(() => expect(mock.removeLookupUrlHost).toHaveBeenCalledWith('intel.example.com'));
});
