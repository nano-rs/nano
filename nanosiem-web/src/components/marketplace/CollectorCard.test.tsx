// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4970: the Marketplace pull-collector install sheet renders the identity
 * shrink-guard override (`identity_allow_shrink`) as a checkbox, never as a
 * free-text config field: left out unless checked, boolean `true` when checked.
 */
import { afterEach, beforeAll, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ConnectorSpecInfo } from '@/lib/api/connector-feeds';

const calls = vi.hoisted(() => ({ create: vi.fn() }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/lib/api', () => ({
  api: {
    connectorFeeds: { create: calls.create },
    listCredentials: async () => ({ credentials: [] }),
  },
}));
import { CollectorCard } from './CollectorCard';

const permissions = { installExisting: true, installNew: true, toggle: true, remove: true, rotate: true };
const identity = {
  name: 'okta_users', display_name: 'Okta directory', kind: 'identity', credential_provider: 'okta', source_type: 'identity',
  schedule: '0 * * * *', config_fields: ['OKTA_DOMAIN', 'identity_allow_shrink'],
  optional_config_fields: ['identity_allow_shrink'], credential_fields: ['API_TOKEN'],
} as unknown as ConnectorSpecInfo;

beforeAll(() => {
  // jsdom lacks ResizeObserver (Radix Checkbox).
  globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver;
  // jsdom lacks matchMedia (FormSheet's useIsMobile): desktop.
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false, media: query, onchange: null, addEventListener: () => {}, removeEventListener: () => {},
        addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
      }),
    });
  }
});
beforeEach(() => calls.create.mockResolvedValue({ id: 'cfeed_1' }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

function openInstall(spec: ConnectorSpecInfo = identity) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>
        <CollectorCard spec={spec} feeds={[]} feedStatus={{ isError: false, isPending: false }} permissions={permissions} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByText('Install'));
  const sheet = screen.getByRole('dialog');
  fireEvent.change(within(sheet).getByLabelText(/Okta domain/i), { target: { value: 'acme.okta.com' } });
  fireEvent.change(within(sheet).getByLabelText(/Api token/i), { target: { value: 'tok' } });
  return sheet;
}

function submit(sheet: HTMLElement) {
  const install = within(sheet).getAllByRole('button', { name: /^Install$/ }).at(-1) as HTMLButtonElement;
  expect(install.disabled).toBe(false);
  fireEvent.click(install);
}

it('shows identity_allow_shrink as an unchecked checkbox, not a text field, and leaves it out', async () => {
  const sheet = openInstall();
  expect(within(sheet).queryByLabelText(/Identity allow shrink/i)).toBeNull();
  const box = within(sheet).getByRole('checkbox', { name: /drop more than half/ });
  expect(box.getAttribute('aria-checked')).toBe('false');
  submit(sheet);
  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0].config).toEqual({ OKTA_DOMAIN: 'acme.okta.com' });
});

it('sends identity_allow_shrink as boolean true when checked', async () => {
  const sheet = openInstall();
  fireEvent.click(within(sheet).getByRole('checkbox', { name: /drop more than half/ }));
  submit(sheet);
  await vi.waitFor(() => expect(calls.create).toHaveBeenCalledTimes(1));
  expect(calls.create.mock.calls[0][0].config).toEqual({ OKTA_DOMAIN: 'acme.okta.com', identity_allow_shrink: true });
});

it('shows no checkbox for a collector spec without the flag', () => {
  const sheet = openInstall({
    ...identity, name: 'okta_system_log', display_name: 'Okta System Log', kind: 'collector', source_type: 'okta',
    config_fields: ['OKTA_DOMAIN'], optional_config_fields: [],
  } as unknown as ConnectorSpecInfo);
  expect(within(sheet).queryByRole('checkbox')).toBeNull();
});
