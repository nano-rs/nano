// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5443 — the lookup URL allowlist page: merged/locked display, add and
// remove through the API, read-only without settings:system.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import type { LookupAllowlistSettings } from '@/lib/api/lookup-url-allowlist';
import { isLookupAllowlistRefusal } from '@/lib/api/lookup-url-allowlist';

const mock = vi.hoisted(() => ({
  canManage: true,
  get: vi.fn(),
  update: vi.fn(),
  toast: vi.fn(),
}));

vi.mock('@/lib/api', () => ({
  api: { lookupUrlAllowlist: { get: mock.get, update: mock.update } },
}));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => p !== 'settings:system' || mock.canManage }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mock.toast }) }));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }));

import { LookupUrls } from './LookupUrls';

function settings(over: Partial<LookupAllowlistSettings> = {}): LookupAllowlistSettings {
  const domains = over.domains ?? ['feeds.example.com'];
  const deployment = over.deployment_domains ?? ['ops.example.com'];
  const locked = over.locked ?? false;
  const effective = over.effective ?? [...new Set([...deployment, ...(locked ? [] : domains)])].sort();
  return {
    domains,
    deployment_domains: deployment,
    locked,
    effective,
    mode: effective.length ? 'allowlist' : 'any_public_host',
    max_domains: 256,
    refresh_interval_secs: 30,
    ...over,
  };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <LookupUrls />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mock.canManage = true;
  mock.get.mockReset();
  mock.update.mockReset();
  mock.toast.mockReset();
});
afterEach(cleanup);

test('shows both lists, their sources and the effective mode', async () => {
  mock.get.mockResolvedValue(settings());
  renderPage();
  expect(await screen.findByText('feeds.example.com')).toBeTruthy();
  expect(screen.getByText('ops.example.com')).toBeTruthy();
  expect(screen.getByTestId('lookup-mode').textContent).toBe('allowlist · 2 hosts');
  // Only settings rows are removable.
  expect(screen.getByLabelText('Remove feeds.example.com')).toBeTruthy();
  expect(screen.queryByLabelText('Remove ops.example.com')).toBeNull();
});

test('adds a host by saving the full admin list', async () => {
  mock.get.mockResolvedValue(settings());
  mock.update.mockResolvedValue(settings({ domains: ['feeds.example.com', 'intel.example.org'] }));
  renderPage();
  await screen.findByText('feeds.example.com');
  fireEvent.change(screen.getByLabelText('Host to allow'), { target: { value: ' intel.example.org ' } });
  fireEvent.click(screen.getByText('Add host'));
  await waitFor(() => expect(mock.update).toHaveBeenCalledWith(['feeds.example.com', 'intel.example.org']));
  expect(await screen.findByText('intel.example.org')).toBeTruthy();
});

test('removing a host asks first, then saves the list without it', async () => {
  mock.get.mockResolvedValue(settings());
  mock.update.mockResolvedValue(settings({ domains: [] }));
  renderPage();
  fireEvent.click(await screen.findByLabelText('Remove feeds.example.com'));
  expect(mock.update).not.toHaveBeenCalled();
  fireEvent.click(await screen.findByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(mock.update).toHaveBeenCalledWith([]));
});

test('locked deployment list makes the page read-only', async () => {
  mock.get.mockResolvedValue(settings({ locked: true }));
  renderPage();
  await screen.findByText('feeds.example.com');
  expect(screen.getByText('locked by deployment')).toBeTruthy();
  expect(screen.queryByLabelText('Host to allow')).toBeNull();
  expect(screen.queryByLabelText('Remove feeds.example.com')).toBeNull();
  expect(screen.getByText('settings · ignored')).toBeTruthy();
});

test('without settings:system the list is read-only', async () => {
  mock.canManage = false;
  mock.get.mockResolvedValue(settings({ domains: [], deployment_domains: [] }));
  renderPage();
  expect(await screen.findByText('No hosts listed.')).toBeTruthy();
  expect(screen.getByTestId('lookup-mode').textContent).toBe('any public host');
  expect(screen.queryByLabelText('Host to allow')).toBeNull();
});

test('search errors from the allowlist are recognized for the Settings link', () => {
  expect(
    isLookupAllowlistRefusal(
      "inputlookup failed for URL 'x': Fetch error: outbound lookup to host 'a.test' is not permitted: it is not in the lookup URL allowlist. An administrator can add it in Settings > Lookup URLs (/settings/lookup-urls)",
    ),
  ).toBe(true);
  expect(isLookupAllowlistRefusal('Syntax error near |')).toBe(false);
  expect(isLookupAllowlistRefusal(undefined)).toBe(false);
});
