// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5900: the "Admin (all permissions)" preset in the create dialog. Only a
 * creator holding every permission can pick it, it needs a confirm tick and an
 * expiry, and it sends `preset: "admin"` (no list) so the server resolves it.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
const apiMock = vi.hoisted(() => ({ createApiKey: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: apiMock }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

import type { PermissionInfo } from '@/lib/api';
import { CreateApiKeyDialog } from './CreateApiKeyDialog';
import { adminPresetMissing, canUseAdminPreset, isAdminKey } from './admin-preset';

const CATALOGUE: PermissionInfo[] = ['alerts:view', 'search:execute', 'users:view', 'roles:edit'].map(id => ({
  id,
  name: id,
  category: id.split(':')[0],
  description: id,
}));
const ALL = CATALOGUE.map(p => p.id);

function renderDialog() {
  const onCreated = vi.fn();
  render(<CreateApiKeyDialog open permissions={CATALOGUE} onClose={vi.fn()} onCreated={onCreated} />);
  fireEvent.change(screen.getByPlaceholderText('e.g. ci-deploy-robot'), { target: { value: 'kestrel-automation' } });
  return { onCreated };
}

function createButton() {
  return screen.getByRole('button', { name: /create key/i });
}

afterEach(() => {
  cleanup();
  perms.value = new Set();
  apiMock.createApiKey.mockReset();
});

describe('CreateApiKeyDialog admin preset (NAN-5900)', () => {
  it('an admin picks the preset, confirms, and sends preset=admin with an expiry', async () => {
    perms.value = new Set(ALL);
    apiMock.createApiKey.mockResolvedValue({ id: 'k', key: 'secret', name: 'kestrel-automation', key_prefix: 'nano_', created_at: '' });
    const { onCreated } = renderDialog();

    fireEvent.click(screen.getByTestId('admin-preset'));
    expect(screen.getByTestId('admin-preset-summary').textContent).toContain('This key can do anything an admin can.');
    expect(screen.getByTestId('admin-preset-summary').textContent).toContain('not added to this key on their own');
    // An API key can't manage other API keys (key management is session-only).
    expect(screen.getByTestId('admin-preset-summary').textContent).not.toContain("settings and other API keys");
    expect(screen.getByTestId('admin-preset-summary').textContent).toContain("can't create, rotate or change other API keys");
    // "Never" is not offered for an admin key.
    expect(screen.queryByRole('button', { name: 'Never' })).toBeNull();
    // The confirm tick is required.
    expect((createButton() as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId('admin-preset-confirm'));
    expect((createButton() as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(createButton());
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    const body = apiMock.createApiKey.mock.calls[0][0];
    expect(body.preset).toBe('admin');
    expect(body.permissions).toEqual([]);
    expect(typeof body.expires_at).toBe('string');
  });

  it('switching to admin moves a "Never" expiry to a real one', () => {
    perms.value = new Set(ALL);
    renderDialog();
    fireEvent.click(screen.getByRole('button', { name: 'Never' }));
    fireEvent.click(screen.getByTestId('admin-preset'));
    fireEvent.click(screen.getByTestId('admin-preset-confirm'));
    fireEvent.click(createButton());
    const body = apiMock.createApiKey.mock.calls[0][0];
    expect(body.expires_at).toBeDefined();
  });

  it('a creator missing any permission cannot pick the preset', () => {
    perms.value = new Set(ALL.filter(p => p !== 'users:view'));
    renderDialog();
    const card = screen.getByTestId('admin-preset');
    expect((card as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(card);
    expect(screen.queryByTestId('admin-preset-summary')).toBeNull();
    expect(screen.getByTestId('admin-preset-unavailable').textContent).toContain('missing 1');
  });

  it('the custom path still sends a hand-picked list and no preset', async () => {
    perms.value = new Set(ALL);
    apiMock.createApiKey.mockResolvedValue({ id: 'k', key: 's', name: 'n', key_prefix: 'p', created_at: '' });
    const { onCreated } = renderDialog();
    fireEvent.click(createButton());
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    const body = apiMock.createApiKey.mock.calls[0][0];
    expect(body.preset).toBeUndefined();
    expect(body.permissions).toEqual(['alerts:view', 'users:view']);
  });
});

describe('admin-preset helpers', () => {
  it('reports what the creator lacks and labels full keys', () => {
    expect(adminPresetMissing(CATALOGUE, p => p !== 'roles:edit')).toEqual(['roles:edit']);
    expect(canUseAdminPreset(CATALOGUE, () => true)).toBe(true);
    expect(canUseAdminPreset([], () => true)).toBe(false);
    expect(isAdminKey(ALL, CATALOGUE)).toBe(true);
    expect(isAdminKey(ALL.slice(1), CATALOGUE)).toBe(false);
    expect(isAdminKey(ALL, [])).toBe(false);
  });
});
