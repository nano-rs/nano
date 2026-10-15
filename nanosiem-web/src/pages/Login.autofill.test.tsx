// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-3146 — the login wizard must expose the field shapes password managers
// key on: a `username` field, a real `type="password"` `current-password`
// field with the username still in the same form, and a `one-time-code` MFA
// field.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

const auth = vi.hoisted(() => ({
  state: {
    login: vi.fn(),
    loginWithOidc: vi.fn(),
    isAuthenticated: false,
    isLoading: false,
    error: null as string | null,
    clearError: vi.fn(),
    mfaPending: false,
    mfaSetupPending: false,
    challengeToken: null as string | null,
    verifyMfa: vi.fn(),
    cancelMfa: vi.fn(),
    user: null,
    pendingTenantSlug: null,
  },
}));

vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => auth.state }));
vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { sso: false } }),
}));
vi.stubGlobal('__APP_VERSION__', '0.0.0-test');

import { Login } from './Login';

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify({ localPassword: true }), { status: 200 })),
  );
  auth.state.mfaPending = false;
  auth.state.login.mockResolvedValue(undefined);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function renderLogin(tenantSlug?: string) {
  return render(
    <MemoryRouter>
      <Login tenantSlug={tenantSlug} />
    </MemoryRouter>,
  );
}

function form(): HTMLFormElement {
  const el = document.querySelector('form');
  if (!el) throw new Error('login form not rendered');
  return el;
}

async function promptInput(id: string): Promise<HTMLInputElement> {
  let el: HTMLInputElement | null = null;
  await waitFor(() => {
    el = document.getElementById(id) as HTMLInputElement | null;
    expect(el).toBeTruthy();
  });
  return el!;
}

async function submit(input: HTMLInputElement, value: string) {
  fireEvent.change(input, { target: { value } });
  await act(async () => {
    fireEvent.submit(form());
  });
}

it('email step is a username field', async () => {
  renderLogin();
  const input = await promptInput('username');
  expect(input.type).toBe('text');
  expect(input.name).toBe('username');
  expect(input.getAttribute('autocomplete')).toBe('username');
  expect(input.getAttribute('inputmode')).toBe('email');
  expect(form().querySelector('input[type="password"]')).toBeNull();
});

it('password step is a real current-password field with the username in the same form', async () => {
  renderLogin();
  const email = await promptInput('username');
  await submit(email, 'analyst@example.com');

  const password = await promptInput('password');
  expect(password.type).toBe('password');
  expect(password.name).toBe('password');
  expect(password.getAttribute('autocomplete')).toBe('current-password');
  // Not a transparent overlay: the native field renders its own bullets.
  expect(password.className).not.toMatch(/text-transparent/);
  expect(password.form).toBe(form());

  const username = form().querySelector<HTMLInputElement>('input[name="username"]');
  expect(username).toBeTruthy();
  expect(username!.value).toBe('analyst@example.com');
  expect(username!.getAttribute('autocomplete')).toBe('username');
  expect(username!.readOnly).toBe(true);
  expect(username!.hidden).toBe(false);
  expect(username!.className).toContain('sr-only');
  expect(username!.tabIndex).toBe(-1);
  // A fresh element per step, not the email input re-typed.
  expect(password).not.toBe(email);
});

it('mfa step is a one-time-code field', async () => {
  const { rerender } = renderLogin();
  await submit(await promptInput('username'), 'analyst@example.com');
  await submit(await promptInput('password'), 'hunter2-hunter2');
  expect(auth.state.login).toHaveBeenCalledWith('analyst@example.com', 'hunter2-hunter2', undefined);

  auth.state.mfaPending = true;
  rerender(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  );

  const otp = await promptInput('otp');
  expect(otp.type).toBe('text');
  expect(otp.name).toBe('otp');
  expect(otp.getAttribute('autocomplete')).toBe('one-time-code');
  expect(otp.getAttribute('inputmode')).toBe('numeric');
  expect(form().querySelector('input[type="password"]')).toBeNull();
  expect(form().querySelector<HTMLInputElement>('input[name="username"]')!.value).toBe(
    'analyst@example.com',
  );
});

// NAN-3238 — the NAN-3146 username field makes the password-step form hold
// two text-like fields, so HTML implicit submission (Enter) only fires if the
// form has a submit button. Drive a real keyboard Enter, not fireEvent.submit.
it('pressing Enter in the password field submits the login', async () => {
  const user = userEvent.setup();
  renderLogin('acme');
  await user.type(await promptInput('username'), 'analyst@example.com{enter}');

  const password = await promptInput('password');
  await user.type(password, 'hunter2-hunter2{enter}');

  await waitFor(() =>
    expect(auth.state.login).toHaveBeenCalledWith('analyst@example.com', 'hunter2-hunter2', 'acme'),
  );
  expect(form().querySelector('button[type="submit"]')).toBeTruthy();
});
