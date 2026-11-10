// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/** NAN-5237: the first-run page asks for the installer's setup token when the server requires it. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { Setup } from './Setup';

const PASSWORD = 'Setup-Token-5237-ok!';

type Call = { url: string; init?: RequestInit };
let calls: Call[] = [];

function mockFetch(status: Record<string, unknown>) {
  calls = [];
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    if (url.endsWith('/api/setup/status')) {
      return new Response(JSON.stringify(status), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({ success: true, message: 'ok', user_id: 'user_x' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }));
}

function renderSetup() {
  return render(
    <MemoryRouter>
      <Setup />
    </MemoryRouter>,
  );
}

function fillAccount() {
  fireEvent.change(screen.getByLabelText('Full Name'), { target: { value: 'Admin' } });
  fireEvent.change(screen.getByLabelText('Email Address'), { target: { value: 'admin@example.com' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: PASSWORD } });
  fireEvent.change(screen.getByLabelText('Confirm Password'), { target: { value: PASSWORD } });
}

function initializeCall(): Call | undefined {
  return calls.find((c) => c.url.endsWith('/api/setup/initialize'));
}

beforeEach(() => vi.useRealTimers());
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Setup page setup token', () => {
  it('shows a password-type token field when required and sends it as the bearer', async () => {
    mockFetch({ initialized: false, has_users: false, setup_token_required: true });
    renderSetup();
    const token = await screen.findByLabelText('Setup token');
    expect(token.getAttribute('type')).toBe('password');
    expect(screen.getByText(/Printed by the installer/)).toBeTruthy();

    fillAccount();
    fireEvent.change(token, { target: { value: '  abc123token  ' } });
    fireEvent.click(screen.getByRole('button', { name: /Create Admin Account/ }));

    await waitFor(() => expect(initializeCall()).toBeTruthy());
    const headers = initializeCall()!.init!.headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer abc123token');
    expect(String(initializeCall()!.init!.body)).not.toContain('abc123token');
  });

  it('refuses to submit without the token when one is required', async () => {
    mockFetch({ initialized: false, has_users: false, setup_token_required: true });
    renderSetup();
    await screen.findByLabelText('Setup token');
    fillAccount();
    fireEvent.click(screen.getByRole('button', { name: /Create Admin Account/ }));
    expect(await screen.findByText('Setup token is required')).toBeTruthy();
    expect(initializeCall()).toBeUndefined();
  });

  it('hides the field and sends no bearer when no token is required', async () => {
    mockFetch({ initialized: false, has_users: false, setup_token_required: false });
    renderSetup();
    await screen.findByLabelText('Full Name');
    expect(screen.queryByLabelText('Setup token')).toBeNull();
    fillAccount();
    fireEvent.click(screen.getByRole('button', { name: /Create Admin Account/ }));
    await waitFor(() => expect(initializeCall()).toBeTruthy());
    const headers = initializeCall()!.init!.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });
});
