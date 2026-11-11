// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
// NAN-5273: a failed page keeps the shell, reloads once for a stale build, resets on navigation.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { RouteErrorBoundary } from './RouteErrorBoundary';
import { ProviderMissingError } from '@/lib/stale-build';

function Boom({ error }: { error: unknown }): never {
  throw error;
}

beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => {}));
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function shell(resetKey: string, page: React.ReactNode, props: Partial<React.ComponentProps<typeof RouteErrorBoundary>> = {}) {
  return (
    <div>
      <nav>nav</nav>
      <RouteErrorBoundary resetKey={resetKey} {...props}>{page}</RouteErrorBoundary>
    </div>
  );
}

it('shows the panel inside the shell with collapsed details and a working Reload', () => {
  const attemptReload = vi.fn(() => true);
  const onReload = vi.fn();
  render(shell('/rules', <Boom error={new TypeError('x is undefined')} />, { attemptReload, onReload }));
  expect(screen.getByText('nav')).toBeTruthy();
  expect(screen.getByText('This page failed to load')).toBeTruthy();
  expect(screen.queryByText(/nano was updated/)).toBeNull();
  const details = screen.getByText('Error details').closest('details')!;
  expect(details.open).toBe(false);
  expect(details.textContent).toContain('TypeError: x is undefined');
  expect(attemptReload).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Reload' }));
  expect(onReload).toHaveBeenCalledOnce();
});

it('reloads automatically once for a stale build', () => {
  const attemptReload = vi.fn(() => true);
  render(shell('/', <Boom error={new ProviderMissingError('useAuth', 'AuthProvider')} />, { attemptReload }));
  expect(attemptReload).toHaveBeenCalledOnce();
  expect(screen.getByRole('status').textContent).toContain('Reloading');
  expect(screen.queryByRole('alert')).toBeNull();
});

it('says nano was updated when the one-shot reload was already used', () => {
  const attemptReload = vi.fn(() => false);
  render(shell('/', <Boom error={new TypeError('Failed to fetch dynamically imported module')} />, { attemptReload }));
  expect(screen.getByText('This page failed to load')).toBeTruthy();
  expect(screen.getByText('nano was updated, reload to continue.')).toBeTruthy();
});

it('resets when the route changes', () => {
  const { rerender } = render(shell('/broken', <Boom error={new Error('render failed')} />));
  expect(screen.getByRole('alert')).toBeTruthy();
  rerender(shell('/rules', <p>rules page</p>));
  expect(screen.queryByRole('alert')).toBeNull();
  expect(screen.getByText('rules page')).toBeTruthy();
});
