// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4903: dashboard pivots build profile-correct nPL. */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const mocks = vi.hoisted(() => ({ navigate: vi.fn(), getSchemaFields: vi.fn() }));
vi.mock('react-router-dom', () => ({ useNavigate: () => mocks.navigate }));
vi.mock('@/lib/api', () => ({ api: { getSchemaFields: mocks.getSchemaFields } }));

import { QuickEntitySearch, buildEntitySearchQuery } from './QuickEntitySearch';
import { buildQuery } from './QuickPivotIntake';

afterEach(() => {
  cleanup();
  mocks.navigate.mockReset();
});

function renderWith(schema: 'udm' | 'ocsf') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], { schema, fields: [] });
  render(
    <QueryClientProvider client={client}>
      <QuickEntitySearch />
    </QueryClientProvider>,
  );
}

function submit(value: string): string {
  const input = screen.getByPlaceholderText(/Search IP/);
  fireEvent.change(input, { target: { value } });
  fireEvent.submit(input.closest('form') as HTMLFormElement);
  const url = mocks.navigate.mock.calls[0][0] as string;
  return decodeURIComponent(url.replace('/search#q=', ''));
}

describe('QuickEntitySearch while the schema profile is unresolved', () => {
  it('disables the action and builds no query (loading)', () => {
    mocks.getSchemaFields.mockReturnValue(new Promise(() => {}));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <QuickEntitySearch />
      </QueryClientProvider>,
    );
    const input = screen.getByPlaceholderText(/Search IP/);
    fireEvent.change(input, { target: { value: '10.1.2.3' } });
    const button = screen.getByRole('button');
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute('title')).toMatch(/schema profile/i);
    fireEvent.submit(input.closest('form') as HTMLFormElement);
    expect(mocks.navigate).not.toHaveBeenCalled();
  });

  it('disables the action and builds no query (endpoint failed)', async () => {
    mocks.getSchemaFields.mockRejectedValue(new Error('503'));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <QuickEntitySearch />
      </QueryClientProvider>,
    );
    const input = screen.getByPlaceholderText(/Search IP/);
    fireEvent.change(input, { target: { value: '10.1.2.3' } });
    await waitFor(() => expect(screen.getByRole('button').getAttribute('title')).toMatch(/unavailable/i));
    fireEvent.submit(input.closest('form') as HTMLFormElement);
    expect(mocks.navigate).not.toHaveBeenCalled();
  });
});

describe('QuickEntitySearch', () => {
  it('pivots on src_endpoint.ip under OCSF', () => {
    renderWith('ocsf');
    expect(submit('10.1.2.3')).toBe('(src_endpoint.ip="10.1.2.3" OR dst_endpoint.ip="10.1.2.3")');
  });

  it('pivots on src_ip under UDM', () => {
    renderWith('udm');
    expect(submit('10.1.2.3')).toBe('(src_ip="10.1.2.3" OR dest_ip="10.1.2.3")');
  });

  it('a bare name searches both OCSF user columns and hosts', () => {
    expect(buildEntitySearchQuery('ocsf', 'alice')).toBe(
      '(actor.user.name="alice" OR user.name="alice" OR src_endpoint.hostname="alice" OR dst_endpoint.hostname="alice")',
    );
    expect(buildEntitySearchQuery('udm', 'alice')).toBe('(user="alice" OR src_host="alice" OR dest_host="alice")');
  });
});

describe('QuickPivotIntake buildQuery', () => {
  it('IP pivot per profile', () => {
    expect(buildQuery('ipv4', '1.2.3.4', 'ocsf')).toBe('src_endpoint.ip="1.2.3.4" OR dst_endpoint.ip="1.2.3.4"');
    expect(buildQuery('ipv4', '1.2.3.4', 'udm')).toBe('src_ip="1.2.3.4" OR dest_ip="1.2.3.4"');
  });

  it('hash and user pivots per profile', () => {
    const h = 'a'.repeat(64);
    expect(buildQuery('sha256', h, 'ocsf')).toBe(`process.file.hashes.value="${h}" OR file.hashes.value="${h}"`);
    expect(buildQuery('email', 'bob@x.io', 'udm')).toBe('user="bob@x.io"');
    expect(buildQuery('email', 'bob@x.io', 'ocsf')).toBe('(actor.user.name="bob@x.io" OR user.name="bob@x.io")');
  });
});
