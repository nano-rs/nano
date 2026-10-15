// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
/**
 * NAN-3611: the API-key scope picker rendered `slice(0, 100)` of the
 * catalogue. With 139 permissions, everything after `risk:view` (all of
 * `search:*`, `settings:*`, `users:*`, …) only appeared under a filter, so a
 * key built by "selecting everything" silently lacked `search:execute`.
 *
 * The catalogue here is the REAL one, read from `ALL_PERMISSIONS` in
 * `nanosiem-core/src/auth/permissions.rs` (the Rust mirror of what
 * `GET /api/permissions` serves), so the test tracks the catalogue as it grows.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { PermissionInfo } from '@/lib/api';
import { ScopeSelector } from './ScopeSelector';

afterEach(() => cleanup());

function realCatalogue(): PermissionInfo[] {
  const source = readFileSync(
    path.resolve(__dirname, '../../../../../nanosiem-core/src/auth/permissions.rs'),
    'utf8',
  );
  const values = new Map<string, string>();
  for (const [, name, value] of source.matchAll(/pub const ([A-Z0-9_]+): &str = "([^"]+)";/g)) {
    values.set(name, value);
  }
  const block = source.match(/pub const ALL_PERMISSIONS: &\[&str\] = &\[([\s\S]*?)\n\];/);
  if (!block) throw new Error('ALL_PERMISSIONS not found in permissions.rs');
  const ids = [...block[1].matchAll(/^\s*([A-Z][A-Z0-9_]*),\s*$/gm)].map(([, name]) => {
    const id = values.get(name);
    if (!id) throw new Error(`unresolved permission constant ${name}`);
    return id;
  });
  return ids.sort().map(id => ({ id, name: id, description: `${id} description`, category: id.split(':')[0] }));
}

const catalogue = realCatalogue();

function lastReported(onChange: ReturnType<typeof vi.fn>): string[] {
  return onChange.mock.calls[onChange.mock.calls.length - 1][0] as string[];
}

it('renders every catalogue scope unfiltered, past the old 100-row cap', () => {
  // Guard the premise: the regression only bites once the catalogue exceeds 100.
  expect(catalogue.length).toBeGreaterThan(100);
  expect(catalogue.map(p => p.id)).toContain('search:execute');

  render(<ScopeSelector permissions={catalogue} initialScopes={[]} onChange={vi.fn()} />);

  expect(screen.getAllByRole('checkbox')).toHaveLength(catalogue.length);
  expect(screen.getByRole('checkbox', { name: /^search:execute — / })).toBeTruthy();
  expect(screen.getByTestId('scope-selected-count').textContent).toBe(`0/${catalogue.length}`);
});

it('select-all covers the whole server catalogue, including search:execute', () => {
  const onChange = vi.fn();
  render(<ScopeSelector permissions={catalogue} initialScopes={[]} onChange={onChange} />);

  fireEvent.click(screen.getByTestId('scope-select-all'));

  const selected = lastReported(onChange);
  expect(selected).toHaveLength(catalogue.length);
  expect(new Set(selected)).toEqual(new Set(catalogue.map(p => p.id)));
  expect(screen.getByTestId('scope-selected-count').textContent).toBe(`${catalogue.length}/${catalogue.length}`);
  expect(screen.getAllByRole('checkbox').every(box => box.getAttribute('aria-checked') === 'true')).toBe(true);

  // Second click clears.
  fireEvent.click(screen.getByTestId('scope-select-all'));
  expect(lastReported(onChange)).toHaveLength(0);
});

it('select-all under a filter adds only the shown scopes and keeps earlier picks', () => {
  const onChange = vi.fn();
  render(<ScopeSelector permissions={catalogue} initialScopes={['alerts:view']} onChange={onChange} />);

  fireEvent.change(screen.getByPlaceholderText('Filter scopes…'), { target: { value: 'search:' } });
  const shown = screen.getAllByRole('checkbox').map(box => box.getAttribute('aria-label')!.split(' — ')[0]);
  expect(shown.length).toBeGreaterThan(0);
  expect(shown.every(id => id.includes('search:'))).toBe(true);

  fireEvent.click(screen.getByTestId('scope-select-all'));
  expect(new Set(lastReported(onChange))).toEqual(new Set(['alerts:view', ...shown]));
});
