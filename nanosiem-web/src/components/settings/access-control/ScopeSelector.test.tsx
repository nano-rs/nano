// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
/**
 * NAN-5901: the API key scope picker rendered only the first 100 permissions,
 * so a key built by "tick everything you can see" silently missed the rest.
 * Every permission must render and be selectable, bulk select must respect
 * NAN-5329 (only what the creator holds), and the edit dialog must show a
 * key's existing scopes past the first 100.
 */
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const perms = vi.hoisted(() => ({ value: new Set<string>() }));
const apiMock = vi.hoisted(() => ({ updateApiKey: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: apiMock }));
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({ hasPermission: (p: string) => perms.value.has(p) }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

import type { PermissionInfo } from '@/lib/api';
import { ScopeSelector } from './ScopeSelector';
import { EditApiKeyDialog } from './EditApiKeyDialog';

// 30 resources x 5 actions = 150 permissions, well past the old 100 cap.
const ACTIONS = ['view', 'create', 'edit', 'delete', 'manage'];
const CATALOGUE = Array.from({ length: 30 }, (_, r) =>
  ACTIONS.map((a): PermissionInfo => {
    const id = `res${String(r).padStart(2, '0')}:${a}`;
    return { id, name: id, category: `res${r}`, description: `${a} resource ${r}` };
  }),
).flat();
const ALL_IDS = CATALOGUE.map(p => p.id);

function boxes() {
  return screen.getAllByRole('checkbox');
}

function box(id: string) {
  return screen.getByRole('checkbox', { name: new RegExp(`^${id}:`) });
}

function lastOnChange(fn: ReturnType<typeof vi.fn>): string[] {
  return [...(fn.mock.calls.at(-1)?.[0] as string[])].sort();
}

afterEach(() => {
  cleanup();
  perms.value = new Set();
});

describe('ScopeSelector (NAN-5901)', () => {
  it('renders and toggles every permission past 100', () => {
    const onChange = vi.fn();
    render(<ScopeSelector permissions={CATALOGUE} initialScopes={[]} onChange={onChange} />);

    expect(boxes()).toHaveLength(150);
    expect(screen.getByTestId('scope-count').textContent).toBe('150 of 150 shown · 0 selected');

    // The last one alphabetically, which the old slice(0, 100) dropped.
    fireEvent.click(box('res29:view'));
    expect(box('res29:view').getAttribute('aria-checked')).toBe('true');
    expect(lastOnChange(onChange)).toEqual(['res29:view']);

    // Toggle all 150 one by one.
    for (const b of boxes()) if (b.getAttribute('aria-checked') !== 'true') fireEvent.click(b);
    expect(lastOnChange(onChange)).toEqual([...ALL_IDS].sort());
    expect(screen.getByTestId('scope-count').textContent).toBe('150 of 150 shown · 150 selected');
  });

  it('groups scopes under their resource prefix', () => {
    render(<ScopeSelector permissions={[...CATALOGUE].reverse()} initialScopes={[]} onChange={vi.fn()} />);
    const groups = screen.getAllByRole('group');
    expect(groups).toHaveLength(30);
    expect(groups[0].getAttribute('aria-label')).toBe('res00');
    expect(within(groups[0]).getAllByRole('checkbox')).toHaveLength(5);
  });

  it('"Select all I can grant" adds only grantable scopes, and Clear removes all', () => {
    const grantable = new Set(ALL_IDS.filter(id => id.endsWith(':view') || id.startsWith('res29:')));
    const onChange = vi.fn();
    render(
      <ScopeSelector
        permissions={CATALOGUE}
        initialScopes={[]}
        onChange={onChange}
        canGrant={id => grantable.has(id)}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Select all I can grant' }));
    expect(lastOnChange(onChange)).toEqual([...grantable].sort());
    expect(box('res00:edit').getAttribute('aria-checked')).toBe('false');
    expect(box('res29:edit').getAttribute('aria-checked')).toBe('true');
    expect(screen.getByTestId('scope-count').textContent).toBe(`150 of 150 shown · ${grantable.size} selected`);

    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(lastOnChange(onChange)).toEqual([]);
  });

  it('with a filter, bulk actions only touch the matches', () => {
    const grantable = new Set(ALL_IDS.filter(id => id !== 'res03:delete'));
    const onChange = vi.fn();
    render(
      <ScopeSelector
        permissions={CATALOGUE}
        initialScopes={['res10:view']}
        onChange={onChange}
        canGrant={id => grantable.has(id)}
      />,
    );

    fireEvent.change(screen.getByPlaceholderText('Filter scopes…'), { target: { value: ':delete' } });
    expect(boxes()).toHaveLength(30);
    expect(screen.getByTestId('scope-count').textContent).toBe('30 of 150 shown · 1 selected');

    fireEvent.click(screen.getByRole('button', { name: 'Select matches I can grant' }));
    const deletes = ALL_IDS.filter(id => id.endsWith(':delete') && id !== 'res03:delete');
    expect(lastOnChange(onChange)).toEqual([...deletes, 'res10:view'].sort());

    fireEvent.click(screen.getByRole('button', { name: 'Clear matches' }));
    // The non-matching scope picked earlier survives.
    expect(lastOnChange(onChange)).toEqual(['res10:view']);
  });

  it('a held-but-ungrantable scope can still be cleared', () => {
    const onChange = vi.fn();
    render(
      <ScopeSelector
        permissions={CATALOGUE}
        initialScopes={['res05:manage']}
        onChange={onChange}
        canGrant={() => false}
      />,
    );
    expect(screen.getByRole('button', { name: 'Select all I can grant' }).hasAttribute('disabled')).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(lastOnChange(onChange)).toEqual([]);
  });
});

describe('unknown or retired scopes on a key (NAN-5901 review P1-1)', () => {
  const RETIRED = ['feeds:view', 'alerts:triage'];

  it('shows them in their own group, clearable one by one, never re-tickable', () => {
    const onChange = vi.fn();
    render(
      <ScopeSelector
        permissions={CATALOGUE}
        initialScopes={['res00:view', ...RETIRED]}
        onChange={onChange}
        canGrant={() => true} // a `*` admin still cannot re-add them
      />,
    );
    const group = screen.getByRole('group', { name: 'Unknown or retired' });
    expect(within(group).getAllByRole('checkbox')).toHaveLength(2);
    expect(within(group).getByText(/no longer exist in nano/)).toBeTruthy();
    expect(screen.getByTestId('scope-count').textContent).toBe('152 of 152 shown · 3 selected');

    fireEvent.click(box('feeds:view'));
    expect(lastOnChange(onChange)).toEqual(['alerts:triage', 'res00:view']);
    expect(box('feeds:view').getAttribute('aria-checked')).toBe('false');
    expect(box('feeds:view').hasAttribute('disabled')).toBe(true);
    fireEvent.click(box('feeds:view'));
    expect(lastOnChange(onChange)).toEqual(['alerts:triage', 'res00:view']);
  });

  it('Clear removes them; Select all never adds them back', () => {
    const onChange = vi.fn();
    render(<ScopeSelector permissions={CATALOGUE} initialScopes={RETIRED} onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(lastOnChange(onChange)).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: 'Select all I can grant' }));
    expect(lastOnChange(onChange)).toEqual([...ALL_IDS].sort());
  });

  it('a filter narrows them too, and Clear matches clears only matching ones', () => {
    const onChange = vi.fn();
    render(<ScopeSelector permissions={CATALOGUE} initialScopes={RETIRED} onChange={onChange} />);
    fireEvent.change(screen.getByLabelText('Filter scopes'), { target: { value: 'feeds' } });
    expect(boxes()).toHaveLength(1);
    fireEvent.click(screen.getByRole('button', { name: 'Clear matches' }));
    expect(lastOnChange(onChange)).toEqual(['alerts:triage']);
  });

  it('does not show a key as all-unknown while the catalogue is still loading', () => {
    render(<ScopeSelector permissions={[]} initialScopes={['res00:view']} onChange={vi.fn()} />);
    expect(screen.queryByRole('group', { name: 'Unknown or retired' })).toBeNull();
  });

  it('the edit dialog blocks Save until they are cleared, then saves without them', async () => {
    perms.value = new Set(ALL_IDS);
    apiMock.updateApiKey.mockResolvedValue({});
    const onSaved = vi.fn();
    render(
      <EditApiKeyDialog
        open
        apiKey={{
          id: 'key_02', name: 'old-robot', description: null, key_prefix: 'nano_def',
          permissions: ['res01:view', ...RETIRED],
        } as never}
        permissions={CATALOGUE}
        onClose={vi.fn()}
        onSaved={onSaved}
      />,
    );
    const save = screen.getByRole('button', { name: 'Save changes' });
    expect(save.hasAttribute('disabled')).toBe(true);
    expect(screen.getByTestId('unknown-scopes-block').textContent).toMatch(/Clear the 2 scopes/);

    fireEvent.click(box('feeds:view'));
    fireEvent.click(box('alerts:triage'));
    expect(screen.queryByTestId('unknown-scopes-block')).toBeNull();
    fireEvent.click(save);
    await waitFor(() => expect(apiMock.updateApiKey).toHaveBeenCalledTimes(1));
    expect(apiMock.updateApiKey.mock.calls[0][1].permissions).toEqual(['res01:view']);
  });
});

describe('grouping (NAN-5901 review P2-2)', () => {
  it('keeps one group per prefix when colon-less ids sort between them', () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const mk = (id: string): PermissionInfo => ({ id, name: id, category: 'x', description: id });
    render(
      <ScopeSelector
        permissions={['alerts:view', 'alerts', 'alerts_v2:view', 'alerts:edit'].map(mk)}
        initialScopes={[]}
        onChange={vi.fn()}
      />,
    );
    const labels = screen.getAllByRole('group').map(g => g.getAttribute('aria-label'));
    expect(labels).toEqual(['alerts', 'alerts_v2']);
    expect(within(screen.getByRole('group', { name: 'alerts' })).getAllByRole('checkbox')).toHaveLength(3);
    expect(errors.mock.calls.some(c => String(c[0]).includes('same key'))).toBe(false);
    errors.mockRestore();
  });
});

describe('EditApiKeyDialog with more than 100 existing scopes (NAN-5901)', () => {
  it('shows every existing scope ticked, including those past the first 100', () => {
    perms.value = new Set(ALL_IDS);
    const existing = ALL_IDS.filter(id => !id.endsWith(':manage')); // 120 scopes
    render(
      <EditApiKeyDialog
        open
        apiKey={{
          id: 'key_01',
          name: 'ci-robot',
          description: null,
          key_prefix: 'nano_abc',
          permissions: existing,
        } as never}
        permissions={CATALOGUE}
        onClose={vi.fn()}
        onSaved={vi.fn()}
      />,
    );

    expect(screen.getByTestId('scope-count').textContent).toBe('150 of 150 shown · 120 selected');
    expect(boxes()).toHaveLength(150);
    const checked = boxes().filter(b => b.getAttribute('aria-checked') === 'true');
    expect(checked).toHaveLength(120);
    expect(box('res29:delete').getAttribute('aria-checked')).toBe('true');
    expect(box('res29:manage').getAttribute('aria-checked')).toBe('false');
  });
});
