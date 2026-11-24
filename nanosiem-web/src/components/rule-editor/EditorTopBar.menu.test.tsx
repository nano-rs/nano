// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5842: the rule editor overflow ("Rule actions") menu uses the shared
 * DropdownMenu compact density and destructive variant, so its rows get the
 * app-standard 12px text, 8px icon gap and 16px icons instead of the bare
 * shadcn item (14px text, no gap, icons jammed against the label). The real
 * rendering is checked by screenshot; these pin the class contract.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { EditorTopBar } from './EditorTopBar';

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { aiTuning: false } }),
}));

afterEach(cleanup);

const META = {
  title: 'nan5842_menu_check',
  severity: 'medium',
  mode: 'staging',
  folder: 'Automated',
  tags: '',
} as unknown as Parameters<typeof EditorTopBar>[0]['metadata'];

const classes = (el: Element) => el.className.toString().split(/\s+/);

function openMenu() {
  render(
    <EditorTopBar
      metadata={META}
      isNewMode={false}
      apiMode="staging"
      dirty={false}
      saving={false}
      valid
      viewMode="code"
      onViewMode={() => {}}
      onBack={() => {}}
      onSave={() => {}}
      onOpenTest={() => {}}
      onDuplicate={() => {}}
      onFormat={() => {}}
      onPromote={() => {}}
      onArchive={() => {}}
      onDelete={() => {}}
    />,
  );
  const trigger = screen.getByRole('button', { name: 'Rule actions' });
  fireEvent.keyDown(trigger, { key: 'Enter' });
  return screen.getByRole('menu');
}

describe('rule editor overflow menu (NAN-5842)', () => {
  it('rows use the compact density: 12px text, 8px icon gap, 16px non-shrinking icons', () => {
    const menu = openMenu();
    const items = within(menu).getAllByRole('menuitem');
    expect(items.length).toBeGreaterThanOrEqual(4);
    for (const item of items) {
      const c = classes(item);
      expect(c).toContain('gap-2');
      expect(c).toContain('text-[12px]');
      expect(c).toContain('h-7');
      expect(c).toContain('[&>svg]:size-4');
      expect(c).not.toContain('text-sm');
      const svg = item.querySelector('svg');
      expect(svg).not.toBeNull();
      // No per-icon size class fighting the item's icon sizing.
      expect(svg!.getAttribute('class') ?? '').not.toMatch(/\bw-3\.5\b/);
      expect(svg!.getAttribute('stroke-width')).toBe('1.5');
    }
  });

  it('archive and delete use the shared destructive variant, other rows do not', () => {
    const menu = openMenu();
    const destructive = ['Archive rule', 'Delete forever'];
    for (const item of within(menu).getAllByRole('menuitem')) {
      const isDestructive = destructive.some((d) => item.textContent?.includes(d));
      expect(classes(item).includes('text-destructive')).toBe(isDestructive);
    }
  });

  it('section labels use the mono meta style', () => {
    const menu = openMenu();
    const label = within(menu).getByText('Rule actions');
    expect(classes(label)).toEqual(expect.arrayContaining(['font-mono', 'text-[10px]', 'uppercase']));
  });
});
