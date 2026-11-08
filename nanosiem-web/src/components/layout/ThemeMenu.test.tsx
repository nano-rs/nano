// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { THEMES, THEME_LABELS } from '@/lib/theme';
import { ThemeMenu } from './ThemeMenu';

const setTheme = vi.fn();
let currentTheme = 'dark';
vi.mock('next-themes', () => ({
  useTheme: () => ({ theme: currentTheme, setTheme }),
}));

beforeAll(() => {
  // Radix menus measure and observe; jsdom has neither.
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  Element.prototype.scrollIntoView ??= () => {};
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
});

afterEach(() => {
  cleanup();
  setTheme.mockClear();
});

function renderMenu() {
  return render(
    <DropdownMenu>
      <DropdownMenuTrigger>Account</DropdownMenuTrigger>
      <DropdownMenuContent>
        <ThemeMenu />
      </DropdownMenuContent>
    </DropdownMenu>,
  );
}

describe('ThemeMenu', () => {
  it('selects every theme with the keyboard alone', async () => {
    const user = userEvent.setup();
    renderMenu();

    // Open the account menu and the Theme submenu from the keyboard.
    screen.getByRole('button', { name: 'Account' }).focus();
    await user.keyboard('{Enter}');
    const trigger = await screen.findByRole('menuitem', { name: 'Theme' });
    trigger.focus();
    await user.keyboard('{ArrowRight}');

    const items = await screen.findAllByRole('menuitemradio');
    expect(items.map((i) => i.textContent)).toEqual(THEMES.map((t) => THEME_LABELS[t]));

    // Walk the radio items with ArrowDown and pick each with Enter. The menu
    // stays open after each pick, so one pass reaches every theme.
    for (let i = 0; i < THEMES.length; i++) {
      if (i > 0) await user.keyboard('{ArrowDown}');
      expect(document.activeElement?.textContent).toBe(THEME_LABELS[THEMES[i]]);
      await user.keyboard('{Enter}');
    }
    expect(setTheme.mock.calls.map((c) => c[0])).toEqual([...THEMES]);
  });

  it('marks the active theme as checked', async () => {
    currentTheme = 'matte';
    const user = userEvent.setup();
    renderMenu();
    await user.click(screen.getByRole('button', { name: 'Account' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Theme' }));
    const matte = await screen.findByRole('menuitemradio', { name: THEME_LABELS.matte });
    expect(matte.getAttribute('aria-checked')).toBe('true');
    currentTheme = 'dark';
  });
});
