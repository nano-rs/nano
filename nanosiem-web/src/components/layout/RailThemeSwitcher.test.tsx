// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { THEMES, THEME_LABELS } from '@/lib/theme';
import { LightDarkToggle, RailThemeFlyout, RailThemeStrip } from './RailThemeSwitcher';

const setTheme = vi.fn();
let currentTheme = 'dark';
let resolvedTheme = 'dark';
vi.mock('next-themes', () => ({
  useTheme: () => ({ theme: currentTheme, resolvedTheme, setTheme }),
}));

beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  // jsdom has no pointer capture; the strip's drag-to-scroll calls it on pointerup.
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
  Element.prototype.setPointerCapture ??= () => {};
});

afterEach(() => {
  cleanup();
  setTheme.mockClear();
  currentTheme = 'dark';
  resolvedTheme = 'dark';
});

describe('LightDarkToggle (NAN-5858)', () => {
  it('offers light from any dark-appearance theme and dark from a light one', async () => {
    const user = userEvent.setup();
    resolvedTheme = 'dark-violet';
    const { unmount } = render(<LightDarkToggle />);
    await user.click(screen.getByRole('button', { name: 'Switch to light theme' }));
    expect(setTheme).toHaveBeenLastCalledWith('light');
    unmount();

    resolvedTheme = 'paper';
    render(<LightDarkToggle />);
    await user.click(screen.getByRole('button', { name: 'Switch to dark theme' }));
    expect(setTheme).toHaveBeenLastCalledWith('dark');
  });
});

describe('RailThemeStrip (NAN-5858)', () => {
  it('shows every theme as a swatch next to the light/dark toggle and selects one', async () => {
    const user = userEvent.setup();
    currentTheme = 'matte';
    render(<RailThemeStrip />);
    const strip = screen.getByRole('group', { name: 'Theme' });
    const swatches = Array.from(strip.querySelectorAll('button'));
    expect(swatches.map((b) => b.getAttribute('aria-label'))).toEqual(THEMES.map((t) => THEME_LABELS[t]));
    expect(screen.getByRole('button', { name: 'Matte Black' }).getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByTestId('rail-light-dark-toggle')).toBeTruthy();

    await user.click(screen.getByRole('button', { name: 'Dark · Amber' }));
    expect(setTheme).toHaveBeenCalledWith('dark-amber');
  });
});

describe('ThemeSwatches roving tabindex (NAN-5858 review)', () => {
  const tabbable = () =>
    Array.from(screen.getByRole('group', { name: 'Theme' }).querySelectorAll('button')).filter(
      (b) => b.tabIndex === 0,
    );

  it('makes the selected swatch the one Tab stop, and the first one on system', async () => {
    currentTheme = 'dark-violet';
    const { unmount } = render(<RailThemeStrip />);
    await vi.waitFor(() => expect(tabbable().map((b) => b.getAttribute('aria-label'))).toEqual(['Dark · Violet']));
    unmount();

    currentTheme = 'system';
    render(<RailThemeStrip />);
    await vi.waitFor(() => expect(tabbable().map((b) => b.getAttribute('aria-label'))).toEqual([THEME_LABELS[THEMES[0]]]));
    expect(screen.getByRole('group', { name: 'Theme' }).querySelector('[aria-pressed="true"]')).toBeNull();
  });

  it('moves with arrows, Home and End, carrying the Tab stop along', async () => {
    const user = userEvent.setup();
    currentTheme = 'light';
    render(<RailThemeStrip />);
    const first = screen.getByRole('button', { name: THEME_LABELS[THEMES[0]] });
    first.focus();
    await user.keyboard('{End}');
    expect(document.activeElement?.getAttribute('aria-label')).toBe(THEME_LABELS[THEMES[THEMES.length - 1]]);
    expect(tabbable()).toEqual([document.activeElement]);
    await user.keyboard('{Home}');
    expect(document.activeElement).toBe(first);
    await user.keyboard('{ArrowLeft}');
    expect(document.activeElement?.getAttribute('aria-label')).toBe(THEME_LABELS[THEMES[THEMES.length - 1]]);
  });
});

describe('RailThemeFlyout (NAN-5858)', () => {
  const trigger = () => screen.getByRole('button', { name: 'Theme' });
  const panel = () => screen.queryByTestId('rail-theme-trigger-flyout');

  it('is a closed popup button until opened', () => {
    render(<RailThemeFlyout />);
    expect(trigger().getAttribute('aria-haspopup')).toBe('dialog');
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
    expect(panel()).toBeNull();
  });

  it('a mouse hover peeks and closes after the pointer leaves', async () => {
    const user = userEvent.setup();
    render(<RailThemeFlyout />);
    await user.hover(screen.getByTestId('rail-theme-trigger'));
    expect(panel()?.getAttribute('data-mode')).toBe('hover');
    await user.unhover(screen.getByTestId('rail-theme-trigger'));
    await vi.waitFor(() => expect(panel()).toBeNull());
  });

  it('a click after a hover pins the panel open and moves focus into it', async () => {
    const user = userEvent.setup();
    currentTheme = 'matte';
    render(<RailThemeFlyout />);
    await user.click(trigger()); // hover (peek) then click
    expect(panel()?.getAttribute('data-mode')).toBe('pinned');
    await vi.waitFor(() => expect(document.activeElement?.getAttribute('aria-label')).toBe('Matte Black'));
    await user.unhover(screen.getByTestId('rail-theme-trigger'));
    await new Promise((r) => setTimeout(r, 200));
    expect(panel()).toBeTruthy();
    await user.click(trigger()); // a second click closes it
    expect(panel()).toBeNull();
  });

  it('a touch tap opens it pinned (no open-then-close on the same tap)', () => {
    render(<RailThemeFlyout />);
    fireEvent.pointerOver(trigger(), { pointerType: 'touch' });
    expect(panel()).toBeNull();
    fireEvent.click(trigger());
    expect(panel()?.getAttribute('data-mode')).toBe('pinned');
  });

  it('opens from the keyboard on the selected swatch, arrows move, Escape returns to the trigger', async () => {
    const user = userEvent.setup();
    currentTheme = 'mono';
    render(<RailThemeFlyout />);
    trigger().focus();
    await user.keyboard('{Enter}');

    const dialog = await screen.findByRole('dialog', { name: 'Choose theme' });
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    expect(trigger().getAttribute('aria-controls')).toBe(dialog.id);
    await vi.waitFor(() => expect(document.activeElement?.getAttribute('aria-label')).toBe('Matte Mono'));

    await user.keyboard('{ArrowRight}');
    expect(document.activeElement?.getAttribute('aria-label')).toBe(THEME_LABELS[THEMES[THEMES.indexOf('mono') + 1]]);
    await user.keyboard('{Enter}');
    expect(setTheme).toHaveBeenCalledWith(THEMES[THEMES.indexOf('mono') + 1]);

    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Choose theme' })).toBeNull();
    expect(document.activeElement).toBe(trigger());
  });

  it('Escape anywhere dismisses a hover peek without moving focus', async () => {
    const user = userEvent.setup();
    render(
      <>
        <RailThemeFlyout />
        <input aria-label="search" />
      </>,
    );
    const input = screen.getByRole('textbox', { name: 'search' });
    input.focus();
    await user.hover(screen.getByTestId('rail-theme-trigger'));
    expect(panel()).toBeTruthy();
    await user.keyboard('{Escape}');
    expect(panel()).toBeNull();
    expect(document.activeElement).toBe(input);
  });

  it('Tab past the last control closes it and moves on; Shift+Tab past the first returns to the trigger', async () => {
    const user = userEvent.setup();
    currentTheme = 'light';
    render(
      <>
        <RailThemeFlyout />
        <button type="button">after</button>
      </>,
    );
    trigger().focus();
    await user.keyboard('{Enter}');
    await vi.waitFor(() => expect(document.activeElement?.getAttribute('aria-label')).toBe('Light'));
    // The light/dark toggle is the panel's first control.
    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(document.activeElement?.getAttribute('data-testid')).toBe('rail-light-dark-toggle');
    await user.keyboard('{Shift>}{Tab}{/Shift}');
    expect(panel()).toBeNull();
    expect(document.activeElement).toBe(trigger());

    await user.keyboard('{Enter}');
    await vi.waitFor(() => expect(document.activeElement?.getAttribute('aria-label')).toBe('Light'));
    const dialog = screen.getByRole('dialog', { name: 'Choose theme' });
    const last = Array.from(dialog.querySelectorAll<HTMLElement>('button')).filter((b) => b.tabIndex >= 0).pop()!;
    last.focus();
    await user.keyboard('{Tab}');
    expect(panel()).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'after' }));
  });

  it('closes on a press outside the trigger and the panel', () => {
    render(
      <>
        <RailThemeFlyout />
        <div data-testid="outside">page</div>
      </>,
    );
    fireEvent.click(trigger());
    expect(panel()).toBeTruthy();
    fireEvent.pointerDown(panel()!);
    expect(panel()).toBeTruthy();
    fireEvent.pointerDown(screen.getByTestId('outside'));
    expect(panel()).toBeNull();
  });

  it('closes when focus leaves both the trigger and the panel', async () => {
    const user = userEvent.setup();
    render(
      <>
        <RailThemeFlyout />
        <button type="button">elsewhere</button>
      </>,
    );
    trigger().focus();
    await user.keyboard('{ArrowRight}');
    await screen.findByRole('dialog', { name: 'Choose theme' });
    act(() => screen.getByRole('button', { name: 'elsewhere' }).focus());
    expect(panel()).toBeNull();
  });
});
