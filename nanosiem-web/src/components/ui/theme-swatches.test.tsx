// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { ThemeSwatches } from './theme-swatches';

// NAN-5836: the swatch strip on /settings/user (200px wide) holds 276px of
// swatches in a 184px scroller. jsdom has no layout, so the strip's scroll
// metrics are faked on the element that carries role=group.
const SCROLL_WIDTH = 276;
const CLIENT_WIDTH = 184;
const scrollLefts = new WeakMap<Element, number>();
const isStrip = (el: Element) => el.getAttribute('role') === 'group';
const saved: Record<string, PropertyDescriptor | undefined> = {};

beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
  for (const k of ['scrollWidth', 'clientWidth', 'scrollLeft', 'scrollBy']) {
    saved[k] = Object.getOwnPropertyDescriptor(Element.prototype, k);
  }
  Object.defineProperty(Element.prototype, 'scrollWidth', {
    configurable: true,
    get(this: Element) {
      return isStrip(this) ? SCROLL_WIDTH : 0;
    },
  });
  Object.defineProperty(Element.prototype, 'clientWidth', {
    configurable: true,
    get(this: Element) {
      return isStrip(this) ? CLIENT_WIDTH : 0;
    },
  });
  Object.defineProperty(Element.prototype, 'scrollLeft', {
    configurable: true,
    get(this: Element) {
      return scrollLefts.get(this) ?? 0;
    },
    set(this: Element, v: number) {
      scrollLefts.set(this, Math.max(0, Math.min(v, SCROLL_WIDTH - CLIENT_WIDTH)));
      this.dispatchEvent(new Event('scroll'));
    },
  });
  Object.defineProperty(Element.prototype, 'scrollBy', {
    configurable: true,
    value(this: Element, opts: ScrollToOptions) {
      this.scrollLeft = this.scrollLeft + (opts.left ?? 0);
    },
  });
});

afterAll(() => {
  for (const [k, d] of Object.entries(saved)) {
    if (d) Object.defineProperty(Element.prototype, k, d);
    else delete (Element.prototype as unknown as Record<string, unknown>)[k];
  }
});

afterEach(cleanup);

const left = () => screen.getByRole('button', { name: 'Scroll themes left' });
const right = () => screen.getByRole('button', { name: 'Scroll themes right' });

describe('ThemeSwatches scroll arrows (NAN-5836)', () => {
  it('puts a left and a right arrow beside the strip, in on-screen Tab order', () => {
    render(<ThemeSwatches />);
    const strip = screen.getByRole('group', { name: 'Theme' });
    // Neither arrow is inside the scroller (so neither can paint over a swatch).
    expect(strip.contains(left())).toBe(false);
    expect(strip.contains(right())).toBe(false);
    // DOM (= Tab) order: left arrow, swatches, right arrow.
    const buttons = Array.from(document.querySelectorAll('button'));
    expect(buttons[0]).toBe(left());
    expect(buttons[buttons.length - 1]).toBe(right());
    // At the start only the right arrow is active.
    expect(left().getAttribute('aria-disabled')).toBe('true');
    expect(right().getAttribute('aria-disabled')).toBe('false');
  });

  it('scrolls right then back left, keeping focus on the pressed arrow', () => {
    render(<ThemeSwatches />);
    const strip = screen.getByRole('group', { name: 'Theme' });

    right().focus();
    act(() => {
      fireEvent.click(right());
    });
    expect(strip.scrollLeft).toBe(SCROLL_WIDTH - CLIENT_WIDTH);
    // At the end: aria-disabled, never native disabled, so focus stays put.
    expect(right().getAttribute('aria-disabled')).toBe('true');
    expect(right().hasAttribute('disabled')).toBe(false);
    expect(document.activeElement).toBe(right());
    // Pressing it again is a no-op.
    act(() => {
      fireEvent.click(right());
    });
    expect(strip.scrollLeft).toBe(SCROLL_WIDTH - CLIENT_WIDTH);

    // The way back.
    expect(left().getAttribute('aria-disabled')).toBe('false');
    left().focus();
    act(() => {
      fireEvent.click(left());
    });
    expect(strip.scrollLeft).toBe(0);
    expect(left().getAttribute('aria-disabled')).toBe('true');
    expect(left().hasAttribute('disabled')).toBe(false);
    expect(document.activeElement).toBe(left());
  });

  it('gives both arrows a visible var(--ring) focus outline, not a box-shadow ring', () => {
    render(<ThemeSwatches />);
    for (const b of [left(), right()]) {
      expect(b.className).toContain('focus-visible:outline-[var(--ring)]');
      expect(b.className).not.toMatch(/(^|\s)(focus-visible:)?ring-/);
    }
  });
});
