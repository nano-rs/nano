// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5777 / NAN-5783: TruncatedText shows the full value in a focusable app
 * Tooltip only while the text is actually cut, and screen readers read it once.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { TruncatedText, isTruncated } from './truncated-text';

/** jsdom has no layout: fake the text's scroll/client widths. */
function fakeWidths(scroll: number, client: number) {
  vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockImplementation(() => scroll);
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(() => client);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const FULL = 'windows_suspicious_lsass_access_via_procdump_from_unusual_parent';

describe('isTruncated', () => {
  it('is true only when the content is wider than the box', () => {
    expect(isTruncated(null)).toBe(false);
    fakeWidths(300, 120);
    expect(isTruncated(document.createElement('span'))).toBe(true);
    fakeWidths(120, 120);
    expect(isTruncated(document.createElement('span'))).toBe(false);
  });
});

describe('TruncatedText', () => {
  it('a value that fits is plain text: no tab stop, no tooltip on focus', () => {
    fakeWidths(100, 100);
    render(<TruncatedText text="dc-01" testId="t" />);
    const el = screen.getByTestId('t');
    expect(el.textContent).toBe('dc-01');
    expect(el.getAttribute('tabindex')).toBeNull();
    act(() => {
      fireEvent.focus(el);
    });
    expect(screen.queryByText('dc-01', { selector: '[data-radix-popper-content-wrapper] *' })).toBeNull();
    expect(document.querySelectorAll('[data-radix-popper-content-wrapper]').length).toBe(0);
  });

  it('a cut value is focusable and shows the full value in the app Tooltip on keyboard focus', async () => {
    fakeWidths(480, 120);
    render(<TruncatedText text={FULL} testId="t" />);
    const el = screen.getByTestId('t');
    expect(el.getAttribute('data-truncated')).toBe('true');
    expect(el.getAttribute('tabindex')).toBe('0');
    // Full value stays in the DOM text: screen readers read it from here.
    expect(el.textContent).toBe(FULL);

    act(() => {
      el.focus();
    });
    const content = await screen.findByText(FULL, { selector: '[data-side] *, [data-side]' });
    // The tooltip repeats the value, so it is hidden from assistive tech...
    expect(content.closest('[aria-hidden="true"]')).not.toBeNull();
    // ...and the focused text carries no description (read once, not twice).
    expect(el.getAttribute('aria-describedby')).toBeNull();
  });

  it('Escape dismisses the tooltip', async () => {
    fakeWidths(480, 120);
    render(<TruncatedText text={FULL} testId="t" />);
    const el = screen.getByTestId('t');
    act(() => {
      el.focus();
    });
    await screen.findByText(FULL, { selector: '[data-side] *, [data-side]' });
    act(() => {
      fireEvent.keyDown(document.activeElement ?? el, { key: 'Escape' });
    });
    expect(document.querySelectorAll('[data-side]').length).toBe(0);
  });
});
