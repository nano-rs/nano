// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { ValidationDetailsDialog } from './ValidationDetailsDialog';

beforeAll(() => {
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }
});

afterEach(cleanup);

function sheetEl() {
  return document.querySelector('[data-detail-sheet]') as HTMLElement | null;
}

describe('ValidationDetailsDialog (DetailSheet)', () => {
  it('renders in a md sheet with the status title and closes via the header X', () => {
    const onOpenChange = vi.fn();
    render(
      <ValidationDetailsDialog
        open
        onOpenChange={onOpenChange}
        validation={{ valid: false, error: 'unexpected token at 12' } as never}
      />,
    );
    const sheet = sheetEl();
    expect(sheet).toBeTruthy();
    expect(sheet!.getAttribute('data-size')).toBe('md');
    const dialog = screen.getByRole('dialog', { name: 'Rule has errors' });
    expect(within(dialog).getByText('unexpected token at 12')).toBeTruthy();
    // Header X is the first Close; the footer keeps its own Close button.
    const closes = within(dialog).getAllByRole('button', { name: 'Close' });
    fireEvent.click(closes[0]);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('Run test closes the sheet and fires the callback', () => {
    const onOpenChange = vi.fn();
    const onRunTest = vi.fn();
    render(
      <ValidationDetailsDialog
        open
        onOpenChange={onOpenChange}
        validation={{ valid: true, matchCount: 3 } as never}
        onRunTest={onRunTest}
      />,
    );
    const dialog = screen.getByRole('dialog', { name: 'Rule is valid' });
    fireEvent.click(within(dialog).getByRole('button', { name: /Run test/ }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onRunTest).toHaveBeenCalled();
  });
});
