// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3011: the Log Source detail page scrolls in the app shell's scroll
 * container. #4801 turned the page root into a second, fixed-height scroller
 * (`h-[calc(100%+1.5rem)] overflow-auto`) and content below the fold became
 * unreachable. Pin the root so it never bounds its own height or clips again.
 * NAN-3014: pin the full-width app shell (no centered max-width column).
 */
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { LOG_SOURCE_DETAIL_ROOT_CLASS, LogSourceDetailShell } from './LogSourceDetailShell';

afterEach(cleanup);

describe('LogSourceDetailShell', () => {
  it('is not a nested scroll container with a bounded height', () => {
    const classes = LOG_SOURCE_DETAIL_ROOT_CLASS.split(/\s+/);
    // No overflow utility: the AppLayout shell owns the vertical scroll.
    expect(classes.filter((c) => /^overflow/.test(c))).toEqual([]);
    // No fixed/max height: the column must grow with its content.
    expect(classes.filter((c) => /^(h|max-h)-/.test(c))).toEqual([]);
  });

  it('uses the full-width app page shell (NAN-3014)', () => {
    const classes = LOG_SOURCE_DETAIL_ROOT_CLASS.split(/\s+/);
    // Same shell as other pages: no centered max-width column, no bespoke
    // gutters or bleed; AppLayout's p-3 is the gutter.
    expect(classes.filter((c) => /^(max-w|mx-auto|-?m[xy]?-|p[xytb]?-)/.test(c))).toEqual([]);
    expect(classes).toContain('w-full');
    expect(classes).toContain('gap-3');
  });

  it('renders children inside the root the shell scrolls', () => {
    render(
      <LogSourceDetailShell>
        <div>below the fold</div>
      </LogSourceDetailShell>,
    );
    const root = screen.getByTestId('log-source-detail-page');
    expect(root.className).toBe(LOG_SOURCE_DETAIL_ROOT_CLASS);
    expect(root.contains(screen.getByText('below the fold'))).toBe(true);
  });

  it('is the root of the loaded LogSourceDetail page', () => {
    const page = readFileSync(resolve(__dirname, '../../pages/LogSourceDetail.tsx'), 'utf8');
    expect(page).toContain('<LogSourceDetailShell>');
    // The #4801 nested scroller must not come back on the page itself.
    expect(page).not.toMatch(/h-\[calc\(100%\+1\.5rem\)\][^"]*overflow-auto/);
  });
});
