// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-5698: a Tooltip rendered without an ancestor TooltipProvider used to
// throw "`Tooltip` must be used within `TooltipProvider`" and take the whole
// route down to the error boundary (every risk notable's alert page).

import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './tooltip';

afterEach(cleanup);

const tip = (
  <Tooltip open>
    <TooltipTrigger>trigger</TooltipTrigger>
    <TooltipContent>tip body</TooltipContent>
  </Tooltip>
);

describe('Tooltip', () => {
  it('renders without an ancestor TooltipProvider', () => {
    render(tip);
    expect(screen.getByText('trigger')).toBeTruthy();
    expect(screen.getAllByText('tip body').length).toBeGreaterThan(0);
  });

  it('renders inside an explicit TooltipProvider', () => {
    render(<TooltipProvider delayDuration={0}>{tip}</TooltipProvider>);
    expect(screen.getByText('trigger')).toBeTruthy();
    expect(screen.getAllByText('tip body').length).toBeGreaterThan(0);
  });
});
