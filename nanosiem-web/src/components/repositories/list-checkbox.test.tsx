// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later

import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@testing-library/react';
import { Chk as RuleRepositoryCheckbox } from './chips';
import { Chk as ParserRepositoryCheckbox } from '@/components/parser-repositories/chips';
import { Chk as RuleCheckbox } from '@/components/rules/RuleRow';

afterEach(cleanup);

it.each([
  ['rule repository', RuleRepositoryCheckbox],
  ['parser repository', ParserRepositoryCheckbox],
  ['rule list', RuleCheckbox],
])('%s checkbox stays anchored to its row after scrolling and selection', (_, Checkbox) => {
  const onChange = vi.fn();
  const view = render(
    <div data-testid="scroll-container" style={{ height: 20, overflow: 'auto' }}>
      <div style={{ height: 100 }} />
      <Checkbox checked={false} onChange={onChange} ariaLabel="Select row" />
    </div>,
  );
  const scrollContainer = view.getByTestId('scroll-container');
  const input = view.getByRole('checkbox', { name: 'Select row' });
  scrollContainer.scrollTop = 100;
  fireEvent.scroll(scrollContainer);
  fireEvent.click(input.closest('label')!);
  expect(onChange).toHaveBeenCalledOnce();
  expect(input.closest('label')?.classList.contains('relative')).toBe(true);
  view.rerender(
    <div data-testid="scroll-container" style={{ height: 20, overflow: 'auto' }}>
      <div style={{ height: 100 }} />
      <Checkbox checked onChange={onChange} ariaLabel="Select row" />
    </div>,
  );
  expect((view.getByRole('checkbox', { name: 'Select row' }) as HTMLInputElement).checked).toBe(true);
  expect(scrollContainer.scrollTop).toBe(100);
});
