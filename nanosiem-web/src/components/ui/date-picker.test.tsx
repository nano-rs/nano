// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { DatePicker } from './date-picker';

afterEach(cleanup);

it('shows the placeholder when unset and the mono day when set', () => {
  const { rerender } = render(<DatePicker aria-label="Target" value={null} onChange={() => {}} placeholder="No target" />);
  expect(screen.getByRole('button', { name: 'Target' }).textContent).toBe('No target');
  rerender(<DatePicker aria-label="Target" value="2026-10-31" onChange={() => {}} />);
  expect(screen.getByRole('button', { name: 'Target' }).textContent).toBe('2026-10-31');
});

it('picks a day from the shared calendar as YYYY-MM-DD', async () => {
  const onChange = vi.fn();
  render(<DatePicker aria-label="Target" value="2026-10-31" onChange={onChange} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target' }));
  const grid = await screen.findByRole('grid');
  const day15 = Array.from(grid.querySelectorAll('button')).find(b => b.textContent === '15')!;
  fireEvent.click(day15);
  expect(onChange).toHaveBeenCalledWith('2026-10-15');
});

it('clears to null', async () => {
  const onChange = vi.fn();
  render(<DatePicker aria-label="Target" value="2026-10-31" onChange={onChange} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target' }));
  fireEvent.click(await screen.findByRole('button', { name: 'Clear' }));
  expect(onChange).toHaveBeenCalledWith(null);
});
