// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { SlosTab } from './SlosTab';

const listSlos = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ api: { observability: { listSlos } }, ApiClientError: class extends Error {} }));
vi.mock('@/components/observability/SloEditorDialog', () => ({ SloEditorDialog: () => null }));
vi.mock('@/components/ui/confirm-dialog', () => ({ ConfirmDialog: () => null }));
vi.mock('@/components/observability/charts', () => ({ BudgetBar: () => null }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('shows partial coverage without fabricated attainment or burning budget', async () => {
  listSlos.mockResolvedValue({ slos: [{ id: 'slo_partial', name: 'Checkout objective', service: 'checkout', sli_kind: 'availability', target: 0.99,
    window_days: 7, current: null, budget_remaining_pct: null, burn_rate: null, status: 'partial' }] });
  render(<SlosTab onOpenService={vi.fn()} onOpenTrace={vi.fn()} timeRange={{ type: 'preset', preset: 'Last 1 hour' }} apiTimeRange={{start:"2026-10-15T00:00:00Z",end:"2026-10-15T01:00:00Z"}} />);
  expect(await screen.findByText('Partial')).toBeTruthy();
  expect(screen.getAllByText('–')).toHaveLength(4);
  expect(screen.queryByText(/burning budget/)).toBeNull();
  expect(screen.queryByText('Healthy')).toBeNull();
});
