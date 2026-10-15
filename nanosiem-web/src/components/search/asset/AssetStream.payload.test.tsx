// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AssetStream } from './AssetStream';
const mocks = vi.hoisted(() => ({ fetchLog: vi.fn(), events: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: {
  fetchLog: mocks.fetchLog, getAssetEvents: mocks.events,
  getSchemaFields: async () => ({ schema: 'udm', fields: [] }),
} }));
const props = {
  identifierField: 'src_ip', identifierValue: '1.2.3.4', identities: [],
  timeRange: { start: '2026-09-30T00:00:00Z', end: '2026-09-30T01:00:00Z' },
};
function view() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <AssetStream {...props} />
  </QueryClientProvider>);
}
beforeEach(() => {
  mocks.fetchLog.mockReset().mockResolvedValue({ event: { id: 'one', full_field: 'payload' } });
  mocks.events.mockReset().mockResolvedValue({
    events: [{ id: 'one', timestamp: '2026-09-30T00:01:00Z', source_type: 'test', event_kind: 'EVENT', summary: { message: 'sample' } }],
    total_count: 1, total_count_exact: true, facets: {}, has_more: false, offset: 0,
  });
});
afterEach(cleanup);
it('reopens without refetching the authorized full payload', async () => {
  view();
  const button = await screen.findByRole('button', { name: /sample/ });
  fireEvent.click(button);
  await screen.findByText('payload');
  fireEvent.click(button);
  fireEvent.click(button);
  await screen.findByText('payload');
  expect(mocks.fetchLog).toHaveBeenCalledTimes(1);
});
it('prefetches on deliberate focus and never performs a broad speculative retry', async () => {
  mocks.fetchLog.mockResolvedValue({ event: null });
  view();
  const button = await screen.findByRole('button', { name: /sample/ });
  fireEvent.focus(button);
  await waitFor(() => expect(mocks.fetchLog).toHaveBeenCalledTimes(1));
  expect(mocks.fetchLog.mock.calls[0][1]).toEqual({ start: '2026-09-30T00:00:59.000Z', end: '2026-09-30T00:01:01.000Z' });
  expect(mocks.fetchLog.mock.calls[0][3]).toBeInstanceOf(AbortSignal);
});
it('cancels a transient hover and aborts a started prefetch on navigation', async () => {
  const mounted = view();
  const button = await screen.findByRole('button', { name: /sample/ });
  fireEvent.mouseEnter(button);
  fireEvent.mouseLeave(button);
  await new Promise(resolve => setTimeout(resolve, 250));
  expect(mocks.fetchLog).not.toHaveBeenCalled();
  mocks.fetchLog.mockImplementation(() => new Promise(() => {}));
  fireEvent.mouseEnter(button);
  await waitFor(() => expect(mocks.fetchLog).toHaveBeenCalledTimes(1));
  const signal = mocks.fetchLog.mock.calls[0][3] as AbortSignal;
  mounted.unmount();
  expect(signal.aborted).toBe(true);
});
it('aborts all page work on a new investigation and preserves the new request', async () => {
  mocks.events.mockImplementation(() => new Promise(() => {}));
  const client = new QueryClient();
  const panel = (identifierValue: string) => <QueryClientProvider client={client}><AssetStream {...props} identifierValue={identifierValue} /></QueryClientProvider>;
  const mounted = render(panel('old'));
  await waitFor(() => expect(mocks.events).toHaveBeenCalledTimes(1));
  const oldSignal = mocks.events.mock.calls[0][1].signal as AbortSignal;
  mounted.rerender(panel('new'));
  await waitFor(() => expect(mocks.events).toHaveBeenCalledTimes(2));
  const newSignal = mocks.events.mock.calls[1][1].signal as AbortSignal;
  expect(oldSignal.aborted).toBe(true);
  expect(newSignal.aborted).toBe(false);
  mounted.unmount();
  expect(newSignal.aborted).toBe(true);
});
