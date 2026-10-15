// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PagedTreeView } from './PagedTreeView';
import { SearchFooterProvider } from './footer-reporter';
import type { TreeNode } from './TreeVisualization';
import type { TreePageResponse } from '@/lib/api/types';
const mocks = vi.hoisted(() => ({ page: vi.fn(), job: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { getTreePage: mocks.page, searchAsync: mocks.job } }));
vi.mock('./TreeVisualization', () => ({ TreeVisualization: ({ nodes, onLoadChildren }: { nodes: TreeNode[]; onLoadChildren?: (node: TreeNode, offset: number) => void }) => <div><div data-testid="nodes">{nodes.map(n => `${n.id}:${n.children.length}`).join(',')}</div>{nodes[0] && <><button onClick={() => onLoadChildren?.(nodes[0], 0)}>Expand root</button><button onClick={() => onLoadChildren?.(nodes[0], nodes[0]._next_children_offset!)}>More children</button></>}</div> }));
const config = { parent_field: 'actor.process.uid', child_field: 'process.uid', label_field: 'process.name' };
const range = { start: '2026-09-30T00:00:00Z', end: '2026-09-30T01:00:00Z' };
const marker = { _tree_pending: true, _tree_query: '* | tree', _tree_time_range: range, _tree_run_id: 'first' };
function page(preview: boolean, nodes: TreeNode[], next: number | null = null): TreePageResponse {
  return { status: 'completed', error: null, preview, nodes: nodes as unknown as Record<string, unknown>[], config, next_offset: next, total_roots: 30, total_nodes: 60, source_truncated: false, total_count: 1, total_count_exact: !preview };
}
const root = (id: string, index = 0): TreeNode => ({ id, label: id, children: [], _page_path: [index], _children_count: 30 });
afterEach(() => { cleanup(); mocks.page.mockReset(); mocks.job.mockReset(); });
it('paints provisional roots before exact completion, then fetches root and child pages on demand', async () => {
  let release!: (value: TreePageResponse) => void;
  mocks.job.mockResolvedValue({ job_id: 'owned-job', status: 'queued' });
  mocks.page.mockImplementation(request => {
    if (!request.job_id) return Promise.resolve(page(true, [root('preview')]));
    if (request.parent_path?.length) {
      const children = Array.from({ length: request.offset ? 5 : 25 }, (_, i) => ({ id: `child-${request.offset + i}`, label: 'child', children: [], _page_path: [0, request.offset + i] }));
      return Promise.resolve(page(false, children, request.offset ? null : 25));
    }
    if (request.offset) return Promise.resolve(page(false, [root('second-root', 25)]));
    return new Promise(resolve => { release = resolve; });
  });
  render(<PagedTreeView marker={marker} nodes={[]} config={config} />);
  await waitFor(() => expect(screen.getByTestId('nodes').textContent).toBe('preview:0'));
  expect(screen.getByRole('status').textContent).toContain('provisional');
  await waitFor(() => expect(release).toBeTypeOf('function'));
  await act(async () => release(page(false, [root('exact')], 25)));
  expect(screen.getByTestId('nodes').textContent).toBe('exact:0');
  fireEvent.click(screen.getByText('Expand root'));
  await waitFor(() => expect(screen.getByTestId('nodes').textContent).toBe('exact:25'));
  expect(mocks.page).toHaveBeenLastCalledWith(expect.objectContaining({ job_id: 'owned-job', parent_path: [0], offset: 0, limit: 25 }), expect.any(AbortSignal));
  fireEvent.click(screen.getByText('More children'));
  await waitFor(() => expect(screen.getByTestId('nodes').textContent).toBe('exact:30'));
  fireEvent.click(screen.getByText('Load more roots'));
  await waitFor(() => expect(screen.getByTestId('nodes').textContent).toBe('exact:30,second-root:0'));
});
it('aborts old ownership and ignores late preview data when pivoting', async () => {
  const signals: AbortSignal[] = []; const resolve: ((page: TreePageResponse) => void)[] = [];
  mocks.page.mockImplementation((_request, signal) => { signals.push(signal); return new Promise(r => resolve.push(r)); });
  const mounted = render(<PagedTreeView marker={marker} nodes={[]} config={config} />);
  mounted.rerender(<PagedTreeView marker={{ ...marker, _tree_run_id: 'next' }} nodes={[]} config={config} />);
  expect(signals[0].aborted).toBe(true); expect(signals[1].aborted).toBe(false);
  await act(async () => resolve[0](page(true, [root('stale')])));
  expect(screen.getByTestId('nodes').textContent).toBe('');
  expect(mocks.job).not.toHaveBeenCalled();
  mounted.unmount(); expect(signals[1].aborted).toBe(true);
});
it('retains explicitly provisional ancestry after exact job failure', async () => {
  mocks.page.mockResolvedValue(page(true, [root('preview')]));
  mocks.job.mockRejectedValue(new Error('exact unavailable'));
  render(<PagedTreeView marker={marker} nodes={[]} config={config} />);
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('exact unavailable'));
  expect(screen.getByTestId('nodes').textContent).toBe('preview:0');
  expect(screen.getByRole('status').textContent).toContain('provisional');
});

it('keeps atomic tree compatibility and settles its footer without starting panel work', () => {
  const report = vi.fn();
  render(<SearchFooterProvider value={report}><PagedTreeView marker={{ _display_type: 'tree' }} nodes={[root('atomic')]} config={config} /></SearchFooterProvider>);
  expect(screen.getByTestId('nodes').textContent).toBe('atomic:0');
  expect(mocks.page).not.toHaveBeenCalled(); expect(mocks.job).not.toHaveBeenCalled();
  expect(report).toHaveBeenLastCalledWith(expect.objectContaining({ loading: false }));
});
it('shows the server note naming the missing field on an empty exact tree (NAN-3261)', async () => {
  mocks.job.mockResolvedValue({ job_id: 'owned-job', status: 'queued' });
  mocks.page.mockImplementation(request => Promise.resolve(request.job_id
    ? { ...page(false, []), total_roots: 0, total_nodes: 0, note: 'No events in range carry http_request.referrer.' }
    : page(true, [])));
  render(<PagedTreeView marker={marker} nodes={[]} config={config} />);
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain('No events in range carry http_request.referrer.'));
});
