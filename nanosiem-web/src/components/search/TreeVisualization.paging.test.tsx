// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TreeVisualization, type TreeNode } from './TreeVisualization';
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('offers expansion for unloaded children and reads only explicit child pages', () => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} disconnect() {} });
  const config = { parent_field: 'actor.process.uid', child_field: 'process.uid', label_field: 'process.name' };
  const root: TreeNode = { id: 'root', label: 'root.exe', children: [], _page_path: [0], _children_count: 30 };
  const load = vi.fn();
  const mounted = render(<TreeVisualization nodes={[root]} config={config} serverPaged onLoadChildren={load} />);
  expect(load).not.toHaveBeenCalled();
  expect(screen.getByText(/1 loaded nodes/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Expand' }));
  expect(load).toHaveBeenCalledExactlyOnceWith(root, 0);
  const partial = { ...root, children: [{ id: 'child', label: 'child.exe', children: [] }], _next_children_offset: 25 };
  mounted.rerender(<TreeVisualization nodes={[partial]} config={config} serverPaged onLoadChildren={load} />);
  fireEvent.click(screen.getByText('Load more children'));
  expect(load).toHaveBeenLastCalledWith(partial, 25);
  expect(screen.getByPlaceholderText('Filter loaded nodes (name or cmdline)…')).toBeTruthy();
});
