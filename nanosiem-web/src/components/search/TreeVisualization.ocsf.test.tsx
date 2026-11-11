// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5271: on an OCSF process-creation row the node is the CREATED process:
// `process.pid` / `process.cmd_line`, not the parent's `actor.process.*`.
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TreeVisualization, type TreeNode } from './TreeVisualization';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const config = { parent_field: 'actor.process.uid', child_field: 'process.uid', label_field: 'process.name' };

it('shows the created process pid and command line, not the parent', () => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} disconnect() {} });
  const node: TreeNode = {
    id: 'n1',
    label: 'child.exe',
    children: [],
    _data: {
      class_uid: 1007,
      'process.pid': '4242',
      'actor.process.pid': '100',
      'process.cmd_line': 'child.exe --flag',
      'actor.process.cmd_line': 'parent.exe',
    },
  } as TreeNode;
  render(<TreeVisualization nodes={[node]} config={config} />);
  expect(screen.getByText(/4242/)).toBeTruthy();
  expect(screen.queryByText(/· 100\b/)).toBeNull();
  expect(screen.getAllByText(/child\.exe --flag/).length).toBeGreaterThan(0);
  expect(screen.queryByText('parent.exe')).toBeNull();
});

it('falls back to the actor pid when the row has no process pid (0 is unset)', () => {
  vi.stubGlobal('IntersectionObserver', class { observe() {} disconnect() {} });
  const node: TreeNode = {
    id: 'n2',
    label: 'svc.exe',
    children: [],
    _data: { class_uid: 4001, 'process.pid': 0, 'actor.process.pid': 777 },
  } as TreeNode;
  render(<TreeVisualization nodes={[node]} config={config} />);
  expect(screen.getByText(/777/)).toBeTruthy();
});
