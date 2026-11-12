// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5313: `| tree process` over Defender EDR events (no `process.uid`) was
// empty with "Try a different root…" advice. The server's `_tree_note` now
// explains the missing id, and the "materialized view" wording is gone.
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TreeVisualization } from './TreeVisualization';
import { PagedTreeView } from './PagedTreeView';

vi.mock('@/lib/api', () => ({ api: { getTreePage: vi.fn(), searchAsync: vi.fn() } }));

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const config = { parent_field: 'actor.process.uid', child_field: 'process.uid', label_field: 'process.name' };
const NOTE = 'None of the 29 matching events carry process.uid, so there is nothing to link.';

it('shows the server note in the empty state instead of generic advice', () => {
  render(<TreeVisualization nodes={[]} config={config} emptyNote={NOTE} />);
  expect(screen.getByText(NOTE)).toBeTruthy();
  expect(screen.queryByText(/Try a different root/)).toBeNull();
});

it('keeps the generic advice without a note', () => {
  render(<TreeVisualization nodes={[]} config={config} />);
  expect(screen.getByText(/Try a different root/)).toBeTruthy();
});

it('reads _tree_note off the non-paged tree marker', () => {
  render(<PagedTreeView marker={{ _display_type: 'tree', _tree_note: NOTE }} nodes={[]} config={config} />);
  expect(screen.getByText(NOTE)).toBeTruthy();
  expect(document.body.textContent).not.toContain('materialized view');
});
