// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-5501 — the rule test panel must test the rule as currently edited. A
// panel-local edit is labelled as such, and Apply never silently overwrites
// the editor's query.

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import type { TestDetectionResult } from '@/lib/api/types';

// CodeMirror doesn't run in jsdom — a textarea keeps the same value/onChange
// contract (external value changes never fire onChange).
vi.mock('@/components/editor', () => ({
  QueryEditor: ({ value, onChange }: { value: string; onChange: (v: string) => void }) => (
    <textarea
      aria-label="test query"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));
vi.mock('@/hooks/useSchemaFieldMap', () => ({ useSchemaFieldMap: () => ({}) }));
vi.mock('@/components/ui/date-time-range-picker', () => ({ DateTimeRangePicker: () => null }));

import { TestDrawer } from './TestDrawer';

beforeAll(() => {
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }
  if (!('ResizeObserver' in window)) {
    (window as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
});

afterEach(cleanup);

const TEMPLATE = 'metadata.log_source = "your_source" | risk';
const RULE = 'user = "admin" | stats count by src_ip';

const EMPTY_RESULT = {
  total_matches: 0,
  sample_events: [],
} as unknown as TestDetectionResult;

function setup(initialQuery = TEMPLATE, extra: { ruleId?: string } = {}) {
  const runUnsavedTest = vi.fn().mockResolvedValue(EMPTY_RESULT);
  const runSavedTest = vi.fn().mockResolvedValue(EMPTY_RESULT);
  const onApplyQuery = vi.fn();
  const props = {
    open: true,
    onClose: () => {},
    runUnsavedTest,
    runSavedTest,
    onApplyQuery,
    ...extra,
  };
  const utils = render(<TestDrawer {...props} query={initialQuery} />);
  const rerenderQuery = (q: string) => utils.rerender(<TestDrawer {...props} query={q} />);
  return { runUnsavedTest, runSavedTest, onApplyQuery, rerenderQuery };
}

function status() {
  return screen.getByTestId('test-query-status').textContent ?? '';
}

async function clickRun() {
  // Header re-run button.
  const btn = screen.getByRole('button', { name: /^(run|re-run)$/i });
  await act(async () => {
    fireEvent.click(btn);
  });
}

describe('TestDrawer (NAN-5501)', () => {
  it('follows the editor: editing the rule changes what Run tests sends', async () => {
    const { runUnsavedTest, rerenderQuery } = setup();
    // The analyst replaces the template in CODE while the drawer is open.
    rerenderQuery(RULE);

    expect((screen.getByLabelText('test query') as HTMLTextAreaElement).value).toBe(RULE);
    expect(status()).toContain('synced with editor');
    expect(screen.queryByText(/Apply to editor/i)).toBeNull();

    await clickRun();
    expect(runUnsavedTest).toHaveBeenCalledTimes(1);
    expect(runUnsavedTest.mock.calls[0][0].query).toBe(RULE);
  });

  it('labels a panel-local edit clearly and runs that edit', async () => {
    const { runUnsavedTest } = setup(RULE);
    fireEvent.change(screen.getByLabelText('test query'), {
      target: { value: `${RULE} | where count > 5` },
    });

    expect(status()).toMatch(/edited in this panel/);
    expect(status()).toMatch(/not the rule/);
    expect(status()).not.toContain('synced with editor');

    await clickRun();
    expect(runUnsavedTest.mock.calls[0][0].query).toBe(`${RULE} | where count > 5`);
  });

  it('flags when the rule changed after the panel edit, and reset returns to following the editor', () => {
    const { rerenderQuery } = setup(RULE);
    fireEvent.change(screen.getByLabelText('test query'), { target: { value: 'panel only' } });
    rerenderQuery('rule edited later');
    expect(status()).toMatch(/rule changed since/);
    // The panel edit is not clobbered by the editor change.
    expect((screen.getByLabelText('test query') as HTMLTextAreaElement).value).toBe('panel only');

    fireEvent.click(screen.getByRole('button', { name: /use rule query/i }));
    expect(status()).toContain('synced with editor');
    expect((screen.getByLabelText('test query') as HTMLTextAreaElement).value).toBe('rule edited later');
  });

  it('Apply to editor requires confirmation before overwriting the rule', () => {
    const { onApplyQuery } = setup(RULE);
    fireEvent.change(screen.getByLabelText('test query'), { target: { value: 'panel only' } });

    fireEvent.click(screen.getByRole('button', { name: /apply to editor/i }));
    // Nothing applied yet — a confirm with both sides is shown.
    expect(onApplyQuery).not.toHaveBeenCalled();
    const diff = screen.getByTestId('apply-query-diff');
    expect(diff.textContent).toContain(RULE);
    expect(diff.textContent).toContain('panel only');

    // Cancel keeps the rule intact.
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onApplyQuery).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: /apply to editor/i }));
    fireEvent.click(screen.getByRole('button', { name: /replace editor query/i }));
    expect(onApplyQuery).toHaveBeenCalledWith('panel only');
  });

  it('Esc while the Apply confirm is open does not close the drawer', () => {
    const onClose = vi.fn();
    const props = {
      open: true,
      onClose,
      runUnsavedTest: vi.fn().mockResolvedValue(EMPTY_RESULT),
      runSavedTest: vi.fn().mockResolvedValue(EMPTY_RESULT),
      onApplyQuery: vi.fn(),
    };
    render(<TestDrawer {...props} query={RULE} />);
    fireEvent.change(screen.getByLabelText('test query'), { target: { value: 'panel only' } });
    fireEvent.click(screen.getByRole('button', { name: /apply to editor/i }));
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(onClose).not.toHaveBeenCalled();
    expect((screen.getByLabelText('test query') as HTMLTextAreaElement).value).toBe('panel only');
  });

  it('reopening the drawer drops a panel fork and follows the editor', () => {
    const base = {
      onClose: () => {},
      runUnsavedTest: vi.fn().mockResolvedValue(EMPTY_RESULT),
      runSavedTest: vi.fn().mockResolvedValue(EMPTY_RESULT),
    };
    const { rerender } = render(<TestDrawer {...base} open query={RULE} />);
    fireEvent.change(screen.getByLabelText('test query'), { target: { value: 'panel only' } });
    rerender(<TestDrawer {...base} open={false} query={RULE} />);
    rerender(<TestDrawer {...base} open query="rule v2" />);
    expect(status()).toContain('synced with editor');
    expect((screen.getByLabelText('test query') as HTMLTextAreaElement).value).toBe('rule v2');
  });

  it('when the editor catches up to the panel copy, the panel follows the editor again', () => {
    const { rerenderQuery } = setup(RULE);
    fireEvent.change(screen.getByLabelText('test query'), { target: { value: 'panel only' } });
    rerenderQuery('panel only');
    expect(status()).toContain('synced with editor');
    rerenderQuery('rule v3');
    expect((screen.getByLabelText('test query') as HTMLTextAreaElement).value).toBe('rule v3');
    expect(status()).toContain('synced with editor');
  });

  it('uses the saved-rule endpoint only when the panel follows the editor', async () => {
    const { runSavedTest, runUnsavedTest } = setup(RULE, { ruleId: 'r1' });
    await clickRun();
    expect(runSavedTest).toHaveBeenCalledTimes(1);
    expect(runUnsavedTest).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText('test query'), { target: { value: 'panel only' } });
    await clickRun();
    expect(runUnsavedTest.mock.calls[0][0].query).toBe('panel only');
  });
});
