// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5783: in a narrow editor column (pivt open at 1280) the editor's top
 * row and bottom tray wrap instead of running under the inspector rail. jsdom
 * has no layout; the real-browser scenario test_v2035_layout_batch_a measures
 * it. These pin the wrap contract and the accessible title.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { EditorTopBar } from './EditorTopBar';
import { BottomTray } from './BottomTray';

vi.mock('@/hooks/use-capabilities', () => ({
  useCapabilities: () => ({ capabilities: { aiTuning: false } }),
}));

afterEach(cleanup);

const META = {
  title: 'windows_suspicious_lsass_access_via_procdump_from_unusual_parent',
  severity: 'high',
  mode: 'staging',
  folder: 'Automated',
  tags: '',
} as unknown as Parameters<typeof EditorTopBar>[0]['metadata'];

function topBar() {
  return render(
    <EditorTopBar
      metadata={META}
      isNewMode={false}
      apiMode="staging"
      dirty={false}
      saving={false}
      valid
      viewMode="code"
      onViewMode={() => {}}
      onBack={() => {}}
      onSave={() => {}}
      onOpenTest={() => {}}
      onViewMatches={() => {}}
    />,
  );
}

const classes = (el: Element) => el.className.split(/\s+/);

describe('rule editor top row (NAN-5783)', () => {
  it('wraps, with the actions as one group that moves to a second row', () => {
    topBar();
    const row = screen.getByTestId('rule-editor-top-row');
    expect(classes(row)).toContain('flex-wrap');
    expect(classes(row)).not.toContain('h-12'); // a fixed height would clip the second row
    const actions = screen.getByTestId('rule-editor-top-actions');
    expect(actions.parentElement).toBe(row);
    expect(classes(actions)).toContain('flex-wrap');
    for (const name of ['Matches', 'Test rule', 'Rule actions', 'Saved']) {
      expect(within(actions).getByRole('button', { name: new RegExp(name) })).toBeTruthy();
    }
  });

  it('the title keeps a basis and truncates; the mode pill never shrinks under the switch', () => {
    topBar();
    const title = screen.getByText(META.title as string);
    expect(title.className).toContain('truncate');
    expect(title.closest('.basis-\\[160px\\]')).not.toBeNull();
    const row = screen.getByTestId('rule-editor-top-row');
    const titleBlock = title.closest('.basis-\\[160px\\]') as HTMLElement;
    // Every chip beside the title (mode pill, UNSAVED, DRAFT) is shrink-0.
    const chips = Array.from(titleBlock.children).slice(1);
    expect(chips.length).toBeGreaterThan(0);
    for (const c of chips) expect(classes(c)).toContain('shrink-0');
    expect(row.contains(titleBlock)).toBe(true);
  });
});

describe('rule editor bottom tray (NAN-5783)', () => {
  it('sizes to the editor column: the header wraps and the cards stack by container width', () => {
    const { container } = render(
      <BottomTray validation={null} matchCount={12} lastSavedLabel="2m ago" versions={[]} onOpenTest={() => {}} />,
    );
    const tray = container.firstElementChild as HTMLElement;
    expect(classes(tray)).toContain('@container/tray');
    const header = tray.querySelector('button[aria-controls="rule-editor-bottom-tray-body"]') as HTMLElement;
    expect(classes(header)).toContain('flex-wrap');
    expect(classes(header)).not.toContain('h-9');
  });
});
