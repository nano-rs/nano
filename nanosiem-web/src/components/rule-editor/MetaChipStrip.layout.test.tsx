// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5783: the rule editor Meta strip and the Rules tactic filter wrap
 * instead of hiding items behind a hidden-scrollbar sideways scroller, and
 * every tag is reachable from the keyboard.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MetaChipStrip } from './EditorTopBar';
import { TacticChips } from '@/components/rules/RulesToolbarChips';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const TAGS = ['brute_force', 'identity_threat_detection_and_response', 'windows_security_eventlog', 'soc_tier1', 'pci_dss_10_2_4'];
const META = {
  name: 'nan5783_meta_strip_check',
  severity: 'high',
  mode: 'staging',
  folder: 'Automated',
  schedule: '*/5 * * * *',
  mitre_tactics: 'TA0006',
  mitre_techniques: 'T1110,T1110.001,T1110.003',
  tags: TAGS.join(','),
} as unknown as Parameters<typeof MetaChipStrip>[0]['metadata'];

function strip() {
  return render(<MetaChipStrip metadata={META} availableFolders={['Automated']} />);
}

describe('rule editor Meta strip (NAN-5783)', () => {
  it('wraps instead of scrolling sideways', () => {
    strip();
    const el = screen.getByTestId('rule-editor-meta-strip');
    const cls = el.className.split(/\s+/);
    expect(cls).toContain('flex-wrap');
    expect(cls).not.toContain('overflow-x-auto');
    expect(cls).not.toContain('h-9'); // a fixed height would clip the wrapped rows
    expect(screen.getByTestId('rule-editor-meta-tags').className).toContain('flex-wrap');
  });

  it('shows three tags and a keyboard-operable "+N" that lists every other tag', async () => {
    strip();
    const shown = screen.getAllByTestId('rule-editor-meta-tag').map((t) => t.textContent);
    expect(shown).toEqual(['#brute_force', '#identity_threat_detection_and_response', '#windows_security_eventlog']);

    const more = screen.getByTestId('rule-editor-meta-more-tags');
    expect(more.tagName).toBe('BUTTON');
    expect(more.textContent).toBe('+2');
    expect(more.getAttribute('aria-label')).toBe('Show 2 more tags');
    expect(more.getAttribute('title')).toBeNull();

    act(() => {
      more.focus();
    });
    fireEvent.keyDown(more, { key: 'Enter' });
    fireEvent.click(more);
    const list = await screen.findByTestId('rule-editor-meta-more-tags-list');
    expect(within(list).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['#soc_tier1', '#pci_dss_10_2_4']);
    expect(more.getAttribute('aria-expanded')).toBe('true');
  });

  it('a cut tag is focusable and its full name is in the app tooltip, not a native title', async () => {
    vi.spyOn(HTMLElement.prototype, 'scrollWidth', 'get').mockImplementation(() => 400);
    vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockImplementation(() => 140);
    strip();
    const chip = screen.getAllByTestId('rule-editor-meta-tag')[1];
    expect(chip.querySelector('[title]')).toBeNull();
    const text = chip.querySelector<HTMLElement>('[data-truncated="true"]')!;
    expect(text.getAttribute('tabindex')).toBe('0');
    act(() => {
      text.focus();
    });
    const tip = await screen.findByText('#identity_threat_detection_and_response', { selector: '[data-side] *, [data-side]' });
    expect(tip.closest('[aria-hidden="true"]')).not.toBeNull();
  });

  it('no "+N" when there are three tags or fewer', () => {
    render(<MetaChipStrip metadata={{ ...META, tags: 'a,b,c' }} />);
    expect(screen.queryByTestId('rule-editor-meta-more-tags')).toBeNull();
  });
});

describe('Rules tactic filter (NAN-5783)', () => {
  it('wraps every tactic onto visible rows instead of a hidden sideways scroller', () => {
    render(<TacticChips value="All tactics" onChange={() => {}} />);
    const group = screen.getByRole('group', { name: 'Filter by tactic' });
    const cls = group.className.split(/\s+/);
    expect(cls).toContain('flex-wrap');
    expect(cls).not.toContain('overflow-x-auto');
    const names = within(group).getAllByRole('button').map((b) => b.textContent);
    expect(names[0]).toBe('All tactics');
    expect(names).toContain('Command and Control');
    expect(names).toContain('Impact');
  });

  it('selecting a tactic past the old visible edge works', () => {
    const onChange = vi.fn();
    render(<TacticChips value="All tactics" onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: 'Impact' }));
    expect(onChange).toHaveBeenCalledWith('Impact');
  });
});
