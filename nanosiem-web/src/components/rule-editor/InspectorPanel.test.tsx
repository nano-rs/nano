// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-3023: the rule editor Inspector moved from radio lists to segmented
 * controls + detail cards. Styling only — pin that the controls still drive
 * the same callbacks (visibility clears groups, non-specific playbook mode
 * clears the playbook id, group checkboxes toggle membership).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('@/hooks/use-api', () => ({
  useGroups: () => ({
    data: [
      { id: 'g1', name: 'soc-tier1' },
      { id: 'g2', name: 'soc-tier2' },
    ],
    loading: false,
  }),
  usePlaybooks: () => ({ data: { playbooks: [] }, loading: false }),
}));

import { InspectorCasesTab } from '@/enterprise/components/rule-editor/InspectorCasesTab';
import { RulePlaybookSelector } from '@/enterprise/components/detection/editor/RulePlaybookSelector';
import { SectionHeading } from './InspectorPrimitives';

afterEach(cleanup);

function renderCases(overrides: Partial<Parameters<typeof InspectorCasesTab>[0]> = {}) {
  const props = {
    visibility: 'public' as const,
    groupIds: [] as string[],
    assignedGroupId: null,
    onVisibilityChange: vi.fn(),
    onGroupIdsChange: vi.fn(),
    onAssignedGroupChange: vi.fn(),
    ...overrides,
  };
  render(<InspectorCasesTab {...props} />);
  return props;
}

describe('Inspector Cases tab', () => {
  it('switches visibility through the segmented control and clears groups when leaving Group', () => {
    const props = renderCases({ visibility: 'group', groupIds: ['g1'] });
    const radio = screen.getByRole('radio', { name: 'Private' });
    fireEvent.click(radio);
    expect(props.onGroupIdsChange).toHaveBeenCalledWith([]);
    expect(props.onVisibilityChange).toHaveBeenCalledWith('private');
  });

  it('marks the current visibility and shows its description', () => {
    renderCases({ visibility: 'public' });
    expect(screen.getByRole('radio', { name: 'Public' }).getAttribute('aria-checked')).toBe('true');
    expect(screen.getByText('Everyone can view cases from this rule.')).toBeTruthy();
  });

  it('toggles group membership in Group mode', () => {
    const props = renderCases({ visibility: 'group', groupIds: ['g1'] });
    fireEvent.click(screen.getByRole('checkbox', { name: 'soc-tier2' }));
    expect(props.onGroupIdsChange).toHaveBeenCalledWith(['g1', 'g2']);
  });

  it('routes the default queue select to onAssignedGroupChange', () => {
    const props = renderCases();
    fireEvent.change(screen.getByRole('combobox', { name: 'Default queue' }), { target: { value: 'g2' } });
    expect(props.onAssignedGroupChange).toHaveBeenCalledWith('g2');
  });
});

describe('Inspector playbook selector', () => {
  it('clears the playbook id when leaving Specific mode', () => {
    const onModeChange = vi.fn();
    const onPlaybookIdChange = vi.fn();
    render(
      <RulePlaybookSelector
        mode="specific"
        playbookId="pb-1"
        onModeChange={onModeChange}
        onPlaybookIdChange={onPlaybookIdChange}
      />,
    );
    fireEvent.click(screen.getByRole('radio', { name: 'Adaptive' }));
    expect(onModeChange).toHaveBeenCalledWith('adaptive');
    expect(onPlaybookIdChange).toHaveBeenCalledWith(null);
  });
});

describe('SectionHeading', () => {
  it('renders a mono label with no icon', () => {
    const { container } = render(<SectionHeading badge={3}>History</SectionHeading>);
    expect(container.querySelector('svg')).toBeNull();
    expect(screen.getByText('History').className).toContain('font-mono');
    expect(screen.getByText('3')).toBeTruthy();
  });
});
