import { describe, expect, it } from 'vitest';

import {
  initialTabs,
  tabLabel,
  newAgentSearchTab,
  newAgentToolTab,
  newTab,
  tabsReducer,
  type TabsState,
} from './tabs';

const GROUP = { id: 'pivt-1', label: 'why the spike?', overflow: 0 };

/** A workspace with one pivt group holding one search tab. */
function withGroup(): TabsState {
  let state = initialTabs();
  state = tabsReducer(state, { type: 'openGroup', group: GROUP });
  state = tabsReducer(state, {
    type: 'add',
    tab: newAgentSearchTab(GROUP.id, 'user=admin', { type: 'preset', preset: 'Last 24 hours' }),
  });
  return state;
}

describe('tab groups', () => {
  it('opens a group once, not once per tool call', () => {
    let state = initialTabs();
    state = tabsReducer(state, { type: 'openGroup', group: GROUP });
    state = tabsReducer(state, { type: 'openGroup', group: GROUP });
    expect(state.groups).toHaveLength(1);
  });

  it('closes the whole investigation with its tabs', () => {
    let state = withGroup();
    expect(state.tabs).toHaveLength(2); // the analyst's tab + pivt's

    state = tabsReducer(state, { type: 'closeGroup', id: GROUP.id });
    expect(state.groups).toHaveLength(0);
    expect(state.tabs).toHaveLength(1);
    expect(state.tabs[0].origin).toBe('user');
  });

  it('re-selects a surviving tab when the group holding the active one closes', () => {
    let state = withGroup();
    const agentTab = state.tabs.find((tab) => tab.origin === 'pivt')!;
    state = tabsReducer(state, { type: 'select', id: agentTab.id });

    state = tabsReducer(state, { type: 'closeGroup', id: GROUP.id });
    // The active id must never point at a tab that no longer exists.
    expect(state.tabs.some((tab) => tab.id === state.activeId)).toBe(true);
  });

  it('drops a group once its last tab is closed one at a time', () => {
    let state = withGroup();
    const agentTab = state.tabs.find((tab) => tab.origin === 'pivt')!;

    state = tabsReducer(state, { type: 'close', id: agentTab.id });
    // An empty group chip in the strip would be a group that isn't there.
    expect(state.groups).toHaveLength(0);
  });

  it('keeps the group while it still holds tabs', () => {
    let state = withGroup();
    state = tabsReducer(state, {
      type: 'add',
      tab: newAgentSearchTab(GROUP.id, 'user=root', { type: 'preset', preset: 'Last hour' }),
    });
    const first = state.tabs.find((tab) => tab.query === 'user=admin')!;

    state = tabsReducer(state, { type: 'close', id: first.id });
    expect(state.groups).toHaveLength(1);
  });

  it('counts tool calls past the tab cap instead of hiding them', () => {
    let state = withGroup();
    state = tabsReducer(state, { type: 'countOverflow', id: GROUP.id });
    state = tabsReducer(state, { type: 'countOverflow', id: GROUP.id });
    expect(state.groups[0].overflow).toBe(2);
  });

  it('renames the group when the notebook titles the investigation', () => {
    let state = withGroup();
    state = tabsReducer(state, { type: 'renameGroup', id: GROUP.id, label: 'lateral movement' });
    expect(state.groups[0].label).toBe('lateral movement');
  });
});

describe('agent tabs', () => {
  it('caps a mirrored search to a preview, and the analyst\'s own tab to a full run', () => {
    const preview = newAgentSearchTab(GROUP.id, 'x', { type: 'preset', preset: 'Last hour' });
    expect(preview.preview).toBe(true);
    expect(preview.limit).toBe(10);
    expect(preview.origin).toBe('pivt');

    const mine = newTab('x');
    expect(mine.preview).toBeUndefined();
    expect(mine.limit).toBe(500);
    expect(mine.origin).toBe('user');
  });

  it('lands a tool result on the tab that recorded its call', () => {
    let state = initialTabs();
    state = tabsReducer(state, { type: 'openGroup', group: GROUP });
    state = tabsReducer(state, {
      type: 'add',
      tab: newAgentToolTab(GROUP.id, { callId: 'toolu_1', name: 'search_sql', input: {} }),
    });
    state = tabsReducer(state, {
      type: 'add',
      tab: newAgentToolTab(GROUP.id, { callId: 'toolu_2', name: 'search_sql', input: {} }),
    });

    state = tabsReducer(state, {
      type: 'toolResult',
      callId: 'toolu_1',
      result: '42 rows',
      failed: false,
    });

    const tabs = state.tabs.filter((tab) => tab.kind === 'tool');
    // Matched by call id, not by position: pivt fires tools in parallel, so the
    // most recent tab is regularly the wrong one to attribute a result to.
    expect(tabs.find((tab) => tab.tool?.callId === 'toolu_1')?.tool?.result).toBe('42 rows');
    expect(tabs.find((tab) => tab.tool?.callId === 'toolu_2')?.tool?.result).toBeUndefined();
  });

  it('marks a denied call on its own tab', () => {
    let state = initialTabs();
    state = tabsReducer(state, { type: 'openGroup', group: GROUP });
    state = tabsReducer(state, {
      type: 'add',
      tab: newAgentToolTab(GROUP.id, { callId: 'toolu_9', name: 'search_sql', input: {} }),
    });
    state = tabsReducer(state, {
      type: 'toolResult',
      callId: 'toolu_9',
      result: 'Forbidden',
      failed: true,
    });
    expect(state.tabs.find((tab) => tab.kind === 'tool')?.tool?.failed).toBe(true);
  });
});

describe('the workspace never empties', () => {
  it('leaves a fresh tab when the last one is closed', () => {
    const state = initialTabs();
    const next = tabsReducer(state, { type: 'close', id: state.tabs[0].id });
    expect(next.tabs).toHaveLength(1);
    expect(next.activeId).toBe(next.tabs[0].id);
  });

  it('leaves a fresh tab when closing a group would empty the workspace', () => {
    let state: TabsState = { tabs: [], activeId: '', groups: [] };
    state = tabsReducer(state, { type: 'openGroup', group: GROUP });
    state = tabsReducer(state, {
      type: 'add',
      tab: newAgentSearchTab(GROUP.id, 'x', { type: 'preset', preset: 'Last hour' }),
    });

    state = tabsReducer(state, { type: 'closeGroup', id: GROUP.id });
    expect(state.tabs).toHaveLength(1);
    expect(state.tabs.some((tab) => tab.id === state.activeId)).toBe(true);
  });
});

describe('tab labels', () => {
  it('leads with the aggregation, not the shared filter prefix', () => {
    // pivt's mirrored searches on an OCSF tenant all begin `class_uid=…`, so
    // labelling by the head of the string produced a strip reading "cl…", "cl…",
    // "cl…". What makes each tab different is what it AGGREGATES.
    const tab = newTab('class_uid=1001 source_type=windows_sysmon | stats count by process_name');
    expect(tabLabel(tab)).toBe('stats count by process_name');
  });

  it('prefers the aggregation over a trailing sort', () => {
    const tab = newTab('class_uid=1001 | stats count by user | sort -count | head 10');
    expect(tabLabel(tab)).toBe('stats count by user');
  });

  it('falls back to the filter when there is no aggregation', () => {
    const tab = newTab('src_ip="10.0.0.1"');
    expect(tabLabel(tab)).toBe('src_ip="10.0.0.1"');
  });

  it('says what an unrun tab is', () => {
    expect(tabLabel(newTab())).toBe('New search');
  });
});
