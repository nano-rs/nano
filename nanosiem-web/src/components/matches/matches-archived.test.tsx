// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5683 — the Matches page stays reachable from an archived (deleted)
// rule (its history is kept), but offers none of the rule actions the API
// now refuses with 404: no Pause/Resume, no Promote/alerting toggle, no Edit,
// no "Open test drawer". The header reads Archived, not a running mode.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DetectionRule } from '@/lib/api/types';
import { MatchesHero } from './MatchesHero';
import { LogicTab } from './LogicTab';

vi.mock('@/hooks/use-api', () => ({
  useDetectionMatches: () => ({ data: { matches: [] } }),
  useRuleDispositionStats: () => ({ data: null }),
  useRuleVersions: () => ({ data: [], loading: false }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

function rule(overrides: Partial<DetectionRule> = {}): DetectionRule {
  return {
    id: 'rule_one',
    name: 'archived_rule',
    query: 'source_type="test"',
    severity: 'high',
    mode: 'live',
    mitre_tactics: [],
    mitre_techniques: [],
    tags: [],
    created_at: '2026-11-06T00:00:00Z',
    updated_at: '2026-11-06T00:00:00Z',
    match_count: 0,
    ...overrides,
  };
}

function renderHero(r: DetectionRule) {
  render(
    <MemoryRouter>
      <MatchesHero
        rule={r}
        views={[]}
        totalMatches={0}
        alertsGenerated={0}
        activity28d={Array(28).fill(0)}
        onTogglePause={vi.fn()}
        onToggleAlerting={vi.fn()}
        canEdit
        canManageLifecycle
        lifecyclePending={false}
      />
    </MemoryRouter>,
  );
}

afterEach(cleanup);

describe('Matches page on an archived rule', () => {
  it('hero shows Archived and no Edit / Pause / alerting control, even for an admin', () => {
    renderHero(rule({ archived: true }));
    expect(screen.getByText('Archived')).toBeTruthy();
    for (const name of ['Pause', 'Resume', 'Enable alerting', 'Promote to live', 'Disable alerting', 'Edit']) {
      expect(screen.queryByRole('button', { name })).toBeNull();
      expect(screen.queryByRole('link', { name })).toBeNull();
    }
  });

  it('control: the same admin on a live rule gets Edit, Pause and Enable alerting', () => {
    renderHero(rule());
    expect(screen.getByRole('link', { name: 'Edit' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Pause' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Enable alerting' })).toBeTruthy();
  });

  it('logic tab offers no "Open test drawer" for an archived rule', () => {
    render(
      <MemoryRouter>
        <LogicTab rule={rule({ archived: true })} />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /Open test drawer/ })).toBeNull();
    cleanup();
    render(
      <MemoryRouter>
        <LogicTab rule={rule()} />
      </MemoryRouter>,
    );
    expect(screen.getByRole('button', { name: /Open test drawer/ })).toBeTruthy();
  });
});
