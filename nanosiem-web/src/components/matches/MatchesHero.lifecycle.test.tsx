// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DetectionRule } from '@/lib/api/types';
import { MatchesHero } from './MatchesHero';

vi.mock('@/hooks/use-api', () => ({
  useDetectionMatches: () => ({ data: { matches: [] } }),
  useRuleDispositionStats: () => ({ data: null }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));

function rule(mode: DetectionRule['mode']): DetectionRule {
  return {
    id: 'rule_one',
    name: 'lifecycle_rule',
    query: 'source_type="test"',
    severity: 'high',
    mode,
    mitre_tactics: [],
    mitre_techniques: [],
    tags: [],
    created_at: '2026-11-06T00:00:00Z',
    updated_at: '2026-11-06T00:00:00Z',
    match_count: 0,
  };
}

function renderHero(
  mode: DetectionRule['mode'],
  options: { canManageLifecycle?: boolean; lifecyclePending?: boolean } = {},
) {
  render(
    <MemoryRouter>
      <MatchesHero
        rule={rule(mode)}
        views={[]}
        totalMatches={0}
        alertsGenerated={0}
        activity28d={Array(28).fill(0)}
        onTogglePause={vi.fn()}
        onToggleAlerting={vi.fn()}
        canEdit={false}
        canManageLifecycle={options.canManageLifecycle ?? true}
        lifecyclePending={options.lifecyclePending ?? false}
      />
    </MemoryRouter>,
  );
}

afterEach(cleanup);

describe('MatchesHero lifecycle controls', () => {
  it.each([
    ['staging', 'Staging', 'Promote to live'],
    ['live', 'Live', 'Enable alerting'],
    ['alerting', 'Alerting', 'Disable alerting'],
  ] as const)('renders %s mode and its state-specific action', (mode, label, action) => {
    renderHero(mode);
    expect(screen.getByText(label)).toBeTruthy();
    expect(screen.getByRole('button', { name: action })).toBeTruthy();
  });

  it('hides lifecycle controls without detections:promote', () => {
    renderHero('live', { canManageLifecycle: false });
    expect(screen.queryByRole('button', { name: 'Pause' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Enable alerting' })).toBeNull();
  });

  it('disables every lifecycle control while a transition is pending', () => {
    renderHero('live', { lifecyclePending: true });
    expect((screen.getByRole('button', { name: 'Pause' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Enable alerting' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
