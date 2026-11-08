// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { DetectionRule } from '@/lib/api/types';
import { Matches } from './Matches';

const mock = vi.hoisted(() => ({
  mode: 'staging' as DetectionRule['mode'],
  lifecyclePending: false,
  pause: vi.fn(),
  resume: vi.fn(),
  promote: vi.fn(),
  demote: vi.fn(),
  toast: vi.fn(),
  refetch: vi.fn(),
}));

function rule(mode = mock.mode): DetectionRule {
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

vi.mock('@/hooks/use-api', () => ({
  useDetection: () => ({ data: rule(), loading: false, error: null, refetch: mock.refetch }),
  useDetectionMatches: () => ({ data: { matches: [], total: 0 }, loading: false }),
  useAlerts: () => ({ data: [] }),
  useDetectionStats: () => ({ data: {} }),
  useTodayCounts: () => ({ data: {} }),
  usePauseDetection: () => ({ mutate: mock.pause, loading: false }),
  useResumeDetection: () => ({ mutate: mock.resume, loading: false }),
  usePromoteDetection: () => ({ mutate: mock.promote, loading: mock.lifecyclePending }),
  useDemoteDetection: () => ({ mutate: mock.demote, loading: false }),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => {} }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mock.toast }) }));
vi.mock('@/hooks/useSchemaEntityMap', () => ({
  useSchemaEntityMap: () => ({ schema: 'ocsf', resolveEntityType: vi.fn() }),
}));
vi.mock('@/components/matches/MatchesHero', () => ({
  MatchesHero: (props: {
    rule: DetectionRule;
    onTogglePause: () => void;
    onToggleAlerting: () => void;
    lifecyclePending: boolean;
  }) => (
    <>
      <button
        type="button"
        onClick={props.onTogglePause}
        disabled={props.lifecyclePending}
      >
        toggle pause from {props.rule.mode}
      </button>
      <button
        type="button"
        onClick={props.onToggleAlerting}
        disabled={props.lifecyclePending}
      >
        transition from {props.rule.mode}
      </button>
    </>
  ),
}));
vi.mock('@/components/matches/MatchesList', () => ({ MatchesList: () => null }));
vi.mock('@/components/matches/MatchesDetail', () => ({ MatchesDetail: () => null }));
vi.mock('@/components/matches/LogicTab', () => ({ LogicTab: () => null }));

function renderMatches() {
  render(
    <MemoryRouter initialEntries={['/rules/rule_one/matches']}>
      <Routes>
        <Route path="/rules/:id/matches" element={<Matches />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  mock.mode = 'staging';
  mock.lifecyclePending = false;
  mock.pause.mockReset();
  mock.resume.mockReset();
  mock.promote.mockReset();
  mock.demote.mockReset();
  mock.toast.mockReset();
  mock.refetch.mockReset();
});

afterEach(cleanup);

describe('Matches lifecycle consumer', () => {
  it.each([
    ['live', 'pause'],
    ['alerting', 'pause'],
    ['paused', 'resume'],
  ] as const)('guards %s -> %s with the rendered source mode', async (from, action) => {
    mock.mode = from;
    const mutation = action === 'resume' ? mock.resume : mock.pause;
    mutation.mockResolvedValue(rule(action === 'resume' ? 'live' : 'paused'));
    renderMatches();

    fireEvent.click(screen.getByRole('button', { name: `toggle pause from ${from}` }));

    await waitFor(() =>
      expect(mutation).toHaveBeenCalledWith({ id: 'rule_one', expectedMode: from }),
    );
  });

  it.each([
    ['staging', 'live'],
    ['live', 'alerting'],
  ] as const)('promotes %s with an expected-mode guard and reports returned %s mode', async (from, to) => {
    mock.mode = from;
    mock.promote.mockResolvedValue(rule(to));
    renderMatches();

    fireEvent.click(screen.getByRole('button', { name: `transition from ${from}` }));

    await waitFor(() =>
      expect(mock.promote).toHaveBeenCalledWith({ id: 'rule_one', expectedMode: from }),
    );
    expect(mock.toast).toHaveBeenCalledWith(expect.objectContaining({ title: `Rule mode: ${to}` }));
  });

  it('disables the lifecycle action while the guarded request is pending', () => {
    mock.lifecyclePending = true;
    renderMatches();
    expect((screen.getByRole('button', { name: 'transition from staging' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
