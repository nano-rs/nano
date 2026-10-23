// @vitest-environment jsdom
import { expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { Matches } from './Matches';
const query = vi.hoisted(() => 'metadata.log_source=ops_shared_apps | eval x=1 | where x=1 | stats count by metadata.product.name, metadata.tenant_uid | where count>0 | table count');
vi.mock('@/hooks/use-api', () => ({
  useDetection: () => ({ data: { id: 'r', name: 'ops', query, lookback_minutes: 15 } }),
  useDetectionMatches: () => ({ data: { matches: [{ id: 'm', detected_at: '2026-10-17T13:00:00Z', severity: 'high', status: 'open', event_count: 1, events: [{ time: '2026-10-17T12:00:00Z' }] }] } }),
  useAlerts: () => ({}), useDetectionStats: () => ({}), useTodayCounts: () => ({}),
  usePauseDetection: () => ({}), useResumeDetection: () => ({}), usePromoteDetection: () => ({}), useDemoteDetection: () => ({}),
}));
vi.mock('@/hooks/useDocumentTitle', () => ({ useDocumentTitle: () => {} }));
vi.mock('@/contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: () => true }) }));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock('@/hooks/useSchemaEntityMap', () => ({ useSchemaEntityMap: () => ({ schema: 'ocsf' }) }));
vi.mock('@/components/matches/MatchesHero', () => ({ MatchesHero: () => null }));
vi.mock('@/components/matches/MatchesList', () => ({ MatchesList: () => null }));
vi.mock('@/components/matches/LogicTab', () => ({ LogicTab: () => null }));
vi.mock('@/components/matches/MatchesDetail', () => ({ MatchesDetail: ({ view, onRunRuleQuery }: any) => <button onClick={() => onRunRuleQuery(view)}>Run rule query</button> }));
function Location() { return <output>{useLocation().search}</output>; }
it('runs the complete ops rule verbatim over the contributing-event window', () => {
  render(<MemoryRouter initialEntries={['/rules/r/matches']}><Routes><Route path="/rules/:id/matches" element={<Matches />} /><Route path="/search" element={<Location />} /></Routes></MemoryRouter>);
  fireEvent.click(screen.getByRole('button', { name: 'Run rule query' }));
  const params = new URLSearchParams(screen.getByRole('status').textContent!);
  expect(params.get('q')).toBe(query);
  expect(params.get('start')).toBe('2026-10-17T11:45:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:01:00.000Z');
});
