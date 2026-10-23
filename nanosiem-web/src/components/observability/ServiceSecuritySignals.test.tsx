// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ServiceSecuritySignals } from './ServiceSecuritySignals';
const state = vi.hoisted(() => ({ rules: [{ name: 'test', lookback_minutes: 30 }] }));
vi.mock('@/hooks/use-api', () => ({ useDetections: () => ({ data: state.rules, loading: false, error: null }) }));
vi.mock('@/lib/api', () => ({ api: { observability: { getServiceSecuritySignals: async () => ({ signal_total: 1, host_count: 1, signals: [{ ts: '2026-10-17 12:00:00', rule_name: 'test', severity: 'high', matched_entity: '198.51.100.1', matched_entity_type: 'ip' }] }) } } }));
afterEach(cleanup);
import { searchHref } from './ServiceSecuritySignals';
it('service signal entity pivots include the historical firing window', () => {
  const params = new URLSearchParams(new URL(searchHref({ ts: '2026-10-17 12:00:00', rule_name: 'test', severity: 'high', matched_entity: '198.51.100.1', matched_entity_type: 'ip' }), 'https://example.test').hash.slice(1));
  expect(params.get('q')).toContain('198.51.100.1');
  expect(params.get('start')).toBe('2026-10-17T11:59:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:01:00.000Z');
});

it('service signals without event payloads use the rule lookback around firing', () => {
  const params = new URLSearchParams(new URL(searchHref({ ts: '2026-10-17 12:00:00', rule_name: 'test', severity: 'high', matched_entity: '198.51.100.1', matched_entity_type: 'ip' }, 30), 'https://example.test').hash.slice(1));
  expect(params.get('start')).toBe('2026-10-17T11:30:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:30:00.000Z');
});

it('rendered service signals use rule metadata for their absolute pivot window', async () => {
  render(<MemoryRouter><ServiceSecuritySignals service="api" apiTimeRange={{ start: '2026-10-17T00:00:00Z', end: '2026-10-18T00:00:00Z' }} /></MemoryRouter>);
  const link = await screen.findByRole('link', { name: /test/ });
  const params = new URLSearchParams(new URL(link.getAttribute('href')!, 'https://example.test').hash.slice(1));
  expect(params.get('start')).toBe('2026-10-17T11:30:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:30:00.000Z');
});
