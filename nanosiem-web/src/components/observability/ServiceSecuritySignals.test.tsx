// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
// #7030 (ported to the profile-aware ClickHouse build): a service signal's
// Search pivot carries the fired detection's window, not Search's default.
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { ServiceSecuritySignals, searchHref } from './ServiceSecuritySignals';

const state = vi.hoisted(() => ({ rules: [{ name: 'test', lookback_minutes: 30 }] }));
const rulesError = vi.hoisted(() => ({ value: null as unknown }));
vi.mock('@/hooks/use-api', () => ({ useDetections: () => ({ data: state.rules, loading: false, error: rulesError.value }) }));
vi.mock('@/hooks/useSchemaFieldMap', () => ({ useSchemaFieldMap: () => ({ profile: 'ocsf', ready: true, guard: (fn: () => void) => fn }) }));
vi.mock('@/lib/api', () => ({
  api: {
    observability: {
      getServiceSecuritySignals: async () => ({
        signal_total: 1,
        host_count: 1,
        signals: [{ ts: '2026-10-17 12:00:00', rule_name: 'test', severity: 'high', src_ip: '198.51.100.1', src_host: null }],
      }),
    },
  },
}));
afterEach(cleanup);

const signal = { ts: '2026-10-17 12:00:00', rule_name: 'test', severity: 'high', src_ip: '198.51.100.1', src_host: null };
const fragment = (href: string) => new URLSearchParams(href.split('#')[1] ?? '');

it('service signal entity pivots include the historical firing window, in the fragment', () => {
  const href = searchHref(signal, 'ocsf');
  expect(href.startsWith('/search#')).toBe(true);
  const params = fragment(href);
  expect(params.get('q')).toContain('198.51.100.1');
  expect(params.get('q')).toContain('src_endpoint.ip');
  expect(params.get('start')).toBe('2026-10-17T11:59:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:01:00.000Z');
});

it('service signals without event payloads use the rule lookback around firing', () => {
  const params = fragment(searchHref(signal, 'ocsf', 30));
  expect(params.get('start')).toBe('2026-10-17T11:30:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:30:00.000Z');
});

it('rendered service signals use rule metadata for their absolute pivot window', async () => {
  render(<MemoryRouter><ServiceSecuritySignals service="api" apiTimeRange={{ start: '2026-10-17T00:00:00Z', end: '2026-10-18T00:00:00Z' }} /></MemoryRouter>);
  const link = await screen.findByRole('link', { name: /test/ });
  const params = fragment(link.getAttribute('href')!);
  expect(params.get('start')).toBe('2026-10-17T11:30:00.000Z');
  expect(params.get('end')).toBe('2026-10-17T12:30:00.000Z');
});

it('without rule metadata (no detections:view) the pivot widens to the longest rule lookback, never ±1 minute', async () => {
  state.rules = null as unknown as typeof state.rules;
  rulesError.value = { status: 403 };
  try {
    render(<MemoryRouter><ServiceSecuritySignals service="api" apiTimeRange={{ start: '2026-10-17T00:00:00Z', end: '2026-10-18T00:00:00Z' }} /></MemoryRouter>);
    const link = await screen.findByRole('link', { name: /test/ });
    expect(link.getAttribute('aria-disabled')).toBe('false');
    const params = fragment(link.getAttribute('href')!);
    expect(params.get('start')).toBe('2026-10-10T12:00:00.000Z');
  } finally {
    state.rules = [{ name: 'test', lookback_minutes: 30 }];
    rulesError.value = null;
  }
});
