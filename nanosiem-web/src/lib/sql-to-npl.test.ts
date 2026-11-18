// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-5575: conversions requested in one tick go out as one batch. */
import { expect, it, vi } from 'vitest';
vi.mock('@/lib/api', () => ({ api: {} }));
import { createSqlToNplBatcher, sqlNplSearchUrl, SQL_TO_NPL_BATCH_MAX } from './sql-to-npl';
import type { SqlToNplRequest, SqlToNplResponse } from '@/lib/api/types';

const reply = (r: SqlToNplRequest): SqlToNplResponse => ({
  npl: r.sql,
  earliest: null,
  latest: null,
  exact: true,
  approximate: false,
  differences: [],
  unsupported_reason: null,
  unsupported_span: null,
    no_search_dataset: false,
});

it('batches a tick of requests and splits at the server cap', async () => {
  const send = vi.fn(async (items: SqlToNplRequest[]) => ({ results: items.map(reply) }));
  const convert = createSqlToNplBatcher(send, 1);
  const n = SQL_TO_NPL_BATCH_MAX + 3;
  const out = await Promise.all(Array.from({ length: n }, (_, i) => convert({ sql: `q${i}` })));
  expect(send).toHaveBeenCalledTimes(2);
  expect(send.mock.calls[0][0]).toHaveLength(SQL_TO_NPL_BATCH_MAX);
  expect(out.map((r) => r.npl)).toEqual(Array.from({ length: n }, (_, i) => `q${i}`));
});

it('rejects every request of a failed batch', async () => {
  const convert = createSqlToNplBatcher(async () => {
    throw new Error('down');
  }, 1);
  await expect(convert({ sql: 'x' })).rejects.toThrow('down');
});

it('builds a fragment Search URL and drops invalid bounds', () => {
  const href = sqlNplSearchUrl('a=1 | head 5', '2026-11-01T00:00:00Z', 'nope');
  const p = new URLSearchParams(href.split('#')[1]);
  expect(href.startsWith('/search#')).toBe(true);
  expect(p.get('q')).toBe('a=1 | head 5');
  expect(p.get('start')).toBe('2026-11-01T00:00:00.000Z');
  expect(p.get('end')).toBeNull();
});

it('carries a non-logs dataset into the Search URL (NAN-5612)', () => {
  const p = new URLSearchParams(sqlNplSearchUrl('* | stats count() by rule_name', null, null, 'signals').split('#')[1]);
  expect(p.get('dataset')).toBe('signals');
  const logs = new URLSearchParams(sqlNplSearchUrl('a=1', null, null, 'logs').split('#')[1]);
  expect(logs.get('dataset')).toBeNull();
});
