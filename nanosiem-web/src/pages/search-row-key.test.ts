// SPDX-License-Identifier: AGPL-3.0-or-later
import { expect, it } from 'vitest';
import { rowKey } from './search-row-key';

it('keys a row on the event identity, never its position', () => {
  expect(rowKey({ id: 'result-0', fields: { 'metadata.uid': 'u1', id: 'e1' } })).toBe('uid:u1');
  expect(rowKey({ id: 'result-0', fields: { metadata: { uid: 'u2' } } })).toBe('uid:u2');
  // ClickHouse table_view rows carry the event `id`; two requests that put
  // the same event at different offsets agree on its key.
  expect(rowKey({ id: 'result-3', fields: { id: 'e1' } })).toBe(rowKey({ id: 'tail-9-0', fields: { id: 'e1' } }));
  expect(rowKey({ id: 'result-7', fields: {} })).toBe('id:result-7');
});
