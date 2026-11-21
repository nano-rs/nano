// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-5715: lookup `_row_id`s are 19-digit strings; a JS number rounds them
// and the cell edit then wrote a new row under the rounded id.
import { describe, it, expect, vi } from 'vitest';
import { LookupTablesApi } from './lookup-tables';
import { lookupRowId } from './types';

const ID = '7529336958272102401';

describe('lookup row ids (NAN-5715)', () => {
  it('reads the wire string unchanged (a number would round)', () => {
    expect(lookupRowId({ _row_id: ID, owner: 'eng' })).toBe(ID);
    expect(String(Number(ID))).not.toBe(ID); // what the old `as number` path did
    expect(lookupRowId({ _row_id: 7 })).toBe('7'); // an older API's small numeric id
  });

  it('edit, delete and bulk delete send the exact id', async () => {
    const request = vi.fn().mockResolvedValue({ success: true, deleted: 1 });
    const api = new LookupTablesApi(request);
    await api.updateRow('owners', ID, { owner: 'sec' });
    await api.deleteRow('owners', ID);
    await api.deleteRows('owners', [ID]);
    expect(request.mock.calls[0][0]).toBe(`/api/lookup-tables/owners/rows/${ID}`);
    expect(request.mock.calls[1][0]).toBe(`/api/lookup-tables/owners/rows/${ID}`);
    expect(JSON.parse(request.mock.calls[2][1].body)).toEqual({ row_ids: [ID] });
  });
});
