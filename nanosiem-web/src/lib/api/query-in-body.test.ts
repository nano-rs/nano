// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from 'vitest';
import { CoreApi } from './core';
import { SearchApi } from './search';

// NAN-4928: hunt queries travel in request bodies, never in GET URLs that
// reach server and proxy logs.
describe('query-bearing lookups use POST bodies', () => {
  it('ext field names', async () => {
    const request = vi.fn().mockResolvedValue([]);
    await new CoreApi(request).getExtFieldNames('user="secret hunt"', '2026-11-03T00:00:00Z', '2026-11-03T01:00:00Z');
    const [endpoint, options] = request.mock.calls[0];
    expect(endpoint).toBe('/api/fields/ext');
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ query: 'user="secret hunt"', start: '2026-11-03T00:00:00Z', end: '2026-11-03T01:00:00Z' });
  });

  it('query explanation lookup', async () => {
    const request = vi.fn().mockResolvedValue({});
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await new (SearchApi as any)(request).getQueryExplanation('process.name=mimikatz.exe');
    const [endpoint, options] = request.mock.calls[0];
    expect(endpoint).toBe('/api/search/explanation/lookup');
    expect(endpoint).not.toContain('mimikatz');
    expect(options.method).toBe('POST');
    expect(JSON.parse(options.body)).toEqual({ q: 'process.name=mimikatz.exe' });
  });
});
