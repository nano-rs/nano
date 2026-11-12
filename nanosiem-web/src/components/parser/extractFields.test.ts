// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from 'vitest';
import { extractFields } from './TestResultRow';

// NAN-5305: the parser test lab dropped every nested OCSF object.
describe('extractFields (OCSF nested output)', () => {
  const ocsf = {
    class_uid: 4002,
    class_name: 'HTTP Activity',
    time: 1731400000000,
    http_request: { http_method: 'GET', url: { hostname: 'example.com', path: '/a' } },
    http_response: { code: 200 },
    src_endpoint: { ip: '10.0.0.1' },
    actor: { user: { name: 'carol' } },
    metadata: { product: { name: 'Apache' }, version: '1.4.0' },
    unmapped: { referer: '-' },
    observables: [{ name: 'src_endpoint.ip', type_id: 2 }],
    enrichments: [],
    empty: null,
  };

  it('flattens nested objects to dotted paths', () => {
    const f = extractFields(ocsf);
    expect(f['http_request.url.hostname']).toBe('example.com');
    expect(f['http_request.http_method']).toBe('GET');
    expect(f['http_response.code']).toBe('200');
    expect(f['src_endpoint.ip']).toBe('10.0.0.1');
    expect(f['actor.user.name']).toBe('carol');
    expect(f['metadata.product.name']).toBe('Apache');
    expect(f['unmapped.referer']).toBe('-');
    expect(f['class_name']).toBe('HTTP Activity');
  });

  it('renders non-empty arrays as JSON and skips null/empty', () => {
    const f = extractFields(ocsf);
    expect(f['observables']).toBe('[{"name":"src_endpoint.ip","type_id":2}]');
    expect('enrichments' in f).toBe(false);
    expect('empty' in f).toBe(false);
  });

  it('does not unwrap a legacy udm key over the whole output', () => {
    const f = extractFields({ udm: { user: 'x' }, ext: { k: 'v' }, class_uid: 1 });
    expect(f['udm.user']).toBe('x');
    expect(f['ext.k']).toBe('v');
    expect(f['class_uid']).toBe('1');
  });

  it('returns {} for undefined', () => {
    expect(extractFields(undefined)).toEqual({});
  });
});
