// SPDX-License-Identifier: AGPL-3.0-or-later
/** NAN-4945: the endpoint card warns when the ingest origin is a dev server. */
import { describe, expect, it } from 'vitest';
import { isDevServerOrigin } from './ingest-endpoint-origin';

describe('isDevServerOrigin', () => {
  it('flags the Vite dev and preview ports', () => {
    expect(isDevServerOrigin('http://localhost:5173')).toBe(true);
    expect(isDevServerOrigin('http://100.103.206.35:5173')).toBe(true);
    expect(isDevServerOrigin('http://localhost:4173')).toBe(true);
  });

  it('accepts edge and production origins', () => {
    expect(isDevServerOrigin('http://localhost:18090')).toBe(false);
    expect(isDevServerOrigin('https://siem.example')).toBe(false);
    expect(isDevServerOrigin('http://siem.example')).toBe(false);
    expect(isDevServerOrigin('not a url')).toBe(false);
  });
});
