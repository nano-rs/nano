// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it } from 'vitest';
import { stripComments } from './utils';

// NAN-4283 (searchfuzz F24): the Search page strips comments before sending the
// query, so a URL value must survive with everything after it.
describe('stripComments', () => {
  it('keeps an unquoted URL value and the pipeline after it', () => {
    expect(
      stripComments('http_request.url.url_string=https://stackoverflow.com/robots.txt | stats count'),
    ).toBe('http_request.url.url_string=https://stackoverflow.com/robots.txt | stats count');
    expect(stripComments('url=https://x.example/* | stats count')).toBe(
      'url=https://x.example/* | stats count',
    );
  });

  it('still strips documented comments at a token boundary', () => {
    expect(stripComments('// header\nerror | stats count')).toBe('error | stats count');
    expect(stripComments('error // trailing note\n| head 5')).toBe('error \n| head 5');
    expect(stripComments('a=1 /* block */ b=2')).toBe('a=1  b=2');
    expect(stripComments('url="http://x" // c')).toBe('url="http://x"');
  });
});
