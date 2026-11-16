// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import {
  canObserveSessionPresence,
  clearSessionPresenceCookie,
  hasSessionPresenceCookie,
  shouldProbeSilentRefresh,
} from './session-presence';

function wipeCookies() {
  for (const part of document.cookie.split(';')) {
    const name = part.split('=')[0].trim();
    if (name) document.cookie = `${name}=; Path=/; Max-Age=0`;
  }
}

describe('session presence cookie (NAN-5483)', () => {
  afterEach(wipeCookies);

  it('skips the silent probe for a visitor who never signed in', () => {
    expect(hasSessionPresenceCookie()).toBe(false);
    expect(shouldProbeSilentRefresh('')).toBe(false);
  });

  it('probes when the API issued a refresh cookie', () => {
    document.cookie = 'nano_session=1; Path=/';
    expect(hasSessionPresenceCookie()).toBe(true);
    expect(shouldProbeSilentRefresh('')).toBe(true);
  });

  it('ignores lookalike and empty cookies', () => {
    document.cookie = 'nano_session_x=1; Path=/';
    document.cookie = 'xnano_session=1; Path=/';
    expect(hasSessionPresenceCookie()).toBe(false);
  });

  it('always probes when the API is cross-origin (cookie not observable)', () => {
    expect(canObserveSessionPresence('https://api.elsewhere.example')).toBe(false);
    expect(shouldProbeSilentRefresh('https://api.elsewhere.example')).toBe(true);
  });

  it('treats a same-origin absolute API URL as observable', () => {
    expect(canObserveSessionPresence(window.location.origin)).toBe(true);
    expect(canObserveSessionPresence('/')).toBe(true);
  });

  it('clearSessionPresenceCookie removes it', () => {
    document.cookie = 'nano_session=1; Path=/';
    clearSessionPresenceCookie();
    expect(hasSessionPresenceCookie()).toBe(false);
  });
});
