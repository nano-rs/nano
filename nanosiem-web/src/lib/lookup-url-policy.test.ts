// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from 'node:fs';
import { describe, expect, test } from 'vitest';
import {
  checkLookupUrl,
  normalizeLookupHost,
  parseLookupUrl,
  utf8Bytes,
  LOOKUP_PSL_VERSION,
  STORAGE_POLICY_ERROR,
} from './lookup-url-policy';

// The Rust production-validator test consumes this exact fixture too.
const cases = JSON.parse(
  readFileSync(
    new URL(
      '../../../nanosiem-core/src/inputlookup/storage_policy_cases.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as {
  psl_version: string;
  entries: { raw: string; normalized: string | null }[];
  urls: {
    raw: string;
    entries: string[];
    allowed: boolean;
    host?: string;
    error?: string;
  }[];
};
describe('the server’s lookup policy cases', () => {
  test.each(cases.entries)('normalizes/rejects $raw', ({ raw, normalized }) => {
    expect(normalizeLookupHost(raw).value ?? null).toBe(normalized);
  });
  test.each(cases.urls)(
    'checks $raw',
    ({ raw, entries, allowed, host, error }) => {
      const result = checkLookupUrl(raw, entries);
      expect(!!result.value).toBe(allowed);
      if (allowed) expect(result.value?.host).toBe(host);
      else expect(result.error).toBe(error);
    },
  );
  test('pins private/public suffix data to the exact Rust dependency', () => {
    const cargo = readFileSync(
      new URL('../../../Cargo.lock', import.meta.url),
      'utf8',
    );
    expect(cargo.match(/name = "psl"\nversion = "([^"]+)"/)?.[1]).toBe(
      LOOKUP_PSL_VERSION,
    );
    expect(cases.psl_version).toBe(LOOKUP_PSL_VERSION);
  });
});
test('uses UTF-8 bytes, and rejects ambiguity before the URL parser normalizes it', () => {
  const prefix = 'https://feeds.example.com/';
  const limit = prefix + 'x'.repeat(16384 - utf8Bytes(prefix));
  expect(parseLookupUrl(limit).value).toBeTruthy();
  expect(parseLookupUrl(limit + 'x').error).toBe(STORAGE_POLICY_ERROR);
  expect(parseLookupUrl(limit.slice(0, -1) + 'é').error).toBe(
    STORAGE_POLICY_ERROR,
  );
  for (const value of [
    'https://feeds.example.com/#',
    'https://feeds.example.com/\u0085x',
    'https://feeds.example.com/a/./b',
  ]) {
    expect(parseLookupUrl(value).error).toBe(STORAGE_POLICY_ERROR);
  }
  expect(
    checkLookupUrl('https://feeds.example.com/x?sig=%2fprivate', [
      'feeds.example.com',
    ]).value,
  ).toEqual({ host: 'feeds.example.com', entry: 'feeds.example.com' });
});
