// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { searchQueryForUrl } from './search-query-url.ts';

test('browser search history and copied URLs exclude lookup credentials', () => {
  for (const query of [
    '| inputlookup url="https://storage.googleapis.com/bucket/x?sig=TEST_CREDENTIAL" | head 2',
    "| inputlookup url='HTTPS://storage.googleapis.com/bucket/x?sig=TEST_CREDENTIAL'",
    '| inputlookup url="https://storage.googleapis.com/bucket/x?sig=\'TEST_CREDENTIAL\'"',
    '| inputlookup url="https://user:TEST_CREDENTIAL@storage.googleapis.com/bucket/x"',
    'bad https://storage.googleapis.com/bucket/x?sig=TEST_CREDENTIAL',
  ]) {
    const params = new URLSearchParams({ q: searchQueryForUrl(query) });
    assert.ok(!params.toString().includes('TEST_CREDENTIAL'));
    assert.ok(!searchQueryForUrl(query).includes('TEST_CREDENTIAL'));
  }
  const ordinary = '| inputlookup url="https://storage.googleapis.com/bucket/x" | head 2';
  assert.equal(searchQueryForUrl(ordinary), ordinary);
  assert.equal(searchQueryForUrl('error | head 2'), 'error | head 2');
  assert.equal(searchQueryForUrl('| inputlookup url="https://storage.googleapis.com/bucket/x?sig=TEST_CREDENTIAL" | head 2'),
    '| inputlookup url="https://storage.googleapis.com/bucket/x?[REDACTED]" | head 2');
});
