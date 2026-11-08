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

test('ordinary URL literals replay byte for byte; only credential parameters are redacted (NAN-4927 review)', () => {
  for (const query of [
    'url.full="https://example.test/download?id=incident-42"',
    'http_request.url.url_string="https://example.test/a/b?x=1&y=two#frag"',
    'https://example.test/search?q=error&page=2 | head 5',
  ]) {
    assert.equal(searchQueryForUrl(query), query);
  }
  assert.equal(
    searchQueryForUrl('url.full="https://example.test/cb?id=7&access_token=TEST_CREDENTIAL&X-Amz-Signature=TEST_CREDENTIAL"'),
    'url.full="https://example.test/cb?id=7&access_token=[REDACTED]&X-Amz-Signature=[REDACTED]"',
  );
  assert.equal(
    searchQueryForUrl('url.full="https://example.test/cb#id_token=TEST_CREDENTIAL&state=s1"'),
    'url.full="https://example.test/cb#id_token=[REDACTED]&state=s1"',
  );
  // A lookup URL can carry its credential in any parameter: it stays fully redacted.
  assert.equal(
    searchQueryForUrl('error | inputlookup url="https://storage.example.test/x?X-Goog-Credential=TEST_CREDENTIAL&id=1"'),
    'error | inputlookup url="https://storage.example.test/x?[REDACTED]"',
  );
});
