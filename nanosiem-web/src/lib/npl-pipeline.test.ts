// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

/**
 * NAN-2209: pipeline splitting and the one-click group-by builder.
 *
 * The emitted shapes here were verified against the live query planner
 * (`/api/search/explain` + execution) before being pinned: bare dotted OCSF
 * paths parse correctly, the quoted form is accepted in the same position, and
 * a `*` prefix is valid where the analyst had no base filters.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildGroupByQuery,
  getBaseSearch,
  getPipeCommands,
  findFirstPipePosition,
  nplFieldRef,
  GROUP_BY_ROW_LIMIT,
} from './npl-pipeline.ts';

// ---------------------------------------------------------------------------
// Pipeline splitting
// ---------------------------------------------------------------------------

test('splits on a top-level pipe', () => {
  assert.equal(getBaseSearch('src_ip=1.2.3.4 | stats count by user'), 'src_ip=1.2.3.4');
  assert.equal(getPipeCommands('src_ip=1.2.3.4 | stats count by user'), '| stats count by user');
});

test('a query with no pipeline is all base search', () => {
  assert.equal(getBaseSearch('src_ip=1.2.3.4'), 'src_ip=1.2.3.4');
  assert.equal(getPipeCommands('src_ip=1.2.3.4'), '');
  assert.equal(findFirstPipePosition('src_ip=1.2.3.4'), -1);
});

/**
 * The regression this module exists for. SearchResults previously carried a
 * quote-only splitter, so a pipe INSIDE a regex literal was mistaken for the
 * command separator. That does not error — the planner compiles the truncated
 * `user=/admin` to `lower("user") = '/admin'` (equality on a literal string)
 * instead of the intended alternation, silently dropping the analyst's filter.
 */
test('does not split inside a regex literal', () => {
  const q = 'user=/admin|root/ | stats count by src_ip';
  assert.equal(getBaseSearch(q), 'user=/admin|root/');
  assert.equal(getPipeCommands(q), '| stats count by src_ip');
});

test('does not split inside a quoted string', () => {
  const q = 'message="a | b" | stats count by user';
  assert.equal(getBaseSearch(q), 'message="a | b"');
});

test('handles a negated regex operator', () => {
  const q = 'user!=/svc|sys/ | head 10';
  assert.equal(getBaseSearch(q), 'user!=/svc|sys/');
});

test('a slash that is not a regex delimiter does not swallow the pipeline', () => {
  // No `=`/`!=` immediately before the slash, so it is a plain path character.
  const q = 'file_path="/var/log/auth.log" | stats count by user';
  assert.equal(getBaseSearch(q), 'file_path="/var/log/auth.log"');
});

// ---------------------------------------------------------------------------
// Group-by builder
// ---------------------------------------------------------------------------

test('keeps the base filters and appends the aggregation pipeline', () => {
  assert.equal(
    buildGroupByQuery('source_type=windows_sysmon', 'event_type'),
    `source_type=windows_sysmon | stats count by event_type | sort -count | head ${GROUP_BY_ROW_LIMIT}`
  );
});

test('drops whatever pipeline the analyst already had', () => {
  assert.equal(
    buildGroupByQuery('source_type=windows_sysmon | table user, src_ip | head 5', 'user'),
    `source_type=windows_sysmon | stats count by user | sort -count | head ${GROUP_BY_ROW_LIMIT}`
  );
});

test('preserves a regex filter instead of truncating it', () => {
  assert.equal(
    buildGroupByQuery('user=/admin|root/ | table user', 'src_ip'),
    `user=/admin|root/ | stats count by src_ip | sort -count | head ${GROUP_BY_ROW_LIMIT}`
  );
});

test('an empty or missing query becomes an explicit `*`', () => {
  // nPL needs a search term before the first pipe; a bare leading `|` is not
  // the shape we want to put in front of the analyst.
  const expected = `* | stats count by user | sort -count | head ${GROUP_BY_ROW_LIMIT}`;
  assert.equal(buildGroupByQuery('', 'user'), expected);
  assert.equal(buildGroupByQuery('   ', 'user'), expected);
  assert.equal(buildGroupByQuery(undefined, 'user'), expected);
});

test('a `*` base search is not doubled', () => {
  assert.equal(
    buildGroupByQuery('*', 'user'),
    `* | stats count by user | sort -count | head ${GROUP_BY_ROW_LIMIT}`
  );
});

test('dotted OCSF paths are emitted bare', () => {
  // Verified end-to-end: `| stats count by actor.process.name` returns grouped
  // rows and the planner quotes the column itself in the generated SQL.
  assert.equal(nplFieldRef('src_endpoint.ip'), 'src_endpoint.ip');
  assert.equal(nplFieldRef('actor.process.name'), 'actor.process.name');
  assert.equal(nplFieldRef('ext.custom_key'), 'ext.custom_key');
});

test('field names that are not plain identifiers are quoted', () => {
  // `ext.*` keys come from parsed log data, so they can carry anything.
  assert.equal(nplFieldRef('ext.some key'), '"ext.some key"');
  assert.equal(nplFieldRef('weird-name'), '"weird-name"');
  assert.equal(nplFieldRef('2starts_with_digit'), '"2starts_with_digit"');
});

test('a field name carrying a quote cannot break out of the literal', () => {
  // nPL has no `\\"` escape — the canonical handling is to strip the quote
  // (see nplQuotedBody). The result must stay a single well-formed reference.
  const emitted = buildGroupByQuery('*', 'ext.a" | delete_everything');
  assert.ok(!emitted.includes('a"'), `quote must not survive: ${emitted}`);
  assert.equal(
    emitted,
    `* | stats count by "ext.a | delete_everything" | sort -count | head ${GROUP_BY_ROW_LIMIT}`
  );
});

test('the base search is preserved verbatim, including quoted values', () => {
  assert.equal(
    buildGroupByQuery('src_host="web-01" dest_port=443', 'user'),
    `src_host="web-01" dest_port=443 | stats count by user | sort -count | head ${GROUP_BY_ROW_LIMIT}`
  );
});
