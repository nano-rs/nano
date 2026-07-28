// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

/**
 * NAN-2226: the API-key scope presets are matchers resolved against the LIVE
 * permission catalogue, so a matcher naming something the catalogue has never
 * contained fails silently — the preset just resolves to fewer scopes, or none.
 * Three such matchers shipped (`:read`, `rules:`, `events:ingest`/`search:read`),
 * all copied out of a static design mock.
 *
 * A fixture would not have caught that, because the fixture would have been
 * copied from the same wrong place. So this suite reads the REAL catalogue out
 * of `nanosiem-core/src/auth/permissions.rs` and asserts every preset actually
 * resolves against it.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  SCOPE_PRESETS,
  derivePreset,
  presetScopeIds,
  type ScopeCandidate,
} from './scope-presets.ts';

const REPO_ROOT = path.resolve(import.meta.dirname, '../../../../..');
const PERMISSIONS_RS = path.join(REPO_ROOT, 'nanosiem-core/src/auth/permissions.rs');

/**
 * The real permission ids, read from `ALL_PERMISSIONS` in permissions.rs.
 *
 * That list is the Rust-side mirror of the `permissions` table the migrations
 * seed and `GET /api/permissions` serves — the catalogue this component filters
 * against at runtime. Resolving the array's identifiers (rather than scraping
 * every `pub const`) keeps ids that exist only as an unused constant out.
 */
function loadCatalogue(): string[] {
  let source: string;
  try {
    source = readFileSync(PERMISSIONS_RS, 'utf8');
  } catch (err) {
    throw new Error(
      `could not read the permission catalogue at ${PERMISSIONS_RS} — did permissions.rs move? (${String(err)})`,
    );
  }

  const values = new Map<string, string>();
  for (const [, name, value] of source.matchAll(/pub const ([A-Z0-9_]+): &str = "([^"]+)";/g)) {
    values.set(name, value);
  }

  const block = source.match(/pub const ALL_PERMISSIONS: &\[&str\] = &\[([\s\S]*?)\n\];/);
  assert.ok(block, 'ALL_PERMISSIONS array not found in permissions.rs');

  const ids: string[] = [];
  for (const [, name] of block[1].matchAll(/^\s*([A-Z][A-Z0-9_]*),\s*$/gm)) {
    const value = values.get(name);
    assert.ok(value, `ALL_PERMISSIONS references ${name}, which has no &str constant`);
    ids.push(value);
  }
  return ids;
}

const CATALOGUE_IDS = loadCatalogue();
const CATALOGUE: ScopeCandidate[] = CATALOGUE_IDS.map(id => ({ id }));

test('the parsed catalogue looks like the real one', () => {
  assert.ok(CATALOGUE_IDS.length > 100, `only parsed ${CATALOGUE_IDS.length} permissions`);
  assert.ok(CATALOGUE_IDS.includes('search:view'));
  assert.ok(CATALOGUE_IDS.includes('users:edit'));
  assert.ok(CATALOGUE_IDS.every(id => id.includes(':')));
});

test('NAN-2226: every preset resolves to a non-empty scope set', () => {
  for (const preset of SCOPE_PRESETS) {
    const ids = presetScopeIds(CATALOGUE, preset.id);
    if (preset.id === 'custom') {
      assert.equal(ids.length, 0, 'the custom preset resolves nothing by design');
      continue;
    }
    assert.ok(
      ids.length > 0,
      `preset "${preset.label}" matches no permission in the real catalogue — ` +
        'it would render as "0 scopes" and produce a key that can call nothing',
    );
    for (const id of ids) {
      assert.ok(CATALOGUE_IDS.includes(id), `preset resolved a non-catalogue id: ${id}`);
    }
  }
});

test('NAN-2226: the read-only preset is every view scope and nothing else', () => {
  const ids = presetScopeIds(CATALOGUE, 'readonly');
  const expected = CATALOGUE_IDS.filter(id => id.endsWith(':view'));

  assert.deepEqual([...ids].sort(), [...expected].sort());
  assert.ok(ids.includes('search:view'));
  assert.ok(ids.includes('audit:view'));
  assert.ok(!ids.includes('search:execute'), 'read-only must not include an execute scope');
});

test('NAN-2226: detection CI/CD covers rule + parser repos, not the phantom "rules:" prefix', () => {
  const ids = presetScopeIds(CATALOGUE, 'detection-ci');

  // The `startsWith('rules:')` clause it replaces matched NOTHING: the real
  // prefix is `rule_repositories:`, and no id starts with `rules:` at all.
  assert.equal(
    CATALOGUE_IDS.filter(id => id.startsWith('rules:')).length,
    0,
    'a `rules:` permission now exists — revisit the detection-ci matcher',
  );

  for (const required of [
    'detections:create',
    'detections:edit',
    'parsers:create',
    'rule_repositories:import',
    'rule_repositories:sync',
    'parser_repositories:import',
  ]) {
    assert.ok(ids.includes(required), `detection CI/CD preset is missing ${required}`);
  }

  assert.ok(!ids.includes('users:edit'), 'detection CI/CD must not reach user administration');
});

test('NAN-2226: the unbuildable "Event ingest" preset is gone, not silently empty', () => {
  assert.equal(
    SCOPE_PRESETS.find(p => p.id === 'ingest'),
    undefined,
    'ingestion does not traverse this API (logs arrive via Vector), so no API key can be scoped to it',
  );
});

test('NAN-2226: no preset matches an id the catalogue has never had', () => {
  // The ids the retired matchers named. None exists; a matcher that names one
  // again contributes nothing and lies about what the key can do.
  for (const ghost of ['events:ingest', 'search:read', 'rules:read', 'alerts:edit', 'settings:edit', 'users:manage']) {
    assert.ok(!CATALOGUE_IDS.includes(ghost), `${ghost} unexpectedly exists — update this test`);
    for (const preset of SCOPE_PRESETS) {
      assert.ok(
        !preset.match({ id: ghost }),
        `preset "${preset.label}" matches ${ghost}, which is not a real permission`,
      );
    }
  }

  assert.equal(
    CATALOGUE_IDS.filter(id => id.endsWith(':read')).length,
    0,
    'a `:read` permission now exists — the read-only matcher may need it back',
  );
});

test('a preset round-trips through derivePreset', () => {
  for (const preset of SCOPE_PRESETS) {
    if (preset.id === 'custom') continue;
    const ids = presetScopeIds(CATALOGUE, preset.id);
    assert.equal(derivePreset(CATALOGUE, ids), preset.id);
  }

  assert.equal(derivePreset(CATALOGUE, ['search:view', 'users:delete']), 'custom');
  assert.equal(derivePreset(CATALOGUE, []), 'custom');
});
