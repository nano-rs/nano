// SPDX-License-Identifier: AGPL-3.0-or-later
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { buildMatchView, extractEntity } from './helpers';

test('aggregate resolves the backend canonical subject', () => {
  // Shape of the 2026-10-17 12:51:44Z ops match; identifiers anonymized.
  const view = buildMatchView({
    id: 'match-ops-denial', detected_at: '2026-10-17T12:51:44.986555Z',
    severity: 'high', status: 'open', event_count: 1,
    events: [{
      _match_kind: 'aggregate', account: 'usr_example', count: 1,
      _match_entity: 'usr_example', _match_entity_type: 'user',
      _match_event_label: 'POST /api/admin/regions',
      _match_event_time: '2026-10-17 12:47:57.686000',
      first_seen: '2026-10-17 12:47:57.686000',
      last_seen: '2026-10-17 12:47:57.686000', risk_score: 60,
    }],
  });
  assert.equal(view.isAggregate, true);
  assert.deepEqual(view.entity, {
    id: 'usr_example', label: 'usr_example', type: 'user', raw: 'usr_example',
  });
});

test('explicit subject and canonical identity retain precedence over account', () => {
  for (const fields of [
    { entity: 'preferred', entity_type: 'user' },
    { _match_entity: 'preferred', _match_entity_type: 'user' },
    { 'actor.user.uid': 'preferred' },
  ]) {
    assert.equal(extractEntity([{ _match_kind: 'aggregate', account: 'other', ...fields }]).label, 'preferred');
  }
});

test('ordinary account fields and missing aggregate subjects are not guessed', () => {
  for (const row of [{ account: 'billing-account' }, { _match_kind: 'aggregate', account: 'usr_example' }, { _match_kind: 'aggregate', account: ' ' }, { _match_kind: 'aggregate', account: 42 }]) {
    assert.equal(extractEntity([row]).label, 'unknown');
  }
  assert.equal(extractEntity([]).label, 'unknown');
});
