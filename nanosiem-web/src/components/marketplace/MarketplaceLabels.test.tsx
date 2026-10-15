// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-3762: Marketplace enum values render as user copy, never raw.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  capabilityLabel, collectorDeliveryLabel, executionStageLabel, feedCredentialLabel,
  feedRunStatusLabel, humanizeEnum, rolloutStateLabel,
} from '../../lib/marketplace-labels';

const SNAKE = /\b[a-z0-9]+(?:_[a-z0-9]+)+\b/;

test('execution_stage maps to user copy; there is no search-time stage', () => {
  assert.equal(executionStageLabel('bronze_ingest'), 'Built in · at ingest');
  assert.equal(executionStageLabel('agent_on_demand'), 'On demand · pivt');
  assert.equal(executionStageLabel('tenant_scheduled_publication'), 'Scheduled refresh');
  for (const unknown of ['search_time', 'query_time', 'future_stage', '', null, undefined, '__proto__', 'toString']) {
    assert.equal(executionStageLabel(unknown as string | null | undefined), 'Enrichment', String(unknown));
  }
});

test('no raw snake_case value renders from any label helper', () => {
  const values = ['bronze_ingest', 'agent_on_demand', 'tenant_scheduled_publication', 'waiting_for_enrollment',
    'not_required', 'ready', 'pending', 'rolling', 'live', 'some_new_value', 'ip_geo', 'threat_intel', 'brand-new_thing'];
  for (const v of values) {
    for (const label of [executionStageLabel(v), feedCredentialLabel(v), rolloutStateLabel(v), feedRunStatusLabel(v), capabilityLabel(v), humanizeEnum(v)]) {
      assert.doesNotMatch(label, SNAKE, `${v} → ${label}`);
    }
  }
  assert.equal(feedCredentialLabel('waiting_for_enrollment'), 'waiting for enrollment');
  assert.equal(feedCredentialLabel('not_required'), 'not required');
  assert.equal(rolloutStateLabel(null), 'pending');
  assert.equal(humanizeEnum('__'), 'unknown');
});

test('pull collector delivery names the vendor API, never HEC', () => {
  assert.equal(collectorDeliveryLabel({ slug: 'entra_directory', name: 'Entra ID', origin: 'Microsoft Graph' }), 'Pull · Microsoft Graph');
  assert.equal(collectorDeliveryLabel({ slug: 'okta_users', name: 'Okta' }), 'Pull · Okta');
  assert.equal(collectorDeliveryLabel({ slug: 'x', name: 'HEC', origin: 'connector → HEC' }), 'Pull · vendor API');
  assert.equal(collectorDeliveryLabel({ slug: 'cp', name: 'Checkpoint', origin: 'Check Point API' }), 'Pull · Check Point API');
});
