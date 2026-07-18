// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import { logSourceTransportLabel, SOURCE_TYPE_LABELS } from './log-source-transports.ts';

// Minimal shape the resolver reads (the two fields of Pick<LogSource, …>).
const src = (dispatch: string | null, sourceType: string) => ({
  dispatch_source_config_type: dispatch,
  source_type: sourceType,
});

test('NAN-1906: dispatch_source_config_type wins and maps gcp_pubsub → "GCP Pub/Sub"', () => {
  // The onboarding fix records dispatch_source_config_id → the list JOIN
  // surfaces config_type='gcp_pubsub' here, which must NOT read as "HTTP".
  assert.equal(logSourceTransportLabel(src('gcp_pubsub', 'routed')), 'GCP Pub/Sub');
});

test('routed/http sentinel → "HTTP" when there is no dispatch config (regression guard)', () => {
  assert.equal(logSourceTransportLabel(src(null, 'routed')), 'HTTP');
  assert.equal(logSourceTransportLabel(src(null, 'http')), 'HTTP');
});

test('falls back to source_type when dispatch is absent', () => {
  assert.equal(logSourceTransportLabel(src(null, 'kafka')), 'Kafka');
  assert.equal(logSourceTransportLabel(src(null, 'aws_s3')), 'AWS S3');
});

test('unknown key passes through unchanged', () => {
  assert.equal(logSourceTransportLabel(src(null, 'something_new')), 'something_new');
});

test('every pull transport the onboarding can pick has a label', () => {
  for (const t of ['gcp_pubsub', 'kafka', 'aws_s3', 'splunk_hec']) {
    assert.ok(SOURCE_TYPE_LABELS[t], `missing label for ${t}`);
  }
});
