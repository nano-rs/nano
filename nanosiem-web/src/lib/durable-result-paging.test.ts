// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import { durableArtifactPageForOffset, localResultStart } from './durable-result-paging.ts';

test('maps UI row offsets to bounded object artifact pages', () => {
  assert.equal(durableArtifactPageForOffset(0, 10_000, 3), 0);
  assert.equal(durableArtifactPageForOffset(9_999, 10_000, 3), 0);
  assert.equal(durableArtifactPageForOffset(10_000, 10_000, 3), 1);
  assert.equal(durableArtifactPageForOffset(99_999, 10_000, 3), 2);
});

test('slices within the loaded artifact rather than the global result array', () => {
  assert.equal(localResultStart(10_050, 10_000), 50);
  assert.equal(localResultStart(20_000, 20_000), 0);
});
