// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildLogSourceParserPrompt,
  extractRecentParserSamples,
  isRawPassThroughVrl,
} from './log-source-pivt-context.ts';

test('NAN-2292: recognizes only the raw collector pass-through as a placeholder', () => {
  assert.equal(isRawPassThroughVrl('  . = .\n'), true);
  assert.equal(isRawPassThroughVrl('.foo = .bar'), false);
  assert.equal(isRawPassThroughVrl('# parser\n. = .'), false);
});

test('NAN-2292: extracts bounded, unique raw messages with event fallback', () => {
  const long = 'x'.repeat(20_000);
  const samples = extractRecentParserSamples([
    { message: '  {"id":"1"}  ', source_type: 'github_public_events' },
    { message: '{"id":"1"}' },
    { message: '', id: '2', type: 'PushEvent' },
    { message: long },
    { message: '{"id":"ignored-by-limit"}' },
  ], 3);

  assert.deepEqual(samples.slice(0, 2), [
    '{"id":"1"}',
    JSON.stringify({ message: '', id: '2', type: 'PushEvent' }),
  ]);
  assert.equal(samples.length, 3);
  assert.equal(samples[2].length, 16_000);
});

test('NAN-2292: prompt identifies the source and directs PIVT to generate without asking again', () => {
  const prompt = buildLogSourceParserPrompt({
    userMessage: 'Create an entire parser for this log source',
    sourceName: 'GitHub Public Events',
    sourceType: 'github_public_events',
    isRawPassThrough: true,
  });

  assert.match(prompt, /Name: GitHub Public Events/);
  assert.match(prompt, /source_type: github_public_events/);
  assert.match(prompt, /raw pass-through placeholder/);
  assert.match(prompt, /generate the complete VRL parser now/);
  assert.match(prompt, /do not ask the user/);
});
