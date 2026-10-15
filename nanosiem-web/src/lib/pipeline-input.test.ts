// SPDX-License-Identifier: AGPL-3.0-or-later
// NAN-3625: "Input is" route branches read the platform input identity.
import { expect, test } from 'vitest';
import { canonicalInput, compileStep, inputOfStamp, inputPredicate, recentEventSamples, routeCondition, routeInputsOfDraft, vrlField } from './pipeline-model';
import { laneInputsFrom } from './api/pipelines';
import { previewEventInputs } from '@/hooks/use-pipeline-workspace';
import type { PipelineStep } from './pipeline-types';

const PUSH = '6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10';
const PULL = '0b7e4d33-8c2a-4f6e-b1d9-5a3f2e7c9d01';
const FEED_CREDENTIAL = '9d2f1a77-3c4b-4e5f-8a6b-7c8d9e0f1a2b';

test('inputs are canonical push/pull UUIDs; feeds route by their credential', () => {
  expect(canonicalInput(`push:${PUSH.toUpperCase()}`)).toBe(`push:${PUSH}`);
  expect(canonicalInput(` pull:${PULL} `)).toBe(`pull:${PULL}`);
  expect(() => canonicalInput(`feed:${PUSH}`)).toThrow(/ingest credential/);
  for (const bad of [`other:${PUSH}`, `push:{${PUSH}}`, `push:${PUSH.replaceAll('-', '')}`, PUSH, `push:${PUSH}" || true || "`, 7]) {
    expect(() => canonicalInput(bad)).toThrow();
  }
  expect(inputOfStamp(PUSH)).toBe(`push:${PUSH}`);
  expect(inputOfStamp(`pull:${PULL}`)).toBe(`pull:${PULL}`);
  expect(inputOfStamp('not-a-uuid')).toBeUndefined();
  expect(inputOfStamp(undefined)).toBeUndefined();
});

test('an input branch compiles to a platform metadata check, exactly as the server does', () => {
  expect(inputPredicate([`push:${PUSH}`, `pull:${PULL}`])).toBe(`(%nano_credential_id == "${PUSH}" || %nano_credential_id == "pull:${PULL}")`);
  expect(routeCondition({ label: 'a', inputs: [`push:${PUSH}`, `push:${PUSH}`] })).toBe(`(%nano_credential_id == "${PUSH}")`);
  expect(routeCondition({ label: 'a', inputs: [`pull:${PULL}`], predicate: '.level == "error"' })).toBe(`(%nano_credential_id == "pull:${PULL}") && (.level == "error")`);
  expect(routeCondition({ label: 'a', predicate: '.x == 1' })).toBe('.x == 1');
  expect(() => routeCondition({ label: 'a', inputs: [] })).toThrow(/1–64/);
  expect(() => routeCondition({ label: 'a' })).toThrow(/predicate or input/);
  const step: PipelineStep = { id: 'route', name: 'Route', kind: 'route', enabled: true, config: { mode: 'first', routes: [
    { label: 'pushed', inputs: [`push:${PUSH}`] }, { label: 'pulled', inputs: [`pull:${PULL}`], drop: true },
  ] } };
  const generated = compileStep(step);
  expect(generated).toContain(`condition = "(%nano_credential_id == \\"${PUSH}\\")"`);
  expect(generated).toContain(`(%nano_credential_id == \\"pull:${PULL}\\")`);
  expect(() => compileStep({ ...step, config: { routes: [{ label: 'x', inputs: [`push:${PUSH}`], extra: 1 }] } })).toThrow(/label, a predicate/);
  expect(routeInputsOfDraft({ steps: [step, { ...step, id: 'r2' }] })).toEqual([`push:${PUSH}`, `pull:${PULL}`]);
});

test('pipe steps cannot write the stored input identity', () => {
  expect(() => vrlField('metadata.nano_credential_id')).toThrow(/Platform identity/);
  expect(() => vrlField('metadata.nano_input')).toThrow(/Platform identity/);
  expect(vrlField('unmapped.nano_input')).toBe('."unmapped"."nano_input"');
});

test('recent events keep the stored platform input; preview sends it per event', () => {
  const events = recentEventSamples([
    { raw: 'a', metadata: { nano_credential_id: PUSH } },
    { raw: 'b', 'metadata.nano_credential_id': `pull:${PULL}` },
    { raw: 'c', metadata: { nano_credential_id: 'garbage' } },
  ], { limit: 10, raw_field: 'raw', source_labels: ['lane'] });
  expect(events.map((event) => event.nanoInput)).toEqual([`push:${PUSH}`, `pull:${PULL}`, undefined]);
  expect(previewEventInputs(events, null)).toEqual([`push:${PUSH}`, `pull:${PULL}`, null]);
  expect(previewEventInputs(events, `pull:${PULL}`)).toEqual([`pull:${PULL}`, `pull:${PULL}`, `pull:${PULL}`]);
  expect(previewEventInputs([{}, {}], null)).toBeUndefined();
});

test('lane inputs normalize push credentials, pull sources and credentialed feeds', () => {
  const inputs = laneInputsFrom({
    push: [{ credential_id: PUSH, label: 'Firewall HEC' }, { credential_id: FEED_CREDENTIAL, label: 'dup' }, { credential_id: 'bad' }],
    pull: [{ id: PULL, name: 'CloudTrail S3' }],
    connectors: [{ id: 'feed-1', name: 'Okta', ingest_credential_id: FEED_CREDENTIAL }, { id: 'feed-2', name: 'Not yet issued' }],
  });
  expect(inputs).toEqual([
    { id: `push:${FEED_CREDENTIAL}`, kind: 'feed', label: 'Okta' },
    { id: `pull:${PULL}`, kind: 'pull', label: 'CloudTrail S3' },
    { id: `push:${PUSH}`, kind: 'push', label: 'Firewall HEC' },
  ]);
  expect(laneInputsFrom(null)).toEqual([]);
  expect(laneInputsFrom([1, 2])).toEqual([]);
});
