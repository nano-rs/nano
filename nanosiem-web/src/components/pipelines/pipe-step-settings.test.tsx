// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { useState } from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { PipelineLaneInput, PipelineStep, PipelineStepKind } from '@/lib/pipeline-types';
import { PipelineStepSettings } from './PipelineSteps';
import { newPipelineStep } from './pipeline-catalog';
vi.mock('@/components/editor/VrlEditor', () => ({ VrlEditor: () => <div /> }));
afterEach(cleanup);
function editor(kind: PipelineStepKind, laneInputs: PipelineLaneInput[] = []) {
  let current: PipelineStep;
  function Harness() {
    const [step, setStep] = useState(newPipelineStep(kind)); current = step;
    return <PipelineStepSettings step={step} supported readOnly={false} onChange={setStep} laneInputs={laneInputs} />;
  }
  render(<Harness />);
  return () => current!;
}
it('fields supports a typed batch of rename, remove and set operations', () => {
  const current = editor('fields');
  fireEvent.change(screen.getByLabelText('Operation'), { target: { value: 'batch' } });
  fireEvent.change(screen.getByLabelText(/Field operations/), { target: { value: '[{"operation":"set","field":"count","value":7}]' } });
  expect(current().config.operations).toEqual([{ operation: 'set', field: 'count', value: 7 }]);
  expect(screen.getByText('."count" = 7')).toBeTruthy();
});
it('mask configures MD5 and partial Unicode character masking', () => {
  const current = editor('mask');
  fireEvent.change(screen.getByLabelText('Operation'), { target: { value: 'hash' } });
  fireEvent.change(screen.getByLabelText('Hash algorithm'), { target: { value: 'md5' } });
  expect(current().config.algorithm).toBe('md5');
  expect(screen.getByText(/= md5\(string!/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Operation'), { target: { value: 'partial' } });
  fireEvent.change(screen.getByLabelText('Visible trailing characters'), { target: { value: '2' } });
  expect(current().config.keepEnd).toBe(2);
  expect(screen.getByText(/\?P<tail>\.\{2\}/)).toBeTruthy();
});
it('filter supports keep-only and drop matching semantics', () => {
  const current = editor('filter');
  fireEvent.change(screen.getByLabelText('Matching events'), { target: { value: 'keep' } });
  fireEvent.change(screen.getByLabelText('Predicate'), { target: { value: '.ok == true' } });
  expect(current().config).toMatchObject({ action: 'keep', predicate: '.ok == true' });
  expect(screen.getByText(/if !\(\.ok == true\)/)).toBeTruthy();
});
it('sampling exposes a deterministic 1-in-N key and exemption', () => {
  const current = editor('sample');
  fireEvent.change(screen.getByLabelText('Keep 1 in every N events'), { target: { value: '4' } });
  fireEvent.change(screen.getByLabelText('Consistent sampling key'), { target: { value: 'request.id' } });
  fireEvent.change(screen.getByLabelText('Always keep condition (optional)'), { target: { value: '.critical == true' } });
  expect(current().config).toMatchObject({ ratio: 4, groupBy: 'request.id', exempt: '.critical == true' });
  expect(screen.getByText(/mod\(parse_int!.*4\) != 0/)).toBeTruthy();
});
it('split exposes source/target fields, retained context and expansion limit', () => {
  const current = editor('split');
  fireEvent.change(screen.getByLabelText('Array field'), { target: { value: 'records' } });
  fireEvent.change(screen.getByLabelText(/Retained context fields/), { target: { value: 'class_uid, user' } });
  fireEvent.change(screen.getByLabelText('Maximum outputs per input'), { target: { value: '3' } });
  expect(current().config).toMatchObject({ field: 'records', keep: ['class_uid', 'user'], max: 3 });
  expect(screen.getByText(/if length\(nano_pipe_0_items\) > 3/)).toBeTruthy();
});

it('dedupe configures the actual native LRU event capacity', () => {
  const current = editor('dedupe');
  fireEvent.change(screen.getByLabelText('Maximum cached events'), { target: { value: '20' } });
  expect(current().config.cacheEvents).toBe(20);
  expect(screen.getByText(/cache.num_events = 20/)).toBeTruthy();
  expect(screen.queryByLabelText('Cache TTL (seconds)')).toBeNull();
});
it('combine configures group fields, merge rules, count and flush limits', () => {
  const current = editor('combine');
  fireEvent.change(screen.getByLabelText(/Group keys/), { target: { value: 'host' } });
  fireEvent.change(screen.getByLabelText(/Merge rules/), { target: { value: '{"bytes":"sum"}' } });
  fireEvent.change(screen.getByLabelText('Maximum events per group'), { target: { value: '3' } });
  expect(current().config).toMatchObject({ keys: ['host'], merge: { bytes: 'sum' }, maxEvents: 3 });
  expect(screen.getByText(/max_events = 3/)).toBeTruthy();
});
it('route exposes branch tagging, ordered branches and single-output fallback', () => {
  const current = editor('route');
  fireEvent.change(screen.getByLabelText('Matching behavior'), { target: { value: 'fanout' } });
  fireEvent.change(screen.getByLabelText('Branch 1 label'), { target: { value: 'audit' } });
  fireEvent.change(screen.getByLabelText('Branch 1 predicate'), { target: { value: '.class_uid == 3002' } });
  fireEvent.click(screen.getByText('Add branch'));
  fireEvent.click(screen.getByLabelText('Branch 2 drop'));
  fireEvent.change(screen.getByLabelText('Unmatched events'), { target: { value: 'drop' } });
  expect(current().config).toMatchObject({ mode: 'fanout', fallback: 'drop', routes: [
    { label: 'audit', predicate: '.class_uid == 3002', drop: false }, { label: 'branch_2', predicate: 'true', drop: true },
  ] });
  expect(screen.getByText(/type = "route"/)).toBeTruthy();
  fireEvent.click(screen.getByLabelText('Remove branch 2'));
  expect((current().config.routes as unknown[]).length).toBe(1);
});
it('lookup edits immutable snapshot rows and missing-match behavior', () => {
  const current = editor('lookup');
  fireEvent.change(screen.getByLabelText(/Lookup snapshot rows/), { target: { value: '[{"key":"event","value":"owner"}]' } });
  fireEvent.change(screen.getByLabelText('Missing match'), { target: { value: 'error' } });
  expect(current().config).toMatchObject({ rows: [{ key: 'event', value: 'owner' }], missing: 'error' });
  expect(screen.getByText(/get_enrichment_table_record/)).toBeTruthy();
});

const PUSH = '6f1c0c1e-2b8f-4d7e-9a51-0c5e6c1d2a10';
const PULL = '0b7e4d33-8c2a-4f6e-b1d9-5a3f2e7c9d01';
it('route "Input is" branches pick the lane\'s inputs and compile to the platform identity', () => {
  const current = editor('route', [
    { id: `push:${PUSH}`, kind: 'push', label: 'Firewall HEC' },
    { id: `pull:${PULL}`, kind: 'pull', label: 'CloudTrail S3' },
  ]);
  fireEvent.change(screen.getByLabelText('Branch 1 condition'), { target: { value: 'input' } });
  expect(screen.queryByLabelText('Branch 1 predicate')).toBeNull();
  expect(screen.getByText('Choose at least one input.')).toBeTruthy();
  fireEvent.click(screen.getByLabelText('Branch 1 input CloudTrail S3'));
  expect(current().config.routes).toEqual([{ label: 'matching', drop: false, inputs: [`pull:${PULL}`] }]);
  expect(screen.getByText(new RegExp(`%nano_credential_id == \\\\"pull:${PULL}\\\\"`))).toBeTruthy();
  // A manual id is canonicalized; a feed id or junk is refused with a message.
  fireEvent.change(screen.getByLabelText('Branch 1 input id'), { target: { value: `feed:${PUSH}` } });
  fireEvent.click(screen.getByText('Add input'));
  expect(screen.getByRole('alert').textContent).toMatch(/ingest credential/);
  fireEvent.change(screen.getByLabelText('Branch 1 input id'), { target: { value: `push:${PUSH.toUpperCase()}` } });
  fireEvent.click(screen.getByText('Add input'));
  expect((current().config.routes as Array<{ inputs: string[] }>)[0].inputs).toEqual([`pull:${PULL}`, `push:${PUSH}`]);
  // Unticking keeps other inputs; switching back restores an expression.
  fireEvent.click(screen.getByLabelText('Branch 1 input CloudTrail S3'));
  expect((current().config.routes as Array<{ inputs: string[] }>)[0].inputs).toEqual([`push:${PUSH}`]);
  fireEvent.change(screen.getByLabelText('Branch 1 condition'), { target: { value: 'expression' } });
  expect(current().config.routes).toEqual([{ label: 'matching', drop: false, predicate: 'true' }]);
});
it('route keeps showing a saved input the lane no longer lists', () => {
  function Harness() {
    const [step, setStep] = useState<PipelineStep>({ ...newPipelineStep('route'), config: { mode: 'first', routes: [{ label: 'old', inputs: [`push:${PUSH}`] }] } });
    return <PipelineStepSettings step={step} supported readOnly={false} onChange={setStep} laneInputs={[]} />;
  }
  render(<Harness />);
  expect((screen.getByLabelText('Branch 1 input Not listed for this lane') as HTMLButtonElement).getAttribute('data-state')).toBe('checked');
});
