// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { groupBoundSource } from './pipe-group-bounds';
import { expect, test } from 'vitest';
import { compilePipeline, compileStep, draftFromSource, serializePipeline, vrlCondition, vrlField, rawMessageSamples, supportedStepKinds, EXECUTABLE_STEP_KINDS } from './pipeline-model';
import type { PipelineDraft, PipelineStep } from './pipeline-types';
import type { LogSource } from './api/types';

const draft: PipelineDraft = { name: 'Firewall', description: '', revision: 3, steps: [
  { id: 'parse', name: 'Parse', kind: 'parse', enabled: true, config: { field: 'message', format: 'json' } },
  { id: 'mask', name: 'Hide username', kind: 'mask', enabled: true, config: { fields: ['user'], replacement: '[REDACTED]' } },
] };
const source = (code: string) => ({ name: 'Firewall', description: '', parser_vrl: code } as LogSource);

test('field paths quote injected source text and reject platform identifiers', () => {
  expect(vrlField('user.name')).toBe('."user"."name"');
  expect(vrlField('foo"; abort')).toBe('."foo\\"; abort"');
  expect(() => vrlField('tenant_id')).toThrow(/Platform identity/);
  expect(() => vrlField('user\nabort')).toThrow(/non-empty field path/);
});
test('structured metadata round trips only while its executable body is unchanged', () => {
  const stored = serializePipeline(draft);
  expect(draftFromSource(source(stored))).toEqual(draft);
  const edited = draftFromSource(source(stored + '\n.user = "manual change"'));
  expect(edited.steps.length).toBe(1);
  expect(edited.steps[0].kind).toBe('vrl');
  expect(edited.steps[0].config.code).toBe(stored + '\n.user = "manual change"');
});
test('disabled unsupported steps are preserved without entering the executable body', () => {
  const disabled: PipelineStep = { id: 'split', name: 'Split', kind: 'split', enabled: false, config: {} };
  expect(compilePipeline({ ...draft, steps: [disabled] })).toBe('.');
});
test('values and replacement strings cannot inject executable VRL', () => {
  expect(compileStep({ id: 'set', name: 'Set', kind: 'fields', enabled: true, config: { operation: 'set', field: 'note', value: '\nabort' } })).toBe('."note" = "\\nabort"');
  expect(compileStep({ id: 'mask', name: 'Hash', kind: 'mask', enabled: true, config: { operation: 'hash', fields: ['user'] } })).toBe('."user" = sha2(string!(."user"), variant: "SHA-256")');
});

test('saved capture samples retain legacy raw-message input without double wrapping', () => {
  expect(rawMessageSamples([{ input: { message: '{"action":"deny"}', timestamp: '2026-10-09' } }])).toEqual(['{"action":"deny"}']);
  expect(() => rawMessageSamples([{ input: { action: 'deny' } }])).toThrow(/input shape/);
});

test('forged metadata cannot inject malformed disabled rows into the editor', () => {
  const forged = '# nano-pipe-v1 ' + JSON.stringify({ version: 1, revision: 1, steps: [{ enabled: false }] }) + '\n.';
  const imported = draftFromSource(source(forged));
  expect(imported.steps[0].kind).toBe('vrl');
  expect(imported.steps[0].config.code).toBe(forged);
  expect(() => vrlField('metadata.log_source')).toThrow(/Platform identity/);
});

test('step conditions stay a single expression inside the generated block', () => {
  const step = (condition: string): PipelineStep => ({ id: 'set', name: 'Set', kind: 'fields', enabled: true, condition, config: { operation: 'set', field: 'note', value: 'x' } });
  expect(compileStep(step('.action == "deny"'))).toBe('if .action == "deny" {\n  ."note" = "x"\n}');
  // Braces, separators and comment markers inside string literals are data.
  const literal = String.raw`.msg == "{a};#b" || .x == s'}\{;#'`;
  expect(vrlCondition(literal)).toBe(literal);
  expect(vrlCondition(String.raw`s'ends\\' == .message`)).toBe(String.raw`s'ends\\' == .message`);
  expect(() => vrlCondition(String.raw`s'ends\\'; .x = true`)).toThrow(/one expression/);
  expect(() => compileStep(step('true }\n.tenant_id = "x"\nif true'))).toThrow(/single line/);
  expect(() => compileStep(step('true } .tenant_id = "x"; if true'))).toThrow(/one expression/);
  expect(() => compileStep(step('true # {'))).toThrow(/one expression/);
  expect(() => compileStep(step('.a == "open'))).toThrow(/unterminated/);
});


test('stateless kind controls generate drops, deterministic sampling and bounded split programs', () => {
  const step = (kind: PipelineStep['kind'], config: Record<string, unknown>): PipelineStep => ({ id: kind, name: kind, kind, enabled: true, config });
  expect(compileStep(step('filter', { predicate: '.ok == true', action: 'keep' }))).toContain('if !(.ok == true)');
  expect(compileStep(step('sample', { ratio: 3, groupBy: 'message' }))).toContain('mod(parse_int!');
  expect(() => compileStep(step('sample', { ratio: 0 }))).toThrow(/ratio/);
  expect(compilePipeline({ ...draft, steps: [step('split', { field: '.items', as: '.item', max: 3 }), step('set', { field: 'value', value: true })] })).toContain('for_each(nano_pipe_0_items)');
  expect(vrlField('.items')).toBe('."items"');
});

test('NAN-3454: every advertised runtime step kind is enabled in the editor', () => {
  const advertised = ['parse', 'rename', 'remove', 'set', 'redact', 'fields', 'mask', 'filter', 'sample', 'split', 'vrl', 'dedupe', 'combine', 'route', 'lookup'];
  const enabled = supportedStepKinds(advertised);
  expect(enabled).toHaveLength(15);
  expect(new Set(enabled)).toEqual(new Set(EXECUTABLE_STEP_KINDS));
});

test('NAN-3454: a legacy-only runtime keeps the old parse/fields/mask/vrl kinds via aliases', () => {
  const enabled = supportedStepKinds(['parse', 'rename', 'remove', 'set', 'redact', 'vrl']);
  for (const kind of ['parse', 'fields', 'mask', 'vrl'] as const) expect(enabled).toContain(kind);
  for (const kind of ['filter', 'sample', 'split', 'dedupe', 'combine', 'route', 'lookup'] as const) expect(enabled).not.toContain(kind);
  expect(supportedStepKinds(['remove'])).toEqual(['remove', 'fields']);
  expect(supportedStepKinds(['redact'])).toEqual(['redact', 'mask']);
});

test('NAN-3454: unknown, duplicate and missing runtime kinds are ignored', () => {
  expect(supportedStepKinds(['reduce', 'filter', 'filter', '__proto__', 'constructor', 'toString'])).toEqual(['filter']);
  expect(supportedStepKinds(undefined)).toEqual([]);
  expect(supportedStepKinds([])).toEqual([]);
});


test('native bounds settings match the backend fixed gate and cap legacy settings', () => {
  const backend = readFileSync(new URL('../../../nanosiem-core/src/parsers/pipe/bounds.lua', import.meta.url), 'utf8');
  expect(groupBoundSource(5)).toBe('local NANO_PIPE_MAX_GROUPS = 64\nlocal NANO_PIPE_EXPIRE_TICKS = 5\n' + backend);
  const combine: PipelineStep = { id:'combine', name:'Combine', kind:'combine', enabled:true, config:{keys:['host'],timeoutSec:60} };
  expect(compileStep(combine)).toContain('expire_after_ms = 5000');
  expect(compileStep(combine)).toContain('NANO_PIPE_MAX_GROUPS = 64');
  expect(compileStep(combine)).toContain('nano_reduced.context[0]');
  expect(compileStep(combine)).not.toContain('parse_json');
  expect(compileStep(combine)).toContain('inputs = ["pipe_prepare","pipe_bound"]');
  expect(compileStep(combine)).toContain('[transforms.pipe_bound]\ntype = "lua"\ninputs = ["pipe_control"]');
  const dedupe: PipelineStep = { id:'dedupe', name:'Dedupe', kind:'dedupe', enabled:true, config:{fields:['message'],cacheEvents:50000} };
  expect(compileStep(dedupe)).toContain('cache.num_events = 5000');
  expect(compileStep(dedupe)).toContain('fields.match = ["signature"]');
  expect(compileStep(dedupe)).toContain('SHA-256');
});
