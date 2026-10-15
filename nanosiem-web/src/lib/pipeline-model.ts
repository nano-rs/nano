// SPDX-License-Identifier: AGPL-3.0-or-later

import { groupBoundSource, PIPE_MAX_DEDUPE_EVENTS, PIPE_MAX_EXPIRE_SECONDS } from './pipe-group-bounds';
import type { LogSource, TenantParserRollout } from './api/types';
import type { CapturedEvent, PipelineDraft, PipelinePreview, PipelineStep, PipelineStepKind, PipelineRelease, PipelineSummary } from './pipeline-types';

const HEADER = '# nano-pipe-v2 ';
const LEGACY_HEADER = '# nano-pipe-v1 ';
const PLAN_BODY = '# Processing plan compiled by Nano at publication.\nnano_pipe_plan_v2()';

/** NAN-3452: the one line the preview shows about what it does not run. */
export const PREVIEW_SCOPE_NOTE = 'Preview runs a frozen batch of draft processing. No normalization or sinks. Times in UTC.';
/** Detail behind the scope note's info icon. */
export const PREVIEW_SCOPE_DETAILS = [
  'Platform normalization, buffering, existing production sampling and sinks are excluded. Native Vector stateful steps use isolated batch simulation.',
  'Dedupe starts with an empty cache. Partial groups flush at the end of the sample; production uses its event limit and idle timeout per Vector instance.',
  'Step traces replay cumulative draft prefixes independently, so time and random functions can differ between stages.',
  'Implicit timezones use UTC; specify a timezone in VRL when you need another.',
] as const;
/**
 * Standing runtime caveats the scope note already covers. The server repeats
 * them on capabilities, validation, and every preview response; showing them
 * verbatim stacked four paragraphs (two duplicates) above the preview.
 */
const PREVIEW_BOILERPLATE = [
  'Draft preview runs stateless VRL',
  'Draft preview executes native VRL only.',
  'Step traces replay cumulative draft prefixes independently',
  'Implicit preview timezones use UTC',
];
export function isPreviewBoilerplate(warning: string): boolean {
  return PREVIEW_BOILERPLATE.some((prefix) => warning.startsWith(prefix));
}
export function withoutPreviewBoilerplate(warnings: readonly string[] | undefined): string[] {
  return (warnings ?? []).filter((warning) => !isPreviewBoilerplate(warning));
}
export const EXECUTABLE_STEP_KINDS = ['parse', 'rename', 'remove', 'set', 'redact', 'fields', 'mask', 'filter', 'sample', 'split', 'dedupe', 'combine', 'route', 'lookup', 'vrl'] as const;
const STEP_KINDS = new Set(['parse', 'rename', 'remove', 'set', 'redact', 'filter', 'sample', 'split', 'fields', 'mask', 'combine', 'lookup', 'dedupe', 'route', 'vrl']);
const LEGACY_STEP_ALIASES: Record<string, PipelineStepKind> = { rename: 'fields', remove: 'fields', set: 'fields', redact: 'mask' };
/**
 * Editor step kinds the runtime can execute, from the backend's advertised
 * `supported_step_kinds`. Known kinds pass straight through, legacy
 * rename/remove/set imply `fields` and redact implies `mask`; unknown kinds are
 * ignored. Returned in catalog order without duplicates.
 */
export function supportedStepKinds(runtimeKinds: readonly string[] | undefined): PipelineStepKind[] {
  const enabled = new Set<string>();
  for (const kind of runtimeKinds ?? []) {
    if (STEP_KINDS.has(kind)) enabled.add(kind);
    const alias = Object.hasOwn(LEGACY_STEP_ALIASES, kind) ? LEGACY_STEP_ALIASES[kind] : undefined;
    if (alias) enabled.add(alias);
  }
  return EXECUTABLE_STEP_KINDS.filter((kind) => enabled.has(kind));
}
function validStoredSteps(value: unknown): value is PipelineStep[] {
  if (!Array.isArray(value) || value.length > 50) return false;
  const ids = new Set<string>();
  return value.every((step) => {
    if (!step || typeof step !== 'object' || typeof step.id !== 'string' || !step.id || !/^[A-Za-z0-9_-]{1,128}$/.test(step.id) || ['__proto__', 'constructor', 'prototype'].includes(step.id) || ids.has(step.id) || typeof step.name !== 'string' || !STEP_KINDS.has(step.kind) || typeof step.enabled !== 'boolean' || !step.config || typeof step.config !== 'object' || Array.isArray(step.config) || step.condition !== undefined && typeof step.condition !== 'string') return false;
    ids.add(step.id);
    return true;
  });
}

/**
 * Quote each field segment so a field name is always a path, never code.
 * This is a client-side authoring guard only: steps may also carry a VRL
 * condition (see `vrlCondition`) or advanced VRL, so the server's
 * shared-bundle structural guards remain the security boundary.
 */
export function vrlField(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error('A field name is required.');
  const path = value.trim().replace(/^\./, '');
  const parts = path.split('.');
  if (path.length > 256 || parts.length > 16 || parts.some((part) => !part || Array.from(part).some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127))) throw new Error('Use a non-empty field path.');
  if (['tenant_id', 'nano_tenant_id', 'source_type', '_nano', '_nano_internal'].includes(parts[0]) || parts[0] === 'metadata' && ['tenant_id', 'tenant_uid', 'log_source', 'nano_credential_id', 'nano_input'].includes(parts[1])) {
    throw new Error('Platform identity fields cannot be changed.');
  }
  return '.' + parts.map((part) => JSON.stringify(part)).join('.');
}
/**
 * NAN-3625: the platform input identity (`nano_input`). Ingress stamps the
 * trusted Vector metadata `%nano_credential_id`: the ingest credential UUID for
 * push (connector feeds push with their own per-feed credential) and
 * `pull:<source id>` for pull. Tenant VRL cannot write `%` metadata, so an
 * "Input is" route branch reads it instead of anything in the event body.
 * The server compiler (`parsers::pipe::input`) is authoritative.
 */
export const INPUT_METADATA = 'nano_credential_id';
const INPUT_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const MAX_ROUTE_INPUTS = 64;
/** Canonical `push:<uuid>` / `pull:<uuid>`; throws on anything else. */
export function canonicalInput(value: unknown): string {
  const text = typeof value === 'string' ? value.trim() : '';
  const split = text.indexOf(':');
  const kind = split > 0 ? text.slice(0, split) : '', id = text.slice(split + 1).toLowerCase();
  if (kind === 'feed') throw new Error('Choose a connector feed by its ingest credential (push:<credential id>).');
  if (kind !== 'push' && kind !== 'pull') throw new Error('An input is push:<credential id> or pull:<pull source id>.');
  if (!INPUT_UUID.test(id)) throw new Error('An input id must be a hyphenated UUID.');
  return `${kind}:${id}`;
}
/** The canonical input behind a stamped `%nano_credential_id` / stored `metadata.nano_credential_id`. */
export function inputOfStamp(stamp: unknown): string | undefined {
  if (typeof stamp !== 'string' || !stamp) return undefined;
  try {
    const input = canonicalInput(stamp.startsWith('pull:') ? stamp : `push:${stamp}`);
    return stampOf(input) === stamp.toLowerCase() ? input : undefined;
  } catch { return undefined; }
}
const stampOf = (input: string) => input.startsWith('push:') ? input.slice(5) : input;
/** Validated, de-duplicated canonical inputs of one route branch. */
export function routeInputs(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error('Route inputs must be an array of push:/pull: input ids.');
  if (!value.length || value.length > MAX_ROUTE_INPUTS) throw new Error(`Route inputs require 1–${MAX_ROUTE_INPUTS} input ids.`);
  return [...new Set(value.map(canonicalInput))];
}
/** The read-only condition an "Input is" branch compiles to. */
export function inputPredicate(inputs: string[]): string {
  return `(${inputs.map((input) => `%${INPUT_METADATA} == ${JSON.stringify(stampOf(input))}`).join(' || ')})`;
}
/** A route branch's compiled condition: its predicate AND its inputs, as the server compiles it. */
export function routeCondition(route: Record<string, unknown>): string {
  const inputs = route.inputs === undefined ? [] : routeInputs(route.inputs);
  const written = typeof route.predicate === 'string' && route.predicate.trim() ? vrlCondition(route.predicate) : '';
  if (route.predicate !== undefined && typeof route.predicate !== 'string') throw new Error('A branch predicate must be text.');
  if (!inputs.length) {
    if (route.predicate === undefined) throw new Error('A branch predicate or input is required.');
    return vrlCondition(String(route.predicate));
  }
  return written ? `${inputPredicate(inputs)} && (${written})` : inputPredicate(inputs);
}
/** Every valid input a draft's route branches name, in order, without duplicates. */
export function routeInputsOfDraft(draft: Pick<PipelineDraft, 'steps'>): string[] {
  const out = new Set<string>();
  for (const step of draft.steps) {
    if (step.kind !== 'route' || !Array.isArray(step.config.routes)) continue;
    for (const route of step.config.routes) {
      if (!route || typeof route !== 'object' || !Array.isArray((route as Record<string, unknown>).inputs)) continue;
      for (const input of (route as Record<string, unknown>).inputs as unknown[]) {
        try { out.add(canonicalInput(input)); } catch { /* invalid entries are reported by validation */ }
      }
    }
  }
  return [...out];
}
/**
 * A step condition is a VRL boolean expression that the author writes, so it
 * cannot be escaped. Validate its structure so it cannot close the generated
 * `if … {` block, start a new statement, or comment out the opening brace.
 * This keeps conditions to one expression; it does not make them sandboxed
 * (advanced VRL steps run arbitrary code). Server guards remain authoritative.
 */
export function vrlCondition(value: string): string {
  const condition = value.trim();
  if (condition.length > 4096 || /[\n\r\0]/.test(condition)) throw new Error('A step condition must be a single line.');
  let quote: '"' | "'" | null = null;
  for (let index = 0; index < condition.length; index++) {
    const char = condition[index];
    if (quote) {
      // VRL uses backslashes for literal token boundaries, including raw literals.
      // The backend's real parser validates their contents and complete expression.
      if (char === '\\') index++;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === '{' || char === '}' || char === ';' || char === '#') throw new Error(`A step condition is one expression; remove "${char}" outside string literals.`);
  }
  if (quote) throw new Error('A step condition has an unterminated string literal.');
  return condition;
}
function text(config: Record<string, unknown>, key: string, fallback = ''): string {
  const value = config[key] ?? fallback;
  if (typeof value !== 'string') throw new Error(`${key} must be text.`);
  return value;
}
function literal(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error('A JSON value is required.');
  return serialized;
}

export function compileStep(step: PipelineStep): string {
  const config = step.config;
  let code: string;
  switch (step.kind) {
    case 'vrl':
      code = text(config, 'code');
      if (!code.trim()) throw new Error(`${step.name}: add VRL code.`);
      break;
    case 'parse': {
      if (text(config, 'format', 'json') !== 'json') throw new Error('Only JSON parsing is supported by this runtime.');
      const field = vrlField(config.field ?? 'message');
      code = `parsed = object!(parse_json!(string!(${field})))\n. = merge(., parsed)`;
      break;
    }
    case 'fields':
    case 'rename':
    case 'remove':
    case 'set': {
      const operation = step.kind === 'fields' ? text(config, 'operation', 'rename') : step.kind;
      if (operation === 'batch') {
        if (!Array.isArray(config.operations) || !config.operations.length || config.operations.length > 64) throw new Error('Use 1–64 field operations.');
        code = config.operations.map((op) => {
          if (!op || typeof op !== 'object' || Array.isArray(op) || !['rename', 'remove', 'set'].includes(op.operation)) throw new Error('Choose a field operation.');
          return compileStep({ ...step, kind: op.operation, condition: '', config: op });
        }).join('\n');
        break;
      }
      const field = vrlField(config.field);
      if (operation === 'rename') code = `${vrlField(config.target)} = del(${field})`;
      else if (operation === 'remove') code = `del(${field})`;
      else if (operation === 'set') code = `${field} = ${literal(config.value)}`;
      else throw new Error('Choose rename, remove, or set.');
      break;
    }
    case 'mask':
    case 'redact': {
      const fields = config.fields;
      if (!Array.isArray(fields) || !fields.length || fields.length > 64) throw new Error('Select at least one field to mask.');
      if (typeof config.replacement === 'string' && new TextEncoder().encode(config.replacement).length > 1024) throw new Error('Mask replacement exceeds 1024 bytes.');
      const operation = text(config, 'operation', 'replace');
      if (!['replace', 'hash', 'partial'].includes(operation)) throw new Error('Choose replacement, hashing or partial masking.');
      code = fields.map((name) => {
        const field = vrlField(name);
        if (operation === 'hash') {
          const algorithm = text(config, 'algorithm', 'sha256');
          if (!['sha256', 'md5'].includes(algorithm)) throw new Error('Choose sha256 or md5.');
          return algorithm === 'md5' ? `${field} = md5(string!(${field}))` : `${field} = sha2(string!(${field}), variant: "SHA-256")`;
        }
        if (operation === 'partial') {
          const start = integer(config, 'keepStart', 1, 0, 64), end = integer(config, 'keepEnd', 0, 0, 64);
          const replacement = literal(config.replacement ?? '*');
          return `nano_mask, nano_mask_error = parse_regex(string!(${field}), r'(?s)^(?P<head>.{${start}})(?P<middle>.*)(?P<tail>.{${end}})$')\n${field} = if nano_mask_error == null { string!(nano_mask.head) + replace(string!(nano_mask.middle), r'(?s).', ${replacement}) + string!(nano_mask.tail) } else { replace(string!(${field}), r'(?s).', ${replacement}) }`;
        }
        return `${field} = ${literal(config.replacement ?? '[REDACTED]')}`;
      }).join('\n');
      break;
    }
    case 'dedupe':
    case 'combine':
    case 'route':
    case 'lookup':
      return nativeStepConfig(step);
    case 'filter':
    case 'sample':
      return `if ${discardCondition(step)} {\n  . = []\n}`;
    case 'split':
      return compileSequence([step]);
    default:
      throw new Error(`${step.kind} is not supported by the current preview and publication runtime.`);
  }
  const condition = step.condition?.trim() ? vrlCondition(step.condition) : '';
  return condition ? `if ${condition} {\n${code.split('\n').map((line) => '  ' + line).join('\n')}\n}` : code;
}

function integer(config: Record<string, unknown>, key: string, fallback: number, min: number, max: number): number {
  const value = config[key] ?? fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${key} must be ${min}–${max}.`);
  return value;
}
const indent = (code: string) => code.split('\n').map(line => '  ' + line).join('\n');
function discardCondition(step: PipelineStep): string {
  const config = step.config;
  let reject: string;
  if (step.kind === 'filter') {
    const predicate = vrlCondition(text(config, 'predicate', 'true'));
    const action = text(config, 'action', 'keep');
    if (!['keep', 'drop'].includes(action)) throw new Error('Filter action must be keep or drop.');
    reject = action === 'keep' ? `!(${predicate})` : `(${predicate})`;
  } else {
    const ratio = integer(config, 'ratio', 10, 1, 1000000);
    const key = text(config, 'groupBy', 'message').trim() || 'message';
    const hash = `parse_int!(slice!(sha2(encode_json(${vrlField(key)}), variant: "SHA-256"), 0, 7), base: 16)`;
    reject = `mod(${hash}, ${ratio}) != 0`;
    const exempt = text(config, 'exempt').trim();
    if (exempt) reject = `!(${vrlCondition(exempt)}) && (${reject})`;
  }
  const gate = step.condition?.trim() ? vrlCondition(step.condition) : '';
  return gate ? `(${gate}) && (${reject})` : reject;
}
function compileSequence(steps: PipelineStep[], depth = 0): string {
  const [step, ...rest] = steps;
  if (!step) return '.';
  if (depth > 50) throw new Error('Too many processing steps.');
  const tail = compileSequence(rest, depth + 1);
  let code: string;
  if (['dedupe', 'combine', 'route', 'lookup'].includes(step.kind)) {
    nativeStepConfig(step);
    code = `# Native Vector ${step.kind} step; emitted as a transform at publication.\n${tail}`;
  } else if (step.kind === 'split') {
    const config = step.config;
    const field = vrlField(config.field ?? 'items');
    const as = vrlField(config.as ?? 'item');
    const max = integer(config, 'max', 50, 1, 1000);
    const keep = config.keep ?? [];
    if (!Array.isArray(keep) || keep.length > 64) throw new Error('Retained context requires at most 64 field paths.');
    const paths = keep.map(vrlField);
    const gate = step.condition?.trim() ? vrlCondition(step.condition) : 'true';
    const prefix = `nano_pipe_${depth}`;
    const context = paths.length ? ['. = {}', ...paths.map(path => `${path} = ${prefix}_parent${path}`)].join('\n') : `. = ${prefix}_parent`;
    const child = `if ${prefix}_run {\n${indent(context)}\n  ${as} = ${prefix}_item\n} else {\n  . = ${prefix}_parent\n}\n${tail}\n${prefix}_out = if is_array(.) { append(${prefix}_out, array!(.)) } else { push(${prefix}_out, .) }\nif length(${prefix}_out) > 1000 { abort }`;
    code = `${prefix}_run = ${gate}\n${prefix}_parent = .\n${prefix}_items = if ${prefix}_run { array!(${field}) } else { [null] }\nif length(${prefix}_items) > ${max} { abort }\n${prefix}_out = []\nfor_each(${prefix}_items) -> |${prefix}_index, ${prefix}_item| {\n${indent(child)}\n}\n. = ${prefix}_out`;
  } else {
    const head = compileStep(step);
    code = ['filter', 'sample'].includes(step.kind) && rest.length ? `${head}\nif is_object(.) {\n${indent(tail)}\n}` : rest.length ? `${head}\n\n${tail}` : head;
  }
  if (new TextEncoder().encode(code).length > 256 * 1024) throw new Error('Compiled processing exceeds 256 KiB.');
  return code;
}
/** Inspectable native graph. Publication binds these illustrative ids to the source. */
export function nativeStepConfig(step: PipelineStep): string {
  const c = step.config;
  const pieces = ['# Illustrative component ids; publication binds ids and lookup paths to this source.'];
  const paths = (key: string) => {
    const values = c[key];
    if (!Array.isArray(values) || !values.length || values.length > 16) throw new Error(`${key} requires 1–16 field paths.`);
    return values.map(path => vrlField(path));
  };
  const emit = (id: string, kind: string, inputs: string[], settings: string[] = []) => {
    pieces.push(`[transforms.${id}]\ntype = ${JSON.stringify(kind)}\ninputs = ${JSON.stringify(inputs)}\n${settings.join('\n')}`);
  };
  const remap = (id: string, inputs: string[], source: string) => {
    emit(id, 'remap', inputs, ['drop_on_abort = true', 'drop_on_error = true', 'reroute_dropped = true', `source = ${JSON.stringify(source)}`]);
  };
  let input = 'previous_processing_step';
  let output = 'pipe_step';
  const gate = step.condition?.trim();
  if (gate) {
    emit('pipe_gate', 'route', [input], [`route.apply = ${JSON.stringify(vrlCondition(gate))}`]);
    input = 'pipe_gate.apply';
  }
  const typeTag = (path: string) => `[${['timestamp', 'integer', 'float', 'string', 'boolean', 'array', 'object'].map(kind => `is_${kind}(${path})`).join(', ')}]`;
  const signature = (fields: string[], present: boolean) => `sha2(encode_json([${fields.map(path => `{ ${present ? `"present": exists(${path}), ` : ''}"type": ${typeTag(path)}, "value": ${path} }`).join(', ')}]), variant: "SHA-256")`;
  if (step.kind === 'dedupe') {
    if ('ttlSec' in c) throw new Error('Native dedupe uses an event-count LRU cache. Remove the prototype TTL setting.');
    const fields = paths('fields');
    remap('pipe_prepare', [input], `nano_signature = ${signature(fields, true)}\n. = { "context": [.], "signature": nano_signature }`);
    emit('pipe_step', 'dedupe', ['pipe_prepare'], ['fields.match = ["signature"]', `cache.num_events = ${Math.min(integer(c, 'cacheEvents', 1000, 1, 50000), PIPE_MAX_DEDUPE_EVENTS)}`]);
    remap('pipe_finish', ['pipe_step'], '. = object!(.context[0])');
    output = 'pipe_finish';
  } else if (step.kind === 'combine') {
    const keys = paths('keys'), count = vrlField(c.countField ?? 'unmapped.event_count');
    const merge = c.merge ?? {};
    if (!merge || typeof merge !== 'object' || Array.isArray(merge) || Object.keys(merge).length > 16) throw new Error('Merge rules map field paths to strategies.');
    const rules = Object.entries(merge).sort(([a], [b]) => a.localeCompare(b));
    for (const [field, strategy] of rules) {
      if (vrlField(field) === count) throw new Error('Count field cannot also have a merge rule.');
      if (!['retain', 'sum', 'min', 'max', 'concat', 'concat_newline', 'array'].includes(String(strategy))) throw new Error('Unsupported merge strategy.');
    }
    const pairs = ['"context": [.]', '"count": 1', `"group_hash": ${signature(keys, false)}`];
    const checks = rules.map(([field, strategy], i) => {
      const valid = ['sum', 'min', 'max'].includes(String(strategy)) ? `is_integer(nano_value_${i}) || is_float(nano_value_${i})` : ['concat', 'concat_newline'].includes(String(strategy)) ? `is_string(nano_value_${i})` : null;
      return `nano_value_${i} = ${vrlField(field)}\n${valid ? `if nano_value_${i} != null && !(${valid}) { abort }\n` : ''}`;
    }).join('');
    const prepare = checks + `. = { ${pairs.join(', ')} }\n` + rules.map(([, strategy], i) => strategy === 'array' ? `.value_${i} = nano_value_${i}` : `if nano_value_${i} != null { .value_${i} = nano_value_${i} }`).join('\n');
    remap('pipe_prepare', [input], prepare);
    const timeout = Math.min(integer(c, 'timeoutSec', 5, 1, 60), PIPE_MAX_EXPIRE_SECONDS);
    // Only a {group_hash} copy enters Lua (its round trip drops metadata and rewrites null/[]); events go straight to reduce.
    remap('pipe_control', ['pipe_prepare'], '. = { "group_hash": .group_hash }');
    emit('pipe_bound', 'lua', ['pipe_control'], ['version = "2"', 'hooks.init = "nano_pipe_init"', 'hooks.process = "nano_pipe_process"', 'hooks.shutdown = "nano_pipe_shutdown"', 'timers = [{ handler = "nano_pipe_expire", interval_seconds = 1 }]', `source = ${JSON.stringify(groupBoundSource(timeout))}`]);
    emit('pipe_step', 'reduce', ['pipe_prepare', 'pipe_bound'], ['ends_when = ".nano_flush == true"',
      'group_by = ["group_hash"]',
      `max_events = ${integer(c, 'maxEvents', 100, 1, 1000)}`,
      `expire_after_ms = ${timeout * 1000}`, 'flush_period_ms = 100',
      'merge_strategies.context = "retain"', 'merge_strategies.count = "sum"',
      'merge_strategies.group_hash = "retain"',
      ...rules.map(([, strategy], i) => `merge_strategies.value_${i} = ${JSON.stringify(strategy)}`),
    ]);
    remap('pipe_finish', ['pipe_step'], `nano_reduced = .\nif exists(nano_reduced.context) {\n. = object!(nano_reduced.context[0])\n${count} = nano_reduced.count\n` + rules.map(([field], i) => `if exists(nano_reduced.value_${i}) { ${vrlField(field)} = nano_reduced.value_${i} }`).join('\n') + '\n} else { . = [] }');
    output = 'pipe_finish';
  } else if (step.kind === 'route') {
    const mode = text(c, 'mode', 'first'); if (!['first', 'fanout'].includes(mode)) throw new Error('Route mode must be first or fanout.');
    const routes = c.routes;
    if (!Array.isArray(routes) || !routes.length || routes.length > 16) throw new Error('Use 1–16 ordered route branches.');
    const field = vrlField(c.field ?? 'unmapped.pipe_route'), labels = new Set<string>();
    for (const route of routes) {
      if (!route || typeof route !== 'object' || Array.isArray(route) || typeof route.label !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(route.label) || labels.has(route.label)) throw new Error('Route labels must be unique names.');
      labels.add(route.label);
      if (Object.keys(route).some((key) => !['label', 'predicate', 'inputs', 'drop'].includes(key))) throw new Error('A route has a label, a predicate and/or inputs, and an optional drop.');
      routeCondition(route);
      if (route.drop !== undefined && typeof route.drop !== 'boolean') throw new Error('Route drop must be boolean.');
    }
    const fallback = text(c, 'fallback', 'keep');
    if (!['keep', 'drop', 'output:nano-lake'].includes(fallback)) throw new Error('Single-output fallback must be keep or drop.');
    emit('pipe_step', mode === 'first' ? 'exclusive_route' : 'route', [input], mode === 'first'
      ? [`routes = [${routes.map((route, i) => `{ name = "branch_${i}", condition = ${JSON.stringify(routeCondition(route))} }`).join(', ')}]`]
      : routes.map((route, i) => `route.branch_${i} = ${JSON.stringify(routeCondition(route))}`));
    routes.forEach((route, i) => remap(`pipe_branch_${i}`, [`pipe_step.branch_${i}`], route.drop ? '. = []' : `${field} = ${JSON.stringify(route.label)}`));
    remap('pipe_fallback', ['pipe_step._unmatched'], fallback === 'drop' ? '. = []' : `${field} = "unmatched"`);
    remap('pipe_join', [...routes.map((_, i) => `pipe_branch_${i}`), 'pipe_fallback'], '.');
    output = 'pipe_join';
    pieces.push('# Every retained branch continues to Nano Lake; fanout may produce multiple copies.');
  } else if (step.kind === 'lookup') {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(text(c, 'table')) || !text(c, 'version') || new TextEncoder().encode(text(c, 'version')).length > 128) throw new Error('Provide a lookup name and version.');
    const mapping = (key: string) => {
      const values = c[key];
      if (!values || typeof values !== 'object' || Array.isArray(values) || !Object.keys(values).length || Object.keys(values).length > 16) throw new Error(`${key} must map table columns to event fields.`);
      for (const [column, path] of Object.entries(values)) { if (!/^[A-Za-z0-9_]{1,64}$/.test(column)) throw new Error('Use plain lookup column names.'); vrlField(path); }
      return values as Record<string, string>;
    };
    const match = mapping('match'), outputs = mapping('outputs');
    if (!Array.isArray(c.rows) || !c.rows.length || c.rows.length > 1000) throw new Error('A lookup snapshot requires 1–1000 rows.');
    const columns = [...new Set([...Object.keys(match), ...Object.keys(outputs)])].sort(), seen = new Set<string>();
    for (const row of c.rows) {
      if (!row || typeof row !== 'object' || Array.isArray(row) || JSON.stringify(Object.keys(row).sort()) !== JSON.stringify(columns) || Object.values(row).some(value => typeof value !== 'string' || new TextEncoder().encode(value).length > 4096)) throw new Error('Lookup rows require exactly the mapped columns with bounded string values.');
      const identity = JSON.stringify(Object.keys(match).sort().map(key => row[key])); if (seen.has(identity)) throw new Error('Lookup match keys must be unique.'); seen.add(identity);
    }
    const missing = text(c, 'missing', 'leave'); if (!['leave', 'error'].includes(missing)) throw new Error('Lookup missing must be leave or error.');
    const entries = Object.entries(match).map(([column, path]) => `${JSON.stringify(column)}: to_string(${vrlField(path)}) ?? ""`).join(', ');
    const code = `nano_lookup, nano_lookup_error = get_enrichment_table_record("source_owned_lookup", { ${entries} }, case_sensitive: true)\n${missing === 'error' ? 'if nano_lookup_error != null { abort }\n' : ''}if nano_lookup_error == null {\n` + Object.entries(outputs).map(([column, path]) => `  ${vrlField(path)} = get!(nano_lookup, [${JSON.stringify(column)}])`).join('\n') + '\n}';
    pieces.push(`# Source-owned CSV snapshot ${JSON.stringify(c.table)} version ${JSON.stringify(c.version)}\n[enrichment_tables.source_owned_lookup]\ntype = "file"\nfile.path = "source_owned_snapshot.csv"\nfile.encoding.type = "csv"\nfile.encoding.include_headers = true`);
    remap('pipe_step', [input], code);
  } else {
    throw new Error('Not a native step.');
  }
  if (gate) { remap('pipe_bypass', [output, 'pipe_gate._unmatched'], '.'); output = 'pipe_bypass'; }
  pieces.push(`# Next processing step consumes ${JSON.stringify(output)}. Remap error ports use the existing parser-failure path.`);
  return pieces.join('\n\n');
}
export function executableSteps(draft: PipelineDraft) {
  return draft.steps.map((step, index) => ({ id: step.id, name: step.name, enabled: step.enabled, vrl: step.enabled ? serializePipeline({ ...draft, steps: draft.steps.slice(0, index + 1) }) : '' }));
}
export function compilePipeline(draft: PipelineDraft): string {
  return compileSequence(draft.steps.filter(step => step.enabled));
}
export function serializePipeline(draft: PipelineDraft): string {
  compilePipeline(draft); // Fail locally before submitting an invalid plan.
  return HEADER + JSON.stringify({ version: 2, revision: draft.revision, steps: draft.steps }) + '\n' + PLAN_BODY;
}

export function draftFromSource(source: LogSource, revision = 1): PipelineDraft {
  const firstNewline = source.parser_vrl.indexOf('\n');
  const header = source.parser_vrl.startsWith(HEADER) ? HEADER : LEGACY_HEADER;
  if (source.parser_vrl.startsWith(header) && firstNewline !== -1) {
    try {
      const meta = JSON.parse(source.parser_vrl.slice(header.length, firstNewline));
      if ((meta.version === 1 || meta.version === 2) && Number.isSafeInteger(meta.revision) && meta.revision > 0 && validStoredSteps(meta.steps)) {
        const draft = { name: source.name, description: source.description ?? '', revision: meta.revision, steps: meta.steps };
        if (meta.version === 2 && header === HEADER && source.parser_vrl.slice(firstNewline + 1) === PLAN_BODY) { compilePipeline(draft); return draft; }
        if (meta.version === 1 && compilePipeline(draft) === source.parser_vrl.slice(firstNewline + 1)) return draft;
      }
    } catch { /* Hand-edited metadata is treated as imported VRL. */ }
  }
  return { name: source.name, description: source.description ?? '', revision, steps: [{ id: 'imported-parser', name: 'Existing parser', kind: 'vrl', enabled: true, config: { code: source.parser_vrl || '.' } }] };
}
export function draftFingerprint(draft: PipelineDraft): string {
  return JSON.stringify(draft);
}
export function releaseFromRollout(rollout: TenantParserRollout): PipelineRelease {
  return {
    id: rollout.id, revision: rollout.version_numbers?.at(-1) ?? null, state: rollout.state,
    createdAt: rollout.requested_at, actor: rollout.requested_by,
    error: [rollout.failure_stage, rollout.failure_reason].filter(Boolean).join(': ') || undefined,
  };
}
export function summaryFromSource(source: LogSource, releases: PipelineRelease[] = []): PipelineSummary {
  const draft = draftFromSource(source);
  return {
    id: source.id, sourceId: source.id, name: source.name, description: source.description ?? '',
    sourceName: source.name, sourceType: source.source_type,
    activeRevision: releases.find((release) => release.state === 'live')?.revision ?? null,
    draftRevision: draft.revision, hasDraft: !source.deployed || !!source.deployed_at && source.updated_at > source.deployed_at,
    health: source.ingest?.health_status === 'healthy' ? 'healthy' : source.ingest ? 'warning' : 'unknown',
    latestRelease: releases[0] ?? null,
  };
}

/** Legacy release-test samples are raw message strings, not serialized events. */
export function rawMessageSamples(events: Array<{ input: unknown }>): string[] {
  return events.map(({ input }) => {
    if (input && typeof input === 'object' && 'message' in input && typeof input.message === 'string') return input.message;
    throw new Error('This event has no raw message string. Preview is available, but saving it as a legacy release-test sample would change its input shape.');
  });
}

/** In-memory editor recovery contains configuration only, never capture/sample state. */
export interface PipelineDraftRecovery {
  draft: PipelineDraft;
  savedFingerprint: string;
  sourceSnapshot: import('./api/pipelines').PipePublicationSnapshot;
}
export const pipelineDraftRecoveryKey = (runtimeKey: string, sourceId: string) => ['pipe-editor-draft', runtimeKey, sourceId] as const;
export function pipelineDraftRecovery(draft: PipelineDraft, savedFingerprint: string, sourceSnapshot: import('./api/pipelines').PipePublicationSnapshot): PipelineDraftRecovery {
  return {
    draft: structuredClone({ name: draft.name, description: draft.description, revision: draft.revision, steps: draft.steps }),
    savedFingerprint,
    sourceSnapshot: Object.freeze({ ...sourceSnapshot }),
  };
}

// NAN-3447: preview input loaded from stored events or pasted. Both build the
// same pre-parse shape a saved sample uses ({ message: <raw text>, source_type }),
// and both stay in browser memory only.
export const PASTE_MAX_EVENTS = 100;
const ROW_SOURCE_FIELD = 'metadata.log_source';

function rowField(row: Record<string, unknown>, path: string): unknown {
  if (path in row) return row[path];
  let value: unknown = row;
  for (const part of path.split('.')) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

/**
 * Search rows → preview inputs. Only rows that carry the original raw text are
 * kept (a row without it cannot reproduce pre-parse input); at most `plan.limit`
 * events and never more than one preview's 100-event bound.
 */
export function recentEventSamples(
  rows: Array<Record<string, unknown>>,
  plan: Pick<import('./api/pipelines').PipeRecentEventsPlan, 'limit' | 'raw_field' | 'source_labels'>,
): CapturedEvent[] {
  const limit = Math.max(0, Math.min(plan.limit, 100));
  const events: CapturedEvent[] = [];
  for (const row of rows) {
    if (events.length >= limit) break;
    const raw = rowField(row, plan.raw_field);
    if (typeof raw !== 'string' || raw.trim() === '') continue;
    const label = rowField(row, ROW_SOURCE_FIELD);
    const time = rowField(row, 'time') ?? rowField(row, 'timestamp');
    // NAN-3625: the stored, platform-stamped input identity of this row.
    const nanoInput = inputOfStamp(rowField(row, `metadata.${INPUT_METADATA}`));
    events.push({
      id: `recent-${events.length + 1}`,
      input: { message: raw, source_type: typeof label === 'string' && label ? label : plan.source_labels[0] },
      ...(typeof time === 'string' || typeof time === 'number' ? { capturedAt: String(time) } : {}),
      ...(nanoInput ? { nanoInput } : {}),
    });
  }
  return events;
}

/**
 * Pasted text → preview inputs. A JSON array yields one event per element
 * (strings verbatim, anything else as its JSON text); a single JSON object
 * (even pretty-printed) is one event; otherwise each non-empty line is one raw
 * event. A raw event that is itself a JSON array must be pasted with others,
 * one per line, or wrapped in an outer array.
 */
export function pastedSampleEvents(text: string, sourceType?: string): CapturedEvent[] {
  const trimmed = text.trim();
  if (!trimmed) throw new Error('Paste at least one raw event.');
  let raws: string[];
  let parsed: unknown;
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    try { parsed = JSON.parse(trimmed); } catch { parsed = undefined; }
  }
  if (Array.isArray(parsed)) {
    raws = parsed.map((item) => typeof item === 'string' ? item : JSON.stringify(item));
  } else if (parsed && typeof parsed === 'object') {
    raws = [JSON.stringify(parsed)];
  } else {
    raws = trimmed.split(/\r?\n/).filter((line) => line.trim() !== '');
  }
  if (!raws.length) throw new Error('Paste at least one raw event.');
  if (raws.length > PASTE_MAX_EVENTS) throw new Error(`Paste at most ${PASTE_MAX_EVENTS} events; preview evaluates up to ${PASTE_MAX_EVENTS} inputs.`);
  return raws.map((message, index) => ({ id: `pasted-${index + 1}`, input: { message, ...(sourceType ? { source_type: sourceType } : {}) } }));
}

/** Loaded and pasted samples are browser-only: never saved or attached to a release. */
export function ephemeralSample(sample: { origin?: string } | null | undefined): boolean {
  return sample?.origin === 'recent' || sample?.origin === 'pasted';
}

/** Per-step outcome of the last preview, for the collapsed step header. */
export interface PipelineStepStatus {
  /** Inputs whose trace reported an error at this step. */
  errors: number;
  /** Inputs whose event this step changed. */
  changed: number;
}

function sameJson(left: unknown, right: unknown): boolean {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

/**
 * NAN-3452: summarize a preview's per-step traces. Returns an empty map when
 * the preview is stale or carries no traces (large drafts run as one
 * program), so the step list shows nothing rather than a wrong count.
 */
export function stepPreviewStatus(
  preview: PipelinePreview | null | undefined,
): Record<string, PipelineStepStatus> {
  const status: Record<string, PipelineStepStatus> = Object.create(null);
  if (!preview || preview.stale) return status;
  for (const event of preview.events) {
    event.trace?.forEach((item, index) => {
      const entry = (status[item.stepId] ??= { errors: 0, changed: 0 });
      if (item.error) {
        entry.errors++;
        return;
      }
      const before =
        index === 0 ? [event.input] : event.trace![index - 1].outputs;
      if (!sameJson(before, item.outputs)) entry.changed++;
    });
  }
  return status;
}
