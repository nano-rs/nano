// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4660 — the AI judge step's authoring rules, mirrored from the server
 * validator (enterprise SOAR backend, soar/flow/judge.rs `validate_definition`,
 * `reference_path`, `PlannedJudge::compile`; module shape in spec.rs
 * `ModuleValue::Judge`). Pure: no imports, so the flow model and the field
 * catalog can both use it without an import cycle.
 *
 * Module fields (deny_unknown_fields): type, question, evidence, labels,
 * token_cap (default 2000), cache_ttl (default "6h"), optional entity.
 */

export const JUDGE = {
  questionBytes: 2048,
  /** Server allows 1; the editor asks for 2 because `unknown` is always the fallback. */
  minLabels: 2,
  maxLabels: 32,
  labelBytes: 64,
  minEvidence: 1,
  maxEvidence: 32,
  tokenCap: { min: 1, max: 8000, default: 2000 },
  ttlSecs: { min: 1, max: 86_400 },
  defaultTtl: '6h',
} as const;

/** Keys the server's `ModuleValue::Judge` accepts. */
export const JUDGE_KEYS = ['type', 'question', 'evidence', 'labels', 'token_cap', 'cache_ttl', 'entity'] as const;

/** Cache TTL presets the inspector offers (all in the server's `<n>s` / `<n>h` form). */
export const TTL_PRESETS: Array<[string, string]> = [
  ['300s', '5 minutes'],
  ['1h', '1 hour'],
  ['6h', '6 hours'],
  ['12h', '12 hours'],
  ['24h', '24 hours'],
];

const bytes = (s: string) => new TextEncoder().encode(s).length;

/** Seconds for a server-format TTL (`6h`, `90s`), or null when the server refuses it. */
export function ttlSecs(ttl: string): number | null {
  const m = /^(\d+)([hs])$/.exec(ttl);
  if (!m) return null;
  const n = Number(m[1]) * (m[2] === 'h' ? 3600 : 1);
  return Number.isSafeInteger(n) && n >= JUDGE.ttlSecs.min && n <= JUDGE.ttlSecs.max ? n : null;
}

/** Why a single label is refused, or null. `others` are the labels it must not duplicate. */
export function labelProblem(label: string, others: readonly string[] = []): string | null {
  if (!label) return 'Label cannot be empty.';
  if (bytes(label) > JUDGE.labelBytes) return `Label is longer than ${JUDGE.labelBytes} characters.`;
  if (!/^[A-Za-z0-9_-]+$/.test(label)) return 'Use letters, digits, _ or - only.';
  if (label.toLowerCase() === 'unknown') return '"unknown" is reserved; it is always the fallback verdict.';
  if (others.some((o) => o.toLowerCase() === label.toLowerCase())) return `"${label}" is already a label.`;
  return null;
}

/**
 * The full scope path a judge evidence/entity reference names (server
 * `reference_path`): `{{…}}` stripped, `alert.x` → `flow_input.alert.x`,
 * `steps.x` → `results.x`. Null when the server would refuse the path.
 */
export function evidencePath(reference: string): string | null {
  let r = reference.trim();
  if (r.startsWith('{{') && r.endsWith('}}')) r = r.slice(2, -2).trim();
  const path = r.startsWith('alert.') ? `flow_input.${r}` : r.startsWith('steps.') ? `results.${r.slice('steps.'.length)}` : r;
  if (path.length > 1024) return null;
  const parts = path.split('.');
  if (parts.some((p) => !/^[A-Za-z0-9_]+$/.test(p))) return null;
  return ['flow_input', 'results', 'run'].includes(parts[0]) ? path : null;
}

const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
export const judgeLabels = (v: Record<string, unknown>) => strs(v.labels);
export const judgeEvidence = (v: Record<string, unknown>) => strs(v.evidence);

/** Definition checks (no scope): the editor's inline findings for one judge module value. */
export function judgeErrors(v: Record<string, unknown>): string[] {
  const e: string[] = [];
  const q = typeof v.question === 'string' ? v.question : '';
  if (!q.trim()) e.push('Question is required');
  else if (bytes(q) > JUDGE.questionBytes) e.push(`Question is longer than ${JUDGE.questionBytes} bytes`);
  else if (q.includes('\0')) e.push('Question contains a NUL character');

  const labels = judgeLabels(v);
  if (labels.length < JUDGE.minLabels) e.push(`At least ${JUDGE.minLabels} labels are required`);
  else if (labels.length > JUDGE.maxLabels) e.push(`At most ${JUDGE.maxLabels} labels`);
  labels.forEach((l, i) => {
    const p = labelProblem(l, labels.slice(0, i));
    if (p) e.push(`Label ${l || `#${i + 1}`}: ${p.replace(/\.$/, '')}`);
  });

  const ev = judgeEvidence(v);
  if (ev.length < JUDGE.minEvidence) e.push('Pick at least one evidence field');
  else if (ev.length > JUDGE.maxEvidence) e.push(`At most ${JUDGE.maxEvidence} evidence fields`);
  for (const r of ev) if (!evidencePath(r)) e.push(`Evidence ${r} is not a flow scope path`);

  const cap = v.token_cap ?? JUDGE.tokenCap.default;
  if (typeof cap !== 'number' || !Number.isInteger(cap) || cap < JUDGE.tokenCap.min || cap > JUDGE.tokenCap.max) e.push(`Token cap must be a whole number from ${JUDGE.tokenCap.min} to ${JUDGE.tokenCap.max}`);

  const ttl = v.cache_ttl ?? JUDGE.defaultTtl;
  if (typeof ttl !== 'string' || ttlSecs(ttl) === null) e.push('Cache TTL must be seconds (90s) or hours (6h), at most 24h');
  return e;
}
