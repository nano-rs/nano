// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — view models for the case automation wall, the verb palette and
 * the Run action sheet (mock soar3-case.jsx / soar-run-action.jsx).
 */
import type { SoarCatalog, SoarCatalogAction, SoarCatalogPack, SoarConnection } from '@/lib/api/soar';
import { asEffect, entityKindForInput, type Effect, type EntityKind } from './soar-model';

// ── Verb palette ────────────────────────────────────────────────────────

export interface PaletteItem {
  pack: SoarCatalogPack;
  action: SoarCatalogAction;
  /** Input the entity value prefills. */
  input: string;
  effect: Effect | null;
  /** Preferred connection (ready first). */
  connection: SoarConnection | null;
  /** Why it cannot be requested now, or null. */
  why: string | null;
}

const EFFECT_ORDER: Record<string, number> = { read: 0, write: 1, destructive: 2 };

/**
 * Every catalog action whose declared input accepts this entity kind,
 * including packs that are not installed (shown disabled, as in the mock).
 */
export function paletteItems(
  kind: EntityKind,
  catalog: SoarCatalog | undefined,
  connections: SoarConnection[],
  ctx: { canRun: boolean; demo: boolean },
): PaletteItem[] {
  const out: PaletteItem[] = [];
  for (const pack of catalog?.packs ?? []) {
    for (const action of pack.actions) {
      const input = action.inputs.find((i) => entityKindForInput(i.name, i.type) === kind);
      if (!input) continue;
      const conns = connections.filter((c) => c.pack_name === pack.name);
      const connection = conns.find((c) => c.ready) ?? conns[0] ?? null;
      const why = ctx.demo
        ? 'Read-only demo'
        : !ctx.canRun
          ? 'Requires soar:run'
          : pack.withdrawn
            ? 'Release withdrawn'
            : !pack.installed
              ? 'Pack not installed'
              : !pack.enabled
                ? 'Pack disabled'
                : !connection
                  ? 'No connection'
                  : null;
      out.push({ pack, action, input: input.name, effect: asEffect(action.effect), connection, why });
    }
  }
  return out.sort(
    (a, b) =>
      Number(!!a.why) - Number(!!b.why) ||
      (EFFECT_ORDER[a.action.effect] ?? 3) - (EFFECT_ORDER[b.action.effect] ?? 3) ||
      a.action.display_name.localeCompare(b.action.display_name),
  );
}

// ── Run action form ─────────────────────────────────────────────────────

export const TYPE_RULES: Record<string, [RegExp, string]> = {
  ip: [/^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i, 'Enter an IPv4 or IPv6 address.'],
  domain: [/^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/i, 'Enter a domain like example.com.'],
  hash: [/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i, 'Enter an MD5, SHA-1 or SHA-256 hex hash.'],
  url: [/^https?:\/\/\S+$/i, 'Enter a full http(s) URL.'],
  email: [/^[^@\s]+@[^@\s]+\.[^@\s]+$/, 'Enter an email address.'],
  integer: [/^-?\d+$/, 'Enter a whole number.'],
};

export const TYPE_HINT: Record<string, string> = {
  ip: 'IPv4 or IPv6',
  domain: 'domain',
  hash: 'MD5 · SHA-1 · SHA-256',
  url: 'http(s) URL',
  email: 'email',
  integer: 'integer',
  number: 'number',
  array: 'comma separated',
  'string[]': 'comma separated',
};

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Field errors keyed by input name; `_alt` for an unmet require_one_of group. */
export function validateInputs(
  action: SoarCatalogAction,
  values: Record<string, string>,
  caseId: string,
): Record<string, string> {
  const e: Record<string, string> = {};
  const alt = new Set(action.require_one_of.flat());
  for (const i of action.inputs) {
    const v = values[i.name]?.trim() ?? '';
    if (!v) {
      if (i.required && !alt.has(i.name) && i.type !== 'boolean') e[i.name] = `${i.name} is required.`;
      continue;
    }
    const rule = TYPE_RULES[i.type];
    if (rule && !rule[0].test(v)) e[i.name] = rule[1];
    else if (i.pattern) {
      try {
        if (!new RegExp(i.pattern).test(v)) e[i.name] = `${i.name} does not match the expected format.`;
      } catch {
        /* server re-validates */
      }
    }
  }
  const unmet = action.require_one_of.filter((g) => !g.some((n) => values[n]?.trim()));
  if (unmet.length) e._alt = `Provide ${unmet.map((g) => g.join(' or ')).join('; ')}.`;
  if (caseId.trim() && !UUID_RE.test(caseId.trim())) e._case = 'Enter a case ID (UUID).';
  return e;
}

export function coerceInput(type: string, raw: string): unknown {
  const value = raw.trim();
  if (type === 'integer' || type === 'number') {
    const n = Number(value);
    return Number.isFinite(n) ? n : value;
  }
  if (type === 'boolean') return value === 'true';
  if (type === 'array' || type === 'string[]') return value.split(',').map((s) => s.trim()).filter(Boolean);
  return value;
}

/** Mock "Approval:" line, from the catalog's declared policy. */
export function approvalPolicyText(action: SoarCatalogAction): string {
  if (action.approval_forced) return 'Always required';
  if (action.approval_required) return 'Required by default · flows may allow automatic approval';
  return 'Not required for users · required for AI requests';
}

export function rollbackAction(pack: SoarCatalogPack | undefined, action: SoarCatalogAction | undefined) {
  if (!pack || !action?.rollback) return undefined;
  return pack.actions.find((a) => a.name === action.rollback);
}

/** First target-like value of the form (alt group first, then required inputs). */
export function formTarget(action: SoarCatalogAction | undefined, values: Record<string, string>) {
  if (!action) return undefined;
  const alt = new Set(action.require_one_of.flat());
  const order = [...action.inputs.filter((i) => alt.has(i.name)), ...action.inputs.filter((i) => !alt.has(i.name) && i.required)];
  for (const i of order) {
    const v = values[i.name]?.trim();
    if (v) return { name: i.name, value: v, kind: entityKindForInput(i.name, i.type) };
  }
  return undefined;
}

/** HH:MM of an ISO timestamp, UTC. */
export function hhmm(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toISOString().slice(11, 16);
}

/** Display form of a long entity value (hashes): head…tail, full value in the title. */
export function shortValue(value: string, max = 24): string {
  return value.length > max && /^[a-f0-9]+$/i.test(value) ? `${value.slice(0, 4)}…${value.slice(-4)}` : value;
}
