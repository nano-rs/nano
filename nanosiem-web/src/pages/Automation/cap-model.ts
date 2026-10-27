// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — Capabilities view model (mock soar3-cap.jsx), derived from the
 * real catalog + connections. The mock hard-codes its verb palette; here a
 * cell is every catalog action whose verb (verbOf) and target input kind
 * (entityKindForInput) land on that entity × verb.
 */
import type { SoarCatalog, SoarCatalogAction, SoarCatalogPack, SoarConnection } from '@/lib/api/soar';
import { asEffect, entityKindForInput, packState, verbOf, type Effect, type EntityKind, type PackState } from './soar-model';

/** Columns, in the mock's order. */
export const CAP_VERBS = ['Look up', 'Hunt', 'Contain', 'Block', 'Suspend', 'Revoke sessions', 'Add IOC'] as const;
export type CapVerb = (typeof CAP_VERBS)[number];
export const CAP_ROWS: Array<[EntityKind, string]> = [
  ['host', 'Host'], ['user', 'User'], ['ip', 'IP'], ['hash', 'File hash'], ['domain', 'Domain'], ['url', 'URL'],
];

/**
 * Entity × verb pairs that are meaningful. A meaningful pair with no provider
 * is a "gap"; anything else with no provider is "not a supported combination".
 */
const MEANINGFUL: Record<CapVerb, EntityKind[]> = {
  'Look up': ['host', 'user', 'ip', 'hash', 'domain', 'url'],
  Hunt: ['host'],
  Contain: ['host', 'user'],
  Block: ['ip', 'domain', 'url'],
  Suspend: ['user'],
  'Revoke sessions': ['user'],
  'Add IOC': ['ip', 'hash', 'domain'],
};
/** Read-only enrichment verbs fold into Look up. */
const VERB_GROUP: Record<string, CapVerb> = { Scan: 'Look up' };

export function capVerb(action: SoarCatalogAction): CapVerb | null {
  const v = verbOf(action.name, action.display_name);
  const g = (VERB_GROUP[v] ?? v) as CapVerb;
  return (CAP_VERBS as readonly string[]).includes(g) ? g : null;
}

export function actionTarget(action: SoarCatalogAction): EntityKind | null {
  for (const i of action.inputs) {
    const k = entityKindForInput(i.name, i.type);
    if (k === 'email') return 'user';
    if (k !== 'value') return k;
  }
  return null;
}

export type ProviderState = 'live' | 'noconn' | 'available' | 'disabled' | 'withdrawn';
export function providerState(pack: SoarCatalogPack, connections: SoarConnection[] | undefined): ProviderState {
  const s: PackState = packState(pack);
  if (s === 'withdrawn') return 'withdrawn';
  if (s === 'disabled') return 'disabled';
  if (s === 'available') return 'available';
  return connections?.some((c) => c.pack_name === pack.name) ? 'live' : 'noconn';
}

export interface Provider {
  pack: SoarCatalogPack;
  action: SoarCatalogAction;
  effect: Effect | null;
  st: ProviderState;
  inverse: SoarCatalogAction | string | null;
}

export function inverseOf(pack: SoarCatalogPack, action: SoarCatalogAction): SoarCatalogAction | string | null {
  if (!action.rollback) return null;
  return pack.actions.find((a) => a.name === action.rollback) ?? action.rollback;
}
export function inverseLabel(inv: SoarCatalogAction | string | null): string | null {
  if (!inv) return null;
  return typeof inv === 'string' ? inv : inv.display_name;
}

export function cellProviders(t: EntityKind, verb: CapVerb, catalog: SoarCatalog | undefined, connections: SoarConnection[] | undefined): Provider[] {
  const out: Provider[] = [];
  for (const pack of catalog?.packs ?? []) {
    for (const action of pack.actions) {
      if (capVerb(action) !== verb || actionTarget(action) !== t) continue;
      out.push({ pack, action, effect: asEffect(action.effect), st: providerState(pack, connections), inverse: inverseOf(pack, action) });
    }
  }
  const rank: Record<ProviderState, number> = { live: 0, noconn: 1, available: 2, disabled: 3, withdrawn: 4 };
  return out.sort((a, b) => rank[a.st] - rank[b.st]);
}

export function isGap(t: EntityKind, verb: CapVerb, providers: Provider[]): boolean {
  return providers.length === 0 && MEANINGFUL[verb].includes(t);
}

export function capSummary(catalog: SoarCatalog | undefined, connections: SoarConnection[] | undefined) {
  let live = 0;
  let gaps = 0;
  for (const [t] of CAP_ROWS) {
    for (const v of CAP_VERBS) {
      const p = cellProviders(t, v, catalog, connections);
      if (p.some((x) => x.st === 'live')) live++;
      if (isGap(t, v, p)) gaps++;
    }
  }
  return { live, gaps, installed: (catalog?.packs ?? []).filter((p) => p.installed).length };
}

/** Effective approval policy, in the mock's wording. */
export function approvalText(a: SoarCatalogAction): string {
  if (a.approval_forced) return 'Always required';
  if (a.approval_required) return 'Required by default · flows may allow automatic approval';
  return 'Not required for users · required for AI requests';
}

/** The version the catalog offers (none once a release is withdrawn). */
export function availableVersion(p: SoarCatalogPack): string | null {
  if (p.withdrawn) return null;
  return p.upstream_version ?? p.version ?? null;
}

// ── Connection tests ────────────────────────────────────────────────────

export type TestState = 'passed' | 'testfailed' | 'untested';
export function testState(status: string | null | undefined): TestState {
  if (!status) return 'untested';
  return /^(ok|pass|passed|succeeded|success)$/i.test(status) ? 'passed' : 'testfailed';
}

export function relAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const ms = now - Date.parse(iso);
  if (!Number.isFinite(ms)) return '—';
  if (ms < 60_000) return 'just now';
  const m = Math.floor(ms / 60_000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** Pack has something a connection can hold (settings or credentials). */
export function packConnectable(p: SoarCatalogPack | undefined): boolean {
  return !!p && ((p.config_fields?.length ?? 0) > 0 || (p.credential_fields?.length ?? 0) > 0);
}

/** Installed, enabled packs a new connection can be made for. */
export function connectablePacks(catalog: SoarCatalog | undefined): SoarCatalogPack[] {
  return (catalog?.packs ?? []).filter((p) => p.installed && p.enabled && !p.withdrawn && packConnectable(p));
}

export function packCategories(catalog: SoarCatalog | undefined): string[] {
  return [...new Set((catalog?.packs ?? []).flatMap((p) => p.categories))];
}
