// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5571: the page ↔ pivt contract.
//
// A page registers, while mounted, what pivt may know about it (a compact,
// serialisable context read from data the page already holds) and what pivt
// may do on it (actions that call the normal REST client as the user). The
// pivt panel reads the registration when it opens (Here card) and when the
// analyst sends a message; nothing is fetched and no AI runs until then.
//
// This file is open-core on purpose: most pages are. It holds types and an
// inert module store only. Executing actions, confirmation cards and the chat
// wiring live in `enterprise/components/pivt/actions/`; without pivt a
// registration is never read.
//
// Rules for action specs (enforced by the enterprise executor and its tests):
// - `run` calls the REST client only, never an AI or a privileged path.
// - `mutates: true` actions run only after the analyst confirms a card.
// - Queries an action shows or runs are nPL (machines → SQL, humans → nPL).
//
// STABLE CONTRACT: `usePivtPage` and the shapes below are shared with other
// programs (hunts M7). Extend with optional fields; don't rename or remove.
import { useEffect, useLayoutEffect, useRef } from 'react';
import { usePageContext, useHereCardOverride, type HereCardData } from './PageContext';

// ── Context ──────────────────────────────────────────────────────────────

export interface PivtPageEntity {
  /** e.g. `rule`, `alert`, `hunt_lead`, `log_source`. */
  kind: string;
  id: string;
  name?: string;
}

/** What pivt may know about the page. Read only from data the page already
    holds (React Query cache, URL, local state). */
export interface PivtPageContext {
  /** Defaults to the route's pageKey. */
  pageKey?: string;
  /** One line, e.g. "Rule · Kerberoasting from non-service accounts". */
  title: string;
  entity?: PivtPageEntity;
  /** Label → value facts; also the Here card lines. Keep values short. */
  facts?: Array<{ label: string; value: string }>;
  /** What the analyst has selected on the page. */
  selection?: { kind: string; ids: string[] };
  /** Page-specific extras (e.g. the current nPL query, visible counts). */
  data?: Record<string, unknown>;
}

// ── Actions ──────────────────────────────────────────────────────────────

export interface PivtParamSpec {
  type: 'string' | 'number' | 'boolean' | 'enum';
  description: string;
  required?: boolean;
  /** For `enum`. */
  values?: string[];
  /** For `string` (default 2000). */
  maxLength?: number;
}

export type PivtParamSchema = Record<string, PivtParamSpec>;

export interface PivtActionPreview {
  /** One sentence: what Apply will do. */
  summary: string;
  /** Label → value rows (ids in mono). */
  rows?: Array<[string, string]>;
  /** Before → after, for edits. */
  diff?: { before: string; after: string; lang?: string };
}

export interface PivtActionResult {
  summary: string;
  /** In-app route to the result. */
  href?: string;
}

export interface PivtActionSpec<P = Record<string, unknown>> {
  /** `area.verb`, e.g. `search.save`, `rules.set_mode`. */
  name: string;
  /** One line for the model: when to propose it. */
  description: string;
  params: PivtParamSchema;
  /** All of these, as the REST route enforces them. */
  permission: string | string[];
  /** Changes state → confirmation card before `run`. */
  mutates: boolean;
  /**
   * NAN-5637: a check beyond `permission`, e.g. ownership ("the server
   * accepts this save only from the owner or an admin"). `false` withholds
   * the action exactly like a missing permission: it is not offered, a card
   * for it does not resolve, and pivt refuses a request for it instead of
   * redirecting to an editor. Optional; absent means available.
   */
  available?: () => boolean;
  /**
   * Freeze the page state the action depends on into its params, once, when
   * the card first shows. `preview` and `run` then both receive the frozen
   * params, so Apply does exactly what the card showed even if the page has
   * changed since (e.g. the analyst ran another query). Optional.
   */
  bind?: (params: P) => P;
  /** What a confirmation card shows. Required when `mutates`. */
  preview?: (params: P) => PivtActionPreview | Promise<PivtActionPreview>;
  /** Calls the REST client as the user. */
  run: (params: P) => Promise<PivtActionResult>;
}

/** Thrown by a spec's `bind` to refuse a target with a message written for
    the analyst (e.g. "Alert X is not on this page."). Any other error shows
    a generic message. */
export class PivtRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PivtRefusal';
  }
}

/** Helper that keeps `P` typed at the definition site. */
export function definePivtAction<P>(spec: PivtActionSpec<P>): PivtActionSpec {
  return spec as unknown as PivtActionSpec;
}

// ── Registration ─────────────────────────────────────────────────────────

export interface PivtPageRegistration {
  /** The context, computed on demand. Must be cheap and side-effect free. */
  getContext: () => PivtPageContext;
  actions?: PivtActionSpec[];
  /** Here card chips. */
  suggestions?: string[];
  /** Here card icon (Lucide name or `pivt`). */
  icon?: string;
}

interface Registered {
  /** Route pageKey at registration; a stale registration is never read. */
  routeKey: string;
  reg: { current: PivtPageRegistration };
}

let registered: Registered | null = null;

/** The current page's registration, if it belongs to `routeKey`. */
export function readPivtPage(routeKey: string): PivtPageRegistration | null {
  return registered && registered.routeKey === routeKey ? registered.reg.current : null;
}

/** Test seam. */
export function clearPivtPageRegistration() {
  registered = null;
}

function hereCardFrom(ctx: PivtPageContext, suggestions?: string[], icon?: string): HereCardData {
  return {
    icon,
    title: ctx.title,
    lines: ctx.facts?.slice(0, 6),
    suggestions,
  };
}

/**
 * Register the page with pivt while it is mounted. Call it from a route page
 * component (like `useHereCardOverride`). `getContext` is called during render
 * for the Here card, so it must read only data the page already has.
 *
 * ```tsx
 * usePivtPage({
 *   getContext: () => ({ title: `Rule · ${rule.name}`, entity: { kind: 'rule', id: rule.id }, facts }),
 *   actions: [setModeAction(rule)],
 *   suggestions: ['Why is this rule noisy?'],
 * });
 * ```
 */
export function usePivtPage(registration: PivtPageRegistration): void {
  const { pageKey } = usePageContext();
  const ref = useRef(registration);
  // Committed renders only (an abandoned concurrent render never publishes).
  useLayoutEffect(() => {
    ref.current = registration;
  });

  useEffect(() => {
    const entry: Registered = { routeKey: pageKey, reg: ref };
    registered = entry;
    return () => {
      if (registered === entry) registered = null;
    };
  }, [pageKey]);

  // The Here card is a projection of the same context: one source of truth.
  // Title and facts only (cheap); a page bug must not break the page.
  let card: HereCardData | null = null;
  try {
    const ctx = registration.getContext();
    card = hereCardFrom(
      { title: ctx.title.slice(0, 160), facts: ctx.facts?.slice(0, 6).map((f) => ({ label: f.label.slice(0, 40), value: f.value.slice(0, 200) })) },
      registration.suggestions,
      registration.icon,
    );
  } catch {
    card = null;
  }
  useHereCardOverride(card);
}

// ── Size cap ─────────────────────────────────────────────────────────────

export const PAGE_CONTEXT_MAX_BYTES = 8 * 1024;
const MAX_STRING = 512;
const MAX_ARRAY = 20;
const MAX_DEPTH = 4;

function clip(value: unknown, depth: number, cut: { hit: boolean }): unknown {
  if (typeof value === 'string') {
    if (value.length <= MAX_STRING) return value;
    cut.hit = true;
    return `${value.slice(0, MAX_STRING)}…`;
  }
  if (typeof value === 'number' || typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) {
    if (depth >= MAX_DEPTH) {
      cut.hit = true;
      return [];
    }
    if (value.length > MAX_ARRAY) cut.hit = true;
    return value.slice(0, MAX_ARRAY).map((v) => clip(v, depth + 1, cut));
  }
  if (typeof value === 'object' && value !== undefined) {
    if (depth >= MAX_DEPTH) {
      cut.hit = true;
      return {};
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v === undefined || typeof v === 'function') continue;
      out[k.slice(0, 64)] = clip(v, depth + 1, cut);
    }
    return out;
  }
  // functions, symbols, bigint, undefined: not serialisable context
  return undefined;
}

const bytes = (v: unknown) => new TextEncoder().encode(JSON.stringify(v)).length;

/**
 * Bound a context for the wire: strings ≤ 512 chars, arrays ≤ 20 items,
 * depth ≤ 4, whole payload ≤ 8 KB (then `data`, then `selection`, then extra
 * `facts` are dropped). `truncated` tells the model it saw a partial view.
 * The server enforces its own cap; the client isn't trusted.
 */
export function capPageContext(ctx: PivtPageContext): { context: PivtPageContext; truncated: boolean } {
  const cut = { hit: false };
  const context = clip(ctx, 0, cut) as PivtPageContext;
  if (bytes(context) > PAGE_CONTEXT_MAX_BYTES) {
    cut.hit = true;
    delete context.data;
  }
  if (bytes(context) > PAGE_CONTEXT_MAX_BYTES) delete context.selection;
  while (bytes(context) > PAGE_CONTEXT_MAX_BYTES && context.facts && context.facts.length > 0) {
    context.facts = context.facts.slice(0, -1);
  }
  if (bytes(context) > PAGE_CONTEXT_MAX_BYTES) {
    context.title = context.title.slice(0, 120);
    delete context.entity;
  }
  return { context, truncated: cut.hit };
}
