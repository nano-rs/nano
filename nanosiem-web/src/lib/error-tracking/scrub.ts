// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5798: secret scrubbing for Sentry payloads, plus the per-issue and
// per-session caps. Pure functions (no SDK import), bundled only into the
// lazy Sentry chunk. Mirrors nanosiem-core/src/error_tracking_scrub.rs.
//
// Sentry runs only in nano-operated environments (local, e2e, a few small
// nano-run tenants), never on customer installs. Payloads keep what makes
// them useful: messages, breadcrumbs (console included), URLs, span and
// transaction names, tags, contexts, stacks, fingerprints. Only SECRETS are
// removed, from every string and every secret-named field: Authorization /
// Cookie / Set-Cookie values, API keys and tokens (nit_, JWT, bearer,
// *_token / *_secret / password / api_key values, PEM), sensitive query
// values (token, key, secret, password, code, sig, ...), and URL userinfo
// (DSNs, connection strings).
import { redactText } from '@/lib/support-diagnostics';

/** Errors that are expected noise in a browser, never worth an issue. */
export const BENIGN_ERRORS: RegExp[] = [
  /ResizeObserver loop/i,
  /AbortError|signal is aborted|The user aborted a request/i,
  // A deploy replaced the chunks: RouteErrorBoundary reloads (stale-build.ts).
  /Failed to fetch dynamically imported module|Importing a module script failed|ChunkLoadError/i,
];

export const FILTERED = '[Filtered]';

const SENSITIVE_KEY =
  /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|dsn|jwt|bearer|.*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|session[_-]?id|licen[cs]e[_-]?key).*)$/i;

export const isSensitiveKey = (key: string): boolean => SENSITIVE_KEY.test(key);

/** Query parameter names whose value is a secret. */
const QUERY_KEY = /token|key|secret|password|passwd|pwd|code|sig|signature|auth|session|credential/i;

const RULES: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, FILTERED],
  // Header-shaped secrets: the whole value, every cookie included.
  // Plain (`Cookie: a=1; b=2`), quoted (`Cookie="..."`) and JSON (`{"Cookie": "..."}`) forms.
  [/\b((?:proxy-)?authorization|(?:set-)?cookie|x-api-key)(["']?\s*[:=]\s*)(?:"[^"]*"?|'[^']*'?|[^\r\n"']*)/gi, `$1$2${FILTERED}`],
  // DSNs and connection strings: any URL userinfo (to the last `@` before the path).
  [/\b([a-z][a-z0-9+.-]*:\/\/)[^/\s]*@/gi, `$1${FILTERED}@`],
  // Query-string values of sensitive keys.
  [/([?&;][A-Za-z0-9_.-]*(?:token|key|secret|password|passwd|pwd|code|sig|signature|auth|session|credential)[A-Za-z0-9_.-]*=)[^&#\s"']*/gi,
    `$1${FILTERED}`],
  [/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, `$1 ${FILTERED}`],
  // key=value whose key names a secret (access_token, client_secret, api_key, password, ...).
  [/\b([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|session[_-]?id|jwt|dsn|licen[cs]e[_-]?key))(["']?\s*[=:]\s*)(?:"[^"]*"?|'[^']*'?|[^\s"'&,;}]+)/gi,
    `$1$2${FILTERED}`],
  [/\bnit_[A-Za-z0-9_-]{8,}/g, FILTERED],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, FILTERED],
];

/** `text` with secrets masked; everything else unchanged. */
export function scrubText(text: string): string {
  let out = redactText(text);
  for (const [rx, rep] of RULES) out = out.replace(rx, rep);
  return out;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Deep copy with secret-named fields filtered and every string scrubbed. */
export function scrubValue<T>(value: T, depth = 0): T {
  if (typeof value === 'string') return scrubText(value) as T;
  if (depth > 12 || value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, depth + 1)) as T;
  const out: Obj = {};
  for (const [k, v] of Object.entries(value as Obj)) {
    out[k] = isSensitiveKey(k) ? FILTERED : scrubValue(v, depth + 1);
  }
  return out as T;
}

/** FNV-1a 64-bit, hex: an opaque, stable id for a user. */
export function hashedUserId(raw: string): string {
  let h = 0xcbf29ce484222325n;
  for (const byte of new TextEncoder().encode(`nano-sentry-user:${raw}`)) {
    h ^= BigInt(byte);
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

export interface Crumb { message?: string; data?: Obj; category?: string; level?: string; type?: string; timestamp?: number }

export function scrubCrumb<T extends Crumb>(crumb: T): T {
  return scrubValue(crumb);
}

export type SentryPayload = Obj;

/** An event or transaction with secrets removed (and no cookies or user IP). */
export function scrubPayload<T extends SentryPayload>(event: T): T {
  const out = scrubValue(event) as Obj;
  if (isObj(out.request)) {
    delete out.request.cookies;
    // Sentry stores query_string without its `?` (string) or as [key, value]
    // pairs; the query rule needs a leading separator.
    const qs = (event.request as Obj | undefined)?.query_string;
    if (typeof qs === 'string') {
      out.request.query_string = scrubText(`?${qs}`).slice(1);
    } else if (Array.isArray(qs)) {
      out.request.query_string = qs.map((pair) => {
        if (!Array.isArray(pair) || typeof pair[0] !== 'string') return scrubValue(pair);
        const [k, v] = pair as [string, unknown];
        const sensitive = isSensitiveKey(k) || QUERY_KEY.test(k);
        return [k, sensitive ? FILTERED : typeof v === 'string' ? scrubText(v) : v];
      });
    }
  }
  if (isObj(out.user)) {
    delete out.user.ip_address;
  }
  return out as T;
}

export interface LogLike { message: unknown; attributes?: Obj; [k: string]: unknown }

export function scrubLog<T extends LogLike>(log: T): T {
  return scrubValue(log);
}

/** CSS selectors masked and blocked in error-only Sentry Replays. */
export const REPLAY_MASK_SELECTORS: readonly string[] = [
  '[data-secret]',
  'input[type="password"]',
  '[data-testid*="token"]',
  '[data-testid*="secret"]',
];

/** Scrub secrets from Sentry Replay recording events (console, navigation, network breadcrumbs). */
export function scrubReplayRecordingEvent<T>(event: T): T {
  return scrubValue(event);
}

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);

export function eventText(event: SentryPayload): string {
  const parts = [str(event.message) ?? ''];
  const values = isObj(event.exception) && Array.isArray(event.exception.values) ? event.exception.values : [];
  for (const exc of values) if (isObj(exc)) parts.push(`${str(exc.type) ?? ''}: ${str(exc.value) ?? ''}`);
  return parts.join('\n');
}

/** Numbers, hex runs and UUIDs collapsed, so `job 12` and `job 13` are one issue. */
export function normalizeMessage(message: string): string {
  return message
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '#')
    .replace(/\b[0-9a-f]{8,}\b|\d+/gi, '#');
}

export function issueKey(event: SentryPayload): string {
  const values = isObj(event.exception) && Array.isArray(event.exception.values) ? (event.exception.values as Obj[]) : [];
  if (values.length === 0) return `m:${normalizeMessage(str(event.message) ?? '')}`;
  return values.map((v) => `${str(v.type) ?? ''}:${normalizeMessage(str(v.value) ?? '')}`).join('|');
}

/** Counter storage: sessionStorage, so a reload loop shares one budget. */
export interface CounterStore {
  get(key: string): number;
  set(key: string, value: number): void;
}

export function sessionCounterStore(prefix = 'nano.sentry.'): CounterStore {
  const memory = new Map<string, number>();
  return {
    get(key) {
      try {
        const v = window.sessionStorage.getItem(prefix + key);
        if (v !== null) return Number(v) || 0;
      } catch { /* storage blocked: memory only */ }
      return memory.get(key) ?? 0;
    },
    set(key, value) {
      memory.set(key, value);
      try { window.sessionStorage.setItem(prefix + key, String(value)); } catch { /* memory only */ }
    },
  };
}

export function memoryCounterStore(): CounterStore {
  const m = new Map<string, number>();
  return { get: (k) => m.get(k) ?? 0, set: (k, v) => { m.set(k, v); } };
}

export const DEFAULT_MAX_REPLAYS = 3;

export interface GateOptions {
  maxPerIssue: number;
  maxEvents: number;
  maxTransactions: number;
  maxLogs: number;
  maxReplays?: number;
  tags: () => Record<string, string>;
  store: CounterStore;
}

/** The before-send pipeline: benign filter, per-issue + per-session caps, secret scrub, run tags. */
export function createGate(opts: GateOptions) {
  // Issue counts stay in memory; the session totals persist across reloads.
  const perIssue = new Map<string, number>();
  const maxReplays = opts.maxReplays ?? DEFAULT_MAX_REPLAYS;
  const bump = (key: string, max: number) => {
    const n = opts.store.get(key);
    if (n >= max) return false;
    opts.store.set(key, n + 1);
    return true;
  };
  const tag = <T extends SentryPayload>(e: T): T => {
    (e as Obj).tags = { ...((e.tags as Obj | undefined) ?? {}), ...opts.tags() };
    return e;
  };
  return {
    event<T extends SentryPayload>(event: T): T | null {
      if (BENIGN_ERRORS.some((rx) => rx.test(eventText(event)))) return null;
      const key = issueKey(event);
      const seen = perIssue.get(key) ?? 0;
      if (seen >= opts.maxPerIssue) return null;
      if (!bump('events', opts.maxEvents)) return null;
      perIssue.set(key, seen + 1);
      return tag(scrubPayload(event));
    },
    transaction<T extends SentryPayload>(tx: T): T | null {
      if (!bump('transactions', opts.maxTransactions)) return null;
      return tag(scrubPayload(tx));
    },
    log<T extends LogLike>(log: T): T | null {
      if (!bump('logs', opts.maxLogs)) return null;
      const clean = scrubLog(log);
      clean.attributes = { ...(clean.attributes ?? {}), ...opts.tags() };
      return clean;
    },
    replay(event?: SentryPayload): boolean {
      if (event && BENIGN_ERRORS.some((rx) => rx.test(eventText(event)))) return false;
      return bump('replays', maxReplays);
    },
  };
}
