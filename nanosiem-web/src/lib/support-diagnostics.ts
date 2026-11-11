// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5253: client-side context for Help > Report a bug / Get support.
 *
 * Records, in memory only, the last failed API calls (method, path, status,
 * request ID; never bodies, query strings or headers other than the request ID)
 * and the last console errors (redacted, trimmed). Nothing here sends anything
 * anywhere: the support dialog formats a report the user copies, downloads or
 * emails themselves.
 */

export const MAX_FAILED_CALLS = 20;
export const MAX_CONSOLE_ERRORS = 20;
const MAX_ERROR_CHARS = 300;

export const SUPPORT_EMAIL = 'support@nano.rs';
export const SUPPORT_BUNDLE_COMMANDS = {
  compose: 'cd ~/nano && scripts/nano support-bundle',
  helm: 'python3 nano/scripts/nano-support-bundle --kubernetes --namespace nano --release nano',
} as const;
export const OPEN_SUPPORT_EVENT = 'nano:open-support';

export type SupportKind = 'bug' | 'support';

/** Get support severity (NAN-5253). */
export type SupportSeverity = 'SEV1' | 'SEV2' | 'SEV3' | 'SEV4';
export const SUPPORT_SEVERITIES: Array<{ value: SupportSeverity; label: string }> = [
  { value: 'SEV1', label: 'Production down' },
  { value: 'SEV2', label: 'Degraded' },
  { value: 'SEV3', label: 'Issue' },
  { value: 'SEV4', label: 'Question' },
];

/** app.nano.rs feedback form (docs/api/support-feedback-link.md). */
export const FEEDBACK_FORM_URL = 'https://app.nano.rs/feedback/new';
/** Whole deep link, fragment included, stays under this many characters. */
export const FEEDBACK_URL_MAX = 8192;
const FEEDBACK_TEXT_MAX = 2000;

export interface FailedApiCall {
  at: string;
  method: string;
  path: string;
  /** HTTP status, or 0 when the request never got an answer (network error). */
  status: number;
  requestId?: string;
  durationMs: number;
}

export interface ConsoleErrorEntry {
  at: string;
  message: string;
}

const failedCalls: FailedApiCall[] = [];
const consoleErrors: ConsoleErrorEntry[] = [];
let installed = false;

/** Ask the mounted support dialog to open (works from any route or shell). */
export function openSupportDialog(kind: SupportKind): void {
  window.dispatchEvent(new CustomEvent<SupportKind>(OPEN_SUPPORT_EVENT, { detail: kind }));
}

// --- redaction ---------------------------------------------------------------------------------

const REDACTIONS: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(-----END [A-Z0-9 ]+-----|$)/g, '[REDACTED:PEM]'],
  [/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, '[REDACTED:JWT]'],
  [/(\b(?:proxy-)?authorization\b["']?\s*[:=]\s*["']?)(?:[A-Za-z][A-Za-z0-9_-]*\s+)?[^\s"',;]+/gi, '$1[REDACTED]'],
  [/\bbearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer [REDACTED]'],
  [/\b([a-z][a-z0-9+.-]*:\/\/)([^:/@\s"']*):([^@/\s"']+)@/gi, '$1$2:[REDACTED]@'],
  [/([?&](?:token|access_token|id_token|refresh_token|api_key|apikey|key|sig|signature|password|code|state|client_secret)=)[^&\s"'#]+/gi,
    '$1[REDACTED]'],
  [/([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|apikey|credential|cookie|licen[cs]e[_-]?key)[A-Za-z0-9_.-]*["']?\s*[:=]\s*["']?)(?!\[REDACTED)[^\s"',;&}<>]+/gi,
    '$1[REDACTED]'],
  [/\bnit_[A-Za-z0-9_-]{8,}/g, '[REDACTED:INGEST_TOKEN]'],
];

/** Remove tokens, JWTs, PEM blocks, URL credentials and key=value secrets. */
export function redactText(text: string): string {
  let out = text;
  for (const [rx, rep] of REDACTIONS) out = out.replace(rx, rep);
  return out;
}

// --- paths and routes ----------------------------------------------------------------------------

/** A path segment that looks like a bearer-style secret (share/claim tokens), not an ID. */
function looksLikeToken(segment: string): boolean {
  if (segment.length < 32) return false;
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return false; // UUID
  if (/^[a-z][a-z0-9]*(_[a-z0-9]+)?_[0-9a-hjkmnp-tv-z]{26}$/.test(segment)) return false; // TypeID
  return /^[A-Za-z0-9_.~+=-]+$/.test(segment);
}

/** Path only (no origin, query or fragment), with token-like segments masked. */
export function sanitizeApiPath(pathname: string): string {
  return pathname
    .split('/')
    .map((segment, i, all) => {
      const prev = all[i - 1];
      if (prev === 'shared' || prev === 'claim' || looksLikeToken(segment)) return segment ? ':token' : segment;
      return segment;
    })
    .join('/');
}

/** Query keys whose values are safe and useful to show (time windows, tabs). */
const SAFE_QUERY_KEYS = new Set([
  'from', 'to', 'earliest', 'latest', 'range', 'span', 'tab', 'view', 'page', 'mode', 'status', 'severity',
  'sort', 'order', 'section', 'step', 'type', 'kind', 'limit',
]);

/** The page route with query values omitted unless the key is known-safe; no fragment. */
export function sanitizeRoute(pathname: string, search: string): string {
  const params = new URLSearchParams(search);
  const parts: string[] = [];
  params.forEach((value, key) => {
    const safe = SAFE_QUERY_KEYS.has(key) && value.length <= 40 && !/[@/\\]/.test(value);
    parts.push(`${encodeURIComponent(key)}=${safe ? encodeURIComponent(value) : '[omitted]'}`);
  });
  return sanitizeApiPath(pathname) + (parts.length ? `?${parts.join('&')}` : '');
}

// --- capture -------------------------------------------------------------------------------------

function push<T>(list: T[], item: T, max: number): void {
  list.push(item);
  if (list.length > max) list.splice(0, list.length - max);
}

function trackedPath(url: string, origin: string): string | null {
  try {
    const parsed = new URL(url, origin);
    if (parsed.origin !== origin) return null;
    if (!/^\/(api|health|auth)(\/|$)/.test(parsed.pathname)) return null;
    return sanitizeApiPath(parsed.pathname);
  } catch {
    return null;
  }
}

export function recordFailedCall(entry: FailedApiCall): void {
  push(failedCalls, entry, MAX_FAILED_CALLS);
}

function stringifyArg(arg: unknown): string {
  if (arg instanceof Error) return `${arg.name}: ${arg.message}`;
  if (typeof arg === 'string') return arg;
  try {
    return JSON.stringify(arg)?.slice(0, 200) ?? String(arg);
  } catch {
    return String(arg);
  }
}

export function recordConsoleError(args: unknown[]): void {
  let message = redactText(args.map(stringifyArg).join(' ').replace(/\s+/g, ' ').trim());
  if (!message) return;
  if (message.length > MAX_ERROR_CHARS) message = `${message.slice(0, MAX_ERROR_CHARS)}…`;
  push(consoleErrors, { at: new Date().toISOString(), message }, MAX_CONSOLE_ERRORS);
}

function requestMethod(input: RequestInfo | URL, init?: RequestInit): string {
  if (init?.method) return init.method.toUpperCase();
  if (typeof Request !== 'undefined' && input instanceof Request) return input.method.toUpperCase();
  return 'GET';
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/**
 * Wrap `fetch` and `console.error` once, at boot. Idempotent. The wrapped
 * fetch returns exactly what the original returns; it only reads the status
 * and the `x-request-id` (or `cf-ray`) response header of failed calls.
 */
export function installSupportCapture(win: Window & typeof globalThis = window): void {
  if (installed || typeof win.fetch !== 'function') return;
  installed = true;
  const originalFetch = win.fetch.bind(win);
  const origin = win.location.origin;
  win.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const started = Date.now();
    const path = trackedPath(requestUrl(input), origin);
    try {
      const response = await originalFetch(input, init);
      if (path && !response.ok) {
        const rid = response.headers.get('x-request-id') || response.headers.get('cf-ray') || undefined;
        recordFailedCall({
          at: new Date().toISOString(), method: requestMethod(input, init), path, status: response.status,
          requestId: rid && /^[A-Za-z0-9._:-]{1,64}$/.test(rid) ? rid : undefined,
          durationMs: Date.now() - started,
        });
      }
      return response;
    } catch (error) {
      const aborted = error instanceof DOMException && error.name === 'AbortError';
      if (path && !aborted) {
        recordFailedCall({
          at: new Date().toISOString(), method: requestMethod(input, init), path, status: 0,
          durationMs: Date.now() - started,
        });
      }
      throw error;
    }
  };
  const originalError = win.console.error.bind(win.console);
  win.console.error = (...args: unknown[]) => {
    try {
      recordConsoleError(args);
    } catch {
      /* never let capture break logging */
    }
    originalError(...args);
  };
  win.addEventListener('error', (event) => recordConsoleError([event.error ?? event.message]));
  win.addEventListener('unhandledrejection', (event) => recordConsoleError(['Unhandled rejection:', event.reason]));
}

export function getFailedCalls(): FailedApiCall[] {
  return failedCalls.slice();
}

export function getConsoleErrors(): ConsoleErrorEntry[] {
  return consoleErrors.slice();
}

/** Test helper. */
export function resetSupportCapture(): void {
  failedCalls.length = 0;
  consoleErrors.length = 0;
}

// --- report --------------------------------------------------------------------------------------

export interface SupportContext {
  appVersion: string;
  edition: string;
  route: string;
  userAgent: string;
  language: string;
  timezone: string;
  viewport: string;
  collectedAt: string;
  installationId?: string;
  /** app.nano.rs deployment ID (`deploy_…`) when the install knows it. */
  deploymentId?: string;
  failedCalls: FailedApiCall[];
  consoleErrors: ConsoleErrorEntry[];
}

export interface SupportReportInput {
  kind: SupportKind;
  /** Get support only. */
  severity?: SupportSeverity;
  whatHappened: string;
  expected: string;
  when: string;
  affected: string;
  context: SupportContext;
}

export function collectSupportContext(opts: {
  appVersion?: string;
  edition?: string;
  installationId?: string;
}): SupportContext {
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown';
  return {
    appVersion: opts.appVersion || 'unknown',
    edition: opts.edition || 'unknown',
    route: sanitizeRoute(window.location.pathname, window.location.search),
    userAgent: navigator.userAgent,
    language: navigator.language,
    timezone: tz,
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    collectedAt: new Date().toISOString(),
    installationId: opts.installationId,
    failedCalls: getFailedCalls(),
    consoleErrors: getConsoleErrors(),
  };
}

/** "2026-11-10 14:05 EST (UTC-05:00)" for the default "When" value. */
export function localTimestamp(date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  const offset = -date.getTimezoneOffset();
  const sign = offset >= 0 ? '+' : '-';
  const abs = Math.abs(offset);
  const tz = Intl.DateTimeFormat('en-US', { timeZoneName: 'short' })
    .formatToParts(date).find((p) => p.type === 'timeZoneName')?.value ?? '';
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`
    + `${tz ? ` ${tz}` : ''} (UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)})`;
}

const one = (text: string) => redactText(text.trim()) || '(not given)';

/** Plain-text report (Markdown-friendly). Every free-text field is redacted too. */
export function buildSupportReport(input: SupportReportInput): string {
  const c = input.context;
  const title = input.kind === 'bug' ? 'Bug report' : 'Support request';
  const lines = [
    `# nano ${title}`,
    '',
    ...(input.kind === 'support' && input.severity
      ? [`## Severity`, `${input.severity} (${SUPPORT_SEVERITIES.find((s) => s.value === input.severity)?.label ?? ''})`, '']
      : []),
    `## What happened`,
    one(input.whatHappened),
    '',
    input.kind === 'bug' ? '## What I expected' : '## What I need',
    one(input.expected),
    '',
    `## When`,
    one(input.when),
    '',
    `## Affected objects (exact names)`,
    one(input.affected),
    '',
    `## Context (collected in the browser)`,
    `- nano version: ${c.appVersion}`,
    `- edition: ${c.edition}`,
    ...(c.deploymentId ? [`- deployment: ${c.deploymentId}`] : []),
    ...(c.installationId ? [`- installation: ${c.installationId}`] : []),
    `- page: ${c.route}`,
    `- browser: ${c.userAgent}`,
    `- language / timezone: ${c.language} / ${c.timezone}`,
    `- viewport: ${c.viewport}`,
    `- collected: ${c.collectedAt}`,
    '',
    `## Recent failed API calls (${c.failedCalls.length})`,
    ...(c.failedCalls.length
      ? c.failedCalls.map((f) => `- ${f.at} ${f.status || 'network error'} ${f.method} ${f.path}`
        + `${f.requestId ? ` request_id=${f.requestId}` : ''} ${f.durationMs}ms`)
      : ['- none recorded in this tab']),
    '',
    `## Recent console errors (${c.consoleErrors.length})`,
    ...(c.consoleErrors.length ? c.consoleErrors.map((e) => `- ${e.at} ${e.message}`) : ['- none recorded in this tab']),
    '',
    `## Support bundle`,
    `For install, ingestion or performance problems, attach a support bundle (redacted, no event data):`,
    `- Compose: ${SUPPORT_BUNDLE_COMMANDS.compose}`,
    `- Kubernetes: ${SUPPORT_BUNDLE_COMMANDS.helm}`,
    '',
  ];
  return lines.join('\n');
}

const MAILTO_BODY_MAX = 1800;

/** mailto: link with the report prefilled; long reports are cut with a pointer to the clipboard copy. */
export function supportMailto(report: string, kind: SupportKind, summary: string): string {
  const subjectBase = kind === 'bug' ? 'nano bug report' : 'nano support request';
  const first = summary.trim().split('\n')[0]?.slice(0, 80) ?? '';
  const subject = first ? `${subjectBase}: ${redactText(first)}` : subjectBase;
  let body = report;
  if (body.length > MAILTO_BODY_MAX) {
    body = `${body.slice(0, MAILTO_BODY_MAX)}\n\n[Report cut to fit an email link. The full report is on your clipboard: paste it here.]`;
  }
  return `mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

// --- app.nano.rs feedback deep link (fragment schema v1) ----------------------------------------

/** The `#r=` payload. Field-by-field contract: docs/api/support-feedback-link.md. */
export interface FeedbackPayloadV1 {
  v: 1;
  type: SupportKind;
  severity?: SupportSeverity;
  summary: string;
  what_happened: string;
  expected: string;
  when: string;
  affected: string;
  context: {
    app_version: string;
    edition: string;
    deployment_id?: string;
    installation_id?: string;
    route: string;
    user_agent: string;
    language: string;
    timezone: string;
    viewport: string;
    collected_at: string;
    failed_calls: Array<{ at: string; method: string; path: string; status: number; request_id?: string; duration_ms: number }>;
    console_errors: Array<{ at: string; message: string }>;
  };
  truncated: boolean;
}

const DEPLOYMENT_ID_RE = /^deploy_[0-9a-hjkmnp-tv-z]{26}$/;

function clip(text: string, max: number): string {
  const t = redactText(text.trim());
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

export function buildFeedbackPayload(input: SupportReportInput): FeedbackPayloadV1 {
  const c = input.context;
  const what = clip(input.whatHappened, FEEDBACK_TEXT_MAX);
  const expected = clip(input.expected, FEEDBACK_TEXT_MAX);
  const affected = clip(input.affected, 1000);
  return {
    v: 1,
    type: input.kind,
    ...(input.kind === 'support' && input.severity ? { severity: input.severity } : {}),
    summary: clip(input.whatHappened.split('\n')[0] ?? '', 120),
    what_happened: what,
    expected,
    when: clip(input.when, 200),
    affected,
    context: {
      app_version: c.appVersion,
      edition: c.edition,
      ...(c.deploymentId && DEPLOYMENT_ID_RE.test(c.deploymentId) ? { deployment_id: c.deploymentId } : {}),
      ...(c.installationId ? { installation_id: c.installationId } : {}),
      route: c.route,
      user_agent: c.userAgent.slice(0, 300),
      language: c.language,
      timezone: c.timezone,
      viewport: c.viewport,
      collected_at: c.collectedAt,
      failed_calls: c.failedCalls.map((f) => ({
        at: f.at, method: f.method, path: f.path, status: f.status,
        ...(f.requestId ? { request_id: f.requestId } : {}), duration_ms: f.durationMs,
      })),
      console_errors: c.consoleErrors.map((e) => ({ at: e.at, message: e.message })),
    },
    truncated: [what, expected, affected].some((t) => t.endsWith('…')),
  };
}

/** UTF-8 JSON -> base64url without padding. */
export function encodeFeedbackPayload(payload: FeedbackPayloadV1): string {
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Inverse of {@link encodeFeedbackPayload} (tests; the same algorithm app.nano.rs uses). */
export function decodeFeedbackPayload(encoded: string): FeedbackPayloadV1 {
  const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(binary, (ch) => ch.charCodeAt(0)))) as FeedbackPayloadV1;
}

/**
 * `https://app.nano.rs/feedback/new?type=…[&deployment=…]#r=<base64url(JSON)>`.
 * The report rides in the fragment, which browsers never send to a server.
 * Over {@link FEEDBACK_URL_MAX}: drop the oldest console errors, then the
 * oldest failed calls, then shorten the free text; `truncated` is then true
 * (the Download/Copy report stays complete).
 */
export function feedbackUrl(input: SupportReportInput): { url: string; truncated: boolean } {
  const payload = buildFeedbackPayload(input);
  const query = new URLSearchParams({ type: input.kind });
  if (payload.context.deployment_id) query.set('deployment', payload.context.deployment_id);
  const base = `${FEEDBACK_FORM_URL}?${query.toString()}#r=`;
  const fits = () => base.length + encodeFeedbackPayload(payload).length <= FEEDBACK_URL_MAX;
  const ctx = payload.context;
  while (!fits() && ctx.console_errors.length) { ctx.console_errors.shift(); payload.truncated = true; }
  while (!fits() && ctx.failed_calls.length) { ctx.failed_calls.shift(); payload.truncated = true; }
  for (const max of [1000, 500, 200]) {
    if (fits()) break;
    payload.truncated = true;
    payload.what_happened = clip(payload.what_happened, max);
    payload.expected = clip(payload.expected, max);
    payload.affected = clip(payload.affected, Math.min(max, 500));
    ctx.user_agent = ctx.user_agent.slice(0, 120);
  }
  return { url: base + encodeFeedbackPayload(payload), truncated: payload.truncated };
}
