// Content-Security-Policy for index.html, built by the `csp` Vite plugin.
//
// Production allows inline scripts only by sha256 hash. The hashes are derived
// from the HTML being served at build time (not a hand-maintained constant),
// and `assertInlineScriptsAllowed` re-checks the final emitted HTML so a later
// transform that edits an inline script fails the build instead of shipping a
// script the browser will block (theme flash / wrong initial theme).
import { createHash } from 'node:crypto';

const SCRIPT_TAG = /<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const CSP_META = /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"\s*\/?>/i;

/** Bodies of every inline (no `src`) <script> element, exactly as written. */
export function extractInlineScripts(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(SCRIPT_TAG)) {
    const attrs = m[1] ?? '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    out.push(m[2] ?? '');
  }
  return out;
}

/** CSP source expression for a script body: `'sha256-<base64>'`. */
export function cspHashSource(scriptBody: string): string {
  return `'sha256-${createHash('sha256').update(scriptBody, 'utf8').digest('base64')}'`;
}

/**
 * Environments where opt-in error-only Sentry Replay may be enabled at build time.
 * Checked strictly against the raw `VITE_NANO_SENTRY_ENVIRONMENT` value (never a fallback).
 */
export const REPLAY_ALLOWED_ENVIRONMENTS: ReadonlySet<string> = new Set([
  'local',
  'e2e',
  'internal',
]);

/**
 * True only when a build explicitly sets a Sentry DSN, opts into Replay (`=1`),
 * targets an allowed internal/e2e environment, and does not disable Replay via
 * a `<= 0` `VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE`.
 */
export function isSentryReplayBuildEnabled(env: Record<string, string | undefined>): boolean {
  const dsn = (env.VITE_NANO_SENTRY_DSN ?? '').trim();
  const rawEnv = (env.VITE_NANO_SENTRY_ENVIRONMENT ?? '').trim().toLowerCase();
  if (!dsn || env.VITE_NANO_SENTRY_REPLAY !== '1' || !REPLAY_ALLOWED_ENVIRONMENTS.has(rawEnv)) {
    return false;
  }
  const rawRate = env.VITE_NANO_SENTRY_REPLAY_ON_ERROR_RATE;
  if (rawRate !== undefined && rawRate.trim() !== '') {
    const parsed = Number(rawRate);
    if (Number.isFinite(parsed) && parsed <= 0) return false;
  }
  return true;
}

/**
 * NAN-5798: the origin of an opt-in Sentry DSN, allowed in connect-src so the
 * SDK can send. Empty for every build without `VITE_NANO_SENTRY_DSN`.
 */
export function sentryConnectOrigin(dsn: string | undefined): string[] {
  if (!dsn) return [];
  try {
    const url = new URL(dsn);
    return url.protocol === 'https:' || url.protocol === 'http:' ? [url.origin] : [];
  } catch {
    return [];
  }
}

export function buildCsp(opts: {
  isDev: boolean;
  inlineScriptHashes: string[];
  connectExtra?: string[];
  allowBlobWorker?: boolean;
}): string {
  // Dev needs 'unsafe-inline' for Vite HMR + React Refresh injected scripts.
  // Prod uses a hash allowlist for the inline scripts in index.html.
  const scriptSrc = opts.isDev
    ? "'self' 'unsafe-inline'"
    : ["'self'", ...new Set(opts.inlineScriptHashes)].join(' ');

  // Dev: allow direct localhost API access (bypass Vite proxy) for testing.
  // Prod: 'self' covers all requests (nginx proxies everything same-origin).
  // CSP3: 'self' on https pages also matches wss:// same-origin.
  const connectSrc = [
    opts.isDev
      ? "'self' http://localhost:3000 http://localhost:3001 http://localhost:3002 ws://localhost:*"
      : "'self'",
    ...(opts.connectExtra ?? []),
  ].join(' ');

  const directives = [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    `connect-src ${connectSrc}`,
  ];
  // Sentry Replay's compression Web Worker loads from a blob: URL. Only allow
  // blob workers in opt-in internal/e2e Replay builds; customer builds stay unchanged.
  if (opts.allowBlobWorker) {
    directives.push("worker-src 'self' blob:");
  }
  directives.push("base-uri 'self'", "form-action 'self'");
  return directives.join('; ');
}

/** Replace the `__CSP__` placeholder with a policy hashed from this HTML's inline scripts. */
export function applyCsp(
  html: string,
  isDev: boolean,
  connectExtra: string[] = [],
  allowBlobWorker = false,
): string {
  if (!html.includes('__CSP__')) {
    throw new Error('csp: index.html is missing the __CSP__ meta placeholder');
  }
  const inlineScriptHashes = extractInlineScripts(html).map(cspHashSource);
  return html.replace('__CSP__', buildCsp({ isDev, inlineScriptHashes, connectExtra, allowBlobWorker }));
}

/** The script-src directive of the CSP meta tag in `html`, or null if absent. */
export function scriptSrcOf(html: string): string | null {
  const meta = html.match(CSP_META);
  if (!meta) return null;
  const directive = meta[1]
    .split(';')
    .map((d) => d.trim())
    .find((d) => d.startsWith('script-src '));
  return directive ?? null;
}

/**
 * Throw unless every inline script in `html` is allowed by its CSP meta tag.
 * Run on the final production HTML.
 */
export function assertInlineScriptsAllowed(html: string): void {
  const scriptSrc = scriptSrcOf(html);
  if (!scriptSrc) throw new Error('csp: built index.html has no script-src in its CSP meta tag');
  if (scriptSrc.includes("'unsafe-inline'")) return;
  const allowed = new Set(scriptSrc.split(/\s+/).slice(1));
  const missing = extractInlineScripts(html)
    .map(cspHashSource)
    .filter((h) => !allowed.has(h));
  if (missing.length > 0) {
    throw new Error(
      `csp: inline script(s) not allowed by script-src (${scriptSrc}); missing ${missing.join(', ')}. ` +
        'An HTML transform changed an inline script after the CSP was computed.',
    );
  }
}
