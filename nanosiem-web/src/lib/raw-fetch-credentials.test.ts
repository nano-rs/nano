// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Static guard: no raw tenant `/api` fetch bypasses the ApiClient credential
 * rule. NAN-2361 first guarded raw fetches that sent a bearer; NAN-3905
 * widens it to EVERY raw fetch (the header-less QueryLibrary reads and the
 * cookie-only step-up slipped through the narrower check).
 *
 * On the pooled hosted origin every signed-in tenant owns an
 * `access_token__<d>` cookie, and the shared-tenant extractor refuses a
 * request that presents more than one credential ("Provide exactly one
 * authentication credential"). The SPA therefore sends its in-memory bearer
 * with `credentials: 'omit'`. A bare `fetch('/api/…')` uses the browser
 * default (`same-origin`: every cookie) and breaks as soon as a second tenant
 * is signed in — the bug behind NAN-3905 (step-up) and earlier useMitreData.
 *
 * Every global `fetch(` call in app code must either go through
 * `authenticatedFetch` / the ApiClient, or pass
 * `credentials: requestCredentials(...)`. The few calls that are not tenant
 * API calls are listed below with the reason. Literal `credentials:
 * 'include' | 'same-origin'` is confined to the cookie-carried auth-lifecycle
 * adapters.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const SRC = fileURLToPath(new URL('..', import.meta.url));

/** Global fetch calls that are not tenant API requests. file -> count. */
const NON_API_FETCH: Record<string, { count: number; reason: string }> = {
  'lib/build-update.ts': { count: 1, reason: 'static /index.html build probe, no API' },
  'enterprise/pages/CustomIntegrationWizard.tsx': { count: 1, reason: 'vendor-API sample inside a generated script template' },
  'components/search/cloud-overview/progressive.ts': { count: 2, reason: '`fetch` is an injected section loader parameter' },
  'hooks/use-api.ts': { count: 1, reason: '`fetch` is a local callback name' },
};

/** `window.fetch` adapters for the dependency-injected auth-lifecycle flows;
 * each caller sets `credentials` explicitly and is covered by its own tests. */
const WINDOW_FETCH_ADAPTERS: Record<string, number> = {
  'pages/EnterpriseSharedOidc.tsx': 1,
  'pages/Login.tsx': 1,
  'pages/EnterpriseSharedActivation.tsx': 1,
  'pages/EnterpriseSharedMembershipAcceptance.tsx': 1,
};

/** Cookie-carried auth lifecycle (activation, SSO entry/start/callback/refresh,
 * best-effort cleanup logout). Never a tenant API read or write. */
const COOKIE_CREDENTIAL_LITERALS: Record<string, number> = {
  'lib/enterprise-shared-activation.ts': 1,
  'lib/enterprise-shared-oidc.ts': 5,
  'pages/EnterpriseSharedOidc.tsx': 1,
};

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === 'node_modules' || name === '__tests__' || name === 'test') continue;
      out.push(...sourceFiles(path));
    } else if (/\.(ts|tsx)$/.test(name) && !/\.(test|spec)\.(ts|tsx)$/.test(name) && !name.endsWith('.d.ts')) {
      out.push(path);
    }
  }
  return out;
}

/** Text of the call starting at `open` (index of its `(`), parens balanced. */
function callText(source: string, open: number): string {
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '(') depth += 1;
    else if (source[i] === ')') {
      depth -= 1;
      if (depth === 0) return source.slice(open, i + 1);
    }
  }
  return source.slice(open);
}

const files = sourceFiles(SRC).map((path) => ({
  rel: relative(SRC, path).split('\\').join('/'),
  source: readFileSync(path, 'utf8'),
}));

test('every raw global fetch( uses requestCredentials or is a listed non-API call', () => {
  const offenders: string[] = [];
  const counts: Record<string, number> = {};
  for (const { rel, source } of files) {
    for (const match of source.matchAll(/(?<![\w$.])fetch\(/g)) {
      const call = callText(source, match.index! + 'fetch'.length);
      if (/credentials:\s*requestCredentials\(/.test(call)) continue;
      counts[rel] = (counts[rel] ?? 0) + 1;
      if (!NON_API_FETCH[rel]) {
        const line = source.slice(0, match.index).split('\n').length;
        offenders.push(`${rel}:${line} ${call.slice(0, 80).replace(/\s+/g, ' ')}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `route tenant API calls through authenticatedFetch/ApiClient or pass credentials: requestCredentials(...):\n${offenders.join('\n')}`);
  for (const [rel, { count }] of Object.entries(NON_API_FETCH)) {
    assert.equal(counts[rel] ?? 0, count, `${rel}: allowlist count is stale`);
  }
});

test('window.fetch is used only by the listed auth-lifecycle adapters', () => {
  const counts: Record<string, number> = {};
  for (const { rel, source } of files) {
    const n = source.match(/\b(?:window|globalThis|self)\.fetch\(/g)?.length ?? 0;
    if (n) counts[rel] = n;
  }
  assert.deepEqual(counts, WINDOW_FETCH_ADAPTERS);
});

test("credentials: 'include' / 'same-origin' literals stay in the cookie-carried auth lifecycle", () => {
  const counts: Record<string, number> = {};
  for (const { rel, source } of files) {
    const n = source.match(/credentials:\s*['"](?:include|same-origin)['"]/g)?.length ?? 0;
    if (n) counts[rel] = n;
  }
  assert.deepEqual(counts, COOKIE_CREDENTIAL_LITERALS);
});

test('the guard actually detects a bare tenant fetch', () => {
  const sample = "const r = await fetch(`${API}/api/rules`, { method: 'GET' });";
  const match = /(?<![\w$.])fetch\(/.exec(sample)!;
  const call = callText(sample, match.index + 'fetch'.length);
  assert.equal(/credentials:\s*requestCredentials\(/.test(call), false);
  const ok = "fetch(url, { headers, credentials: requestCredentials('/api/rules', headers) })";
  assert.equal(/credentials:\s*requestCredentials\(/.test(callText(ok, 'fetch'.length)), true);
});
