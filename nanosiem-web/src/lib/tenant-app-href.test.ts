// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-4800 (AU report): on a pooled host the product lives under
// `/t/<tenant>/…`. A raw `<a href="/ingestion/…">`, `window.open('/…')` or
// `window.location.href = '/…'` skips the router basename, the next refresh has
// no tenant selector (`tenant_required`) and the user is dumped at login.
//
// 1. `tenantAppHref` puts an in-app path under the current tenant prefix.
// 2. `tenantlessDeepLinkRedirect` sends a tenant-less product deep link back
//    under the last tenant this browser signed into (the backstop).
// 3. A guard scans src/ and fails on any NEW raw internal href / navigation.
import { afterEach, describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  rememberActiveTenant,
  rememberedActiveTenant,
  tenantAppHref,
  tenantlessDeepLinkRedirect as checkedRedirect,
} from './tenant-auth-shell';

describe('tenantAppHref', () => {
  it('prefixes in-app paths with the current tenant', () => {
    const at = '/t/acme/ingestion/log-sources/wizard';
    expect(tenantAppHref('/ingestion/log-sources/credentials', at)).toBe('/t/acme/ingestion/log-sources/credentials');
    expect(tenantAppHref('/search#q=a&run=true', at)).toBe('/t/acme/search#q=a&run=true');
    expect(tenantAppHref('/alerts/alrt_1?tab=events', at)).toBe('/t/acme/alerts/alrt_1?tab=events');
    expect(tenantAppHref('/', at)).toBe('/t/acme/');
    expect(tenantAppHref('/denied', '/t/acme')).toBe('/t/acme/denied');
  });

  it('leaves dedicated deployments, external, API, static and already-scoped paths alone', () => {
    expect(tenantAppHref('/ingestion/log-sources/credentials', '/ingestion/log-sources/wizard')).toBe('/ingestion/log-sources/credentials');
    const at = '/t/acme/search';
    expect(tenantAppHref('https://nano.rs/docs/', at)).toBe('https://nano.rs/docs/');
    expect(tenantAppHref('//evil.example/x', at)).toBe('//evil.example/x');
    expect(tenantAppHref('#section', at)).toBe('#section');
    expect(tenantAppHref('/api/log-sources', at)).toBe('/api/log-sources');
    expect(tenantAppHref('/swagger-ui/', at)).toBe('/swagger-ui/');
    expect(tenantAppHref('/scripts/Sync-ADUsers.ps1', at)).toBe('/scripts/Sync-ADUsers.ps1');
    expect(tenantAppHref('/t/other/alerts', at)).toBe('/t/other/alerts');
    expect(tenantAppHref('/auth/shared/activate#token', at)).toBe('/auth/shared/activate#token');
    expect(tenantAppHref('/auth/callback/okta?code=a', at)).toBe('/auth/callback/okta?code=a');
  });
});

describe('tenant-less deep links (the backstop)', () => {
  const tenantlessDeepLinkRedirect = (location: { pathname: string; search: string; hash: string }, slug = rememberedActiveTenant()) =>
    checkedRedirect(location, slug, [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', slug: 'acme' }, { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', slug: 'acme-sec' }]);
  afterEach(() => window.localStorage.clear());
  const loc = (pathname: string, search = '', hash = '') => ({ pathname, search, hash });

  it('sends a product path back under the remembered tenant, keeping query and hash', () => {
    expect(tenantlessDeepLinkRedirect(loc('/ingestion/log-sources/credentials'), 'acme'))
      .toBe('/t/acme/ingestion/log-sources/credentials');
    expect(tenantlessDeepLinkRedirect(loc('/search', '?s=Ab3xYz09', '#q=x'), 'acme')).toBe('/t/acme/search?s=Ab3xYz09#q=x');
    expect(tenantlessDeepLinkRedirect(loc('/alerts/alrt_1'), 'acme')).toBe('/t/acme/alerts/alrt_1');
  });

  it('never moves public, auth, API or already-scoped paths, and does nothing with no tenant on record', () => {
    for (const p of ['/', '/login', '/mfa-setup', '/demo', '/d/tok_1', '/denied', '/setup', '/auth/shared/activate',
      '/auth/shared/oidc/callback', '/auth/callback/okta', '/api/auth/me', '/swagger-ui/', '/t/acme/search', '/t/acme']) {
      expect(tenantlessDeepLinkRedirect(loc(p), 'acme')).toBeUndefined();
    }
    expect(tenantlessDeepLinkRedirect(loc('/ingestion/log-sources'), undefined)).toBeUndefined();
  });

  it('requires live session membership, even for a valid stored slug', () => {
    expect(checkedRedirect(loc('/rules'), 'acme')).toBeUndefined();
    expect(checkedRedirect(loc('/rules'), 'other', [{ id: 'a', slug: 'acme' }])).toBeUndefined();
  });

  it('rejects paths that escape the tenant and treats query redirects as data', () => {
    for (const path of ['//evil.example', '/\\evil.example', '/../other/rules', '/../../t/other/search',
      '/%2e%2e/other/search', '/x/%2e%2e/%2e%2e/other/search', '/%2f%2fevil.example', '/%5cevil', '/\t/evil']) {
      expect(tenantlessDeepLinkRedirect(loc(path), 'acme'), path).toBeUndefined();
    }
    expect(tenantlessDeepLinkRedirect(loc('/search', '?next=https://evil.example&redirect=//evil.example', '#https://evil.example'), 'acme'))
      .toBe('/t/acme/search?next=https://evil.example&redirect=//evil.example#https://evil.example');
  });

  it('remembers only a canonical tenant slug', () => {
    expect(rememberedActiveTenant()).toBeUndefined();
    rememberActiveTenant('acme-sec');
    expect(rememberedActiveTenant()).toBe('acme-sec');
    expect(tenantlessDeepLinkRedirect(loc('/rules'))).toBe('/t/acme-sec/rules');
    window.localStorage.setItem('nano.last-tenant-slug', '../evil');
    expect(rememberedActiveTenant()).toBeUndefined();
    expect(() => rememberActiveTenant('Not A Slug')).not.toThrow();
    expect(rememberedActiveTenant()).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Guard: no raw internal href / navigation outside the router.
// ---------------------------------------------------------------------------

// jsdom rewrites import.meta.url; vitest runs from the package root.
const ROOT = join(process.cwd(), 'src');

/**
 * Origin-level paths that are not product routes: API, docs, static files,
 * already-scoped `/t/…`, and the public `/auth/…` callbacks/activation that
 * live outside the tenant basename by design (OIDC redirect URIs are fixed).
 */
const ORIGIN_LEVEL = /^\/(?:api\/|swagger-ui|scripts\/|assets\/|t\/|auth\/)/;

function walk(dir: string, out: string[]): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.[^.]+$/.test(name) && !/\.fixture\./.test(name)) out.push(p);
  }
  return out;
}

/** The literal start of an attribute / argument expression, when it is a string or template literal. */
function literalPath(expr: string): string | undefined {
  const m = expr.trim().match(/^\{?\s*(['"`])(\/[^'"`$]*)/);
  return m ? m[2] : undefined;
}

function findRawInternalNavigation(src: string): string[] {
  const hits: string[] = [];
  const lineOf = (index: number) => src.slice(0, index).split('\n').length;
  const internal = (path: string | undefined) => path !== undefined && !path.startsWith('//') && !ORIGIN_LEVEL.test(path);

  // <a ... href="/x"> / href={'/x'} / href={`/x`} / href={SOME_PATH}
  for (const m of src.matchAll(/<a\b([^>]*?)>/gs)) {
    const href = m[1].match(/\bhref=(\{[^}]*\}|"[^"]*"|'[^']*')/);
    if (!href) continue;
    const value = href[1];
    if (internal(literalPath(value)) || /^\{\s*[A-Z][A-Z0-9_]*_PATH\s*\}$/.test(value)) {
      hits.push(`${lineOf(m.index ?? 0)}: <a href=${value}>`);
    }
  }
  // window.location.href = '/x' / location.assign('/x') / location.replace('/x') / window.open('/x')
  for (const m of src.matchAll(/(?:location\.href\s*=|location\.(?:assign|replace)\(|window\.open\()\s*(['"`][^'"`]*)/g)) {
    if (internal(literalPath(m[1]))) hits.push(`${lineOf(m.index ?? 0)}: ${m[0]}`);
  }
  // `${window.location.origin}/x` share links built without the tenant
  for (const m of src.matchAll(/\$\{window\.location\.origin\}(\/[^`$]*)/g)) {
    if (internal(m[1])) hits.push(`${lineOf(m.index ?? 0)}: ${m[0]}`);
  }
  return hits;
}

describe('guard: no raw internal links outside the router (NAN-4800)', () => {
  it('flags raw internal hrefs and navigations, allows routed and origin-level ones', () => {
    expect(findRawInternalNavigation(`<a href={INGEST_CREDENTIALS_PATH} className="x">Creds</a>`)).toHaveLength(1);
    expect(findRawInternalNavigation(`<a href="/rules/repositories">Repos</a>`)).toHaveLength(1);
    expect(findRawInternalNavigation('<a\n  href={`/alerts/${id}`}\n  target="_blank">')).toHaveLength(1);
    expect(findRawInternalNavigation(`onClick={() => window.location.href = '/'}`)).toHaveLength(1);
    expect(findRawInternalNavigation('window.open(`/search#${q}`, "_blank")')).toHaveLength(1);
    expect(findRawInternalNavigation('const u = `${window.location.origin}/dashboards/${id}`;')).toHaveLength(1);

    expect(findRawInternalNavigation(`<Link to={INGEST_CREDENTIALS_PATH}>Creds</Link>`)).toHaveLength(0);
    expect(findRawInternalNavigation(`<a href={tenantAppHref('/rules')}>x</a>`)).toHaveLength(0);
    expect(findRawInternalNavigation(`<a href="/scripts/Sync-ADUsers.ps1" download>`)).toHaveLength(0);
    expect(findRawInternalNavigation(`<a href="https://nano.rs/docs/">`)).toHaveLength(0);
    expect(findRawInternalNavigation('window.location.href = tenantAppHref(\'/denied\');')).toHaveLength(0);
    expect(findRawInternalNavigation('`${window.location.origin}${tenantAppHref(`/dashboards/${id}`)}`')).toHaveLength(0);
    expect(findRawInternalNavigation('`${window.location.origin}/auth/callback/${slug}`')).toHaveLength(0);
  });

  it('src/ has no raw internal href / navigation (use <Link>, useHref or tenantAppHref)', () => {
    const offenders: string[] = [];
    for (const file of walk(ROOT, [])) {
      const rel = relative(ROOT, file);
      for (const hit of findRawInternalNavigation(readFileSync(file, 'utf8'))) offenders.push(`${rel}:${hit}`);
    }
    expect(offenders).toEqual([]);
  });
});
