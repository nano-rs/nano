// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  TenantAuthContractError,
  loginRequestBody,
  safeReturnPath,
  tenantLoginPath,
  tenantContinuationBody,
  tenantMfaSetupPath,
  tenantSearchPath,
  tenantBasename,
  tenantSlugForAuthContinuation,
  tenantSlugFromLoginPath,
  tenantSlugFromShellPath,
  tenantSlugFromMfaSetupPath,
  tenantSlugFromSearchPath,
  verifyServerAuthIdentity,
} from './tenant-auth-shell.ts';

const ACTIVE = {
  id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  slug: 'acme-soc',
};

test('tenant login path accepts only an exact lowercase unencoded slug', () => {
  assert.equal(tenantSlugFromLoginPath('/t/acme-soc/login'), 'acme-soc');
  assert.equal(tenantSlugFromShellPath('/t/acme-soc'), 'acme-soc');
  assert.equal(tenantSlugFromMfaSetupPath('/t/acme-soc/mfa-setup'), 'acme-soc');
  assert.equal(tenantSlugFromSearchPath('/t/acme-soc/search'), 'acme-soc');
  for (const path of [
    '/t/Acme-soc/login',
    '/t/%61cme-soc/login',
    '/t/acme%2Fsibling/login',
    '/t/acme-soc%00/login',
    '/t/acme-soc/login/',
    '/t/acme--soc/../login',
  ]) {
    assert.throws(() => tenantSlugFromLoginPath(path), TenantAuthContractError, path);
  }
});

test('a shared tenant gets the full product under its own basename', () => {
  const app = readFileSync(new URL('../App.tsx', import.meta.url), 'utf8');
  // No route may mount a reduced tenant surface any more.
  assert.doesNotMatch(app, /TenantIdentityShell|TenantSearchContent|TenantSocRoute|TenantRedirectRoute/);
  // The router's basename carries the tenant selector for every product path.
  assert.match(app, /<BrowserRouter basename=\{tenantBasename\(rawBrowserPath\('\/'\)\)\}>/);
  // Under it, /login IS the tenant login and validates the slug off the browser path.
  assert.match(app, /function LoginRoute\(\)[\s\S]*?tenantSlugFromLoginPath\(raw\)/);
  assert.match(app, /path="\/login" element=\{<LoginRoute \/>\}/);
  assert.match(app, /path="\/mfa-setup" element=\{<MfaSetupRoute \/>\}/);
  // And no route is registered under a literal /t/ prefix any more.
  assert.doesNotMatch(app, /path="\/t\//);
  assert.equal(tenantBasename('/t/acme-soc/search/jobs'), '/t/acme-soc');
  assert.equal(tenantBasename('/search'), undefined);
  assert.equal(tenantBasename('/t/ACME/search'), undefined);
});

test('returned shared tenant must match selector by exact slug and UUID shape', () => {
  assert.deepEqual(
    verifyServerAuthIdentity({
      id: 'user-1', roles: [], deployment_mode: 'enterprise_shared', active_tenant: ACTIVE,
    }, 'acme-soc').activeTenant,
    ACTIVE,
  );
  assert.throws(() => verifyServerAuthIdentity({
    id: 'user-1', roles: [], deployment_mode: 'enterprise_shared', active_tenant: ACTIVE,
  }, 'other-tenant'), /does not match/);
  assert.throws(() => verifyServerAuthIdentity({
    id: 'user-1', roles: [], deployment_mode: 'enterprise_shared',
    active_tenant: { id: 'not-a-uuid', slug: 'acme-soc' },
  }, 'acme-soc'), /missing an exact active_tenant/);
});

test('server identity parsing still requires an exact tenant when no route is supplied', () => {
  const restored = verifyServerAuthIdentity({
    id: 'user-1', roles: [], deployment_mode: 'enterprise_shared', active_tenant: ACTIVE,
  });
  assert.deepEqual(restored.activeTenant, ACTIVE);
});

test('missing server mode or shared tenant fails closed', () => {
  assert.throws(() => verifyServerAuthIdentity({ id: 'u', roles: [] }), /deployment_mode/);
  assert.throws(() => verifyServerAuthIdentity({
    id: 'u', roles: [], deployment_mode: 'enterprise_shared',
  }), /active_tenant/);
});

test('dedicated and demo identities remain tenantless and selectors are rejected', () => {
  for (const mode of ['managed', 'self-hosted', 'demo'] as const) {
    assert.equal(verifyServerAuthIdentity({ id: 'u', roles: [], deployment_mode: mode }).activeTenant, null);
    assert.throws(
      () => verifyServerAuthIdentity({ id: 'u', roles: [], deployment_mode: mode }, 'acme-soc'),
      /non-shared/,
    );
  }
});

test('MFA continuation path retains only a validated tenant selector', () => {
  assert.equal(tenantLoginPath('acme-soc'), '/t/acme-soc/login');
  assert.equal(tenantMfaSetupPath('acme-soc'), '/t/acme-soc/mfa-setup');
  assert.equal(tenantSearchPath('acme-soc'), '/t/acme-soc/search');
  assert.throws(() => tenantLoginPath('ACME'), TenantAuthContractError);
  for (const path of [
    '/t/acme-soc/login',
    '/t/acme-soc/mfa-setup',
    '/t/acme-soc',
    '/t/acme-soc/search',
  ]) {
    assert.equal(tenantSlugForAuthContinuation(path), 'acme-soc', path);
  }
  assert.equal(tenantSlugForAuthContinuation('/search'), undefined);
  // Every path under the tenant prefix carries the selector now: the whole
  // product lives there. Outside it there is still none.
  assert.equal(tenantSlugForAuthContinuation('/t/acme-soc/search/jobs'), 'acme-soc');
  assert.equal(tenantSlugForAuthContinuation('/t/acme-soc/settings/users'), 'acme-soc');
  assert.deepEqual(tenantContinuationBody('acme-soc'), { tenant_slug: 'acme-soc' });
  assert.deepEqual(tenantContinuationBody(), {});
  assert.throws(() => tenantContinuationBody('other/tenant'), TenantAuthContractError);
});

test('shared login sends the canonical slug only as the tenant selector', () => {
  assert.deepEqual(loginRequestBody('a@example.test', 'pw', 'acme-soc'), {
    email: 'a@example.test', password: 'pw', tenant_slug: 'acme-soc',
  });
  assert.deepEqual(loginRequestBody('a@example.test', 'pw'), {
    email: 'a@example.test', password: 'pw',
  });
  assert.throws(() => loginRequestBody('a@example.test', 'pw', '../admin'));
});

test('return paths reject open redirects and encoded path confusion', () => {
  assert.equal(safeReturnPath('/settings/user'), '/settings/user');
  for (const value of [
    'https://evil.example', '//evil.example', '/\\evil', '/%2fevil', '/a%3ab',
  ]) {
    assert.equal(safeReturnPath(value), '/', value);
  }
});


test('continuation selectors are read off any tenant-scoped path, never off a non-canonical slug', () => {
  for (const path of ['/t/acme-soc/rules', '/t/acme-soc/alerts', '/t/acme-soc/alerts/alert_01abc', '/t/acme-soc/rules/editor', '/t/acme-soc/alerts/%2fother', '/t/acme-soc/alerts/']) {
    assert.equal(tenantSlugForAuthContinuation(path), 'acme-soc', path);
  }
  // The slug itself is still held to the canonical expression, and a path
  // outside the prefix yields nothing.
  for (const path of ['/t/ACME/alerts', '/t/acme%2dsoc/alerts', '/t//alerts', '/alerts', '/tt/acme-soc']) {
    assert.equal(tenantSlugForAuthContinuation(path), undefined, path);
  }
});

test('return paths preserve literal and encoded timestamps and query values', () => {
  for (const path of [
    '/search?q=src_endpoint.ip%3D%22198.51.100.1%22&start=2026-10-17T12:00:00Z&end=2026-10-17T13:00:00Z',
    '/search?q=https%3A%2F%2Fexample.test&start=2026-10-17T12%3A00%3A00Z#events',
  ]) assert.equal(safeReturnPath(path), path);
  for (const path of ['/\n/evil.example', '/\t/evil.example']) assert.equal(safeReturnPath(path), '/');
});
