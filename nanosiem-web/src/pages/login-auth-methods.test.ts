// SPDX-License-Identifier: AGPL-3.0-or-later
/// <reference types="node" />

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  SSO_PANEL_CLASS,
  authMethodsLine,
  hasViewportGate,
  parseSsoCommand,
  resolveLoginMode,
  resolveSsoSurface,
  resolveSsoTarget,
  showPasswordPrompt,
  showSsoPanel,
} from './login-auth-methods.ts';

const OKTA = { name: 'Okta', slug: 'okta' };
const GOOGLE = { name: 'Google Workspace', slug: 'google-workspace' };

const surface = (over: Partial<Parameters<typeof resolveSsoSurface>[0]> = {}) =>
  resolveSsoSurface({ ssoEnabled: true, loading: false, failed: false, providers: [], ...over });

test('a configured provider produces an actionable providers surface', () => {
  const s = surface({ providers: [OKTA] });
  assert.equal(s.kind, 'providers');
  assert.deepEqual(s.kind === 'providers' ? s.providers : null, [OKTA]);
});

test('several providers are all offered, in order', () => {
  const s = surface({ providers: [GOOGLE, OKTA] });
  assert.equal(s.kind, 'providers');
  assert.deepEqual(
    s.kind === 'providers' ? s.providers.map((p) => p.slug) : null,
    ['google-workspace', 'okta'],
  );
});

test('provider absence hides the surface rather than showing an empty panel', () => {
  assert.equal(surface({ providers: [] }).kind, 'hidden');
});

test('an all-disabled tenant is indistinguishable from no providers', () => {
  // /api/auth/oidc/providers only returns enabled providers, so disabling the
  // last one arrives at the login page as an empty list.
  assert.equal(surface({ providers: [] }).kind, 'hidden');
});

test('open-core builds have no SSO surface at all', () => {
  assert.equal(surface({ ssoEnabled: false, providers: [OKTA] }).kind, 'hidden');
  // Even mid-fetch — the fetch is skipped entirely when the capability is off.
  assert.equal(surface({ ssoEnabled: false, loading: true }).kind, 'hidden');
});

test('the in-flight fetch is distinct from the empty result', () => {
  assert.equal(surface({ loading: true }).kind, 'loading');
  assert.notEqual(surface({ loading: true }).kind, surface({ loading: false }).kind);
});

test('a failed provider fetch is distinct from no providers configured', () => {
  // Previously both collapsed to `[]`, so an unreachable endpoint looked exactly
  // like a tenant that had never set SSO up.
  assert.equal(surface({ failed: true }).kind, 'error');
  assert.notEqual(surface({ failed: true }).kind, surface({ providers: [] }).kind);
});

test('the post-email line never claims a per-account provider lookup', () => {
  const line = authMethodsLine(surface({ providers: [OKTA] }));
  assert.match(line, /tenant auth methods/);
  assert.doesNotMatch(line, /provider resolved/, 'the hard-coded claim must not come back');
  assert.doesNotMatch(line, /local-password/);
});

test('the post-email line names both methods when SSO is available', () => {
  assert.equal(
    authMethodsLine(surface({ providers: [OKTA, GOOGLE] })),
    '→ tenant auth methods: password · sso (okta, google-workspace)',
  );
});

test('the post-email line states password only when there is no SSO', () => {
  assert.equal(authMethodsLine(surface({ providers: [] })), '→ tenant auth methods: password');
  assert.equal(authMethodsLine(surface({ ssoEnabled: false })), '→ tenant auth methods: password');
});

test('the post-email line is honest while loading and when the fetch failed', () => {
  assert.match(authMethodsLine(surface({ loading: true })), /checking providers/);
  assert.match(authMethodsLine(surface({ failed: true })), /unavailable/);
});

test('SSO is offered at identity and password entry, not mid-MFA or after', () => {
  assert.equal(showSsoPanel('email'), true);
  assert.equal(showSsoPanel('password'), true);
  assert.equal(showSsoPanel('mfa'), false, 'switching methods mid-challenge abandons it');
  assert.equal(showSsoPanel('done'), false);
});

test('the SSO panel is not gated by viewport width', () => {
  // The regression this guards: SSO used to live in a `hidden lg:flex`
  // inspector, so it was unreachable below the lg breakpoint.
  assert.equal(hasViewportGate(SSO_PANEL_CLASS), false);
  // The guard itself must actually catch the shape it exists to reject.
  assert.equal(hasViewportGate('hidden lg:flex w-[300px]'), true);
  assert.equal(hasViewportGate('lg:hidden'), true);
  assert.equal(hasViewportGate('flex md:block'), true);
  assert.equal(hasViewportGate('mt-2 max-w-[78ch] space-y-1.5'), false);
});

test('the sso command parses into list and launch forms', () => {
  assert.deepEqual(parseSsoCommand('sso'), { kind: 'list' });
  assert.deepEqual(parseSsoCommand('  SSO  '), { kind: 'list' });
  assert.deepEqual(parseSsoCommand('sso okta'), { kind: 'launch', target: 'okta' });
  assert.deepEqual(parseSsoCommand('sso 2'), { kind: 'launch', target: '2' });
  assert.equal(parseSsoCommand('help'), null);
  assert.equal(parseSsoCommand('ssoo okta'), null);
});

test('sso targets resolve by index, slug, or name', () => {
  const providers = [OKTA, GOOGLE];
  assert.equal(resolveSsoTarget('1', providers), OKTA);
  assert.equal(resolveSsoTarget('2', providers), GOOGLE);
  assert.equal(resolveSsoTarget('okta', providers), OKTA);
  assert.equal(resolveSsoTarget('OKTA', providers), OKTA);
  assert.equal(resolveSsoTarget('google-workspace', providers), GOOGLE);
  assert.equal(resolveSsoTarget('Google Workspace', providers), GOOGLE);
});

test('unresolvable sso targets return null rather than a wrong provider', () => {
  const providers = [OKTA, GOOGLE];
  assert.equal(resolveSsoTarget('3', providers), null);
  assert.equal(resolveSsoTarget('0', providers), null);
  assert.equal(resolveSsoTarget('azure', providers), null);
  assert.equal(resolveSsoTarget('', providers), null);
  assert.equal(resolveSsoTarget('1', []), null);
});

// ---------------------------------------------------------------------------
// NAN-2181 — SSO-only mode
// ---------------------------------------------------------------------------

test('the default tenant shows the password wizard with SSO alongside', () => {
  const mode = resolveLoginMode({
    localPassword: true,
    sso: surface({ providers: [OKTA] }),
  });
  assert.equal(mode.kind, 'password');
  assert.equal(showPasswordPrompt(mode), true);
});

test('password stays available when local auth is on and no SSO exists', () => {
  const mode = resolveLoginMode({ localPassword: true, sso: surface({ providers: [] }) });
  assert.equal(mode.kind, 'password');
  assert.equal(showPasswordPrompt(mode), true);
});

test('SSO-only mode drops the password wizard entirely', () => {
  const mode = resolveLoginMode({
    localPassword: false,
    sso: surface({ providers: [OKTA, GOOGLE] }),
  });
  assert.equal(mode.kind, 'ssoOnly');
  assert.equal(showPasswordPrompt(mode), false);
  assert.deepEqual(
    mode.kind === 'ssoOnly' ? mode.providers.map((p) => p.slug) : null,
    ['okta', 'google-workspace'],
  );
});

test('an unknown local-password setting never flashes a password prompt', () => {
  // The whole point of SSO-only is that credentials are not solicited. Rendering
  // the wizard optimistically while /api/auth/methods is in flight would show
  // one on every page load.
  const mode = resolveLoginMode({ localPassword: null, sso: surface({ loading: true }) });
  assert.equal(mode.kind, 'loading');
  assert.equal(showPasswordPrompt(mode), false);
});

test('SSO-only waits for providers rather than declaring itself broken', () => {
  const mode = resolveLoginMode({ localPassword: false, sso: surface({ loading: true }) });
  assert.equal(mode.kind, 'ssoOnlyLoading');
  assert.equal(showPasswordPrompt(mode), false);
});

test('SSO-only with an unreachable provider endpoint reports why', () => {
  const mode = resolveLoginMode({ localPassword: false, sso: surface({ failed: true }) });
  assert.equal(mode.kind, 'ssoOnlyUnavailable');
  assert.equal(mode.kind === 'ssoOnlyUnavailable' ? mode.reason : null, 'error');
  assert.equal(showPasswordPrompt(mode), false, 'the server would reject the credentials anyway');
});

test('SSO-only with no providers is surfaced, not silently blank', () => {
  // The server guards against reaching this state, but a client that gets an
  // empty list still owes the user an explanation instead of a dead page.
  const mode = resolveLoginMode({ localPassword: false, sso: surface({ providers: [] }) });
  assert.equal(mode.kind, 'ssoOnlyUnavailable');
  assert.equal(mode.kind === 'ssoOnlyUnavailable' ? mode.reason : null, 'noProviders');
});

test('open-core builds are never put into SSO-only mode by a stale flag', () => {
  // capabilities.sso false means there is no SSO surface at all; a localPassword
  // of false could then only come from a corrupt response, and honoring it would
  // leave no way to sign in.
  const mode = resolveLoginMode({
    localPassword: false,
    sso: surface({ ssoEnabled: false, providers: [OKTA] }),
  });
  assert.equal(mode.kind, 'ssoOnlyUnavailable');
  assert.equal(mode.kind === 'ssoOnlyUnavailable' ? mode.reason : null, 'noProviders');
});
