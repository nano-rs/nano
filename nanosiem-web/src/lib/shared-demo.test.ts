// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-4152: shared demo link parsing, the claim body, and demo identity.

import assert from 'node:assert/strict';
import test from 'node:test';
import { setTenantPathAlias, sharedDemoClaimFromPath, TenantAuthContractError } from './tenant-auth-shell.ts';
import {
  demoHoursRemaining,
  demoTimeRemainingText,
  isDemoIdentity,
  isInvalidDemoLinkError,
  sharedDemoClaimBody,
} from './shared-demo.ts';

const TOKEN = 'A'.repeat(43) + '_-' + 'b'.repeat(19);
const ALIAS = { pathSegment: 'demo', canonicalSlug: 'lean-internal-20261004b' };

test('a demo link under the alias claims the canonical slug', () => {
  setTenantPathAlias(ALIAS);
  try {
    const target = sharedDemoClaimFromPath(`/t/demo/d/${TOKEN}`);
    assert.deepEqual(target, { tenantSlug: 'lean-internal-20261004b', token: TOKEN });
    assert.deepEqual(sharedDemoClaimBody(target.tenantSlug, target.token), {
      tenant_slug: 'lean-internal-20261004b',
      token: TOKEN,
    });
  } finally {
    setTenantPathAlias(null);
  }
});

test('without an alias the segment is the slug', () => {
  assert.deepEqual(sharedDemoClaimFromPath(`/t/acme/d/${TOKEN}`), { tenantSlug: 'acme', token: TOKEN });
});

test('non-canonical demo paths are refused', () => {
  for (const path of [`/t/ACME/d/${TOKEN}`, `/t/acme/d/`, `/t/acme/d/a%2Fb`, `/t/acme/x/${TOKEN}`, `/d/${TOKEN}`]) {
    assert.throws(() => sharedDemoClaimFromPath(path), TenantAuthContractError, path);
  }
  assert.throws(() => sharedDemoClaimBody('Not Canonical', TOKEN), TenantAuthContractError);
});

test('demo identity is demo.active (shared) or the Saturn role; members are not demo', () => {
  assert.equal(isDemoIdentity(null), false);
  assert.equal(isDemoIdentity({ roles: ['analyst'] }), false);
  assert.equal(isDemoIdentity({ roles: ['analyst'], demo: { active: false, expires_at: '2026-10-20T00:00:00Z' } }), false);
  assert.equal(isDemoIdentity({ roles: [], demo: { active: true, expires_at: '2026-10-20T00:00:00Z' } }), true);
  assert.equal(isDemoIdentity({ roles: ['demo_analyst'] }), true);
});

test('the uniform claim refusal is recognised', () => {
  assert.equal(isInvalidDemoLinkError({ status: 401, code: 'invalid_demo_link' }), true);
  assert.equal(isInvalidDemoLinkError({ status: 503, code: 'demo_unavailable' }), false);
  assert.equal(isInvalidDemoLinkError(new Error('network')), false);
});

test('time remaining from expires_at', () => {
  const now = new Date('2026-10-19T12:00:00Z');
  assert.equal(demoHoursRemaining('2026-10-19T17:30:00Z', now), 5.5);
  assert.equal(demoHoursRemaining('2026-10-19T11:00:00Z', now), 0);
  assert.equal(demoHoursRemaining('garbage', now), 0);
  assert.equal(demoTimeRemainingText(5.5), '5h remaining');
  assert.equal(demoTimeRemainingText(50), '2d 2h remaining');
  assert.equal(demoTimeRemainingText(0.25), '15m remaining');
});
