// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import {
  acceptTenantBootstrapAuthorityRevisions,
  DEDICATED_SEARCH_SURFACE,
  ENTERPRISE_SHARED_FEATURE_FLAG_CODES,
  parseTenantAiAvailability,
  SHARED_RISK_SEARCH_SURFACE,
  SHARED_SEARCH_SURFACE,
  TENANT_AI_UNAVAILABLE,
  TENANT_COMPONENT_CODES,
  TenantCapabilityContractError,
  tenantAiCapabilities,
  tenantBootstrapCacheKey,
  tenantQueryCorrectionEnabled,
  tenantSearchSurface,
  validateTenantCapabilitySnapshot,
} from './tenant-capabilities.ts';
import { TenantRuntimeAuthority } from './tenant-runtime.ts';

const USER_ID = '018f6f72-84b6-7a10-9f11-7ab36f022001';
const TENANT_A = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'tenant-a' };
const TENANT_B = { id: '018f6f72-84b6-7a10-9f11-7ab36f02200b', slug: 'tenant-b' };

function response(
  tenant = TENANT_A,
  assignmentRevision = 1,
  authorizationRevision = 11,
  featureFlagRevision = 13,
) {
  return {
    edition: 'enterprise',
    version: '0.1.0',
    deploymentMode: 'enterprise_shared',
    tenant,
    identity: {
      userId: USER_ID,
      roles: ['analyst'],
      permissions: ['search:read'],
      authorizationRevision,
    },
    plan: { code: 'hobby', revision: 1, assignmentRevision },
    limits: { ha_enabled: true, retention_days: 365 },
    haEnabled: true,
    components: Object.fromEntries(TENANT_COMPONENT_CODES.map((code) => [
      code,
      { enabled: true, configuration: {} },
    ])),
    featureFlags: {
      revision: featureFlagRevision,
      flags: Object.fromEntries(ENTERPRISE_SHARED_FEATURE_FLAG_CODES.map((code) => [code, false])),
    },
  };
}

function expected(tenant = TENANT_A) {
  return {
    userId: USER_ID,
    tenant,
    roles: ['analyst'],
    permissions: ['search:read'],
  };
}

test('same user and identical object names cannot cross tenant A/B', () => {
  assert.equal(validateTenantCapabilitySnapshot(response(TENANT_A), expected(TENANT_A)).tenant.id,
    TENANT_A.id);
  assert.throws(
    () => validateTenantCapabilitySnapshot(response(TENANT_A), expected(TENANT_B)),
    TenantCapabilityContractError,
  );
});

test('matching UUID with a different route slug fails closed', () => {
  assert.throws(
    () => validateTenantCapabilitySnapshot(
      response({ id: TENANT_A.id, slug: 'tenant-b' }),
      expected(TENANT_A),
    ),
    /identity does not match/,
  );
});

test('revoked or changed membership cannot reuse the old capability snapshot', () => {
  assert.throws(
    () => validateTenantCapabilitySnapshot(response(), {
      ...expected(),
      roles: [],
      permissions: [],
    }),
    /membership changed/,
  );
});

test('disabled components remain explicit and missing components reject the plan', () => {
  const disabled = response();
  disabled.components.cases.enabled = false;
  assert.equal(validateTenantCapabilitySnapshot(disabled, expected()).components.cases.enabled,
    false);

  const incomplete = response();
  delete (incomplete.components as Record<string, unknown>).search;
  assert.throws(
    () => validateTenantCapabilitySnapshot(incomplete, expected()),
    /manifest is incomplete/,
  );
});

test('NAN-4435: optional soar component is absent-means-disabled; unknown codes still fail closed', () => {
  // `lean` plans predate SOAR: the server omits the row entirely.
  const lean = validateTenantCapabilitySnapshot(response(), expected());
  assert.equal(lean.components.soar.enabled, false);
  assert.equal(lean.components.search.enabled, true);

  // `lean-soar` (migration 9014940) serializes `soar` alongside every legacy row.
  for (const enabled of [true, false]) {
    const leanSoar = response();
    (leanSoar.components as Record<string, unknown>).soar = { enabled, configuration: {} };
    const parsed = validateTenantCapabilitySnapshot(leanSoar, expected());
    assert.equal(parsed.components.soar.enabled, enabled);
    for (const code of TENANT_COMPONENT_CODES) {
      assert.equal(parsed.components[code].enabled, true, code);
    }
  }

  const unknown = response();
  (unknown.components as Record<string, unknown>).unrecognized = { enabled: true, configuration: {} };
  assert.throws(
    () => validateTenantCapabilitySnapshot(unknown, expected()),
    /manifest is incomplete or unknown/,
  );

  const malformed = response();
  (malformed.components as Record<string, unknown>).soar = { enabled: 'yes', configuration: {} };
  assert.throws(
    () => validateTenantCapabilitySnapshot(malformed, expected()),
    /component soar is invalid/,
  );

  const leaky = response();
  (leaky.components as Record<string, unknown>).soar = { enabled: true, configuration: { api_key: 'x' } };
  assert.throws(
    () => validateTenantCapabilitySnapshot(leaky, expected()),
    /component soar is invalid/,
  );
});

test('auth, assignment, and feature revisions are monotonic as one bootstrap', () => {
  const first = validateTenantCapabilitySnapshot(response(TENANT_A, 7), expected());
  const changed = validateTenantCapabilitySnapshot(response(TENANT_A, 8, 12, 14), expected());
  const accepted = acceptTenantBootstrapAuthorityRevisions({
    authorization: first.identity.authorizationRevision,
    planAssignment: first.plan.assignmentRevision,
    featureFlags: first.featureFlags.revision,
  }, {
    authorization: changed.identity.authorizationRevision,
    planAssignment: changed.plan.assignmentRevision,
    featureFlags: changed.featureFlags.revision,
  });
  assert.deepEqual(accepted, { authorization: 12, planAssignment: 8, featureFlags: 14 });
  for (const stale of [
    { authorization: 11, planAssignment: 8, featureFlags: 14 },
    { authorization: 12, planAssignment: 7, featureFlags: 14 },
    { authorization: 12, planAssignment: 8, featureFlags: 13 },
  ]) {
    assert.throws(
      () => acceptTenantBootstrapAuthorityRevisions(accepted, stale),
      /revision regressed/,
    );
  }
});

test('feature flags require the exact reviewed catalog and boolean values', () => {
  const valid = validateTenantCapabilitySnapshot(response(), expected());
  assert.deepEqual(Object.keys(valid.featureFlags.flags).sort(),
    [...ENTERPRISE_SHARED_FEATURE_FLAG_CODES].sort());

  const missing = response();
  delete (missing.featureFlags.flags as Record<string, unknown>).parser_cell_canary;
  assert.throws(() => validateTenantCapabilitySnapshot(missing, expected()), /catalog/);

  const unknown = response();
  (unknown.featureFlags.flags as Record<string, unknown>).browser_flag = true;
  assert.throws(() => validateTenantCapabilitySnapshot(unknown, expected()), /catalog/);

  const nonBoolean = response();
  (nonBoolean.featureFlags.flags as Record<string, unknown>).soc_ai_long_hunts = 'yes';
  assert.throws(() => validateTenantCapabilitySnapshot(nonBoolean, expected()), /is invalid/);
});

test('browser cache identity binds tenant, member, auth, plan, and flag revisions', () => {
  const a = validateTenantCapabilitySnapshot(response(TENANT_A, 7, 11, 13), expected(TENANT_A));
  const b = validateTenantCapabilitySnapshot(response(TENANT_B, 7, 11, 13), expected(TENANT_B));
  const changed = validateTenantCapabilitySnapshot(response(TENANT_A, 8, 12, 14), expected(TENANT_A));
  assert.deepEqual(tenantBootstrapCacheKey(a), [
    'tenant-bootstrap', TENANT_A.id, USER_ID, 11, 7, 13,
  ]);
  assert.notDeepEqual(tenantBootstrapCacheKey(a), tenantBootstrapCacheKey(b));
  assert.notDeepEqual(tenantBootstrapCacheKey(a), tenantBootstrapCacheKey(changed));
});

test('a response completing after an A to B switch is stale', async () => {
  const runtime = new TenantRuntimeAuthority();
  const capturedA = runtime.activate({
    kind: 'enterprise_shared',
    userId: USER_ID,
    tenant: TENANT_A,
  });
  let resolveA!: (value: unknown) => void;
  const pendingA = new Promise<unknown>((resolve) => { resolveA = resolve; });
  const guardedA = runtime.guard(capturedA, pendingA);

  runtime.activate({
    kind: 'enterprise_shared',
    userId: USER_ID,
    tenant: TENANT_B,
  });
  resolveA(response(TENANT_A));
  await assert.rejects(guardedA, /inactive tenant runtime/);
});

test('shared HA and SSO are required while OIDC authority remains out of band', () => {
  const noHa = response();
  noHa.haEnabled = false;
  assert.throws(() => validateTenantCapabilitySnapshot(noHa, expected()), /highly available/);

  const noSso = response();
  noSso.components.sso.enabled = false;
  assert.throws(() => validateTenantCapabilitySnapshot(noSso, expected()), /SSO is required/);
});

test('credential-shaped plan documents never render in the browser', () => {
  const leaked = response();
  leaked.components.search.configuration = { api_token: 'do-not-render' };
  assert.throws(
    () => validateTenantCapabilitySnapshot(leaked, expected()),
    /component search is invalid/,
  );
});

test('shared query correction requires both components and exact permissions', () => {
  const enabled = validateTenantCapabilitySnapshot(
    {
      ...response(),
      identity: {
        ...response().identity,
        permissions: ['search:execute', 'melod:query'],
      },
    },
    {
      ...expected(),
      permissions: ['search:execute', 'melod:query'],
    },
  );
  assert.equal(tenantQueryCorrectionEnabled(enabled), true);

  const noMelodPermission = structuredClone(enabled);
  noMelodPermission.identity.permissions = ['search:execute'];
  assert.equal(tenantQueryCorrectionEnabled(noMelodPermission), false);

  const noMelodComponent = structuredClone(enabled);
  noMelodComponent.components.melod.enabled = false;
  assert.equal(tenantQueryCorrectionEnabled(noMelodComponent), false);
});

test('AI capabilities require the plan grant AND an enabled platform provider', () => {
  // NAN-2361 wave 8: on the live lake every provider_credentials row was
  // enabled=false, so a plan that includes meloD still cannot serve a job.
  const snapshot = validateTenantCapabilitySnapshot(
    {
      ...response(),
      identity: { ...response().identity, permissions: ['search:execute', 'melod:query'] },
    },
    { ...expected(), permissions: ['search:execute', 'melod:query'] },
  );
  assert.deepEqual(
    tenantAiCapabilities(snapshot, { connected: true, modelAvailable: true }),
    { melod: true, queryCorrection: true, aiTuning: true },
  );
  // No enabled provider: every AI flag is off, so no page issues an AI call.
  assert.deepEqual(
    tenantAiCapabilities(snapshot, { connected: false, modelAvailable: false }),
    { melod: false, queryCorrection: false, aiTuning: false },
  );
  // Provider connected but no selectable model is still "cannot serve".
  assert.deepEqual(
    tenantAiCapabilities(snapshot, { connected: true, modelAvailable: false }),
    { melod: false, queryCorrection: false, aiTuning: false },
  );
  // The unreadable-probe default is deny-all.
  assert.deepEqual(TENANT_AI_UNAVAILABLE, { connected: false, modelAvailable: false });
  // Plan exclusion still wins over a healthy platform.
  const noPlan = structuredClone(snapshot);
  noPlan.components.melod.enabled = false;
  noPlan.components.ai_tuning.enabled = false;
  assert.deepEqual(
    tenantAiCapabilities(noPlan, { connected: true, modelAvailable: true }),
    { melod: false, queryCorrection: false, aiTuning: false },
  );
});

test('the AI availability probe is parsed from its snake_case wire shape only', () => {
  assert.deepEqual(
    parseTenantAiAvailability({ connected: true, model_available: false, tenant_enabled: true, plan_includes_ai: true }),
    { connected: true, modelAvailable: false },
  );
  assert.throws(() => parseTenantAiAvailability({ connected: 'yes', model_available: true }), TenantCapabilityContractError);
  assert.throws(() => parseTenantAiAvailability(null), TenantCapabilityContractError);
});

test('the Search surface names what the tenant-pinned runtime serves', () => {
  const snapshot = validateTenantCapabilitySnapshot(response(), expected());
  assert.equal(tenantSearchSurface(snapshot), SHARED_SEARCH_SURFACE);
  assert.equal(tenantSearchSurface(undefined), DEDICATED_SEARCH_SURFACE);
  // Shared: logs only, nPL only, durable jobs, no browser row cache. Stored
  // short links and the explanation cache are tenant-scoped since wave 8
  // (`shared_search_extras`), so both affordances render.
  assert.deepEqual(SHARED_SEARCH_SURFACE.datasets, ['logs']);
  assert.equal(SHARED_SEARCH_SURFACE.rawSql, false);
  assert.equal(SHARED_SEARCH_SURFACE.storedShortLinks, true);
  assert.equal(SHARED_SEARCH_SURFACE.explanationCache, true);
  assert.equal(SHARED_SEARCH_SURFACE.browserResultCache, false);
  assert.equal(SHARED_SEARCH_SURFACE.durableExecution, true);
  // Dedicated serves everything the page can render.
  assert.deepEqual(DEDICATED_SEARCH_SURFACE.datasets, ['logs', 'spans', 'metrics', 'risk']);
  assert.equal(DEDICATED_SEARCH_SURFACE.rawSql, true);
  assert.equal(DEDICATED_SEARCH_SURFACE.durableExecution, false);
});

test('NAN-3018: shared risk dataset needs the risk component and risk:view', () => {
  const withPermission = (permissions: string[], riskEnabled = true) => {
    const raw = response();
    raw.identity.permissions = permissions;
    raw.components.risk = { enabled: riskEnabled, configuration: {} };
    return validateTenantCapabilitySnapshot(raw, { ...expected(), permissions });
  };
  const risk = tenantSearchSurface(withPermission(['search:execute', 'risk:view']));
  assert.equal(risk, SHARED_RISK_SEARCH_SURFACE);
  assert.deepEqual(risk.datasets, ['logs', 'risk']);
  assert.equal(risk.durableExecution, true);
  assert.equal(risk.rawSql, false);
  assert.equal(tenantSearchSurface(withPermission(['*'])), SHARED_RISK_SEARCH_SURFACE);
  assert.equal(tenantSearchSurface(withPermission(['search:execute'])), SHARED_SEARCH_SURFACE);
  assert.equal(tenantSearchSurface(withPermission(['risk:view'], false)), SHARED_SEARCH_SURFACE);
});
