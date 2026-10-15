// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  activateEnterpriseSharedAccount,
  hasSharedActivationFieldErrors,
  SHARED_ACTIVATION_PASSWORD_MAX_BYTES,
  SHARED_ACTIVATION_PASSWORD_MIN_BYTES,
  SharedActivationBrowserError,
  SharedActivationPasswordRejectedError,
  validateSharedActivationForm,
  validateSharedActivationPassword,
} from './enterprise-shared-activation.ts';

const TOKEN = 'activation_0123456789abcdefghijklmnopqrstuvwxyz_ABC';

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function success() {
  return {
    deploymentMode: 'enterprise_shared',
    tenant: { tenantId: '018f6f72-84b6-7a10-9f11-7ab36f02200a', slug: 'tenant-a' },
    planCode: 'hobby',
    planRevision: 1,
    assignmentRevision: 1,
    mfaEnrollmentRequired: true,
  };
}

test('activation strips fragment, posts credentials once, and accepts only cookie-only MFA shape', async () => {
  const replacements: string[] = [];
  const requests: Array<{ input: string; init?: RequestInit }> = [];
  const result = await activateEnterpriseSharedAccount(`#${TOKEN}`, 'Strong-Passphrase-2361!', {
    replaceUrl: (path) => replacements.push(path),
    fetch: (async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({ input: String(input), init });
      return json(success());
    }) as typeof globalThis.fetch,
  });

  assert.deepEqual(replacements, ['/auth/shared/activate']);
  assert.deepEqual(result, { tenantSlug: 'tenant-a', destination: '/t/tenant-a/mfa-setup' });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].input, '/api/auth/shared/activate');
  assert.equal(requests[0].init?.method, 'POST');
  assert.equal(requests[0].init?.credentials, 'include');
  assert.deepEqual(JSON.parse(String(requests[0].init?.body)), {
    activation_token: TOKEN,
    new_password: 'Strong-Passphrase-2361!',
  });
  assert.doesNotMatch(JSON.stringify(success()), /token|secret|password|state|nonce/i);
});

test('activation rejects malformed fragments, response credentials, and tenant aliases uniformly', async () => {
  let calls = 0;
  const dependencies = {
    replaceUrl: () => {},
    fetch: (async () => {
      calls += 1;
      return json({ ...success(), accessToken: 'forbidden' });
    }) as typeof globalThis.fetch,
  };
  await assert.rejects(
    activateEnterpriseSharedAccount('?token=leak', 'Strong-Passphrase-2361!', dependencies),
    SharedActivationBrowserError,
  );
  assert.equal(calls, 0);
  await assert.rejects(
    activateEnterpriseSharedAccount(`#${TOKEN}`, 'Strong-Passphrase-2361!', dependencies),
    SharedActivationBrowserError,
  );

  await assert.rejects(
    activateEnterpriseSharedAccount(`#${TOKEN}`, 'Strong-Passphrase-2361!', {
      replaceUrl: () => {},
      fetch: (async () => json({ ...success(), tenant: { ...success().tenant, slug: 'Tenant-A' } })) as typeof globalThis.fetch,
    }),
    /canonical/,
  );
});

test('activation client never writes credentials to browser storage', async () => {
  const source = await readFile(fileURLToPath(new URL('./enterprise-shared-activation.ts', import.meta.url)), 'utf8');
  assert.doesNotMatch(source, /localStorage|sessionStorage|document\.cookie/);
  assert.match(source, /credentials: 'include'/);
  assert.match(source, /replaceUrl\(sharedActivationPagePath\(/);
  assert.match(source, /const BARE_ACTIVATION_PATH = '\/auth\/shared\/activate';/);
});


const PAGE_SOURCE = new URL('../pages/EnterpriseSharedActivation.tsx', import.meta.url);
const RUST_POLICY = new URL('../../../nanosiem-core/src/auth/password.rs', import.meta.url);
const RUST_ACTIVATION = new URL(
  '../../../nanosiem-core/src/enterprise_shared_activation.rs',
  import.meta.url,
);

test('client password policy stays in lockstep with the Rust validator', async () => {
  const policy = await readFile(fileURLToPath(RUST_POLICY), 'utf8');
  const activation = await readFile(fileURLToPath(RUST_ACTIVATION), 'utf8');
  assert.match(policy, new RegExp(`min_length: ${SHARED_ACTIVATION_PASSWORD_MIN_BYTES},`));
  for (const requirement of [
    'require_uppercase: true',
    'require_lowercase: true',
    'require_digit: true',
    'require_special: true',
  ]) {
    assert.ok(policy.includes(requirement), `server still enforces ${requirement}`);
  }
  // MAX_PASSWORD_BYTES now lives with the rest of the policy in auth/password.rs
  // (it used to be a local const here, duplicated in member activation). The
  // activation path must still enforce it.
  assert.match(
    policy,
    new RegExp(`MAX_PASSWORD_BYTES: usize = ${SHARED_ACTIVATION_PASSWORD_MAX_BYTES};`),
  );
  assert.match(activation, /MAX_PASSWORD_BYTES/);
});

test('password validation mirrors every server requirement', () => {
  assert.deepEqual(validateSharedActivationPassword('Strong-Passphrase-2361!'), []);
  assert.deepEqual(validateSharedActivationPassword(''), ['Enter a password.']);
  assert.deepEqual(validateSharedActivationPassword('Short-1a'), [
    `Password must be at least ${SHARED_ACTIVATION_PASSWORD_MIN_BYTES} characters long.`,
  ]);
  assert.deepEqual(validateSharedActivationPassword('alllowercase-1'), [
    'Password must contain at least one uppercase letter.',
  ]);
  assert.deepEqual(validateSharedActivationPassword('ALLUPPERCASE-1'), [
    'Password must contain at least one lowercase letter.',
  ]);
  assert.deepEqual(validateSharedActivationPassword('NoDigitsHere-x'), [
    'Password must contain at least one digit.',
  ]);
  assert.deepEqual(validateSharedActivationPassword('NoSpecials2361x'), [
    'Password must contain at least one special character.',
  ]);
  // Byte length, not UTF-16 length: eleven 3-byte characters clear the minimum.
  assert.ok(
    !validateSharedActivationPassword('Aa1!———————').includes(
      `Password must be at least ${SHARED_ACTIVATION_PASSWORD_MIN_BYTES} characters long.`,
    ),
  );
  assert.deepEqual(
    validateSharedActivationPassword(`Aa1!${'x'.repeat(SHARED_ACTIVATION_PASSWORD_MAX_BYTES)}`),
    [`Password must be at most ${SHARED_ACTIVATION_PASSWORD_MAX_BYTES} characters long.`],
  );
});

test('form validation is field-keyed so the page can render inline', () => {
  const valid = validateSharedActivationForm('Strong-Passphrase-2361!', 'Strong-Passphrase-2361!');
  assert.deepEqual(valid, { password: [], confirmation: [] });
  assert.equal(hasSharedActivationFieldErrors(valid), false);

  const tooShort = validateSharedActivationForm('Short-1a', 'Short-1a');
  assert.deepEqual(tooShort.password, [
    `Password must be at least ${SHARED_ACTIVATION_PASSWORD_MIN_BYTES} characters long.`,
  ]);
  assert.deepEqual(tooShort.confirmation, []);
  assert.equal(hasSharedActivationFieldErrors(tooShort), true);

  const mismatched = validateSharedActivationForm(
    'Strong-Passphrase-2361!',
    'Strong-Passphrase-2362!',
  );
  assert.deepEqual(mismatched.password, []);
  assert.deepEqual(mismatched.confirmation, ['Passwords do not match.']);

  assert.deepEqual(
    validateSharedActivationForm('Strong-Passphrase-2361!', '').confirmation,
    ['Confirm your password.'],
  );
});

test('a too-short password is rejected in-app without reaching the network', async () => {
  let calls = 0;
  await assert.rejects(
    activateEnterpriseSharedAccount(`#${TOKEN}`, 'Short-1a', {
      replaceUrl: () => {},
      fetch: (async () => {
        calls += 1;
        return json(success());
      }) as typeof globalThis.fetch,
    }),
    SharedActivationPasswordRejectedError,
  );
  assert.equal(calls, 0);
});

test('a server password rejection surfaces as a field error, other failures stay uniform', async () => {
  await assert.rejects(
    activateEnterpriseSharedAccount(`#${TOKEN}`, 'Strong-Passphrase-2361!', {
      replaceUrl: () => {},
      fetch: (async () =>
        json({ error: 'password_requirements_not_met', message: 'Password does not meet requirements' }, 400)) as typeof globalThis.fetch,
    }),
    (error: unknown) => error instanceof SharedActivationPasswordRejectedError
      && error.field === 'password'
      && error.messages.length > 0,
  );

  await assert.rejects(
    activateEnterpriseSharedAccount(`#${TOKEN}`, 'Strong-Passphrase-2361!', {
      replaceUrl: () => {},
      fetch: (async () => json({ error: 'activation_failed', message: 'Account activation failed' }, 401)) as typeof globalThis.fetch,
    }),
    SharedActivationBrowserError,
  );
});

test('activation page validates in-app with the required accessibility wiring', async () => {
  const page = await readFile(fileURLToPath(PAGE_SOURCE), 'utf8');
  const shell = await readFile(fileURLToPath(new URL('../pages/auth-shell.tsx', import.meta.url)), 'utf8');
  assert.match(shell, /role=\{noteTone === 'bad' \? 'alert' : undefined\}/);
  assert.match(shell, /export function AuthError[\s\S]{0,120}role="alert"/);
  // Native constraint bubbles are suppressed; the app owns the messaging.
  assert.match(page, /<form[\s\S]{0,200}noValidate/);
  // Semantics kept for assistive tech, sourced from the shared constants.
  assert.match(page, /minLength=\{SHARED_ACTIVATION_PASSWORD_MIN_BYTES\}/);
  assert.match(page, /maxLength=\{SHARED_ACTIVATION_PASSWORD_MAX_BYTES\}/);
  assert.doesNotMatch(page, /minLength=\{12\}|maxLength=\{1024\}/);
  // Announced inline errors (the auth-shell `Field` renders a `noteTone="bad"`
  // note with role="alert"; `AuthError` is the request-level alert), invalid
  // state, the policy checklist described-by wiring, and focus recovery.
  assert.match(page, /noteTone="bad"/);
  assert.match(page, /<AuthError>/);
  assert.match(page, /aria-invalid=\{passwordInvalid\}/);
  assert.match(page, /aria-invalid=\{confirmationInvalid\b/);
  assert.match(page, /aria-describedby="activation-password-policy"/);
  assert.match(page, /focusFirstInvalid/);
  assert.match(page, /passwordInput\.current\?\.focus\(\)/);
  assert.match(page, /confirmationInput\.current\?\.focus\(\)/);
  // The page never persists or logs the plaintext.
  assert.doesNotMatch(page, /localStorage|sessionStorage|document\.cookie|console\./);
});

test('member links carry the tenant prefix through activation to the tenant MFA setup (NAN-3788)', async () => {
  const { sharedActivationPagePath, tenantSlugFromActivationPath } = await import('./enterprise-shared-activation.ts');
  const { tenantSlugForAuthContinuation, tenantSlugFromMfaSetupPath } = await import('./tenant-auth-shell.ts');

  // Fresh load of `https://app.example.com/t/tenant-a/auth/shared/activate#<token>`:
  // the router basename is /t/tenant-a, the page keeps the prefix and names
  // the tenant, and the token leaves the address bar before the request.
  const page = '/t/tenant-a/auth/shared/activate';
  assert.equal(sharedActivationPagePath(page), page);
  assert.equal(tenantSlugFromActivationPath(page), 'tenant-a');
  assert.equal(tenantSlugForAuthContinuation(page), 'tenant-a');
  const replacements: string[] = [];
  const result = await activateEnterpriseSharedAccount(`#${TOKEN}`, 'Strong-Passphrase-2361!', {
    replaceUrl: (path) => replacements.push(path),
    activationPath: page,
    fetch: (async () => json(success())) as typeof globalThis.fetch,
  });
  assert.deepEqual(replacements, [page]);
  // Next: the MFA enrollment page under the same prefix, then the product.
  assert.deepEqual(result, { tenantSlug: 'tenant-a', destination: '/t/tenant-a/mfa-setup' });
  assert.equal(tenantSlugFromMfaSetupPath(result.destination), 'tenant-a');

  // Bare (owner / already-issued) links are unchanged; anything else falls back.
  assert.equal(sharedActivationPagePath('/auth/shared/activate'), '/auth/shared/activate');
  assert.equal(tenantSlugFromActivationPath('/auth/shared/activate'), undefined);
  for (const odd of ['/t/Tenant-A/auth/shared/activate', '/t/a%2fb/auth/shared/activate', '/t/a/b/auth/shared/activate', '/t/a/search']) {
    assert.equal(sharedActivationPagePath(odd), '/auth/shared/activate', odd);
    assert.equal(tenantSlugFromActivationPath(odd), undefined, odd);
  }
});
